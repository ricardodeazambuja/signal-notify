//! Python binding for round-3 CRYSTALS-Kyber-1024, the KEM Signal's PQXDH uses
//! (KeyType byte 0x08). Mirrors libsignal v0.96.4 `protocol/src/kem/kyber1024.rs`
//! exactly, backed by the same `libcrux_ml_kem::kyber1024` (the `kyber` feature,
//! NOT FIPS-203 `mlkem1024`). All values are raw `bytes` WITHOUT the 0x08 wire
//! prefix — the Python side adds/strips it.
//!
//! Sizes: public key 1568, secret key 3168, ciphertext 1568, shared secret 32.
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand_core::{OsRng, TryRngCore};

// Kyber1024 reuses the ML-KEM-1024 wire types (identical sizes); the `kyber1024`
// module selects the round-3 algorithm.
use libcrux_ml_kem::kyber1024;
use libcrux_ml_kem::mlkem1024::{MlKem1024Ciphertext, MlKem1024PublicKey};

fn err<E: std::fmt::Debug>(e: E) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(format!("kyber1024: {:?}", e))
}

fn os_random<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.try_fill_bytes(&mut buf).expect("OS RNG must not fail");
    buf
}

/// Generate a Kyber1024 key pair. Returns (public_key[1568], secret_key[3168]).
#[pyfunction]
fn generate(py: Python<'_>) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let kp = kyber1024::generate_key_pair(os_random::<64>());
    let (sk, pk) = kp.into_parts();
    Ok((
        PyBytes::new_bound(py, pk.as_ref()).unbind(),
        PyBytes::new_bound(py, sk.as_ref()).unbind(),
    ))
}

/// Encapsulate to a public key. Returns (ciphertext[1568], shared_secret[32]).
#[pyfunction]
fn encapsulate(py: Python<'_>, public_key: Vec<u8>) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let pk = MlKem1024PublicKey::try_from(public_key.as_slice()).map_err(err)?;
    let (ct, ss) = kyber1024::encapsulate(&pk, os_random::<32>());
    Ok((
        PyBytes::new_bound(py, ct.as_ref()).unbind(),
        PyBytes::new_bound(py, ss.as_ref()).unbind(),
    ))
}

/// Decapsulate a ciphertext with our secret key. Returns shared_secret[32].
/// Note: Kyber (like ML-KEM) never errors on a wrong key/ciphertext — it returns
/// a pseudo-random secret (implicit rejection). A wrong secret shows up only
/// downstream as a MAC failure.
#[pyfunction]
fn decapsulate(py: Python<'_>, secret_key: Vec<u8>, ciphertext: Vec<u8>) -> PyResult<Py<PyBytes>> {
    let sk = libcrux_ml_kem::mlkem1024::MlKem1024PrivateKey::try_from(secret_key.as_slice())
        .map_err(err)?;
    let ct = MlKem1024Ciphertext::try_from(ciphertext.as_slice()).map_err(err)?;
    let ss = kyber1024::decapsulate(&sk, &ct);
    Ok(PyBytes::new_bound(py, ss.as_ref()).unbind())
}

#[pymodule]
fn kyber1024_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate, m)?)?;
    m.add_function(wrap_pyfunction!(encapsulate, m)?)?;
    m.add_function(wrap_pyfunction!(decapsulate, m)?)?;
    Ok(())
}
