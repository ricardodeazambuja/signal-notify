//! Thin Python binding around Signal's Sparse Post-Quantum Ratchet (spqr) crate.
//! Exposes only the message-key API libsignal's triple_ratchet uses:
//! initial_state / recv / send. State and messages are opaque `bytes`.
//!
//! Return values are `bytes` (PyBytes), not `list[int]`: the state is base64
//! serialized by the Python side, and callers treat every value as opaque bytes.
//! Inputs stay `Vec<u8>`, which accepts both `bytes` and any int sequence.
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use spqr::{ChainParams, Direction, Params, Version};

fn err<E: std::fmt::Debug>(e: E) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(format!("spqr: {:?}", e))
}

/// Initialize SPQR state from the PQXDH-derived auth key (the 3rd derived key).
/// b2a=True for the responder (Bob), False for the initiator (Alice). Returns
/// the serialized state bytes.
#[pyfunction]
fn initial_state<'py>(
    py: Python<'py>,
    auth_key: Vec<u8>,
    b2a: bool,
    max_jump: u32,
    max_ooo_keys: u32,
) -> PyResult<Bound<'py, PyBytes>> {
    let params = Params {
        direction: if b2a { Direction::B2A } else { Direction::A2B },
        version: Version::V1,
        min_version: Version::V1,
        auth_key: &auth_key,
        chain_params: ChainParams { max_jump, max_ooo_keys },
    };
    let state = spqr::initial_state(params).map_err(err)?;
    Ok(PyBytes::new_bound(py, &state))
}

/// Process an incoming pq_ratchet message. Returns (new_state, optional_key).
/// The key, when present, is the HKDF salt for the classic message-key derivation.
#[pyfunction]
fn recv<'py>(
    py: Python<'py>,
    state: Vec<u8>,
    msg: Vec<u8>,
) -> PyResult<(Bound<'py, PyBytes>, Option<Bound<'py, PyBytes>>)> {
    let r = spqr::recv(&state, &msg).map_err(err)?;
    let key = r.key.map(|k| PyBytes::new_bound(py, &k));
    Ok((PyBytes::new_bound(py, &r.state), key))
}

/// Produce an outgoing pq_ratchet message. Returns (new_state, msg, optional_key).
#[pyfunction]
fn send<'py>(
    py: Python<'py>,
    state: Vec<u8>,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>, Option<Bound<'py, PyBytes>>)> {
    // rand_core 0.9's OsRng is fallible (TryRngCore). `.unwrap_err()` adapts it
    // into an infallible RngCore (panicking on OS failure), which is what
    // spqr::send's `Rng + CryptoRng` bound requires — mirrors spqr's own tests.
    use rand_core::{OsRng, TryRngCore};
    let mut rng = OsRng.unwrap_err();
    let s = spqr::send(&state, &mut rng).map_err(err)?;
    let key = s.key.map(|k| PyBytes::new_bound(py, &k));
    Ok((PyBytes::new_bound(py, &s.state), PyBytes::new_bound(py, &s.msg), key))
}

#[pymodule]
fn spqr_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(initial_state, m)?)?;
    m.add_function(wrap_pyfunction!(recv, m)?)?;
    m.add_function(wrap_pyfunction!(send, m)?)?;
    Ok(())
}
