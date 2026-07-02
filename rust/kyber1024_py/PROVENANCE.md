# kyber1024_py — provenance & reproducibility

Python binding for **round-3 CRYSTALS-Kyber-1024**, the KEM Signal's PQXDH uses.

## Why this exists

Signal's PQXDH does **not** use FIPS-203 ML-KEM. In libsignal's `kem::KeyType`,
byte `0x08` is `Kyber1024` (round-3 Kyber, backed by `libcrux_ml_kem::kyber1024`
via the `kyber` feature); byte `0x0A` is `MLKEM1024` (FIPS 203). They share
key/ciphertext sizes (1568 bytes) but are different algorithms — decapsulating a
Kyber ciphertext with ML-KEM silently returns a wrong shared secret (implicit
rejection), which only surfaces as a downstream MAC failure. `cryptography`'s
`mlkem` module is FIPS-203 ML-KEM, so it is the wrong primitive here. This crate
binds the *same* `libcrux_ml_kem::kyber1024` libsignal uses.

## Source & pin

- `libcrux-ml-kem = "0.0.8"`, features `["kyber", "mlkem1024"]` — the exact
  version + features libsignal v0.96.4 depends on (its workspace Cargo.toml pins
  `libcrux-ml-kem = "0.0.8"`; the `kyber1024` module reuses the `mlkem1024` wire
  types). `Cargo.lock` (committed) freezes the full dependency tree.
- `rust-toolchain.toml` pins rustc.
- Build with `rust/build.sh` (builds all bindings, `--locked`).

Round-3 Kyber decapsulation is deterministic given (secret key, ciphertext), so
any correct round-3 Kyber1024 implementation yields the same secret as the phone;
pinning to libsignal's exact crate removes any doubt.

## API (raw bytes, no 0x08 wire prefix — the Python side adds/strips it)

- `generate() -> (public_key[1568], secret_key[3168])`
- `encapsulate(public_key[1568]) -> (ciphertext[1568], shared_secret[32])`
- `decapsulate(secret_key[3168], ciphertext[1568]) -> shared_secret[32]`
