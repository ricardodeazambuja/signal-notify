# spqr_py — provenance & reproducibility

Thin [pyo3](https://pyo3.rs) binding around Signal's **Sparse Post-Quantum
Ratchet** (SPQR, the "triple ratchet"). signal-notify's pure-Python engine
implements PQXDH + the classic Double Ratchet, but modern Signal forces every
newly-linked device to advertise the `spqr` capability, so the primary phone
wraps message keys with SPQR. Without this layer, decrypt fails with "bad MAC"
on the first message. Reimplementing SPQR in Python (Reed-Solomon erasure codes,
incremental ML-KEM-768, a formally-verified key schedule) would be large and
error-prone, so we bind the real upstream crate instead.

## Source & pin

- Upstream: `https://github.com/signalapp/SparsePostQuantumRatchet`
- `signalapp` is the GitHub-**verified** organization "Signal" — the same org
  that publishes `libsignal`, `Signal-Android`, and `Signal-Server`.
- Pinned in `Cargo.toml` to the **immutable commit**
  `f2589fef855c10f39d72634dab3d14654dd410bf`
  (= tag `v1.5.1`). Pinning to the raw SHA, not the movable tag, means upstream
  changes cannot silently alter what we compile.
- This is the **exact revision** that official `libsignal` v0.96.4 depends on
  (its `Cargo.toml` pins `spqr = { ... tag = "v1.5.1" }`). We track what Signal
  itself ships.
- The crate is AGPL-3.0 and formally verified (hax / F*).

## What makes this reproducible

1. **Crate source is committed here** (`Cargo.toml`, `src/lib.rs`) — not left in
   a scratchpad. A fresh checkout can rebuild with no external investigation.
2. **`Cargo.lock` is committed.** The `spqr` git dep is SHA-pinned; the lockfile
   additionally freezes every transitive dep (pyo3, prost, curve25519-dalek,
   libcrux-ml-kem, rand, …) by exact version + checksum.
3. **`rust-toolchain.toml`** pins the compiler to the rustc that produced the
   committed lockfile.
4. **`build.sh`** is the single documented rebuild command.

The build is reproducible as long as GitHub still serves that commit and
crates.io still serves the pinned deps. If you also want to survive upstream
*disappearing* (offline / bulletproof build), run `cargo vendor` and commit the
vendored tree — not done by default because it adds tens of MB of Rust source.

## Build

```sh
rust/build.sh          # from the repo root
```

Or manually:

```sh
. "$HOME/.cargo/env"
cd rust/spqr_py
python -m maturin develop --release   # installs spqr_py into the active env
```

## API exposed to Python

Opaque `bytes` state and messages; no secrets are logged.

- `initial_state(auth_key: bytes, b2a: bool, max_jump: int, max_ooo_keys: int) -> bytes`
  — seed SPQR from PQXDH's third derived key. `b2a=True` for the responder (us,
  receiving from the phone), `False` for the initiator.
- `recv(state: bytes, msg: bytes) -> tuple[bytes, bytes | None]`
  — process an inbound `pq_ratchet` message; the returned key (when present) is
  the HKDF salt for the classic message-key derivation.
- `send(state: bytes) -> tuple[bytes, bytes, bytes | None]`
  — produce an outbound `pq_ratchet` message (new_state, msg, optional key).
