# pure-python port — loop state

Goal: make signal-notify 100% pure Python — replace rust/spqr_py and
rust/kyber1024_py with pure-Python implementations. Branch: `pure-python`.

Interpretation (decided 2026-07-02 23:40): "Rust libraries we currently use" =
the two in-repo maturin bindings (spqr_py, kyber1024_py) that require a Rust
toolchain. Standard pip wheels (`cryptography`, `websockets`, `protobuf`) stay.
Rust bindings remain in-repo as optional differential-test oracles only.

## Plan
1. [in progress] Study spqr v1.5.1 source (~2.4k lines, cached at
   ~/.cargo/git/checkouts/sparsepostquantumratchet-b58d7f56e3645ccd/f2589fe)
   + libcrux-ml-kem 0.0.8 incremental module.
2. Pure-Python ML-KEM-768 + libcrux incremental API (oracle: pyca cryptography
   MLKEM768 + cargo tests).
3. Pure-Python round-3 Kyber1024 (oracle: kyber1024_py binding).
4. Pure-Python SPQR port; state protobuf-compatible with rust states.
5. Differential tests (py↔rust conversations, state swap mid-stream).
6. Wire into kem.py/ratchet.py as default; full pytest suite.
7. Docs + perf + clean commits.
8. MAYBE live Note-to-Self smoke test (backup data dir first). Decide at end.

## Position
- [DONE] Step 1 study — all spqr + libcrux incremental sources read.
- [DONE] Step 2 ML-KEM-768 pure Python (native/pure/mlkem768.py) — validated
  byte-for-byte vs pyca MLKEM768 (keygen, both encaps dirs, decaps, incremental
  split). ~30ms/full cycle. tests/test_pure_mlkem.py green. COMMITTED.
- [DONE] Step 3 Kyber1024 (native/pure/kyber1024.py) vs kyber1024_py: COMMITTED.
- [DONE] Step 4 SPQR (native/pure/{_pb,spqr_gf,spqr}.py) — interop w/ spqr_py:
  lockstep both dirs, state handoff both ways, OOO, 400-round chaos, es-blob
  handoff. COMMITTED.
- [DONE] Step 5 differential tests (test_pure_{mlkem,kyber,spqr}.py). COMMITTED.
- [DONE] Step 6 wired pure as DEFAULT in kem.py/ratchet.py (env override
  SIGNALNOTIFY_{KEM,SPQR}_BACKEND=rust for oracle). Full 139-test suite green.
  CI split pure-only + differential jobs. Clean-env (rust blocked) verified. COMMITTED.
- [NEXT] Step 7 docs (native_caveats/technical_reference/customizing/README) +
  perf pass (NTT/GF hot paths) + final commit. Then DONE.
  NOTE: per advisor, do NOT run live Note-to-Self test (link overwrites account,
  needs approval). Behavioral equivalence to rust is sufficient proof.
  Add caveat: pure impl is NOT constant-time (decaps re-encrypts & compares).

## Key facts learned (for resume)
- Matrix: A_hat[i][j] = SampleNTT(rho, j, i)  (column byte first).
- ML-KEM dk (2400) = FIPS-203 standard sk: dk_pke(1152)|ek(1184)|H(ek)(32)|z(32).
- es (2080) = r_as_ntt(3*512 i16 LE) | error2(512 i16 LE, signed, in [-2,2]) | m(32).
- G=SHA3-512, H=SHA3-256, J=SHAKE256; KeyGen G(d||K_byte=3).
- spqr uses ML-KEM-768 incremental; Kyber1024 is separate (PQXDH only).

## Notes / gotchas
- ScheduleWakeup ENDS the turn in this harness — schedule only at turn end
  (2 wakeups burned learning this; work runs 21:37→ now via goal stop-hook).
- spqr uses ML-KEM-768 **incremental** (chunked ek/ct) — NOT Kyber1024;
  Kyber1024 round-3 is only for PQXDH (kem.py).
- Oracles available in env: spqr_py, kyber1024_py, pyca cryptography MLKEM768.
- Python for tests: ~/miniforge3/envs/local/bin/python (NOT `condalocal` in
  non-interactive bash).
