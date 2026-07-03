"""Pure-Python replacements for the project's Rust extension modules.

These implement, in dependency-free Python, exactly the post-quantum
primitives the native Signal stack needs:

* :mod:`mlkem768` — FIPS-203 ML-KEM-768 with the incremental encapsulation
  split used by the Sparse Post-Quantum Ratchet (replaces ``libcrux-ml-kem``).
* :mod:`kyber1024` — round-3 CRYSTALS-Kyber-1024 for PQXDH (replaces the
  ``kyber1024_py`` Rust binding).
* :mod:`spqr` — the Sparse Post-Quantum Ratchet itself (replaces ``spqr_py``).

Every module is validated byte-for-byte against a reference: ML-KEM against
``cryptography``'s ``MLKEM768``, and Kyber1024/SPQR against the Rust bindings
when they are present (see ``tests/test_pure_*``).
"""
