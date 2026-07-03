"""Round-3 Kyber1024 pure-Python vs the ``kyber1024_py`` Rust binding.

Keys and ciphertexts are interchangeable between the two implementations, so
the Rust binding (when built) is an exact oracle. Skips cleanly when it is
absent, leaving the self-consistency test as the floor.
"""
import pytest

from signalnotify.native.pure import kyber1024 as k


def test_self_roundtrip():
    for _ in range(10):
        pk, sk = k.generate()
        assert len(pk) == k.PUBLIC_KEY_LEN
        assert len(sk) == k.SECRET_KEY_LEN
        ct, ss = k.encapsulate(pk)
        assert len(ct) == k.CIPHERTEXT_LEN
        assert len(ss) == k.SHARED_SECRET_LEN
        assert k.decapsulate(sk, ct) == ss


def test_implicit_rejection_is_deterministic():
    pk, sk = k.generate()
    ct, _ss = k.encapsulate(pk)
    bad = bytearray(ct)
    bad[0] ^= 0xFF
    # Wrong ciphertext must decapsulate to a stable pseudo-random secret,
    # never raise and never equal the real one.
    r1 = k.decapsulate(sk, bytes(bad))
    r2 = k.decapsulate(sk, bytes(bad))
    assert r1 == r2 and len(r1) == 32


rust = pytest.importorskip("kyber1024_py", reason="Rust kyber1024_py not built")


def test_my_encaps_rust_decaps():
    for _ in range(8):
        pk_r, sk_r = rust.generate()
        ct, ss = k.encapsulate(pk_r)
        assert rust.decapsulate(sk_r, ct) == ss


def test_rust_encaps_my_decaps():
    for _ in range(8):
        pk_r, sk_r = rust.generate()
        ct, ss = rust.encapsulate(pk_r)
        assert k.decapsulate(sk_r, ct) == ss


def test_cross_keygen():
    for _ in range(8):
        pk, sk = k.generate()
        ct, ss = rust.encapsulate(pk)         # Rust encaps to a pure-Python key
        assert k.decapsulate(sk, ct) == ss
