"""ML-KEM-768 pure-Python vs pyca ``cryptography`` differential tests.

The incremental pieces (hdr/ek/ct1/ct2/shared-secret) are standard FIPS-203
values, so ``cryptography.MLKEM768`` is an exact oracle. If ``cryptography``
lacks ML-KEM (older builds), the whole module is skipped.
"""
import os

import pytest

from signalnotify.native.pure import mlkem768 as m

mlkem = pytest.importorskip(
    "cryptography.hazmat.primitives.asymmetric.mlkem",
    reason="cryptography without ML-KEM support",
)

if not hasattr(mlkem, "MLKEM768PrivateKey"):  # pragma: no cover
    pytest.skip("MLKEM768 unavailable", allow_module_level=True)


def _seed():
    return os.urandom(m.SEED_LEN)


def test_keygen_matches_pyca():
    for _ in range(10):
        seed = _seed()
        hdr, ek, dk = m.generate(seed)
        assert len(hdr) == m.HDR_LEN
        assert len(ek) == m.EK_LEN
        assert len(dk) == m.DK_LEN
        pca = mlkem.MLKEM768PrivateKey.from_seed_bytes(seed)
        ek_full = pca.public_key().public_bytes_raw()
        assert ek_full[:m.EK_LEN] == ek          # t_hat bytes
        assert ek_full[m.EK_LEN:] == hdr[:32]    # rho


def test_my_encaps_pyca_decaps():
    for _ in range(10):
        seed = _seed()
        hdr, ek, _dk = m.generate(seed)
        pca = mlkem.MLKEM768PrivateKey.from_seed_bytes(seed)
        ct1, es, ss = m.encaps1(hdr, os.urandom(32))
        ct2 = m.encaps2(ek, es)
        assert len(ct1) == m.C1_LEN
        assert len(ct2) == m.C2_LEN
        assert len(es) == m.ES_LEN
        assert pca.decapsulate(ct1 + ct2) == ss


def test_pyca_encaps_my_decaps():
    for _ in range(10):
        seed = _seed()
        _hdr, _ek, dk = m.generate(seed)
        pca = mlkem.MLKEM768PrivateKey.from_seed_bytes(seed)
        ss, ct = pca.public_key().encapsulate()
        assert m.decaps(dk, ct[:m.C1_LEN], ct[m.C1_LEN:]) == ss


def test_self_roundtrip_and_header_check():
    for _ in range(10):
        seed = _seed()
        hdr, ek, dk = m.generate(seed)
        ct1, es, ss = m.encaps1(hdr, os.urandom(32))
        ct2 = m.encaps2(ek, es)
        assert m.decaps(dk, ct1, ct2) == ss
        assert m.ek_matches_header(ek, hdr)
        # A tampered ek must not validate against the header.
        bad = bytearray(ek)
        bad[0] ^= 0x01
        assert not m.ek_matches_header(bytes(bad), hdr)


def test_es_roundtrip_layout():
    seed = _seed()
    hdr, ek, _dk = m.generate(seed)
    ct1, es, ss = m.encaps1(hdr, os.urandom(32))
    r_hat, error2, msg = m._es_unpack(es)
    assert len(r_hat) == m.K and all(len(p) == m.N for p in r_hat)
    assert len(error2) == m.N
    assert all(v in (0, 1, 2, m.Q - 1, m.Q - 2) for v in error2)  # eta2=2
    assert m._es_pack(r_hat, error2, msg) == es
