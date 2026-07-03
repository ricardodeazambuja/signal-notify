"""Pure-Python round-3 CRYSTALS-Kyber-1024, the KEM Signal's PQXDH uses.

Signal's PQXDH is keyed on **round-3 Kyber1024** (libsignal ``kem::KeyType``
byte ``0x08``), NOT FIPS-203 ML-KEM. They share ring/NTT arithmetic and key
sizes but differ in the CCA transform:

* the encapsulated message is pre-hashed: ``m = H(rand)``;
* key generation derives ``(rho, sigma) = G(d)`` with **no** domain-separation
  byte (ML-KEM appends the rank ``k``);
* the shared secret binds the ciphertext: ``K = KDF(K̄ ‖ H(c))`` where
  ``KDF = SHAKE256(·, 32)``;
* implicit rejection returns ``KDF(PRF(z ‖ c) ‖ H(c))``.

Parameters: k=4, du=11, dv=5, eta1=eta2=2. The lattice primitives (NTT, byte
(de)serialization, compression, CBD, matrix sampling) are shared with
:mod:`mlkem768`. Validated against the ``kyber1024_py`` Rust binding in
``tests/test_pure_kyber.py``.
"""
from __future__ import annotations

import hashlib

from . import mlkem768 as _m

Q = _m.Q
N = _m.N
K = 4
ETA1 = 2
ETA2 = 2
DU = 11
DV = 5

POLY_BYTES = _m.POLY_BYTES           # 384
PUBLIC_KEY_LEN = K * POLY_BYTES + 32          # 1568
SECRET_KEY_LEN = K * POLY_BYTES + PUBLIC_KEY_LEN + 32 + 32  # 3168
C1_LEN = K * (N * DU // 8)           # 1408
C2_LEN = N * DV // 8                 # 160
CIPHERTEXT_LEN = C1_LEN + C2_LEN     # 1568
SHARED_SECRET_LEN = 32
SEED_LEN = 32                        # d (keygen entropy)


def _G(data: bytes) -> tuple[bytes, bytes]:
    h = hashlib.sha3_512(data).digest()
    return h[:32], h[32:]


def _H(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def _kdf(data: bytes) -> bytes:
    return hashlib.shake_256(data).digest(32)


def _gen_matrix(rho: bytes):
    # Same convention as ML-KEM (validated there): A[i][j] = SampleNTT(rho, j, i).
    return [[_m._sample_ntt(rho, j, i) for j in range(K)] for i in range(K)]


def _pke_keygen(d: bytes):
    rho, sigma = _G(d)                # round-3: G(d), no domain byte
    A = _gen_matrix(rho)
    s = [_m._cbd(_m._prf(ETA1, sigma, i), ETA1) for i in range(K)]
    e = [_m._cbd(_m._prf(ETA1, sigma, K + i), ETA1) for i in range(K)]
    s_hat = [_m._ntt(p) for p in s]
    e_hat = [_m._ntt(p) for p in e]
    t_hat = []
    for i in range(K):
        acc = [0] * N
        for j in range(K):
            acc = _m._poly_add(acc, _m._mul_ntt(A[i][j], s_hat[j]))
        t_hat.append(_m._poly_add(acc, e_hat[i]))
    pk = b"".join(_m._encode_poly12(t_hat[i]) for i in range(K)) + rho
    sk_pke = b"".join(_m._encode_poly12(s_hat[i]) for i in range(K))
    return pk, sk_pke


def _pke_encrypt(pk: bytes, msg: bytes, coins: bytes) -> bytes:
    t_hat = [_m._decode_poly12(pk[i * POLY_BYTES:(i + 1) * POLY_BYTES]) for i in range(K)]
    rho = pk[K * POLY_BYTES:]
    A = _gen_matrix(rho)
    r = [_m._cbd(_m._prf(ETA1, coins, i), ETA1) for i in range(K)]
    e1 = [_m._cbd(_m._prf(ETA2, coins, K + i), ETA2) for i in range(K)]
    e2 = _m._cbd(_m._prf(ETA2, coins, 2 * K), ETA2)
    r_hat = [_m._ntt(p) for p in r]
    # u = NTT^-1(A^T @ r_hat) + e1
    u = []
    for i in range(K):
        acc = [0] * N
        for j in range(K):
            acc = _m._poly_add(acc, _m._mul_ntt(A[j][i], r_hat[j]))
        u.append(_m._poly_add(_m._intt(acc), e1[i]))
    # v = NTT^-1(t_hat^T @ r_hat) + e2 + Decompress_1(m)
    acc = [0] * N
    for i in range(K):
        acc = _m._poly_add(acc, _m._mul_ntt(t_hat[i], r_hat[i]))
    v = _m._poly_add(_m._intt(acc), e2)
    v = _m._poly_add(v, _m._decode_decompress(msg, 1))
    c1 = b"".join(_m._compress_encode(u[i], DU) for i in range(K))
    c2 = _m._compress_encode(v, DV)
    return c1 + c2


def _pke_decrypt(sk_pke: bytes, ct: bytes) -> bytes:
    s_hat = [_m._decode_poly12(sk_pke[i * POLY_BYTES:(i + 1) * POLY_BYTES]) for i in range(K)]
    block = N * DU // 8
    c1, c2 = ct[:C1_LEN], ct[C1_LEN:]
    u = [_m._decode_decompress(c1[i * block:(i + 1) * block], DU) for i in range(K)]
    v = _m._decode_decompress(c2, DV)
    acc = [0] * N
    for i in range(K):
        acc = _m._poly_add(acc, _m._mul_ntt(s_hat[i], _m._ntt(u[i])))
    w = [(a - b) % Q for a, b in zip(v, _m._intt(acc))]
    return _m._compress_encode(w, 1)


# ---- public KEM API (mirrors kyber1024_py) ---------------------------------
def generate() -> tuple[bytes, bytes]:
    """Generate a Kyber1024 keypair. Returns ``(public_key, secret_key)``.

    Sizes: public 1568, secret 3168 — matching the Rust binding, so keys are
    interchangeable between the two implementations.
    """
    import os

    d = os.urandom(SEED_LEN)
    z = os.urandom(32)
    pk, sk_pke = _pke_keygen(d)
    sk = sk_pke + pk + _H(pk) + z
    return pk, sk


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Encapsulate to ``public_key``. Returns ``(ciphertext, shared_secret)``."""
    if len(public_key) != PUBLIC_KEY_LEN:
        raise ValueError(f"public_key must be {PUBLIC_KEY_LEN} bytes")
    import os

    m = _H(os.urandom(32))                      # entropy_preprocess
    shared, coins = _G(m + _H(public_key))
    ct = _pke_encrypt(public_key, m, coins)
    ss = _kdf(shared + _H(ct))
    return ct, ss


def decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate ``ciphertext`` with ``secret_key`` → 32-byte shared secret."""
    if len(secret_key) != SECRET_KEY_LEN:
        raise ValueError(f"secret_key must be {SECRET_KEY_LEN} bytes")
    if len(ciphertext) != CIPHERTEXT_LEN:
        raise ValueError(f"ciphertext must be {CIPHERTEXT_LEN} bytes")
    sk_pke = secret_key[:K * POLY_BYTES]
    pk = secret_key[K * POLY_BYTES:K * POLY_BYTES + PUBLIC_KEY_LEN]
    pk_hash = secret_key[K * POLY_BYTES + PUBLIC_KEY_LEN:K * POLY_BYTES + PUBLIC_KEY_LEN + 32]
    z = secret_key[K * POLY_BYTES + PUBLIC_KEY_LEN + 32:]
    m_prime = _pke_decrypt(sk_pke, ciphertext)
    shared, coins = _G(m_prime + pk_hash)
    ct_check = _pke_encrypt(pk, m_prime, coins)
    reject = _kdf(hashlib.shake_256(z + ciphertext).digest(32) + _H(ciphertext))
    if ct_check == ciphertext:
        return _kdf(shared + _H(ciphertext))
    return reject
