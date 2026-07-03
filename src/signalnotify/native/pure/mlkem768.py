"""Pure-Python ML-KEM-768 (FIPS-203) with the incremental split SPQR needs.

This replaces the Rust ``libcrux-ml-kem`` dependency used by the Sparse
Post-Quantum Ratchet (``spqr``). SPQR does not use ML-KEM's one-shot
``Encaps``: it splits encapsulation into two wire steps so the second public
key half can arrive later (see ``incremental_mlkem768.rs``). The pieces —
``hdr`` (pk1, 64 B), ``ek`` (pk2, 1152 B), ``ct1`` (960 B), ``ct2`` (128 B) and
the 32-byte shared secret — are all *standard* FIPS-203 ML-KEM-768 values, so
the whole thing is validated byte-for-byte against ``cryptography``'s
``MLKEM768`` in the test suite.

The only libcrux-specific artifact is the 2080-byte encapsulation *state*
(``es``): a keep-between-steps blob holding ``r_as_ntt`` and ``error2`` as raw
little-endian ``i16`` coefficients plus the 32-byte message. We reproduce that
exact layout so a ``PqRatchetState`` serialized by the Rust binding round-trips
through this code unchanged.

Naming follows FIPS-203: ``t_hat``/``s_hat`` are NTT-domain vectors, ``A_hat``
the sampled matrix, ``mu`` the decompressed message polynomial.
"""
from __future__ import annotations

import hashlib

Q = 3329
N = 256
K = 3
ETA1 = 2
ETA2 = 2
DU = 10
DV = 4

# Serialized sizes (bytes).
POLY_BYTES = 384                     # ByteEncode_12 of one ring element
EK_LEN = K * POLY_BYTES              # 1152  (pk2 = t_hat bytes)
HDR_LEN = 64                         # pk1  = rho(32) || H(ek)(32)
DK_LEN = K * POLY_BYTES + (EK_LEN + 32) + 32 + 32  # 2400: dk_pke|ek|H(ek)|z
C1_LEN = K * (N * DU // 8)           # 960
C2_LEN = N * DV // 8                 # 128
CT_LEN = C1_LEN + C2_LEN            # 1088
ES_LEN = (K + 1) * (N * 2) + 32      # 2080 (r_as_ntt||error2 i16 LE || m)
SS_LEN = 32
SEED_LEN = 64                        # d(32) || z(32)


# ---- NTT tables ------------------------------------------------------------
def _brv7(x: int) -> int:
    return int(f"{x:07b}"[::-1], 2)


_ZETAS = [pow(17, _brv7(i), Q) for i in range(128)]
_GAMMAS = [pow(17, 2 * _brv7(i) + 1, Q) for i in range(128)]
_INV_N = pow(128, Q - 2, Q)          # 128^-1 mod q, applied in inverse NTT


def _ntt(f: list[int]) -> list[int]:
    f = f[:]
    i = 1
    length = 128
    while length >= 2:
        start = 0
        while start < N:
            z = _ZETAS[i]
            i += 1
            for j in range(start, start + length):
                t = (z * f[j + length]) % Q
                f[j + length] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
            start += 2 * length
        length //= 2
    return f


def _intt(f: list[int]) -> list[int]:
    f = f[:]
    i = 127
    length = 2
    while length <= 128:
        start = 0
        while start < N:
            z = _ZETAS[i]
            i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = (z * (f[j + length] - t)) % Q
            start += 2 * length
        length *= 2
    return [(x * _INV_N) % Q for x in f]


def _basemul(a0, a1, b0, b1, g):
    c0 = (a0 * b0 + a1 * b1 * g) % Q
    c1 = (a0 * b1 + a1 * b0) % Q
    return c0, c1


def _mul_ntt(f: list[int], g: list[int]) -> list[int]:
    h = [0] * N
    for i in range(128):
        h[2 * i], h[2 * i + 1] = _basemul(
            f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1], _GAMMAS[i]
        )
    return h


def _poly_add(a, b):
    return [(x + y) % Q for x, y in zip(a, b)]


# ---- compression + byte (de)serialization ---------------------------------
def _compress(x: int, d: int) -> int:
    # round((2^d / q) * x) mod 2^d, ties impossible since q is odd
    return (((x << d) * 2 + Q) // (2 * Q)) & ((1 << d) - 1)


def _decompress(y: int, d: int) -> int:
    return (y * Q + (1 << (d - 1))) >> d


def _byte_encode(poly: list[int], d: int) -> bytes:
    bits = bytearray()
    acc = 0
    nbits = 0
    out = bytearray()
    for coeff in poly:
        acc |= (coeff & ((1 << d) - 1)) << nbits
        nbits += d
        while nbits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            nbits -= 8
    if nbits:
        out.append(acc & 0xFF)
    return bytes(out)


def _byte_decode(data: bytes, d: int) -> list[int]:
    out = []
    acc = 0
    nbits = 0
    mask = (1 << d) - 1
    idx = 0
    for _ in range(N):
        while nbits < d:
            acc |= data[idx] << nbits
            idx += 1
            nbits += 8
        out.append(acc & mask)
        acc >>= d
        nbits -= d
    return out


def _encode_poly12(poly: list[int]) -> bytes:
    return _byte_encode([c % Q for c in poly], 12)


def _decode_poly12(data: bytes) -> list[int]:
    return _byte_decode(data, 12)


def _compress_encode(poly: list[int], d: int) -> bytes:
    return _byte_encode([_compress(c % Q, d) for c in poly], d)


def _decode_decompress(data: bytes, d: int) -> list[int]:
    return [_decompress(y, d) for y in _byte_decode(data, d)]


# ---- sampling --------------------------------------------------------------
def _sample_ntt(seed: bytes, i: int, j: int) -> list[int]:
    xof = hashlib.shake_128(seed + bytes([i, j]))
    # Draw generously; rejection almost never needs a second squeeze.
    stream = xof.digest(3 * 256 + 96)
    out = []
    pos = 0
    while len(out) < N:
        if pos + 3 > len(stream):
            stream += hashlib.shake_128(seed + bytes([i, j])).digest(len(stream) + 168)
        b0, b1, b2 = stream[pos], stream[pos + 1], stream[pos + 2]
        pos += 3
        d1 = b0 | ((b1 & 0x0F) << 8)
        d2 = (b1 >> 4) | (b2 << 4)
        if d1 < Q:
            out.append(d1)
        if len(out) < N and d2 < Q:
            out.append(d2)
    return out


def _cbd(data: bytes, eta: int) -> list[int]:
    bits = []
    for byte in data:
        for k in range(8):
            bits.append((byte >> k) & 1)
    out = []
    for i in range(N):
        base = 2 * i * eta
        a = sum(bits[base + k] for k in range(eta))
        b = sum(bits[base + eta + k] for k in range(eta))
        out.append((a - b) % Q)
    return out


def _prf(eta: int, s: bytes, b: int) -> bytes:
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


def _G(data: bytes) -> tuple[bytes, bytes]:
    h = hashlib.sha3_512(data).digest()
    return h[:32], h[32:]


def _H(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def _J(data: bytes) -> bytes:
    return hashlib.shake_256(data).digest(32)


# ---- matrix helper ---------------------------------------------------------
def _gen_matrix(rho: bytes):
    # A_hat[i][j] = SampleNTT(rho, j, i): the XOF eats (column, row), per
    # FIPS-203 Algorithm 13 (validated byte-for-byte against pyca MLKEM768).
    return [[_sample_ntt(rho, j, i) for j in range(K)] for i in range(K)]


# ---- key generation --------------------------------------------------------
def _keygen_internal(d: bytes, z: bytes):
    rho, sigma = _G(d + bytes([K]))
    A = _gen_matrix(rho)
    s = [_cbd(_prf(ETA1, sigma, i), ETA1) for i in range(K)]
    e = [_cbd(_prf(ETA1, sigma, K + i), ETA1) for i in range(K)]
    s_hat = [_ntt(p) for p in s]
    e_hat = [_ntt(p) for p in e]
    # t_hat = A @ s_hat + e_hat
    t_hat = []
    for i in range(K):
        acc = [0] * N
        for j in range(K):
            acc = _poly_add(acc, _mul_ntt(A[i][j], s_hat[j]))
        t_hat.append(_poly_add(acc, e_hat[i]))
    ek_pke = b"".join(_encode_poly12(t_hat[i]) for i in range(K)) + rho
    dk_pke = b"".join(_encode_poly12(s_hat[i]) for i in range(K))
    dk = dk_pke + ek_pke + _H(ek_pke) + z
    return ek_pke, dk, t_hat, rho, s_hat


def generate(seed: bytes):
    """Generate an incremental keypair from a 64-byte seed (d || z).

    Returns ``(hdr, ek, dk)``: ``hdr`` = pk1 (rho || H(ek), 64 B), ``ek`` = pk2
    (t_hat bytes, 1152 B), ``dk`` = compressed key (FIPS-203 dk, 2400 B).
    """
    if len(seed) != SEED_LEN:
        raise ValueError(f"seed must be {SEED_LEN} bytes")
    d, z = seed[:32], seed[32:]
    ek_pke, dk, _t, rho, _s = _keygen_internal(d, z)
    hdr = rho + _H(ek_pke)
    ek = ek_pke[:EK_LEN]
    return hdr, ek, dk


# ---- incremental encapsulation ---------------------------------------------
def _es_pack(r_hat: list[list[int]], error2: list[int], m: bytes) -> bytes:
    out = bytearray()
    for poly in r_hat:
        for c in poly:
            out += (c % Q).to_bytes(2, "little")
    for c in error2:
        # error2 is small and signed in normal domain; store as i16 LE.
        v = c % Q
        if v >= Q // 2 + 1 or v > 2:  # map back to signed range [-2,2]
            v = v - Q
        out += (v & 0xFFFF).to_bytes(2, "little")
    out += m
    return bytes(out)


def _es_unpack(es: bytes):
    if len(es) != ES_LEN:
        raise ValueError(f"es must be {ES_LEN} bytes")
    r_hat = []
    pos = 0
    for _ in range(K):
        poly = []
        for _ in range(N):
            poly.append(int.from_bytes(es[pos:pos + 2], "little"))
            pos += 2
        r_hat.append(poly)
    error2 = []
    for _ in range(N):
        v = int.from_bytes(es[pos:pos + 2], "little", signed=True)
        error2.append(v % Q)
        pos += 2
    m = es[pos:pos + 32]
    return r_hat, error2, m


def encaps1(hdr: bytes, randomness: bytes):
    """First encapsulation step: needs only pk1 (hdr).

    Returns ``(ct1, es, shared_secret)``.
    """
    if len(hdr) != HDR_LEN:
        raise ValueError(f"hdr must be {HDR_LEN} bytes")
    rho, ek_hash = hdr[:32], hdr[32:]
    m = randomness
    shared_secret, r_coins = _G(m + ek_hash)
    A = _gen_matrix(rho)
    r = [_cbd(_prf(ETA1, r_coins, i), ETA1) for i in range(K)]
    e1 = [_cbd(_prf(ETA2, r_coins, K + i), ETA2) for i in range(K)]
    e2 = _cbd(_prf(ETA2, r_coins, 2 * K), ETA2)
    r_hat = [_ntt(p) for p in r]
    # u = NTT^-1(A^T @ r_hat) + e1
    u = []
    for i in range(K):
        acc = [0] * N
        for j in range(K):
            acc = _poly_add(acc, _mul_ntt(A[j][i], r_hat[j]))
        u.append(_poly_add(_intt(acc), e1[i]))
    ct1 = b"".join(_compress_encode(u[i], DU) for i in range(K))
    es = _es_pack(r_hat, e2, m)
    return ct1, es, shared_secret


def encaps2(ek: bytes, es: bytes) -> bytes:
    """Second encapsulation step: needs pk2 (ek) and the stored state."""
    if len(ek) != EK_LEN:
        raise ValueError(f"ek must be {EK_LEN} bytes")
    r_hat, e2, m = _es_unpack(es)
    t_hat = [_decode_poly12(ek[i * POLY_BYTES:(i + 1) * POLY_BYTES]) for i in range(K)]
    # v = NTT^-1(t_hat^T @ r_hat) + e2 + Decompress_1(Decode_1(m))
    acc = [0] * N
    for i in range(K):
        acc = _poly_add(acc, _mul_ntt(t_hat[i], r_hat[i]))
    v = _poly_add(_intt(acc), e2)
    mu = _decode_decompress(m, 1)
    v = _poly_add(v, mu)
    return _compress_encode(v, DV)


# ---- decapsulation ---------------------------------------------------------
def _pke_decrypt(dk_pke: bytes, ct1: bytes, ct2: bytes) -> bytes:
    s_hat = [_decode_poly12(dk_pke[i * POLY_BYTES:(i + 1) * POLY_BYTES]) for i in range(K)]
    block = N * DU // 8
    u = [_decode_decompress(ct1[i * block:(i + 1) * block], DU) for i in range(K)]
    v = _decode_decompress(ct2, DV)
    acc = [0] * N
    for i in range(K):
        acc = _poly_add(acc, _mul_ntt(s_hat[i], _ntt(u[i])))
    w = [(a - b) % Q for a, b in zip(v, _intt(acc))]
    return _compress_encode(w, 1)


def decaps(dk: bytes, ct1: bytes, ct2: bytes) -> bytes:
    """Decapsulate incremental ciphertext parts to the 32-byte shared secret."""
    if len(dk) != DK_LEN:
        raise ValueError(f"dk must be {DK_LEN} bytes")
    dk_pke = dk[:K * POLY_BYTES]
    ek_pke = dk[K * POLY_BYTES:K * POLY_BYTES + EK_LEN + 32]
    ek_hash = dk[K * POLY_BYTES + EK_LEN + 32:K * POLY_BYTES + EK_LEN + 64]
    z = dk[K * POLY_BYTES + EK_LEN + 64:]
    ct = ct1 + ct2
    m_prime = _pke_decrypt(dk_pke, ct1, ct2)
    shared_secret, r_coins = _G(m_prime + ek_hash)
    # Re-encrypt to check (implicit rejection).
    rho = ek_pke[EK_LEN:EK_LEN + 32]
    hdr = rho + ek_hash
    ct1_p, _es, _ss = encaps1(hdr, m_prime)
    ct2_p = encaps2(ek_pke[:EK_LEN], _es)
    if ct1_p + ct2_p == ct:
        return shared_secret
    return _J(z + ct)


# ---- header / ek consistency (validate_pk_bytes) ---------------------------
def ek_matches_header(ek: bytes, hdr: bytes) -> bool:
    """True if pk2 (ek) is consistent with pk1 (hdr): H(ek || rho) == hdr.hash."""
    if len(ek) != EK_LEN or len(hdr) != HDR_LEN:
        return False
    rho, ek_hash = hdr[:32], hdr[32:]
    if _H(ek + rho) != ek_hash:
        return False
    # Domain check: every decoded coefficient must be < q.
    for i in range(K):
        for c in _decode_poly12(ek[i * POLY_BYTES:(i + 1) * POLY_BYTES]):
            if c >= Q:
                return False
    return True
