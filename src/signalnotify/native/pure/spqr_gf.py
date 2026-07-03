"""GF(2^16) erasure coding for SPQR's chunked key transport.

SPQR splits each large ML-KEM value (header, encapsulation key, ciphertexts)
into 32-byte *chunks* carried one-per-message, using a Reed-Solomon-style
Lagrange scheme over GF(2^16) so any sufficient subset of chunks reconstructs
the value. This mirrors ``encoding/gf.rs`` and ``encoding/polynomial.rs``.

Each 32-byte chunk holds 16 field elements (one per "poly"); element ``k`` of
chunk ``idx`` is ``poly_k(idx)``. The reduction polynomial is ``0x1100b`` — the
same primitive polynomial libsignal uses — so field arithmetic, hence every
encoded/decoded byte, matches the Rust implementation exactly.
"""
from __future__ import annotations

from ._pb import Message

# Primitive reduction polynomial for GF(2^16) (matches encoding/gf.rs).
_POLY = 0x1100B
NUM_POLYS = 16          # 32-byte chunk / 2 bytes per field element


# ---- field tables (generator alpha = 2) ------------------------------------
def _build_tables():
    order = (1 << 16) - 1
    exp = [0] * order
    log = [0] * (1 << 16)
    x = 1
    for i in range(order):
        exp[i] = x
        log[x] = i
        x <<= 1
        if x & (1 << 16):
            x ^= _POLY
    # exp has period 65535; duplicate so log[a]+log[b] (up to 2*(order-1))
    # indexes without a modulo.
    exp = exp + exp
    return exp, log


_EXP, _LOG = _build_tables()
_ORDER = (1 << 16) - 1


def gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("GF16 inverse of zero")
    return _EXP[_ORDER - _LOG[a]]


def gf_div(a: int, b: int) -> int:
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % _ORDER]


def gf_pow(a: int, e: int) -> int:
    if e == 0:
        return 1
    if a == 0:
        return 0
    return _EXP[(_LOG[a] * e) % _ORDER]


# ---- polynomial over GF(2^16) ----------------------------------------------
class Poly:
    """Coefficients little-endian: ``coeffs[i]`` multiplies ``x**i``."""

    __slots__ = ("coeffs",)

    def __init__(self, coeffs):
        self.coeffs = coeffs

    def compute_at(self, x: int) -> int:
        out = 0
        xp = 1
        for c in self.coeffs:
            if c:
                out ^= gf_mul(c, xp)
            xp = gf_mul(xp, x)
        return out

    def serialize(self) -> bytes:
        out = bytearray()
        for c in self.coeffs:
            out += c.to_bytes(2, "big")
        return bytes(out)

    @classmethod
    def deserialize(cls, data: bytes) -> "Poly":
        if not data or len(data) % 2:
            raise ValueError("invalid poly serialization")
        return cls([int.from_bytes(data[i:i + 2], "big") for i in range(0, len(data), 2)])

    @staticmethod
    def lagrange_interpolate(points) -> "Poly":
        """Interpolate ``[(x, y), ...]`` (distinct x) to a polynomial."""
        pts = list(points)
        n = len(pts)
        if n == 0:
            return Poly([])
        result = [0] * n
        for i in range(n):
            xi, yi = pts[i]
            # Build basis numerator PRODUCT_{j!=i}(x - xj) and denominator.
            basis = [1]
            denom = 1
            for j in range(n):
                if j == i:
                    continue
                xj = pts[j][0]
                # multiply basis by (x - xj) == (x + xj) in GF(2)
                new = [0] * (len(basis) + 1)
                for k, c in enumerate(basis):
                    new[k] ^= gf_mul(c, xj)   # c * xj  (the -xj term)
                    new[k + 1] ^= c           # c * x
                basis = new
                denom = gf_mul(denom, xi ^ xj)
            scale = gf_div(yi, denom)
            for k, c in enumerate(basis):
                result[k] ^= gf_mul(c, scale)
        return Poly(result)


# ---- protobuf messages for encoder/decoder state ---------------------------
class PolynomialEncoder(Message):
    FIELDS = (
        (1, "idx", "u32", None),
        (2, "pts", "rep_bytes", None),
        (3, "polys", "rep_bytes", None),
    )


class PolynomialDecoder(Message):
    FIELDS = (
        (1, "pts_needed", "u32", None),
        (2, "polys", "u32", None),
        (3, "pts", "rep_bytes", None),
        (4, "is_complete", "bool", None),
    )


# ---- chunk encoder ---------------------------------------------------------
class PolyEncoder:
    """Encodes a byte string into an unbounded stream of 32-byte chunks."""

    __slots__ = ("idx", "points", "polys")

    def __init__(self, points=None, polys=None, idx=0):
        self.idx = idx
        self.points = points   # list[16][GF16] or None
        self.polys = polys     # list[16] of Poly or None

    @classmethod
    def encode_bytes(cls, msg: bytes) -> "PolyEncoder":
        if len(msg) % 2:
            raise ValueError("message length must be even")
        points = [[] for _ in range(NUM_POLYS)]
        for i in range(0, len(msg), 2):
            poly = (i // 2) % NUM_POLYS
            points[poly].append((msg[i] << 8) | msg[i + 1])
        return cls(points=points)

    def _point_at(self, poly: int, idx: int) -> int:
        if self.points is not None:
            if idx < len(self.points[poly]):
                return self.points[poly][idx]
            # Ran past stored samples: switch to polynomial form for all polys.
            polys = []
            for p in range(NUM_POLYS):
                pts = [(x, y) for x, y in enumerate(self.points[p])]
                polys.append(Poly.lagrange_interpolate(pts))
            self.polys = polys
            self.points = None
        return self.polys[poly].compute_at(idx)

    def chunk_at(self, idx: int) -> tuple[int, bytes]:
        out = bytearray()
        for i in range(NUM_POLYS):
            total = idx * NUM_POLYS + i
            poly = total % NUM_POLYS
            poly_idx = total // NUM_POLYS
            v = self._point_at(poly, poly_idx)
            out += v.to_bytes(2, "big")
        return idx, bytes(out)

    def next_chunk(self) -> tuple[int, bytes]:
        chunk = self.chunk_at(self.idx & 0xFFFF)
        self.idx = (self.idx + 1) & 0xFFFFFFFF
        return chunk

    # -- serialization -------------------------------------------------------
    def into_pb(self) -> PolynomialEncoder:
        pb = PolynomialEncoder(idx=self.idx)
        if self.points is not None:
            for p in range(NUM_POLYS):
                v = bytearray()
                for y in self.points[p]:
                    v += y.to_bytes(2, "big")
                pb.pts.append(bytes(v))
        else:
            for poly in self.polys:
                pb.polys.append(poly.serialize())
        return pb

    @classmethod
    def from_pb(cls, pb: PolynomialEncoder) -> "PolyEncoder":
        if pb.pts:
            if pb.polys or len(pb.pts) != NUM_POLYS:
                raise ValueError("invalid PolynomialEncoder")
            points = []
            for raw in pb.pts:
                if len(raw) % 2:
                    raise ValueError("invalid encoder points")
                points.append([int.from_bytes(raw[i:i + 2], "big")
                               for i in range(0, len(raw), 2)])
            return cls(points=points, idx=pb.idx)
        if len(pb.polys) == NUM_POLYS:
            polys = [Poly.deserialize(x) for x in pb.polys]
            return cls(polys=polys, idx=pb.idx)
        raise ValueError("invalid PolynomialEncoder")


# ---- chunk decoder ---------------------------------------------------------
class PolyDecoder:
    """Collects chunks until it can reconstruct the ``pts_needed`` elements."""

    __slots__ = ("pts_needed", "pts", "is_complete")

    def __init__(self, pts_needed: int, pts=None, is_complete=False):
        self.pts_needed = pts_needed
        # pts[poly] is a dict {x: y} kept sorted-by-x on read (first-write wins).
        self.pts = pts if pts is not None else [dict() for _ in range(NUM_POLYS)]
        self.is_complete = is_complete

    @classmethod
    def new(cls, len_bytes: int) -> "PolyDecoder":
        if len_bytes % 2:
            raise ValueError("message length must be even")
        return cls(pts_needed=len_bytes // 2)

    def _necessary(self, poly: int) -> int:
        per = self.pts_needed // NUM_POLYS
        rem = self.pts_needed % NUM_POLYS
        return per + 1 if poly < rem else per

    def add_chunk(self, index: int, data: bytes) -> None:
        for i in range(NUM_POLYS):
            total = index * NUM_POLYS + i
            poly = total % NUM_POLYS
            poly_idx = total // NUM_POLYS
            y = (data[i * 2] << 8) | data[i * 2 + 1]
            need = self._necessary(i)
            if poly_idx < need or len(self.pts[poly]) < need:
                self.pts[poly].setdefault(poly_idx, y)   # first-write wins

    def decoded_message(self):
        if self.is_complete:
            return None
        sorted_pts = []
        for i in range(NUM_POLYS):
            need = self._necessary(i)
            if len(self.pts[i]) < need:
                return None
            items = sorted(self.pts[i].items())[:need]
            sorted_pts.append(items)
        polys = [None] * NUM_POLYS
        out = bytearray()
        for i in range(self.pts_needed):
            poly = i % NUM_POLYS
            poly_idx = i // NUM_POLYS
            table = self.pts[poly]
            if poly_idx in table:
                y = table[poly_idx]
            else:
                if polys[poly] is None:
                    polys[poly] = Poly.lagrange_interpolate(sorted_pts[poly])
                y = polys[poly].compute_at(poly_idx)
            out += y.to_bytes(2, "big")
        return bytes(out)

    # -- serialization -------------------------------------------------------
    def into_pb(self) -> PolynomialDecoder:
        pb = PolynomialDecoder(pts_needed=self.pts_needed, polys=NUM_POLYS,
                               is_complete=self.is_complete)
        for i in range(NUM_POLYS):
            v = bytearray()
            for x, y in sorted(self.pts[i].items()):
                v += x.to_bytes(2, "big") + y.to_bytes(2, "big")
            pb.pts.append(bytes(v))
        return pb

    @classmethod
    def from_pb(cls, pb: PolynomialDecoder) -> "PolyDecoder":
        if len(pb.pts) != NUM_POLYS:
            raise ValueError("invalid PolynomialDecoder")
        pts = []
        for raw in pb.pts:
            if len(raw) % 4:
                raise ValueError("invalid decoder points")
            d = {}
            for i in range(0, len(raw), 4):
                x = int.from_bytes(raw[i:i + 2], "big")
                y = int.from_bytes(raw[i + 2:i + 4], "big")
                d.setdefault(x, y)
            pts.append(d)
        return cls(pts_needed=pb.pts_needed, pts=pts, is_complete=pb.is_complete)
