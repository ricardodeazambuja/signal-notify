"""Pure-Python Sparse Post-Quantum Ratchet (SPQR), replacing ``spqr_py``.

SPQR is the post-quantum triple ratchet Signal wraps around the classic Double
Ratchet; modern linked devices mandate it and encrypt Note-to-Self sync with
it. This is a faithful port of ``SparsePostQuantumRatchet`` v1.5.1 (the commit
libsignal v0.96.4 pins), exposing the same three entry points the Rust binding
did — :func:`initial_state`, :func:`send`, :func:`recv` — with byte-compatible
protobuf state and wire messages, so an existing Rust-serialized session keeps
working unchanged.

Layers, mirroring the Rust crate:

* protobuf state messages (``proto/pq_ratchet.proto``) — declared with
  :mod:`._pb`;
* :class:`Authenticator` — HMAC-SHA256 header/ciphertext tags;
* :class:`Chain` — per-epoch symmetric key chains feeding the Double Ratchet;
* :class:`States` — the 11-state chunked send_ek/send_ct machine;
* the top-level version-negotiation + chain glue (``lib.rs``).

ML-KEM operations come from :mod:`.mlkem768`; erasure coding from
:mod:`.spqr_gf`.
"""
from __future__ import annotations

import hashlib
import hmac
import os

from . import mlkem768 as _mlkem
from ._pb import Message, dec_varint, enc_varint
from .spqr_gf import (
    PolyDecoder,
    PolyEncoder,
    PolynomialDecoder,
    PolynomialEncoder,
)

# ---- constants -------------------------------------------------------------
MACSIZE = 32
HEADER_SIZE = _mlkem.HDR_LEN            # 64
EK_SIZE = _mlkem.EK_LEN                 # 1152
CT1_SIZE = _mlkem.C1_LEN               # 960
CT2_SIZE = _mlkem.C2_LEN               # 128
SS_SIZE = 32

DEFAULT_MAX_JUMP = 25_000
DEFAULT_MAX_OOO = 2_000
EPOCHS_TO_KEEP_PRIOR_TO_SEND_EPOCH = 1

DIR_A2B = 0
DIR_B2A = 1
VERSION_V0 = 0
VERSION_V1 = 1

# HKDF / MAC domain labels (exact bytes from the Rust crate).
_L_AUTH_UPDATE = b"Signal_PQCKA_V1_MLKEM768:Authenticator Update"
_L_CT = b"Signal_PQCKA_V1_MLKEM768:ciphertext"
_L_HDR = b"Signal_PQCKA_V1_MLKEM768:ekheader"
_L_SCKA_KEY = b"Signal_PQCKA_V1_MLKEM768:SCKA Key"
_L_CHAIN_START = b"Signal PQ Ratchet V1 Chain  Start"   # two spaces, verbatim
_L_CHAIN_NEXT = b"Signal PQ Ratchet V1 Chain Next"
_L_CHAIN_ADD_EPOCH = b"Signal PQ Ratchet V1 Chain Add Epoch"

_ZERO32 = b"\x00" * 32


class SpqrError(Exception):
    """Any SPQR protocol failure (mirrors the Rust ``Error`` enum)."""


# ---- HKDF-SHA256 (RFC 5869) ------------------------------------------------
def _hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def _be8(n: int) -> bytes:
    return n.to_bytes(8, "big")


def _be4(n: int) -> bytes:
    return n.to_bytes(4, "big")


def _switch(direction: int) -> int:
    return DIR_B2A if direction == DIR_A2B else DIR_A2B


# ===========================================================================
# protobuf messages
# ===========================================================================
class ChainParamsPB(Message):
    FIELDS = ((1, "max_jump", "u32", None), (2, "max_ooo_keys", "u32", None))


class AuthenticatorPB(Message):
    FIELDS = ((1, "root_key", "bytes", None), (2, "mac_key", "bytes", None))


class EpochDirectionPB(Message):
    FIELDS = ((1, "ctr", "u32", None), (2, "next", "bytes", None),
              (3, "prev", "bytes", None))


class ChainEpochPB(Message):
    FIELDS = ((1, "send", "msg", "EpochDirectionPB"),
              (2, "recv", "msg", "EpochDirectionPB"))


class ChainPB(Message):
    FIELDS = (
        (1, "direction", "enum", None),
        (2, "current_epoch", "u64", None),
        (3, "links", "rep_msg", "ChainEpochPB"),
        (4, "next_root", "bytes", None),
        (5, "send_epoch", "u64", None),
        (6, "params", "msg", "ChainParamsPB"),
    )


# --- unchunked inner states ---
class UcKeysUnsampled(Message):
    FIELDS = ((1, "epoch", "u64", None), (2, "auth", "msg", "AuthenticatorPB"))


class UcHeaderSent(Message):
    FIELDS = ((1, "epoch", "u64", None), (2, "auth", "msg", "AuthenticatorPB"),
              (3, "ek", "bytes", None), (4, "dk", "bytes", None))


class UcEkSent(Message):
    FIELDS = ((1, "epoch", "u64", None), (2, "auth", "msg", "AuthenticatorPB"),
              (3, "dk", "bytes", None))


class UcEkSentCt1Received(Message):
    FIELDS = ((1, "epoch", "u64", None), (2, "auth", "msg", "AuthenticatorPB"),
              (3, "dk", "bytes", None), (4, "ct1", "bytes", None))


class UcNoHeaderReceived(Message):
    FIELDS = ((1, "epoch", "u64", None), (2, "auth", "msg", "AuthenticatorPB"))


class UcHeaderReceived(Message):
    FIELDS = ((1, "epoch", "u64", None), (2, "auth", "msg", "AuthenticatorPB"),
              (3, "hdr", "bytes", None))


class UcCt1Sent(Message):
    FIELDS = ((1, "epoch", "u64", None), (2, "auth", "msg", "AuthenticatorPB"),
              (3, "hdr", "bytes", None), (4, "es", "bytes", None),
              (5, "ct1", "bytes", None))


class UcCt1SentEkReceived(Message):
    FIELDS = ((1, "epoch", "u64", None), (2, "auth", "msg", "AuthenticatorPB"),
              (3, "es", "bytes", None), (4, "ek", "bytes", None),
              (5, "ct1", "bytes", None))


class UcCt2Sent(Message):
    FIELDS = ((1, "epoch", "u64", None), (2, "auth", "msg", "AuthenticatorPB"))


# --- chunked inner states ---
class ChKeysUnsampled(Message):
    FIELDS = ((1, "uc", "msg", "UcKeysUnsampled"),)


class ChKeysSampled(Message):
    FIELDS = ((1, "uc", "msg", "UcHeaderSent"),
              (2, "sending_hdr", "msg", "PolynomialEncoder"))


class ChHeaderSent(Message):
    FIELDS = ((1, "uc", "msg", "UcEkSent"),
              (2, "sending_ek", "msg", "PolynomialEncoder"),
              (3, "receiving_ct1", "msg", "PolynomialDecoder"))


class ChCt1Received(Message):
    FIELDS = ((1, "uc", "msg", "UcEkSentCt1Received"),
              (2, "sending_ek", "msg", "PolynomialEncoder"))


class ChEkSentCt1Received(Message):
    FIELDS = ((1, "uc", "msg", "UcEkSentCt1Received"),
              (3, "receiving_ct2", "msg", "PolynomialDecoder"))


class ChNoHeaderReceived(Message):
    FIELDS = ((1, "uc", "msg", "UcNoHeaderReceived"),
              (2, "receiving_hdr", "msg", "PolynomialDecoder"))


class ChHeaderReceived(Message):
    FIELDS = ((1, "uc", "msg", "UcHeaderReceived"),
              (2, "receiving_ek", "msg", "PolynomialDecoder"))


class ChCt1Sampled(Message):
    FIELDS = ((1, "uc", "msg", "UcCt1Sent"),
              (2, "sending_ct1", "msg", "PolynomialEncoder"),
              (3, "receiving_ek", "msg", "PolynomialDecoder"))


class ChEkReceivedCt1Sampled(Message):
    FIELDS = ((1, "uc", "msg", "UcCt1SentEkReceived"),
              (2, "sending_ct1", "msg", "PolynomialEncoder"))


class ChCt1Acknowledged(Message):
    FIELDS = ((1, "uc", "msg", "UcCt1Sent"),
              (2, "receiving_ek", "msg", "PolynomialDecoder"))


class ChCt2Sampled(Message):
    FIELDS = ((1, "uc", "msg", "UcCt2Sent"),
              (2, "sending_ct2", "msg", "PolynomialEncoder"))


class V1StatePB(Message):
    FIELDS = (
        (1, "keys_unsampled", "msg", "ChKeysUnsampled"),
        (2, "keys_sampled", "msg", "ChKeysSampled"),
        (3, "header_sent", "msg", "ChHeaderSent"),
        (4, "ct1_received", "msg", "ChCt1Received"),
        (5, "ek_sent_ct1_received", "msg", "ChEkSentCt1Received"),
        (6, "no_header_received", "msg", "ChNoHeaderReceived"),
        (7, "header_received", "msg", "ChHeaderReceived"),
        (8, "ct1_sampled", "msg", "ChCt1Sampled"),
        (9, "ek_received_ct1_sampled", "msg", "ChEkReceivedCt1Sampled"),
        (10, "ct1_acknowledged", "msg", "ChCt1Acknowledged"),
        (11, "ct2_sampled", "msg", "ChCt2Sampled"),
    )


class VersionNegotiationPB(Message):
    FIELDS = (
        (1, "auth_key", "bytes", None),
        (2, "direction", "enum", None),
        (3, "min_version", "enum", None),
        (4, "chain_params", "msg", "ChainParamsPB"),
    )


class PqRatchetStatePB(Message):
    FIELDS = (
        (1, "version_negotiation", "msg", "VersionNegotiationPB"),
        (2, "chain", "msg", "ChainPB"),
        (3, "v1", "msg", "V1StatePB"),
    )


# ===========================================================================
# Authenticator
# ===========================================================================
class Authenticator:
    __slots__ = ("root_key", "mac_key")

    def __init__(self, root_key=_ZERO32, mac_key=_ZERO32):
        self.root_key = root_key
        self.mac_key = mac_key

    @classmethod
    def new(cls, root_key: bytes, ep: int) -> "Authenticator":
        a = cls(_ZERO32, _ZERO32)
        a.update(ep, root_key)
        return a

    def update(self, ep: int, k: bytes) -> None:
        ikm = self.root_key + k
        info = _L_AUTH_UPDATE + _be8(ep)
        out = _hkdf(_ZERO32, ikm, info, 64)
        self.root_key = out[:32]
        self.mac_key = out[32:]

    def mac_ct(self, ep: int, ct: bytes) -> bytes:
        data = _L_CT + _be8(ep) + ct
        return hmac.new(self.mac_key, data, hashlib.sha256).digest()

    def mac_hdr(self, ep: int, hdr: bytes) -> bytes:
        data = _L_HDR + _be8(ep) + hdr
        return hmac.new(self.mac_key, data, hashlib.sha256).digest()

    def verify_ct(self, ep: int, ct: bytes, expected: bytes) -> None:
        if not hmac.compare_digest(expected, self.mac_ct(ep, ct)):
            raise SpqrError("ciphertext MAC verification failed")

    def verify_hdr(self, ep: int, hdr: bytes, expected: bytes) -> None:
        if not hmac.compare_digest(expected, self.mac_hdr(ep, hdr)):
            raise SpqrError("header MAC verification failed")

    def into_pb(self) -> AuthenticatorPB:
        return AuthenticatorPB(root_key=self.root_key, mac_key=self.mac_key)

    @classmethod
    def from_pb(cls, pb: AuthenticatorPB) -> "Authenticator":
        return cls(pb.root_key, pb.mac_key)


# ===========================================================================
# Chain
# ===========================================================================
class _KeyHistory:
    __slots__ = ("data",)

    def __init__(self, keys=None):
        self.data = keys if keys is not None else []   # list[(idx:int, key:bytes)]

    @staticmethod
    def _trim_size(max_ooo: int) -> int:
        return max_ooo * 11 // 10 + 1

    def add(self, idx: int, key: bytes) -> None:
        self.data.append((idx, key))

    def gc(self, current_key: int, max_ooo: int) -> None:
        if len(self.data) >= self._trim_size(max_ooo):
            horizon = current_key - max_ooo
            self.data = [(i, k) for (i, k) in self.data if i >= horizon]

    def clear(self) -> None:
        self.data = []

    def get(self, at: int, current_ctr: int, max_ooo: int) -> bytes:
        if at + max_ooo < current_ctr:
            raise SpqrError(f"key trimmed: {at}")
        for j, (i, k) in enumerate(self.data):
            if i == at:
                del self.data[j]
                return k
        raise SpqrError(f"key already requested: {at}")

    def serialize(self) -> bytes:
        out = bytearray()
        for i, k in self.data:
            out += _be4(i) + k
        return bytes(out)

    @classmethod
    def deserialize(cls, data: bytes) -> "_KeyHistory":
        keys = []
        for off in range(0, len(data), 36):
            i = int.from_bytes(data[off:off + 4], "big")
            keys.append((i, data[off + 4:off + 36]))
        return cls(keys)


class _EpochDir:
    __slots__ = ("ctr", "next", "prev")

    def __init__(self, ctr=0, next_key=b"", prev=None):
        self.ctr = ctr
        self.next = next_key
        self.prev = prev if prev is not None else _KeyHistory()

    @classmethod
    def new(cls, k: bytes) -> "_EpochDir":
        return cls(0, k, _KeyHistory())

    def _next_key_internal(self) -> tuple[int, bytes]:
        self.ctr += 1
        info = _be4(self.ctr) + _L_CHAIN_NEXT
        gen = _hkdf(_ZERO32, self.next, info, 64)
        self.next = gen[:32]
        return self.ctr, gen[32:64]

    def next_key(self) -> tuple[int, bytes]:
        return self._next_key_internal()

    def key(self, at: int, max_jump: int, max_ooo: int) -> bytes:
        if at > self.ctr:
            if at - self.ctr > max_jump:
                raise SpqrError(f"key jump: {self.ctr} - {at}")
        elif at < self.ctr:
            return self.prev.get(at, self.ctr, max_ooo)
        else:
            raise SpqrError(f"key already requested: {at}")
        if at > self.ctr + max_ooo:
            self.prev.clear()
        while at > self.ctr + 1:
            idx, k = self._next_key_internal()
            if self.ctr + max_ooo >= at:
                self.prev.add(idx, k)
        self.prev.gc(self.ctr, max_ooo)
        return self._next_key_internal()[1]

    def clear_next(self) -> None:
        self.next = b""

    def into_pb(self) -> EpochDirectionPB:
        return EpochDirectionPB(ctr=self.ctr, next=self.next,
                                prev=self.prev.serialize())

    @classmethod
    def from_pb(cls, pb: EpochDirectionPB) -> "_EpochDir":
        return cls(pb.ctr, pb.next, _KeyHistory.deserialize(pb.prev))


class Chain:
    __slots__ = ("dir", "current_epoch", "send_epoch", "links", "next_root",
                 "max_jump", "max_ooo")

    def __init__(self, direction, current_epoch, send_epoch, links, next_root,
                 max_jump, max_ooo):
        self.dir = direction
        self.current_epoch = current_epoch
        self.send_epoch = send_epoch
        self.links = links          # list[(send:_EpochDir, recv:_EpochDir)]
        self.next_root = next_root
        self.max_jump = max_jump
        self.max_ooo = max_ooo

    @staticmethod
    def _ced(gen: bytes, direction: int) -> _EpochDir:
        return _EpochDir.new(gen[32:64] if direction == DIR_A2B else gen[64:96])

    @classmethod
    def new(cls, initial_key: bytes, direction: int, max_jump: int,
            max_ooo: int) -> "Chain":
        gen = _hkdf(_ZERO32, initial_key, _L_CHAIN_START, 96)
        link = (cls._ced(gen, direction), cls._ced(gen, _switch(direction)))
        return cls(direction, 0, 0, [link], gen[0:32], max_jump, max_ooo)

    def add_epoch(self, epoch: int, secret: bytes) -> None:
        assert epoch == self.current_epoch + 1
        gen = _hkdf(self.next_root, secret, _L_CHAIN_ADD_EPOCH, 96)
        self.current_epoch = epoch
        self.next_root = gen[0:32]
        self.links.append((self._ced(gen, self.dir),
                           self._ced(gen, _switch(self.dir))))

    def _epoch_idx(self, epoch: int) -> int:
        if epoch > self.current_epoch:
            raise SpqrError(f"epoch out of range: {epoch}")
        back = self.current_epoch - epoch
        if back >= len(self.links):
            raise SpqrError(f"epoch out of range: {epoch}")
        return len(self.links) - 1 - back

    def send_key(self, epoch: int) -> tuple[int, bytes]:
        if epoch < self.send_epoch:
            raise SpqrError(f"send key epoch decreased ({self.send_epoch} -> {epoch})")
        idx = self._epoch_idx(epoch)
        if self.send_epoch != epoch:
            self.send_epoch = epoch
            while idx > EPOCHS_TO_KEEP_PRIOR_TO_SEND_EPOCH:
                self.links.pop(0)
                idx -= 1
            for i in range(idx):
                self.links[i][0].clear_next()
        return self.links[idx][0].next_key()

    def recv_key(self, epoch: int, index: int) -> bytes:
        idx = self._epoch_idx(epoch)
        return self.links[idx][1].key(index, self.max_jump, self.max_ooo)

    def into_pb(self) -> ChainPB:
        links = [ChainEpochPB(send=s.into_pb(), recv=r.into_pb())
                 for (s, r) in self.links]
        params = ChainParamsPB(
            max_jump=0 if self.max_jump == DEFAULT_MAX_JUMP else self.max_jump,
            max_ooo_keys=0 if self.max_ooo == DEFAULT_MAX_OOO else self.max_ooo,
        )
        return ChainPB(direction=self.dir, current_epoch=self.current_epoch,
                       send_epoch=self.send_epoch, links=links,
                       next_root=self.next_root, params=params)

    @classmethod
    def from_pb(cls, pb: ChainPB) -> "Chain":
        if pb.params is None:
            raise SpqrError("chain missing params")
        max_jump = pb.params.max_jump or DEFAULT_MAX_JUMP
        max_ooo = pb.params.max_ooo_keys or DEFAULT_MAX_OOO
        links = [(_EpochDir.from_pb(l.send), _EpochDir.from_pb(l.recv))
                 for l in pb.links]
        return cls(pb.direction, pb.current_epoch, pb.send_epoch, links,
                   pb.next_root, max_jump, max_ooo)

    @classmethod
    def from_version_negotiation(cls, vn: VersionNegotiationPB) -> "Chain":
        if vn.chain_params is None:
            raise SpqrError("chain not available")
        max_jump = vn.chain_params.max_jump or DEFAULT_MAX_JUMP
        max_ooo = vn.chain_params.max_ooo_keys or DEFAULT_MAX_OOO
        return cls.new(vn.auth_key, vn.direction, max_jump, max_ooo)


# ===========================================================================
# V1 chunked state machine
# ===========================================================================
# Payload / message-type tags (wire byte values from states/serialize.rs).
MT_NONE = 0
MT_HDR = 1
MT_EK = 2
MT_EK_CT1_ACK = 3
MT_CT1_ACK = 4
MT_CT1 = 5
MT_CT2 = 6


class SckaMessage:
    __slots__ = ("epoch", "mtype", "chunk")

    def __init__(self, epoch: int, mtype: int, chunk=None):
        self.epoch = epoch
        self.mtype = mtype
        self.chunk = chunk          # (index:int, data:bytes) or None

    def serialize(self, index: int) -> bytes:
        out = bytearray([VERSION_V1])
        out += enc_varint(self.epoch)
        out += enc_varint(index)
        out.append(self.mtype)
        if self.chunk is not None:
            cidx, data = self.chunk
            out += enc_varint(cidx)
            out += data
        return bytes(out)

    @classmethod
    def deserialize(cls, data: bytes) -> tuple["SckaMessage", int, int]:
        if not data or data[0] != VERSION_V1:
            raise SpqrError("message decode failed")
        pos = 1
        epoch, pos = dec_varint(data, pos)
        if epoch == 0:
            raise SpqrError("message decode failed")
        index, pos = dec_varint(data, pos)
        if index > 0xFFFFFFFF:
            raise SpqrError("message decode failed")
        if pos >= len(data):
            raise SpqrError("message decode failed")
        mtype = data[pos]
        pos += 1
        chunk = None
        if mtype in (MT_HDR, MT_EK, MT_EK_CT1_ACK, MT_CT1, MT_CT2):
            cidx, pos = dec_varint(data, pos)
            start = pos
            pos += 32
            if pos > len(data) or cidx > 0xFFFF:
                raise SpqrError("message decode failed")
            chunk = (cidx, data[start:pos])
        elif mtype not in (MT_NONE, MT_CT1_ACK):
            raise SpqrError("message decode failed")
        return cls(epoch, mtype, chunk), index, pos


# State kinds.
KEYS_UNSAMPLED = "keys_unsampled"
KEYS_SAMPLED = "keys_sampled"
HEADER_SENT = "header_sent"
CT1_RECEIVED = "ct1_received"
EK_SENT_CT1_RECEIVED = "ek_sent_ct1_received"
NO_HEADER_RECEIVED = "no_header_received"
HEADER_RECEIVED = "header_received"
CT1_SAMPLED = "ct1_sampled"
EK_RECEIVED_CT1_SAMPLED = "ek_received_ct1_sampled"
CT1_ACKNOWLEDGED = "ct1_acknowledged"
CT2_SAMPLED = "ct2_sampled"


def _mkinfo_scka(epoch: int) -> bytes:
    return _L_SCKA_KEY + _be8(epoch)


class States:
    """The chunked send_ek/send_ct state machine.

    A single object with a ``kind`` tag and the fields that state needs, rather
    than Rust's typestate structs. ``send``/``recv`` return
    ``(msg_or_None, epoch_secret_or_None)`` and mutate ``self`` in place where
    the Rust code moves between struct types.
    """

    __slots__ = ("kind", "epoch", "auth", "ek", "dk", "hdr", "es", "ct1",
                 "sending", "receiving")

    def __init__(self, kind, epoch, auth, ek=b"", dk=b"", hdr=b"", es=b"",
                 ct1=b"", sending=None, receiving=None):
        self.kind = kind
        self.epoch = epoch
        self.auth = auth
        self.ek = ek
        self.dk = dk
        self.hdr = hdr
        self.es = es
        self.ct1 = ct1
        self.sending = sending      # PolyEncoder
        self.receiving = receiving  # PolyDecoder

    # -- constructors --------------------------------------------------------
    @classmethod
    def init_a(cls, auth_key: bytes) -> "States":
        return cls(KEYS_UNSAMPLED, 1, Authenticator.new(auth_key, 1))

    @classmethod
    def init_b(cls, auth_key: bytes) -> "States":
        return cls(NO_HEADER_RECEIVED, 1, Authenticator.new(auth_key, 1),
                   receiving=PolyDecoder.new(HEADER_SIZE + MACSIZE))

    # -- send ----------------------------------------------------------------
    def send(self):
        """Return ``(SckaMessage, epoch_secret_or_None)`` and advance state."""
        k = self.kind
        e = self.epoch
        if k == KEYS_UNSAMPLED:
            hdr, ek, dk = _mlkem.generate(os.urandom(_mlkem.SEED_LEN))
            mac = self.auth.mac_hdr(e, hdr)
            enc = PolyEncoder.encode_bytes(hdr + mac)
            chunk = enc.next_chunk()
            self.kind, self.ek, self.dk, self.sending = KEYS_SAMPLED, ek, dk, enc
            return SckaMessage(e, MT_HDR, chunk), None
        if k == KEYS_SAMPLED:
            return SckaMessage(e, MT_HDR, self.sending.next_chunk()), None
        if k == HEADER_SENT:
            return SckaMessage(e, MT_EK, self.sending.next_chunk()), None
        if k == CT1_RECEIVED:
            return SckaMessage(e, MT_EK_CT1_ACK, self.sending.next_chunk()), None
        if k == EK_SENT_CT1_RECEIVED:
            return SckaMessage(e, MT_CT1_ACK), None
        if k == NO_HEADER_RECEIVED:
            return SckaMessage(e, MT_NONE), None
        if k == HEADER_RECEIVED:
            ct1, es, secret = _mlkem.encaps1(self.hdr, os.urandom(32))
            secret = _hkdf(_ZERO32, secret, _mkinfo_scka(e), 32)
            self.auth.update(e, secret)
            enc = PolyEncoder.encode_bytes(ct1)
            chunk = enc.next_chunk()
            self.kind, self.es, self.ct1, self.sending = CT1_SAMPLED, es, ct1, enc
            return SckaMessage(e, MT_CT1, chunk), (e, secret)
        if k == CT1_SAMPLED:
            return SckaMessage(e, MT_CT1, self.sending.next_chunk()), None
        if k == EK_RECEIVED_CT1_SAMPLED:
            return SckaMessage(e, MT_CT1, self.sending.next_chunk()), None
        if k == CT1_ACKNOWLEDGED:
            return SckaMessage(e, MT_NONE), None
        if k == CT2_SAMPLED:
            return SckaMessage(e, MT_CT2, self.sending.next_chunk()), None
        raise SpqrError(f"unknown state {k}")

    # -- helpers for send_ct2 ------------------------------------------------
    def _send_ct2(self):
        """From an ek+es+ct1 state, produce ct2 and enter CT2_SAMPLED."""
        ct2 = _mlkem.encaps2(self.ek, self.es)
        ct1_full = self.ct1 + ct2
        mac = self.auth.mac_ct(self.epoch, ct1_full)
        self.kind = CT2_SAMPLED
        self.sending = PolyEncoder.encode_bytes(ct2 + mac)
        self.ek = self.es = self.ct1 = self.hdr = b""
        self.receiving = None

    # -- recv ----------------------------------------------------------------
    def recv(self, msg: SckaMessage):
        """Return an ``epoch_secret_or_None``; advance state in place."""
        k = self.kind
        e = self.epoch
        me = msg.epoch
        # Epoch handling that is common: future epoch is an error except for
        # the CT2_SAMPLED roll-over; past epoch is a no-op.
        if k == CT2_SAMPLED:
            if me > e:
                if me == e + 1:
                    self.kind, self.epoch = KEYS_UNSAMPLED, e + 1
                    self.sending = None
                return None
            return None
        if me > e:
            raise SpqrError(f"epoch out of range: {me}")
        if me < e:
            return None

        # me == e
        if k == KEYS_UNSAMPLED:
            return None
        if k == KEYS_SAMPLED:
            if msg.mtype == MT_CT1:
                dec = PolyDecoder.new(CT1_SIZE)
                dec.add_chunk(*msg.chunk)
                enc = PolyEncoder.encode_bytes(self.ek)
                self.kind, self.sending, self.receiving = HEADER_SENT, enc, dec
                self.ek = b""
            return None
        if k == HEADER_SENT:
            if msg.mtype == MT_CT1:
                self.receiving.add_chunk(*msg.chunk)
                decoded = self.receiving.decoded_message()
                if decoded is not None:
                    self.kind, self.ct1, self.receiving = CT1_RECEIVED, decoded, None
            return None
        if k == CT1_RECEIVED:
            if msg.mtype == MT_CT2:
                dec = PolyDecoder.new(CT2_SIZE + MACSIZE)
                dec.add_chunk(*msg.chunk)
                self.kind, self.sending, self.receiving = EK_SENT_CT1_RECEIVED, None, dec
            return None
        if k == EK_SENT_CT1_RECEIVED:
            if msg.mtype == MT_CT2:
                self.receiving.add_chunk(*msg.chunk)
                decoded = self.receiving.decoded_message()
                if decoded is not None:
                    ct2 = decoded[:CT2_SIZE]
                    mac = decoded[CT2_SIZE:CT2_SIZE + MACSIZE]
                    ss = _mlkem.decaps(self.dk, self.ct1, ct2)
                    ss = _hkdf(_ZERO32, ss, _mkinfo_scka(e), 32)
                    self.auth.update(e, ss)
                    self.auth.verify_ct(e, self.ct1 + ct2, mac)
                    self.kind = NO_HEADER_RECEIVED
                    self.epoch = e + 1
                    self.dk = self.ct1 = b""
                    self.receiving = PolyDecoder.new(HEADER_SIZE + MACSIZE)
                    return (e, ss)
            return None
        if k == NO_HEADER_RECEIVED:
            if msg.mtype == MT_HDR:
                self.receiving.add_chunk(*msg.chunk)
                decoded = self.receiving.decoded_message()
                if decoded is not None:
                    hdr = decoded[:HEADER_SIZE]
                    mac = decoded[HEADER_SIZE:HEADER_SIZE + MACSIZE]
                    self.auth.verify_hdr(e, hdr, mac)
                    self.kind, self.hdr = HEADER_RECEIVED, hdr
                    self.receiving = PolyDecoder.new(EK_SIZE)
            return None
        if k == HEADER_RECEIVED:
            return None
        if k == CT1_SAMPLED:
            chunk, ack = None, False
            if msg.mtype == MT_EK:
                chunk, ack = msg.chunk, False
            elif msg.mtype == MT_EK_CT1_ACK:
                chunk, ack = msg.chunk, True
            if chunk is not None:
                self.receiving.add_chunk(*chunk)
                decoded = self.receiving.decoded_message()
                if decoded is not None:
                    if not _mlkem.ek_matches_header(decoded, self.hdr):
                        raise SpqrError("erroneous data received")
                    self.ek = decoded
                    if ack:
                        self._send_ct2()
                    else:
                        self.kind, self.receiving = EK_RECEIVED_CT1_SAMPLED, None
                        self.hdr = b""
                elif ack:
                    self.kind, self.sending = CT1_ACKNOWLEDGED, None
            return None
        if k == EK_RECEIVED_CT1_SAMPLED:
            if msg.mtype == MT_CT1_ACK or msg.mtype == MT_EK_CT1_ACK:
                self._send_ct2()
            return None
        if k == CT1_ACKNOWLEDGED:
            chunk = msg.chunk if msg.mtype in (MT_EK, MT_EK_CT1_ACK) else None
            if chunk is not None:
                self.receiving.add_chunk(*chunk)
                decoded = self.receiving.decoded_message()
                if decoded is not None:
                    if not _mlkem.ek_matches_header(decoded, self.hdr):
                        raise SpqrError("erroneous data received")
                    self.ek = decoded
                    self._send_ct2()
            return None
        raise SpqrError(f"unknown state {k}")

    # -- (de)serialization ---------------------------------------------------
    def into_pb(self) -> V1StatePB:
        pb = V1StatePB()
        auth = self.auth.into_pb()
        e = self.epoch
        if self.kind == KEYS_UNSAMPLED:
            pb.keys_unsampled = ChKeysUnsampled(uc=UcKeysUnsampled(epoch=e, auth=auth))
        elif self.kind == KEYS_SAMPLED:
            pb.keys_sampled = ChKeysSampled(
                uc=UcHeaderSent(epoch=e, auth=auth, ek=self.ek, dk=self.dk),
                sending_hdr=self.sending.into_pb())
        elif self.kind == HEADER_SENT:
            pb.header_sent = ChHeaderSent(
                uc=UcEkSent(epoch=e, auth=auth, dk=self.dk),
                sending_ek=self.sending.into_pb(),
                receiving_ct1=self.receiving.into_pb())
        elif self.kind == CT1_RECEIVED:
            pb.ct1_received = ChCt1Received(
                uc=UcEkSentCt1Received(epoch=e, auth=auth, dk=self.dk, ct1=self.ct1),
                sending_ek=self.sending.into_pb())
        elif self.kind == EK_SENT_CT1_RECEIVED:
            pb.ek_sent_ct1_received = ChEkSentCt1Received(
                uc=UcEkSentCt1Received(epoch=e, auth=auth, dk=self.dk, ct1=self.ct1),
                receiving_ct2=self.receiving.into_pb())
        elif self.kind == NO_HEADER_RECEIVED:
            pb.no_header_received = ChNoHeaderReceived(
                uc=UcNoHeaderReceived(epoch=e, auth=auth),
                receiving_hdr=self.receiving.into_pb())
        elif self.kind == HEADER_RECEIVED:
            pb.header_received = ChHeaderReceived(
                uc=UcHeaderReceived(epoch=e, auth=auth, hdr=self.hdr),
                receiving_ek=self.receiving.into_pb())
        elif self.kind == CT1_SAMPLED:
            pb.ct1_sampled = ChCt1Sampled(
                uc=UcCt1Sent(epoch=e, auth=auth, hdr=self.hdr, es=self.es, ct1=self.ct1),
                sending_ct1=self.sending.into_pb(),
                receiving_ek=self.receiving.into_pb())
        elif self.kind == EK_RECEIVED_CT1_SAMPLED:
            pb.ek_received_ct1_sampled = ChEkReceivedCt1Sampled(
                uc=UcCt1SentEkReceived(epoch=e, auth=auth, es=self.es, ek=self.ek, ct1=self.ct1),
                sending_ct1=self.sending.into_pb())
        elif self.kind == CT1_ACKNOWLEDGED:
            pb.ct1_acknowledged = ChCt1Acknowledged(
                uc=UcCt1Sent(epoch=e, auth=auth, hdr=self.hdr, es=self.es, ct1=self.ct1),
                receiving_ek=self.receiving.into_pb())
        elif self.kind == CT2_SAMPLED:
            pb.ct2_sampled = ChCt2Sampled(
                uc=UcCt2Sent(epoch=e, auth=auth),
                sending_ct2=self.sending.into_pb())
        else:
            raise SpqrError(f"unknown state {self.kind}")
        return pb

    @classmethod
    def from_pb(cls, pb: V1StatePB) -> "States":
        def auth_of(uc):
            return Authenticator.from_pb(uc.auth)

        if pb.keys_unsampled is not None:
            uc = pb.keys_unsampled.uc
            return cls(KEYS_UNSAMPLED, uc.epoch, auth_of(uc))
        if pb.keys_sampled is not None:
            uc = pb.keys_sampled.uc
            return cls(KEYS_SAMPLED, uc.epoch, auth_of(uc), ek=uc.ek, dk=uc.dk,
                       sending=PolyEncoder.from_pb(pb.keys_sampled.sending_hdr))
        if pb.header_sent is not None:
            uc = pb.header_sent.uc
            return cls(HEADER_SENT, uc.epoch, auth_of(uc), dk=uc.dk,
                       sending=PolyEncoder.from_pb(pb.header_sent.sending_ek),
                       receiving=PolyDecoder.from_pb(pb.header_sent.receiving_ct1))
        if pb.ct1_received is not None:
            uc = pb.ct1_received.uc
            return cls(CT1_RECEIVED, uc.epoch, auth_of(uc), dk=uc.dk, ct1=uc.ct1,
                       sending=PolyEncoder.from_pb(pb.ct1_received.sending_ek))
        if pb.ek_sent_ct1_received is not None:
            uc = pb.ek_sent_ct1_received.uc
            return cls(EK_SENT_CT1_RECEIVED, uc.epoch, auth_of(uc), dk=uc.dk, ct1=uc.ct1,
                       receiving=PolyDecoder.from_pb(pb.ek_sent_ct1_received.receiving_ct2))
        if pb.no_header_received is not None:
            uc = pb.no_header_received.uc
            return cls(NO_HEADER_RECEIVED, uc.epoch, auth_of(uc),
                       receiving=PolyDecoder.from_pb(pb.no_header_received.receiving_hdr))
        if pb.header_received is not None:
            uc = pb.header_received.uc
            return cls(HEADER_RECEIVED, uc.epoch, auth_of(uc), hdr=uc.hdr,
                       receiving=PolyDecoder.from_pb(pb.header_received.receiving_ek))
        if pb.ct1_sampled is not None:
            uc = pb.ct1_sampled.uc
            return cls(CT1_SAMPLED, uc.epoch, auth_of(uc), hdr=uc.hdr, es=uc.es, ct1=uc.ct1,
                       sending=PolyEncoder.from_pb(pb.ct1_sampled.sending_ct1),
                       receiving=PolyDecoder.from_pb(pb.ct1_sampled.receiving_ek))
        if pb.ek_received_ct1_sampled is not None:
            uc = pb.ek_received_ct1_sampled.uc
            return cls(EK_RECEIVED_CT1_SAMPLED, uc.epoch, auth_of(uc), es=uc.es, ek=uc.ek, ct1=uc.ct1,
                       sending=PolyEncoder.from_pb(pb.ek_received_ct1_sampled.sending_ct1))
        if pb.ct1_acknowledged is not None:
            uc = pb.ct1_acknowledged.uc
            return cls(CT1_ACKNOWLEDGED, uc.epoch, auth_of(uc), hdr=uc.hdr, es=uc.es, ct1=uc.ct1,
                       receiving=PolyDecoder.from_pb(pb.ct1_acknowledged.receiving_ek))
        if pb.ct2_sampled is not None:
            uc = pb.ct2_sampled.uc
            return cls(CT2_SAMPLED, uc.epoch, auth_of(uc),
                       sending=PolyEncoder.from_pb(pb.ct2_sampled.sending_ct2))
        raise SpqrError("state decode failed")


# ===========================================================================
# top-level API (mirrors spqr_py: initial_state / send / recv)
# ===========================================================================
def _decode_state(data: bytes) -> PqRatchetStatePB:
    if not data:
        return PqRatchetStatePB()
    return PqRatchetStatePB.decode(data)


def _init_inner(direction: int, auth_key: bytes) -> V1StatePB:
    states = States.init_a(auth_key) if direction == DIR_A2B else States.init_b(auth_key)
    return states.into_pb()


def initial_state(auth_key: bytes, b2a: bool, max_jump: int, max_ooo_keys: int) -> bytes:
    """Create a fresh V1 SPQR state. Signature matches the Rust binding."""
    direction = DIR_B2A if b2a else DIR_A2B
    vn = VersionNegotiationPB(
        auth_key=auth_key,
        direction=direction,
        min_version=VERSION_V1,
        chain_params=ChainParamsPB(
            max_jump=0 if max_jump == DEFAULT_MAX_JUMP else max_jump,
            max_ooo_keys=0 if max_ooo_keys == DEFAULT_MAX_OOO else max_ooo_keys,
        ),
    )
    st = PqRatchetStatePB(version_negotiation=vn, v1=_init_inner(direction, auth_key))
    return st.encode()


def _chain_from(chain_pb, vn) -> Chain:
    if chain_pb is not None:
        return Chain.from_pb(chain_pb)
    if vn is not None:
        return Chain.from_version_negotiation(vn)
    raise SpqrError("chain not available")


def send(state: bytes) -> tuple[bytes, bytes, bytes | None]:
    """Produce the next outgoing message. Returns ``(new_state, msg, key)``."""
    sp = _decode_state(state)
    if sp.v1 is None:
        return b"", b"", None                       # V0 / disabled
    v1 = States.from_pb(sp.v1)
    msg, epoch_secret = v1.send()

    if sp.chain is not None:
        chain = Chain.from_pb(sp.chain)
    elif sp.version_negotiation is not None and sp.version_negotiation.min_version > VERSION_V0:
        chain = Chain.from_version_negotiation(sp.version_negotiation)
    else:
        chain = None

    if chain is None:
        index, msg_key, chain_pb = 0, b"", None
    else:
        if epoch_secret is not None:
            chain.add_epoch(epoch_secret[0], epoch_secret[1])
        index, msg_key = chain.send_key(msg.epoch - 1)
        chain_pb = chain.into_pb()

    msg_bytes = msg.serialize(index)
    new_state = PqRatchetStatePB(v1=v1.into_pb(),
                                 version_negotiation=sp.version_negotiation,
                                 chain=chain_pb)
    return new_state.encode(), msg_bytes, (msg_key or None)


def _msg_version(msg: bytes):
    if not msg:
        return VERSION_V0
    v = msg[0]
    return v if v in (VERSION_V0, VERSION_V1) else None


def _state_version(sp: PqRatchetStatePB) -> int:
    return VERSION_V1 if sp.v1 is not None else VERSION_V0


def recv(state: bytes, msg: bytes) -> tuple[bytes, bytes | None]:
    """Process an incoming message. Returns ``(new_state, key)``."""
    pre = _decode_state(state)
    v = _msg_version(msg)
    if v is None:
        return state, None                          # their version too high
    sv = _state_version(pre)
    if v >= sv:
        sp = pre
    else:
        # Negotiate down (only reachable if a V0 peer talks to a V1 state).
        if pre.version_negotiation is None:
            raise SpqrError("version mismatch after negotiation")
        vn = pre.version_negotiation
        if v < vn.min_version:
            raise SpqrError("minimum version")
        inner = _init_inner(vn.direction, vn.auth_key) if v == VERSION_V1 else None
        chain = _chain_from(pre.chain, vn)
        sp = PqRatchetStatePB(v1=inner, version_negotiation=None,
                              chain=chain.into_pb())

    if sp.v1 is None:
        return b"", None
    v1 = States.from_pb(sp.v1)
    scka_msg, index, _pos = SckaMessage.deserialize(msg)
    epoch_secret = v1.recv(scka_msg)

    msg_key_epoch = scka_msg.epoch - 1
    chain = _chain_from(sp.chain, sp.version_negotiation)
    if epoch_secret is not None:
        chain.add_epoch(epoch_secret[0], epoch_secret[1])
    if msg_key_epoch == 0 and index == 0:
        msg_key = b""
    else:
        msg_key = chain.recv_key(msg_key_epoch, index)

    new_state = PqRatchetStatePB(v1=v1.into_pb(), version_negotiation=None,
                                 chain=chain.into_pb())
    return new_state.encode(), (msg_key or None)
