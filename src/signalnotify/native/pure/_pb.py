"""A tiny declarative protobuf3 codec, just enough for SPQR state.

The Sparse Post-Quantum Ratchet serializes its state with ``prost`` (proto3).
To keep pure-Python states interoperable with the Rust binding, we re-encode
those exact messages here. Only the wire features SPQR uses are supported:
varints (uint32/uint64/bool/enum), length-delimited bytes, embedded messages,
and repeated bytes/messages. proto3 default-omission is honored so encodings
match ``prost`` closely (decoders are order- and default-tolerant regardless).

Messages are declared with a ``FIELDS`` table — ``(number, name, kind, sub)`` —
and the base class drives encode/decode generically. ``kind`` is one of
``u32 u64 bool enum bytes msg rep_bytes rep_msg``; ``sub`` names the nested
message class (as a string, resolved lazily) for ``msg``/``rep_msg``.
"""
from __future__ import annotations

# ---- wire primitives -------------------------------------------------------
WIRE_VARINT = 0
WIRE_LEN = 2
WIRE_I64 = 1
WIRE_I32 = 5


def enc_varint(n: int) -> bytes:
    if n < 0:
        n &= (1 << 64) - 1
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def dec_varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7


def _tag(field: int, wire: int) -> bytes:
    return enc_varint((field << 3) | wire)


def _skip(buf: bytes, pos: int, wire: int) -> int:
    if wire == WIRE_VARINT:
        _, pos = dec_varint(buf, pos)
    elif wire == WIRE_LEN:
        n, pos = dec_varint(buf, pos)
        pos += n
    elif wire == WIRE_I64:
        pos += 8
    elif wire == WIRE_I32:
        pos += 4
    else:
        raise ValueError(f"unknown wire type {wire}")
    return pos


def iter_fields(buf: bytes):
    """Yield ``(field_number, wire_type, value, next_pos)`` over a message."""
    pos = 0
    n = len(buf)
    while pos < n:
        tag, pos = dec_varint(buf, pos)
        field = tag >> 3
        wire = tag & 0x07
        if wire == WIRE_VARINT:
            val, pos = dec_varint(buf, pos)
        elif wire == WIRE_LEN:
            length, pos = dec_varint(buf, pos)
            val = buf[pos:pos + length]
            pos += length
        elif wire == WIRE_I64:
            val = buf[pos:pos + 8]
            pos += 8
        elif wire == WIRE_I32:
            val = buf[pos:pos + 4]
            pos += 4
        else:
            raise ValueError(f"unknown wire type {wire}")
        yield field, wire, val


_REGISTRY: dict[str, type] = {}


class Message:
    FIELDS: tuple = ()

    def __init_subclass__(cls, **kw):
        super().__init_subclass__(**kw)
        _REGISTRY[cls.__name__] = cls

    def __init__(self, **kw):
        # Initialize declared fields to type-appropriate defaults.
        for _num, name, kind, _sub in self.FIELDS:
            if kind in ("rep_bytes", "rep_msg"):
                setattr(self, name, [])
            elif kind in ("u32", "u64", "enum"):
                setattr(self, name, 0)
            elif kind == "bool":
                setattr(self, name, False)
            elif kind == "bytes":
                setattr(self, name, b"")
            else:  # msg
                setattr(self, name, None)
        for k, v in kw.items():
            setattr(self, k, v)

    # -- encode --------------------------------------------------------------
    def encode(self) -> bytes:
        out = bytearray()
        for num, name, kind, sub in self.FIELDS:
            val = getattr(self, name)
            if kind in ("u32", "u64", "enum"):
                if val:
                    out += _tag(num, WIRE_VARINT) + enc_varint(val)
            elif kind == "bool":
                if val:
                    out += _tag(num, WIRE_VARINT) + enc_varint(1)
            elif kind == "bytes":
                if val:
                    out += _tag(num, WIRE_LEN) + enc_varint(len(val)) + val
            elif kind == "msg":
                if val is not None:
                    body = val.encode()
                    out += _tag(num, WIRE_LEN) + enc_varint(len(body)) + body
            elif kind == "rep_bytes":
                for item in val:
                    out += _tag(num, WIRE_LEN) + enc_varint(len(item)) + item
            elif kind == "rep_msg":
                for item in val:
                    body = item.encode()
                    out += _tag(num, WIRE_LEN) + enc_varint(len(body)) + body
            else:
                raise ValueError(f"bad kind {kind}")
        return bytes(out)

    # -- decode --------------------------------------------------------------
    @classmethod
    def decode(cls, buf: bytes):
        obj = cls()
        by_num = {num: (name, kind, sub) for num, name, kind, sub in cls.FIELDS}
        for field, wire, val in iter_fields(buf):
            spec = by_num.get(field)
            if spec is None:
                continue  # unknown/forward-compat field: skip
            name, kind, sub = spec
            if kind in ("u32", "u64", "enum"):
                setattr(obj, name, val)
            elif kind == "bool":
                setattr(obj, name, bool(val))
            elif kind == "bytes":
                setattr(obj, name, bytes(val))
            elif kind == "msg":
                setattr(obj, name, _REGISTRY[sub].decode(val))
            elif kind == "rep_bytes":
                getattr(obj, name).append(bytes(val))
            elif kind == "rep_msg":
                getattr(obj, name).append(_REGISTRY[sub].decode(val))
        return obj
