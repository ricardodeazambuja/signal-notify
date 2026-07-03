"""Round-3 CRYSTALS-Kyber-1024 key encapsulation for Signal's PQXDH.

Signal's PQXDH uses **round-3 Kyber1024**, libsignal ``kem::KeyType`` byte
``0x08`` — NOT FIPS-203 ML-KEM (byte ``0x0A``). The two share key/ciphertext
sizes (1568 bytes) but are different algorithms with different shared secrets;
decapsulating a Kyber ciphertext with ML-KEM silently returns a wrong secret
(implicit rejection), surfacing only as a MAC failure downstream. The primitive
therefore comes from :mod:`kyber1024_py`, a thin binding around the *same*
``libcrux_ml_kem::kyber1024`` (the ``kyber`` feature) that libsignal itself uses,
so encaps/decaps are byte-identical to the phone. Build it with ``rust/build.sh``.

This module is the glue that:

* wraps keygen / encapsulate / decapsulate, and
* speaks Signal's on-wire serialization, which prefixes both the KEM public key
  and the KEM ciphertext with a single **type byte** (``0x08``). The public form
  is ``0x08 || ek`` (1 + 1568 = 1569 bytes) and is what gets *signed* and
  published; the ciphertext form is ``0x08 || ct`` (1569 bytes) and is what
  arrives inside a ``PreKeySignalMessage``.

The private key we persist is the full 3168-byte Kyber decapsulation key (Kyber
has no compact seed-reconstruction like ML-KEM's ``from_seed_bytes``).
"""
from __future__ import annotations

import os


def _kyber():
    """Return the Kyber1024 backend.

    Defaults to the pure-Python implementation (:mod:`.pure.kyber1024`), so no
    Rust toolchain is required. Set ``SIGNALNOTIFY_KEM_BACKEND=rust`` to use the
    ``kyber1024_py`` binding instead (kept as a differential-test oracle); keys
    and ciphertexts are byte-compatible between the two.
    """
    if os.environ.get("SIGNALNOTIFY_KEM_BACKEND") == "rust":
        import kyber1024_py
        return kyber1024_py
    from .pure import kyber1024
    return kyber1024


# libsignal kem::KeyType id for Kyber1024. Prefixes both the serialized public
# key and the serialized ciphertext on the wire.
KYBER_TYPE_BYTE = 0x08

# Fixed sizes for round-3 Kyber1024.
PUBLIC_KEY_LEN = 1568
SECRET_KEY_LEN = 3168
CIPHERTEXT_LEN = 1568
SHARED_SECRET_LEN = 32

# Serialized (type-prefixed) sizes.
PUBLIC_KEY_SERIALIZED_LEN = 1 + PUBLIC_KEY_LEN   # 1569
CIPHERTEXT_SERIALIZED_LEN = 1 + CIPHERTEXT_LEN   # 1569


def _strip_type_byte(data: bytes, raw_len: int) -> bytes:
    """Return the raw KEM bytes, tolerating an optional ``0x08`` type prefix.

    Accepts either the bare ``raw_len`` bytes or the ``0x08``-prefixed
    ``raw_len + 1`` form used on the Signal wire.
    """
    if len(data) == raw_len:
        return data
    if len(data) == raw_len + 1 and data[0] == KYBER_TYPE_BYTE:
        return data[1:]
    raise ValueError(
        f"unexpected KEM blob length {len(data)} (want {raw_len} or {raw_len + 1})"
    )


def generate_kyber_keypair() -> tuple[bytes, bytes]:
    """Generate a Kyber1024 keypair for a Kyber prekey.

    Returns ``(private_key, public_serialized)`` where ``private_key`` is the
    3168-byte decapsulation key to persist and ``public_serialized`` is
    ``0x08 || ek`` (1569 bytes) — the form to sign and publish.
    """
    pub_raw, priv = _kyber().generate()
    return priv, bytes([KYBER_TYPE_BYTE]) + pub_raw


def serialize_public(pub_raw: bytes) -> bytes:
    """Prefix a raw 1568-byte encapsulation key with the ``0x08`` type byte."""
    return bytes([KYBER_TYPE_BYTE]) + _strip_type_byte(pub_raw, PUBLIC_KEY_LEN)


def kyber_encapsulate(public_serialized: bytes) -> tuple[bytes, bytes]:
    """Sender side: encapsulate to a peer's KEM public key.

    ``public_serialized`` may be ``0x08``-prefixed or bare. Returns
    ``(shared_secret_32, ciphertext_serialized)`` where the ciphertext is
    ``0x08``-prefixed for the wire.
    """
    pub_raw = _strip_type_byte(public_serialized, PUBLIC_KEY_LEN)
    ct, shared_secret = _kyber().encapsulate(pub_raw)
    return shared_secret, bytes([KYBER_TYPE_BYTE]) + ct


def kyber_decapsulate(private_key: bytes, ciphertext_serialized: bytes) -> bytes:
    """Receiver side: decapsulate a ``PreKeySignalMessage`` Kyber ciphertext.

    ``ciphertext_serialized`` may be ``0x08``-prefixed (wire form) or bare.
    Returns the 32-byte shared secret.
    """
    ct_raw = _strip_type_byte(ciphertext_serialized, CIPHERTEXT_LEN)
    return _kyber().decapsulate(private_key, ct_raw)
