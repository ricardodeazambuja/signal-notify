"""Signal Double Ratchet + X3DH/PQXDH, both directions, in pure Python.

This is the responder-capable core the send-only chain in :mod:`messaging` never
implemented. It follows libsignal's constructions exactly (the phone runs
libsignal, so interop demands byte-for-byte agreement):

* **Session establishment** — classic X3DH *and* post-quantum PQXDH. As the
  *responder* (``accept_prekey``) we derive the same master secret the initiator
  computed, mixing in the ML-KEM-1024 shared secret when the ``PreKeySignalMessage``
  carries a Kyber ciphertext.
* **Double Ratchet** — a real receiving chain, DH-ratchet steps on a new ratchet
  public key, and a bounded skipped-message-key store, replacing "one ephemeral
  forever, increment a counter".

Key constants (verified against libsignal ``main`` and a live-linked device store):

* discontinuity prefix ``0xFF`` * 32 prepended to the DH concatenation;
* X3DH info ``WhisperText``; PQXDH info
  ``WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024`` (adds a third derived key we
  don't use — the SPQR "pq ratchet" key);
* DH-ratchet root KDF: HKDF salt = current root key, info ``WhisperRatchet``;
* chain step: msg key = ``HMAC(ck, 0x01)``, next ck = ``HMAC(ck, 0x02)``;
* message keys: HKDF info ``WhisperMessageKeys`` → 32-byte cipher key, 32-byte
  MAC key, 16-byte IV; AES-256-CBC + PKCS7;
* MAC: ``HMAC(mac_key, sender_ident || receiver_ident || serialized)[:8]`` where
  ``serialized`` is the version byte + SignalMessage protobuf (the version byte
  IS covered by the MAC);
* wire message version byte: ``0x33`` (v3, classic) / ``0x44`` (v4, PQXDH).

A ``Session`` holds raw bytes in memory; :func:`session_to_json` /
:func:`session_from_json` (de)serialize it for the account store.
"""
from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import proto as P
from .kem import kyber_decapsulate, kyber_encapsulate
from .messaging import (encode_prekey_signal_message, encode_signal_message,
                        encode_varint)
from .registration import decode_proto

# ---- constants -------------------------------------------------------------
DISCONTINUITY = b"\xff" * 32
INFO_X3DH = b"WhisperText"
INFO_PQXDH = b"WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024"
INFO_RATCHET = b"WhisperRatchet"
INFO_MSGKEYS = b"WhisperMessageKeys"
MAC_LEN = 8
CIPHERTEXT_VERSION_V3 = 0x33   # classic X3DH
CIPHERTEXT_VERSION_V4 = 0x44   # PQXDH
MAX_SKIP = 2000                # bounded skipped-message-key store

# SPQR (Sparse Post-Quantum Ratchet) chain params, matching libsignal
# ratchet.rs::spqr_chain_params + consts.rs at v0.96.4:
#   max_jump    = u32::MAX for a self session (Note-to-Self), else MAX_FORWARD_JUMPS
#   max_ooo_keys = MAX_MESSAGE_KEYS
SPQR_MAX_JUMP_SELF = 0xFFFFFFFF
SPQR_MAX_JUMP = 25000
SPQR_MAX_OOO_KEYS = 2000


def _spqr():
    """Return the SPQR backend.

    Defaults to the pure-Python implementation (:mod:`.pure.spqr`), so no Rust
    toolchain is required to decrypt messages from modern linked devices. Set
    ``SIGNALNOTIFY_SPQR_BACKEND=rust`` to use the ``spqr_py`` binding instead
    (kept as a differential-test oracle); protobuf state and wire messages are
    byte-compatible, so a session can move between the two mid-conversation.
    """
    if os.environ.get("SIGNALNOTIFY_SPQR_BACKEND") == "rust":
        import spqr_py
        return spqr_py
    from .pure import spqr
    return spqr


# ---- small key helpers -----------------------------------------------------
def _unprefix(pub: bytes) -> bytes:
    """Strip a Signal ``0x05`` type byte from a 33-byte public key."""
    if len(pub) == 33 and pub[0] == 0x05:
        return pub[1:]
    return pub


def _prefix(pub_raw: bytes) -> bytes:
    return b"\x05" + pub_raw if len(pub_raw) == 32 else pub_raw


def _dh(priv_bytes: bytes, pub_bytes: bytes) -> bytes:
    priv = X25519PrivateKey.from_private_bytes(priv_bytes)
    pub = X25519PublicKey.from_public_bytes(_unprefix(pub_bytes))
    return priv.exchange(pub)


def _gen_keypair() -> tuple[bytes, bytes]:
    priv = X25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()


def _hkdf(ikm: bytes, salt: bytes | None, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt,
                info=info).derive(ikm)


# ---- chain / message keys --------------------------------------------------
def chain_step(chain_key: bytes) -> tuple[bytes, bytes]:
    """Return ``(message_key, next_chain_key)`` from a chain key."""
    message_key = hmac.new(chain_key, b"\x01", hashlib.sha256).digest()
    next_chain_key = hmac.new(chain_key, b"\x02", hashlib.sha256).digest()
    return message_key, next_chain_key


def message_keys(message_key: bytes, salt: bytes | None = None) -> tuple[bytes, bytes, bytes]:
    """Derive ``(cipher_key32, mac_key32, iv16)`` from a message key.

    ``salt`` is the SPQR message key (libsignal ``MessageKeys::derive_keys``'s
    ``optional_salt``): when a session runs the post-quantum ratchet, HKDF is
    salted with it. ``None`` means classic derivation — HKDF with a salt of
    ``HashLen`` zeros, which is what ``optional_salt = None`` means in RFC 5869.
    """
    effective_salt = salt if salt is not None else b"\x00" * 32
    derived = _hkdf(message_key, effective_salt, INFO_MSGKEYS, 80)
    return derived[:32], derived[32:64], derived[64:80]


def kdf_rk(root_key: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """DH-ratchet root KDF → ``(new_root_key, chain_key)``."""
    derived = _hkdf(dh_out, root_key, INFO_RATCHET, 64)
    return derived[:32], derived[32:64]


# ---- X3DH / PQXDH ----------------------------------------------------------
def _derive_master(dh_concat: bytes,
                   kyber_ss: bytes | None) -> tuple[bytes, bytes, bytes | None]:
    """HKDF the X3DH/PQXDH secret into ``(root_key, chain_key, pqr_key)``.

    For PQXDH the HKDF emits 96 bytes = root ‖ chain ‖ pqr_key, matching
    libsignal ``HandshakeKeys::derive`` (the third slice is the SPQR auth key).
    Classic X3DH emits 64 bytes and has no ``pqr_key``.
    """
    if kyber_ss is not None:
        secret = DISCONTINUITY + dh_concat + kyber_ss
        out = _hkdf(secret, None, INFO_PQXDH, 96)
        return out[:32], out[32:64], out[64:96]
    secret = DISCONTINUITY + dh_concat
    out = _hkdf(secret, None, INFO_X3DH, 64)
    return out[:32], out[32:64], None


def x3dh_accept(our_identity_priv, our_signed_prekey_priv, their_identity_pub,
                their_base_pub, our_one_time_prekey_priv=None,
                our_kyber_priv=None, kyber_ciphertext=None):
    """Responder-side X3DH/PQXDH. Returns ``(root_key, chain_key)``.

    DH order matches libsignal ``pqxdh_accept``:
      DH1 = DH(our_signed_prekey, their_identity)
      DH2 = DH(our_identity,      their_base)
      DH3 = DH(our_signed_prekey, their_base)
      DH4 = DH(our_one_time_prekey, their_base)   [if a one-time prekey was used]
      Kyber shared secret appended last            [if a Kyber ciphertext present]
    """
    dh1 = _dh(our_signed_prekey_priv, their_identity_pub)
    dh2 = _dh(our_identity_priv, their_base_pub)
    dh3 = _dh(our_signed_prekey_priv, their_base_pub)
    dh_concat = dh1 + dh2 + dh3
    if our_one_time_prekey_priv is not None:
        dh_concat += _dh(our_one_time_prekey_priv, their_base_pub)
    kyber_ss = None
    if kyber_ciphertext:
        if our_kyber_priv is None:
            raise ValueError("Kyber ciphertext present but no Kyber private key")
        kyber_ss = kyber_decapsulate(our_kyber_priv, kyber_ciphertext)
    return _derive_master(dh_concat, kyber_ss)


def x3dh_initiate(our_identity_priv, our_base_priv, their_identity_pub,
                  their_signed_prekey_pub, their_one_time_prekey_pub=None,
                  their_kyber_pub=None):
    """Initiator-side X3DH/PQXDH (mirror of :func:`x3dh_accept`).

    Used to build test vectors and, later, to unify the send path. Returns
    ``(root_key, chain_key, pqr_key_or_None, kyber_ciphertext_or_None)``.
    """
    dh1 = _dh(our_identity_priv, their_signed_prekey_pub)
    dh2 = _dh(our_base_priv, their_identity_pub)
    dh3 = _dh(our_base_priv, their_signed_prekey_pub)
    dh_concat = dh1 + dh2 + dh3
    if their_one_time_prekey_pub is not None:
        dh_concat += _dh(our_base_priv, their_one_time_prekey_pub)
    kyber_ss = None
    kyber_ct = None
    if their_kyber_pub is not None:
        kyber_ss, kyber_ct = kyber_encapsulate(their_kyber_pub)
    root, chain, pqr_key = _derive_master(dh_concat, kyber_ss)
    return root, chain, pqr_key, kyber_ct


# ---- session ---------------------------------------------------------------
class Session:
    """In-memory Double Ratchet state for one (peer serviceId, deviceId).

    All key fields are raw ``bytes``. ``dhs`` is our current ratchet keypair,
    ``dhr`` the peer's current ratchet public key. ``ns``/``nr`` are the send /
    receive message counters, ``pn`` the length of the previous sending chain.
    ``skipped`` maps ``(dhr_pub_raw, n)`` → message key for out-of-order delivery.
    """

    __slots__ = ("rk", "dhs_priv", "dhs_pub", "dhr", "cks", "ckr",
                 "ns", "nr", "pn", "skipped", "our_identity", "their_identity",
                 "pqr_state")

    def __init__(self):
        self.rk = b""
        self.dhs_priv = b""
        self.dhs_pub = b""
        self.dhr = None
        self.cks = None
        self.ckr = None
        self.ns = 0
        self.nr = 0
        self.pn = 0
        self.skipped = {}  # (dhr_pub_raw_bytes, n) -> message_key
        self.our_identity = b""    # 0x05-prefixed
        self.their_identity = b""  # 0x05-prefixed
        self.pqr_state = None      # serialized SPQR state (bytes) or None (classic)


def _same_identity(a: bytes, b: bytes) -> bool:
    """True if two identity keys match (Note-to-Self shares one identity key)."""
    return bool(a) and bool(b) and _unprefix(a) == _unprefix(b)


def _spqr_init_state(pqr_key: bytes, b2a: bool, self_session: bool) -> bytes:
    max_jump = SPQR_MAX_JUMP_SELF if self_session else SPQR_MAX_JUMP
    return _spqr().initial_state(pqr_key, b2a, max_jump, SPQR_MAX_OOO_KEYS)


def _spqr_recv_salt(session: Session, pq_ratchet: bytes) -> bytes | None:
    """Advance the SPQR receive ratchet with the message's field-5 bytes.

    Returns the HKDF salt for this message's key derivation (``None`` if the
    session has no SPQR state — a classic session).
    """
    if not session.pqr_state:
        return None
    state, key = _spqr().recv(session.pqr_state, pq_ratchet or b"")
    session.pqr_state = state
    return key


def _dh_ratchet(session: Session, their_ratchet_pub: bytes) -> None:
    """Perform a DH-ratchet step on a newly seen peer ratchet key."""
    session.pn = session.ns
    session.ns = 0
    session.nr = 0
    session.dhr = _unprefix(their_ratchet_pub)
    session.rk, session.ckr = kdf_rk(session.rk, _dh(session.dhs_priv, session.dhr))
    session.dhs_priv, session.dhs_pub = _gen_keypair()
    session.rk, session.cks = kdf_rk(session.rk, _dh(session.dhs_priv, session.dhr))


def _skip_message_keys(session: Session, until: int) -> None:
    """Store message keys for messages [nr, until) skipped in the recv chain."""
    if session.ckr is None:
        return
    if session.nr + MAX_SKIP < until:
        raise ValueError(f"too many skipped messages ({until - session.nr} > {MAX_SKIP})")
    while session.nr < until:
        mk, session.ckr = chain_step(session.ckr)
        session.skipped[(session.dhr, session.nr)] = mk
        session.nr += 1
        # Bound the store.
        if len(session.skipped) > MAX_SKIP:
            session.skipped.pop(next(iter(session.skipped)))


# ---- message (de)serialization + crypto ------------------------------------
def _aes_cbc_decrypt(cipher_key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    dec = Cipher(algorithms.AES(cipher_key), modes.CBC(iv)).decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _aes_cbc_encrypt(cipher_key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    enc = Cipher(algorithms.AES(cipher_key), modes.CBC(iv)).encryptor()
    return enc.update(padded) + enc.finalize()


def _mac(mac_key, sender_ident, receiver_ident, serialized) -> bytes:
    return hmac.new(mac_key, sender_ident + receiver_ident + serialized,
                    hashlib.sha256).digest()[:MAC_LEN]


def _decrypt_with_message_key(mk, sender_ident, receiver_ident, serialized_msg,
                              salt=None):
    """Verify MAC and decrypt one serialized SignalMessage (``ver||proto||mac``).

    ``salt`` is the SPQR message key for this message (``None`` for classic).
    """
    if len(serialized_msg) < 1 + MAC_LEN:
        raise ValueError("SignalMessage too short")
    body, their_mac = serialized_msg[:-MAC_LEN], serialized_msg[-MAC_LEN:]
    cipher_key, mac_key, iv = message_keys(mk, salt=salt)
    expected = _mac(mac_key, sender_ident, receiver_ident, body)
    if not hmac.compare_digest(expected, their_mac):
        raise ValueError("bad MAC — message key / identity mismatch")
    fields = decode_proto(body[1:])  # strip version byte
    ciphertext = fields.get(P.SM_CIPHERTEXT, [b""])[0]
    return _aes_cbc_decrypt(cipher_key, iv, ciphertext)


def ratchet_decrypt(session: Session, serialized_msg: bytes,
                    version: int = CIPHERTEXT_VERSION_V4) -> bytes:
    """Decrypt one whisper (SignalMessage) against ``session``; advances state.

    ``serialized_msg`` = ``version_byte || SignalMessage protobuf || mac(8)``.
    """
    body = serialized_msg[:-MAC_LEN]
    fields = decode_proto(body[1:])
    their_ratchet = fields.get(P.SM_RATCHET_KEY, [b""])[0]
    counter = fields.get(P.SM_COUNTER, [0])[0]
    pq_ratchet = fields.get(P.SM_PQ_RATCHET, [b""])[0]
    their_ratchet_raw = _unprefix(their_ratchet)

    # SPQR: advance the post-quantum ratchet with this message's field-5 bytes to
    # get the HKDF salt for its message key. libsignal calls pq_ratchet_recv once
    # per message (session_cipher_legacy.rs), independent of the DH chain step.
    salt = _spqr_recv_salt(session, pq_ratchet)

    # Out-of-order message whose key we already stored?
    skip_key = (their_ratchet_raw, counter)
    if skip_key in session.skipped:
        mk = session.skipped.pop(skip_key)
        return _decrypt_with_message_key(mk, session.their_identity,
                                         session.our_identity, serialized_msg,
                                         salt=salt)

    # New ratchet key → DH-ratchet step (skipping the tail of the old chain).
    if session.dhr != their_ratchet_raw:
        previous_counter = fields.get(P.SM_PREVIOUS_COUNTER, [0])[0]
        _skip_message_keys(session, previous_counter)
        _dh_ratchet(session, their_ratchet)

    # Advance the receive chain to this message's counter.
    _skip_message_keys(session, counter)
    mk, session.ckr = chain_step(session.ckr)
    session.nr += 1
    return _decrypt_with_message_key(mk, session.their_identity,
                                     session.our_identity, serialized_msg,
                                     salt=salt)


def accept_prekey(account_keys: dict, prekey_content: bytes) -> tuple[Session, bytes]:
    """Establish a responder session from a ``PreKeySignalMessage`` and decrypt it.

    ``prekey_content`` is the Envelope content for a PREKEY message:
    ``version_byte || PreKeySignalMessage protobuf``. ``account_keys`` provides
    our privates (see :func:`account_keys_from_config`). Returns
    ``(session, plaintext)``.
    """
    outer_version = prekey_content[0]
    pk = decode_proto(prekey_content[1:])

    their_identity = pk.get(P.PKSM_IDENTITY_KEY, [b""])[0]   # 0x05||32
    base_key = pk.get(P.PKSM_BASE_KEY, [b""])[0]             # Alice's X3DH ephemeral
    inner = pk.get(P.PKSM_MESSAGE, [b""])[0]                 # ver||SignalMessage||mac
    signed_prekey_id = pk.get(P.PKSM_SIGNED_PRE_KEY_ID, [None])[0]
    pre_key_id = pk.get(P.PKSM_PRE_KEY_ID, [None])[0]
    kyber_prekey_id = pk.get(P.PKSM_KYBER_PRE_KEY_ID, [None])[0]
    kyber_ciphertext = (pk.get(P.PKSM_KYBER_CIPHERTEXT, [b""])[0]
                        if P.PKSM_KYBER_CIPHERTEXT in pk else None)

    signed_prekey_priv = account_keys["signed_prekeys"].get(signed_prekey_id)
    if signed_prekey_priv is None:
        raise ValueError(f"no signed prekey private for id {signed_prekey_id}")
    one_time_priv = None
    if pre_key_id is not None:
        one_time_priv = account_keys["one_time_prekeys"].get(pre_key_id)
    kyber_priv = None
    if kyber_ciphertext:
        kyber_priv = account_keys["kyber_prekeys"].get(kyber_prekey_id)

    root, chain, pqr_key = x3dh_accept(
        our_identity_priv=account_keys["identity_priv"],
        our_signed_prekey_priv=signed_prekey_priv,
        their_identity_pub=their_identity,
        their_base_pub=base_key,
        our_one_time_prekey_priv=one_time_priv,
        our_kyber_priv=kyber_priv,
        kyber_ciphertext=kyber_ciphertext,
    )

    # Bob's initial ratchet key pair is his signed prekey pair; his sending
    # chain is the X3DH chain key. No DH step happens until the first receive.
    session = Session()
    session.rk = root
    session.dhs_priv = signed_prekey_priv
    session.dhs_pub = X25519PrivateKey.from_private_bytes(
        signed_prekey_priv).public_key().public_bytes_raw()
    session.cks = chain
    session.our_identity = account_keys["identity_pub"]
    session.their_identity = their_identity if len(their_identity) == 33 else _prefix(their_identity)

    # PQXDH → seed the SPQR receive ratchet (we are the recipient, B2A). Must
    # happen before ratchet_decrypt, which consumes the first pq_ratchet message.
    if pqr_key is not None:
        self_session = _same_identity(session.our_identity, session.their_identity)
        session.pqr_state = _spqr_init_state(pqr_key, b2a=True, self_session=self_session)

    plaintext = ratchet_decrypt(session, inner, version=outer_version)
    return session, plaintext


# ---- initiator side (round-trip tests + future send unification) -----------
def init_sender_session(our_identity_priv, our_identity_pub, their_identity_pub,
                        their_signed_prekey_pub, their_one_time_prekey_pub=None,
                        their_kyber_pub=None):
    """Build an *initiator* session against a peer's prekey bundle.

    Returns ``(session, base_pub, kyber_ciphertext)`` — ``base_pub`` is our X3DH
    ephemeral (the ``PreKeySignalMessage.base_key``) and ``kyber_ciphertext`` is
    the Kyber ciphertext to embed (or ``None`` for classic X3DH).
    """
    base_priv, base_pub = _gen_keypair()
    root, chain, pqr_key, kyber_ct = x3dh_initiate(
        our_identity_priv=our_identity_priv,
        our_base_priv=base_priv,
        their_identity_pub=their_identity_pub,
        their_signed_prekey_pub=their_signed_prekey_pub,
        their_one_time_prekey_pub=their_one_time_prekey_pub,
        their_kyber_pub=their_kyber_pub,
    )
    session = Session()
    session.our_identity = our_identity_pub if len(our_identity_pub) == 33 else _prefix(our_identity_pub)
    session.their_identity = their_identity_pub if len(their_identity_pub) == 33 else _prefix(their_identity_pub)
    # Alice generates her first ratchet key and immediately ratchets against the
    # peer's signed prekey (their initial ratchet key) to derive her send chain.
    session.dhs_priv, session.dhs_pub = _gen_keypair()
    session.dhr = _unprefix(their_signed_prekey_pub)
    session.rk, session.cks = kdf_rk(root, _dh(session.dhs_priv, session.dhr))
    # PQXDH → seed the SPQR send ratchet (we are the initiator, A2B).
    if pqr_key is not None:
        self_session = _same_identity(session.our_identity, session.their_identity)
        session.pqr_state = _spqr_init_state(pqr_key, b2a=False, self_session=self_session)
    return session, base_pub, kyber_ct


def ratchet_encrypt(session: Session, plaintext: bytes,
                    version: int = CIPHERTEXT_VERSION_V4,
                    addresses: bytes | None = None) -> bytes:
    """Encrypt ``plaintext`` on the sending chain → ``version||proto||mac``.

    ``addresses`` is the optional SignalMessage field-6 sender/recipient binding
    (see :func:`messaging.encode_message_addresses`); real clients always send it.
    """
    mk, session.cks = chain_step(session.cks)
    # SPQR: emit a pq_ratchet message and salt the message key with its key.
    pq_ratchet = None
    salt = None
    if session.pqr_state:
        state, pq_ratchet, salt = _spqr().send(session.pqr_state)
        session.pqr_state = state
    cipher_key, mac_key, iv = message_keys(mk, salt=salt)
    ciphertext = _aes_cbc_encrypt(cipher_key, iv, plaintext)
    proto = encode_signal_message(
        ephemeral_pub=_prefix(session.dhs_pub), counter=session.ns,
        previous_counter=session.pn, ciphertext=ciphertext, pq_ratchet=pq_ratchet,
        addresses=addresses)
    session.ns += 1
    serialized = bytes([version]) + proto
    mac = _mac(mac_key, session.our_identity, session.their_identity, serialized)
    return serialized + mac


def frame_prekey_message(inner_serialized, base_pub, our_identity_pub,
                         registration_id, signed_prekey_id, pre_key_id=None,
                         kyber_prekey_id=None, kyber_ciphertext=None,
                         version=CIPHERTEXT_VERSION_V4) -> bytes:
    """Wrap an inner SignalMessage as Envelope content for a PREKEY message."""
    identity_pub = our_identity_pub if len(our_identity_pub) == 33 else _prefix(our_identity_pub)
    # All Curve25519 public keys go on the wire 0x05-prefixed (33 bytes). Our
    # base key is generated raw (32); prefix it or the peer's libsignal can't
    # parse it and decryption fails ("chat session refreshed").
    proto = encode_prekey_signal_message(
        registration_id=registration_id, prekey_id=pre_key_id,
        signed_prekey_id=signed_prekey_id, base_key=_prefix(base_pub),
        identity_key=identity_pub, message=inner_serialized)
    if kyber_prekey_id is not None and kyber_ciphertext is not None:
        proto += encode_varint((P.PKSM_KYBER_PRE_KEY_ID << 3) | 0) + encode_varint(kyber_prekey_id)
        proto += (encode_varint((P.PKSM_KYBER_CIPHERTEXT << 3) | 2)
                  + encode_varint(len(kyber_ciphertext)) + kyber_ciphertext)
    return bytes([version]) + proto


# ---- serialization ---------------------------------------------------------
def session_to_json(session: Session) -> dict:
    import base64

    def b(x):
        return base64.b64encode(x).decode() if x else None

    return {
        "rk": b(session.rk),
        "dhs_priv": b(session.dhs_priv),
        "dhs_pub": b(session.dhs_pub),
        "dhr": b(session.dhr),
        "cks": b(session.cks),
        "ckr": b(session.ckr),
        "ns": session.ns,
        "nr": session.nr,
        "pn": session.pn,
        "our_identity": b(session.our_identity),
        "their_identity": b(session.their_identity),
        "pqr_state": b(session.pqr_state),
        "skipped": [
            {"dhr": b(k[0]), "n": k[1], "mk": b(v)}
            for k, v in session.skipped.items()
        ],
    }


def session_from_json(data: dict) -> Session:
    import base64

    def d(x):
        return base64.b64decode(x) if x else (b"" if x == "" else None)

    s = Session()
    s.rk = d(data.get("rk")) or b""
    s.dhs_priv = d(data.get("dhs_priv")) or b""
    s.dhs_pub = d(data.get("dhs_pub")) or b""
    s.dhr = d(data.get("dhr"))
    s.cks = d(data.get("cks"))
    s.ckr = d(data.get("ckr"))
    s.ns = data.get("ns", 0)
    s.nr = data.get("nr", 0)
    s.pn = data.get("pn", 0)
    s.our_identity = d(data.get("our_identity")) or b""
    s.their_identity = d(data.get("their_identity")) or b""
    s.pqr_state = d(data.get("pqr_state"))
    s.skipped = {
        (base64.b64decode(e["dhr"]), e["n"]): base64.b64decode(e["mk"])
        for e in data.get("skipped", [])
    }
    return s


def account_keys_from_config(config_data: dict, identity="aci") -> dict:
    """Extract our responder privates from a saved account config.

    Returns a dict of ``identity_priv``/``identity_pub`` plus ``signed_prekeys``,
    ``kyber_prekeys`` and ``one_time_prekeys`` maps (keyId → private bytes) for
    the ``aci`` (default) or ``pni`` identity.
    """
    import base64

    def b64d(s):
        # Tolerate padding-stripped base64 (crypto.py strips '='; other writers don't).
        return base64.b64decode(s + "=" * (-len(s) % 4))

    acct = config_data["aciAccountData" if identity == "aci" else "pniAccountData"]
    identity_priv = b64d(acct["identityPrivateKey"])
    identity_pub = b64d(acct["identityPublicKey"])

    # Lookup pools include the ACTIVE key plus every not-yet-aged-out replaced
    # key (maintenance.refresh_prekeys rotates on Signal's 2-day cadence and
    # archives the old key for 30 days): a message can reference a key that was
    # rotated out after it was sent.
    signed_prekeys = {}
    for spk in [acct.get("signedPreKey")] + list(acct.get("previousSignedPreKeys") or []):
        if spk:
            signed_prekeys.setdefault(spk["keyId"], b64d(spk["priv"]))

    kyber_prekeys = {}
    for kpk in [acct.get("kyberPreKey")] + list(acct.get("previousKyberPreKeys") or []):
        if kpk:
            kyber_prekeys.setdefault(kpk["keyId"], b64d(kpk["priv"]))
    # One-time Kyber prekeys share the id space (kyberPreKeyId on the wire).
    for kid, priv in (acct.get("oneTimeKyberPreKeys") or {}).items():
        kyber_prekeys.setdefault(int(kid), b64d(priv))

    one_time_prekeys = {
        int(kid): b64d(priv)
        for kid, priv in (acct.get("oneTimePreKeys") or {}).items()
    }

    return {
        "identity_priv": identity_priv,
        "identity_pub": identity_pub,
        "signed_prekeys": signed_prekeys,
        "kyber_prekeys": kyber_prekeys,
        "one_time_prekeys": one_time_prekeys,
    }
