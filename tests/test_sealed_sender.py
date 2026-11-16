"""Sealed Sender v1 unwrap: round-trip + rejection of invalid envelopes.

We build real v1 envelopes with the same primitives libsignal's
``sealed_sender_encrypt_from_usmc`` uses, anchored to a synthetic server
certificate registered under a known signer id. The negative cases prove an
invalid / expired / malformed certificate, an unknown signer id, and a bad MAC
are rejected with :class:`SealedSenderError` — i.e. the caller quarantines them
instead of decrypting and keying a session off an unauthenticated sender.
"""
import hashlib
import hmac
import time
import uuid

import pytest

from signalnotify.native import ratchet, receive
from signalnotify.native import sealed_sender as SS
from signalnotify.native.crypto import generate_x25519_keypair, xed25519_sign
from signalnotify.native.messaging import (encode_bytes_field, encode_varint,
                                           encode_varint_field)
from signalnotify.native.ratchet import _dh, _hkdf
from signalnotify.native.sealed_sender import (SALT_PREFIX, SEALED_SENDER_V1,
                                               SealedSenderError, unwrap_v1)
from test_native_receive import (ACI, FakeWS, _envelope, _linked_account,
                                 _ws_request)

SIGNER_ID = 424242
SENDER_UUID = "11111111-2222-3333-4444-555555555555"


def _p33(pub):
    return pub if len(pub) == 33 else b"\x05" + pub


def _fixed64_field(tag, val):
    return encode_varint((tag << 3) | 1) + val.to_bytes(8, "little")


def _server_certificate(signer_id, server_pub, trust_root_priv):
    """A ServerCertificate {certificate: Certificate{id, key}, signature}."""
    cert = encode_varint_field(1, signer_id) + encode_bytes_field(2, _p33(server_pub))
    return encode_bytes_field(1, cert) + encode_bytes_field(2, xed25519_sign(trust_root_priv, cert))


def _sender_certificate(sender_uuid, device, sender_identity_pub, expires_ms,
                        signer_id, signing_priv):
    """A SenderCertificate signed by the server certificate's key."""
    body = (encode_varint_field(2, device)
            + _fixed64_field(3, expires_ms)
            + encode_bytes_field(4, _p33(sender_identity_pub))
            + encode_varint_field(8, signer_id)
            + encode_bytes_field(7, uuid.UUID(sender_uuid).bytes))
    return encode_bytes_field(1, body) + encode_bytes_field(2, xed25519_sign(signing_priv, body))


def _ctr_hmac_encrypt(plaintext, cipher_key, mac_key):
    body = SS._aes_ctr_decrypt(cipher_key, plaintext)  # AES-CTR is symmetric
    return body + hmac.new(mac_key, body, hashlib.sha256).digest()[:10]


def _seal(recipient_identity_pub, sender_identity_priv, sender_identity_pub,
          sender_cert, msg_type, inner):
    """Encrypt an UnidentifiedSenderMessageContent (Sealed Sender v1)."""
    usmc = (encode_varint_field(1, msg_type) + encode_bytes_field(2, sender_cert)
            + encode_bytes_field(3, inner))
    e_priv, e_pub = generate_x25519_keypair()
    our_pub = _p33(recipient_identity_pub)
    eph = _hkdf(_dh(e_priv, our_pub), SALT_PREFIX + our_pub + _p33(e_pub), b"", 96)
    chain_key, cipher_key, mac_key = eph[:32], eph[32:64], eph[64:96]
    enc_static = _ctr_hmac_encrypt(_p33(sender_identity_pub), cipher_key, mac_key)
    stat = _hkdf(_dh(sender_identity_priv, our_pub), chain_key + enc_static, b"", 96)
    enc_msg = _ctr_hmac_encrypt(usmc, stat[32:64], stat[64:96])
    usm = (encode_bytes_field(1, _p33(e_pub)) + encode_bytes_field(2, enc_static)
           + encode_bytes_field(3, enc_msg))
    return bytes([SEALED_SENDER_V1]) + usm


@pytest.fixture
def server(monkeypatch):
    """Register a synthetic server certificate under SIGNER_ID we control."""
    trust_root_priv, trust_root_pub = generate_x25519_keypair()
    server_priv, server_pub = generate_x25519_keypair()
    cert = _server_certificate(SIGNER_ID, server_pub, trust_root_priv)
    monkeypatch.setitem(SS.KNOWN_SERVER_CERTS, SIGNER_ID, cert)
    return {"priv": server_priv, "pub": server_pub, "cert": cert,
            "trust_root_pub": trust_root_pub}


def _build(server, *, expires_delta=3_600_000, signer_id=SIGNER_ID,
           signing_priv=None, cert_bytes=None, msg_type=2, inner=b"\x44inner"):
    our_priv, our_pub = generate_x25519_keypair()
    sender_priv, sender_pub = generate_x25519_keypair()
    if cert_bytes is None:
        cert_bytes = _sender_certificate(
            SENDER_UUID, 3, sender_pub, int(time.time() * 1000) + expires_delta,
            signer_id, signing_priv or server["priv"])
    sealed = _seal(our_pub, sender_priv, sender_pub, cert_bytes, msg_type, inner)
    account_keys = {"identity_priv": our_priv, "identity_pub": _p33(our_pub)}
    return account_keys, sealed, sender_pub


def test_unwrap_v1_round_trip(server):
    account_keys, sealed, sender_pub = _build(server, inner=b"\x44real-inner")
    res = unwrap_v1(account_keys, sealed)
    assert res["msg_type"] == 2
    assert res["sender_uuid"] == SENDER_UUID
    assert res["sender_device"] == 3
    assert res["inner"] == b"\x44real-inner"
    assert res["sender_identity"] == _p33(sender_pub)


def test_unwrap_v1_bad_mac(server):
    account_keys, sealed, _ = _build(server)
    tampered = sealed[:-1] + bytes([sealed[-1] ^ 0x01])
    with pytest.raises(SealedSenderError, match="MAC"):
        unwrap_v1(account_keys, tampered)


def test_unwrap_v1_invalid_certificate_signature(server):
    # The sender certificate is signed by a key that is not the server cert key.
    other_priv, _ = generate_x25519_keypair()
    account_keys, sealed, _ = _build(server, signing_priv=other_priv)
    with pytest.raises(SealedSenderError, match="signature invalid"):
        unwrap_v1(account_keys, sealed)


def test_unwrap_v1_expired_certificate(server):
    account_keys, sealed, _ = _build(server, expires_delta=-1000)
    with pytest.raises(SealedSenderError, match="expired"):
        unwrap_v1(account_keys, sealed)


def test_unwrap_v1_malformed_certificate(server):
    account_keys, sealed, _ = _build(server, cert_bytes=b"\xff\xff\xff")
    with pytest.raises(SealedSenderError, match="malformed"):
        unwrap_v1(account_keys, sealed)


def test_unwrap_v1_unknown_signer_id(server):
    account_keys, sealed, _ = _build(server, signer_id=0xBADBAD)
    with pytest.raises(SealedSenderError, match="unknown sealed-sender signer"):
        unwrap_v1(account_keys, sealed)


def test_unwrap_v1_unsupported_version(server):
    account_keys, _, _ = _build(server)
    with pytest.raises(SealedSenderError, match="not implemented"):
        unwrap_v1(account_keys, b"\x22garbage")


# ---- receive-loop integration ---------------------------------------------
def _stranger_prekey_content(sender_priv, sender_pub, bundle, text, ts):
    """A PREKEY envelope content from a *different* account to our bundle."""
    session, base_pub, kyber_ct = ratchet.init_sender_session(
        our_identity_priv=sender_priv, our_identity_pub=sender_pub,
        their_identity_pub=bundle["id_pub"],
        their_signed_prekey_pub=bundle["signed_prekey_pub"],
        their_one_time_prekey_pub=bundle["one_time_prekey_pub"],
        their_kyber_pub=bundle["kyber_pub"])
    # A plain DataMessage (not a Note-to-Self sync transcript).
    from signalnotify.native.messaging import encode_content, encode_data_message
    plaintext = encode_content(data_message_bytes=encode_data_message(text, ts))
    inner = ratchet.ratchet_encrypt(session, plaintext,
                                    version=ratchet.CIPHERTEXT_VERSION_V4)
    return ratchet.frame_prekey_message(
        inner_serialized=inner, base_pub=base_pub, our_identity_pub=sender_pub,
        registration_id=555, signed_prekey_id=bundle["signed_prekey_id"],
        pre_key_id=bundle["one_time_prekey_id"], kyber_prekey_id=bundle["kyber_id"],
        kyber_ciphertext=kyber_ct, version=ratchet.CIPHERTEXT_VERSION_V4)


def _sealed_envelope_for_account(server, bundle, sender_priv, sender_pub,
                                 sender_cert, msg_type, inner):
    return _seal(bundle["id_pub"], sender_priv, sender_pub, sender_cert,
                 msg_type, inner)


def test_receive_sealed_from_stranger(tmp_path, monkeypatch, server):
    cfg_path, bundle = _linked_account(tmp_path)
    sender_priv, sender_pub = generate_x25519_keypair()
    cert = _sender_certificate(SENDER_UUID, 3, sender_pub,
                               int(time.time() * 1000) + 3_600_000,
                               SIGNER_ID, server["priv"])
    inner = _stranger_prekey_content(sender_priv, sender_pub, bundle, "hi from a friend", 123)
    sealed = _sealed_envelope_for_account(server, bundle, sender_priv, sender_pub,
                                          cert, 1, inner)

    frames = [_ws_request("/api/v1/message",
                          _envelope(receive.TYPE_SEALED, "", 1, sealed), 1),
              _ws_request("/api/v1/queue/empty", b"", 2)]
    monkeypatch.setattr(receive, "_ws_connect", lambda *a, **k: FakeWS(frames))

    msgs = receive.receive(config_path=cfg_path, idle_timeout=5)
    assert [m.body for m in msgs] == ["hi from a friend"]
    assert msgs[0].source == SENDER_UUID
    assert msgs[0].note_to_self is False
    # Session keyed by the certified sender, not our own ACI.
    import json
    cfg = json.loads(open(cfg_path).read())
    assert f"{SENDER_UUID}:3" in cfg["nativeRatchetSessions"]
    assert not any(k.startswith(ACI) for k in cfg["nativeRatchetSessions"])


def test_receive_invalid_cert_quarantined(tmp_path, monkeypatch, server):
    cfg_path, bundle = _linked_account(tmp_path)
    sender_priv, sender_pub = generate_x25519_keypair()
    other_priv, _ = generate_x25519_keypair()
    cert = _sender_certificate(SENDER_UUID, 3, sender_pub,
                               int(time.time() * 1000) + 3_600_000,
                               SIGNER_ID, other_priv)  # wrong signer key
    sealed = _sealed_envelope_for_account(server, bundle, sender_priv, sender_pub,
                                          cert, 1, b"\x44anything")

    frames = [_ws_request("/api/v1/message",
                          _envelope(receive.TYPE_SEALED, "", 1, sealed), 1),
              _ws_request("/api/v1/queue/empty", b"", 2)]
    ws = FakeWS(frames)
    monkeypatch.setattr(receive, "_ws_connect", lambda *a, **k: ws)

    assert receive.receive(config_path=cfg_path, idle_timeout=5) == []
    assert len(ws.sent) == 2  # still acked (after quarantine)
    import json
    cfg = json.loads(open(cfg_path).read())
    # No session was created for the attacker-claimed key.
    assert not cfg.get("nativeRatchetSessions")
    qfile = tmp_path / (cfg_path.name + ".undecryptable.jsonl")
    assert "signature invalid" in qfile.read_text()


def test_receive_unsupported_sealed_type_quarantined(tmp_path, monkeypatch, server):
    cfg_path, bundle = _linked_account(tmp_path)
    sender_priv, sender_pub = generate_x25519_keypair()
    cert = _sender_certificate(SENDER_UUID, 3, sender_pub,
                               int(time.time() * 1000) + 3_600_000,
                               SIGNER_ID, server["priv"])
    # SENDERKEY_MESSAGE = 7: valid envelope, but we cannot decrypt it -> must be
    # quarantined, never acked-and-deleted.
    sealed = _sealed_envelope_for_account(server, bundle, sender_priv, sender_pub,
                                          cert, 7, b"\x00")
    frames = [_ws_request("/api/v1/message",
                          _envelope(receive.TYPE_SEALED, "", 1, sealed), 1),
              _ws_request("/api/v1/queue/empty", b"", 2)]
    monkeypatch.setattr(receive, "_ws_connect", lambda *a, **k: FakeWS(frames))

    assert receive.receive(config_path=cfg_path, idle_timeout=5) == []
    qfile = tmp_path / (cfg_path.name + ".undecryptable.jsonl")
    assert "unsupported inner message type 7" in qfile.read_text()


def test_receive_sealed_self_send_rejected(tmp_path, monkeypatch, server):
    # A sealed envelope from our OWN account/device would collide with the
    # Note-to-Self session key; libsignal rejects it (SealedSenderSelfSend).
    cfg_path, bundle = _linked_account(tmp_path)  # device_id == 2
    cert = _sender_certificate(ACI, 2, bundle["id_pub"],
                               int(time.time() * 1000) + 3_600_000,
                               SIGNER_ID, server["priv"])
    sealed = _seal(bundle["id_pub"], bundle["id_priv"], bundle["id_pub"], cert, 1, b"\x44x")
    frames = [_ws_request("/api/v1/message",
                          _envelope(receive.TYPE_SEALED, "", 1, sealed), 1),
              _ws_request("/api/v1/queue/empty", b"", 2)]
    monkeypatch.setattr(receive, "_ws_connect", lambda *a, **k: FakeWS(frames))

    assert receive.receive(config_path=cfg_path, idle_timeout=5) == []
    qfile = tmp_path / (cfg_path.name + ".undecryptable.jsonl")
    assert "self-send rejected" in qfile.read_text()


def test_receive_inner_identity_mismatch_quarantined(tmp_path, monkeypatch, server):
    # The certificate/encryptedStatic bind one identity, but the inner PreKey
    # message claims a different one: the inner identity key must match the
    # sender recovered from the certificate.
    cfg_path, bundle = _linked_account(tmp_path)
    sender_priv, sender_pub = generate_x25519_keypair()   # cert + encryptedStatic
    inner_priv, inner_pub = generate_x25519_keypair()     # inner PreKey identity
    cert = _sender_certificate(SENDER_UUID, 3, sender_pub,
                               int(time.time() * 1000) + 3_600_000,
                               SIGNER_ID, server["priv"])
    inner = _stranger_prekey_content(inner_priv, inner_pub, bundle, "x", 1)
    sealed = _sealed_envelope_for_account(server, bundle, sender_priv, sender_pub,
                                          cert, 1, inner)
    frames = [_ws_request("/api/v1/message",
                          _envelope(receive.TYPE_SEALED, "", 1, sealed), 1),
              _ws_request("/api/v1/queue/empty", b"", 2)]
    monkeypatch.setattr(receive, "_ws_connect", lambda *a, **k: FakeWS(frames))

    assert receive.receive(config_path=cfg_path, idle_timeout=5) == []
    qfile = tmp_path / (cfg_path.name + ".undecryptable.jsonl")
    assert "inner PreKey identity" in qfile.read_text()


def test_receive_malformed_inner_quarantined(tmp_path, monkeypatch, server):
    # A valid certificate but a malformed inner PreKey message must quarantine,
    # not raise an unhandled error that would wedge the receive loop.
    cfg_path, bundle = _linked_account(tmp_path)
    sender_priv, sender_pub = generate_x25519_keypair()
    cert = _sender_certificate(SENDER_UUID, 3, sender_pub,
                               int(time.time() * 1000) + 3_600_000,
                               SIGNER_ID, server["priv"])
    sealed = _sealed_envelope_for_account(server, bundle, sender_priv, sender_pub,
                                          cert, 1, b"")  # empty inner
    frames = [_ws_request("/api/v1/message",
                          _envelope(receive.TYPE_SEALED, "", 1, sealed), 1),
              _ws_request("/api/v1/queue/empty", b"", 2)]
    monkeypatch.setattr(receive, "_ws_connect", lambda *a, **k: FakeWS(frames))

    assert receive.receive(config_path=cfg_path, idle_timeout=5) == []
    qfile = tmp_path / (cfg_path.name + ".undecryptable.jsonl")
    assert "malformed inner message" in qfile.read_text()
