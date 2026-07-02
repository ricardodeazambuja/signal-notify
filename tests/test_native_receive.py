"""Native receive integration tests (synthetic keys, mocked websocket).

Builds a real Note-to-Self PREKEY envelope with the ratchet initiator, wraps it
in Envelope + WebSocketMessage framing, feeds it through a fake websocket, and
asserts the receive loop decrypts it, flags note_to_self, and acks.
"""
import base64
import json

import pytest

from signalnotify.native import ratchet, receive
from signalnotify.native.crypto import generate_linking_payload, generate_x25519_keypair
from signalnotify.native.messaging import (encode_bytes_field, encode_content,
                                           encode_data_message, encode_string_field,
                                           encode_sync_message, encode_sync_message_sent,
                                           encode_varint_field, pad_content)
from signalnotify.native.provisioning import save_account_config

ACI = "00000000-0000-0000-0000-0000000000aa"
PNI = "00000000-0000-0000-0000-0000000000bb"


def _envelope(etype, source, source_device, content, ts=111222333):
    # Envelope: type=1, timestamp=5, sourceDeviceId=7, content=8, sourceServiceId=11
    return (encode_varint_field(1, etype) + encode_varint_field(5, ts)
            + encode_varint_field(7, source_device) + encode_bytes_field(8, content)
            + encode_string_field(11, source))


def _ws_request(path, body=b"", req_id=1, verb="PUT"):
    # WebSocketRequestMessage: verb=1, path=2, body=3, id=4
    req = (encode_string_field(1, verb) + encode_string_field(2, path)
           + (encode_bytes_field(3, body) if body else b"") + encode_varint_field(4, req_id))
    # WebSocketMessage: type=1 (REQUEST), request=2
    return encode_varint_field(1, 1) + encode_bytes_field(2, req)


class FakeWS:
    def __init__(self, frames):
        self._frames = list(frames)
        self.sent = []

    async def recv(self):
        if self._frames:
            return self._frames.pop(0)
        import asyncio
        await asyncio.sleep(3600)  # block; loop should have stopped already

    async def send(self, data):
        self.sent.append(data)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def _fake_connect(frames):
    def _connect(url, headers, ssl_context=None):
        return FakeWS(frames)
    return _connect


def _linked_account(tmp_path, with_kyber=True, with_otk=True):
    """Create a natively-linked account on disk; return (config_path, bundle)."""
    id_priv, id_pub_raw = generate_x25519_keypair()
    id_pub = b"\x05" + id_pub_raw
    _, responder_keys = generate_linking_payload("00000000", id_priv, id_pub,
                                                 num_one_time_prekeys=5)
    cfg_path = save_account_config(
        data_dir=str(tmp_path), number="+15550100", aci=ACI, pni=PNI, password="pw",
        aci_identity_pub=id_pub, aci_identity_priv=id_priv,
        pni_identity_pub=b"\x05" + b"\x33" * 32, pni_identity_priv=b"\x44" * 32,
        profile_key=None, account_entropy_pool=None, media_root_backup_key=None,
        device_id=2, responder_keys=responder_keys)

    spk = responder_keys["aci_signed_prekey"]
    otk = responder_keys["one_time_prekeys"][0]
    kpk = responder_keys["aci_kyber_prekey"]

    def b64d(s):
        return base64.b64decode(s + "=" * (-len(s) % 4))

    bundle = {
        "id_priv": id_priv,
        "id_pub": id_pub,
        "signed_prekey_pub": b64d(spk["publicKey"]),
        "signed_prekey_id": spk["keyId"],
        "one_time_prekey_pub": b64d(otk["publicKey"]) if with_otk else None,
        "one_time_prekey_id": otk["keyId"] if with_otk else None,
        "kyber_pub": b64d(kpk["publicKey"]) if with_kyber else None,
        "kyber_id": kpk["keyId"] if with_kyber else None,
    }
    return cfg_path, bundle


def _note_to_self_prekey_content(bundle, text, ts, transport_padding=False):
    """Build the PREKEY Envelope content for a Note-to-Self sync from the phone."""
    session, base_pub, kyber_ct = ratchet.init_sender_session(
        our_identity_priv=bundle["id_priv"], our_identity_pub=bundle["id_pub"],
        their_identity_pub=bundle["id_pub"],
        their_signed_prekey_pub=bundle["signed_prekey_pub"],
        their_one_time_prekey_pub=bundle["one_time_prekey_pub"],
        their_kyber_pub=bundle["kyber_pub"])

    if transport_padding:
        # Real-phone style: Content with no field-8 padding, then 0x80 + 0x00s.
        dm = encode_data_message(text, ts)
        sent = encode_sync_message_sent(ACI, ts, dm)
        content_proto = encode_content(sync_message_bytes=encode_sync_message(sent))
        plaintext = content_proto + b"\x80" + b"\x00" * 20
    else:
        plaintext = pad_content(text, destination_aci=ACI, timestamp_ms=ts)

    inner = ratchet.ratchet_encrypt(session, plaintext, version=ratchet.CIPHERTEXT_VERSION_V4)
    return ratchet.frame_prekey_message(
        inner_serialized=inner, base_pub=base_pub, our_identity_pub=bundle["id_pub"],
        registration_id=555, signed_prekey_id=bundle["signed_prekey_id"],
        pre_key_id=bundle["one_time_prekey_id"], kyber_prekey_id=bundle["kyber_id"],
        kyber_ciphertext=kyber_ct, version=ratchet.CIPHERTEXT_VERSION_V4)


def test_receive_note_to_self_prekey(tmp_path, monkeypatch):
    cfg_path, bundle = _linked_account(tmp_path)
    content = _note_to_self_prekey_content(bundle, "reply from my phone", 111222333)
    frames = [
        _ws_request("/api/v1/message", _envelope(receive.TYPE_PREKEY, ACI, 1, content), 1),
        _ws_request("/api/v1/queue/empty", b"", 2),
    ]
    fake = FakeWS(frames)
    monkeypatch.setattr(receive, "_ws_connect", lambda *a, **k: fake)

    msgs = receive.receive(config_path=cfg_path, idle_timeout=5)
    assert len(msgs) == 1
    assert msgs[0].body == "reply from my phone"
    assert msgs[0].note_to_self is True
    assert msgs[0].source == ACI
    # Two acks: the message and the queue-empty marker.
    assert len(fake.sent) == 2
    # Session persisted for continuation.
    cfg = json.loads(open(cfg_path).read())
    assert f"{ACI}:1" in cfg["nativeRatchetSessions"]


def test_receive_transport_padding_variant(tmp_path, monkeypatch):
    # The phone pads with 0x80 + 0x00s, not our field-8 scheme.
    cfg_path, bundle = _linked_account(tmp_path)
    content = _note_to_self_prekey_content(bundle, "padded body", 999, transport_padding=True)
    frames = [_ws_request("/api/v1/message", _envelope(receive.TYPE_PREKEY, ACI, 1, content), 1),
              _ws_request("/api/v1/queue/empty", b"", 2)]
    monkeypatch.setattr(receive, "_ws_connect", lambda *a, **k: FakeWS(frames))
    msgs = receive.receive(config_path=cfg_path, idle_timeout=5)
    assert len(msgs) == 1 and msgs[0].body == "padded body" and msgs[0].note_to_self


def test_receive_drain_vs_persistent(tmp_path, monkeypatch):
    # Agent-chat scenario: connect, the queue is already empty (queue/empty
    # marker), and only THEN is the reply pushed on the same connection.
    cfg_path, bundle = _linked_account(tmp_path)

    # drain=True (one-shot) breaks on the leading queue/empty -> sees no reply.
    frames1 = [_ws_request("/api/v1/queue/empty", b"", 1),
               _ws_request("/api/v1/message",
                           _envelope(receive.TYPE_PREKEY, ACI, 1,
                                     _note_to_self_prekey_content(bundle, "late reply", 42)), 2)]
    monkeypatch.setattr(receive, "_ws_connect", lambda *a, **k: FakeWS(frames1))
    assert receive.receive(config_path=cfg_path, idle_timeout=5, drain=True) == []

    # drain=False stays connected past queue/empty and returns the pushed reply.
    frames2 = [_ws_request("/api/v1/queue/empty", b"", 1),
               _ws_request("/api/v1/message",
                           _envelope(receive.TYPE_PREKEY, ACI, 1,
                                     _note_to_self_prekey_content(bundle, "late reply", 43)), 2)]
    monkeypatch.setattr(receive, "_ws_connect", lambda *a, **k: FakeWS(frames2))
    msgs = receive.receive(config_path=cfg_path, drain=False, max_messages=1, wait=5)
    assert len(msgs) == 1 and msgs[0].body == "late reply"


def test_receive_note_to_self_filter(tmp_path, monkeypatch):
    cfg_path, bundle = _linked_account(tmp_path)
    content = _note_to_self_prekey_content(bundle, "n2s only", 222)
    frames = [_ws_request("/api/v1/message", _envelope(receive.TYPE_PREKEY, ACI, 1, content), 1),
              _ws_request("/api/v1/queue/empty", b"", 2)]
    monkeypatch.setattr(receive, "_ws_connect", lambda *a, **k: FakeWS(frames))
    msgs = receive.receive_note_to_self(config_path=cfg_path, idle_timeout=5)
    assert [m.body for m in msgs] == ["n2s only"]


def test_receive_whisper_after_prekey_continuation(tmp_path, monkeypatch):
    cfg_path, bundle = _linked_account(tmp_path)
    # Drive an initiator session and reuse it for a follow-up whisper message.
    session, base_pub, kyber_ct = ratchet.init_sender_session(
        our_identity_priv=bundle["id_priv"], our_identity_pub=bundle["id_pub"],
        their_identity_pub=bundle["id_pub"],
        their_signed_prekey_pub=bundle["signed_prekey_pub"],
        their_one_time_prekey_pub=bundle["one_time_prekey_pub"],
        their_kyber_pub=bundle["kyber_pub"])
    inner0 = ratchet.ratchet_encrypt(session, pad_content("first", destination_aci=ACI, timestamp_ms=1),
                                     version=ratchet.CIPHERTEXT_VERSION_V4)
    content0 = ratchet.frame_prekey_message(
        inner_serialized=inner0, base_pub=base_pub, our_identity_pub=bundle["id_pub"],
        registration_id=555, signed_prekey_id=bundle["signed_prekey_id"],
        pre_key_id=bundle["one_time_prekey_id"], kyber_prekey_id=bundle["kyber_id"],
        kyber_ciphertext=kyber_ct)
    inner1 = ratchet.ratchet_encrypt(session, pad_content("second", destination_aci=ACI, timestamp_ms=2),
                                     version=ratchet.CIPHERTEXT_VERSION_V4)

    # First deliver the prekey (establishes session), then the whisper.
    for content, etype, text in [(content0, receive.TYPE_PREKEY, "first"),
                                 (inner1, receive.TYPE_WHISPER, "second")]:
        frames = [_ws_request("/api/v1/message", _envelope(etype, ACI, 1, content), 1),
                  _ws_request("/api/v1/queue/empty", b"", 2)]
        monkeypatch.setattr(receive, "_ws_connect", lambda *a, **k: FakeWS(frames))
        msgs = receive.receive(config_path=cfg_path, idle_timeout=5)
        assert len(msgs) == 1 and msgs[0].body == text


def test_receipt_envelope_yields_no_message(tmp_path, monkeypatch):
    cfg_path, _ = _linked_account(tmp_path)
    frames = [_ws_request("/api/v1/message", _envelope(receive.TYPE_RECEIPT, ACI, 1, b""), 1),
              _ws_request("/api/v1/queue/empty", b"", 2)]
    fake = FakeWS(frames)
    monkeypatch.setattr(receive, "_ws_connect", lambda *a, **k: fake)
    msgs = receive.receive(config_path=cfg_path, idle_timeout=5)
    assert msgs == []
    assert len(fake.sent) == 2  # still acked both frames


def test_timeout_param_split(tmp_path, monkeypatch):
    """timeout= is a deprecated alias; the split params reject the wrong mode."""
    cfg_path, _ = _linked_account(tmp_path)
    frames = [_ws_request("/api/v1/queue/empty", b"", 1)]
    monkeypatch.setattr(receive, "_ws_connect", lambda *a, **k: FakeWS(frames))
    with pytest.warns(DeprecationWarning):
        receive.receive(config_path=cfg_path, timeout=1)
    with pytest.raises(ValueError):
        receive.receive(config_path=cfg_path, wait=5)  # wait is persistent-only
    with pytest.raises(ValueError):
        receive.receive(config_path=cfg_path, drain=False, idle_timeout=5)
