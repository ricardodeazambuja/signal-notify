import base64
import json
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from signalnotify.native.messaging import (
    encode_varint,
    encode_varint_field,
    encode_bytes_field,
    encode_string_field,
    pad_content,
    find_account_config,
    send_message_native,
)
from signalnotify.native.registration import SignalAPIError


def _kp():
    priv = X25519PrivateKey.generate()
    return priv.private_bytes_raw(), b"\x05" + priv.public_key().public_bytes_raw()


def test_varint_helpers():
    assert encode_varint(150) == b"\x96\x01"
    assert encode_varint_field(1, 150) == b"\x08\x96\x01"
    assert encode_bytes_field(2, b"hello") == b"\x12\x05hello"
    assert encode_string_field(3, "world") == b"\x1a\x05world"


def test_pad_content():
    from signalnotify.native.receive import _strip_push_padding

    for body, dest in [("hello", "test-aci"), ("hello direct message", None)]:
        padded = pad_content(body, destination_aci=dest, timestamp_ms=123456789)
        # Signal PushTransportDetails scheme: length is a multiple of the padding
        # block (80) minus one, and the plaintext is terminated by a 0x80 marker
        # followed only by 0x00 bytes -- NOT a protobuf padding field.
        assert (len(padded) + 1) % 80 == 0
        marker = padded.rfind(b"\x80")
        assert marker != -1
        assert set(padded[marker + 1:]) <= {0}
        # Stripping the transport padding must leave a Content with NO field 8
        # (field 8 is decryptionErrorMessage; padding there breaks display).
        content = _strip_push_padding(padded)
        i = 0
        top_fields = []
        while i < len(content):
            tag = content[i]; i += 1
            fn, wt = tag >> 3, tag & 7
            top_fields.append(fn)
            if wt == 2:
                ln = 0; sh = 0
                while content[i] & 0x80:
                    ln |= (content[i] & 0x7f) << sh; sh += 7; i += 1
                ln |= (content[i] & 0x7f) << sh; i += 1; i += ln
            elif wt == 0:
                while content[i] & 0x80:
                    i += 1
                i += 1
        assert 8 not in top_fields


def test_find_account_config(tmp_path):
    accounts_json = tmp_path / "accounts.json"
    accounts_data = {
        "accounts": [
            {"number": "+15550001", "uuid": "uuid1", "path": "+15550001.json"},
            {"number": "+15550002", "uuid": "uuid2", "path": "+15550002.json"}
        ]
    }
    with open(accounts_json, "w") as f:
        json.dump(accounts_data, f)

    (tmp_path / "+15550001.json").write_text("{}")
    (tmp_path / "+15550002.json").write_text("{}")

    assert find_account_config("+15550002", data_dir=str(tmp_path)) == (tmp_path / "+15550002.json")
    assert find_account_config(data_dir=str(tmp_path)) == (tmp_path / "+15550001.json")
    assert find_account_config("nonexistent", data_dir=str(tmp_path)) is None


def _config(tmp_path, device_id=2):
    our_priv, our_pub = _kp()
    config_data = {
        "number": "+15550001",
        "password": "my-password",
        "deviceId": device_id,
        "aciAccountData": {
            "serviceId": "our-aci-uuid",
            "registrationId": 1234,
            "identityPrivateKey": base64.b64encode(our_priv).decode(),
            "identityPublicKey": base64.b64encode(our_pub).decode(),
        },
    }
    path = tmp_path / "+15550001.json"
    path.write_text(json.dumps(config_data))
    return path


def _bundle(devices):
    _, rec_pub = _kp()
    return {"identityKey": base64.b64encode(rec_pub).decode(), "devices": devices}


def _device(device_id, reg_id, with_opk=True):
    _, spk_pub = _kp()
    dev = {
        "deviceId": device_id,
        "registrationId": reg_id,
        "signedPreKey": {"keyId": 999, "publicKey": base64.b64encode(spk_pub).decode(),
                         "signature": "mock-sig"},
    }
    if with_opk:
        _, opk_pub = _kp()
        dev["preKey"] = {"keyId": 888, "publicKey": base64.b64encode(opk_pub).decode()}
    return dev


@patch("signalnotify.native.messaging.make_request")
def test_send_message_native_new_session(mock_make_request, tmp_path):
    config_path = _config(tmp_path)
    bundle = _bundle([_device(1, 5678)])
    mock_make_request.side_effect = lambda path, method="GET", body=None, headers=None, base_url=None: (
        (bundle, {}) if method == "GET" else ({}, {}))

    ok = send_message_native(config_path, "Hello native Signal", recipient="rec-aci-uuid")
    assert ok is True

    calls = mock_make_request.call_args_list
    assert calls[0][0][0] == "/v2/keys/rec-aci-uuid/*"
    assert calls[1][0][0] == "/v1/messages/rec-aci-uuid"
    put_body = calls[1][1]["body"]
    assert put_body["destination"] == "rec-aci-uuid"
    msg = put_body["messages"][0]
    assert msg["destinationDeviceId"] == 1
    assert msg["destinationRegistrationId"] == 5678
    assert msg["type"] == 3  # PREKEY_MESSAGE

    # Session stored in the unified ratchet store.
    updated = json.loads(config_path.read_text())
    assert "rec-aci-uuid:1" in updated["nativeRatchetSessions"]


@patch("signalnotify.native.messaging.make_request")
def test_send_message_native_continuation_is_type_1(mock_make_request, tmp_path):
    config_path = _config(tmp_path)
    bundle = _bundle([_device(1, 5678)])
    mock_make_request.side_effect = lambda path, method="GET", body=None, headers=None, base_url=None: (
        (bundle, {}) if method == "GET" else ({}, {}))

    # First send establishes the session (type 3) and fetches keys once.
    assert send_message_native(config_path, "first", recipient="rec-aci-uuid")
    first_type = mock_make_request.call_args_list[1][1]["body"]["messages"][0]["type"]
    assert first_type == 3

    # Second send on the same session is a whisper (type 1) AND does NOT refetch
    # /v2/keys -- it reuses the cached device set + stored session.
    assert send_message_native(config_path, "second", recipient="rec-aci-uuid")
    paths = [c[0][0] for c in mock_make_request.call_args_list]
    assert paths == ["/v2/keys/rec-aci-uuid/*",
                     "/v1/messages/rec-aci-uuid",
                     "/v1/messages/rec-aci-uuid"]  # only ONE key fetch, ever
    second_type = mock_make_request.call_args_list[2][1]["body"]["messages"][0]["type"]
    assert second_type == 1


@patch("signalnotify.native.messaging.make_request")
def test_send_reconciles_409_mismatched_devices(mock_make_request, tmp_path):
    # A 409 with a missing device must drop/refetch and retry once, ending in a
    # successful PUT covering the corrected device set.
    config_path = _config(tmp_path)
    calls = {"n": 0}

    def side_effect(path, method="GET", body=None, headers=None, base_url=None):
        if method == "GET":
            # First fetch: only device 1. Second (post-409) fetch: devices 1 + 2.
            devs = [_device(1, 5678)] if calls["n"] == 0 else [_device(1, 5678), _device(2, 9012)]
            return _bundle(devs), {}
        calls["n"] += 1
        if calls["n"] == 1:
            raise SignalAPIError(409, "mismatched",
                                 json.dumps({"missingDevices": [2], "extraDevices": []}))
        return {}, {}

    mock_make_request.side_effect = side_effect
    assert send_message_native(config_path, "hi", recipient="rec-aci-uuid") is True

    # Ended with a retry PUT to both devices.
    put_bodies = [c[1]["body"] for c in mock_make_request.call_args_list
                  if c[0][0].startswith("/v1/messages")]
    final = put_bodies[-1]
    assert sorted(m["destinationDeviceId"] for m in final["messages"]) == [1, 2]


@patch("signalnotify.native.messaging.make_request")
def test_send_message_native_note_to_self_skips_own_device(mock_make_request, tmp_path):
    config_path = _config(tmp_path, device_id=1)  # we are primary device 1
    our_pub = json.loads(config_path.read_text())["aciAccountData"]["identityPublicKey"]
    # Note-to-Self: bundle advertises our own account identity + two devices.
    bundle = {
        "identityKey": our_pub,
        "devices": [_device(1, 1234), _device(2, 5678)],
    }
    mock_make_request.side_effect = lambda path, method="GET", body=None, headers=None, base_url=None: (
        (bundle, {}) if method == "GET" else ({}, {}))

    ok = send_message_native(config_path, "Note to self message")
    assert ok is True

    put_body = mock_make_request.call_args_list[1][1]["body"]
    assert put_body["destination"] == "our-aci-uuid"
    assert len(put_body["messages"]) == 1  # device 1 (ourselves) skipped
    assert put_body["messages"][0]["destinationDeviceId"] == 2


@patch("signalnotify.native.messaging.make_request")
def test_send_output_decrypts_via_responder(mock_make_request, tmp_path):
    # End-to-end: what send_message_native puts on the wire must decrypt with the
    # native responder path (ratchet.accept_prekey + receive.parse_content).
    from signalnotify.native import ratchet
    from signalnotify.native.receive import parse_content

    config_path = _config(tmp_path)  # sender

    # Responder (recipient) keys + the public bundle the sender fetches.
    rec_id_priv, rec_id_pub = _kp()
    rec_spk_priv, rec_spk_pub = _kp()
    rec_opk_priv, rec_opk_pub = _kp()
    account_keys = {
        "identity_priv": rec_id_priv, "identity_pub": rec_id_pub,
        "signed_prekeys": {7: rec_spk_priv}, "kyber_prekeys": {},
        "one_time_prekeys": {9: rec_opk_priv},
    }
    bundle = {
        "identityKey": base64.b64encode(rec_id_pub).decode(),
        "devices": [{
            "deviceId": 1, "registrationId": 5678,
            "signedPreKey": {"keyId": 7, "publicKey": base64.b64encode(rec_spk_pub).decode(),
                             "signature": "x"},
            "preKey": {"keyId": 9, "publicKey": base64.b64encode(rec_opk_pub).decode()},
        }],
    }
    captured = {}

    def side_effect(path, method="GET", body=None, headers=None, base_url=None):
        if method == "GET":
            return bundle, {}
        captured["body"] = body
        return {}, {}

    mock_make_request.side_effect = side_effect
    assert send_message_native(config_path, "hi from sender", recipient="rec-aci-uuid")

    content = base64.b64decode(captured["body"]["messages"][0]["content"])
    _, plaintext = ratchet.accept_prekey(account_keys, content)
    msg = parse_content(plaintext, set(), "rec-aci-uuid", None)
    assert msg is not None and msg.body == "hi from sender"


@patch("signalnotify.native.messaging.make_request")
def test_send_persists_before_put(mock_make_request, tmp_path):
    # Commit-before-send: if the PUT fails, the session was already persisted.
    config_path = _config(tmp_path)
    bundle = _bundle([_device(1, 5678)])
    from signalnotify.native.registration import SignalAPIError

    def side_effect(path, method="GET", body=None, headers=None, base_url=None):
        if method == "GET":
            return bundle, {}
        raise SignalAPIError(500, "boom")

    mock_make_request.side_effect = side_effect
    ok = send_message_native(config_path, "will fail to send", recipient="rec-aci-uuid")
    assert ok is False
    # Ratchet state persisted despite the send failure.
    updated = json.loads(config_path.read_text())
    assert "rec-aci-uuid:1" in updated["nativeRatchetSessions"]
