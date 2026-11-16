"""Reactions and group-context encoding + send fan-out.

Reaction: ``DataMessage.reaction`` (field 16). Group: ``DataMessage.groupV2``
(field 15) — the send path carries the group context and fans out to the
caller-supplied member list.
"""
import base64
import json
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from signalnotify.native import ratchet
from signalnotify.native import proto as P
from signalnotify.native.messaging import (encode_data_message,
                                           encode_group_context_v2,
                                           encode_reaction, send_message_native)
from signalnotify.native.receive import _strip_push_padding
from signalnotify.native.registration import decode_proto
from test_native_messaging import _bundle, _config, _device, _kp

ACI = "00000000-0000-0000-0000-0000000000aa"


def _data_message(plaintext):
    content = decode_proto(_strip_push_padding(plaintext))
    return decode_proto(content[P.CONTENT_DATA_MESSAGE][0])


def test_encode_reaction_fields():
    r = encode_reaction("👍", ACI, 12345)
    f = decode_proto(r)
    assert f[P.REACTION_EMOJI][0] == "👍".encode()
    assert f[P.REACTION_TARGET_AUTHOR_ACI][0] == ACI.encode()
    assert f[P.REACTION_TARGET_SENT_TIMESTAMP][0] == 12345
    import uuid
    assert f[P.REACTION_TARGET_AUTHOR_ACI_BINARY][0] == uuid.UUID(ACI).bytes
    assert P.REACTION_REMOVE not in f


def test_encode_reaction_remove():
    f = decode_proto(encode_reaction("", ACI, 9, remove=True))
    assert f[P.REACTION_REMOVE][0] == 1
    assert P.REACTION_EMOJI not in f


def test_encode_group_context_v2_fields():
    f = decode_proto(encode_group_context_v2(b"\x11" * 32, 7, group_change=b"chg"))
    assert f[P.GROUP_V2_MASTER_KEY][0] == b"\x11" * 32
    assert f[P.GROUP_V2_REVISION][0] == 7
    assert f[P.GROUP_V2_GROUP_CHANGE][0] == b"chg"


def test_data_message_reaction_and_group_fields_present():
    dm = encode_data_message("", 1, reaction_bytes=encode_reaction("x", ACI, 2),
                             group_v2_bytes=encode_group_context_v2(b"\x22" * 32, 1))
    f = decode_proto(dm)
    assert P.DATA_GROUP_V2 in f and P.DATA_REACTION in f


def test_data_message_without_new_fields_is_unchanged():
    # Golden-test safety: the new optional params must not alter existing output.
    assert encode_data_message("hi", 42) == encode_data_message("hi", 42, reaction_bytes=None,
                                                                group_v2_bytes=None)


@patch("signalnotify.native.messaging.make_request")
def test_send_reaction_round_trips(mock_make_request, tmp_path):
    config_path = _config(tmp_path)
    rec_id_priv, rec_id_pub = _kp()
    rec_spk_priv, rec_spk_pub = _kp()
    rec_opk_priv, rec_opk_pub = _kp()
    account_keys = {"identity_priv": rec_id_priv, "identity_pub": rec_id_pub,
                    "signed_prekeys": {7: rec_spk_priv}, "kyber_prekeys": {},
                    "one_time_prekeys": {9: rec_opk_priv}}
    bundle = {"identityKey": base64.b64encode(rec_id_pub).decode(), "devices": [{
        "deviceId": 1, "registrationId": 5678,
        "signedPreKey": {"keyId": 7, "publicKey": base64.b64encode(rec_spk_pub).decode(), "signature": "x"},
        "preKey": {"keyId": 9, "publicKey": base64.b64encode(rec_opk_pub).decode()}}]}
    captured = {}

    def side_effect(path, method="GET", body=None, headers=None, base_url=None):
        if method == "GET":
            return bundle, {}
        captured["body"] = body
        return {}, {}

    mock_make_request.side_effect = side_effect
    reaction = encode_reaction("❤", ACI, 999)
    assert send_message_native(config_path, "", recipient="rec-aci-uuid",
                               reaction_bytes=reaction)

    content = base64.b64decode(captured["body"]["messages"][0]["content"])
    _, plaintext = ratchet.accept_prekey(account_keys, content)
    f = decode_proto(_data_message(plaintext)[P.DATA_REACTION][0])
    assert f[P.REACTION_EMOJI][0] == "❤".encode()
    assert f[P.REACTION_TARGET_SENT_TIMESTAMP][0] == 999


@patch("signalnotify.native.messaging.make_request")
@patch("signalnotify.sender.find_account_config")
def test_send_group_fans_out_with_context(mock_find, mock_make_request, tmp_path):
    config_path = _config(tmp_path)
    mock_find.return_value = config_path
    rec_id_priv, rec_id_pub = _kp()
    rec_spk_priv, rec_spk_pub = _kp()
    rec_opk_priv, rec_opk_pub = _kp()
    account_keys = {"identity_priv": rec_id_priv, "identity_pub": rec_id_pub,
                    "signed_prekeys": {7: rec_spk_priv}, "kyber_prekeys": {},
                    "one_time_prekeys": {9: rec_opk_priv}}
    bundle = {"identityKey": base64.b64encode(rec_id_pub).decode(), "devices": [{
        "deviceId": 1, "registrationId": 5678,
        "signedPreKey": {"keyId": 7, "publicKey": base64.b64encode(rec_spk_pub).decode(), "signature": "x"},
        "preKey": {"keyId": 9, "publicKey": base64.b64encode(rec_opk_pub).decode()}}]}
    puts = {}

    def side_effect(path, method="GET", body=None, headers=None, base_url=None):
        if method == "GET":
            return bundle, {}
        puts[path] = body
        return {}, {}

    mock_make_request.side_effect = side_effect
    from signalnotify import send_group
    ok = send_group("hello group", members=["member-a", "member-b"],
                    master_key=b"\x11" * 32, revision=5)
    assert ok is True
    assert set(puts) == {"/v1/messages/member-a", "/v1/messages/member-b"}
    for body in puts.values():
        content = base64.b64decode(body["messages"][0]["content"])
        _, plaintext = ratchet.accept_prekey(account_keys, content)
        gc = decode_proto(_data_message(plaintext)[P.DATA_GROUP_V2][0])
        assert gc[P.GROUP_V2_MASTER_KEY][0] == b"\x11" * 32
        assert gc[P.GROUP_V2_REVISION][0] == 5
