"""Byte-exact golden tests anchored to the LIVE-PROVEN implementation.

Caveat #9 (docs/native_caveats.md): a local round-trip proves nothing, because
a symmetric bug cancels out — both the wrong-KEM and the raw-key bugs sailed
through green round-trips. These goldens break that symmetry differently: the
expected bytes/fixtures below were produced by the implementation that was
proven against real phones (send + receive, July 2026) and FROZEN. Any change
to padding, field numbers, field order, or the Sent-transcript shape now fails
here instead of failing live.

- The hex constants are frozen encoder outputs (deterministic inputs).
- tests/fixtures/ holds a frozen PREKEY Note-to-Self envelope + synthetic
  account; decrypting it exercises the full responder stack (PQXDH + Kyber +
  SPQR + Double Ratchet + padding + Sent parsing) deterministically.
- Deterministic ENCRYPT goldens are impossible without deeper changes: the
  ratchet generates X25519 ephemerals via os.urandom and spqr_py draws from
  the OS RNG inside Rust. The decrypt direction covers the shared wire-format
  code paths instead.

Do NOT regenerate the constants/fixtures to make a failing test pass — that
inverts their purpose. Regenerate only for a deliberate, re-proven-live wire
change (tests/fixtures/generate_fixtures.py).
"""
import json
import shutil
from pathlib import Path

from signalnotify.native.messaging import (encode_content, encode_data_message,
                                           encode_message_addresses,
                                           encode_sync_message,
                                           encode_sync_message_sent, pad_content,
                                           push_pad)

FIXTURES = Path(__file__).parent / "fixtures"

ACI = "00000000-0000-0000-0000-0000000000aa"
TS = 1751300000000
PROFILE_KEY = bytes(range(32))

GOLDEN_DATA_MESSAGE = (
    "0a0f676f6c64656e20626f647920e29c8528003220000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f388092f58cfc326000b80101")
GOLDEN_SENT = (
    "0a092b3135353530313030108092f58cfc321a410a0f676f6c64656e20626f647920e29c85"
    "28003220000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f38"
    "8092f58cfc326000b80101208092f58cfc3230006210000000000000000000000000000000aa")
GOLDEN_PADDED = (
    "12720a700a092b3135353530313030108092f58cfc321a410a0f676f6c64656e20626f6479"
    "20e29c8528003220000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"
    "1d1e1f388092f58cfc326000b80101208092f58cfc32300062100000000000000000000000"
    "00000000aa8000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000")
GOLDEN_ADDRESSES = (
    "00000000000000000000000000000000aa0200000000000000000000000000000000aa01")


def test_data_message_bytes_exact():
    dm = encode_data_message("golden body ✅", TS, profile_key=PROFILE_KEY)
    assert dm.hex() == GOLDEN_DATA_MESSAGE


def test_sent_transcript_bytes_exact():
    # Shape per the live wire capture (caveat #13): fields 1,2,3,4,6,12 — no
    # unidentifiedStatus(5); expirationStartTimestamp(4) == timestamp.
    dm = encode_data_message("golden body ✅", TS, profile_key=PROFILE_KEY)
    sent = encode_sync_message_sent(ACI, TS, dm, destination_e164="+15550100")
    assert sent.hex() == GOLDEN_SENT


def test_full_padded_content_bytes_exact():
    # The exact plaintext handed to the ratchet: Content(syncMessage) followed
    # by BYTE-level 0x80+0x00 padding to the 80-block boundary (caveat #2:
    # padding must never be a Content field — field 8 is decryptionErrorMessage).
    padded = pad_content("golden body ✅", destination_aci=ACI, timestamp_ms=TS,
                         profile_key=PROFILE_KEY, destination_e164="+15550100")
    assert padded.hex() == GOLDEN_PADDED
    content = encode_content(sync_message_bytes=encode_sync_message(
        encode_sync_message_sent(ACI, TS,
                                 encode_data_message("golden body ✅", TS,
                                                     profile_key=PROFILE_KEY),
                                 destination_e164="+15550100")))
    assert padded[len(content)] == 0x80          # boundary marker right after proto
    assert set(padded[len(content) + 1:]) <= {0}  # then zeros only
    assert len(padded) % 80 == 79                # ceil((n+2)/80)*80 - 1


def test_push_pad_length_law():
    # PushTransportDetails.getPaddedMessageBody: rounds len+2 up to the block.
    assert len(push_pad(b"x" * 78)) == 79
    assert len(push_pad(b"x" * 79)) == 159   # one byte over -> next block
    assert len(push_pad(b"")) == 79


def test_addresses_bytes_exact():
    # serialize_addresses: kind byte + UUID + device, sender then recipient.
    assert encode_message_addresses(ACI, 2, ACI, 1).hex() == GOLDEN_ADDRESSES


def test_frozen_envelope_decrypts_through_full_stack(tmp_path, monkeypatch):
    """The frozen PREKEY envelope must keep decrypting byte-for-byte: PQXDH
    (round-3 Kyber-1024) + SPQR + Double Ratchet + padding + Sent parsing."""
    from test_native_receive import FakeWS, _ws_request
    from signalnotify.native import receive

    meta = json.loads((FIXTURES / "meta.json").read_text())
    envelope = (FIXTURES / "note_to_self_prekey_envelope.bin").read_bytes()
    cfg_path = tmp_path / "account"          # copy: receive persists sessions
    shutil.copyfile(FIXTURES / "account_config.json", cfg_path)

    frames = [_ws_request("/api/v1/message", envelope, 1),
              _ws_request("/api/v1/queue/empty", b"", 2)]
    monkeypatch.setattr(receive, "_ws_connect", lambda *a, **k: FakeWS(frames))
    msgs = receive.receive(config_path=cfg_path, idle_timeout=5)

    assert [m.body for m in msgs] == [meta["body"]]
    assert msgs[0].note_to_self is True
    assert msgs[0].timestamp == meta["timestamp"]
    assert msgs[0].source == meta["aci"]


def test_capture_hook_dumps_raw_envelope(tmp_path, monkeypatch):
    import base64
    from test_native_receive import FakeWS, _ws_request
    from signalnotify.native import receive

    envelope = (FIXTURES / "note_to_self_prekey_envelope.bin").read_bytes()
    cfg_path = tmp_path / "account"
    shutil.copyfile(FIXTURES / "account_config.json", cfg_path)
    cap_dir = tmp_path / "capture"
    monkeypatch.setenv("SIGNALNOTIFY_CAPTURE_DIR", str(cap_dir))

    frames = [_ws_request("/api/v1/message", envelope, 1),
              _ws_request("/api/v1/queue/empty", b"", 2)]
    monkeypatch.setattr(receive, "_ws_connect", lambda *a, **k: FakeWS(frames))
    receive.receive(config_path=cfg_path, idle_timeout=5)

    rec = json.loads((cap_dir / "capture.jsonl").read_text().splitlines()[0])
    assert base64.b64decode(rec["envelope_b64"]) == envelope
