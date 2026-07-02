"""Quarantine + inbox-journal spooling in the receive loop.

The server's ack semantics are delete-forever, so both spool files must be
written BEFORE the ack goes out: the quarantine (always on) preserves
envelopes we cannot decrypt — sealed-sender type 6 in particular — and the
opt-in journal gives consumers at-least-once delivery.
"""
import base64
import json

from signalnotify.native import receive
from test_native_receive import (ACI, FakeWS, _envelope, _linked_account,
                                 _note_to_self_prekey_content, _ws_request)


class CheckingWS(FakeWS):
    """FakeWS that snapshots a predicate's value at every ack."""

    def __init__(self, frames, probe):
        super().__init__(frames)
        self.probe_results = []
        self._probe = probe

    async def send(self, data):
        self.probe_results.append(self._probe())
        await super().send(data)


def test_sealed_envelope_quarantined_before_ack(tmp_path, monkeypatch):
    cfg_path, _ = _linked_account(tmp_path)
    qfile = tmp_path / (cfg_path.name + ".undecryptable.jsonl")
    env = _envelope(receive.TYPE_SEALED, "", 1, b"\x01\x02\x03opaque")
    frames = [_ws_request("/api/v1/message", env, 1),
              _ws_request("/api/v1/queue/empty", b"", 2)]
    ws = CheckingWS(frames, probe=qfile.exists)
    monkeypatch.setattr(receive, "_ws_connect", lambda *a, **k: ws)

    msgs = receive.receive(config_path=cfg_path, idle_timeout=5)
    assert msgs == []                      # nothing decryptable
    assert len(ws.sent) == 2               # but both frames still acked
    assert ws.probe_results[0] is True     # quarantined BEFORE the first ack

    rec = json.loads(qfile.read_text().splitlines()[0])
    assert base64.b64decode(rec["envelope_b64"]) == env  # replayable verbatim
    assert rec["type"] == receive.TYPE_SEALED
    assert "sealed-sender" in rec["error"]
    assert (qfile.stat().st_mode & 0o777) == 0o600


def test_whisper_without_session_quarantined(tmp_path, monkeypatch):
    cfg_path, _ = _linked_account(tmp_path)
    frames = [_ws_request("/api/v1/message",
                          _envelope(receive.TYPE_WHISPER, ACI, 1, b"\x44garbage"), 1),
              _ws_request("/api/v1/queue/empty", b"", 2)]
    monkeypatch.setattr(receive, "_ws_connect", lambda *a, **k: FakeWS(frames))
    assert receive.receive(config_path=cfg_path, idle_timeout=5) == []
    qfile = tmp_path / (cfg_path.name + ".undecryptable.jsonl")
    rec = json.loads(qfile.read_text().splitlines()[0])
    assert "no session" in rec["error"]


def test_journal_written_before_ack(tmp_path, monkeypatch):
    cfg_path, bundle = _linked_account(tmp_path)
    jfile = tmp_path / (cfg_path.name + ".inbox.jsonl")
    content = _note_to_self_prekey_content(bundle, "journaled reply", 4242)
    frames = [_ws_request("/api/v1/message",
                          _envelope(receive.TYPE_PREKEY, ACI, 1, content), 1),
              _ws_request("/api/v1/queue/empty", b"", 2)]
    ws = CheckingWS(frames, probe=jfile.exists)
    monkeypatch.setattr(receive, "_ws_connect", lambda *a, **k: ws)

    msgs = receive.receive(config_path=cfg_path, idle_timeout=5, journal=True)
    assert [m.body for m in msgs] == ["journaled reply"]
    assert ws.probe_results[0] is True     # journaled BEFORE the message's ack

    rec = json.loads(jfile.read_text().splitlines()[0])
    assert rec["body"] == "journaled reply"
    assert rec["note_to_self"] is True
    assert rec["timestamp"] == 4242
    assert (jfile.stat().st_mode & 0o777) == 0o600


def test_journal_off_by_default(tmp_path, monkeypatch):
    cfg_path, bundle = _linked_account(tmp_path)
    content = _note_to_self_prekey_content(bundle, "not journaled", 1)
    frames = [_ws_request("/api/v1/message",
                          _envelope(receive.TYPE_PREKEY, ACI, 1, content), 1),
              _ws_request("/api/v1/queue/empty", b"", 2)]
    monkeypatch.setattr(receive, "_ws_connect", lambda *a, **k: FakeWS(frames))
    receive.receive(config_path=cfg_path, idle_timeout=5)
    assert not (tmp_path / (cfg_path.name + ".inbox.jsonl")).exists()
