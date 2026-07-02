from datetime import datetime

from signalnotify import notify_from_config
from signalnotify.dedupe import read_lines

DAY = datetime(2026, 1, 1, 12, 0)    # outside quiet hours
NIGHT = datetime(2026, 1, 1, 23, 0)  # inside quiet hours (22:00–07:00)


def _cfg(**over):
    cfg = {
        "channels": {"signal": {"enabled": True, "note_to_self": True}},
        "push_keywords": ["PUSH", "CRIT"],
        "critical_keywords": ["CRIT"],
        "quiet_hours": {"enabled": True, "start": "22:00", "end": "07:00"},
        "max_per_message": 8,
        "prefixes": {"CRIT": "🛑"},
    }
    cfg.update(over)
    return cfg


def _files(tmp_path, active, notified=""):
    a = tmp_path / "active.txt"
    n = tmp_path / "notified.txt"
    a.write_text(active)
    if notified:
        n.write_text(notified)
    return a, n


class _Sink:
    def __init__(self):
        self.lines = []

    def __call__(self, *a, **k):
        self.lines.append(" ".join(str(x) for x in a))


def _sender():
    sent = []
    return sent, (lambda body, **k: sent.append(body) or True)


def test_no_new_alerts(tmp_path):
    a, n = _files(tmp_path, "PUSH x\n", "PUSH x\n")
    sent, fn = _sender()
    out = _Sink()
    assert notify_from_config(_cfg(), a, n, now=DAY, send_fn=fn, out=out) == 0
    assert sent == []
    assert any("no new alerts" in line for line in out.lines)


def test_pushable_sent_and_committed(tmp_path):
    a, n = _files(tmp_path, "PUSH one\nignore me\n")
    sent, fn = _sender()
    rc = notify_from_config(_cfg(), a, n, now=DAY, app_name="App", send_fn=fn, out=_Sink())
    assert rc == 0
    assert len(sent) == 1 and "PUSH one" in sent[0]
    assert sent[0].startswith("App — 2026-01-01 12:00")
    # pushed + info both marked handled
    assert set(read_lines(n)) == {"PUSH one", "ignore me"}


def test_info_only_no_send_but_committed(tmp_path):
    a, n = _files(tmp_path, "ignore me\nalso info\n")
    sent, fn = _sender()
    assert notify_from_config(_cfg(), a, n, now=DAY, send_fn=fn, out=_Sink()) == 0
    assert sent == []
    assert set(read_lines(n)) == {"ignore me", "also info"}


def test_quiet_hours_suppress_noncritical_not_committed(tmp_path):
    a, n = _files(tmp_path, "PUSH soft\n")
    sent, fn = _sender()
    assert notify_from_config(_cfg(), a, n, now=NIGHT, send_fn=fn, out=_Sink()) == 0
    assert sent == []
    assert read_lines(n) == []  # deferred, not committed → pushes when quiet ends


def test_quiet_hours_critical_rings_through(tmp_path):
    a, n = _files(tmp_path, "CRIT down\nPUSH soft\n")
    sent, fn = _sender()
    assert notify_from_config(_cfg(), a, n, now=NIGHT, send_fn=fn, out=_Sink()) == 0
    assert len(sent) == 1
    assert "🛑 CRIT down" in sent[0] and "PUSH soft" not in sent[0]
    assert set(read_lines(n)) == {"CRIT down"}  # soft deferred


def test_empty_push_keywords_pushes_everything(tmp_path):
    a, n = _files(tmp_path, "whatever\n")
    sent, fn = _sender()
    rc = notify_from_config(_cfg(push_keywords=[]), a, n, now=DAY, send_fn=fn, out=_Sink())
    assert rc == 0 and len(sent) == 1 and "whatever" in sent[0]


def test_send_failure_returns_1_and_no_commit(tmp_path):
    a, n = _files(tmp_path, "PUSH one\n")
    rc = notify_from_config(_cfg(), a, n, now=DAY,
                            send_fn=lambda body, **k: False,
                            out=_Sink(), err=lambda *a, **k: None)
    assert rc == 1
    assert read_lines(n) == []  # not committed on failure


def test_disabled_channel_commits_without_sending(tmp_path):
    a, n = _files(tmp_path, "PUSH one\n")
    sent, fn = _sender()
    cfg = _cfg(channels={"signal": {"enabled": False}})
    rc = notify_from_config(cfg, a, n, now=DAY, send_fn=fn, out=_Sink())
    assert rc == 0 and sent == []
    assert set(read_lines(n)) == {"PUSH one"}  # treated as handled
