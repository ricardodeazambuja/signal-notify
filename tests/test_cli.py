"""CLI exit codes and error paths (the seams a scripted/cron user relies on)."""
from signalnotify.cli import main


def _run_args(tmp_path, config):
    active = tmp_path / "active.txt"
    notified = tmp_path / "notified.txt"
    active.write_text("PUSH boom\n")
    return ["run", "--config", str(config),
            "--active", str(active), "--notified", str(notified)], notified


def test_run_missing_config_is_hard_error(tmp_path, capsys):
    """A --config typo must NOT silently mark alerts as handled (exit 2)."""
    args, notified = _run_args(tmp_path, tmp_path / "nope.yaml")
    assert main(args) == 2
    assert "config file not found" in capsys.readouterr().err
    assert not notified.exists()  # nothing committed as "notified"


def test_run_malformed_yaml_is_friendly_error(tmp_path, capsys):
    cfg = tmp_path / "notify.yaml"
    cfg.write_text("channels: [unclosed\n")
    args, notified = _run_args(tmp_path, cfg)
    assert main(args) == 2
    assert "invalid YAML" in capsys.readouterr().err
    assert not notified.exists()


def test_run_disabled_channel_does_not_claim_sent(tmp_path, capsys):
    cfg = tmp_path / "notify.yaml"
    cfg.write_text("channels:\n  signal:\n    enabled: false\n")
    args, notified = _run_args(tmp_path, cfg)
    assert main(args) == 0
    out = capsys.readouterr().out
    assert "NOT sent" in out
    assert "notify: sent" not in out
    # compute-only mode still commits state (documented behaviour)
    assert "PUSH boom" in notified.read_text()


def test_receive_unlinked_exits_nonzero_with_hint(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("SIGNALNOTIFY_DATA_DIR", str(tmp_path / "empty"))
    assert main(["receive"]) == 1
    assert "signal-notify link" in capsys.readouterr().err


def test_send_unlinked_exits_nonzero(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGNALNOTIFY_DATA_DIR", str(tmp_path / "empty"))
    assert main(["send", "-m", "hi"]) == 1
