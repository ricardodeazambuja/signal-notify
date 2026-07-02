"""Data-dir resolution + one-time migration from the legacy location.

signal-notify historically stored account state in signal-cli's directory
(``…/signal-cli/data``); it now owns ``…/signal-notify/data``. The migration
MOVES files (two live copies of ratchet state would diverge) and leaves a
marker so the legacy dir is never harvested twice.
"""
import json
import os
from pathlib import Path

from signalnotify.config import _MIGRATION_MARKER, get_data_dir


def _mk_legacy(xdg: Path) -> Path:
    legacy = xdg / "signal-cli" / "data"
    legacy.mkdir(parents=True)
    (legacy / "accounts.json").write_text(json.dumps(
        {"accounts": [{"path": "555001", "number": "+15550100"}]}))
    (legacy / "555001").write_text("{\"number\": \"+15550100\"}")
    (legacy / "555001.inbox.jsonl").write_text("{}\n")
    return legacy


def test_env_override_wins(monkeypatch, tmp_path):
    monkeypatch.setenv("SIGNALNOTIFY_DATA_DIR", str(tmp_path / "custom"))
    assert get_data_dir() == str(tmp_path / "custom")


def test_default_under_xdg(monkeypatch, tmp_path):
    monkeypatch.delenv("SIGNALNOTIFY_DATA_DIR", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert get_data_dir() == str(tmp_path / "signal-notify" / "data")


def test_migrates_legacy_store_once(monkeypatch, tmp_path):
    monkeypatch.delenv("SIGNALNOTIFY_DATA_DIR", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    legacy = _mk_legacy(tmp_path)

    new_dir = Path(get_data_dir())
    # Everything moved, sidecars included; nothing left behind but the marker.
    assert (new_dir / "accounts.json").exists()
    assert (new_dir / "555001").exists()
    assert (new_dir / "555001.inbox.jsonl").exists()
    assert not (legacy / "accounts.json").exists()
    assert (legacy / _MIGRATION_MARKER).exists()

    # Second resolution is a no-op even if a stray old tool recreates files.
    (legacy / "accounts.json").write_text("{\"accounts\": []}")
    get_data_dir()
    assert (new_dir / "accounts.json").read_text() != "{\"accounts\": []}"


def test_no_migration_when_new_store_exists(monkeypatch, tmp_path):
    monkeypatch.delenv("SIGNALNOTIFY_DATA_DIR", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    new_dir = tmp_path / "signal-notify" / "data"
    new_dir.mkdir(parents=True)
    (new_dir / "accounts.json").write_text("{\"accounts\": []}")
    legacy = _mk_legacy(tmp_path)

    get_data_dir()
    assert (legacy / "accounts.json").exists()      # untouched
    assert not (legacy / _MIGRATION_MARKER).exists()


def test_env_override_skips_migration(monkeypatch, tmp_path):
    monkeypatch.setenv("SIGNALNOTIFY_DATA_DIR", str(tmp_path / "own"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    legacy = _mk_legacy(tmp_path)
    get_data_dir()
    assert (legacy / "accounts.json").exists()
