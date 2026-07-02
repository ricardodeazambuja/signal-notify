"""Load a notify-config YAML file into a plain dict."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import yaml


def load_config(path) -> dict:
    """Parse ``path`` as YAML and return a dict (empty dict if missing/blank)."""
    p = Path(path)
    if not p.exists():
        return {}
    with open(p) as f:
        return yaml.safe_load(f) or {}


def atomic_write_secure(path, text: str) -> None:
    """Write ``text`` to ``path`` atomically with owner-only (0o600) permissions.

    The data is written to a temp file in the *same* directory (so the final
    ``os.replace`` is atomic on one filesystem) then renamed over the target.
    A crash mid-write therefore can never leave the credential file truncated
    or world-readable — the old contents survive until the rename succeeds.
    Used for the account config / session-state files, which hold the only
    copy of our identity private keys, device password and ratchet state.
    """
    path = Path(path)
    # mkstemp creates the file with 0o600 already (O_CREAT | O_EXCL).
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def append_line_secure(path, line: str) -> None:
    """Append one line to ``path``, creating it owner-only (0o600) if missing.

    Used for the per-account ``.inbox.jsonl`` / ``.undecryptable.jsonl`` spool
    files, which can hold message content and raw envelopes. A single
    ``os.write`` of one line keeps concurrent appenders (O_APPEND) from
    interleaving partial records.
    """
    fd = os.open(str(path), os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
    try:
        os.write(fd, (line.rstrip("\n") + "\n").encode("utf-8"))
    finally:
        os.close(fd)


# Historical default: this project originally reused signal-cli's storage
# location. We have our own now; the old path is only consulted (once) to
# migrate an existing account.
_LEGACY_DATA_SUBPATH = os.path.join("signal-cli", "data")
_DATA_SUBPATH = os.path.join("signal-notify", "data")
_MIGRATION_MARKER = "MIGRATED-TO-SIGNAL-NOTIFY.txt"


def _xdg_data_home() -> str:
    return os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")


def _migrate_legacy_data_dir(new_dir: str) -> None:
    """One-time move of an account store from the legacy signal-cli path.

    Runs only when the new directory has no ``accounts.json`` but the legacy
    one does. Files are MOVED (not copied): two live copies of ratchet state
    would diverge and start failing MACs. A marker file is left behind so a
    stray old checkout fails loudly instead of recreating a parallel store.
    Never touches a directory containing the marker twice.
    """
    import logging
    import shutil

    legacy_dir = os.path.join(_xdg_data_home(), _LEGACY_DATA_SUBPATH)
    if os.path.exists(os.path.join(new_dir, "accounts.json")):
        return
    if not os.path.exists(os.path.join(legacy_dir, "accounts.json")):
        return
    if os.path.exists(os.path.join(legacy_dir, _MIGRATION_MARKER)):
        return

    os.makedirs(new_dir, mode=0o700, exist_ok=True)
    # makedirs applies mode only to the leaf; tighten the created parent too.
    try:
        os.chmod(os.path.dirname(new_dir), 0o700)
        os.chmod(new_dir, 0o700)
    except OSError:
        pass
    for entry in sorted(os.listdir(legacy_dir)):
        shutil.move(os.path.join(legacy_dir, entry), os.path.join(new_dir, entry))
    with open(os.path.join(legacy_dir, _MIGRATION_MARKER), "w") as f:
        f.write("This account store moved to:\n  %s\n"
                "signal-notify no longer uses this directory.\n" % new_dir)
    logging.getLogger(__name__).info(
        "migrated account store from %s to %s", legacy_dir, new_dir)


def get_data_dir() -> str:
    """Resolve signal-notify's data directory (account keys + sessions).

    Precedence: ``SIGNALNOTIFY_DATA_DIR`` env var, else
    ``$XDG_DATA_HOME/signal-notify/data`` (default
    ``~/.local/share/signal-notify/data``). On first use, an account store
    found at the legacy pre-1.0 location is moved here automatically.
    """
    override = os.environ.get("SIGNALNOTIFY_DATA_DIR")
    if override:
        return os.path.expanduser(override)
    data_dir = os.path.join(_xdg_data_home(), _DATA_SUBPATH)
    _migrate_legacy_data_dir(data_dir)
    return data_dir

