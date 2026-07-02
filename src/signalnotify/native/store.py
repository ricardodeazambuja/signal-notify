"""Serialized access to the account config file (the crypto-state store).

Send and receive both read-modify-write the same JSON file — identity keys,
password, ``nativeRatchetSessions``, ``nativeDevices``. Concurrent writers are
the norm for the agent-bridge use case: a ``listen()`` daemon whose callback
calls ``send_message()``, or a cron ``signal-notify send`` racing a running
receiver. A lost update on this file is not a cosmetic bug: it discards a
Double Ratchet advance, so a later send can reuse a message counter (the peer
drops it as a replay) or a receive can lose the session the other direction
just established.

:func:`locked_account` serializes every read-modify-write behind an ``fcntl``
lock and **reloads the file fresh inside the lock**, so a writer always builds
on the previous writer's state — never on a stale in-memory snapshot.
"""
from __future__ import annotations

import fcntl
import json
import os
from contextlib import contextmanager
from pathlib import Path

from ..config import atomic_write_secure


@contextmanager
def locked_account(config_path, write: bool = True):
    """Lock, load fresh, yield the config dict, persist and unlock.

    The flock is taken on a sidecar ``<config>.lock`` file, NOT on the config
    itself: :func:`~signalnotify.config.atomic_write_secure` replaces the
    config *inode* (``os.replace``), which would silently detach a lock held on
    the old inode and let a second writer proceed in parallel.

    The lock is held across the caller's mutation AND the persist, so the next
    ``locked_account()`` — in this process or another — always sees this
    writer's state. Rules for the body:

    - no user callbacks while holding the lock (a callback that re-enters
      ``locked_account()`` on the same file deadlocks — ``flock`` is per open
      file description, not per process);
    - keep network I/O out where possible (the send path holds it across a
      single ``/v2/keys`` GET only on first-contact / device-reconcile).

    If the body raises, nothing is persisted (the on-disk state stays at the
    previous commit). ``write=False`` skips the persist for read-only access
    under the same serialization.
    """
    config_path = Path(config_path)
    lock_path = config_path.with_name(config_path.name + ".lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        with open(config_path) as f:
            cfg = json.load(f)
        yield cfg
        if write:
            atomic_write_secure(config_path, json.dumps(cfg, indent=2))
    finally:
        # Closing the fd releases the flock.
        os.close(fd)
