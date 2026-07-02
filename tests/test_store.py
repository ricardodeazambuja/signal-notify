"""Account-store locking: serialized read-modify-write on the config file.

The regression these tests guard: send and receive both read-modify-write the
same account JSON. Before locking, the receive loop held a connect-time
snapshot and rewrote the whole file per message, clobbering any ratchet
advance a concurrent send had persisted (the exact flow of
examples/agent_daemon.py — send_message() inside the listen() callback).
"""
import json
import multiprocessing
import sys

from signalnotify.native.store import locked_account


def _mk_config(tmp_path, extra=None):
    path = tmp_path / "account"
    data = {"counter": 0}
    if extra:
        data.update(extra)
    path.write_text(json.dumps(data))
    return path


def _increment_worker(path_str, n):
    for _ in range(n):
        with locked_account(path_str) as cfg:
            cfg["counter"] += 1


def test_concurrent_writers_lose_no_updates(tmp_path):
    """N processes × M increments each == N*M — no lost update under contention."""
    path = _mk_config(tmp_path)
    procs = [multiprocessing.Process(target=_increment_worker, args=(str(path), 25))
             for _ in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join()
    assert all(p.exitcode == 0 for p in procs)
    assert json.loads(path.read_text())["counter"] == 100


def test_reload_sees_external_write(tmp_path):
    """Each locked_account loads fresh from disk, never a cached snapshot."""
    path = _mk_config(tmp_path)
    with locked_account(path) as cfg:
        cfg["a"] = 1
    # External writer (another process in real life).
    data = json.loads(path.read_text())
    data["external"] = "kept"
    path.write_text(json.dumps(data))
    with locked_account(path) as cfg:
        assert cfg["external"] == "kept"  # not clobbered by any stale state
        cfg["b"] = 2
    final = json.loads(path.read_text())
    assert final == {"counter": 0, "a": 1, "external": "kept", "b": 2}


def test_exception_persists_nothing(tmp_path):
    path = _mk_config(tmp_path)
    try:
        with locked_account(path) as cfg:
            cfg["counter"] = 999
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    assert json.loads(path.read_text())["counter"] == 0


def test_write_false_is_read_only(tmp_path):
    path = _mk_config(tmp_path)
    with locked_account(path, write=False) as cfg:
        cfg["counter"] = 999
    assert json.loads(path.read_text())["counter"] == 0


def test_lockfile_not_world_readable(tmp_path):
    path = _mk_config(tmp_path)
    with locked_account(path):
        pass
    lock = tmp_path / "account.lock"
    assert lock.exists()
    assert (lock.stat().st_mode & 0o777) == 0o600


def test_receive_preserves_concurrent_send_state(tmp_path, monkeypatch):
    """The agent_daemon race: a write made between two received messages (as a
    send inside the on_message callback would make) must survive the receive
    loop's own persist for the second message."""
    from test_native_receive import (FakeWS, _envelope, _linked_account,
                                     _note_to_self_prekey_content, _ws_request, ACI)
    from signalnotify.native import receive
    import asyncio

    cfg_path, bundle = _linked_account(tmp_path)
    c1 = _note_to_self_prekey_content(bundle, "first", 1)
    c2 = _note_to_self_prekey_content(bundle, "second", 2)

    def simulated_send(msg):
        # What send_message_native does: lock, reload, advance state, persist.
        if msg.body == "first":
            with locked_account(cfg_path) as cfg:
                cfg["sentMarker"] = "advanced-by-send"

    frames = [
        _ws_request("/api/v1/message", _envelope(receive.TYPE_PREKEY, ACI, 1, c1), 1),
        _ws_request("/api/v1/message", _envelope(receive.TYPE_PREKEY, ACI, 1, c2), 2),
        _ws_request("/api/v1/queue/empty", b"", 3),
    ]
    monkeypatch.setattr(receive, "_ws_connect", lambda *a, **k: FakeWS(frames))
    msgs = asyncio.run(receive._receive_async(cfg_path, 5, None, "wss://x",
                                              on_message=simulated_send))
    assert [m.body for m in msgs] == ["first", "second"]
    # Pre-locking, message #2's persist wrote the connect-time snapshot and
    # dropped the callback's write.
    final = json.loads(cfg_path.read_text())
    assert final.get("sentMarker") == "advanced-by-send"
    assert f"{ACI}:1" in final["nativeRatchetSessions"]


if __name__ == "__main__":
    sys.exit("run via pytest")
