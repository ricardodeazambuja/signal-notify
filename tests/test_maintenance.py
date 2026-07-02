"""Prekey maintenance: top-up, rotation, archival — mocked server.

Thresholds/cadence per Signal-Android PreKeysSyncJob / PreKeyUtil: refill a
batch of 100 when the server count drops below 10 (EC and Kyber alike),
rotate the signed + last-resort Kyber prekeys every 2 days, keep replaced
keys 30 days.
"""
import json

import pytest

from signalnotify.native import maintenance
from signalnotify.native.maintenance import (ARCHIVE_AGE_MS,
                                             REFRESH_INTERVAL_MS,
                                             maintain_if_due, refresh_prekeys)
from signalnotify.native.ratchet import account_keys_from_config
from test_native_receive import _linked_account

NOW = 1_800_000_000_000  # fixed clock for determinism


@pytest.fixture(autouse=True)
def small_batches(monkeypatch):
    """Keep the live constant at Signal's 100 but generate 8 in tests: each key
    costs a pure-Python XEdDSA signature, and 100×N runs dominates the suite."""
    assert maintenance.BATCH_SIZE == 100  # the live value, per PreKeyUtil
    monkeypatch.setattr(maintenance, "BATCH_SIZE", 8)


class FakeServer:
    def __init__(self, ec=100, pq=100):
        self.counts = {"count": ec, "pqCount": pq}
        self.puts = []

    def make_request(self, path, method="GET", body=None, headers=None,
                     base_url=None, timeout=30):
        assert headers and headers.get("Authorization", "").startswith("Basic ")
        if method == "GET":
            assert path == "/v2/keys?identity=aci"
            return dict(self.counts), {}
        if method == "PUT":
            assert path == "/v2/keys?identity=aci"
            self.puts.append(body)
            return {}, {}
        raise AssertionError(f"unexpected {method} {path}")


@pytest.fixture
def fresh_account(tmp_path, monkeypatch):
    cfg_path, _ = _linked_account(tmp_path)
    # Pretend link-time keys were registered "now" so rotation is NOT due.
    with open(cfg_path) as f:
        cfg = json.load(f)
    cfg["aciAccountData"]["signedPreKeyRotatedAt"] = NOW
    cfg["aciAccountData"]["kyberPreKeyRotatedAt"] = NOW
    cfg_path.write_text(json.dumps(cfg))
    return cfg_path


def _patch(monkeypatch, server):
    monkeypatch.setattr(maintenance, "make_request", server.make_request)


def test_counts_ok_is_a_noop(fresh_account, monkeypatch):
    server = FakeServer(ec=100, pq=100)
    _patch(monkeypatch, server)
    s = refresh_prekeys(fresh_account, now_ms=NOW)
    assert server.puts == []
    assert s["ecUploaded"] == 0 and s["kyberUploaded"] == 0
    assert not s["signedRotated"] and not s["lastResortRotated"]


def test_low_counts_top_up_batches(fresh_account, monkeypatch):
    server = FakeServer(ec=3, pq=0)
    _patch(monkeypatch, server)
    s = refresh_prekeys(fresh_account, now_ms=NOW)
    assert s["ecUploaded"] == maintenance.BATCH_SIZE and s["kyberUploaded"] == maintenance.BATCH_SIZE

    (body,) = server.puts
    assert len(body["preKeys"]) == maintenance.BATCH_SIZE
    assert len(body["pqPreKeys"]) == maintenance.BATCH_SIZE
    assert "signedPreKey" not in body and "pqLastResortPreKey" not in body
    assert all(e["signature"] for e in body["pqPreKeys"])  # kyber entities are signed

    # Every uploaded id has its private persisted and resolvable for decrypt.
    cfg = json.loads(fresh_account.read_text())
    keys = account_keys_from_config(cfg)
    for e in body["preKeys"]:
        assert e["keyId"] in keys["one_time_prekeys"]
    for e in body["pqPreKeys"]:
        assert e["keyId"] in keys["kyber_prekeys"]
        assert len(keys["kyber_prekeys"][e["keyId"]]) == 3168  # kyber decap key


def test_rotation_due_rotates_and_activates(fresh_account, monkeypatch):
    server = FakeServer()
    _patch(monkeypatch, server)
    later = NOW + REFRESH_INTERVAL_MS  # 2 days on
    old = json.loads(fresh_account.read_text())["aciAccountData"]
    s = refresh_prekeys(fresh_account, now_ms=later)
    assert s["signedRotated"] and s["lastResortRotated"]

    (body,) = server.puts
    acct = json.loads(fresh_account.read_text())["aciAccountData"]
    assert acct["signedPreKey"]["keyId"] == body["signedPreKey"]["keyId"] != old["signedPreKey"]["keyId"]
    assert acct["kyberPreKey"]["keyId"] == body["pqLastResortPreKey"]["keyId"] != old["kyberPreKey"]["keyId"]
    assert acct["signedPreKeyRotatedAt"] == later
    # The replaced keys stay decryptable (archived, not dropped)...
    keys = account_keys_from_config({"aciAccountData": acct})
    assert old["signedPreKey"]["keyId"] in keys["signed_prekeys"]
    assert old["kyberPreKey"]["keyId"] in keys["kyber_prekeys"]
    # ...and the new actives resolve too.
    assert acct["signedPreKey"]["keyId"] in keys["signed_prekeys"]


def test_upload_failure_keeps_privates_but_not_activation(fresh_account, monkeypatch):
    server = FakeServer(ec=0, pq=100)

    def failing(path, method="GET", **kw):
        if method == "PUT":
            from signalnotify.native.registration import SignalAPIError
            raise SignalAPIError(500, "boom")
        return server.make_request(path, method=method, **kw)

    monkeypatch.setattr(maintenance, "make_request", failing)
    later = NOW + REFRESH_INTERVAL_MS
    old_active = json.loads(fresh_account.read_text())["aciAccountData"]["signedPreKey"]["keyId"]
    with pytest.raises(Exception):
        refresh_prekeys(fresh_account, now_ms=later)

    acct = json.loads(fresh_account.read_text())["aciAccountData"]
    # Privates were committed before the network step (commit-before-network)...
    assert len(acct["oneTimePreKeys"]) > maintenance.BATCH_SIZE / 2
    # ...but the active pointer and rotation stamp did NOT advance.
    assert acct["signedPreKey"]["keyId"] == old_active
    assert acct["signedPreKeyRotatedAt"] == NOW


def test_archive_cleanup_after_30_days(fresh_account, monkeypatch):
    server = FakeServer()
    _patch(monkeypatch, server)
    # Rotate once at t1: the link-time key becomes archived at t1.
    t1 = NOW + REFRESH_INTERVAL_MS
    refresh_prekeys(fresh_account, now_ms=t1)
    # Rotate again 31 days later: the t1 archive is past ARCHIVE_AGE -> dropped.
    t2 = t1 + ARCHIVE_AGE_MS + 24 * 3600 * 1000
    refresh_prekeys(fresh_account, now_ms=t2)
    acct = json.loads(fresh_account.read_text())["aciAccountData"]
    archived_ids = [e["keyId"] for e in acct["previousSignedPreKeys"]]
    assert len(archived_ids) == 1  # only the key replaced at t2 survives


def test_maintain_if_due_throttles(fresh_account, monkeypatch):
    server = FakeServer(ec=0, pq=0)
    _patch(monkeypatch, server)
    assert maintain_if_due(fresh_account, now_ms=NOW) is not None
    n_puts = len(server.puts)
    # Immediately again: throttled, no server traffic.
    assert maintain_if_due(fresh_account, now_ms=NOW + 1000) is None
    assert len(server.puts) == n_puts
    # After the refresh interval it runs again.
    assert maintain_if_due(fresh_account, now_ms=NOW + REFRESH_INTERVAL_MS + 1) is not None


def test_maintain_if_due_swallows_network_errors(fresh_account, monkeypatch):
    def down(*a, **k):
        raise OSError("network unreachable")
    monkeypatch.setattr(maintenance, "make_request", down)
    assert maintain_if_due(fresh_account, now_ms=NOW) is None
    # Not stamped -> retried on the next call.
    assert "nativePreKeyRefreshAt" not in json.loads(fresh_account.read_text())
