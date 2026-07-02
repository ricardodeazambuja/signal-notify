"""Prekey maintenance for a long-lived linked device.

Every inbound PREKEY message consumes one of this device's one-time prekeys;
without replenishment a daemon runs the server-side supply to zero, and the
signed / last-resort Kyber prekeys registered at link time age forever. Real
clients run a periodic sync; this module is that job for us.

Modeled on Signal-Android ``PreKeysSyncJob`` + ``PreKeyUtil`` (constants and
flow verified against the source, 2026-07):

* one-time EC and Kyber counts are fetched from ``GET /v2/keys?identity=…``
  (``{"count": ec, "pqCount": kyber}``) and topped up with a batch of 100 when
  below 10;
* the signed prekey and the last-resort Kyber prekey rotate every 2 days;
* replaced keys are kept for 30 days (``ARCHIVE_AGE``) so late-arriving
  messages that reference them still decrypt, then dropped;
* the upload is one ``PUT /v2/keys?identity=…`` whose body carries any of
  ``preKeys`` / ``signedPreKey`` / ``pqPreKeys`` / ``pqLastResortPreKey``
  (field names per libsignal-service ``PreKeyState``).

Durability order mirrors the rest of the stack (commit-before-network): new
private keys are persisted under the account lock BEFORE the upload — a crash
after upload with unpersisted privates would make messages undecryptable,
while persisted-but-never-uploaded privates are merely dead weight. Active-key
pointers and rotation timestamps advance only AFTER the server accepted the
upload (as Signal-Android does).

Only the ACI identity is maintained by default: that is the identity the
phone opens sessions to on this linked device, and the only one we have
live-proven. PNI can be passed explicitly once its paths are exercised.
"""
from __future__ import annotations

import base64
import logging
import time

from .registration import DEFAULT_BASE_URL, SignalAPIError, make_request

log = logging.getLogger(__name__)

# Constants from Signal-Android PreKeysSyncJob / PreKeyUtil.
ONE_TIME_PREKEY_MINIMUM = 10
BATCH_SIZE = 100
REFRESH_INTERVAL_MS = 2 * 24 * 3600 * 1000       # signed / last-resort rotation
ARCHIVE_AGE_MS = 30 * 24 * 3600 * 1000           # keep replaced keys this long
MEDIUM_MAX_VALUE = 0xFFFFFF                      # prekey-id wraparound (libsignal Medium.MAX_VALUE)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8").rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _acct(config_data: dict, identity: str) -> dict:
    return config_data["aciAccountData" if identity == "aci" else "pniAccountData"]


def _auth_headers(config_data: dict) -> dict:
    aci = config_data["aciAccountData"]["serviceId"]
    device_id = config_data.get("deviceId", 1)
    auth = base64.b64encode(
        f"{aci}.{device_id}:{config_data['password']}".encode()).decode()
    return {"Authorization": f"Basic {auth}"}


def _next_ids(acct: dict, field: str, n: int) -> list:
    """Reserve ``n`` sequential key ids from ``acct[field]``, wrapping at
    ``MEDIUM_MAX_VALUE`` like Signal-Android PreKeyUtil."""
    start = acct.get(field) or 1
    ids = [(start + i) % MEDIUM_MAX_VALUE for i in range(n)]
    acct[field] = (start + n) % MEDIUM_MAX_VALUE
    return ids


def _gen_ec_batch(acct: dict) -> list:
    """Generate BATCH_SIZE one-time EC prekeys; persist privates, return entities."""
    from .crypto import generate_x25519_keypair, serialize_signal_public_key

    store = acct.setdefault("oneTimePreKeys", {})
    entities = []
    for kid in _next_ids(acct, "nextPreKeyId", BATCH_SIZE):
        priv, pub = generate_x25519_keypair()
        store[str(kid)] = _b64(priv)
        entities.append({"keyId": kid,
                         "publicKey": _b64(serialize_signal_public_key(pub))})
    return entities


def _gen_kyber_batch(acct: dict, identity_priv: bytes) -> list:
    """Generate BATCH_SIZE one-time Kyber prekeys (signed); persist privates."""
    from .crypto import xed25519_sign
    from .kem import generate_kyber_keypair

    store = acct.setdefault("oneTimeKyberPreKeys", {})
    entities = []
    for kid in _next_ids(acct, "nextKyberPreKeyId", BATCH_SIZE):
        priv, pub_serialized = generate_kyber_keypair()
        store[str(kid)] = _b64(priv)
        entities.append({"keyId": kid, "publicKey": _b64(pub_serialized),
                         "signature": _b64(xed25519_sign(identity_priv, pub_serialized))})
    return entities


def _gen_signed_prekey(acct: dict, identity_priv: bytes) -> dict:
    """Generate a replacement signed prekey record (not yet active)."""
    from .crypto import (generate_x25519_keypair, serialize_signal_public_key,
                         xed25519_sign)

    kid = _next_ids(acct, "nextSignedPreKeyId", 1)[0]
    priv, pub = generate_x25519_keypair()
    pub_prefixed = serialize_signal_public_key(pub)
    return {"keyId": kid, "priv": _b64(priv), "publicKey": _b64(pub_prefixed),
            "signature": _b64(xed25519_sign(identity_priv, pub_prefixed))}


def _gen_last_resort_kyber(acct: dict, identity_priv: bytes) -> dict:
    """Generate a replacement last-resort Kyber prekey record (not yet active)."""
    from .crypto import xed25519_sign
    from .kem import generate_kyber_keypair

    kid = _next_ids(acct, "nextKyberPreKeyId", 1)[0]
    priv, pub_serialized = generate_kyber_keypair()
    return {"keyId": kid, "priv": _b64(priv), "publicKey": _b64(pub_serialized),
            "signature": _b64(xed25519_sign(identity_priv, pub_serialized))}


def _clean_archived(acct: dict, now_ms: int) -> None:
    """Drop replaced signed / last-resort keys older than ARCHIVE_AGE."""
    for field in ("previousSignedPreKeys", "previousKyberPreKeys"):
        keep = [e for e in acct.get(field, [])
                if now_ms - e.get("archivedAt", now_ms) <= ARCHIVE_AGE_MS]
        if field in acct or keep:
            acct[field] = keep


def refresh_prekeys(config_path, *, base_url: str = DEFAULT_BASE_URL,
                    force: bool = False, identity: str = "aci",
                    now_ms: int | None = None) -> dict:
    """Ensure the server holds enough one-time prekeys and rotation is current.

    Returns a summary dict: server counts seen, how many EC/Kyber one-time
    prekeys were uploaded, and whether the signed / last-resort keys rotated.
    Raises :class:`SignalAPIError` on server rejection (the caller decides how
    loud to be — the opportunistic hook in receive downgrades it to a warning).
    """
    from .store import locked_account

    if now_ms is None:
        now_ms = int(time.time() * 1000)

    with locked_account(config_path, write=False) as config_data:
        headers = _auth_headers(config_data)

    counts, _ = make_request(f"/v2/keys?identity={identity}", method="GET",
                             headers=headers, base_url=base_url)
    ec_count = counts.get("count", 0)
    kyber_count = counts.get("pqCount", 0)

    summary = {"identity": identity, "ecCount": ec_count, "pqCount": kyber_count,
               "ecUploaded": 0, "kyberUploaded": 0,
               "signedRotated": False, "lastResortRotated": False}

    # Phase 1 (under lock): generate + persist privates for everything needed.
    body = {}
    new_signed = None
    new_last_resort = None
    with locked_account(config_path) as config_data:
        acct = _acct(config_data, identity)
        identity_priv = _b64d(acct["identityPrivateKey"])

        if force or ec_count < ONE_TIME_PREKEY_MINIMUM:
            body["preKeys"] = _gen_ec_batch(acct)
        if force or kyber_count < ONE_TIME_PREKEY_MINIMUM:
            body["pqPreKeys"] = _gen_kyber_batch(acct, identity_priv)

        signed_age = now_ms - acct.get("signedPreKeyRotatedAt", 0)
        if force or signed_age >= REFRESH_INTERVAL_MS or signed_age < 0:
            new_signed = _gen_signed_prekey(acct, identity_priv)
            # Park it in the lookup pool now: inbound messages may reference it
            # the moment the server learns of it, even before we mark it active.
            acct.setdefault("previousSignedPreKeys", []).append(
                dict(new_signed, archivedAt=now_ms))
            body["signedPreKey"] = {k: new_signed[k]
                                    for k in ("keyId", "publicKey", "signature")}

        kyber_age = now_ms - acct.get("kyberPreKeyRotatedAt", 0)
        if force or kyber_age >= REFRESH_INTERVAL_MS or kyber_age < 0:
            new_last_resort = _gen_last_resort_kyber(acct, identity_priv)
            acct.setdefault("previousKyberPreKeys", []).append(
                dict(new_last_resort, archivedAt=now_ms))
            body["pqLastResortPreKey"] = {k: new_last_resort[k]
                                          for k in ("keyId", "publicKey", "signature")}

    if not body:
        return summary

    # Network upload OUTSIDE the lock; privates are already committed.
    make_request(f"/v2/keys?identity={identity}", method="PUT", body=body,
                 headers=headers, base_url=base_url)

    # Phase 2 (under lock): the server accepted — activate rotated keys, stamp
    # rotation times, and age out >30-day-old replaced keys.
    with locked_account(config_path) as config_data:
        acct = _acct(config_data, identity)
        if new_signed is not None:
            old = acct.get("signedPreKey")
            if old and old.get("keyId") != new_signed["keyId"]:
                acct.setdefault("previousSignedPreKeys", []).append(
                    dict(old, archivedAt=now_ms))
            acct["signedPreKey"] = new_signed
            acct["activeSignedPreKeyId"] = new_signed["keyId"]
            acct["signedPreKeyRotatedAt"] = now_ms
            # The new key is active; remove its placeholder from the pool.
            acct["previousSignedPreKeys"] = [
                e for e in acct.get("previousSignedPreKeys", [])
                if e.get("keyId") != new_signed["keyId"]]
        if new_last_resort is not None:
            old = acct.get("kyberPreKey")
            if old and old.get("keyId") != new_last_resort["keyId"]:
                acct.setdefault("previousKyberPreKeys", []).append(
                    dict(old, archivedAt=now_ms))
            acct["kyberPreKey"] = new_last_resort
            acct["activeLastResortKyberPreKeyId"] = new_last_resort["keyId"]
            acct["kyberPreKeyRotatedAt"] = now_ms
            acct["previousKyberPreKeys"] = [
                e for e in acct.get("previousKyberPreKeys", [])
                if e.get("keyId") != new_last_resort["keyId"]]
        _clean_archived(acct, now_ms)

    summary["ecUploaded"] = len(body.get("preKeys", []))
    summary["kyberUploaded"] = len(body.get("pqPreKeys", []))
    summary["signedRotated"] = new_signed is not None
    summary["lastResortRotated"] = new_last_resort is not None
    return summary


def maintain_if_due(config_path, *, base_url: str = DEFAULT_BASE_URL,
                    now_ms: int | None = None) -> dict | None:
    """Run :func:`refresh_prekeys` if the last run is older than the refresh
    interval (Signal-Android's ``enqueueIfNeeded`` gating). Returns the summary
    or ``None`` when skipped. Errors are downgraded to a warning — maintenance
    must never take down a receive loop — and left un-stamped so the next
    connect retries.
    """
    from .store import locked_account

    if now_ms is None:
        now_ms = int(time.time() * 1000)

    with locked_account(config_path, write=False) as config_data:
        last = config_data.get("nativePreKeyRefreshAt", 0)
    if 0 <= now_ms - last < REFRESH_INTERVAL_MS:
        return None

    try:
        summary = refresh_prekeys(config_path, base_url=base_url, now_ms=now_ms)
    except (SignalAPIError, OSError) as e:
        log.warning("prekey maintenance skipped: %s", e)
        return None

    with locked_account(config_path) as config_data:
        config_data["nativePreKeyRefreshAt"] = now_ms
    return summary
