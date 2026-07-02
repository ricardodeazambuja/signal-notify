"""Native (pure-Python) Signal receive: authenticated WebSocket + decrypt.

Connects the authenticated
websocket, decodes the ``WebSocketMessage`` framing that wraps each ``Envelope``,
decrypts PREKEY / whisper messages with :mod:`ratchet`, parses the plaintext
``Content`` (including the ``SyncMessage.Sent`` transcripts the primary phone
emits for Note-to-Self), and ACKs each message so the server clears it.

Public surface mirrors the old receiver: a :class:`Message` dataclass, a one-shot
:func:`receive` drain (cron fit), :func:`receive_note_to_self`, and :func:`listen`.

Requires an account **linked natively** (``signal-notify link``): responder decryption
needs the signed-prekey / Kyber-prekey / one-time-prekey privates that
:func:`provisioning.save_account_config` persists. An account created by a
different Signal client keeps those elsewhere (e.g. an SQLite store), so this
cannot decrypt for it.
"""
from __future__ import annotations

import asyncio
import base64
import logging
from dataclasses import dataclass, field

from . import proto as P
from .messaging import (encode_bytes_field, encode_string_field,
                        encode_varint_field)
from .provisioning import _ws_connect
from .ratchet import (account_keys_from_config, accept_prekey, ratchet_decrypt,
                      session_from_json, session_to_json, Session)
from .registration import DEFAULT_USER_AGENT, DEFAULT_WS_URL, decode_proto

log = logging.getLogger(__name__)

# Envelope.type values (SignalService.proto)
TYPE_WHISPER = 1
TYPE_PREKEY = 3
TYPE_RECEIPT = 5
TYPE_SEALED = 6
TYPE_PLAINTEXT = 8


@dataclass
class Message:
    """A received Signal message, normalized across direct / Note-to-Self forms.

    ``attachments`` holds one pointer dict per received attachment (cdnKey,
    key material, digest, size, contentType, fileName…) — pass each to
    :func:`signalnotify.native.attachments.download_attachment` to fetch and
    decrypt it.
    """
    timestamp: int | None
    body: str | None
    source: str | None
    source_name: str | None
    note_to_self: bool
    group_id: str | None
    raw: dict = field(default_factory=dict, repr=False)
    attachments: list = field(default_factory=list)

    @property
    def is_text(self) -> bool:
        return bool(self.body)


# ---- plaintext Content parsing --------------------------------------------
def _strip_push_padding(data: bytes) -> bytes:
    """Remove Signal's transport padding (``0x80`` marker followed by ``0x00``s).

    The phone pads the plaintext with a single ``0x80`` byte and then ``0x00``
    bytes to a block boundary. Scan back over trailing zeros; if a ``0x80``
    marker is found, drop it and everything after. If a different non-zero byte
    appears first the data is already unpadded (e.g. our own field-8 padding),
    so leave it untouched.
    """
    for i in range(len(data) - 1, -1, -1):
        b = data[i]
        if b == 0x80:
            return data[:i]
        if b != 0x00:
            return data
    return data


def _sent_destination_ids(sent: dict) -> set:
    """Candidate destination ids for a ``SyncMessage.Sent`` transcript.

    Modern Signal (SignalService.proto) carries the destination in
    ``destinationServiceIdBinary`` (field 12): a raw 16-byte UUID for an ACI, or
    a 1-byte prefix + 16-byte UUID for a PNI. The legacy string
    ``destinationServiceId`` (7) and ``destinationE164`` (1) are usually empty
    now. We return every form we can derive so a match against ``_self_ids``
    (which holds the ACI/PNI UUID strings and the E164 number) succeeds.
    """
    import uuid as _uuid

    ids = set()
    raw = sent.get(P.SENT_DESTINATION_SERVICE_ID_BINARY, [b""])[0]
    if isinstance(raw, bytes):
        if len(raw) == 16:
            ids.add(str(_uuid.UUID(bytes=raw)))
        elif len(raw) == 17:  # PNI: 1-byte prefix + 16-byte UUID
            ids.add(str(_uuid.UUID(bytes=raw[1:])))
            ids.add("PNI:" + str(_uuid.UUID(bytes=raw[1:])))
    # legacy destinationServiceId / destinationE164 strings
    for field in (P.SENT_DESTINATION_SERVICE_ID, P.SENT_DESTINATION_E164):
        val = sent.get(field, [b""])[0]
        if isinstance(val, bytes) and val:
            ids.add(val.decode("utf-8", "replace"))
    return ids


def _parse_attachments(dm: dict) -> list:
    """Decode ``DataMessage.attachments`` pointers into pointer dicts."""
    from .attachments import parse_attachment_pointer
    out = []
    for pointer_bytes in dm.get(P.DATA_ATTACHMENTS, []):
        try:
            out.append(parse_attachment_pointer(pointer_bytes))
        except (ValueError, KeyError) as e:
            log.warning("skipping unparseable attachment pointer: %s", e)
    return out


def parse_content(plaintext: bytes, self_ids: set, source: str | None,
                  envelope_ts: int | None) -> Message | None:
    """Parse a decrypted ``Content`` protobuf into a :class:`Message`.

    Returns ``None`` for envelopes with no user text (receipts, typing, other
    sync messages). A ``SyncMessage.Sent`` addressed to one of our own ids is
    flagged ``note_to_self`` — the reply typed in the phone's Note-to-Self chat.
    """
    fields = decode_proto(_strip_push_padding(plaintext))

    if P.CONTENT_DATA_MESSAGE in fields:
        dm = decode_proto(fields[P.CONTENT_DATA_MESSAGE][0])
        body = dm.get(P.DATA_BODY, [b""])[0]
        body = body.decode("utf-8", "replace") if isinstance(body, bytes) else None
        group_id = None
        if P.DATA_GROUP_V2 in dm:
            group_id = base64.b64encode(dm[P.DATA_GROUP_V2][0]).decode()
        return Message(timestamp=dm.get(P.DATA_TIMESTAMP, [envelope_ts])[0], body=body or None,
                       source=source, source_name=None, note_to_self=False,
                       group_id=group_id, raw={},
                       attachments=_parse_attachments(dm))

    if P.CONTENT_SYNC_MESSAGE in fields:
        sync = decode_proto(fields[P.CONTENT_SYNC_MESSAGE][0])
        if P.SYNC_SENT in sync:
            sent = decode_proto(sync[P.SYNC_SENT][0])
            dest_ids = _sent_destination_ids(sent)
            dm_bytes = sent.get(P.SENT_MESSAGE, [b""])[0]
            body = None
            group_id = None
            atts = []
            if dm_bytes:
                dm = decode_proto(dm_bytes)
                b = dm.get(P.DATA_BODY, [b""])[0]
                body = b.decode("utf-8", "replace") if isinstance(b, bytes) else None
                if P.DATA_GROUP_V2 in dm:
                    group_id = base64.b64encode(dm[P.DATA_GROUP_V2][0]).decode()
                atts = _parse_attachments(dm)
            note_to_self = bool(not group_id and (dest_ids & self_ids))
            return Message(timestamp=sent.get(P.SENT_TIMESTAMP, [envelope_ts])[0], body=body or None,
                           source=source, source_name=None,
                           note_to_self=note_to_self, group_id=group_id, raw={},
                           attachments=atts)

    # Receipt / typing / other sync — no user content.
    return None


# ---- account / session store ----------------------------------------------
def _b64d(s: str) -> bytes:
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _self_ids(config_data: dict) -> set:
    ids = set()
    if config_data.get("number"):
        ids.add(config_data["number"])
    aci = (config_data.get("aciAccountData") or {}).get("serviceId")
    if aci:
        ids.add(aci)
    pni = (config_data.get("pniAccountData") or {}).get("serviceId")
    if pni:
        ids.add(pni)
        ids.add(pni[4:] if pni.startswith("PNI:") else f"PNI:{pni}")
    return ids


def _decrypt_envelope(env: dict, account_keys: dict, sessions: dict,
                      our_aci: str | None = None) -> tuple[bytes | None, str | None, int | None]:
    """Decrypt one Envelope field-map. Returns ``(plaintext, source, timestamp)``.

    Updates ``sessions`` (the ``nativeRatchetSessions`` map) in place. Returns
    ``(None, ...)`` for envelopes we cannot or need not decrypt.
    """
    etype = env.get(P.ENVELOPE_TYPE, [None])[0]
    content = env.get(P.ENVELOPE_CONTENT, [b""])[0] if P.ENVELOPE_CONTENT in env else b""
    source = env.get(P.ENVELOPE_SOURCE_SERVICE_ID, [b""])[0]
    source = source.decode("utf-8", "replace") if isinstance(source, bytes) else None
    # Self / sync envelopes (our own devices, incl. Note-to-Self replies) arrive
    # with an EMPTY source field -- the server omits it for own-account traffic.
    # Our send keys the session by our ACI ("{our_aci}:{device}"), so map an empty
    # source to our ACI here; otherwise receive keys ":{device}" and can't find
    # the session our own send established (the two directions would diverge).
    if not source and our_aci:
        source = our_aci
    source_device = env.get(P.ENVELOPE_SOURCE_DEVICE, [1])[0]
    ts = env.get(P.ENVELOPE_TIMESTAMP, [None])[0]
    session_key = f"{source}:{source_device}"

    if etype == TYPE_PREKEY:
        session, plaintext = accept_prekey(account_keys, content)
        sessions[session_key] = session_to_json(session)
        return plaintext, source, ts

    if etype == TYPE_WHISPER:
        stored = sessions.get(session_key)
        if stored is None:
            raise ValueError(f"no session for {session_key} (whisper before prekey)")
        session = session_from_json(stored)
        plaintext = ratchet_decrypt(session, content)
        sessions[session_key] = session_to_json(session)
        return plaintext, source, ts

    if etype == TYPE_SEALED:
        # Sealed-sender (unidentified) delivery. Unwrapping needs the
        # sealed-sender protocol; not required for the phone's own Note-to-Self
        # sync transcripts, which are sender-authenticated. Left as a gap.
        raise NotImplementedError("sealed-sender (type 6) unwrap not implemented")

    # Receipts / plaintext-content envelopes carry no ciphertext to decrypt.
    return None, source, ts


# ---- spool files (quarantine + inbox journal) ------------------------------
def _quarantine(config_path, envelope_bytes: bytes, err: Exception) -> None:
    """Preserve an envelope we could not decrypt BEFORE it is acked.

    The server's ack semantics are delete-forever, so without this a
    sealed-sender (type 6) message from a contact would be destroyed
    unreadable. The raw envelope is appended to
    ``<config>.undecryptable.jsonl`` (owner-only) with whatever metadata
    parses; if sealed-sender unwrap is implemented later, these records are
    replayable.
    """
    import json
    import time as _time

    rec = {"receivedAt": int(_time.time() * 1000), "error": str(err),
           "envelope_b64": base64.b64encode(envelope_bytes).decode()}
    try:
        env = decode_proto(envelope_bytes)
        rec["type"] = env.get(P.ENVELOPE_TYPE, [None])[0]
        src = env.get(P.ENVELOPE_SOURCE_SERVICE_ID, [b""])[0]
        rec["source"] = src.decode("utf-8", "replace") if isinstance(src, bytes) else None
        rec["timestamp"] = env.get(P.ENVELOPE_TIMESTAMP, [None])[0]
    except Exception:
        pass  # metadata is best-effort; the raw envelope is what matters
    from ..config import append_line_secure
    append_line_secure(f"{config_path}.undecryptable.jsonl", json.dumps(rec))


def _capture(capture_dir: str, envelope_bytes: bytes) -> None:
    """Wire-capture hook: dump every raw envelope for fixture-building.

    Enabled by the ``SIGNALNOTIFY_CAPTURE_DIR`` env var. ⚠️ Use ONLY with a
    throwaway test account: captures pair with the account privates to form
    decryptable fixtures, and this project's history was once scrubbed for
    exactly this kind of material. See tests/fixtures/generate_fixtures.py.
    """
    import json
    import os
    import time as _time

    os.makedirs(capture_dir, exist_ok=True)
    from ..config import append_line_secure
    append_line_secure(
        os.path.join(capture_dir, "capture.jsonl"),
        json.dumps({"receivedAt": int(_time.time() * 1000),
                    "envelope_b64": base64.b64encode(envelope_bytes).decode()}))


def _journal(config_path, msg: "Message") -> None:
    """Append a parsed message to ``<config>.inbox.jsonl`` (before the ack)."""
    import json
    import time as _time

    def _jsonable(pointer):
        return {k: (base64.b64encode(v).decode() if isinstance(v, bytes) else v)
                for k, v in pointer.items()}

    rec = {"receivedAt": int(_time.time() * 1000), "timestamp": msg.timestamp,
           "body": msg.body, "source": msg.source, "source_name": msg.source_name,
           "note_to_self": msg.note_to_self, "group_id": msg.group_id,
           "attachments": [_jsonable(p) for p in msg.attachments]}
    from ..config import append_line_secure
    append_line_secure(f"{config_path}.inbox.jsonl", json.dumps(rec, ensure_ascii=False))


# ---- websocket receive loop ------------------------------------------------
def _ack_frame(request_id: int) -> bytes:
    """Build a WebSocketMessage(RESPONSE, status 200) for a request id."""
    response = (encode_varint_field(P.WSRES_ID, request_id)
                + encode_varint_field(P.WSRES_STATUS, 200)
                + encode_string_field(P.WSRES_MESSAGE, "OK"))
    return (encode_varint_field(P.WSM_TYPE, P.WSM_TYPE_RESPONSE)
            + encode_bytes_field(P.WSM_RESPONSE, response))


async def _receive_async(config_path, timeout, max_messages, ws_url,
                         on_message=None, stop=None, drain=True, journal=False,
                         maintain=False):
    from .store import locked_account

    if maintain:
        # Opportunistic prekey upkeep, throttled to Signal's refresh interval;
        # never fatal for the receive loop (errors are logged and retried on
        # the next connect).
        from .maintenance import maintain_if_due
        maintain_if_due(config_path)

    # Credentials and self-ids are immutable for the connection lifetime; read
    # them once. All MUTABLE state (nativeRatchetSessions) is reloaded fresh
    # under the account lock per envelope below, so a concurrent send (e.g. the
    # listen() callback calling send_message in another read-modify-write) is
    # never clobbered by a stale snapshot from connect time.
    with locked_account(config_path, write=False) as config_data:
        aci = config_data["aciAccountData"]["serviceId"]
        device_id = config_data.get("deviceId", 1)
        password = config_data["password"]
        self_ids = _self_ids(config_data)

    # The authenticated websocket is authenticated by an HTTP Basic auth HEADER
    # on the handshake (username "{aci}.{deviceId}"), NOT by ?login=&password=
    # query params — Signal ignores the query form, leaving the socket
    # unauthenticated so no queued messages are ever delivered.
    auth = base64.b64encode(f"{aci}.{device_id}:{password}".encode()).decode()
    url = f"{ws_url}/v1/websocket/"
    headers = {"User-Agent": DEFAULT_USER_AGENT, "X-Signal-Agent": DEFAULT_USER_AGENT,
               "Authorization": f"Basic {auth}"}

    # drain=True (default): one-shot — drain what's queued and return (break on
    # queue/empty; ``timeout`` is the per-recv idle wait). drain=False: stay
    # connected and dispatch messages as the server pushes them, up to a
    # ``timeout``-second wall-clock budget — the primitive an agent chat loop
    # needs to wait for a reply on a single persistent connection.
    loop = asyncio.get_event_loop()
    deadline = None if drain else loop.time() + timeout
    messages: list[Message] = []
    async with _ws_connect(url, headers) as ws:
        while True:
            if stop is not None and stop():
                break
            if deadline is not None:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                recv_timeout = min(remaining, 30)  # cap so stop()/deadline are re-checked
            else:
                recv_timeout = timeout
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=recv_timeout)
            except asyncio.TimeoutError:
                if drain:
                    break
                continue  # persistent mode: keep waiting until deadline / stop
            if isinstance(raw, str):
                raw = raw.encode()

            wsm = decode_proto(raw)
            if wsm.get(P.WSM_TYPE, [None])[0] != P.WSM_TYPE_REQUEST:
                continue
            req = decode_proto(wsm[P.WSM_REQUEST][0])
            path = req.get(P.WSREQ_PATH, [b""])[0]
            path = path.decode() if isinstance(path, bytes) else path
            req_id = req.get(P.WSREQ_ID, [0])[0]
            body = req.get(P.WSREQ_BODY, [b""])[0] if P.WSREQ_BODY in req else b""

            if path == "/api/v1/queue/empty":
                await ws.send(_ack_frame(req_id))
                if drain:
                    break
                continue  # persistent mode: caught up, keep the socket open
            if path != "/api/v1/message":
                # Keepalive or other server request — acknowledge and continue.
                await ws.send(_ack_frame(req_id))
                continue

            import os as _os
            capture_dir = _os.environ.get("SIGNALNOTIFY_CAPTURE_DIR")
            if capture_dir:
                _capture(capture_dir, body)

            msg = None
            try:
                env = decode_proto(body)
                # Lock + reload + decrypt + persist as ONE unit: the decrypt
                # advances the shared ratchet state, and locked_account commits
                # it on exit — before the ack below, so an ack we never see
                # cannot desync the ratchet (commit-before-ack), and always on
                # top of the latest on-disk state, never a stale snapshot.
                with locked_account(config_path) as config_data:
                    account_keys = account_keys_from_config(config_data)
                    sessions = config_data.setdefault("nativeRatchetSessions", {})
                    plaintext, source, ts = _decrypt_envelope(env, account_keys,
                                                              sessions, aci)
                if plaintext is not None:
                    msg = parse_content(plaintext, self_ids, source, ts)
                    if msg is not None:
                        msg.raw = {"type": env.get(P.ENVELOPE_TYPE, [None])[0],
                                   "source": source}
                        messages.append(msg)
            except (NotImplementedError, ValueError) as e:
                # Quarantine BEFORE the ack: the ack deletes the message from
                # the server forever (sealed-sender envelopes land here).
                log.warning("quarantining undecryptable envelope: %s", e)
                _quarantine(config_path, body, e)

            # At-least-once for consumers: journal the parsed message before
            # the ack, so a crash in downstream handling cannot lose it.
            if msg is not None and journal:
                _journal(config_path, msg)

            await ws.send(_ack_frame(req_id))

            # Dispatch OUTSIDE the account lock: callbacks routinely call
            # send_message(), which takes the same lock (deadlock otherwise).
            if msg is not None and on_message is not None:
                on_message(msg)

            if max_messages is not None and len(messages) >= max_messages:
                break
    return messages


def receive(*, config_path=None, account=None, timeout: int | None = None,
            idle_timeout: int | None = None, wait: int | None = None,
            max_messages: int | None = None, drain: bool = True,
            ws_url: str = DEFAULT_WS_URL, journal: bool = False,
            maintain: bool = False) -> list[Message]:
    """Receive parsed :class:`Message`\\ s from Signal.

    - ``drain=True`` (default): one-shot. Connects, receives/acks whatever is
      queued (waiting up to ``idle_timeout`` seconds — default 5 — for new
      traffic), and returns; ideal for a per-cycle cron consumer.
    - ``drain=False``: stay connected and collect messages the server pushes
      for up to ``wait`` seconds *total* (wall-clock, default 300), returning
      early once ``max_messages`` is reached. This is how to **wait for a
      reply** on one persistent connection — e.g. ``receive(drain=False,
      max_messages=1, wait=180)`` after sending a prompt.

    ``timeout`` is a deprecated alias: it meant ``idle_timeout`` in drain mode
    and ``wait`` in persistent mode — two different clocks under one name.

    ``journal=True`` appends every parsed message to ``<config>.inbox.jsonl``
    *before* it is acked (the server deletes on ack), so a crash downstream
    cannot lose a message. Undecryptable envelopes are always preserved in
    ``<config>.undecryptable.jsonl`` before their ack.

    ``maintain=True`` runs throttled prekey upkeep (top-up + rotation, see
    :mod:`maintenance`) before connecting.

    Non-content envelopes (receipts, typing) are dropped either way.
    """
    if timeout is not None:
        import warnings
        warnings.warn("receive(timeout=...) is deprecated: use idle_timeout= "
                      "(drain mode) or wait= (persistent mode)",
                      DeprecationWarning, stacklevel=2)
    if drain:
        if wait is not None:
            raise ValueError("wait= applies to drain=False; use idle_timeout=")
        effective = idle_timeout if idle_timeout is not None else (
            timeout if timeout is not None else 5)
    else:
        if idle_timeout is not None:
            raise ValueError("idle_timeout= applies to drain=True; use wait=")
        effective = wait if wait is not None else (
            timeout if timeout is not None else 300)

    if config_path is None:
        from .messaging import find_account_config
        config_path = find_account_config(account)
        if not config_path:
            log.error("no native Signal account configuration found")
            return []
    return asyncio.run(_receive_async(config_path, effective, max_messages, ws_url,
                                      drain=drain, journal=journal,
                                      maintain=maintain))


def receive_note_to_self(**kwargs) -> list[Message]:
    """:func:`receive`, filtered to replies (text or attachments) typed in your
    Note-to-Self chat."""
    return [m for m in receive(**kwargs)
            if m.note_to_self and (m.is_text or m.attachments)]


def listen(callback, *, config_path=None, account=None, poll_interval: int = 5,
           stop=None, ws_url: str = DEFAULT_WS_URL, journal: bool = False) -> None:
    """Daemon loop: dispatch every inbound :class:`Message` to ``callback``.

    Holds a single persistent authenticated connection and calls ``callback(msg)``
    as the server pushes each message (real-time, not polling). If the
    connection drops it reconnects with exponential backoff — ``poll_interval``
    seconds after the first error, doubling per consecutive failure up to 60s
    (plus jitter), reset after a healthy connection — so an outage is not
    hammered. Pass ``stop=lambda: ...`` to break out. Use this for an agent
    that reacts to incoming replies; use ``receive(drain=False,
    max_messages=1)`` for a send-then-wait-for-one-reply turn.

    ``callback`` runs *after* the message is acked (so the server has already
    deleted it) and outside the account lock (so it can call ``send_message``).
    If your callback can crash, pass ``journal=True``: each message is appended
    to ``<config>.inbox.jsonl`` before the ack, so nothing is lost.
    """
    import random
    import time as _time
    if config_path is None:
        from .messaging import find_account_config
        config_path = find_account_config(account)
        if not config_path:
            log.error("no native Signal account configuration found")
            return
    failures = 0
    while True:
        if stop is not None and stop():
            return
        try:
            # Hold one connection for up to an hour, dispatching pushes as they
            # arrive; the outer loop reconnects on drop / after the budget.
            # maintain=True: a daemon is exactly the long-lived device whose
            # prekey supply depletes, so upkeep piggybacks on each reconnect
            # (internally throttled to the 2-day refresh interval).
            asyncio.run(_receive_async(config_path, 3600, None, ws_url,
                                       on_message=callback, stop=stop, drain=False,
                                       journal=journal, maintain=True))
            failures = 0  # a healthy connection resets the backoff
        except Exception as e:  # transient network/socket error -> reconnect
            failures += 1
            delay = min(poll_interval * (2 ** (failures - 1)), 60)
            delay += random.uniform(0, delay / 2)  # jitter: don't thundering-herd
            log.warning("listen reconnecting in %.1fs after error: %s", delay, e)
            _time.sleep(delay)
