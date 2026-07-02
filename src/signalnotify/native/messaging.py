"""Pure Python implementation of Signal message encryption and sending protocols.

Implements X3DH session establishment, Double Ratchet sending chain,
and message transmission via standard HTTPS PUT endpoints.
"""
import base64
import json
import logging
import os
import time
from pathlib import Path

from . import proto as P
from .registration import make_request, DEFAULT_BASE_URL, SignalAPIError

log = logging.getLogger(__name__)


class SendError(Exception):
    """A send failed for a local / protocol-state reason (not an HTTP error)."""


class AccountNotLinkedError(SendError):
    """No native account configuration found (run: ``signal-notify link``)."""


# Protobuf Varint Helpers
def encode_varint(val):
    res = bytearray()
    while True:
        b = val & 0x7F
        val >>= 7
        if val:
            res.append(b | 0x80)
        else:
            res.append(b)
            break
    return bytes(res)


def encode_varint_field(tag, val):
    return encode_varint((tag << 3) | 0) + encode_varint(val)


def encode_bytes_field(tag, val):
    return encode_varint((tag << 3) | 2) + encode_varint(len(val)) + val


def encode_string_field(tag, val):
    return encode_bytes_field(tag, val.encode("utf-8"))


# Protobuf Message Encoders
def encode_signal_message(ephemeral_pub, counter, previous_counter, ciphertext,
                          pq_ratchet=None, addresses=None):
    data = b""
    data += encode_bytes_field(P.SM_RATCHET_KEY, ephemeral_pub)
    data += encode_varint_field(P.SM_COUNTER, counter)
    data += encode_varint_field(P.SM_PREVIOUS_COUNTER, previous_counter)
    data += encode_bytes_field(P.SM_CIPHERTEXT, ciphertext)
    if pq_ratchet:
        # Field 5: SPQR (post-quantum triple ratchet) message. Required by modern
        # linked devices; the MAC covers it since it's part of this proto.
        data += encode_bytes_field(P.SM_PQ_RATCHET, pq_ratchet)
    if addresses:
        # Field 6: sender/recipient service-id + device binding. libsignal binds
        # it into MAC verification (verify_mac_with_addresses); real clients
        # always include it, so we do too.
        data += encode_bytes_field(P.SM_ADDRESSES, addresses)
    return data


def encode_message_addresses(sender_aci, sender_device, recipient_aci, recipient_device):
    """Build the SignalMessage ``addresses`` field (libsignal serialize_addresses).

    ``sender_fixed_width(17) || sender_device(1) || recipient_fixed_width(17) ||
    recipient_device(1)`` = 36 bytes. Fixed-width service id = kind byte (0x00
    ACI / 0x01 PNI) + 16-byte UUID.

    Returns ``None`` if either id isn't a valid service id (e.g. a phone number
    or a synthetic test value) — libsignal accepts a message with no addresses
    for backward compatibility, so omitting is safe when we can't build them.
    """
    import uuid as _uuid

    def fixed_width(service_id):
        if service_id.startswith("PNI:"):
            return b"\x01" + _uuid.UUID(service_id[4:]).bytes
        return b"\x00" + _uuid.UUID(service_id).bytes

    try:
        return (fixed_width(sender_aci) + bytes([sender_device & 0xFF])
                + fixed_width(recipient_aci) + bytes([recipient_device & 0xFF]))
    except (ValueError, AttributeError):
        return None


def encode_prekey_signal_message(registration_id, prekey_id, signed_prekey_id, base_key, identity_key, message):
    data = b""
    if prekey_id is not None:
        data += encode_varint_field(P.PKSM_PRE_KEY_ID, prekey_id)
    data += encode_bytes_field(P.PKSM_BASE_KEY, base_key)
    data += encode_bytes_field(P.PKSM_IDENTITY_KEY, identity_key)
    data += encode_bytes_field(P.PKSM_MESSAGE, message)
    data += encode_varint_field(P.PKSM_REGISTRATION_ID, registration_id)
    if signed_prekey_id is not None:
        data += encode_varint_field(P.PKSM_SIGNED_PRE_KEY_ID, signed_prekey_id)
    return data


def encode_data_message(body_text, timestamp_ms, profile_key=None,
                        attachment_pointers=None):
    """Encode a DataMessage matching what the Signal app emits for a text message.

    Fields (per SignalService.proto): body(1), attachments(2), expireTimer(5),
    profileKey(6), timestamp(7), requiredProtocolVersion(12),
    expireTimerVersion(23), emitted in numeric order like real clients. The
    profileKey is required for the primary to attribute and display the
    message. ``attachment_pointers`` are serialized ``AttachmentPointer``
    protos (see :mod:`attachments`); ``body_text`` may be empty for an
    attachment-only message.
    """
    data = b""
    if body_text:
        data += encode_string_field(P.DATA_BODY, body_text)
    for pointer_bytes in attachment_pointers or []:
        data += encode_bytes_field(P.DATA_ATTACHMENTS, pointer_bytes)
    data += encode_varint_field(P.DATA_EXPIRE_TIMER, 0)   # no disappearing
    if profile_key:
        data += encode_bytes_field(P.DATA_PROFILE_KEY, profile_key)  # 32 bytes
    data += encode_varint_field(P.DATA_TIMESTAMP, timestamp_ms)
    data += encode_varint_field(P.DATA_REQUIRED_PROTOCOL_VERSION, 0)
    data += encode_varint_field(P.DATA_EXPIRE_TIMER_VERSION, 1)
    return data


def encode_sync_message_sent(destination_aci, timestamp_ms, data_message_bytes,
                             destination_e164=None):
    """Encode a SyncMessage.Sent transcript matching what a real client emits.

    Ground truth: a phone-generated Note-to-Self transcript captured via our own
    receive path had exactly fields destinationE164(1), timestamp(2), message(3),
    expirationStartTimestamp(4), isRecipientUpdate(6), destinationServiceIdBinary
    (12). It does NOT carry unidentifiedStatus(5) — that list is populated only
    for ordinary (sealed-sender) recipients, and Note-to-Self has no
    unidentified-delivery semantics, so field 5 never reaches the wire. Fields 4
    and 6 are default-valued (0 / false) but the real client emits them, so we
    match the capture byte-structure exactly to remove that variable.
    """
    import uuid as _uuid

    data = b""
    if destination_e164:
        data += encode_string_field(P.SENT_DESTINATION_E164, destination_e164)
    data += encode_varint_field(P.SENT_TIMESTAMP, timestamp_ms)
    data += encode_bytes_field(P.SENT_MESSAGE, data_message_bytes)
    # Capture shows expirationStartTimestamp = the message timestamp (not 0),
    # even with no disappearing timer. Match it exactly.
    data += encode_varint_field(P.SENT_EXPIRATION_START, timestamp_ms)
    data += encode_varint_field(P.SENT_IS_RECIPIENT_UPDATE, 0)
    try:
        aci_binary = _uuid.UUID(destination_aci).bytes
        data += encode_bytes_field(P.SENT_DESTINATION_SERVICE_ID_BINARY, aci_binary)
    except (ValueError, AttributeError):
        pass
    return data


def encode_sync_message(sent_bytes):
    return encode_bytes_field(P.SYNC_SENT, sent_bytes)


def encode_content(data_message_bytes=None, sync_message_bytes=None):
    """Encode a Content protobuf (the dataMessage/syncMessage oneof).

    IMPORTANT: never add padding as a Content field here. Content field 8 is
    ``decryptionErrorMessage`` (per SignalService.proto) -- stuffing padding
    bytes there makes the receiving client treat the whole message as a
    decryption-error/retry notice and silently refuse to display it. Padding is
    applied at the byte level in :func:`pad_content` via the 0x80 boundary
    marker (libsignal ``PADDING_BOUNDARY_BYTE``), not as a protobuf field.
    """
    data = b""
    if data_message_bytes is not None:
        data += encode_bytes_field(P.CONTENT_DATA_MESSAGE, data_message_bytes)
    elif sync_message_bytes is not None:
        data += encode_bytes_field(P.CONTENT_SYNC_MESSAGE, sync_message_bytes)
    return data


# Signal message padding block, from Signal-Android PushTransportDetails
# (PADDING_BLOCK_SIZE). The message plaintext is the Content protobuf followed by
# a single 0x80 boundary byte and 0x00 bytes to the block boundary. This is a
# BYTE-level scheme, applied *after* the protobuf -- never a Content field.
PADDING_BLOCK_SIZE = 80


def push_pad(content: bytes) -> bytes:
    """Apply Signal's transport padding to a serialized Content protobuf.

    Mirrors ``PushTransportDetails.getPaddedMessageBody`` exactly:
    ``paddedLen = getPaddedMessageLength(len(content) + 1) - 1``; copy content,
    write 0x80 at ``content[len]``, leave the rest 0x00. ``getPaddedMessageLength``
    rounds ``messageLength + 1`` up to a multiple of ``PADDING_BLOCK_SIZE`` (80).
    """
    message_length_with_terminator = (len(content) + 1) + 1
    parts = (message_length_with_terminator + PADDING_BLOCK_SIZE - 1) // PADDING_BLOCK_SIZE
    padded_len = parts * PADDING_BLOCK_SIZE - 1
    out = bytearray(padded_len)
    out[:len(content)] = content
    out[len(content)] = 0x80
    return bytes(out)


def pad_content(body_text, destination_aci=None, timestamp_ms=None,
                profile_key=None, destination_e164=None,
                attachment_pointers=None):
    """Encode a Content protobuf and apply Signal's 0x80 transport padding."""
    if timestamp_ms is None:
        timestamp_ms = int(time.time() * 1000)

    data_msg = encode_data_message(body_text, timestamp_ms, profile_key=profile_key,
                                   attachment_pointers=attachment_pointers)

    if destination_aci is not None:
        # Note-to-Self: wrap inside SyncMessage.Sent
        sync_sent = encode_sync_message_sent(destination_aci, timestamp_ms, data_msg,
                                             destination_e164=destination_e164)
        content = encode_content(sync_message_bytes=encode_sync_message(sync_sent))
    else:
        content = encode_content(data_message_bytes=data_msg)

    return push_pad(content)


def find_account_config(account_selector=None, data_dir=None):
    """Finds the path to the account configuration file based on a selector."""
    if data_dir is None:
        from ..config import get_data_dir
        data_dir = get_data_dir()
    data_path = Path(data_dir).expanduser()
    accounts_json_path = data_path / "accounts.json"
    if not accounts_json_path.exists():
        return None
        
    try:
        with open(accounts_json_path) as f:
            accounts_data = json.load(f)
    except Exception:
        return None
        
    accounts = accounts_data.get("accounts", [])
    if not accounts:
        return None
        
    selected = None
    if account_selector:
        for acc in accounts:
            if account_selector in (acc.get("number"), acc.get("uuid"), acc.get("path")):
                selected = acc
                break
    else:
        selected = accounts[0]
        
    if not selected:
        return None
        
    config_file_path = data_path / selected["path"]
    if not config_file_path.exists():
        return None
        
    return config_file_path


def _prepare_outgoing(config_data, text, recipient, timestamp_ms, base_url,
                      drop_ids=(), force_bundle=False, attachment_pointers=None):
    """Build the encrypted per-device messages for one send, mutating ``config_data``.

    Runs UNDER the account-store lock: it reads and advances the shared
    ``nativeRatchetSessions`` / ``nativeDevices`` state. Reuses stored Double
    Ratchet sessions: once a session and the peer device's registration id are
    cached, repeated sends go out as WHISPERs with NO ``/v2/keys`` fetch
    (avoiding prekey-fetch rate limits) — only a first send, or
    ``force_bundle`` (device reconcile), fetches the bundle. ``drop_ids`` are
    device ids whose sessions/cache entries are discarded first (409/410
    handling).

    Returns ``(outgoing, target_recipient, headers)``.
    """
    import base64
    from . import ratchet as _r

    our_number = config_data["number"]
    our_password = config_data["password"]
    our_device_id = config_data.get("deviceId", 1)
    our_aci = config_data["aciAccountData"]["serviceId"]
    our_registration_id = config_data["aciAccountData"]["registrationId"]
    our_identity_priv_bytes = base64.b64decode(config_data["aciAccountData"]["identityPrivateKey"])
    our_identity_pub_prefixed = base64.b64decode(config_data["aciAccountData"]["identityPublicKey"])

    our_profile_key = None
    if config_data.get("profileKey"):
        try:
            our_profile_key = base64.b64decode(config_data["profileKey"] + "==")
        except Exception:
            our_profile_key = None

    is_note_to_self = (recipient is None or recipient == our_number or recipient == our_aci)
    target_recipient = our_aci if is_note_to_self else recipient

    auth_str = f"{our_aci}.{our_device_id}:{our_password}"
    auth_b64 = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
    headers = {"Authorization": f"Basic {auth_b64}"}

    # Session store (shared with receive) + cached peer device set -> reg id.
    # nativeDevices lets us build WHISPERs without refetching /v2/keys.
    sessions = config_data.setdefault("nativeRatchetSessions", {})
    devices_cache = config_data.setdefault("nativeDevices", {}).setdefault(target_recipient, {})

    def make_plaintext():
        destination_aci = our_aci if is_note_to_self else None
        return pad_content(text, destination_aci=destination_aci,
                           timestamp_ms=timestamp_ms, profile_key=our_profile_key,
                           destination_e164=our_number if is_note_to_self else None,
                           attachment_pointers=attachment_pointers)

    def encrypt_whisper(device_id, reg_id):
        """Encrypt on the stored session (Double Ratchet WHISPER). No fetch."""
        session_key = f"{target_recipient}:{device_id}"
        session = _r.session_from_json(sessions[session_key])
        addresses = encode_message_addresses(our_aci, our_device_id, target_recipient, device_id)
        content_bytes = _r.ratchet_encrypt(session, make_plaintext(),
                                           version=_r.CIPHERTEXT_VERSION_V4, addresses=addresses)
        sessions[session_key] = _r.session_to_json(session)
        devices_cache[str(device_id)] = reg_id
        return {"type": 1, "destinationDeviceId": device_id,
                "destinationRegistrationId": reg_id,
                "content": base64.b64encode(content_bytes).decode("utf-8")}

    def encrypt_prekey(device, rec_identity_pub):
        """PQXDH-initiate a new session and frame a v4 PreKeySignalMessage."""
        device_id = device["deviceId"]
        reg_id = device["registrationId"]
        rec_spk_pub = base64.b64decode(device["signedPreKey"]["publicKey"])
        signed_prekey_id = device["signedPreKey"]["keyId"]
        opk_pub = base64.b64decode(device["preKey"]["publicKey"]) if device.get("preKey") else None
        pre_key_id = device["preKey"]["keyId"] if device.get("preKey") else None
        kyber_pub = base64.b64decode(device["pqPreKey"]["publicKey"]) if device.get("pqPreKey") else None
        kyber_prekey_id = device["pqPreKey"]["keyId"] if device.get("pqPreKey") else None

        session, base_pub, kyber_ct = _r.init_sender_session(
            our_identity_priv=our_identity_priv_bytes,
            our_identity_pub=our_identity_pub_prefixed,
            their_identity_pub=rec_identity_pub,
            their_signed_prekey_pub=rec_spk_pub,
            their_one_time_prekey_pub=opk_pub, their_kyber_pub=kyber_pub)
        addresses = encode_message_addresses(our_aci, our_device_id, target_recipient, device_id)
        inner = _r.ratchet_encrypt(session, make_plaintext(),
                                   version=_r.CIPHERTEXT_VERSION_V4, addresses=addresses)
        content_bytes = _r.frame_prekey_message(
            inner_serialized=inner, base_pub=base_pub,
            our_identity_pub=our_identity_pub_prefixed, registration_id=our_registration_id,
            signed_prekey_id=signed_prekey_id, pre_key_id=pre_key_id,
            kyber_prekey_id=kyber_prekey_id, kyber_ciphertext=kyber_ct,
            version=_r.CIPHERTEXT_VERSION_V4)
        sessions[f"{target_recipient}:{device_id}"] = _r.session_to_json(session)
        devices_cache[str(device_id)] = reg_id
        return {"type": 3, "destinationDeviceId": device_id,
                "destinationRegistrationId": reg_id,
                "content": base64.b64encode(content_bytes).decode("utf-8")}

    def build_from_bundle():
        """Fetch /v2/keys and (re)build outgoing for every active device."""
        bundle, _ = make_request(f"/v2/keys/{target_recipient}/*", method="GET",
                                 headers=headers, base_url=base_url)
        rec_identity_pub = base64.b64decode(bundle["identityKey"])
        out = []
        live_devices = set()
        for device in bundle.get("devices", []):
            device_id = device["deviceId"]
            if is_note_to_self and device_id == our_device_id:
                continue
            live_devices.add(str(device_id))
            if f"{target_recipient}:{device_id}" in sessions:
                out.append(encrypt_whisper(device_id, device["registrationId"]))
            else:
                out.append(encrypt_prekey(device, rec_identity_pub))
        # Drop any cached/session devices the server no longer lists.
        for stale in [d for d in list(devices_cache) if d not in live_devices]:
            devices_cache.pop(stale, None)
            sessions.pop(f"{target_recipient}:{stale}", None)
        return out

    for d in drop_ids:
        sessions.pop(f"{target_recipient}:{d}", None)
        devices_cache.pop(str(d), None)

    # Fast path: cached device set with a live session for each -> WHISPER, no fetch.
    fast_ids = [int(d) for d in devices_cache
                if not (is_note_to_self and int(d) == our_device_id)]
    can_fast = (not force_bundle and bool(fast_ids)
                and all(f"{target_recipient}:{d}" in sessions for d in fast_ids))

    if can_fast:
        outgoing = [encrypt_whisper(d, devices_cache[str(d)]) for d in fast_ids]
    else:
        outgoing = build_from_bundle()
    return outgoing, target_recipient, headers


def send_message_native(config_path, text, recipient=None, base_url=DEFAULT_BASE_URL,
                        raise_on_error=False, attachments=None):
    """Encrypt and send to Note-to-Self (or a recipient) natively.

    ``attachments`` is an optional list of file paths (or ``bytes``): each is
    encrypted and uploaded to Signal's CDN first (network, outside the account
    lock), then referenced from the message as ``DataMessage.attachments``
    pointers. ``text`` may be empty for an attachment-only message.

    Concurrency: all crypto-state mutation happens inside
    :func:`store.locked_account` — the config is reloaded fresh under the lock,
    advanced, and persisted before the lock is released (commit-before-send: a
    crash between persist and PUT can only skip a message key, which the
    ratchet tolerates, never reuse one). The network ``PUT`` runs *outside* the
    lock so a slow send never blocks a concurrent receiver.

    The server's 409 (MismatchedDevices) / 410 (StaleDevices) responses are
    handled per Signal-Android: drop extra/stale sessions, (re)establish
    missing ones, retry once.

    Errors: returns ``False`` by default, logging the cause. With
    ``raise_on_error=True`` the underlying exception propagates instead —
    :class:`SignalAPIError` for a server rejection (inspect ``.code``: 429 =
    rate-limited, 401/403 = credentials revoked → re-link) or
    :class:`SendError` for local preconditions — so callers can react
    programmatically.
    """
    from .store import locked_account

    timestamp_ms = int(time.time() * 1000)

    def fail(exc, msg):
        log.error(msg)
        if raise_on_error:
            raise exc
        return False

    # Upload attachments FIRST (pure network, no crypto-state mutation, so no
    # lock): the resulting pointers are then baked into the plaintext.
    attachment_pointers = None
    if attachments:
        from .attachments import encode_attachment_pointer, upload_attachment
        with locked_account(config_path, write=False) as config_data:
            our_aci = config_data["aciAccountData"]["serviceId"]
            our_device_id = config_data.get("deviceId", 1)
            auth = base64.b64encode(
                f"{our_aci}.{our_device_id}:{config_data['password']}".encode()).decode()
        auth_headers = {"Authorization": f"Basic {auth}"}
        try:
            attachment_pointers = [
                encode_attachment_pointer(
                    upload_attachment(a, auth_headers=auth_headers,
                                      base_url=base_url))
                for a in attachments]
        except SignalAPIError as e:
            return fail(e, f"error uploading attachment: {e.message} "
                           f"(HTTP {e.code})")

    try:
        with locked_account(config_path) as config_data:
            outgoing, target_recipient, headers = _prepare_outgoing(
                config_data, text, recipient, timestamp_ms, base_url,
                attachment_pointers=attachment_pointers)
    except SignalAPIError as e:
        return fail(e, f"error preparing message: {e.message} (HTTP {e.code})")

    if not outgoing:
        return fail(SendError("no target devices to send to"),
                    "no target devices to send to")

    def put(messages):
        body = {"destination": target_recipient, "timestamp": timestamp_ms,
                "messages": messages, "online": False, "urgent": True}
        make_request(f"/v1/messages/{target_recipient}", method="PUT",
                     body=body, headers=headers, base_url=base_url)

    try:
        put(outgoing)
        return True
    except SignalAPIError as e:
        if e.code not in (409, 410):
            return fail(e, f"error sending to {target_recipient}: "
                           f"{e.message} (HTTP {e.code})")
        # 409 MismatchedDevices {missingDevices,extraDevices} / 410 StaleDevices
        # {staleDevices}: drop the offending sessions, then refetch + rebuild for
        # the corrected device set and retry once (per Signal-Android
        # handleMismatchedDevices / handleStaleDevices).
        try:
            err = json.loads(e.response_body) if e.response_body else {}
        except (ValueError, TypeError):
            err = {}
        drop_ids = ((err.get("extraDevices") or []) + (err.get("staleDevices") or [])
                    + (err.get("missingDevices") or []))  # missing -> force fresh PREKEY
        log.info("%s device mismatch, reconciling and retrying once", e.code)
        try:
            with locked_account(config_path) as config_data:
                outgoing, target_recipient, headers = _prepare_outgoing(
                    config_data, text, recipient, timestamp_ms, base_url,
                    drop_ids=drop_ids, force_bundle=True,
                    attachment_pointers=attachment_pointers)
            if not outgoing:
                return fail(SendError("no target devices after reconcile"),
                            "no target devices after reconcile")
            put(outgoing)
            return True
        except SignalAPIError as e2:
            return fail(e2, f"error sending to {target_recipient} after reconcile: "
                            f"{e2.message} (HTTP {e2.code})")
