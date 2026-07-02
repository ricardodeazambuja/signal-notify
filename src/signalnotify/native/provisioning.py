"""Device provisioning and linking flow for the native Signal client."""
import asyncio
import base64
import hashlib
import inspect
import os
import hmac
import websockets

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .registration import (decode_proto, DEFAULT_BASE_URL, DEFAULT_WS_URL,
                           DEFAULT_USER_AGENT, register_secondary_device,
                           signal_ssl_context)
from .crypto import generate_x25519_keypair, serialize_signal_public_key, generate_linking_payload, encrypt_device_name


def _ws_connect(url, headers, ssl_context=None):
    """Open a WebSocket, tolerating the ``extra_headers`` → ``additional_headers``
    rename in ``websockets`` 14.

    The new (>=14) client accepts ``**kwargs``, so passing the old
    ``extra_headers`` name does *not* raise — the headers are silently dropped
    and the provisioning handshake goes out without ``User-Agent``. Detect the
    supported keyword from the signature instead of relying on an exception.

    For ``wss://`` URLs an ``ssl_context`` trusting Signal's pinned root CA is
    required; it defaults to :func:`signal_ssl_context`.
    """
    kwargs = {}
    if url.startswith("wss://"):
        kwargs["ssl"] = ssl_context or signal_ssl_context()
    try:
        params = inspect.signature(websockets.connect).parameters
        if "additional_headers" in params:
            return websockets.connect(url, additional_headers=headers, **kwargs)
    except (TypeError, ValueError):
        pass
    return websockets.connect(url, extra_headers=headers, **kwargs)


async def _recv_provisioning_body(ws):
    """Receive one provisioning message and return its inner body.

    The provisioning socket wraps each message in the same ``WebSocketMessage``
    framing as the authenticated socket: a ``REQUEST`` whose ``body`` (field 3)
    is the actual ``ProvisioningUuid`` / ``ProvisionEnvelope`` protobuf. Unlike
    the authenticated socket, the provisioning endpoint does not want a client
    ``RESPONSE`` frame back (sending one gets the connection closed with 1007);
    the ``websockets`` library answers protocol-level pings on its own. Skip any
    framing that carries no body (e.g. keepalives).
    """
    while True:
        raw = await ws.recv()
        if isinstance(raw, str):
            raw = raw.encode()
        wsm = decode_proto(raw)
        if wsm.get(1, [None])[0] != 1:  # not a REQUEST
            continue
        req = decode_proto(wsm[2][0])
        body = req.get(3, [b""])[0] if 3 in req else b""
        if body:
            return body


def save_account_config(data_dir, number, aci, pni, password, aci_identity_pub, aci_identity_priv, pni_identity_pub, pni_identity_priv, profile_key, account_entropy_pool, media_root_backup_key, device_id, device_name=None, responder_keys=None):
    """Save the linked account credentials to disk in the account-store JSON format.

    ``responder_keys`` (from :func:`crypto.generate_linking_payload`) carries the
    signed-prekey / Kyber-prekey / one-time-prekey **privates** that responder
    X3DH/PQXDH needs. They are stored under ``aciAccountData`` /
    ``pniAccountData`` keyed by id so the receive path can look up the private
    matching an inbound message's ``signedPreKeyId`` / ``kyberPreKeyId`` /
    ``preKeyId``.
    """
    import json
    import os
    import random
    import base64
    from pathlib import Path
    
    from ..config import atomic_write_secure

    # Ensure data_dir exists and is owner-only (it holds private key material).
    data_path = Path(data_dir).expanduser()
    data_path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(data_path, 0o700)
    except OSError:
        pass

    accounts_json_path = data_path / "accounts.json"
    
    # 1. Read accounts.json
    if accounts_json_path.exists():
        try:
            with open(accounts_json_path, "r") as f:
                accounts_data = json.load(f)
        except Exception:
            accounts_data = {"accounts": [], "version": 2}
    else:
        accounts_data = {"accounts": [], "version": 2}
        
    # Check if account already exists
    existing_account = None
    for acc in accounts_data.get("accounts", []):
        if acc.get("number") == number or acc.get("uuid") == aci:
            existing_account = acc
            break
            
    if existing_account:
        account_path_name = existing_account["path"]
        # Update details in accounts.json
        existing_account["number"] = number
        existing_account["uuid"] = aci
        existing_account["environment"] = "LIVE"
    else:
        # Generate new random 6-digit path name that doesn't conflict
        while True:
            account_path_name = str(random.randint(100000, 999999))
            if not (data_path / account_path_name).exists():
                break
        accounts_data.setdefault("accounts", []).append({
            "path": account_path_name,
            "environment": "LIVE",
            "number": number,
            "uuid": aci
        })
        
    # Save accounts.json (atomic, owner-only)
    atomic_write_secure(accounts_json_path, json.dumps(accounts_data, indent=2))

    # 2. Encrypt device name if device_name is given
    encrypted_dev_name = None
    if device_name:
        try:
            encrypted_dev_name = encrypt_device_name(device_name, aci_identity_priv)
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning("could not encrypt device name: %s", e)
            
    # Base64 utility
    def to_b64(b):
        if not b:
            return None
        if isinstance(b, str):
            return b
        return base64.b64encode(b).decode("utf-8")
        
    # Ensure public keys have 0x05 prefix if they are 32 bytes
    def ensure_prefixed(pub):
        if len(pub) == 32:
            return b"\x05" + pub
        return pub
        
    aci_pub_prefixed = ensure_prefixed(aci_identity_pub)
    pni_pub_prefixed = ensure_prefixed(pni_identity_pub)
    
    # Registration IDs MUST match what we advertised to the server at link time
    # (they live in ``responder_keys``); a fresh random id here would disagree
    # with the server's record. Fall back to random only for legacy callers.
    responder_keys = responder_keys or {}
    registration_id = responder_keys.get("registration_id") or random.randint(1, 16380)
    pni_registration_id = responder_keys.get("pni_registration_id") or random.randint(1, 16380)

    def _prekey_entry(spec):
        """Persist {keyId, priv, publicKey, signature} verbatim (already b64)."""
        return dict(spec) if spec else None

    aci_signed_prekey = _prekey_entry(responder_keys.get("aci_signed_prekey"))
    pni_signed_prekey = _prekey_entry(responder_keys.get("pni_signed_prekey"))
    aci_kyber_prekey = _prekey_entry(responder_keys.get("aci_kyber_prekey"))
    pni_kyber_prekey = _prekey_entry(responder_keys.get("pni_kyber_prekey"))
    # One-time prekeys stored as {str(keyId): priv_b64} for lookup by preKeyId.
    aci_one_time_prekeys = {
        str(otk["keyId"]): otk["priv"]
        for otk in responder_keys.get("one_time_prekeys", [])
    }

    import time
    timestamp_ms = int(time.time() * 1000)
    
    # 3. Construct the account configuration JSON
    account_config = {
        "version": 10,
        "timestamp": timestamp_ms,
        "serviceEnvironment": "LIVE",
        "registered": True,
        "number": number,
        "username": None,
        "encryptedDeviceName": encrypted_dev_name,
        "deviceId": device_id,
        "isMultiDevice": True,
        "password": password,
        "aciAccountData": {
            "serviceId": aci,
            "registrationId": registration_id,
            "identityPrivateKey": to_b64(aci_identity_priv),
            "identityPublicKey": to_b64(aci_pub_prefixed),
            "nextPreKeyId": random.randint(1, 15000000),
            "nextSignedPreKeyId": 2,
            "activeSignedPreKeyId": 1,
            "nextKyberPreKeyId": 2,
            "activeLastResortKyberPreKeyId": 1,
            "signedPreKey": aci_signed_prekey,
            "kyberPreKey": aci_kyber_prekey,
            "oneTimePreKeys": aci_one_time_prekeys,
        },
        "pniAccountData": {
            "serviceId": f"PNI:{pni}" if pni and not pni.startswith("PNI:") else pni,
            "registrationId": pni_registration_id,
            "identityPrivateKey": to_b64(pni_identity_priv),
            "identityPublicKey": to_b64(pni_pub_prefixed),
            "nextPreKeyId": random.randint(1, 15000000),
            "nextSignedPreKeyId": 2,
            "activeSignedPreKeyId": 1,
            "nextKyberPreKeyId": 2,
            "activeLastResortKyberPreKeyId": 1,
            "signedPreKey": pni_signed_prekey,
            "kyberPreKey": pni_kyber_prekey,
        },
        "registrationLockPin": None,
        "pinMasterKey": None,
        "storageKey": None,
        "accountEntropyPool": to_b64(account_entropy_pool),
        "mediaRootBackupKey": to_b64(media_root_backup_key),
        "profileKey": to_b64(profile_key),
        "usernameLinkEntropy": None,
        "usernameLinkServerId": None
    }
    
    # Save account config file (atomic, owner-only)
    account_file_path = data_path / account_path_name
    atomic_write_secure(account_file_path, json.dumps(account_config, indent=2))

    return account_file_path


class SecondaryProvisioningCipher:
    """Decrypts provisioning messages sent by the primary device during linking."""
    def __init__(self, private_bytes):
        self.our_private = X25519PrivateKey.from_private_bytes(private_bytes)

    def decrypt(self, primary_ephemeral_pub_prefixed, body):
        """Decrypt the provision envelope body.

        Args:
            primary_ephemeral_pub_prefixed (bytes): 33-byte prefixed public key (starts with 0x05).
            body (bytes): The encrypted envelope payload.
        """
        # 1. Parse primary public key
        if not primary_ephemeral_pub_prefixed.startswith(b"\x05"):
            raise ValueError("Expected 0x05 prefix on primary public key")
        primary_pub_bytes = primary_ephemeral_pub_prefixed[1:]
        primary_pub = X25519PublicKey.from_public_bytes(primary_pub_bytes)

        # 2. Check length of body
        # body is: version (1) + iv (16) + ciphertext + mac (32)
        if len(body) <= 1 + 16 + 32:
            raise ValueError("Invalid envelope body length")

        version = body[0]
        if version != 1:
            raise ValueError(f"Expected version 1, got {version}")

        iv = body[1:17]
        ciphertext = body[17:-32]
        expected_mac = body[-32:]
        mac_data = body[:-32]

        # 3. Perform ECDH Key Agreement
        shared_secret = self.our_private.exchange(primary_pub)

        # 4. HKDF derivation
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b"TextSecure Provisioning Message"
        )
        derived_secret = hkdf.derive(shared_secret)
        cipher_key = derived_secret[:32]
        mac_key = derived_secret[32:64]

        # 5. Verify HMAC-SHA256
        computed_mac = hmac.new(mac_key, mac_data, hashlib.sha256).digest()
        if not hmac.compare_digest(computed_mac, expected_mac):
            raise ValueError("HMAC verification failed")

        # 6. Decrypt ciphertext (AES-256-CBC)
        decryptor = Cipher(algorithms.AES(cipher_key), modes.CBC(iv)).decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad PKCS7
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext


async def link_device_async(device_name, output_fn=print, base_url=DEFAULT_BASE_URL, ws_url=DEFAULT_WS_URL, data_dir=None):
    """Link device asynchronously over WebSockets, displaying the QR code and decrypting keys.

    Returns:
        dict: The decrypted and registered device credentials.
    """
    # 1. Ephemeral keypair for secondary device. The device-link URI carries the
    #    0x05-prefixed public key, standard base64 WITH padding, URL-encoded.
    import urllib.parse
    priv_bytes, pub_bytes = generate_x25519_keypair()
    pub_prefixed = serialize_signal_public_key(pub_bytes)
    pub_b64 = base64.b64encode(pub_prefixed).decode("utf-8")

    url = f"{ws_url}/v1/websocket/provisioning/"
    headers = {
        "User-Agent": DEFAULT_USER_AGENT,
        "X-Signal-Agent": DEFAULT_USER_AGENT,
    }

    output_fn("Connecting to Signal provisioning server...")
    async with _ws_connect(url, headers) as ws:
        # First message: ProvisioningUuid (contains the session ID / address)
        body = await _recv_provisioning_body(ws)
        fields = decode_proto(body)
        if 1 not in fields:
            raise ValueError("Provisioning address missing from server response")
        address = fields[1][0].decode("utf-8")

        # Renders the URI. Modern Signal apps expect the sgnl://linkdevice scheme
        # (the legacy tsdevice:/ scheme is rejected as "not valid"); both params
        # are URL-encoded.
        uuid_enc = urllib.parse.quote(address, safe="")
        pub_enc = urllib.parse.quote(pub_b64, safe="")
        uri = f"sgnl://linkdevice?uuid={uuid_enc}&pub_key={pub_enc}"
        output_fn(f"\nDevice-link URI:\n  {uri}\n")

        # Renders QR code in terminal
        import qrcode
        qr = qrcode.QRCode(border=1, error_correction=qrcode.constants.ERROR_CORRECT_L)
        qr.add_data(uri)
        qr.make(fit=True)
        
        # print_ascii writes to a file-like object (needs .write), not a function.
        import io
        buf = io.StringIO()
        qr.print_ascii(invert=True, out=buf)
        output_fn(buf.getvalue())
        output_fn("\nScan this from your phone under 'Settings -> Linked Devices'...")

        # Wait for the second message (ProvisionEnvelope) containing keys
        envelope_body = await _recv_provisioning_body(ws)
        envelope_fields = decode_proto(envelope_body)
        if 1 not in envelope_fields or 2 not in envelope_fields:
            raise ValueError("Invalid provision envelope from server")

        primary_ephemeral_pub = envelope_fields[1][0]
        encrypted_body = envelope_fields[2][0]

        # Decrypt payload
        cipher = SecondaryProvisioningCipher(priv_bytes)
        plaintext = cipher.decrypt(primary_ephemeral_pub, encrypted_body)

        # Decode plaintext as ProvisionMessage protobuf
        msg_fields = decode_proto(plaintext)

        number = msg_fields.get(3, [b""])[0].decode("utf-8")
        provisioning_code = msg_fields.get(4, [b""])[0].decode("utf-8")

        # Modern ProvisionMessage carries the service ids as raw 16-byte UUIDs in
        # aciBinary (field 17) / pniBinary (field 18); the legacy string fields
        # aci (8) / pni (10) are now empty. Prefer the binary form.
        import uuid as _uuid

        def _service_id(str_field, bin_field):
            if bin_field in msg_fields and len(msg_fields[bin_field][0]) == 16:
                return str(_uuid.UUID(bytes=msg_fields[bin_field][0]))
            s = msg_fields.get(str_field, [b""])[0]
            return s.decode("utf-8") if s else ""

        aci = _service_id(8, 17)
        pni = _service_id(10, 18)

        output_fn(f"\n✓ Linked successfully for: {number}")

        # Generate local password (18 bytes random base64)
        raw_pw = os.urandom(18)
        password = base64.b64encode(raw_pw).decode("utf-8")

        aci_identity_key_pub = msg_fields.get(1, [b""])[0]
        aci_identity_key_priv = msg_fields.get(2, [b""])[0]
        pni_identity_key_pub = msg_fields.get(11, [b""])[0]
        pni_identity_key_priv = msg_fields.get(12, [b""])[0]

        payload, responder_keys = generate_linking_payload(
            verification_code=provisioning_code,
            secondary_priv=aci_identity_key_priv,
            secondary_pub=aci_identity_key_pub,
            device_name=device_name or "signal-notify",
            pni_priv=pni_identity_key_priv,
        )

        output_fn("Registering device on Signal servers...")
        res = register_secondary_device(
            payload=payload,
            aci=number,  # Authorize using basic auth with number:password
            password=password,
            base_url=base_url
        )
        device_id = res.get("deviceId", 2)
        output_fn(f"✓ Registered device with ID: {device_id}")

        # Best-effort: upload the one-time prekey public halves so the phone can
        # consume them (X3DH DH4). Non-fatal — the last-resort signed prekey we
        # already published lets the phone open a session even if this fails.
        try:
            from .registration import upload_one_time_prekeys
            n_up = upload_one_time_prekeys(
                aci=aci, device_id=device_id, password=password,
                one_time_prekeys=responder_keys.get("one_time_prekeys", []),
                base_url=base_url,
            )
            output_fn(f"✓ Uploaded {n_up} one-time prekeys")
        except Exception as e:
            output_fn(f"Warning: one-time prekey upload skipped: {e}")

        if data_dir is None:
            from ..config import get_data_dir
            data_dir = get_data_dir()
        output_fn(f"Saving configuration to {data_dir}...")
        config_file = save_account_config(
            data_dir=data_dir,
            number=number,
            aci=aci,
            pni=pni,
            password=password,
            aci_identity_pub=aci_identity_key_pub,
            aci_identity_priv=aci_identity_key_priv,
            pni_identity_pub=pni_identity_key_pub,
            pni_identity_priv=pni_identity_key_priv,
            profile_key=msg_fields.get(6, [b""])[0],
            account_entropy_pool=msg_fields.get(15, [b""])[0] if 15 in msg_fields else None,
            media_root_backup_key=msg_fields.get(16, [b""])[0] if 16 in msg_fields else None,
            device_id=device_id,
            device_name=device_name,
            responder_keys=responder_keys,
        )
        output_fn(f"✓ Saved configuration file: {config_file}")
        
        return {
            "number": number,
            "provisioning_code": provisioning_code,
            "aci": aci,
            "pni": pni,
            "aci_identity_key_pub": aci_identity_key_pub,
            "aci_identity_key_priv": aci_identity_key_priv,
            "pni_identity_key_pub": pni_identity_key_pub,
            "pni_identity_key_priv": pni_identity_key_priv,
            "profile_key": msg_fields.get(6, [b""])[0],
            "account_entropy_pool": msg_fields.get(15, [b""])[0].decode("utf-8") if 15 in msg_fields else None,
            "media_root_backup_key": msg_fields.get(16, [b""])[0] if 16 in msg_fields else None,
            "password": password,
            "deviceId": device_id,
            "config_file": str(config_file)
        }


def link_device_sync(device_name, output_fn=print, base_url=DEFAULT_BASE_URL, ws_url=DEFAULT_WS_URL, data_dir=None):
    """Sync wrapper to execute the async device linking flow."""
    return asyncio.run(link_device_async(device_name, output_fn, base_url, ws_url, data_dir=data_dir))

