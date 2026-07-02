"""Signal attachments: encrypt/upload (send) and download/decrypt (receive).

Everything here mirrors Signal-Android's libsignal-service (read 2026-07;
see docs/native_caveats.md meta-lesson — source first, no guessing):

* **Cipher** (``AttachmentCipherOutputStream`` / ``AttachmentCipherInputStream``):
  the key material is 64 bytes = AES-256 key (32) ‖ HMAC-SHA256 key (32). The
  encrypted blob is ``iv(16) ‖ AES-CBC/PKCS7 ciphertext ‖ HMAC-SHA256(iv ‖ ct)``
  and the pointer ``digest`` is SHA-256 over the ENTIRE blob (iv+ct+mac).
* **Plaintext padding** (``PaddingInputStream.getPaddedSize``): the plaintext
  is zero-padded to ``max(541, floor(1.05 ** ceil(log_1.05(size))))`` before
  encryption; the receiver truncates back to ``AttachmentPointer.size``.
* **Upload**: ``GET /v4/attachments/form/upload?uploadLength=N`` (Basic auth,
  chat host) returns ``{cdn, key, headers, signedUploadLocation}``. For cdn 3
  the upload is TUS "creation-with-upload": one POST to
  ``signedUploadLocation`` with the form headers plus ``Tus-Resumable: 1.0.0``,
  ``Upload-Length`` and ``Content-Type: application/offset+octet-stream``, the
  encrypted blob as body (``PushServiceSocket.createAndUploadToCdn3``). cdn 2
  is the legacy resumable flow: an empty POST yields a ``Location`` to PUT the
  blob to.
* **Download**: ``GET {cdn_base}/attachments/{cdnKey-or-cdnId}``
  (``ATTACHMENT_KEY_DOWNLOAD_PATH``), cdn_base per ``cdnNumber``.

Live status: PROVEN both directions on 2026-07-01 — an agent-sent PNG
rendered in the phone's Note-to-Self, and a real phone-sent JPEG (358 KB sync
transcript) was parsed, downloaded from cdn3, digest/MAC-verified and
decrypted by this module.
"""
from __future__ import annotations

import hashlib
import hmac as hmac_mod
import logging
import math
import mimetypes
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import proto as P
from .messaging import (encode_bytes_field, encode_string_field,
                        encode_varint_field)
from .registration import (DEFAULT_BASE_URL, DEFAULT_USER_AGENT, SignalAPIError,
                           decode_proto, make_request, signal_ssl_context)

log = logging.getLogger(__name__)

# PushServiceSocket / SignalServiceNetworkAccess CDN hosts by cdnNumber.
CDN_BASE_URLS = {
    0: "https://cdn.signal.org",
    2: "https://cdn2.signal.org",
    3: "https://cdn3.signal.org",
}

KEY_MATERIAL_LEN = 64          # 32 AES + 32 HMAC
IV_LEN = 16
MAC_LEN = 32


# ---- cipher ------------------------------------------------------------------
def padded_plaintext_length(size: int) -> int:
    """``PaddingInputStream.getPaddedSize``: bucket sizes hide exact lengths."""
    if size <= 0:
        return 541
    return max(541, math.floor(1.05 ** math.ceil(math.log(size, 1.05))))


def encrypt_attachment(plaintext: bytes, key_material: bytes | None = None,
                       iv: bytes | None = None) -> tuple[bytes, bytes, bytes]:
    """Encrypt per ``AttachmentCipherOutputStream``.

    Returns ``(blob, key_material_64, digest)`` where ``blob`` is
    ``iv ‖ ciphertext ‖ mac`` (what gets uploaded), ``key_material`` goes into
    ``AttachmentPointer.key`` and ``digest`` (SHA-256 of the whole blob) into
    ``AttachmentPointer.digest``.
    """
    from cryptography.hazmat.primitives import padding as _pad
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    if key_material is None:
        key_material = os.urandom(KEY_MATERIAL_LEN)
    if iv is None:
        iv = os.urandom(IV_LEN)
    aes_key, mac_key = key_material[:32], key_material[32:]

    padded = plaintext + b"\x00" * (padded_plaintext_length(len(plaintext))
                                    - len(plaintext))
    padder = _pad.PKCS7(128).padder()
    data = padder.update(padded) + padder.finalize()
    enc = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    ciphertext = enc.update(data) + enc.finalize()

    mac = hmac_mod.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    blob = iv + ciphertext + mac
    return blob, key_material, hashlib.sha256(blob).digest()


def decrypt_attachment(blob: bytes, key_material: bytes,
                       digest: bytes | None = None,
                       plaintext_length: int | None = None) -> bytes:
    """Verify and decrypt per ``AttachmentCipherInputStream``.

    Order matters: digest (whole blob) and MAC (iv‖ct) are checked BEFORE any
    decryption. ``plaintext_length`` (``AttachmentPointer.size``) truncates the
    bucket zero-padding; without it trailing zeros may remain.
    """
    from cryptography.hazmat.primitives import padding as _pad
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    if len(key_material) != KEY_MATERIAL_LEN:
        raise ValueError(f"attachment key must be {KEY_MATERIAL_LEN} bytes")
    if len(blob) < IV_LEN + 16 + MAC_LEN:
        raise ValueError("attachment blob too short")
    if digest is not None and not hmac_mod.compare_digest(
            hashlib.sha256(blob).digest(), digest):
        raise ValueError("attachment digest mismatch")

    aes_key, mac_key = key_material[:32], key_material[32:]
    iv, ciphertext, their_mac = (blob[:IV_LEN], blob[IV_LEN:-MAC_LEN],
                                 blob[-MAC_LEN:])
    ours = hmac_mod.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac_mod.compare_digest(ours, their_mac):
        raise ValueError("attachment MAC mismatch")

    dec = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = _pad.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    if plaintext_length is not None:
        plaintext = plaintext[:plaintext_length]
    return plaintext


# ---- AttachmentPointer wire format ---------------------------------------------
def encode_attachment_pointer(p: dict) -> bytes:
    """Serialize a pointer dict (as returned by :func:`upload_attachment`)."""
    data = b""
    data += encode_string_field(P.AP_CONTENT_TYPE, p["contentType"])
    data += encode_bytes_field(P.AP_KEY, p["key"])
    data += encode_varint_field(P.AP_SIZE, p["size"])
    data += encode_bytes_field(P.AP_DIGEST, p["digest"])
    if p.get("fileName"):
        data += encode_string_field(P.AP_FILE_NAME, p["fileName"])
    if p.get("uploadTimestamp"):
        data += encode_varint_field(P.AP_UPLOAD_TIMESTAMP, p["uploadTimestamp"])
    data += encode_varint_field(P.AP_CDN_NUMBER, p["cdnNumber"])
    data += encode_string_field(P.AP_CDN_KEY, p["cdnKey"])
    return data


def parse_attachment_pointer(pointer_bytes: bytes) -> dict:
    """Decode an ``AttachmentPointer`` into the same dict shape we encode."""
    f = decode_proto(pointer_bytes)

    def _str(field):
        v = f.get(field, [b""])[0]
        return v.decode("utf-8", "replace") if isinstance(v, bytes) and v else None

    return {
        "cdnId": f.get(P.AP_CDN_ID, [None])[0],
        "cdnKey": _str(P.AP_CDN_KEY),
        "cdnNumber": f.get(P.AP_CDN_NUMBER, [0])[0],
        "contentType": _str(P.AP_CONTENT_TYPE) or "application/octet-stream",
        "key": f.get(P.AP_KEY, [b""])[0],
        "size": f.get(P.AP_SIZE, [None])[0],
        "digest": f.get(P.AP_DIGEST, [b""])[0] or None,
        "fileName": _str(P.AP_FILE_NAME),
        "uploadTimestamp": f.get(P.AP_UPLOAD_TIMESTAMP, [None])[0],
    }


# ---- HTTP to the CDN -----------------------------------------------------------
def _http(url: str, method: str = "GET", body: bytes | None = None,
          headers: dict | None = None, timeout: int = 120):
    """Raw-bytes HTTP for CDN hosts. Returns ``(body_bytes, headers_dict)``.

    Tries Signal's pinned CA first (the CDNs sit behind Signal-configured
    fronts), then falls back to the system trust store — the CDN hosts serve
    publicly-chained certificates in some regions.
    """
    import ssl

    req_headers = {"User-Agent": DEFAULT_USER_AGENT}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=body, headers=req_headers,
                                 method=method)
    for context in (signal_ssl_context(), ssl.create_default_context()):
        try:
            with urllib.request.urlopen(req, context=context,
                                        timeout=timeout) as res:
                return res.read(), dict(res.info())
        except urllib.error.HTTPError as e:
            raise SignalAPIError(e.code, f"CDN {method} {url} failed",
                                 e.read().decode("utf-8", "replace"),
                                 dict(e.info()))
        except ssl.SSLError:
            continue
    raise SignalAPIError(0, f"TLS verification failed for {url}")


# ---- upload / download ----------------------------------------------------------
def upload_attachment(source, *, auth_headers: dict,
                      base_url: str = DEFAULT_BASE_URL,
                      content_type: str | None = None,
                      file_name: str | None = None) -> dict:
    """Encrypt ``source`` (path or bytes) and upload it; return the pointer dict.

    The returned dict feeds :func:`encode_attachment_pointer` /
    ``DataMessage.attachments``.
    """
    if isinstance(source, (str, Path)):
        path = Path(source)
        plaintext = path.read_bytes()
        file_name = file_name or path.name
        content_type = (content_type
                        or mimetypes.guess_type(str(path))[0]
                        or "application/octet-stream")
    else:
        plaintext = bytes(source)
        content_type = content_type or "application/octet-stream"

    blob, key_material, digest = encrypt_attachment(plaintext)

    form, _ = make_request(
        f"/v4/attachments/form/upload?uploadLength={len(blob)}",
        method="GET", headers=auth_headers, base_url=base_url)
    cdn = form["cdn"]
    upload_headers = {k: v for k, v in (form.get("headers") or {}).items()
                      if k.lower() != "host"}

    if cdn == 3:
        # TUS creation-with-upload: one POST carries the whole blob.
        upload_headers.update({"Tus-Resumable": "1.0.0",
                               "Upload-Length": str(len(blob)),
                               "Content-Type": "application/offset+octet-stream"})
        _http(form["signedUploadLocation"], method="POST", body=blob,
              headers=upload_headers)
    elif cdn == 2:
        # Legacy resumable: empty POST yields the upload URL in Location.
        create_headers = dict(upload_headers)
        create_headers.update({"Content-Type": "application/octet-stream",
                               "Content-Length": "0"})
        _, res_headers = _http(form["signedUploadLocation"], method="POST",
                               body=b"", headers=create_headers)
        location = res_headers.get("Location") or res_headers.get("location")
        if not location:
            raise SignalAPIError(0, "cdn2 upload: no resumable Location returned")
        _http(location, method="PUT", body=blob,
              headers={"Content-Type": "application/octet-stream"})
    else:
        raise SignalAPIError(0, f"unsupported attachment CDN {cdn}")

    log.info("uploaded attachment (%d bytes plaintext) to cdn%d", len(plaintext), cdn)
    return {
        "cdnKey": form["key"],
        "cdnNumber": cdn,
        "contentType": content_type,
        "key": key_material,
        "size": len(plaintext),
        "digest": digest,
        "fileName": file_name,
        "uploadTimestamp": int(time.time() * 1000),
    }


def download_attachment(pointer: dict, dest_dir, *,
                        cdn_base_urls: dict | None = None) -> Path:
    """Download, verify and decrypt one received pointer; return the saved path."""
    bases = cdn_base_urls or CDN_BASE_URLS
    base = bases.get(pointer.get("cdnNumber", 0))
    if base is None:
        raise SignalAPIError(0, f"unknown attachment CDN {pointer.get('cdnNumber')}")
    remote_id = pointer.get("cdnKey") or pointer.get("cdnId")
    if not remote_id:
        raise ValueError("attachment pointer has no cdnKey/cdnId")

    import urllib.parse
    blob, _ = _http(f"{base}/attachments/{urllib.parse.quote(str(remote_id))}")
    plaintext = decrypt_attachment(blob, pointer["key"],
                                   digest=pointer.get("digest"),
                                   plaintext_length=pointer.get("size"))

    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    # Both fileName AND cdnKey come from the wire: basename + strip leading
    # dots so neither can traverse out of dest_dir (or hide as a dotfile).
    safe_remote_id = os.path.basename(str(remote_id)).lstrip(".") or "unknown"
    name = os.path.basename(pointer.get("fileName") or "").lstrip(".")
    if not name:
        name = f"attachment-{safe_remote_id}"
    dest = dest_dir / name
    n = 1
    while dest.exists():
        dest = dest_dir / f"{Path(name).stem}-{n}{Path(name).suffix}"
        n += 1
    # Belt-and-braces containment check after resolving symlinks.
    if dest_dir.resolve() not in dest.resolve().parents:
        raise ValueError("attachment path escapes destination directory")
    dest.write_bytes(plaintext)
    try:
        os.chmod(dest, 0o600)
    except OSError:
        pass
    return dest
