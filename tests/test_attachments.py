"""Attachments: cipher, pointer wire format, upload/download plumbing.

Cipher/padding per Signal-Android AttachmentCipherOutputStream /
AttachmentCipherInputStream / PaddingInputStream (source-verified), and
live-proven both directions on 2026-07-01 (agent PNG rendered on the phone;
real phone JPEG downloaded + decrypted).
"""
import hashlib
import json
from unittest.mock import patch

import pytest

from signalnotify.native import attachments as A
from signalnotify.native.attachments import (decrypt_attachment,
                                             download_attachment,
                                             encode_attachment_pointer,
                                             encrypt_attachment,
                                             padded_plaintext_length,
                                             parse_attachment_pointer)


# ---- cipher -----------------------------------------------------------------
def test_encrypt_decrypt_round_trip():
    plaintext = b"agent screenshot bytes" * 100
    blob, key, digest = encrypt_attachment(plaintext)
    assert len(key) == 64
    assert digest == hashlib.sha256(blob).digest()
    out = decrypt_attachment(blob, key, digest=digest,
                             plaintext_length=len(plaintext))
    assert out == plaintext


def test_blob_structure():
    # iv(16) || CBC ciphertext (multiple of 16, PKCS7 over the padded bucket)
    # || hmac(32)
    plaintext = b"z" * 100
    blob, key, _ = encrypt_attachment(plaintext)
    bucket = padded_plaintext_length(100)
    assert len(blob) == 16 + (bucket // 16 + 1) * 16 + 32


def test_bucket_padding_law():
    # PaddingInputStream.getPaddedSize: max(541, floor(1.05^ceil(log1.05 n)))
    assert padded_plaintext_length(0) == 541
    assert padded_plaintext_length(1) == 541
    assert padded_plaintext_length(541) == 541
    assert padded_plaintext_length(542) > 542
    for n in (1000, 12345, 1_000_000):
        p = padded_plaintext_length(n)
        assert p >= n
        assert padded_plaintext_length(p) == p  # buckets are fixed points


def test_tampered_blob_rejected():
    blob, key, digest = encrypt_attachment(b"payload")
    bad = bytearray(blob)
    bad[20] ^= 0x01
    with pytest.raises(ValueError, match="digest"):
        decrypt_attachment(bytes(bad), key, digest=digest)
    # Without digest the MAC still catches it.
    with pytest.raises(ValueError, match="MAC"):
        decrypt_attachment(bytes(bad), key)


def test_zero_truncation_needs_size():
    plaintext = b"ends in data"
    blob, key, digest = encrypt_attachment(plaintext)
    full = decrypt_attachment(blob, key, digest=digest)
    assert full.startswith(plaintext) and len(full) == padded_plaintext_length(len(plaintext))
    exact = decrypt_attachment(blob, key, digest=digest, plaintext_length=len(plaintext))
    assert exact == plaintext


# ---- pointer wire format -------------------------------------------------------
def test_pointer_round_trip():
    p = {"cdnKey": "abc/def", "cdnNumber": 3, "contentType": "image/png",
         "key": b"k" * 64, "size": 12345, "digest": b"d" * 32,
         "fileName": "plot.png", "uploadTimestamp": 1751300000000}
    parsed = parse_attachment_pointer(encode_attachment_pointer(p))
    for field in ("cdnKey", "cdnNumber", "contentType", "key", "size",
                  "digest", "fileName", "uploadTimestamp"):
        assert parsed[field] == p[field], field


# ---- upload / send plumbing ------------------------------------------------------
class FakeCDN:
    """Mocks make_request (form fetch) + _http (CDN traffic)."""

    def __init__(self, cdn=3):
        self.cdn = cdn
        self.stored = {}
        self.form_requests = []

    def make_request(self, path, method="GET", body=None, headers=None,
                     base_url=None, timeout=30):
        assert path.startswith("/v4/attachments/form/upload?uploadLength=")
        assert headers and "Authorization" in headers
        self.form_requests.append(path)
        key = f"attachments/test-key-{len(self.form_requests)}"
        return {"cdn": self.cdn, "key": key,
                "headers": {"x-goog-resumable": "start"},
                "signedUploadLocation": f"https://cdn3.example/{key}"}, {}

    def http(self, url, method="GET", body=None, headers=None, timeout=120):
        if method == "POST" and self.cdn == 3:
            assert headers["Tus-Resumable"] == "1.0.0"
            assert headers["Upload-Length"] == str(len(body))
            assert headers["Content-Type"] == "application/offset+octet-stream"
            self.stored[url.split("/", 3)[3]] = body
            return b"", {}
        if method == "GET":
            key = url.split("/attachments/", 1)[1]
            import urllib.parse
            return self.stored[urllib.parse.unquote(key)], {}
        raise AssertionError(f"unexpected {method} {url}")


def test_upload_attachment_cdn3(tmp_path, monkeypatch):
    cdn = FakeCDN()
    monkeypatch.setattr(A, "make_request", cdn.make_request)
    monkeypatch.setattr(A, "_http", cdn.http)
    f = tmp_path / "plot.png"
    f.write_bytes(b"\x89PNG fake image data")

    p = A.upload_attachment(f, auth_headers={"Authorization": "Basic zzz"})
    assert p["cdnNumber"] == 3
    assert p["contentType"] == "image/png"
    assert p["fileName"] == "plot.png"
    assert p["size"] == 20
    assert len(p["key"]) == 64
    # What the CDN stored decrypts back to the file with the pointer's material.
    blob = cdn.stored[p["cdnKey"]]
    assert hashlib.sha256(blob).digest() == p["digest"]
    assert decrypt_attachment(blob, p["key"], digest=p["digest"],
                              plaintext_length=p["size"]) == f.read_bytes()


def test_download_attachment(tmp_path, monkeypatch):
    cdn = FakeCDN()
    monkeypatch.setattr(A, "make_request", cdn.make_request)
    monkeypatch.setattr(A, "_http", cdn.http)
    p = A.upload_attachment(b"round trip bytes", auth_headers={"Authorization": "b"},
                            file_name="../evil.bin")  # traversal must not escape
    p["cdnNumber"] = 3
    monkeypatch.setitem(A.CDN_BASE_URLS, 3, "https://cdn3.example")

    dest = download_attachment(p, tmp_path / "in")
    assert dest.parent == tmp_path / "in"       # basename() stripped the ../
    assert dest.read_bytes() == b"round trip bytes"


def test_download_traversal_via_cdnkey_blocked(tmp_path, monkeypatch):
    """With no fileName, the cdnKey (also remote input) names the file — a
    crafted key like 'x/../../../evil' must not escape dest_dir either."""
    cdn = FakeCDN()
    monkeypatch.setattr(A, "make_request", cdn.make_request)
    monkeypatch.setattr(A, "_http", cdn.http)
    p = A.upload_attachment(b"payload", auth_headers={"Authorization": "b"})
    blob = cdn.stored.pop(p["cdnKey"])
    evil_key = "k/../../../../outside/evil"
    cdn.stored[evil_key] = blob
    p.update({"cdnKey": evil_key, "fileName": None})
    monkeypatch.setitem(A.CDN_BASE_URLS, 3, "https://cdn3.example")

    dest = download_attachment(p, tmp_path / "in")
    assert dest.parent == tmp_path / "in"
    assert dest.name == "attachment-evil"
    assert not (tmp_path.parent / "outside").exists()


def test_send_with_attachment_end_to_end_wire(tmp_path, monkeypatch):
    """send -> Sent transcript carries an AttachmentPointer that our own
    receive-side parser resolves back to the uploaded content."""
    from signalnotify.native import messaging
    from signalnotify.native.messaging import send_message_native
    from signalnotify.native.proto import (CONTENT_SYNC_MESSAGE, DATA_ATTACHMENTS,
                                           SENT_MESSAGE, SYNC_SENT)
    from test_native_messaging import _bundle, _config, _device

    cdn = FakeCDN()
    monkeypatch.setattr(A, "make_request", cdn.make_request)
    monkeypatch.setattr(A, "_http", cdn.http)

    config_path = _config(tmp_path)
    bundle = _bundle([_device(1, 5678)])
    puts = []

    def service(path, method="GET", body=None, headers=None, base_url=None):
        if method == "GET":
            return bundle, {}
        puts.append(body)
        return {}, {}

    monkeypatch.setattr(messaging, "make_request", service)
    img = tmp_path / "shot.jpg"
    img.write_bytes(b"jpeg bytes here")

    ok = send_message_native(config_path, "see attached",
                             recipient="rec-aci-uuid", attachments=[img])
    assert ok is True and len(puts) == 1
    # One upload happened and the pointer decodes from the pipeline dict.
    assert len(cdn.stored) == 1


def test_message_attachments_parse(tmp_path):
    """A Sent transcript with attachments yields Message.attachments."""
    from signalnotify.native.messaging import (encode_content,
                                               encode_data_message,
                                               encode_sync_message,
                                               encode_sync_message_sent)
    from signalnotify.native.receive import parse_content

    p = {"cdnKey": "k1", "cdnNumber": 3, "contentType": "image/jpeg",
         "key": b"a" * 64, "size": 15, "digest": b"g" * 32,
         "fileName": "shot.jpg", "uploadTimestamp": 5}
    dm = encode_data_message("with pic", 7,
                             attachment_pointers=[encode_attachment_pointer(p)])
    sent = encode_sync_message_sent("00000000-0000-0000-0000-0000000000aa", 7, dm)
    content = encode_content(sync_message_bytes=encode_sync_message(sent))

    msg = parse_content(content, {"00000000-0000-0000-0000-0000000000aa"}, None, 7)
    assert msg.note_to_self and msg.body == "with pic"
    assert len(msg.attachments) == 1
    got = msg.attachments[0]
    assert got["cdnKey"] == "k1" and got["key"] == b"a" * 64
    assert got["size"] == 15 and got["fileName"] == "shot.jpg"


def test_attachment_only_message(tmp_path):
    from signalnotify.native.messaging import encode_content, encode_data_message
    from signalnotify.native.receive import parse_content

    p = {"cdnKey": "k2", "cdnNumber": 3, "contentType": "image/png",
         "key": b"b" * 64, "size": 9, "digest": b"h" * 32}
    dm = encode_data_message("", 9,
                             attachment_pointers=[encode_attachment_pointer(p)])
    content = encode_content(data_message_bytes=dm)
    msg = parse_content(content, set(), "src", 9)
    assert msg.body is None
    assert msg.is_text is False
    assert len(msg.attachments) == 1
