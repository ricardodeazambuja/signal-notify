import json
import urllib.error
import urllib.request
from io import BytesIO
from unittest.mock import MagicMock, patch
import pytest

from signalnotify.native import (
    create_verification_session,
    get_verification_session_status,
    submit_captcha,
    request_verification_code,
    submit_verification_code,
    SignalAPIError,
    ProofRequiredError,
)


def create_mock_response(status, body_dict, headers=None):
    mock = MagicMock()
    mock.getcode.return_value = status
    mock.read.return_value = json.dumps(body_dict).encode("utf-8")
    mock.info.return_value = headers or {}
    return mock


@patch("urllib.request.urlopen")
def test_create_verification_session_success(mock_urlopen):
    response_body = {
        "metadata": {
            "id": "test-session-id",
            "allowedToRequestCode": True,
            "verified": False,
            "requestedInformation": []
        }
    }
    mock_urlopen.return_value.__enter__.return_value = create_mock_response(200, response_body)
    
    res = create_verification_session("+15551234567")
    
    assert res["metadata"]["id"] == "test-session-id"
    assert res["metadata"]["allowedToRequestCode"] is True
    
    # Verify the call parameters
    args, kwargs = mock_urlopen.call_args
    req = args[0]
    assert req.method == "POST"
    assert req.full_url == "https://chat.signal.org/v1/verification/session"
    assert req.headers["Content-type"] == "application/json"
    
    body = json.loads(req.data.decode("utf-8"))
    assert body["number"] == "+15551234567"


@patch("urllib.request.urlopen")
def test_create_verification_session_proof_required(mock_urlopen):
    # Construct an HTTPError with code 428
    headers = {"Retry-After": "60"}
    
    response_body = {
        "token": "challenge-token-123",
        "options": ["recaptcha", "hcaptcha"]
    }
    
    # We raise HTTPError
    err = urllib.error.HTTPError(
        url="https://chat.signal.org/v1/verification/session",
        code=428,
        msg="Precondition Required",
        hdrs=headers,
        fp=BytesIO(json.dumps(response_body).encode("utf-8"))
    )
    mock_urlopen.side_effect = err
    
    with pytest.raises(ProofRequiredError) as exc_info:
        create_verification_session("+15551234567")
        
    assert exc_info.value.code == 428
    assert exc_info.value.token == "challenge-token-123"
    assert exc_info.value.options == ["recaptcha", "hcaptcha"]
    assert exc_info.value.retry_after == 60


@patch("urllib.request.urlopen")
def test_get_verification_session_status(mock_urlopen):
    response_body = {"metadata": {"id": "session-123", "verified": True}}
    mock_urlopen.return_value.__enter__.return_value = create_mock_response(200, response_body)
    
    res = get_verification_session_status("session-123")
    assert res["metadata"]["id"] == "session-123"
    assert res["metadata"]["verified"] is True
    
    args, kwargs = mock_urlopen.call_args
    req = args[0]
    assert req.method == "GET"
    assert req.full_url == "https://chat.signal.org/v1/verification/session/session-123"


@patch("urllib.request.urlopen")
def test_submit_captcha(mock_urlopen):
    response_body = {"metadata": {"id": "session-123", "allowedToRequestCode": True}}
    mock_urlopen.return_value.__enter__.return_value = create_mock_response(200, response_body)
    
    res = submit_captcha("session-123", "signalcaptcha://solved-token")
    assert res["metadata"]["allowedToRequestCode"] is True
    
    args, kwargs = mock_urlopen.call_args
    req = args[0]
    assert req.method == "PATCH"
    assert req.full_url == "https://chat.signal.org/v1/verification/session/session-123"
    
    body = json.loads(req.data.decode("utf-8"))
    assert body["captcha"] == "solved-token"


@patch("urllib.request.urlopen")
def test_request_verification_code(mock_urlopen):
    mock_urlopen.return_value.__enter__.return_value = create_mock_response(200, {"status": "ok"})
    
    res = request_verification_code("session-123", transport="voice", locale="en-US")
    
    args, kwargs = mock_urlopen.call_args
    req = args[0]
    assert req.method == "POST"
    assert req.full_url == "https://chat.signal.org/v1/verification/session/session-123/code"
    assert req.headers["Accept-language"] == "en-US"
    
    body = json.loads(req.data.decode("utf-8"))
    assert body["transport"] == "voice"
    assert body["client"] == "android"


@patch("urllib.request.urlopen")
def test_submit_verification_code(mock_urlopen):
    mock_urlopen.return_value.__enter__.return_value = create_mock_response(200, {"metadata": {"verified": True}})
    
    res = submit_verification_code("session-123", "123-456")
    assert res["metadata"]["verified"] is True
    
    args, kwargs = mock_urlopen.call_args
    req = args[0]
    assert req.method == "PUT"
    assert req.full_url == "https://chat.signal.org/v1/verification/session/session-123/code"
    
    body = json.loads(req.data.decode("utf-8"))
    assert body["code"] == "123456"


def test_crypto_xed25519_sign_and_verify():
    from signalnotify.native.crypto import generate_x25519_keypair, xed25519_sign, x25519_pub_to_ed25519_pub
    from cryptography.hazmat.primitives.asymmetric import ed25519
    
    # 1. Generate keypair
    priv_bytes, pub_bytes = generate_x25519_keypair()
    assert len(priv_bytes) == 32
    assert len(pub_bytes) == 32
    
    # 2. Convert to Ed25519 public key
    ed_pub_bytes = x25519_pub_to_ed25519_pub(pub_bytes)
    assert len(ed_pub_bytes) == 32
    
    # 3. Sign message
    message = b"Test signature message payload"
    signature = xed25519_sign(priv_bytes, message)
    assert len(signature) == 64
    
    # 4. Verify using cryptography library
    pub_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(ed_pub_bytes)
    pub_key_obj.verify(signature, message)  # should not raise exception


@patch("urllib.request.urlopen")
def test_generate_registration_payload_and_register(mock_urlopen):
    from signalnotify.native import generate_registration_payload, register_account
    
    mock_urlopen.return_value.__enter__.return_value = create_mock_response(200, {"uuid": "test-uuid", "pni": "test-pni", "storageCapable": True})
    
    # 1. Generate payload
    payload, keys = generate_registration_payload("test-session-id", voice=False)
    
    # Validate payload contents
    assert payload["sessionId"] == "test-session-id"
    assert payload["accountAttributes"]["voice"] is False
    assert "aciIdentityKey" in payload
    assert "pniIdentityKey" in payload
    assert "aciSignedPreKey" in payload
    assert payload["aciSignedPreKey"]["keyId"] == 1
    assert "signature" in payload["aciSignedPreKey"]
    assert "aciPqLastResortPreKey" in payload
    assert payload["aciPqLastResortPreKey"]["keyId"] == 1
    
    # Validate keys dictionary contains base64 encoded private keys
    assert "aci_priv" in keys
    assert "pni_priv" in keys
    assert "signaling_key" in keys
    assert "unidentified_access_key" in keys
    assert isinstance(keys["registration_id"], int)
    
    # 2. Register account via mocked URL with basic authorization
    res = register_account(payload, number="+15551234567", password="some-password")
    assert res["uuid"] == "test-uuid"
    assert res["pni"] == "test-pni"
    assert res["storageCapable"] is True
    
    args, kwargs = mock_urlopen.call_args
    req = args[0]
    assert req.method == "POST"
    assert req.full_url == "https://chat.signal.org/v1/registration"
    assert "Authorization" in req.headers
    assert req.headers["Authorization"].startswith("Basic ")


def test_encrypt_device_name():
    from signalnotify.native.crypto import generate_x25519_keypair, encrypt_device_name
    priv_bytes, pub_bytes = generate_x25519_keypair()
    
    encrypted = encrypt_device_name("My Custom laptop", priv_bytes)
    assert isinstance(encrypted, str)
    assert len(encrypted) > 0


@patch("urllib.request.urlopen")
def test_proof_required_nonint_retry_after(mock_urlopen):
    # A 428 may carry an HTTP-date Retry-After; it must not mask the
    # ProofRequiredError with a ValueError from int().
    headers = {"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}
    response_body = {"token": "tok-1", "options": ["captcha"]}
    err = urllib.error.HTTPError(
        url="https://chat.signal.org/v1/verification/session",
        code=428,
        msg="Precondition Required",
        hdrs=headers,
        fp=BytesIO(json.dumps(response_body).encode("utf-8")),
    )
    mock_urlopen.side_effect = err

    with pytest.raises(ProofRequiredError) as exc_info:
        create_verification_session("+15551234567")

    assert exc_info.value.token == "tok-1"
    assert exc_info.value.retry_after is None


def test_ws_connect_prefers_additional_headers(monkeypatch):
    import signalnotify.native.provisioning as prov

    captured = {}

    def fake_connect(url, *, additional_headers=None, **kw):  # websockets>=14
        captured["url"] = url
        captured["additional_headers"] = additional_headers
        return "NEW_CM"

    monkeypatch.setattr(prov.websockets, "connect", fake_connect)
    cm = prov._ws_connect("wss://example.invalid/ws", {"User-Agent": "UA"})
    assert cm == "NEW_CM"
    assert captured["additional_headers"] == {"User-Agent": "UA"}


def test_ws_connect_falls_back_to_extra_headers(monkeypatch):
    import signalnotify.native.provisioning as prov

    captured = {}

    def fake_connect(url, *, extra_headers=None, ssl=None):  # legacy websockets<14
        captured["extra_headers"] = extra_headers
        captured["ssl"] = ssl
        return "OLD_CM"

    monkeypatch.setattr(prov.websockets, "connect", fake_connect)
    cm = prov._ws_connect("wss://example.invalid/ws", {"User-Agent": "UA"})
    assert cm == "OLD_CM"
    assert captured["extra_headers"] == {"User-Agent": "UA"}


def test_save_account_config(tmp_path):
    from signalnotify.native.provisioning import save_account_config
    import json
    
    # Generate mock inputs
    number = "+15551234567"
    aci = "aci-uuid-123"
    pni = "pni-uuid-456"
    password = "mock-password"
    aci_pub = b"A" * 32
    aci_priv = b"B" * 32
    pni_pub = b"C" * 32
    pni_priv = b"D" * 32
    profile_key = b"P" * 32
    account_entropy_pool = b"E" * 32
    media_root_backup_key = b"M" * 32
    device_id = 2
    device_name = "test-device"
    
    config_file = save_account_config(
        data_dir=tmp_path,
        number=number,
        aci=aci,
        pni=pni,
        password=password,
        aci_identity_pub=aci_pub,
        aci_identity_priv=aci_priv,
        pni_identity_pub=pni_pub,
        pni_identity_priv=pni_priv,
        profile_key=profile_key,
        account_entropy_pool=account_entropy_pool,
        media_root_backup_key=media_root_backup_key,
        device_id=device_id,
        device_name=device_name
    )
    
    # Verify accounts.json was created/updated correctly
    accounts_json_path = tmp_path / "accounts.json"
    assert accounts_json_path.exists()
    with open(accounts_json_path) as f:
        accounts_data = json.load(f)
    
    assert accounts_data["version"] == 2
    assert len(accounts_data["accounts"]) == 1
    acc = accounts_data["accounts"][0]
    assert acc["number"] == number
    assert acc["uuid"] == aci
    assert acc["environment"] == "LIVE"
    
    # Verify account config file was created
    assert config_file.exists()
    assert config_file.name == acc["path"]
    
    with open(config_file) as f:
        config_data = json.load(f)
        
    assert config_data["version"] == 10
    assert config_data["number"] == number
    assert config_data["deviceId"] == device_id
    assert config_data["registered"] is True
    assert config_data["password"] == password
    assert config_data["aciAccountData"]["serviceId"] == aci
    assert config_data["pniAccountData"]["serviceId"] == f"PNI:{pni}"
    assert "identityPrivateKey" in config_data["aciAccountData"]
    assert "identityPublicKey" in config_data["aciAccountData"]
    assert config_data["encryptedDeviceName"] is not None



