"""Native Python implementation of the Signal registration and verification protocol.

This module communicates directly with the Signal service registration endpoints.
"""
import json
import urllib.request
import urllib.error
import ssl
from functools import lru_cache
from pathlib import Path

# Signal's production service. The historical
# ``textsecure-service.whispersystems.org`` hostname no longer resolves; the
# live endpoint is ``chat.signal.org``, whose TLS certificate is pinned to
# Signal's own private root CA (a public bundle rejects it).
DEFAULT_BASE_URL = "https://chat.signal.org"
DEFAULT_WS_URL = "wss://chat.signal.org"
# Wire-compatibility constant: the exact User-Agent the whole live-proven
# stack was validated with. It names other clients purely as an HTTP
# identification string sent to Signal's servers -- do not "clean it up"
# without re-proving live behavior.
DEFAULT_USER_AGENT = "Signal-Android/8.15.0 signal-cli/0.14.5"

# Signal Messenger self-signed root CA (extracted from the open-source Android
# client's whisper.store). Required to verify chat.signal.org.
SIGNAL_CA_PEM = Path(__file__).with_name("signal-ca.pem")


@lru_cache(maxsize=1)
def signal_ssl_context():
    """SSL context that trusts Signal's pinned root CA (and only that).

    Signal's service cert does not chain to a public CA, so the system trust
    store cannot verify it. Falls back to the default context if the bundled
    PEM is somehow missing.
    """
    try:
        return ssl.create_default_context(cafile=str(SIGNAL_CA_PEM))
    except (FileNotFoundError, ssl.SSLError):
        return ssl.create_default_context()


class SignalAPIError(Exception):
    """Base exception for errors returned by the Signal service API."""
    def __init__(self, code, message, response_body=None, headers=None):
        super().__init__(f"Signal API Error {code}: {message}")
        self.code = code
        self.message = message
        self.response_body = response_body
        self.headers = headers or {}


def read_varint(data, offset):
    """Read a varint integer from bytes at offset.

    Returns:
        tuple: (value, new_offset)
    """
    val = 0
    shift = 0
    while True:
        b = data[offset]
        offset += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return val, offset


def decode_proto(data):
    """Parse a binary protobuf message into a field-map.

    Returns:
        dict: field_num -> list of values
    """
    fields = {}
    offset = 0
    while offset < len(data):
        key, offset = read_varint(data, offset)
        field_num = key >> 3
        wire_type = key & 7
        if wire_type == 0:
            val, offset = read_varint(data, offset)
            fields.setdefault(field_num, []).append(val)
        elif wire_type == 2:
            length, offset = read_varint(data, offset)
            val = data[offset:offset+length]
            offset += length
            fields.setdefault(field_num, []).append(val)
        elif wire_type == 1:
            val = data[offset:offset+8]
            offset += 8
            fields.setdefault(field_num, []).append(val)
        elif wire_type == 5:
            val = data[offset:offset+4]
            offset += 4
            fields.setdefault(field_num, []).append(val)
        else:
            raise ValueError(f"Unsupported wire type {wire_type}")
    return fields


class ProofRequiredError(SignalAPIError):
    """Exception raised when a CAPTCHA or push challenge proof is required to proceed."""
    def __init__(self, token, options, retry_after=None, response_body=None, headers=None):
        super().__init__(428, "Proof Required (Captcha or challenge needed)", response_body, headers)
        self.token = token
        self.options = options or []
        self.retry_after = retry_after


def make_request(path, method="GET", body=None, headers=None, base_url=DEFAULT_BASE_URL, timeout=30):
    """Perform an HTTP request to the Signal server."""
    url = f"{base_url}{path}"
    req_headers = {
        "User-Agent": DEFAULT_USER_AGENT,
        "X-Signal-Agent": DEFAULT_USER_AGENT,
    }
    if headers:
        req_headers.update(headers)
    
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        req_headers["Content-Type"] = "application/json"
        
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    context = signal_ssl_context()
    
    try:
        with urllib.request.urlopen(req, context=context, timeout=timeout) as response:
            res_body = response.read().decode("utf-8", errors="replace")
            res_headers = dict(response.info())
            if res_body:
                return json.loads(res_body), res_headers
            return {}, res_headers
    except urllib.error.HTTPError as e:
        res_body = e.read().decode("utf-8", errors="replace")
        res_headers = dict(e.info())
        
        if e.code == 428:
            try:
                err_data = json.loads(res_body)
                token = err_data.get("token")
                options = err_data.get("options", [])
                retry_after_raw = res_headers.get("Retry-After")
                # Retry-After may be a delta-seconds int or an HTTP-date; only the
                # former is useful here. Never let a non-int header mask the 428.
                try:
                    retry_after = int(retry_after_raw) if retry_after_raw else None
                except (TypeError, ValueError):
                    retry_after = None
                raise ProofRequiredError(token, options, retry_after, res_body, res_headers)
            except json.JSONDecodeError:
                pass
        raise SignalAPIError(e.code, res_body or e.reason, res_body, res_headers)


def create_verification_session(number, push_token=None, mcc=None, mnc=None, base_url=DEFAULT_BASE_URL):
    """Start a new verification session for a phone number.

    POST /v1/verification/session
    """
    body = {
        "number": number,
    }
    if push_token:
        body["pushToken"] = push_token
        body["pushTokenType"] = "fcm"
    if mcc:
        body["mcc"] = mcc
    if mnc:
        body["mnc"] = mnc
        
    res, headers = make_request("/v1/verification/session", method="POST", body=body, base_url=base_url)
    return res


def get_verification_session_status(session_id, base_url=DEFAULT_BASE_URL):
    """Retrieve current status of a verification session.

    GET /v1/verification/session/{session_id}
    """
    res, headers = make_request(f"/v1/verification/session/{session_id}", method="GET", base_url=base_url)
    return res


def submit_captcha(session_id, captcha_token, push_token=None, push_challenge=None, mcc=None, mnc=None, base_url=DEFAULT_BASE_URL):
    """Submit a solved CAPTCHA token to the verification session.

    PATCH /v1/verification/session/{session-id}
    """
    if captcha_token.startswith("signalcaptcha://"):
        captcha_token = captcha_token[len("signalcaptcha://"):]
        
    body = {
        "captcha": captcha_token,
    }
    if push_token:
        body["pushToken"] = push_token
        body["pushTokenType"] = "fcm"
    if push_challenge:
        body["pushChallenge"] = push_challenge
    if mcc:
        body["mcc"] = mcc
    if mnc:
        body["mnc"] = mnc
        
    res, headers = make_request(f"/v1/verification/session/{session_id}", method="PATCH", body=body, base_url=base_url)
    return res


def request_verification_code(session_id, transport="sms", locale=None, base_url=DEFAULT_BASE_URL):
    """Request an SMS or voice verification code to be sent.

    POST /v1/verification/session/{session-id}/code
    """
    body = {
        "transport": transport.lower(),
        "client": "android"
    }
    headers = {}
    if locale:
        headers["Accept-Language"] = locale
        
    res, headers = make_request(f"/v1/verification/session/{session_id}/code", method="POST", body=body, headers=headers, base_url=base_url)
    return res


def submit_verification_code(session_id, verification_code, base_url=DEFAULT_BASE_URL):
    """Submit the verification code received via SMS/voice.

    PUT /v1/verification/session/{session-id}/code
    """
    code = verification_code.replace("-", "").strip()
    body = {
        "code": code
    }
    res, headers = make_request(f"/v1/verification/session/{session_id}/code", method="PUT", body=body, base_url=base_url)
    return res


def register_account(payload, number=None, password=None, base_url=DEFAULT_BASE_URL):
    """Submit final cryptographic key assets and registration details to finalize the account.

    POST /v1/registration
    """
    headers = {}
    if number and password:
        import base64
        auth_str = f"{number}:{password}"
        auth_b64 = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
        headers["Authorization"] = f"Basic {auth_b64}"
    res, headers = make_request("/v1/registration", method="POST", body=payload, headers=headers, base_url=base_url)
    return res



def upload_one_time_prekeys(aci, device_id, password, one_time_prekeys,
                            identity="aci", base_url=DEFAULT_BASE_URL):
    """Upload one-time (ephemeral) X25519 prekey public halves.

    ``PUT /v2/keys?identity=aci`` with a ``preKeys`` list. Auth for a linked
    device is basic ``{aci}.{deviceId}:{password}``. Returns the number of
    prekeys uploaded. Raises :class:`SignalAPIError` on failure.
    """
    import base64
    if not one_time_prekeys:
        return 0
    auth_str = f"{aci}.{device_id}:{password}"
    auth_b64 = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
    headers = {"Authorization": f"Basic {auth_b64}"}
    body = {
        "preKeys": [
            {"keyId": otk["keyId"], "publicKey": otk["publicKey"]}
            for otk in one_time_prekeys
        ],
    }
    make_request(f"/v2/keys?identity={identity}", method="PUT", body=body,
                 headers=headers, base_url=base_url)
    return len(one_time_prekeys)


def register_secondary_device(payload, aci, password, base_url=DEFAULT_BASE_URL):
    """Register device as a linked secondary device.

    PUT /v1/devices/link
    """
    import base64
    auth_str = f"{aci}:{password}"
    auth_b64 = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
    headers = {
        "Authorization": f"Basic {auth_b64}"
    }
    res, headers = make_request("/v1/devices/link", method="PUT", body=payload, headers=headers, base_url=base_url)
    return res
