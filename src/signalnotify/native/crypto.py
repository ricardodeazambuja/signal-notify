"""Cryptographic utilities for the native Signal client.

Implements Twisted Edwards curve arithmetic, point encoding/decoding,
and XEd25519 signatures (XEdDSA) in pure Python, allowing compatibility
with Signal's key registration and verification servers.
"""
import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import x25519

# Curve25519 / Ed25519 curve parameters
p = 2**255 - 19
q = 2**252 + 27742317777372353535851937790883648493


def inv(x):
    """Modular multiplicative inverse using Fermat's Little Theorem."""
    return pow(x, p - 2, p)


# Twisted Edwards curve constants
# d = -121665/121666 (mod p)
d = -121665 * inv(121666) % p
# Square root of -1 (mod p)
I = pow(2, (p - 1) // 4, p)


def recover_x(y, sign):
    """Recover x-coordinate of a point on the Ed25519 curve."""
    x2 = (y**2 - 1) * inv(d * y**2 + 1) % p
    x = pow(x2, (p + 3) // 8, p)
    if (x**2 - x2) % p != 0:
        x = (x * I) % p
    if x % 2 != sign:
        x = p - x
    return x


# Base point coordinates
by = 4 * inv(5) % p
bx = recover_x(by, 0)
B = (bx, by)


def edwards_add(P, Q):
    """Elliptic curve point addition on Twisted Edwards curve."""
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * inv(1 + d * x1 * x2 * y1 * y2) % p
    y3 = (y1 * y2 + x1 * x2) * inv(1 - d * x1 * x2 * y1 * y2) % p
    return (x3, y3)


def edwards_mul(P, e):
    """Elliptic curve point scalar multiplication."""
    if e == 0:
        return (0, 1)
    Q = edwards_mul(P, e // 2)
    Q = edwards_add(Q, Q)
    if e & 1:
        Q = edwards_add(Q, P)
    return Q


def encode_point(P):
    """Encode a point to its compressed 32-byte representation."""
    x, y = P
    y_bytes = bytearray(y.to_bytes(32, "little"))
    if x & 1:
        y_bytes[31] |= 0x80
    return bytes(y_bytes)


def decode_point(s):
    """Decode a compressed 32-byte representation into a point."""
    y_bytes = bytearray(s)
    sign = (y_bytes[31] & 0x80) >> 7
    y_bytes[31] &= 0x7F
    y = int.from_bytes(y_bytes, "little")
    x = recover_x(y, sign)
    if (y**2 - x**2 - 1 - d * x**2 * y**2) % p != 0:
        raise ValueError("Point is not on the curve")
    return (x, y)


def xed25519_sign(private_bytes, message):
    """Generate an XEd25519 signature over a message using X25519 private key.

    Implements XEdDSA specification for Curve25519.
    """
    # 1. Clamp and parse private key scalar
    priv_clamp = bytearray(private_bytes)
    priv_clamp[0] &= 248
    priv_clamp[31] &= 127
    priv_clamp[31] |= 64
    a = int.from_bytes(priv_clamp, "little")

    # 2. Compute public key point
    A = edwards_mul(B, a)
    # If the x-coordinate is odd, we replace a with q - a
    if A[0] & 1:
        a = (q - a) % q
        A = (p - A[0], A[1])

    A_bytes = encode_point(A)

    # 3. Generate nonce
    Z = os.urandom(64)
    D1 = b"\xfe" * 32
    r = int.from_bytes(hashlib.sha512(D1 + priv_clamp + message + Z).digest(), "little") % q
    R = edwards_mul(B, r)
    R_bytes = encode_point(R)

    # 4. Compute hash and signature scalar
    h = int.from_bytes(hashlib.sha512(R_bytes + A_bytes + message).digest(), "little") % q
    s = (r + h * a) % q

    return R_bytes + s.to_bytes(32, "little")


def generate_x25519_keypair():
    """Generate a standard X25519 private/public keypair."""
    priv = x25519.X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes_raw()
    pub_bytes = priv.public_key().public_bytes_raw()
    return priv_bytes, pub_bytes


def x25519_pub_to_ed25519_pub(u_bytes):
    """Map an X25519 public key (Montgomery u) to an Ed25519 public key."""
    u = int.from_bytes(u_bytes, "little")
    y = (u - 1) * inv(u + 1) % p
    x = recover_x(y, 0)
    return encode_point((x, y))


def serialize_signal_public_key(pub_bytes):
    """Serialize public key with Signal's 0x05 type prefix."""
    return b"\x05" + pub_bytes


def generate_registration_payload(session_id, voice=True):
    """Generate the complete registration payload and private/public key pairs.

    Returns:
        tuple: (payload_dict, keys_dict)
    """
    import base64
    import random
    
    def b64(data):
        return base64.b64encode(data).decode("utf-8").rstrip("=")
        
    # Generate ACI & PNI identity keypairs
    aci_priv, aci_pub = generate_x25519_keypair()
    pni_priv, pni_pub = generate_x25519_keypair()
    
    aci_pub_prefixed = serialize_signal_public_key(aci_pub)
    pni_pub_prefixed = serialize_signal_public_key(pni_pub)
    
    # Generate signed prekeys (X25519) with ID 1
    aci_spk_priv, aci_spk_pub = generate_x25519_keypair()
    pni_spk_priv, pni_spk_pub = generate_x25519_keypair()
    
    aci_spk_pub_prefixed = serialize_signal_public_key(aci_spk_pub)
    pni_spk_pub_prefixed = serialize_signal_public_key(pni_spk_pub)
    
    # Sign public prekeys using identity private keys
    aci_spk_sig = xed25519_sign(aci_priv, aci_spk_pub_prefixed)
    pni_spk_sig = xed25519_sign(pni_priv, pni_spk_pub_prefixed)

    # Generate real post-quantum ML-KEM-1024 (Kyber) last-resort prekeys. The
    # published/signed public form is 0x08-prefixed (1569 bytes); we persist the
    # 64-byte seed private.
    from .kem import generate_kyber_keypair
    aci_pq_priv, aci_pq_pub = generate_kyber_keypair()
    pni_pq_priv, pni_pq_pub = generate_kyber_keypair()

    aci_pq_sig = xed25519_sign(aci_priv, aci_pq_pub)
    pni_pq_sig = xed25519_sign(pni_priv, pni_pq_pub)
    
    # Generate registration IDs (14-bit)
    registration_id = random.randint(1, 16380)
    pni_registration_id = random.randint(1, 16380)
    
    # Generate random credentials
    signaling_key = os.urandom(16)
    unidentified_access_key = os.urandom(16)
    
    payload = {
        "sessionId": session_id,
        "accountAttributes": {
            "signalingKey": b64(signaling_key),
            "registrationId": registration_id,
            "pniRegistrationId": pni_registration_id,
            "voice": voice,
            "video": True,
            "fetchesMessages": True,
            "registrationLock": None,
            "unidentifiedAccessKey": b64(unidentified_access_key),
            "unrestrictedUnidentifiedAccess": True,
            "discoverableByPhoneNumber": True,
            "capabilities": {
                "storage": True,
                "versionedExpirationTimer": True,
                "attachmentBackfill": False,
                "spqr": True,
                "usernameChangeSyncMessage": False
            }
        },
        "aciIdentityKey": b64(aci_pub_prefixed),
        "pniIdentityKey": b64(pni_pub_prefixed),
        "aciSignedPreKey": {
            "keyId": 1,
            "publicKey": b64(aci_spk_pub_prefixed),
            "signature": b64(aci_spk_sig)
        },
        "pniSignedPreKey": {
            "keyId": 1,
            "publicKey": b64(pni_spk_pub_prefixed),
            "signature": b64(pni_spk_sig)
        },
        "aciPqLastResortPreKey": {
            "keyId": 1,
            "publicKey": b64(aci_pq_pub),
            "signature": b64(aci_pq_sig)
        },
        "pniPqLastResortPreKey": {
            "keyId": 1,
            "publicKey": b64(pni_pq_pub),
            "signature": b64(pni_pq_sig)
        },
        "skipDeviceTransfer": True,
        "requireAtomic": True
    }
    
    keys = {
        "aci_priv": b64(aci_priv),
        "aci_pub": b64(aci_pub_prefixed),
        "pni_priv": b64(pni_priv),
        "pni_pub": b64(pni_pub_prefixed),
        "aci_spk_priv": b64(aci_spk_priv),
        "aci_spk_pub": b64(aci_spk_pub_prefixed),
        "pni_spk_priv": b64(pni_spk_priv),
        "pni_spk_pub": b64(pni_spk_pub_prefixed),
        "signaling_key": b64(signaling_key),
        "unidentified_access_key": b64(unidentified_access_key),
        "registration_id": registration_id,
        "pni_registration_id": pni_registration_id,
        "aci_kyber_priv": b64(aci_pq_priv),
        "pni_kyber_priv": b64(pni_pq_priv),
        "kyber_key_id": 1,
    }

    return payload, keys


def generate_linking_payload(verification_code, secondary_priv, secondary_pub,
                             num_one_time_prekeys=100, device_name="signal-notify",
                             pni_priv=None):
    """Generate the registration payload for a secondary linked device.

    Unlike a throwaway payload, this also **returns the private keys** so the
    caller can persist them: a linked device is the *responder* in every session
    the primary phone opens to it (e.g. the Note-to-Self sync transcripts), and
    responder X3DH/PQXDH needs our signed-prekey private, our Kyber-prekey
    private, and (optionally) our one-time-prekey privates. The previous version
    published the public halves and discarded the privates, making receive
    impossible.

    Returns:
        tuple: ``(payload, keys)`` where ``payload`` goes to
        ``PUT /v1/devices/link`` and ``keys`` carries the privates + a batch of
        one-time prekeys (public halves to upload via ``PUT /v2/keys``, privates
        to persist).
    """
    import base64
    import random

    from .kem import generate_kyber_keypair

    def b64(data):
        return base64.b64encode(data).decode("utf-8").rstrip("=")

    # Ensure secondary_pub is 32 bytes raw (strip 0x05 prefix if present)
    if len(secondary_pub) == 33 and secondary_pub.startswith(b"\x05"):
        secondary_pub_raw = secondary_pub[1:]
    else:
        secondary_pub_raw = secondary_pub

    secondary_pub_prefixed = serialize_signal_public_key(secondary_pub_raw)

    # The ACI prekeys are signed by the ACI identity key; the PNI prekeys MUST be
    # signed by the PNI identity key (the server verifies each against its own
    # identity — signing PNI prekeys with the ACI key is a 422). Fall back to the
    # ACI key only if no PNI private was supplied.
    pni_signing_priv = pni_priv if pni_priv else secondary_priv

    # Signed prekeys (X25519), keyId 1.
    aci_spk_priv, aci_spk_pub = generate_x25519_keypair()
    pni_spk_priv, pni_spk_pub = generate_x25519_keypair()

    aci_spk_pub_prefixed = serialize_signal_public_key(aci_spk_pub)
    pni_spk_pub_prefixed = serialize_signal_public_key(pni_spk_pub)

    aci_spk_sig = xed25519_sign(secondary_priv, aci_spk_pub_prefixed)
    pni_spk_sig = xed25519_sign(pni_signing_priv, pni_spk_pub_prefixed)

    # Real ML-KEM-1024 last-resort Kyber prekeys, keyId 1. The published/signed
    # form is 0x08-prefixed (1569 bytes); the persisted private is the 64-byte
    # seed.
    aci_pq_priv, aci_pq_pub = generate_kyber_keypair()
    pni_pq_priv, pni_pq_pub = generate_kyber_keypair()

    aci_pq_sig = xed25519_sign(secondary_priv, aci_pq_pub)
    pni_pq_sig = xed25519_sign(pni_signing_priv, pni_pq_pub)

    # Batch of one-time (ephemeral) X25519 prekeys for the ACI identity. These
    # are consumed by the phone as the X3DH one-time prekey (DH4); once
    # exhausted the phone falls back to the last-resort signed prekey, so this
    # batch is a best-effort optimisation, not a correctness requirement.
    one_time_prekeys = []
    for kid in range(1, num_one_time_prekeys + 1):
        otk_priv, otk_pub = generate_x25519_keypair()
        one_time_prekeys.append({
            "keyId": kid,
            "priv": b64(otk_priv),
            "publicKey": b64(serialize_signal_public_key(otk_pub)),
        })

    # Generate registration IDs (14-bit)
    registration_id = random.randint(1, 16380)
    pni_registration_id = random.randint(1, 16380)

    # Generate random credentials
    signaling_key = os.urandom(16)
    unidentified_access_key = os.urandom(16)

    # Encrypted device name (byte[] "name" in DeviceAttributes; required, base64).
    encrypted_name = encrypt_device_name(device_name, secondary_priv)

    # accountAttributes must match the modern Signal-Server DeviceAttributes /
    # AccountAttributes schema exactly — it has no @JsonIgnoreProperties, so any
    # unknown field (the legacy signalingKey / voice / video) is a 422. The
    # nullable ``capabilities`` is omitted rather than guessing its adapter's
    # array-vs-object wire form.
    payload = {
        "verificationCode": verification_code,
        "accountAttributes": {
            "fetchesMessages": True,
            "registrationId": registration_id,
            "pniRegistrationId": pni_registration_id,
            "name": encrypted_name,
            "unidentifiedAccessKey": b64(unidentified_access_key),
            "unrestrictedUnidentifiedAccess": True,
            "discoverableByPhoneNumber": True,
            # DeviceCapability is a {name: true} object. A new linked device MUST
            # advertise the CAPABILITIES_REQUIRED_FOR_NEW_DEVICES set (spqr +
            # profiles_v2); spqr also has preventDowngrade=true so it cannot be
            # omitted. NOTE: advertising spqr means the phone may use the sparse
            # post-quantum ratchet for messages to us, which our receive path
            # does not yet implement.
            "capabilities": {
                "storage": True,
                "attachmentBackfill": True,
                "spqr": True,
                "profiles_v2": True,
                "usernameChangeSyncMessage": True,
            },
        },
        "aciSignedPreKey": {
            "keyId": 1,
            "publicKey": b64(aci_spk_pub_prefixed),
            "signature": b64(aci_spk_sig)
        },
        "pniSignedPreKey": {
            "keyId": 1,
            "publicKey": b64(pni_spk_pub_prefixed),
            "signature": b64(pni_spk_sig)
        },
        "aciPqLastResortPreKey": {
            "keyId": 1,
            "publicKey": b64(aci_pq_pub),
            "signature": b64(aci_pq_sig)
        },
        "pniPqLastResortPreKey": {
            "keyId": 1,
            "publicKey": b64(pni_pq_pub),
            "signature": b64(pni_pq_sig)
        },
        "gcmToken": None
    }

    keys = {
        "registration_id": registration_id,
        "pni_registration_id": pni_registration_id,
        "aci_signed_prekey": {"keyId": 1, "priv": b64(aci_spk_priv),
                              "publicKey": b64(aci_spk_pub_prefixed),
                              "signature": b64(aci_spk_sig)},
        "pni_signed_prekey": {"keyId": 1, "priv": b64(pni_spk_priv),
                              "publicKey": b64(pni_spk_pub_prefixed),
                              "signature": b64(pni_spk_sig)},
        "aci_kyber_prekey": {"keyId": 1, "priv": b64(aci_pq_priv),
                             "publicKey": b64(aci_pq_pub),
                             "signature": b64(aci_pq_sig)},
        "pni_kyber_prekey": {"keyId": 1, "priv": b64(pni_pq_priv),
                             "publicKey": b64(pni_pq_pub),
                             "signature": b64(pni_pq_sig)},
        "one_time_prekeys": one_time_prekeys,
    }

    return payload, keys


def encrypt_device_name(device_name: str, identity_private_bytes: bytes) -> str:
    """Encrypt the device name using the standard synthetic IV AES-256-CTR scheme.

    Matches org.whispersystems.signalservice.api.util.DeviceNameUtil.java.
    """
    import base64
    import os
    import hmac
    import hashlib
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    plain_bytes = device_name.encode("utf-8")

    # Generate ephemeral keypair
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public_bytes = ephemeral_private.public_key().public_bytes_raw()

    # ECDH shared secret
    identity_private = X25519PrivateKey.from_private_bytes(identity_private_bytes)
    master_secret = identity_private.exchange(ephemeral_private.public_key())

    # Derive keys
    key1 = hmac.new(master_secret, b"auth", hashlib.sha256).digest()
    synthetic_iv_full = hmac.new(key1, plain_bytes, hashlib.sha256).digest()
    synthetic_iv = synthetic_iv_full[:16]

    key2 = hmac.new(master_secret, b"cipher", hashlib.sha256).digest()
    cipher_key = hmac.new(key2, synthetic_iv, hashlib.sha256).digest()

    # Encrypt plain_bytes using AES-256-CTR with zero IV
    cipher = Cipher(algorithms.AES(cipher_key), modes.CTR(b"\x00" * 16))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plain_bytes) + encryptor.finalize()

    # Protobuf encode DeviceName:
    # message DeviceName {
    #   optional bytes ephemeralPublic = 1;
    #   optional bytes syntheticIv     = 2;
    #   optional bytes ciphertext      = 3;
    # }
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

    def encode_bytes_field(tag, val):
        key = (tag << 3) | 2
        return encode_varint(key) + encode_varint(len(val)) + val

    proto_data = (
        encode_bytes_field(1, ephemeral_public_bytes) +
        encode_bytes_field(2, synthetic_iv) +
        encode_bytes_field(3, ciphertext)
    )

    return base64.b64encode(proto_data).decode("utf-8")

