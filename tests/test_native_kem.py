"""Tests for the round-3 Kyber1024 PQXDH primitive and its Signal wire glue.

Synthetic only — no real account material.
"""
import base64

import pytest

from signalnotify.native import kem
from signalnotify.native.crypto import generate_linking_payload, generate_x25519_keypair


def test_generate_kyber_keypair_shapes():
    priv, pub_serialized = kem.generate_kyber_keypair()
    assert len(priv) == kem.SECRET_KEY_LEN == 3168
    assert len(pub_serialized) == kem.PUBLIC_KEY_SERIALIZED_LEN == 1569
    assert pub_serialized[0] == kem.KYBER_TYPE_BYTE == 0x08


def test_encapsulate_decapsulate_round_trip():
    seed, pub_serialized = kem.generate_kyber_keypair()
    shared_a, ct = kem.kyber_encapsulate(pub_serialized)
    assert len(shared_a) == kem.SHARED_SECRET_LEN == 32
    assert len(ct) == kem.CIPHERTEXT_SERIALIZED_LEN == 1569
    assert ct[0] == kem.KYBER_TYPE_BYTE
    shared_b = kem.kyber_decapsulate(seed, ct)
    assert shared_a == shared_b


def test_decapsulate_tolerates_bare_and_prefixed_ciphertext():
    seed, pub_serialized = kem.generate_kyber_keypair()
    shared_a, ct = kem.kyber_encapsulate(pub_serialized)
    # Strip the 0x08 wire prefix -> still decapsulates.
    assert kem.kyber_decapsulate(seed, ct[1:]) == shared_a


def test_encapsulate_accepts_bare_public_key():
    seed, pub_serialized = kem.generate_kyber_keypair()
    shared_a, ct = kem.kyber_encapsulate(pub_serialized[1:])  # bare 1568
    assert kem.kyber_decapsulate(seed, ct) == shared_a


def test_bad_length_rejected():
    with pytest.raises(ValueError):
        kem.kyber_decapsulate(b"\x00" * 64, b"\x08" + b"\x00" * 10)


def test_linking_payload_returns_and_matches_kyber_private():
    sec_priv, sec_pub = generate_x25519_keypair()
    payload, keys = generate_linking_payload("00000000", sec_priv, sec_pub,
                                             num_one_time_prekeys=3)
    # Published last-resort Kyber pubkey is the 0x08-prefixed 1569-byte form.
    pub_serialized = base64.b64decode(payload["aciPqLastResortPreKey"]["publicKey"] + "==")
    assert len(pub_serialized) == 1569 and pub_serialized[0] == 0x08

    # The returned private seed decapsulates a ciphertext made against the
    # published public key — i.e. responder PQXDH will have the right key.
    seed = base64.b64decode(keys["aci_kyber_prekey"]["priv"] + "==")
    shared_a, ct = kem.kyber_encapsulate(pub_serialized)
    assert kem.kyber_decapsulate(seed, ct) == shared_a

    # Responder privates are all returned for persistence.
    assert base64.b64decode(keys["aci_signed_prekey"]["priv"] + "==")
    assert len(keys["one_time_prekeys"]) == 3
    assert keys["registration_id"] == payload["accountAttributes"]["registrationId"]


def test_linking_payload_one_time_prekeys_have_public_and_priv():
    sec_priv, sec_pub = generate_x25519_keypair()
    _, keys = generate_linking_payload("00000000", sec_priv, sec_pub,
                                       num_one_time_prekeys=4)
    for otk in keys["one_time_prekeys"]:
        assert otk["keyId"] >= 1
        pub = base64.b64decode(otk["publicKey"] + "==")
        assert len(pub) == 33 and pub[0] == 0x05  # 0x05 || raw32
        assert len(base64.b64decode(otk["priv"] + "==")) == 32
