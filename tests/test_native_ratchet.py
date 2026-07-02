"""Double Ratchet + X3DH/PQXDH round-trip tests (synthetic keys only).

An initiator built from the same module encrypts; the responder path
(``accept_prekey`` / ``ratchet_decrypt``) decrypts. This validates internal
consistency of the responder against a spec-faithful sender — it does NOT prove
interop with a real phone (that needs a live captured envelope), but it exercises
X3DH, PQXDH (ML-KEM-1024), the DH-ratchet, chain stepping, the MAC, and the
skipped-message-key store.
"""
import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from signalnotify.native import kem, ratchet


def _x25519():
    priv = X25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()


def _bob_bundle(with_kyber=True, with_otk=True):
    """Build Bob's (responder) privates + the public bundle Alice consumes."""
    id_priv, id_pub_raw = _x25519()
    spk_priv, spk_pub_raw = _x25519()
    otk_priv, otk_pub_raw = _x25519()
    kyber_priv, kyber_pub = (kem.generate_kyber_keypair() if with_kyber else (None, None))

    account_keys = {
        "identity_priv": id_priv,
        "identity_pub": b"\x05" + id_pub_raw,
        "signed_prekeys": {1: spk_priv},
        "kyber_prekeys": {1: kyber_priv} if with_kyber else {},
        "one_time_prekeys": {77: otk_priv} if with_otk else {},
    }
    bundle = {
        "identity_pub": b"\x05" + id_pub_raw,
        "signed_prekey_pub": b"\x05" + spk_pub_raw,
        "signed_prekey_id": 1,
        "one_time_prekey_pub": (b"\x05" + otk_pub_raw) if with_otk else None,
        "one_time_prekey_id": 77 if with_otk else None,
        "kyber_pub": kyber_pub if with_kyber else None,
        "kyber_id": 1 if with_kyber else None,
    }
    return account_keys, bundle


def _alice_prekey_content(bundle, plaintext, version):
    """Alice initiates against Bob's bundle and frames the first PREKEY message."""
    alice_id_priv, alice_id_pub_raw = _x25519()
    alice_id_pub = b"\x05" + alice_id_pub_raw
    session, base_pub, kyber_ct = ratchet.init_sender_session(
        our_identity_priv=alice_id_priv,
        our_identity_pub=alice_id_pub,
        their_identity_pub=bundle["identity_pub"],
        their_signed_prekey_pub=bundle["signed_prekey_pub"],
        their_one_time_prekey_pub=bundle["one_time_prekey_pub"],
        their_kyber_pub=bundle["kyber_pub"],
    )
    inner = ratchet.ratchet_encrypt(session, plaintext, version=version)
    content = ratchet.frame_prekey_message(
        inner_serialized=inner, base_pub=base_pub, our_identity_pub=alice_id_pub,
        registration_id=4242, signed_prekey_id=bundle["signed_prekey_id"],
        pre_key_id=bundle["one_time_prekey_id"],
        kyber_prekey_id=bundle["kyber_id"], kyber_ciphertext=kyber_ct,
        version=version)
    return session, content, alice_id_pub


def test_pqxdh_prekey_round_trip():
    account_keys, bundle = _bob_bundle(with_kyber=True, with_otk=True)
    _, content, alice_id = _alice_prekey_content(bundle, b"hello note to self",
                                                 ratchet.CIPHERTEXT_VERSION_V4)
    session, plaintext = ratchet.accept_prekey(account_keys, content)
    assert plaintext == b"hello note to self"
    assert session.their_identity == alice_id


def test_classic_x3dh_prekey_round_trip():
    account_keys, bundle = _bob_bundle(with_kyber=False, with_otk=True)
    _, content, _ = _alice_prekey_content(bundle, b"classic hi",
                                          ratchet.CIPHERTEXT_VERSION_V3)
    _, plaintext = ratchet.accept_prekey(account_keys, content)
    assert plaintext == b"classic hi"


def test_prekey_without_one_time_prekey():
    # Phone falls back to the last-resort signed prekey (no DH4).
    account_keys, bundle = _bob_bundle(with_kyber=True, with_otk=False)
    _, content, _ = _alice_prekey_content(bundle, b"no otk",
                                          ratchet.CIPHERTEXT_VERSION_V4)
    _, plaintext = ratchet.accept_prekey(account_keys, content)
    assert plaintext == b"no otk"


def test_session_continuation_in_order():
    account_keys, bundle = _bob_bundle()
    alice, content, _ = _alice_prekey_content(bundle, b"m0",
                                              ratchet.CIPHERTEXT_VERSION_V4)
    bob, p0 = ratchet.accept_prekey(account_keys, content)
    assert p0 == b"m0"
    # Alice keeps sending on the same ratchet; Bob decrypts in order.
    for i in range(1, 5):
        msg = ratchet.ratchet_encrypt(alice, f"m{i}".encode(),
                                      version=ratchet.CIPHERTEXT_VERSION_V4)
        assert ratchet.ratchet_decrypt(bob, msg) == f"m{i}".encode()


def test_out_of_order_uses_skipped_keys():
    account_keys, bundle = _bob_bundle()
    alice, content, _ = _alice_prekey_content(bundle, b"m0",
                                              ratchet.CIPHERTEXT_VERSION_V4)
    bob, _ = ratchet.accept_prekey(account_keys, content)
    msgs = [ratchet.ratchet_encrypt(alice, f"m{i}".encode(),
                                    version=ratchet.CIPHERTEXT_VERSION_V4)
            for i in range(1, 5)]
    # Deliver 4th first, then 1st — both must decrypt (skipped-key store).
    assert ratchet.ratchet_decrypt(bob, msgs[3]) == b"m4"
    assert ratchet.ratchet_decrypt(bob, msgs[0]) == b"m1"
    assert ratchet.ratchet_decrypt(bob, msgs[1]) == b"m2"


def test_bad_mac_rejected():
    account_keys, bundle = _bob_bundle()
    _, content, _ = _alice_prekey_content(bundle, b"tamper me",
                                          ratchet.CIPHERTEXT_VERSION_V4)
    tampered = bytearray(content)
    tampered[-1] ^= 0xFF  # flip a MAC byte
    with pytest.raises(ValueError):
        ratchet.accept_prekey(account_keys, bytes(tampered))


def test_session_json_round_trip_preserves_decryption():
    account_keys, bundle = _bob_bundle()
    alice, content, _ = _alice_prekey_content(bundle, b"m0",
                                              ratchet.CIPHERTEXT_VERSION_V4)
    bob, _ = ratchet.accept_prekey(account_keys, content)
    # Serialize/reload Bob's session, then decrypt a follow-up message.
    reloaded = ratchet.session_from_json(ratchet.session_to_json(bob))
    msg = ratchet.ratchet_encrypt(alice, b"after reload",
                                  version=ratchet.CIPHERTEXT_VERSION_V4)
    assert ratchet.ratchet_decrypt(reloaded, msg) == b"after reload"


def test_account_keys_from_config():
    from signalnotify.native.crypto import generate_linking_payload, generate_x25519_keypair
    from signalnotify.native.provisioning import save_account_config
    import json
    import tempfile
    import os

    sec_priv, sec_pub = generate_x25519_keypair()
    _, responder_keys = generate_linking_payload("00000000", sec_priv, sec_pub,
                                                 num_one_time_prekeys=2)
    with tempfile.TemporaryDirectory() as d:
        cfg_path = save_account_config(
            data_dir=d, number="+15550100", aci="00000000-0000-0000-0000-000000000000",
            pni="00000000-0000-0000-0000-000000000001", password="pw",
            aci_identity_pub=b"\x05" + b"\x11" * 32, aci_identity_priv=b"\x22" * 32,
            pni_identity_pub=b"\x05" + b"\x33" * 32, pni_identity_priv=b"\x44" * 32,
            profile_key=None, account_entropy_pool=None, media_root_backup_key=None,
            device_id=2, responder_keys=responder_keys)
        cfg = json.loads(open(cfg_path).read())
    keys = ratchet.account_keys_from_config(cfg)
    assert 1 in keys["signed_prekeys"]
    assert 1 in keys["kyber_prekeys"]
    assert len(keys["one_time_prekeys"]) == 2
    assert len(keys["identity_priv"]) == 32
