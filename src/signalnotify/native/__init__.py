"""Native Python client implementation for the Signal Protocol and server API."""
from .registration import (
    create_verification_session,
    get_verification_session_status,
    submit_captcha,
    request_verification_code,
    submit_verification_code,
    register_account,
    register_secondary_device,
    decode_proto,
    SignalAPIError,
    ProofRequiredError,
)
from .crypto import generate_registration_payload, generate_linking_payload, encrypt_device_name
from .provisioning import link_device_sync, link_device_async, SecondaryProvisioningCipher, save_account_config
from .messaging import (send_message_native, find_account_config,
                        SendError, AccountNotLinkedError)

__all__ = [
    "create_verification_session",
    "get_verification_session_status",
    "submit_captcha",
    "request_verification_code",
    "submit_verification_code",
    "register_account",
    "register_secondary_device",
    "generate_registration_payload",
    "generate_linking_payload",
    "encrypt_device_name",
    "decode_proto",
    "link_device_sync",
    "link_device_async",
    "SecondaryProvisioningCipher",
    "save_account_config",
    "send_message_native",
    "find_account_config",
    "SignalAPIError",
    "ProofRequiredError",
    "SendError",
    "AccountNotLinkedError",
]


