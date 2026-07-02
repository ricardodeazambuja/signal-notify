"""Named protobuf field numbers for the hand-rolled codec.

The zero-dependency encoder/decoder works on raw field numbers; these
constants give them names so the wire code reads like the .proto files it
mirrors. Sources: ``SignalService.proto`` (Signal-Android
libsignal-service), ``wire.proto`` (libsignal SignalMessage /
PreKeySignalMessage), and ``WebSocketResources.proto``.

Changing any value here is a WIRE FORMAT change — the golden tests in
tests/test_golden.py pin the resulting bytes.
"""

# ---- WebSocketMessage framing (WebSocketResources.proto) --------------------
WSM_TYPE = 1                    # WebSocketMessage.type
WSM_REQUEST = 2                 # WebSocketMessage.request
WSM_RESPONSE = 3                # WebSocketMessage.response
WSM_TYPE_REQUEST = 1            # Type enum
WSM_TYPE_RESPONSE = 2

WSREQ_VERB = 1                  # WebSocketRequestMessage.verb
WSREQ_PATH = 2                  # .path
WSREQ_BODY = 3                  # .body
WSREQ_ID = 4                    # .id

WSRES_ID = 1                    # WebSocketResponseMessage.id
WSRES_STATUS = 2                # .status
WSRES_MESSAGE = 3               # .message

# ---- Envelope (SignalService.proto) -----------------------------------------
ENVELOPE_TYPE = 1
ENVELOPE_TIMESTAMP = 5
ENVELOPE_SOURCE_DEVICE = 7
ENVELOPE_CONTENT = 8
ENVELOPE_SOURCE_SERVICE_ID = 11

# ---- Content ----------------------------------------------------------------
CONTENT_DATA_MESSAGE = 1
CONTENT_SYNC_MESSAGE = 2
# Field 8 is decryptionErrorMessage — NEVER write padding there (caveat #2).

# ---- DataMessage --------------------------------------------------------------
DATA_BODY = 1
DATA_ATTACHMENTS = 2
DATA_EXPIRE_TIMER = 5
DATA_PROFILE_KEY = 6
DATA_TIMESTAMP = 7
DATA_REQUIRED_PROTOCOL_VERSION = 12
DATA_GROUP_V2 = 15
DATA_EXPIRE_TIMER_VERSION = 23

# ---- AttachmentPointer --------------------------------------------------------
AP_CDN_ID = 1                   # oneof attachment_identifier (fixed64)
AP_CONTENT_TYPE = 2
AP_KEY = 3                      # 64 bytes: AES key ‖ HMAC key
AP_SIZE = 4                     # plaintext length (truncates bucket padding)
AP_THUMBNAIL = 5
AP_DIGEST = 6                   # SHA-256 over iv‖ciphertext‖mac
AP_FILE_NAME = 7
AP_FLAGS = 8
AP_WIDTH = 9
AP_HEIGHT = 10
AP_CAPTION = 11
AP_BLURHASH = 12
AP_UPLOAD_TIMESTAMP = 13
AP_CDN_NUMBER = 14
AP_CDN_KEY = 15                 # oneof attachment_identifier (string)
AP_CLIENT_UUID = 20

# ---- SyncMessage / SyncMessage.Sent ------------------------------------------
SYNC_SENT = 1
SENT_DESTINATION_E164 = 1
SENT_TIMESTAMP = 2
SENT_MESSAGE = 3
SENT_EXPIRATION_START = 4
SENT_UNIDENTIFIED_STATUS = 5    # absent for Note-to-Self (caveat #13)
SENT_IS_RECIPIENT_UPDATE = 6
SENT_DESTINATION_SERVICE_ID = 7
SENT_DESTINATION_SERVICE_ID_BINARY = 12

# ---- SignalMessage (libsignal wire.proto) -------------------------------------
SM_RATCHET_KEY = 1
SM_COUNTER = 2
SM_PREVIOUS_COUNTER = 3
SM_CIPHERTEXT = 4
SM_PQ_RATCHET = 5               # SPQR message (caveat #4)
SM_ADDRESSES = 6                # sender/recipient binding, MAC-covered

# ---- PreKeySignalMessage -------------------------------------------------------
PKSM_PRE_KEY_ID = 1
PKSM_BASE_KEY = 2
PKSM_IDENTITY_KEY = 3
PKSM_MESSAGE = 4
PKSM_REGISTRATION_ID = 5
PKSM_SIGNED_PRE_KEY_ID = 6
PKSM_KYBER_PRE_KEY_ID = 7
PKSM_KYBER_CIPHERTEXT = 8
