# Using, Extending & Customizing

How to drive the native engine, and where the seams are if you want to send more
than plain Note-to-Self text. For the *why-it-works-this-way* traps, read
[Caveats & Hard-Won Lessons](native_caveats.md). For wire-format detail, read the
[Technical Reference](technical_reference.md).

---

## 1. Setup

### Python
```sh
pip install -e .
```
Runtime deps: `cryptography>=38` (X25519 / AES / HKDF — the post-quantum
primitives are pure Python, see below), `websockets`, `qrcode`, `PyYAML`.

### Post-quantum crypto (pure Python, built in)
The post-quantum primitives Signal mandates on a modern account are implemented
in pure Python and ship with the package — nothing to build:

| module | provides |
|--------|----------|
| `native/pure/kyber1024.py` | round-3 CRYSTALS-Kyber-1024 KEM (`generate` / `encapsulate` / `decapsulate`) |
| `native/pure/mlkem768.py`  | FIPS-203 ML-KEM-768 with the incremental split SPQR needs |
| `native/pure/spqr.py`      | Signal's Sparse Post-Quantum Ratchet (`initial_state` / `send` / `recv`) |

There is **no Java / JRE / subprocess / Rust toolchain** anywhere — the only
compiled dependency is `cryptography` (a standard pip wheel).

The Rust bindings under `rust/` are kept **only as differential-test oracles**.
You do not need them to use `signal-notify`. To run the cross-implementation
tests against them, build with a Rust toolchain + `maturin`
(`PYTHON=$(which python) rust/build.sh`; reproducible via pinned commit +
committed `Cargo.lock` + `rust-toolchain.toml` + `--locked`, see
`rust/*/PROVENANCE.md`) and select them with `SIGNALNOTIFY_KEM_BACKEND=rust` /
`SIGNALNOTIFY_SPQR_BACKEND=rust`. See
[Caveats #19](native_caveats.md) for the security posture (the pure code is
byte-compatible but **not constant-time**).

### Link an account
```sh
signal-notify link -n "server-alerts"      # prints a QR; scan with Signal → Linked Devices
signal-notify doctor                        # verify the engine can reach Signal
```
Account state lives in `~/.local/share/signal-notify/data/<number-or-uuid>`
(override with `SIGNALNOTIFY_DATA_DIR`; a store at the legacy location is
auto-migrated once) — a JSON
file, `0o600`). **Back it up before re-linking** — a fresh link overwrites it
(caveat #10).

---

## 2. CLI

```sh
signal-notify send -m "Deploy done ✅"                 # to your Note-to-Self
signal-notify send -m "hi" --to "+15551234567"         # to another recipient
signal-notify receive                                  # drain queued messages once (cron-friendly)
signal-notify receive --note-to-self                   # only your own Note-to-Self replies
signal-notify receive -t 30 --max-messages 5           # wait up to 30s, stop after 5
signal-notify doctor                                   # connectivity check
signal-notify run --config notify.yaml \
    --active active.txt --notified notified.txt        # diff-based alert engine (see README)
```
`register` / `verify` exist for registering a *primary* number rather than
linking; most users want `link`.

---

## 3. Python API

### Send
```python
from signalnotify import send_message, send            # high-level helpers
send_message("Backup OK ✅")                            # Note-to-Self
send(["disk 92%", "load 14.2"], header="host01")       # batched, with a header line

from signalnotify.native.messaging import send_message_native
send_message_native(config_path, "hi", recipient="+15551234567")   # low-level, explicit config
```
`send_message_native` returns `True`/`False`. It reuses the stored session
(whisper) and only fetches `/v2/keys` on a first send or a `409`/`410`
device-mismatch, which it reconciles and retries automatically (caveats #11, #12).

### Receive
```python
from signalnotify import receive, receive_note_to_self

for m in receive():                        # one-shot drain (returns list[Message])
    print(m.timestamp, m.source, m.body)

for m in receive_note_to_self():           # only your own Note-to-Self replies
    handle_command(m.body)
```
A `Message` has: `timestamp`, `body`, `source`, `source_name`, `note_to_self`,
`group_id`, `raw`, `attachments`. `receive()` is **one-shot** — it drains what's queued (waiting
up to `idle_timeout` for new traffic), acks, and returns; ideal per cron cycle. The
server **deletes on ack**, so persist each `Message` before doing anything that
can crash (caveat #15).

### Daemon-style listen
```python
from signalnotify.native.receive import listen
listen(lambda m: print("got:", m.body))    # persistent connection; dispatches each push
```

### Two-way loop (send + wait for a reply)
Send and receive share one session store, so you can alternate. Use
`drain=False` to hold **one** connection open and return as soon as the reply
pushes (rather than the one-shot drain, which returns immediately if nothing is
queued yet):
```python
from signalnotify import send_message, receive

send_message("What's the status?")                        # shows on the phone
reply = next((m.body for m in
              receive(drain=False, max_messages=1, wait=180) if m.note_to_self), None)
```
Ready-to-run: **[`examples/agent_chat.py`](../examples/agent_chat.py)**
(`notify()` / `ask()` + an interactive demo) and
**[`examples/agent_daemon.py`](../examples/agent_daemon.py)** (a persistent
`listen()` loop that dispatches Note-to-Self commands to a handler). These are the
AI-agent bridge patterns — see the README's [AI Agent Bridge](../README.md#-ai-agent-bridge) section.

---

## 4. Extension seams — sending richer content

Everything a message *contains* is built in `native/messaging.py` from small
protobuf encoders (`encode_varint_field`, `encode_bytes_field`,
`encode_string_field`). The layering is:

```
push_pad(                              # 0x80 byte padding, block 80  (caveat #2)
  encode_content(                      # Content{ dataMessage | syncMessage }
    encode_sync_message(               # SyncMessage{ sent }          (Note-to-Self)
      encode_sync_message_sent(        # Sent[1,2,3,4,6,12]           (caveat #13)
        encode_data_message(...)))))   # DataMessage[1,5,6,7,12,23]
```

To add a new message feature you extend the innermost encoder and, if it changes
the Content type, the wrapper:

- **New DataMessage field** (reaction, quote, expire timer, GroupV2 context):
  add it in `encode_data_message`. Field numbers come from
  `SignalService.proto`'s `DataMessage` — **look them up in the source**, don't
  guess (caveat #2 is what happens when you guess a field number).
- **Attachments:** implemented in `native/attachments.py`:
  `send_message("text", attachments=["plot.png"])` (or CLI `send --attach FILE`)
  encrypts client-side (AES-256-CBC + HMAC per `AttachmentCipherOutputStream`),
  uploads to Signal's CDN (TUS creation-with-upload on cdn3), and embeds the
  `AttachmentPointer` (`DataMessage` field 2). Received attachments appear as
  `Message.attachments` pointer dicts; fetch them with
  `attachments.download_attachment(pointer, dest_dir)` or CLI
  `receive --save-attachments DIR`. Live-proven both directions (2026-07-01):
  agent→phone renders, phone→agent downloads + decrypts.
- **Reactions / typing / receipts:** these are their own `Content` oneof members
  (`DataMessage.reaction`, `TypingMessage`=Content field 6,
  `ReceiptMessage`=Content field 5). Add an `encode_*` for the member and a branch
  in `encode_content`.
- **Group messages:** add the `GroupContextV2` (`DataMessage` field 15) and send
  to each member's devices — the send loop already handles multi-device fan-out
  and `409`/`410` reconciliation; you supply the recipient list.

**Rule:** every field number and default in these encoders is transcribed from
`SignalService.proto`. When extending, open the proto for the message you're
touching and match it exactly — the padding-in-field-8 disaster (caveat #2) was a
field-number mistake.

---

## 5. Where things live

| file | responsibility |
|------|----------------|
| `native/registration.py` | HTTP REST + Signal CA pinning + `SignalAPIError` (`.code`, `.response_body`) |
| `native/provisioning.py`  | device linking (provisioning WebSocket + cipher) |
| `native/crypto.py`        | X25519 / XEd25519 / AES / device-name encryption |
| `native/kem.py`           | Kyber-1024 wrapper over `native/pure/kyber1024.py` (caveat #1) |
| `native/ratchet.py`       | X3DH / PQXDH + Double Ratchet + SPQR; `init_sender_session`, `accept_prekey`, `ratchet_encrypt`, `ratchet_decrypt`, session (de)serialize |
| `native/messaging.py`     | protobuf encoders, padding, `send_message_native` |
| `native/attachments.py`   | attachment cipher + CDN upload/download + `AttachmentPointer` |
| `native/maintenance.py`   | prekey top-up + signed/last-resort rotation (PreKeysSyncJob flow) |
| `native/store.py`         | `locked_account()` — serialized read-modify-write on the account JSON |
| `native/proto.py`         | named protobuf field numbers for every message the codec touches |
| `native/receive.py`       | authenticated WebSocket receive/ack loop, envelope decrypt, `Content` parse, `receive`/`receive_note_to_self`/`listen` |

### Session / config store
Send and receive share **one** Double Ratchet store, `nativeRatchetSessions`
(keyed `"{peer_aci}:{device_id}"`), plus a `nativeDevices` cache
(`{recipient: {device_id: registration_id}}`) that lets repeated sends skip the
`/v2/keys` fetch. Both are persisted in the account JSON, atomically and
before every network step (caveat #15). Keep send and receive keying consistent —
self/sync traffic has an empty source and must map to your own ACI (caveat #6).

---

## 6. Testing without a live account

Committed tests use **synthetic fixtures only** — generated keypairs, mocked
`make_request`. See `tests/test_native_messaging.py` for the pattern (mock the
bundle fetch + PUT, assert on the outgoing `type`/device set, and — for the fast
path — assert exactly one `/v2/keys` fetch across two sends). Never commit real
account keys, numbers, UUIDs, or captured envelopes; those stay in gitignored
paths or the scratchpad.

```sh
python -m pytest tests/ -q
```

---

## 7. Known gaps (open extension points)

- **Sealed-sender (Envelope type 6)** inbound is `NotImplementedError`. Note-to-Self
  sync transcripts are sender-authenticated (not sealed), so this doesn't block
  the primary use case, but sealed direct messages are skipped on receive.
- **SPQR out-of-order handling** can throw `KeyAlreadyRequested` on
  significantly out-of-order whispers; in-order turn-by-turn is solid.
- **Reactions / groups** are not implemented (§4 above are the seams).
