# Caveats & Hard-Won Lessons

This document records the non-obvious traps in talking to Signal's live servers
with a from-scratch client. Each entry is **symptom → root cause → fix → source**
so a future maintainer does not have to rediscover it empirically. Most of these
cost hours or days to find; almost all were ultimately answered by *reading
Signal's own source*, not by guessing.

> **Meta-lesson (read this first).** For any protocol question, **read the
> libsignal / Signal-Android source before experimenting.** Every wall below was
> broken by a single source read after a long empirical detour. The two worst
> bugs (wrong KEM, padding-in-wrong-field) were each a one-line fact in the
> source. Clone the references and grep them:
> - `signalapp/libsignal` (Rust) — ratchet, X3DH/PQXDH, `kem.rs`, envelope/message protobufs, `PADDING_BOUNDARY_BYTE`.
> - `signalapp/Signal-Android` `libsignal-service` — `PushTransportDetails` (padding block size), `SignalServiceProtos` (`Content`/`SyncMessage` field numbers), `MessageSender` (mismatched/stale-device handling, sent-transcript construction).
> - `AsamK/signal-cli` (Java) — config/storage layout and `--notify-self` semantics. It wraps the Rust crypto; the crypto is *not* in the Java.

---

## 1. The KEM is round-3 CRYSTALS-Kyber-1024 — NOT FIPS-203 ML-KEM

**Symptom:** every inbound message fails with "bad MAC," on every message, and
re-linking never helps.

**Cause:** Signal's PQXDH uses **round-3 Kyber-1024** (libsignal `kem::KeyType`
wire byte **`0x08`**), backed by `libcrux_ml_kem::kyber1024` (the `kyber`
feature). It is **not** FIPS-203 ML-KEM (byte `0x0A`). The two have identical
key/ciphertext sizes (1568 bytes), so decapsulating a Kyber ciphertext with an
ML-KEM decapsulator does **not** error — it silently returns a *different* shared
secret (KEM implicit rejection). That wrong secret poisons the PQXDH root key, so
every derived message key is wrong and the MAC fails. There is no loud failure to
point you at the KEM.

**Fix:** `rust/kyber1024_py` binds the exact `libcrux-ml-kem 0.0.8` `kyber1024`
that libsignal ships. The private key is the **full 3168-byte decapsulation
key**, not a 64-byte seed. On the wire Signal prefixes the Kyber public key and
ciphertext with `0x08` → 1569 bytes.

**Source:** `libsignal/rust/protocol/src/kem.rs` (`KeyType::Kyber1024 = 0x08`).
This superseded an earlier (wrong) ML-KEM assumption.

---

## 2. Padding is a byte-level scheme — NOT a protobuf field (this one blocked *display*)

**Symptom:** messages send successfully, the phone even *decrypts* them (proven
on the wire), but they **never appear** in the chat — no bubble, no notification.
Earlier variants showed "chat session refreshed" instead.

**Cause:** we padded the `Content` protobuf by appending **field 8**. In
`SignalService.proto`, `Content` **field 8 is `decryptionErrorMessage`**, not
padding. So every message we sent looked to the phone like a decryption-error /
retry notice, and the client handled it as a protocol event instead of a
displayable message — silently.

**Fix:** Signal pads at the **byte level, after** the serialized protobuf:
append a single `0x80` boundary marker, then `0x00` bytes to a block boundary.
No protobuf padding field exists. Block size is **`PADDING_BLOCK_SIZE = 80`** in
the current app (the archived `libsignal-service-java` used 160 — the constant
changed; verify against a live capture). The exact length is
`ceil((len(content)+2)/80)*80 - 1`. Implemented in `messaging.push_pad()`.

**Source:** libsignal `PADDING_BOUNDARY_BYTE = 0x80`
(`rust/protocol/src/protocol.rs`); Signal-Android
`PushTransportDetails.getPaddedMessageBody` / `getPaddedMessageLength`.

---

## 3. Every Curve25519 public key on the wire is `0x05`-prefixed (33 bytes)

**Symptom:** the peer rejects our PreKey message ("chat session refreshed"), or a
whisper fails to decrypt, even though a local send→receive round-trip passes.

**Cause:** Signal's wire format tags every Curve25519 public key with a type
byte `0x05`, so identity keys, the PreKey `base_key`, and the SignalMessage
`ratchet_key` are all **33 bytes** (`0x05 || 32-byte raw`), never raw 32 bytes.
We were emitting raw 32-byte keys for `base_key`/`ratchet_key`; the MAC binds
these, so the peer's MAC check failed. (Kyber keys/ciphertexts are `0x08`-prefixed
→ 1569 bytes.)

**Fix:** prefix on the way out (`_prefix()`), accept either width on the way in
(`_unprefix()` tolerates 32|33). The lenient receive is exactly what *masked* the
send bug in the round-trip — see caveat #9.

**Source:** `libsignal/rust/protocol/src/curve` / `PublicKey` serialization.

---

## 4. SPQR (the "triple ratchet") is mandatory for modern linked devices

**Symptom:** PQXDH + Double Ratchet is implemented correctly and *still* every
Note-to-Self sync fails "bad MAC."

**Cause:** modern Signal mandates the **`spqr` capability** for newly linked
devices and encrypts Note-to-Self sync transcripts with the **Sparse
Post-Quantum Ratchet** (SPQR / "triple ratchet") layered on top of PQXDH +
Double Ratchet. Without it the message keys are wrong.

**Fix:** `rust/spqr_py` binds Signal's `spqr` crate (pinned to the commit
libsignal ships). Wiring: the **3rd PQXDH output** is the SPQR `auth_key`;
`SignalMessage` **field 5** carries the SPQR message; SPQR's returned key is the
**HKDF salt** used to derive the Double Ratchet message keys.

**Source:** libsignal `spqr` crate + `ratchet` integration.

---

## 5. The authenticated WebSocket needs a Basic-auth HEADER, not query params

**Symptom:** the socket connects and stays open, but **no queued messages are
ever delivered** — it looks idle forever.

**Cause:** the authenticated endpoint `wss://chat.signal.org/v1/websocket/`
authenticates via an HTTP **`Authorization: Basic base64("{aci}.{deviceId}:{password}")`
header on the handshake**. The `?login=…&password=…` query-param form is silently
ignored — the socket connects *unauthenticated*, so the server has no identity to
deliver queued messages to.

**Fix:** set the `Authorization` header on the WS handshake. Username is
`{aci}.{deviceId}` (the `.deviceId` matters — a bare ACI means device 1).

---

## 6. Self / sync envelopes arrive with an EMPTY source field

**Symptom:** we can receive fine *until* we send first; after a send, the phone's
own replies (Note-to-Self) fail with "no session for :1".

**Cause:** the server **omits the `Envelope.source` field for own-account
traffic** (your other devices, Note-to-Self). Receive keyed the session `":1"`
(empty source + device), but send keys it `"{our_aci}:1"`. The two directions
diverged, so the reply on the session we established could not be found.

**Fix:** in receive, map an empty source to our own ACI before building the
session key. Now both directions agree on `"{our_aci}:{device}"`.

**Source:** observed on the wire; fixed in `receive._decrypt_envelope`.

---

## 7. Live host + pinned CA

**Symptom:** connections to the old host hang/fail; connections to the live host
fail public-CA verification.

**Cause:** the historical `textsecure-service.whispersystems.org` host is dead —
everything is `chat.signal.org` now. That host presents a certificate chained to
**Signal's own root CA**, which the public trust store does not contain, so
default TLS verification rejects it.

**Fix:** pin Signal's root CA, bundled as `native/signal-ca.pem` (extracted from
the app's `whisper.store` BKS keystore via `pyjks`) and loaded by
`registration.signal_ssl_context()`.

---

## 8. "Chat session refreshed" is a decryption-error signal — and easy to self-inflict

**Symptom:** the phone shows "chat session refreshed" and no message, repeatedly.

**Cause:** the phone renders "chat session refreshed" when it resets a session —
typically because it received a **new PreKey message with a new base key** and
archived the old session. During debugging we cleared `nativeRatchetSessions`
between every send, so every send went out as a fresh PreKey → the phone reset
its session **every time**. We were manufacturing the symptom we were chasing.

**Fix:** do **not** clear sessions to "start clean." Reuse the stored session
(sends go out as whispers). Only a genuine first contact should be a PreKey.

---

## 9. A passing local round-trip proves *nothing* about the wire

**Symptom:** `Alice.send → Bob.decrypt → Bob.reply → Alice.decrypt` passes in a
unit test, but real interop fails.

**Cause:** a local round-trip uses **the same code for both sides**, so any
*symmetric* error cancels out. Both the wrong-KEM bug (#1) and the raw-vs-`0x05`
key bug (#3) sailed through a green round-trip because the receive side made the
identical mistake (or was lenient about it). This is the single biggest source of
false confidence in this project.

**Fix:** the only trustworthy evidence is **cross-implementation / live**: send
to a real phone, or decrypt a real phone message. When we finally proved send
crypto, it was by catching the phone replying *on the session our send
established* — something a local test can never show.

---

## 10. Re-linking overwrites the account data dir

**Symptom:** a working account suddenly can't decrypt anything after a re-link.

**Cause:** a fresh native `link` of the same number **overwrites**
`~/.local/share/signal-notify/data/<id>` (new identity/prekeys/sessions). Any prior
session state — and any captured-but-undecrypted material tied to it — is gone.

**Fix:** back up the config file before any re-link or live experiment.

---

## 11. Rate-limits: `/v2/keys` (HTTP 429)

**Symptom:** `429 Too Many Requests` on `/v2/keys` mid-testing; sends start
failing.

**Cause:** fetching the recipient's prekey bundle on **every** send. Rapid
repeated fetches trip the rate limit (each also consumes one of the peer's
one-time prekeys).

**Fix:** cache the peer device set + registration ids (`nativeDevices`) and reuse
the stored session — repeated sends are whispers with **no** `/v2/keys` fetch.
Only a first send, or a `409`/`410` device-mismatch, triggers a fetch. See
`send_message_native` and caveat #12.

---

## 12. Device reconciliation: 409 / 410 are normal, not errors

**Symptom:** a `PUT /v1/messages` fails `409` or `410` and the message is lost.

**Cause:** the server rejects a send when your device set is wrong: **`409`
MismatchedDevices** `{missingDevices, extraDevices}` (you skipped a device the
recipient now has, or sent to one they don't) and **`410` StaleDevices**
`{staleDevices}` (a device's session is stale). These are *recoverable*, expected
responses — not failures.

**Fix (per Signal-Android `handleMismatchedDevices`/`handleStaleDevices`):** on
`409` drop sessions for `extraDevices`, (re)establish `missingDevices`; on `410`
drop sessions for `staleDevices` so they re-establish via a fresh PreKey; then
**retry once**. Implemented in `send_message_native`.

**Source:** `libsignal-service-java` `MismatchedDevices`/`StaleDevices`,
`PushServiceSocket` 409/410 parsing, `SignalServiceMessageSender`.

---

## 13. Note-to-Self display requires a *Sent transcript*, not a bare DataMessage

**Symptom:** a plain `DataMessage` addressed to your own ACI decrypts but does not
show in Note-to-Self.

**Cause:** a linked device announces what it sent via a **`SyncMessage.Sent`
transcript**, and that is what the primary renders in Note-to-Self. The exact
shape a real client emits (verified against a live capture): `Sent` fields
`[1 destinationE164, 2 timestamp, 3 DataMessage, 4 expirationStartTimestamp(=ts),
6 isRecipientUpdate(=0), 12 destinationServiceIdBinary]`; the inner `DataMessage`
is `[1 body, 5 expireTimer(=0), 6 profileKey, 7 timestamp, 12 requiredProtocolVersion(=0),
23 expireTimerVersion(=1)]`. `unidentifiedStatus(5)` is populated only for
sealed-sender recipients and is **absent** for Note-to-Self.

**Note:** `signal-cli --notify-self` uses a slightly different path (a real
DataMessage to self via `sendMessage(getSelfRecipientId())`); either can display,
but a linked device's Sent transcript is what we emit and what a live capture
confirmed renders.

---

## 14. Provisioning: ACI is `aciBinary` (16 bytes), not the string field

When parsing the provisioning envelope, the account ACI comes from **`aciBinary`
field 17 (16-byte UUID)**, not the deprecated string field.

---

## 15. Commit-before-network (ratchet durability)

Both directions persist ratchet state **before** their network step — send
persists before the `PUT`, receive persists before the `ACK`. Rationale: a crash
between using a message key and persisting could **reuse** an AES key+IV (a real
cryptographic failure); persisting first can at worst **skip** a key (which the
Double Ratchet tolerates via its skipped-key store). The config file is the sole
copy of identity keys + password + ratchet state, so writes are atomic + `0o600`.

---

## 16. `register --captcha` starts a fresh verification session

`register --captcha` does **not** accept an existing `--session-id`; a CAPTCHA
opens a new session. Re-run `register` from the start if a CAPTCHA round does not
immediately yield `allowedToRequestCode`.

---

## 17. Reproducible Rust builds — don't let the lockfile drift

Both bindings pin everything so a clean checkout rebuilds identical binaries: the
git dependency is pinned to an **immutable commit**, `Cargo.lock` is committed,
`rust-toolchain.toml` pins the compiler, and `rust/build.sh` uses
**`maturin develop --release --locked`** so a drifted lockfile is an *error*, not
a silent auto-update. See `rust/*/PROVENANCE.md`. Build gotcha: `rand_core 0.9`
`OsRng` is fallible — use `.unwrap_err()` where a `CryptoRng` is expected.

---

## 18. Personal-account data handling (MANDATORY when testing against a real account)

Development/testing may use a real, already-linked personal Signal account on
disk. But:

- The account's credentials, identity/session keys, phone number, UUID, and
  **any artifact derived from it** (captured envelopes, decrypted bodies,
  dumps, debug logs, ad-hoc test data) **must never enter git history** — not
  a commit, not a tracked/stashed file.
- Anything real-account-derived must live only in a **gitignored** path
  (`captures/`, `*.envelope`, `notify.yaml` / `notify.*.yaml` / `*.local.yaml`
  all match this). Before writing such a file, verify with
  `git check-ignore -v <path>`; if it's not ignored, add a rule to
  `.gitignore` first.
- After any work touching a real account, run `git status` and confirm no
  real-account-derived file is staged or untracked-and-committable. Redact
  the phone number / UUID in console output and logs. Never transmit the
  account or any envelope off-machine.
- **Committed tests must use synthetic fixtures only** (reserved
  `+1555-01xx` numbers, all-zero UUIDs, as the existing tests do) — never a
  real account. See [Using, Extending & Customizing §6](customizing.md#6-testing-without-a-live-account). 
