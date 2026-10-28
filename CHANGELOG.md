# Changelog

## 0.1.1 — 2026-10-27

Security fix — upgrade recommended, especially for agent-bridge users.

- **Receive: sync messages are only trusted from our own account.** Any
  Signal user could previously send a `SyncMessage.Sent` addressed to us and
  have it surface as a `note_to_self` message, which the agent-bridge
  examples (`agent_chat.py`, `agent_daemon.py`) treat as the owner's
  command. Such messages are now dropped unless they come from one of our
  own ids.

## 0.1.0 — 2026-07-03

First tagged release.

- 100% pure-Python Signal stack: QR device-linking, registration, native
  send **and** receive (X3DH/PQXDH, Double Ratchet, round-3 Kyber-1024,
  SPQR post-quantum ratchet, sealed protobuf handling) — no external
  Signal client, no Java, no Rust toolchain required at install time.
- Note-to-Self self-notifications with attachments (client-side encrypted).
- Two-way AI-agent bridge: `send_message`, `receive(drain=False)`, `listen`
  (see `examples/agent_chat.py`, `examples/agent_daemon.py`).
- Home Assistant integration guide (`docs/home_assistant.md`).
- Config-driven alert engine (`signal-notify run`): dedupe, push/critical
  keywords, quiet hours, batching, emoji prefixes.
- `doctor` diagnostic with optional prekey maintenance (`--maintain`).
- Rust bindings under `rust/` retained only as differential-test oracles;
  CI proves a clean pip-only checkout tests green.
