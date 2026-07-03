# signal-notify

[![CI](https://github.com/ricardodeazambuja/signal-notify/actions/workflows/ci.yml/badge.svg)](https://github.com/ricardodeazambuja/signal-notify/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://github.com/ricardodeazambuja/signal-notify/blob/main/pyproject.toml)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

Notify **yourself** via [Signal](https://signal.org) with full push notifications (lock screen + Apple Watch). Messages land in your own **Note-to-Self** chat. No second phone number, no bot account, no third-party push service required.

**A phone bridge for headless AI agents.** signal-notify turns the Signal app you
already have into a two-way remote interface for an AI agent (Claude Code, Codex,
or any custom harness) running on a server or VM. The agent pushes you updates and
questions; you reply in your own Note-to-Self chat; the agent reads your reply and
acts. It's an alternative to needing a dedicated mobile app (like the Claude app)
or a [Tailscale](https://tailscale.com)-style tunnel just to reach your agent from
your phone — the transport is Signal, end-to-end encrypted, reachable from anywhere
your phone has signal. See [🤖 AI Agent Bridge](#-ai-agent-bridge) below.

**100% pure Python, no external Signal client, no Java, no Rust.** Linking,
sending *and* receiving all talk directly to Signal's servers over
HTTPS/WebSockets. Every piece of protocol logic — X3DH/PQXDH, the Double
Ratchet, the post-quantum primitives Signal mandates (**round-3 Kyber-1024**
and the **Sparse Post-Quantum Ratchet / SPQR**), protobuf, transport, padding,
session management — is Python. The only compiled dependency is `cryptography`
(a standard pip wheel, used for X25519/AES/HKDF). **No JVM, no subprocess, no
compiled extensions to build.**

---

## 📖 Quick Links

*   **Self-Notifications Tutorial:** [Setting Up Note-to-Self Notifications Step-by-Step](docs/tutorial_self_notifications.md)
*   **Home Assistant:** [Push HA notifications (and camera snapshots) to Signal](docs/home_assistant.md)
*   **Using, Extending & Customizing:** [How to drive the API and send richer content](docs/customizing.md)
*   **Caveats & Hard-Won Lessons:** [The non-obvious traps we hit building this](docs/native_caveats.md)
*   **Protocol Details & Architecture:** [Technical Reference & Protocol Design Docs](docs/technical_reference.md)
*   **Example Configuration:** [Configuration Schema Guide](notify.example.yaml)

---

## 🚀 Installation

### From a local clone
```sh
git clone https://github.com/ricardodeazambuja/signal-notify.git
cd signal-notify
pip install -e .
```

### Directly from GitHub (no manual clone)
```sh
pip install "git+https://github.com/ricardodeazambuja/signal-notify.git"
```
This installs the `signal-notify` package and CLI straight from the repo (pip
clones it internally). Python dependencies: `cryptography>=38`
(X25519/AES/HKDF), `websockets`, `qrcode`, `PyYAML`. **No external binaries, no
Java, no Rust toolchain** — a plain `pip install` is everything you need,
including the post-quantum crypto.

### ARM boards (Raspberry Pi, Jetson, …)

`signal-notify` itself is a pure-Python (`py3-none-any`) package; the only
compiled dependency is `cryptography`, and PyPI ships prebuilt `cryptography`
wheels for 64-bit ARM (`aarch64`) — so on a 64-bit Raspberry Pi OS, Jetson or
similar, a plain `pip install` just works. Two caveats:

* **32-bit ARM (`armv7l`, e.g. 32-bit Raspberry Pi OS):** PyPI has no
  `cryptography` wheel, so pip would try to build it from source (needing a
  Rust toolchain + OpenSSL headers). Use a prebuilt wheel instead: on
  Raspberry Pi OS, [piwheels](https://www.piwheels.org/project/cryptography/)
  is preconfigured and provides one (`pip install cryptography` picks it up
  automatically), or install the distro package (`apt install
  python3-cryptography`, version ≥ 38).
* **Older aarch64 images** (old JetPack / Debian): if the newest `cryptography`
  wheel doesn't match your glibc/Python, pin an older one that still ships a
  wheel for your platform — anything `>=38` works with signal-notify.

> **Post-quantum crypto is pure Python.** Kyber-1024 and SPQR are implemented in
> `signalnotify/native/pure/` and validated byte-for-byte against Signal's own
> Rust libraries (see [caveat #19](docs/native_caveats.md)). The Rust bindings
> under `rust/` are kept only as differential-test oracles; you never need to
> build them to use `signal-notify`. To run the cross-implementation tests
> against them, build with `PYTHON=$(which python) rust/build.sh` (needs a Rust
> toolchain + `maturin`) and set `SIGNALNOTIFY_SPQR_BACKEND=rust` /
> `SIGNALNOTIFY_KEM_BACKEND=rust`.

---

## ⚡ Quick Start

### 1. Link your device
Scan the terminal QR code using your phone's Signal app (**Settings → Linked Devices → Link New Device**):

```sh
signal-notify link -n "server-alerts"
```

### 2. Send a test message
```sh
signal-notify send -m "Deployment complete! ✅"
```

### 3. Send to another recipient
```sh
signal-notify send -m "Hello there" --to "+15551234567"
```

### 4. Receive replies (bidirectional, incl. Note-to-Self)
```sh
# Drain pending messages once (ideal for cron): prints each message.
signal-notify receive

# Only the replies you typed in your own Note-to-Self chat on your phone:
signal-notify receive --note-to-self
```
Receiving decrypts messages natively (responder X3DH/PQXDH + Double Ratchet).
The Note-to-Self channel works because when you type in your own Note-to-Self
chat, your phone broadcasts a *sync transcript* to this linked device — that sync
transcript is the inbound half of the loop.

---

## 🤖 AI Agent Bridge

Give a headless agent (Claude Code, Codex, or your own harness) a two-way channel
to your phone over Signal — no dedicated app, no tunnel.

### Connect your Signal app (one time)
```sh
pip install -e .                              # pure Python; post-quantum crypto included
signal-notify link -n "my-agent"              # prints a QR
```
On your phone: **Signal → Settings → Linked Devices → Link New Device → scan the QR.**
`signal-notify doctor` confirms the connection. Your account state lives (owner-only)
under `~/.local/share/signal-notify/data/` — **back it up before re-linking.**

### Two building blocks
```python
from signalnotify import send_message, receive

# 1. Push a message to your phone (fire-and-forget)
send_message("Build finished ✅ — deploy? (yes/no)")

# 1b. Push a file too — a plot, a screenshot, a log (encrypted client-side).
send_message("today's error rate", attachments=["plot.png"])

# 2. Wait for your reply, typed in Note-to-Self on the phone
#    drain=False keeps ONE connection open and returns as soon as you reply.
reply = next((m.body for m in
              receive(drain=False, max_messages=1, wait=300) if m.note_to_self), None)
if reply and reply.lower().startswith("y"):
    deploy()
```

### Ready-to-run examples
* **[`examples/agent_chat.py`](examples/agent_chat.py)** — send-then-wait. Exposes
  `notify(text)` and `ask(prompt, timeout)` (send a question, block until you
  reply on the phone). Run it for an interactive terminal ↔ phone chat.
* **[`examples/agent_daemon.py`](examples/agent_daemon.py)** — always-on. A
  persistent listener that dispatches every Note-to-Self command you send from
  your phone to a handler (wire your agent/LLM in). This is your phone "remote."

```sh
python examples/agent_chat.py       # you type here → phone → you reply on phone → prints here
python examples/agent_daemon.py     # then Note-to-Self "status" / "echo hi" from your phone
```

Why this works: your phone (the primary device) and this linked device are two
devices on **one** Signal account, so anything you type in Note-to-Self syncs to
the agent, and anything the agent sends to Note-to-Self shows up (and notifies) on
your phone. It's end-to-end encrypted and reachable anywhere your phone has Signal.
See [Using, Extending & Customizing](docs/customizing.md) for the full API.

---

## 🏠 Home Assistant

Signal makes a great Home Assistant notification channel: end-to-end
encrypted, free, no bot number, and it lands on your lock screen. The
simplest hookup is a `shell_command`:

```yaml
shell_command:
  signal_notify: "signal-notify send -m '{{ message }}'"
```

…called from any automation with `service: shell_command.signal_notify`.
The **[Home Assistant guide](docs/home_assistant.md)** covers a first-class
`notify.signal` service, sending **camera snapshots** as encrypted
attachments, alert batching/quiet hours via `run`, and a two-way daemon that
turns Note-to-Self replies into HA service calls.

---

## 🚨 Config-Driven Alert Monitoring (`run`)

`signal-notify` includes a powerful diff-based alerting engine designed for cron jobs. It compares an **active** alert list against a **notified** history file, pushing only new alerts and clearing resolved ones to ensure you get notified **exactly once** per alert instance.

Copy the template and edit your own copy:
```sh
cp notify.example.yaml notify.yaml      # then put your number/recipients in notify.yaml
signal-notify run --config notify.yaml --active active.txt --notified notified.txt
```

> **Note:** `notify.yaml` (and `*.local.yaml`) is git-ignored on purpose — it holds
> your personal number / recipients, so it never lands in the repo. Only the
> placeholder `notify.example.yaml` is tracked. Your Signal account keys live
> under `~/.local/share/signal-notify/data` and are likewise never committed.

### Example `notify.yaml`
```yaml
channels:
  signal:
    enabled: true
    note_to_self: true
```

---

## 🐍 Python API Usage

You can also import and use the library directly inside your Python applications:

```python
from signalnotify import send_message, send

# Send a single message to Note-to-Self
send_message("Server backup successful! ✅")

# Send batched alerts with a header
send(["disk 92%", "load 14.2"], header="host01")
```

### Receiving (bidirectional)

```python
from signalnotify import receive, receive_note_to_self

# One-shot drain of whatever is queued:
for m in receive():
    print(m.timestamp, m.source, m.body)

# Just the commands you typed into your Note-to-Self chat on your phone:
for m in receive_note_to_self():
    handle_command(m.body)
```

Each item is a `Message` (`timestamp`, `body`, `source`, `source_name`,
`note_to_self`, `group_id`, `raw`, `attachments`). `receive()` is one-shot — call it once per
cron cycle. A thin `listen(callback)` loop is also provided for daemon-style use.
The server acks-and-deletes on receive; pass `journal=True` to have every
parsed message appended to `<account>.inbox.jsonl` *before* it is acked, so a
crash downstream can never lose one. Envelopes that cannot be decrypted (e.g.
sealed-sender messages from contacts) are always preserved raw in
`<account>.undecryptable.jsonl` instead of being destroyed by the ack.

---

## ⚠️ Gotchas & Tips

*   **Notification Body Previews:** If you receive notifications but cannot see the message body, make sure you configure your phone's notifications preview setting. See the [Tutorial](docs/tutorial_self_notifications.md) for details.
*   **Session De-authorization:** Signal will de-authorize linked secondary devices if they remain unused for a prolonged period. If notifications stop delivering, simply re-run the `link` command and scan the QR code again.
*   **Security:** Device key credentials and session files are saved securely under owner-only read/write permissions (`0o600`) inside `~/.local/share/signal-notify/data` (override with `SIGNALNOTIFY_DATA_DIR`; an account store found at the legacy pre-1.0 location is migrated here automatically, once).

---

## 🗺️ Future Developments

The two post-quantum primitives Signal mandates — **round-3 Kyber-1024** and
**SPQR** — were originally in-process Rust (pyo3) bindings. They are now
**reimplemented in pure Python** under `signalnotify/native/pure/`
(`mlkem768.py`, `kyber1024.py`, `spqr.py` and helpers), making `signal-notify`
**100% pure Python** with zero compiled extensions to build — no Rust
toolchain, no `maturin`, no platform-specific wheels. The pure implementation
is the default; the Rust bindings under `rust/` are retained only as
differential-test oracles (keys, ciphertexts, wire messages and serialized
state are byte-compatible, so a live session can even move between the two
mid-conversation). See [caveat #19](docs/native_caveats.md) for the security
posture (notably: the pure code is *not* constant-time).

Remaining ideas: optional acceleration of the erasure-coding hot path (only
material under heavy packet loss), and PyPI publishing.

---

## 💖 Credits & Acknowledgments

This project is inspired by and built upon the design of these outstanding open source repositories:
*   [AsamK/signal-cli](https://github.com/AsamK/signal-cli) — Historical reference for the account-store layout and provisioning patterns; signal-notify no longer uses or shares state with it.
*   [signalapp/libsignal](https://github.com/signalapp/libsignal) — The cryptographic protocol specification defining the X3DH key agreement and Double Ratchet systems.

---

## License
AGPL-3.0-or-later — see [LICENSE](LICENSE). Same license as the Signal source
it interoperates with (`libsignal`, `Signal-Android`, `Signal-Server`, and the
`SparsePostQuantumRatchet` crate this project binds are all AGPL-3.0).

