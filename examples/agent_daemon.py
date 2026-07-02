#!/usr/bin/env python3
"""Reactive agent: run on a server and react to commands you Note-to-Self yourself.

Where ``agent_chat.py`` is send-then-wait, this is the always-on pattern: a
persistent listener dispatches every message you type in your phone's Note-to-Self
chat to a handler, which can run work and reply. This is how you'd give a headless
AI agent a phone "remote control" without any dedicated app.

    python examples/agent_daemon.py

Then, from your phone's Note-to-Self, send e.g. "status" or "echo hello".
Ctrl-C to stop.
"""
from __future__ import annotations

from signalnotify import send_message
from signalnotify.native.receive import listen


def handle(msg) -> None:
    # Only act on text you typed into your own Note-to-Self chat.
    if not (msg.note_to_self and msg.body):
        return
    text = msg.body.strip()
    print(f"[cmd] {text!r}")

    if text.lower() in ("status", "ping"):
        send_message("✅ agent is up and listening")
    elif text.lower().startswith("echo "):
        send_message(text[5:])
    else:
        # Hand `text` to your agent/LLM here and send back its answer:
        #     answer = my_agent(text)
        #     send_message(answer)
        send_message(f"got: {text!r} (no handler — wire your agent in here)")


if __name__ == "__main__":
    print("Listening for Note-to-Self commands. Send 'status' or 'echo hi' from your phone.")
    try:
        listen(handle)          # persistent connection; reconnects on drop
    except KeyboardInterrupt:
        print("\nstopped")
