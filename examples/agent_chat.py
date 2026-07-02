#!/usr/bin/env python3
"""Use your phone's Signal Note-to-Self as the interface to a headless AI agent.

signal-notify lets an agent running on a server/VM talk to you through the Signal
app you already have — no second phone number, no dedicated app, no Tailscale
tunnel. The agent pushes messages to your lock screen / Watch; you reply in your
own Note-to-Self chat; the agent reads the reply. This module is the two primitives
an agent harness needs:

    notify(text)          -> fire-and-forget: push a message to your phone.
    ask(prompt, timeout)  -> push a message, then BLOCK until you reply on the
                             phone (or the timeout elapses); returns your text.

Prereqs (one time):
    pip install -e .
    PYTHON=$(which python) rust/build.sh        # post-quantum bindings
    signal-notify link -n "my-agent"            # scan the QR with your phone

Run the interactive demo (you type here -> it appears on your phone -> you reply
on the phone -> it prints here):
    python examples/agent_chat.py
"""
from __future__ import annotations

from signalnotify import send_message, receive


def notify(text: str, *, account: str | None = None) -> bool:
    """Push a one-way message to your Note-to-Self. Returns True on success."""
    return send_message(text, account=account)


def ask(prompt: str, *, timeout: int = 180, account: str | None = None) -> str | None:
    """Send ``prompt`` to your Note-to-Self, then wait for your reply.

    Blocks on a single persistent connection until you type a reply in your
    Note-to-Self chat on the phone, or ``timeout`` seconds pass. Returns the reply
    text, or ``None`` if nothing came back in time.
    """
    send_message(prompt, account=account)
    # drain=False keeps the socket open and returns as soon as one message pushes.
    for m in receive(account=account, drain=False, max_messages=1, wait=timeout):
        if m.note_to_self and m.body:
            return m.body
        # Not a Note-to-Self text (a receipt, or a DM): return its body if any.
        if m.body:
            return m.body
    return None


def _demo() -> None:
    print("Agent <-> phone chat over Signal Note-to-Self.")
    print("Type a message to send to your phone; I'll wait for your reply there.")
    print("Ctrl-C to quit.\n")
    try:
        while True:
            outgoing = input("you (agent side) > ").strip()
            if not outgoing:
                continue
            print("  ...sent; waiting up to 180s for your reply on the phone...")
            reply = ask(outgoing, timeout=180)
            if reply is None:
                print("  (no reply within the window)\n")
            else:
                print(f"  phone > {reply!r}\n")
    except (KeyboardInterrupt, EOFError):
        print("\nbye")


if __name__ == "__main__":
    _demo()
