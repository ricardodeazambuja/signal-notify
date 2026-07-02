"""signal-notify — notify yourself via Signal (Note-to-Self), pure Python.

No external Signal client, no Java: link, send and receive are all native
Python talking directly to Signal's servers.

Public API::

    from signalnotify import send_message, send, link
    send_message("build passed ✅")                     # one message to Note-to-Self
    send(["a", "b", "c"], header="CI")                   # batched
    link()                                               # QR device-link (native)

Bidirectional — read replies typed in your Note-to-Self chat::

    from signalnotify import receive, receive_note_to_self
    for m in receive_note_to_self():                     # one-shot drain
        print(m.timestamp, m.body)

Plus config-driven alert dedupe for monitoring pipelines::

    from signalnotify import load_config, notify_from_config
    cfg = load_config("notify.yaml")
    notify_from_config(cfg, "active.txt", "notified.txt", app_name="MyApp")
"""
import logging as _logging

# Library convention: emit through logging.getLogger("signalnotify.*") and let
# the application choose handlers/levels. The CLI installs a stderr handler.
_logging.getLogger(__name__).addHandler(_logging.NullHandler())

from ._version import __version__
from .config import load_config
from .dedupe import AlertDiff, read_lines
from .engine import notify_from_config
from .native import link_device_sync as link
from .native.messaging import AccountNotLinkedError, SendError
from .native.registration import SignalAPIError
from .native.receive import (
    Message,
    listen,
    receive,
    receive_note_to_self,
)
from .policy import in_quiet_hours, matches_any
from .sender import chunk, send, send_message, with_prefix

__all__ = [
    "__version__",
    "send_message",
    "send",
    "with_prefix",
    "chunk",
    "in_quiet_hours",
    "matches_any",
    "AlertDiff",
    "read_lines",
    "notify_from_config",
    "load_config",
    "link",
    "receive",
    "receive_note_to_self",
    "listen",
    "Message",
    "SignalAPIError",
    "SendError",
    "AccountNotLinkedError",
]
