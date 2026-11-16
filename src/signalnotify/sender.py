"""Send Signal messages via the native pure-Python engine.

Everything here is policy-free: format/batch text and hand it to the native
messaging engine. Quiet hours, keyword filtering and alert dedupe live in
:mod:`policy`, :mod:`dedupe` and :mod:`engine`.
"""
from __future__ import annotations

import logging

from .native import send_message_native, find_account_config
from .native.messaging import AccountNotLinkedError

log = logging.getLogger(__name__)


def send_message(text: str, *,
                 recipient: str | None = None,
                 note_to_self: bool = True,
                 account: str | None = None,
                 raise_on_error: bool = False,
                 attachments: list | None = None) -> bool:
    """Send a single message and return True on success.

    Routing:
      - ``recipient`` set   → send to that recipient (number / ACI / group id).
      - else ``note_to_self`` → send to your own Note-to-Self chat.

    Uses the native engine against a locally linked account; there is no
    external-binary fallback.

    ``attachments`` is a list of file paths (or raw ``bytes``): each is
    encrypted client-side and uploaded to Signal's CDN, then attached to the
    message — e.g. ``send_message("build output", attachments=["plot.png"])``
    puts the image in your Note-to-Self chat. ``text`` may be ``""`` for an
    attachment-only message.

    ``raise_on_error=True`` propagates the failure as a typed exception instead
    of returning ``False``: :class:`~signalnotify.native.SignalAPIError` for a
    server rejection (``.code`` 429 = rate-limited, 401/403 = re-link needed),
    :class:`AccountNotLinkedError` when no account is configured.
    """
    if recipient is None and not note_to_self:
        raise ValueError("send_message: pass a recipient or set note_to_self=True")
    if not text and not attachments:
        raise ValueError("send_message: pass text and/or attachments")

    config_path = find_account_config(account)
    if not config_path:
        if raise_on_error:
            raise AccountNotLinkedError(
                "no native Signal account configuration found (run: signal-notify link)")
        log.error("no native Signal account configuration found "
                  "(run: signal-notify link)")
        return False
    return send_message_native(config_path, text, recipient=recipient,
                               raise_on_error=raise_on_error,
                               attachments=attachments)


def send_reaction(emoji: str, target_author: str, target_sent_timestamp: int, *,
                  recipient: str | None = None,
                  remove: bool = False,
                  account: str | None = None,
                  raise_on_error: bool = False) -> bool:
    """React to a message (or remove a reaction) in a conversation.

    ``target_author`` is the ACI of the reacted-to message's author;
    ``target_sent_timestamp`` is that message's timestamp. ``recipient`` is the
    conversation to send the reaction to (``None`` = your Note-to-Self chat).
    ``remove=True`` with an empty ``emoji`` removes a previous reaction.
    """
    from .native.messaging import encode_reaction

    if not emoji and not remove:
        raise ValueError("send_reaction: pass an emoji or remove=True")

    config_path = find_account_config(account)
    if not config_path:
        if raise_on_error:
            raise AccountNotLinkedError(
                "no native Signal account configuration found (run: signal-notify link)")
        log.error("no native Signal account configuration found "
                  "(run: signal-notify link)")
        return False
    reaction_bytes = encode_reaction(emoji, target_author, target_sent_timestamp,
                                     remove=remove)
    return send_message_native(config_path, "", recipient=recipient,
                               raise_on_error=raise_on_error,
                               reaction_bytes=reaction_bytes)


def send_group(text: str, *, members: list[str], master_key: bytes, revision: int,
               group_change: bytes | None = None,
               account: str | None = None,
               raise_on_error: bool = False) -> bool:
    """Send a message to a Signal group by fanning out to each member.

    Signal has no group-state store here, so the caller supplies the group's
    ``master_key`` (32 bytes), ``revision``, and the ``members`` (ACIs). The
    message is sent to every member's devices with the ``GroupContextV2``
    embedded; returns True only if every member send succeeded.

    NOTE: this does not fetch group membership, does not add an own-device
    "sent" sync transcript, and does not handle server-side group
    authorization/endorsement — a larger, group-state-dependent effort. It is
    the explicit-member seam, not a complete GroupsV2 client.
    """
    from .native.messaging import encode_group_context_v2

    if not members:
        raise ValueError("send_group: pass at least one member ACI")

    config_path = find_account_config(account)
    if not config_path:
        if raise_on_error:
            raise AccountNotLinkedError(
                "no native Signal account configuration found (run: signal-notify link)")
        log.error("no native Signal account configuration found "
                  "(run: signal-notify link)")
        return False
    group_v2_bytes = encode_group_context_v2(master_key, revision,
                                             group_change=group_change)
    ok = True
    for member in members:
        sent = send_message_native(config_path, text, recipient=member,
                                   raise_on_error=raise_on_error,
                                   group_v2_bytes=group_v2_bytes)
        ok = ok and sent
    return ok


def chunk(seq: list, size: int):
    """Yield successive ``size``-length slices of ``seq``."""
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def with_prefix(text: str, prefixes: dict | None) -> str:
    """Prepend an emoji/marker to ``text`` for the first matching substring.

    ``prefixes`` maps a substring → marker. First match wins; no match returns
    the text unchanged.
    """
    if not prefixes:
        return text
    for pattern, marker in prefixes.items():
        if pattern in text:
            return f"{marker} {text}"
    return text


def send(messages: list[str], *,
         recipient: str | None = None,
         note_to_self: bool = True,
         prefixes: dict | None = None,
         header: str | None = None,
         max_per_message: int = 8,
         account: str | None = None,
         send_message_fn=None) -> bool:
    """Format, batch and send a list of message lines.

    Each line is run through :func:`with_prefix`; lines are grouped into batches
    of ``max_per_message`` and each batch sent as one message. When ``header``
    is given and there is more than one batch, an ``(i/n)`` counter is appended
    to the header. Returns True only if every batch sent successfully.

    ``send_message_fn`` overrides the per-message sender (used by tests).
    An empty ``messages`` list is a successful no-op.
    """
    fn = send_message_fn or send_message
    formatted = [with_prefix(m, prefixes) for m in messages]
    if not formatted:
        return True
    n_batches = (len(formatted) + max_per_message - 1) // max_per_message
    for idx, batch in enumerate(chunk(formatted, max_per_message)):
        head = header or ""
        if header and n_batches > 1:
            head = f"{header} ({idx + 1}/{n_batches})"
        body = (head + "\n\n" if head else "") + "\n".join(batch)
        ok = fn(body, recipient=recipient, note_to_self=note_to_self,
                account=account)
        if not ok:
            return False
    return True
