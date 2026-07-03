"""Config-driven notify orchestrator.

Ties together :mod:`dedupe`, :mod:`policy` and :mod:`sender` into one
monitoring-cycle step: diff the active/notified alert files, apply push and
quiet-hours policy, push the survivors via Signal, and persist state.

Config schema (all keys optional)::

    channels:
      signal:
        enabled: true          # actually send (else compute state only)
        note_to_self: true     # send to Note-to-Self (default)
        recipient: "+1..."     # OR send to a recipient instead
        account: "+1..."       # account selector (number / ACI)
    push_keywords: [...]       # only alerts containing one push at all
                               #   (empty/missing → push everything)
    critical_keywords: [...]   # of pushed alerts, these bypass quiet hours
    quiet_hours: {enabled: true, start: "22:00", end: "07:00"}
    max_per_message: 8
    prefixes: {substring: marker, ...}
"""
from __future__ import annotations

import sys
from datetime import datetime

from . import sender as _sender
from .dedupe import AlertDiff
from .policy import in_quiet_hours, matches_any


def _is_pushable(alert: str, push_keywords) -> bool:
    """True if the alert should be pushed at all.

    Empty/missing ``push_keywords`` → push everything (legacy default).
    """
    if not push_keywords:
        return True
    return any(k in alert for k in push_keywords)


def notify_from_config(cfg: dict, active_path, notified_path, *,
                       now: datetime | None = None,
                       app_name: str = "signal-notify",
                       send_fn=None,
                       out=print,
                       err=None) -> int:
    """Run one notify cycle. Returns a process-style exit code (0 ok / 1 fail).

    ``send_fn`` overrides the per-message sender (tests inject a fake).
    ``out`` / ``err`` override stdout/stderr sinks.
    """
    if err is None:
        def err(*a, **k):
            print(*a, file=sys.stderr, **k)
    now = now or datetime.now()

    push_keywords = cfg.get("push_keywords")
    critical_keywords = cfg.get("critical_keywords") or []
    prefixes = cfg.get("prefixes") or {}
    quiet = cfg.get("quiet_hours") or {}
    max_per = int(cfg.get("max_per_message", 8))
    signal_cfg = (cfg.get("channels") or {}).get("signal") or {}

    diff = AlertDiff(active_path, notified_path)
    all_new = diff.new()
    if not all_new:
        out("notify: no new alerts")
        return 0

    # Stage 1: only push_keywords matches get pushed; the rest stay visible
    # in the producer's output but generate no push.
    pushable = [a for a in all_new if _is_pushable(a, push_keywords)]
    skipped_info = len(all_new) - len(pushable)
    if skipped_info:
        out(f"notify: {skipped_info} info alert(s) deferred (not pushable)")
    if not pushable:
        # Nothing to push; mark every new alert handled so it doesn't re-flag.
        diff.commit(set(all_new))
        return 0
    new = pushable

    # Stage 2: quiet hours suppress non-critical alerts (deferred, not dropped).
    if quiet.get("enabled") and in_quiet_hours(
            quiet.get("start", "22:00"), quiet.get("end", "07:00"), now):
        critical = [a for a in new if matches_any(a, critical_keywords)]
        suppressed = [a for a in new if not matches_any(a, critical_keywords)]
        if suppressed and not critical:
            out(f"notify: quiet hours; suppressing {len(suppressed)} non-critical")
            # Don't commit — defer until quiet hours end.
            return 0
        if suppressed:
            out(f"notify: quiet hours; sending {len(critical)} critical, "
                f"deferring {len(suppressed)}")
        new = critical

    # Stage 3: send.
    enabled = bool(signal_cfg.get("enabled"))
    sent_all = True
    if enabled:
        header = f"{app_name} — {now.strftime('%Y-%m-%d %H:%M')}"
        sent_all = _sender.send(
            new,
            note_to_self=signal_cfg.get("note_to_self", True),
            recipient=signal_cfg.get("recipient"),
            account=signal_cfg.get("account"),
            prefixes=prefixes,
            header=header,
            max_per_message=max_per,
            send_message_fn=send_fn,
        )

    if sent_all:
        # Mark what we sent + info-only alerts as handled. Quiet-hours-deferred
        # non-critical alerts are NOT in `new`, so they stay un-handled and
        # push once quiet hours end.
        info_handled = {a for a in all_new if not _is_pushable(a, push_keywords)}
        diff.commit(set(new) | info_handled)
        if enabled:
            out(f"notify: sent {len(new)} new alert(s)")
        else:
            out(f"notify: signal channel disabled; "
                f"{len(new)} new alert(s) marked handled (NOT sent)")
        return 0
    err("notify: send failed; will retry next cycle")
    return 1
