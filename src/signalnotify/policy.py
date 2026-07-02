"""Send-policy helpers: quiet hours and keyword matching."""
from __future__ import annotations

from datetime import datetime, time


def in_quiet_hours(start: str, end: str, now: datetime | None = None) -> bool:
    """True if ``now`` falls in the [start, end) window (``HH:MM`` strings).

    Windows that wrap past midnight (start > end, e.g. 22:00→07:00) are handled.
    Unparseable times return False (fail open — never suppress on bad config).
    """
    now = now or datetime.now()
    try:
        s = time.fromisoformat(start)
        e = time.fromisoformat(end)
    except (ValueError, TypeError):
        return False
    t = now.time()
    if s <= e:
        return s <= t < e
    return t >= s or t < e


def matches_any(text: str, keywords) -> bool:
    """True if ``text`` contains any of ``keywords`` (case-sensitive substring).

    Empty/None ``keywords`` → False (nothing matches). This is the strict
    sense used for *critical* keywords; the "empty means everything" default
    for *push* keywords is applied explicitly in :mod:`engine`.
    """
    if not keywords:
        return False
    return any(k in text for k in keywords)
