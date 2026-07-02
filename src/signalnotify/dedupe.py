"""File-based alert dedupe.

Two newline-delimited files drive the dedupe:

  * **active**  — every alert that is true *this run* (written by the producer).
  * **notified**— alerts we have already pushed (managed here).

``new()`` = active minus notified, order preserved. ``commit(handled)`` rewrites
notified to ``(notified ∩ active) ∪ handled`` so that:

  * an alert that *cleared* (no longer in active) drops out, and re-notifies if
    it fires again later;
  * an alert we just handled won't notify again while it stays active.
"""
from __future__ import annotations

from pathlib import Path


def read_lines(path) -> list[str]:
    """Return non-empty, stripped lines of ``path`` (empty list if missing)."""
    p = Path(path)
    if not p.exists():
        return []
    return [ln.strip() for ln in p.read_text().splitlines() if ln.strip()]


class AlertDiff:
    """Diff/commit the active-vs-notified alert files."""

    def __init__(self, active_path, notified_path):
        self.active_path = Path(active_path)
        self.notified_path = Path(notified_path)

    def active(self) -> list[str]:
        return read_lines(self.active_path)

    def notified(self) -> set[str]:
        return set(read_lines(self.notified_path))

    def new(self) -> list[str]:
        """Active alerts not yet in notified, in active-file order."""
        notified = self.notified()
        return [a for a in self.active() if a not in notified]

    def commit(self, handled) -> None:
        """Persist notified := (notified ∩ active) ∪ handled."""
        active_set = set(self.active())
        notified = self.notified()
        new_state = (notified & active_set) | set(handled)
        self.notified_path.write_text("\n".join(sorted(new_state)) + "\n")
