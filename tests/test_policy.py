from datetime import datetime

from signalnotify import policy


def _at(h, m=0):
    return datetime(2026, 1, 1, h, m)


def test_quiet_hours_normal_window():
    assert policy.in_quiet_hours("09:00", "17:00", _at(12))
    assert not policy.in_quiet_hours("09:00", "17:00", _at(8))
    assert not policy.in_quiet_hours("09:00", "17:00", _at(17))  # end exclusive


def test_quiet_hours_wrap_midnight():
    assert policy.in_quiet_hours("22:00", "07:00", _at(23))
    assert policy.in_quiet_hours("22:00", "07:00", _at(3))
    assert not policy.in_quiet_hours("22:00", "07:00", _at(12))
    assert policy.in_quiet_hours("22:00", "07:00", _at(22))      # start inclusive
    assert not policy.in_quiet_hours("22:00", "07:00", _at(7))   # end exclusive


def test_quiet_hours_bad_input_fails_open():
    assert policy.in_quiet_hours("nonsense", "07:00", _at(23)) is False


def test_matches_any():
    assert policy.matches_any("STOP HIT AAPL", ["STOP HIT", "TARGET"])
    assert not policy.matches_any("calm", ["STOP HIT"])
    assert not policy.matches_any("anything", [])
    assert not policy.matches_any("anything", None)
