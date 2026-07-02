from signalnotify.dedupe import AlertDiff, read_lines


def test_read_lines_missing(tmp_path):
    assert read_lines(tmp_path / "nope.txt") == []


def test_new_preserves_order_and_skips_notified(tmp_path):
    active = tmp_path / "active.txt"
    notified = tmp_path / "notified.txt"
    active.write_text("A\nB\nC\n")
    notified.write_text("B\n")
    d = AlertDiff(active, notified)
    assert d.new() == ["A", "C"]


def test_commit_union_with_still_active(tmp_path):
    active = tmp_path / "active.txt"
    notified = tmp_path / "notified.txt"
    active.write_text("A\nB\nC\n")
    notified.write_text("B\n")
    d = AlertDiff(active, notified)
    d.commit({"A", "C"})
    # (notified ∩ active) ∪ handled = ({B}) ∪ {A,C} = {A,B,C}
    assert set(read_lines(notified)) == {"A", "B", "C"}


def test_commit_drops_cleared_alert(tmp_path):
    active = tmp_path / "active.txt"
    notified = tmp_path / "notified.txt"
    active.write_text("A\n")          # B is no longer active this run
    notified.write_text("A\nB\n")
    d = AlertDiff(active, notified)
    assert d.new() == []
    d.commit(set())
    # B drops out, so if it ever fires again it re-notifies.
    assert set(read_lines(notified)) == {"A"}
