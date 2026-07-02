"""Tests for the native sender: formatting/batching + native routing."""
from unittest.mock import patch

import pytest

from signalnotify import sender


def test_with_prefix_first_match_wins():
    prefixes = {"STOP": "🛑", "near": "⚠️"}
    assert sender.with_prefix("STOP HIT AAPL", prefixes) == "🛑 STOP HIT AAPL"
    assert sender.with_prefix("near stop AAPL", prefixes) == "⚠️ near stop AAPL"
    assert sender.with_prefix("plain", prefixes) == "plain"
    assert sender.with_prefix("plain", None) == "plain"


def test_chunk():
    assert list(sender.chunk([1, 2, 3, 4, 5], 2)) == [[1, 2], [3, 4], [5]]
    assert list(sender.chunk([], 3)) == []


def test_send_empty_is_noop_success():
    calls = []
    assert sender.send([], send_message_fn=lambda *a, **k: calls.append(a) or True)
    assert calls == []


def test_send_single_batch_no_counter():
    sent = []
    ok = sender.send(["a", "b"], header="H", max_per_message=8,
                     send_message_fn=lambda body, **k: sent.append(body) or True)
    assert ok
    assert sent == ["H\n\na\nb"]


def test_send_multi_batch_adds_counter():
    sent = []
    ok = sender.send(["a", "b", "c"], header="H", max_per_message=2,
                     send_message_fn=lambda body, **k: sent.append(body) or True)
    assert ok
    assert len(sent) == 2
    assert sent[0].startswith("H (1/2)\n\n") and "a\nb" in sent[0]
    assert sent[1].startswith("H (2/2)\n\n") and sent[1].endswith("c")


def test_send_no_header():
    sent = []
    assert sender.send(["a"], send_message_fn=lambda body, **k: sent.append(body) or True)
    assert sent == ["a"]


def test_send_stops_on_failure():
    sent = []
    ok = sender.send(["a", "b", "c"], max_per_message=1,
                     send_message_fn=lambda body, **k: sent.append(body) or False)
    assert ok is False
    assert len(sent) == 1  # bailed after the first failed batch


def test_send_applies_prefixes():
    sent = []
    sender.send(["STOP HIT"], prefixes={"STOP": "🛑"},
                send_message_fn=lambda body, **k: sent.append(body) or True)
    assert sent == ["🛑 STOP HIT"]


def test_send_message_requires_a_target():
    with pytest.raises(ValueError):
        sender.send_message("x", note_to_self=False)


def test_send_message_routes_to_native():
    with patch("signalnotify.sender.find_account_config") as mock_find, \
         patch("signalnotify.sender.send_message_native") as mock_native:
        mock_find.return_value = "/path/to/config.json"
        mock_native.return_value = True

        ok = sender.send_message("Hello", account="+15551234")
        assert ok is True
        mock_find.assert_called_once_with("+15551234")
        mock_native.assert_called_once_with("/path/to/config.json", "Hello",
                                            recipient=None, raise_on_error=False,
                                            attachments=None)


def test_send_message_missing_config_returns_false():
    with patch("signalnotify.sender.find_account_config", return_value=None):
        assert sender.send_message("Hello", account="+15551234") is False


def test_send_passes_account_through_batches():
    seen = []

    def fake_send(body, **kwargs):
        seen.append(kwargs)
        return True

    sender.send(["msg"], account="+1999", send_message_fn=fake_send)
    assert seen[0]["account"] == "+1999"
    assert "native" not in seen[0]  # the native/signal_cli knobs are gone
