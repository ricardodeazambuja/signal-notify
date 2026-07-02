"""Typed error propagation: raise_on_error surfaces the real failure cause.

An agent harness needs to distinguish a 429 (back off and retry) from 401/403
(credentials revoked -> re-link) from a missing account config; a bare False
return can't carry that.
"""
import json
from unittest.mock import patch

import pytest

from signalnotify import AccountNotLinkedError, SendError, SignalAPIError
from signalnotify.native.messaging import send_message_native
from signalnotify.sender import send_message
from test_native_messaging import _bundle, _config, _device


@patch("signalnotify.native.messaging.make_request")
def test_rate_limit_raises_with_code(mock_req, tmp_path):
    config_path = _config(tmp_path)

    def side_effect(path, method="GET", body=None, headers=None, base_url=None):
        raise SignalAPIError(429, "rate limited")

    mock_req.side_effect = side_effect
    with pytest.raises(SignalAPIError) as exc:
        send_message_native(config_path, "hi", recipient="rec-aci-uuid",
                            raise_on_error=True)
    assert exc.value.code == 429


@patch("signalnotify.native.messaging.make_request")
def test_default_still_returns_false(mock_req, tmp_path):
    config_path = _config(tmp_path)
    mock_req.side_effect = SignalAPIError(401, "unauthorized")
    assert send_message_native(config_path, "hi", recipient="rec-aci-uuid") is False


@patch("signalnotify.native.messaging.make_request")
def test_no_devices_raises_send_error(mock_req, tmp_path):
    config_path = _config(tmp_path)
    mock_req.side_effect = lambda path, method="GET", body=None, headers=None, \
        base_url=None: (_bundle([]), {}) if method == "GET" else ({}, {})
    with pytest.raises(SendError):
        send_message_native(config_path, "hi", recipient="rec-aci-uuid",
                            raise_on_error=True)


@patch("signalnotify.native.messaging.make_request")
def test_reconcile_failure_raises_final_error(mock_req, tmp_path):
    config_path = _config(tmp_path)

    def side_effect(path, method="GET", body=None, headers=None, base_url=None):
        if method == "GET":
            return _bundle([_device(1, 5678)]), {}
        if not hasattr(side_effect, "hit"):
            side_effect.hit = True
            raise SignalAPIError(410, "stale",
                                 json.dumps({"staleDevices": [1]}))
        raise SignalAPIError(500, "server broke")

    mock_req.side_effect = side_effect
    with pytest.raises(SignalAPIError) as exc:
        send_message_native(config_path, "hi", recipient="rec-aci-uuid",
                            raise_on_error=True)
    assert exc.value.code == 500


def test_unlinked_account_raises(tmp_path, monkeypatch):
    monkeypatch.setattr("signalnotify.sender.find_account_config", lambda a: None)
    with pytest.raises(AccountNotLinkedError):
        send_message("hi", raise_on_error=True)
    assert send_message("hi") is False  # default behavior preserved


def test_error_types_are_importable_from_top_level():
    import signalnotify
    assert issubclass(signalnotify.AccountNotLinkedError, signalnotify.SendError)
    assert signalnotify.SignalAPIError is SignalAPIError
