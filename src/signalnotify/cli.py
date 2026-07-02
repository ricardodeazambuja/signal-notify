"""Command-line interface: ``signal-notify <send|link|receive|doctor|run|…>``.

Fully native (pure Python) — no external binaries.
"""
from __future__ import annotations

import argparse
import sys

from ._version import __version__
from .config import load_config
from .engine import notify_from_config
from .sender import send_message


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="signal-notify",
        description="Notify yourself via Signal (native Note-to-Self, pure Python).",
    )
    p.add_argument("--version", action="version",
                   version=f"signal-notify {__version__}")
    p.add_argument("-v", "--verbose", action="count", default=0,
                   help="verbose logging (-v = DEBUG); library logs go to stderr")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("send", help="send a message")
    sp.add_argument("-m", "--message", default="", help="message text")
    sp.add_argument("--attach", action="append", default=[], metavar="FILE",
                    help="attach a file (repeatable); encrypted client-side")
    sp.add_argument("--to", "--recipient", dest="recipient",
                    help="send to a recipient (number / ACI / group) instead of Note-to-Self")
    sp.add_argument("-a", "--account", help="account selector (number / ACI)")

    lp = sub.add_parser("link", help="QR-link this device to your Signal account")
    lp.add_argument("-n", "--name", default="signal-notify", help="linked device name")

    rcp = sub.add_parser(
        "receive",
        help="receive incoming messages, incl. Note-to-Self replies")
    rcp.add_argument("-a", "--account", help="account selector (number / ACI)")
    rcp.add_argument("-t", "--timeout", type=int, default=5,
                     help="seconds to wait for new messages (default: 5)")
    rcp.add_argument("--max-messages", type=int,
                     help="stop after receiving this many messages")
    rcp.add_argument("--note-to-self", action="store_true",
                     help="only print text replies typed in your Note-to-Self chat")
    rcp.add_argument("--save-attachments", metavar="DIR",
                     help="download+decrypt received attachments into DIR")

    dp = sub.add_parser("doctor", help="check that the native engine is reachable")
    dp.add_argument("-a", "--account", help="account selector (number / ACI)")
    dp.add_argument("--maintain", action="store_true",
                    help="also top up one-time prekeys and rotate the signed/"
                         "last-resort prekeys if due (2-day cadence)")

    rp = sub.add_parser(
        "run", help="diff alert files and push new alerts (config-driven)")
    rp.add_argument("--config", required=True, help="notify-config YAML path")
    rp.add_argument("--active", required=True, help="active-alerts file path")
    rp.add_argument("--notified", required=True, help="notified-alerts file path")
    rp.add_argument("--app-name", default="signal-notify",
                    help="header prefix on pushed messages")

    # Native registration subcommands (register a brand-new number)
    reg_p = sub.add_parser("register", help="Register a phone number (start verification session)")
    reg_p.add_argument("--number", required=True, help="E164 phone number, e.g., +15551234567")
    reg_p.add_argument("--voice", action="store_true", help="use voice call instead of SMS")
    reg_p.add_argument("--captcha", help="CAPTCHA token if required (from https://signalcaptchas.org/registration/generate.html)")
    reg_p.add_argument("--mcc", help="Mobile Country Code")
    reg_p.add_argument("--mnc", help="Mobile Network Code")

    ver_p = sub.add_parser("verify", help="Verify phone number with code received via SMS/voice")
    ver_p.add_argument("--number", required=True, help="E164 phone number, e.g., +15551234567")
    ver_p.add_argument("--session-id", required=True, help="verification session ID")
    ver_p.add_argument("--code", required=True, help="verification code, e.g., 123-456")

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    import logging
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s")

    if args.cmd == "send":
        if not args.message and not args.attach:
            print("send: pass -m and/or --attach", file=sys.stderr)
            return 2
        ok = send_message(
            args.message,
            recipient=args.recipient,
            note_to_self=args.recipient is None,
            account=args.account,
            attachments=args.attach or None,
        )
        return 0 if ok else 1

    if args.cmd == "link":
        from .native import link_device_sync, SignalAPIError
        try:
            link_device_sync(args.name)
            return 0
        except SignalAPIError as e:
            print(f"ERROR: {e.message} (HTTP {e.code})", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1

    if args.cmd == "receive":
        from .native.receive import receive, receive_note_to_self

        fn = receive_note_to_self if args.note_to_self else receive
        # maintain=True: cron-driven receivers are long-lived accounts too;
        # upkeep is internally throttled to the 2-day refresh interval.
        msgs = fn(
            account=args.account,
            idle_timeout=args.timeout,
            max_messages=args.max_messages,
            maintain=True,
        )
        rc = 0
        for m in msgs:
            tag = "note-to-self" if m.note_to_self else (m.source_name or m.source or "?")
            print(f"[{m.timestamp}] {tag}: {m.body if m.body is not None else ''}")
            for pointer in m.attachments:
                if args.save_attachments:
                    from .native.attachments import download_attachment
                    try:
                        dest = download_attachment(pointer, args.save_attachments)
                        print(f"    attachment saved: {dest}")
                    except Exception as e:
                        print(f"    attachment FAILED: {e}", file=sys.stderr)
                        rc = 1
                else:
                    print(f"    attachment: {pointer.get('fileName') or pointer.get('cdnKey')}"
                          f" ({pointer.get('contentType')}, {pointer.get('size')} bytes)"
                          " — use --save-attachments DIR to download")
        return rc

    if args.cmd == "doctor":
        return _doctor(args.account, maintain=args.maintain)

    if args.cmd == "run":
        cfg = load_config(args.config)
        return notify_from_config(cfg, args.active, args.notified,
                                  app_name=args.app_name)

    if args.cmd == "register":
        return _register(args)

    if args.cmd == "verify":
        return _verify(args)

    return 2  # unreachable: subparser is required


def _doctor(account=None, maintain=False) -> int:
    """Report whether a native account is configured and the service reachable."""
    from .native.messaging import find_account_config
    from .native.registration import DEFAULT_BASE_URL, signal_ssl_context

    cfg = find_account_config(account)
    if cfg:
        print(f"account config: {cfg}")
    else:
        print("account config: NOT FOUND (run: signal-notify link)", file=sys.stderr)

    # Confirm the service host resolves and the pinned CA verifies.
    import socket
    import ssl
    import urllib.parse
    host = urllib.parse.urlparse(DEFAULT_BASE_URL).hostname
    try:
        with socket.create_connection((host, 443), timeout=10) as s:
            with signal_ssl_context().wrap_socket(s, server_hostname=host):
                print(f"service: {host} reachable, TLS verified")
    except (OSError, ssl.SSLError) as e:
        print(f"service: {host} UNREACHABLE ({e})", file=sys.stderr)
        return 1

    if cfg and maintain:
        from .native.maintenance import refresh_prekeys
        from .native.registration import SignalAPIError
        try:
            s = refresh_prekeys(cfg)
            print(f"prekeys: server has ec={s['ecCount']} pq={s['pqCount']}; "
                  f"uploaded ec={s['ecUploaded']} pq={s['kyberUploaded']}; "
                  f"rotated signed={s['signedRotated']} lastResort={s['lastResortRotated']}")
        except SignalAPIError as e:
            print(f"prekeys: maintenance FAILED ({e.message}, HTTP {e.code})",
                  file=sys.stderr)
            return 1
    return 0 if cfg else 1


def _register(args) -> int:
    from .native import (
        create_verification_session,
        submit_captcha,
        request_verification_code,
        ProofRequiredError,
        SignalAPIError,
    )
    try:
        if args.captcha:
            print(f"Submitting CAPTCHA for {args.number}...")
            try:
                session = create_verification_session(args.number, mcc=args.mcc, mnc=args.mnc)
                session_id = session["metadata"]["id"]
            except ProofRequiredError as e:
                session_id = e.token
            print(f"Submitting CAPTCHA token for session: {session_id}")
            res = submit_captcha(session_id, args.captcha, mcc=args.mcc, mnc=args.mnc)
        else:
            print(f"Starting registration session for {args.number}...")
            res = create_verification_session(args.number, mcc=args.mcc, mnc=args.mnc)

        metadata = res["metadata"]
        session_id = metadata["id"]

        if metadata.get("allowedToRequestCode"):
            transport = "voice" if args.voice else "sms"
            print(f"Requesting verification code via {transport}...")
            request_verification_code(session_id, transport=transport)
            print("✓ Verification code requested successfully!")
            print(f"Session ID: {session_id}")
            print("Run verify command next when you receive the code:")
            print(f'  signal-notify verify --session-id "{session_id}" --code "XXX-XXX"')
        else:
            if "captcha" in metadata.get("requestedInformation", []):
                print("⚠️ CAPTCHA required. Please solve the CAPTCHA at:")
                print("  https://signalcaptchas.org/registration/generate.html")
                print("Then rerun the command with the --captcha parameter:")
                print(f'  signal-notify register --number "{args.number}" --captcha "signalcaptcha://..."')
            else:
                print(f"Session status: {res}")
        return 0
    except ProofRequiredError:
        print("⚠️ CAPTCHA required. Please solve the CAPTCHA at:")
        print("  https://signalcaptchas.org/registration/generate.html")
        print("Then rerun the command with the --captcha parameter:")
        print(f'  signal-notify register --number "{args.number}" --captcha "signalcaptcha://..."')
        return 1
    except SignalAPIError as e:
        print(f"ERROR: {e.message} (HTTP {e.code})", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def _verify(args) -> int:
    from .native import (
        submit_verification_code,
        generate_registration_payload,
        register_account,
        save_account_config,
        SignalAPIError,
    )
    import base64
    import os
    try:
        print(f"Verifying code for session {args.session_id}...")
        res = submit_verification_code(args.session_id, args.code)
        metadata = res.get("metadata", {})
        if metadata.get("verified"):
            print("✓ Account verified successfully!")
            print("Finalizing registration on Signal servers...")

            raw_pw = os.urandom(18)
            password = base64.b64encode(raw_pw).decode("utf-8")

            payload, keys = generate_registration_payload(args.session_id, voice=False)
            reg_res = register_account(payload, number=args.number, password=password)

            aci = reg_res.get("uuid")
            pni = reg_res.get("pni")

            aci_priv = base64.b64decode(keys["aci_priv"] + "==")
            aci_pub = base64.b64decode(keys["aci_pub"] + "==")
            pni_priv = base64.b64decode(keys["pni_priv"] + "==")
            pni_pub = base64.b64decode(keys["pni_pub"] + "==")

            from .config import get_data_dir
            data_dir = get_data_dir()
            print(f"Saving configuration to {data_dir}...")
            config_file = save_account_config(
                data_dir=data_dir, number=args.number, aci=aci, pni=pni,
                password=password, aci_identity_pub=aci_pub, aci_identity_priv=aci_priv,
                pni_identity_pub=pni_pub, pni_identity_priv=pni_priv,
                profile_key=None, account_entropy_pool=None,
                media_root_backup_key=None, device_id=1)
            print(f"✓ Saved configuration file: {config_file}")
        else:
            print(f"Verification call succeeded, but account is not verified yet. State: {res}")
        return 0
    except SignalAPIError as e:
        print(f"ERROR: {e.message} (HTTP {e.code})", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
