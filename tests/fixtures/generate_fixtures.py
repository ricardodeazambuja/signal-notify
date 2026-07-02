#!/usr/bin/env python3
"""(Re)generate the frozen receive-path fixture.

⚠️  The fixture is a REGRESSION ANCHOR: it was produced by the implementation
that is live-proven against real phones (send + receive, July 2026).
Regenerating it with a changed implementation defeats its purpose — only do
so if the wire format legitimately changed AND the new format has been
re-proven live (see docs/native_caveats.md #9: a local round-trip proves
nothing).

All keys in here are synthetic throwaways generated on the spot — never a
real account (the repo history was once scrubbed for exactly this).

Run from the repo root:  python tests/fixtures/generate_fixtures.py
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))          # tests/ helpers
sys.path.insert(0, str(HERE.parent.parent / "src"))

from test_native_receive import (ACI, _envelope, _linked_account,
                                 _note_to_self_prekey_content)
from signalnotify.native import receive

BODY = "frozen fixture reply 📌"
TS = 1751300000123


def main():
    cfg_path, bundle = _linked_account(HERE)
    content = _note_to_self_prekey_content(bundle, BODY, TS)
    envelope = _envelope(receive.TYPE_PREKEY, ACI, 1, content, ts=TS)

    (HERE / "note_to_self_prekey_envelope.bin").write_bytes(envelope)
    # The account dir helpers wrote accounts.json + a random-named config;
    # normalize to a stable filename and drop the random original.
    cfg = json.loads(Path(cfg_path).read_text())
    (HERE / "account_config.json").write_text(json.dumps(cfg, indent=2))
    Path(cfg_path).unlink()
    (HERE / "accounts.json").unlink(missing_ok=True)
    (HERE / "meta.json").write_text(json.dumps(
        {"body": BODY, "timestamp": TS, "aci": ACI,
         "note": "PREKEY Note-to-Self sync envelope; decrypts via the full "
                 "PQXDH+SPQR+DoubleRatchet receive stack"}, indent=2))
    print("fixture regenerated — are you SURE that was intended? (see header)")


if __name__ == "__main__":
    main()
