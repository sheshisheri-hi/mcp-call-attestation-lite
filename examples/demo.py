#!/usr/bin/env python3
"""Print the pin → rug-pull deny → good call + chain → bad MAC walkthrough.

    PYTHONPATH=src python examples/demo.py
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mcp_call_attestation import (  # noqa: E402
    ClientInterceptor,
    ServerGate,
    honest_catalog,
    rugpull_catalog,
)
from mcp_call_attestation.gate import format_decision  # noqa: E402

WIDTH = 72
FROZEN = datetime(2026, 9, 12, 20, 0, tzinfo=timezone.utc)
INTENT = "Look up invoice INV-1001 for the weekly close."


def _box(title: str) -> None:
    print()
    print("=" * WIDTH)
    print(f" {title}")
    print("=" * WIDTH)


def _kv(label: str, value: str) -> None:
    print(f"  {label:<14} {value}")


def run_attestation_demo() -> dict:
    """Drive the five-beat story. Used by the demo script and tests."""
    host = ClientInterceptor()
    gate = ServerGate()
    catalog = honest_catalog()

    pin = host.pin_tools(catalog, now=FROZEN)
    pin_ok = host.check_pin(catalog)

    rug_check = host.check_pin(rugpull_catalog())
    gate.rugpull()
    rug_call = host.intercept(
        "lookup_invoice",
        {"invoiceId": "INV-1001"},
        intent=INTENT,
        request_id=1,
        now=FROZEN,
        nonce="demo-rug-1",
    )
    rug_decision = gate.evaluate(rug_call, now=FROZEN)
    gate.restore()

    good_invoice = host.intercept(
        "lookup_invoice",
        {"invoiceId": "INV-1001"},
        intent=INTENT,
        request_id=2,
        now=FROZEN,
        nonce="demo-good-1",
    )
    good_invoice_decision = gate.evaluate(good_invoice, now=FROZEN)

    good_invoice_2 = host.intercept(
        "lookup_invoice",
        {"invoiceId": "INV-1002"},
        intent="Look up invoice INV-1002.",
        request_id=3,
        now=FROZEN,
        nonce="demo-good-2",
    )
    good_invoice_2_decision = gate.evaluate(good_invoice_2, now=FROZEN)

    good_export = host.intercept(
        "export_report",
        {"period": "2026-W37"},
        intent="Export the local weekly invoice report.",
        request_id=4,
        now=FROZEN,
        nonce="demo-good-3",
    )
    good_export_decision = gate.evaluate(good_export, now=FROZEN)

    bad_mac_call = host.intercept(
        "lookup_invoice",
        {"invoiceId": "INV-1001"},
        intent=INTENT,
        request_id=5,
        now=FROZEN,
        nonce="demo-bad-mac",
    )
    bad_mac_call.meta["toolCallAttestation"]["mac"] = "deadbeef"
    bad_mac_decision = gate.evaluate(bad_mac_call, now=FROZEN)

    swapped_args = host.intercept(
        "lookup_invoice",
        {"invoiceId": "INV-1001"},
        intent=INTENT,
        request_id=6,
        now=FROZEN,
        nonce="demo-bad-args",
    )
    swapped_args.arguments = {"invoiceId": "INV-9999"}
    swapped_args_decision = gate.evaluate(swapped_args, now=FROZEN)

    chain_ok = gate.chain.verify()
    ok = (
        pin_ok.ok
        and not rug_check.ok
        and not rug_decision.allowed
        and good_invoice_decision.allowed
        and good_invoice_2_decision.allowed
        and good_export_decision.allowed
        and not bad_mac_decision.allowed
        and not swapped_args_decision.allowed
        and chain_ok
        and len(gate.chain.events) == 3
    )
    return {
        "ok": ok,
        "pin": pin,
        "pinOk": pin_ok,
        "rugCheck": rug_check,
        "rugCall": rug_call,
        "rug": rug_decision,
        "goodInvoiceCall": good_invoice,
        "goodInvoice": good_invoice_decision,
        "goodInvoice2": good_invoice_2_decision,
        "goodExport": good_export_decision,
        "badMac": bad_mac_decision,
        "swappedArgs": swapped_args_decision,
        "chain": gate.chain.events,
        "chainOk": chain_ok,
    }


def main() -> int:
    print("MCP call-attestation lite — prove which call ran")
    print("CPU only. HMAC demo key. No WebAuthn. No SEP-3004 KAT suite. No network.")
    print()
    print("  Pin            = wax seal on the tool menu     (SEP-3140-lite)")
    print("  Attestation    = signed shipping label         (SEP-2787-lite)")
    print("  Hash chain     = numbered receipts             (SEP-3004-lite)")
    print()
    print("  Sibling meta-gate = door key. This sample = seal + label + receipt book.")
    print()
    print("  MCP host/client interceptor stamps _meta")
    print("  MCP server gate verifies pin + attestation, then appends a chain link")
    print()
    print("  tools/list --> [ pin contentHash ]")
    print("  tools/call --> [ interceptor ] --stamp--> [ gate ] --allow--> mock tool")
    print("                                              |")
    print("                                              +-- deny --> fail closed")

    run = run_attestation_demo()

    _box("1 / PIN AT CONNECT — first tools/list")
    _kv("contentHash", run["pin"].content_hash)
    _kv("tools", ", ".join(run["pin"].tool_names))
    _kv("verdict", "PIN OK" if run["pinOk"].ok else "PIN FAIL")

    _box("2 / RUG-PULL — schema/description swap (host pin + MCP server)")
    _kv("swapped", "lookup_invoice description + inputSchema")
    _kv("pinned", run["rugCheck"].pinned_hash)
    _kv("observed", run["rugCheck"].observed_hash)
    _kv("hostPin", "DENY" if not run["rugCheck"].ok else "OK")
    print(format_decision("  MCP server gate", run["rug"]))
    if run["rug"].denial:
        print("  structured denial")
        print(json.dumps(run["rug"].denial, indent=2))

    _box("3 / GOOD CALL — lookup_invoice INV-1001 (ALLOW + receipt 1)")
    print(json.dumps(run["goodInvoiceCall"].to_rpc(), indent=2))
    print()
    print(format_decision("  MCP server gate", run["goodInvoice"]))
    if run["goodInvoice"].result:
        print("  result")
        print(json.dumps(run["goodInvoice"].result, indent=2))

    _box("4 / GOOD CALLS — chain receipts 2 and 3")
    print(format_decision("  lookup_invoice INV-1002", run["goodInvoice2"]))
    print()
    print(format_decision("  export_report 2026-W37", run["goodExport"]))
    print()
    print("  chain")
    for event in run["chain"]:
        print(
            f"    seq={event.seq}  tool={event.tool_name:<16}  "
            f"prev={event.prev_digest[7:15]}…  this={event.this_digest[7:15]}…"
        )
    _kv("chainOk", "yes" if run["chainOk"] else "NO")

    _box("5 / BAD MAC — tampered shipping label (DENY)")
    print(format_decision("  MCP server gate", run["badMac"]))
    print()
    print(format_decision("  arg substitution", run["swappedArgs"]))

    print()
    print("-" * WIDTH)
    if run["ok"]:
        print(" Demo done. Pin OK. Rug-pull DENY. Three chained ALLOW receipts.")
        print(" Bad MAC DENY. Swapped args DENY. Seal + label + receipt book.")
        return 0
    print(" Demo failed the success contract.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
