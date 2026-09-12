"""MCP server gate: verify pin + attestation; append a chain link on allow.

The gate is the only allow/deny point. A broken wax seal (pin mismatch)
or a torn shipping label (bad MAC / swapped args) fails closed. Allowed
calls get a thin SEP-3004-lite receipt in result ``_meta``.
"""

from __future__ import annotations

from typing import Any, Mapping

from .attestation import args_digest, verify_envelope
from .audit_chain import AuditChain
from .models import (
    AuditEvent,
    GateDecision,
    Reason,
    ServerPolicy,
    ToolAdvertisement,
    ToolCall,
    advertised_from,
    honest_catalog,
)
from .pin import ToolListPin, tools_content_hash

INVOICES: dict[str, dict[str, str]] = {
    "INV-1001": {"amount": "1200.00", "status": "open"},
    "INV-1002": {"amount": "85.50", "status": "paid"},
}


def execute_mock(name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """CPU-only mock. No network."""
    if name == "lookup_invoice":
        invoice_id = str(arguments.get("invoiceId") or "")
        row = INVOICES.get(invoice_id, {"amount": "0.00", "status": "unknown"})
        return {
            "ok": True,
            "tool": name,
            "invoice": {"id": invoice_id, **row},
            "network": False,
        }
    if name == "export_report":
        return {
            "ok": True,
            "tool": name,
            "reportId": "rpt-local-1",
            "period": str(arguments.get("period") or ""),
            "network": False,
        }
    return {"ok": True, "tool": name, "network": False}


class ServerGate:
    """Evaluate a stamped ``tools/call`` on the MCP server."""

    def __init__(
        self,
        *,
        advertised: tuple[ToolAdvertisement, ...] | None = None,
        policy: ServerPolicy | None = None,
        chain: AuditChain | None = None,
    ) -> None:
        self.advertised = advertised_from(advertised or honest_catalog())
        self.policy = policy or ServerPolicy()
        self.chain = chain or AuditChain()

    def rugpull(self, swapped: tuple[ToolAdvertisement, ...] | None = None) -> None:
        """Swap the advertised menu mid-session. Pin check must fail closed."""
        from .models import rugpull_catalog

        self.advertised = advertised_from(swapped or rugpull_catalog())

    def restore(self, tools: tuple[ToolAdvertisement, ...] | None = None) -> None:
        self.advertised = advertised_from(tools or honest_catalog())

    def evaluate(self, call: ToolCall | dict[str, Any], *, now=None) -> GateDecision:
        request = call if isinstance(call, ToolCall) else ToolCall.from_rpc(call)
        reasons: list[Reason] = []

        known = {tool.name for tool in self.advertised}
        if request.name not in known:
            reasons.append(
                Reason(
                    code="unknown_tool",
                    message=f"MCP server does not expose tool '{request.name}'.",
                    field="params.name",
                )
            )
            return self._deny(request, reasons)

        pin_check = None
        if self.policy.require_pin:
            host_pin = ToolListPin()
            if request.pin() is not None:
                host_pin.load(request.pin())
            pin_check = host_pin.verify(self.advertised)
            if not pin_check.ok:
                reasons.extend(pin_check.reasons)

        envelope = request.attestation()
        if self.policy.require_attestation:
            reasons.extend(
                verify_envelope(
                    envelope,
                    secret=self.policy.attestation_secret,
                    tool_name=request.name,
                    arguments=request.arguments,
                    trusted_issuers=self.policy.trusted_issuers,
                    trusted_agents=self.policy.trusted_agents,
                    now=now,
                )
            )

        if reasons:
            return self._deny(request, reasons, pin_check=pin_check)

        result = execute_mock(request.name, request.arguments)
        event = self.chain.append(
            tool_name=request.name,
            agent_id=envelope.sub if envelope else "",
            args_digest=args_digest(request.arguments),
            pin_hash=request.pin().content_hash if request.pin() else tools_content_hash(self.advertised),
            allowed=True,
            now=now,
        )
        result = {
            **result,
            "_meta": {"auditEvent": event.to_wire()},
        }
        allow_reasons = (
            Reason(
                code="allowed",
                message=(
                    f"MCP server allowed tools/call '{request.name}'. "
                    f"Pin matched. Attestation verified. Chain seq={event.seq}."
                ),
            ),
        )
        return GateDecision(
            allowed=True,
            tool_name=request.name,
            reasons=allow_reasons,
            result=result,
            audit_event=event,
            pin_check=pin_check,
        )

    def _deny(
        self,
        request: ToolCall,
        reasons: list[Reason],
        *,
        pin_check=None,
    ) -> GateDecision:
        packed = tuple(reasons)
        denial = {
            "jsonrpc": "2.0",
            "id": request.request_id,
            "error": {
                "code": -32010,
                "message": f"MCP server denied tools/call '{request.name}'.",
                "data": {
                    "denied": True,
                    "toolName": request.name,
                    "reasons": [r.to_dict() for r in packed],
                },
            },
        }
        return GateDecision(
            allowed=False,
            tool_name=request.name,
            reasons=packed,
            denial=denial,
            pin_check=pin_check,
        )


def format_decision(title: str, decision: GateDecision) -> str:
    verdict = "ALLOW" if decision.allowed else "DENY"
    lines = [
        f"  tool           {decision.tool_name}",
        f"  verdict        {verdict}",
        f"  reasons        {', '.join(r.code for r in decision.reasons)}",
    ]
    if decision.audit_event is not None:
        event: AuditEvent = decision.audit_event
        lines.extend(
            [
                f"  seq            {event.seq}",
                f"  prevDigest     {event.prev_digest}",
                f"  thisDigest     {event.this_digest}",
            ]
        )
    return "\n".join([title, *lines])
