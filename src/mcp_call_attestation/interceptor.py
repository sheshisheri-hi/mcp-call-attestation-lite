"""MCP host/client interceptor: stamp the pin + attestation envelope.

The interceptor is a mutator, not a gate. It never allow/denies a tool.
It can refuse to mint a shipping label when the wax seal already broke.
The MCP server gate is the only place a call is admitted.
"""

from __future__ import annotations

from typing import Any, Mapping

from .attestation import create_envelope
from .models import (
    DEFAULT_ATTESTATION_SECRET,
    HostPolicy,
    PinCheck,
    ToolCall,
    ToolPin,
)
from .pin import ToolListPin


class ClientInterceptor:
    """Stamps request ``_meta`` on the MCP host/client side."""

    def __init__(
        self,
        *,
        pin: ToolListPin | None = None,
        policy: HostPolicy | None = None,
        secret: str = DEFAULT_ATTESTATION_SECRET,
    ) -> None:
        self.pin = pin or ToolListPin()
        self.policy = policy or HostPolicy()
        self.secret = secret

    def pin_tools(self, tools, *, now=None) -> ToolPin:
        """Wax-seal the advertised menu at connect / first ``tools/list``."""
        return self.pin.store(tools, now=now)

    def check_pin(self, tools) -> PinCheck:
        """Host-side pin check. Call this before ``tools/call``."""
        return self.pin.verify(tools)

    def intercept(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        intent: str = "",
        request_id: str | int = 1,
        now=None,
        nonce: str | None = None,
        stamp_attestation: bool = True,
    ) -> ToolCall:
        """Return a ``tools/call`` with pin + (usually) attestation ``_meta``."""
        meta: dict[str, Any] = {}
        stored = self.pin.stored
        if stored is not None:
            meta["toolListPin"] = stored.to_wire()

        if stamp_attestation and self.policy.may_attest(tool_name):
            envelope = create_envelope(
                tool_name=tool_name,
                arguments=arguments,
                agent_id=self.policy.agent_id,
                issuer=self.policy.issuer,
                intent=intent,
                secret=self.secret,
                ttl_seconds=self.policy.attestation_ttl_seconds,
                nonce=nonce,
                now=now,
            )
            meta["toolCallAttestation"] = envelope.to_wire()

        return ToolCall(
            name=tool_name,
            arguments=dict(arguments),
            meta=meta,
            request_id=request_id,
        )
