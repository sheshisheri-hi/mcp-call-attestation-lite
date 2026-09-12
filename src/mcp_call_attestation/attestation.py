"""SEP-2787-lite attestation envelope: signed shipping label on the call.

The MCP host/client interceptor mints an HMAC envelope in request ``_meta``
that binds agent id + tool name + args digest. The MCP server verifies it
before the tool runs. Tampered MAC or substituted arguments fail closed.

HMAC-SHA256 with a shared demo secret is **not** production crypto.
Not WebAuthn. Not a full SEP-2787 vector suite.
"""

from __future__ import annotations

import hmac
from datetime import timedelta
from typing import Any, Mapping
from uuid import uuid4

from .models import (
    DEFAULT_ATTESTATION_SECRET,
    AttestationEnvelope,
    Reason,
    canonical_json,
    digest_uri,
    parse_utc,
    utc_now,
)


def args_digest(arguments: Mapping[str, Any] | None) -> str:
    """SHA-256 over canonical tool arguments. This is the args commitment."""
    return digest_uri(canonical_json(dict(arguments or {})))


def sign_envelope(envelope: AttestationEnvelope, secret: str) -> AttestationEnvelope:
    """Return a copy with ``mac`` set. Demo HMAC only."""
    digest = hmac.new(
        secret.encode("utf-8"),
        canonical_json(envelope.unsigned_payload()),
        "sha256",
    )
    return AttestationEnvelope(**{**envelope.__dict__, "mac": digest.hexdigest()})


def create_envelope(
    *,
    tool_name: str,
    arguments: Mapping[str, Any],
    agent_id: str,
    issuer: str,
    intent: str = "",
    secret: str = DEFAULT_ATTESTATION_SECRET,
    ttl_seconds: int = 300,
    nonce: str | None = None,
    now=None,
) -> AttestationEnvelope:
    """Mint a SEP-2787-lite envelope. Called by the MCP host/client interceptor."""
    clock = now or utc_now()
    issued = clock if getattr(clock, "tzinfo", None) else clock
    expires = issued + timedelta(seconds=ttl_seconds)
    unsigned = AttestationEnvelope(
        iss=issuer,
        sub=agent_id,
        tool_name=tool_name,
        args_digest=args_digest(arguments),
        intent=intent,
        issued_at=issued.isoformat().replace("+00:00", "Z"),
        expires_at=expires.isoformat().replace("+00:00", "Z"),
        nonce=nonce or uuid4().hex,
    )
    return sign_envelope(unsigned, secret)


def verify_mac(envelope: AttestationEnvelope, secret: str) -> bool:
    if not envelope.mac:
        return False
    expected = sign_envelope(envelope, secret).mac
    return hmac.compare_digest(expected, envelope.mac)


def verify_envelope(
    envelope: AttestationEnvelope | None,
    *,
    secret: str,
    tool_name: str,
    arguments: Mapping[str, Any],
    trusted_issuers: frozenset[str],
    trusted_agents: frozenset[str],
    now=None,
) -> list[Reason]:
    """Return findings. Empty list means the shipping label checks out."""
    if envelope is None:
        return [
            Reason(
                code="missing_attestation",
                message=(
                    "tools/call is missing a SEP-2787-lite attestation envelope. "
                    "The MCP host/client must stamp _meta.toolCallAttestation."
                ),
                field="params._meta.toolCallAttestation",
            )
        ]

    findings: list[Reason] = []
    if envelope.alg != "HS256":
        findings.append(
            Reason(
                code="invalid_attestation",
                message=f"Unsupported attestation alg '{envelope.alg}'. Demo only accepts HS256.",
                field="params._meta.toolCallAttestation.alg",
                detail=envelope.alg,
            )
        )
    if not verify_mac(envelope, secret):
        findings.append(
            Reason(
                code="invalid_attestation",
                message="Attestation MAC did not verify. Tampered shipping label.",
                field="params._meta.toolCallAttestation.mac",
            )
        )
    if envelope.iss not in trusted_issuers:
        findings.append(
            Reason(
                code="untrusted_issuer",
                message=f"Attestation issuer '{envelope.iss}' is not trusted by this MCP server.",
                field="params._meta.toolCallAttestation.iss",
                detail=envelope.iss,
            )
        )
    if envelope.sub not in trusted_agents:
        findings.append(
            Reason(
                code="untrusted_agent",
                message=f"Attestation agent '{envelope.sub}' is not the pinned agent id.",
                field="params._meta.toolCallAttestation.sub",
                detail=envelope.sub,
            )
        )
    if envelope.tool_name != tool_name:
        findings.append(
            Reason(
                code="tool_mismatch",
                message=(
                    f"Attestation is bound to tool '{envelope.tool_name}', not '{tool_name}'."
                ),
                field="params._meta.toolCallAttestation.toolName",
            )
        )
    observed_args = args_digest(arguments)
    if envelope.args_digest != observed_args:
        findings.append(
            Reason(
                code="args_mismatch",
                message=(
                    "Argument substitution: call arguments no longer match the "
                    "attested argsDigest. Fail closed."
                ),
                field="params.arguments",
                detail=f"attested={envelope.args_digest} observed={observed_args}",
            )
        )
    clock = now or utc_now()
    try:
        expires = parse_utc(envelope.expires_at)
        if clock > expires:
            findings.append(
                Reason(
                    code="expired_attestation",
                    message=f"Attestation expired at {envelope.expires_at}.",
                    field="params._meta.toolCallAttestation.expiresAt",
                )
            )
    except (TypeError, ValueError):
        findings.append(
            Reason(
                code="invalid_attestation",
                message="Attestation expiresAt is not a usable timestamp.",
                field="params._meta.toolCallAttestation.expiresAt",
            )
        )
    return findings
