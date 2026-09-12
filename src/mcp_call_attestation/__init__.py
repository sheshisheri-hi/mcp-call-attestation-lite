"""MCP call-attestation lite: pin the menu, sign the call, number the receipts.

Educational sample inspired by draft SEP-2787, SEP-3140, and SEP-3004.
Not official compliance. HMAC demo key only. No WebAuthn. No network.
"""

from .attestation import args_digest, create_envelope, verify_envelope, verify_mac
from .audit_chain import AuditChain
from .gate import ServerGate
from .interceptor import ClientInterceptor
from .models import (
    AttestationEnvelope,
    AuditEvent,
    GateDecision,
    HostPolicy,
    PinCheck,
    ServerPolicy,
    ToolAdvertisement,
    ToolCall,
    ToolPin,
    honest_catalog,
    rugpull_catalog,
)
from .pin import ToolListPin, tools_content_hash

__all__ = [
    "AttestationEnvelope",
    "AuditChain",
    "AuditEvent",
    "ClientInterceptor",
    "GateDecision",
    "HostPolicy",
    "PinCheck",
    "ServerGate",
    "ServerPolicy",
    "ToolAdvertisement",
    "ToolCall",
    "ToolListPin",
    "ToolPin",
    "args_digest",
    "create_envelope",
    "honest_catalog",
    "rugpull_catalog",
    "tools_content_hash",
    "verify_envelope",
    "verify_mac",
]

__version__ = "0.1.0"
