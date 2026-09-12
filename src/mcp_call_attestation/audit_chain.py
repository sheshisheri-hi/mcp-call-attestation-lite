"""Thin SEP-3004-style append-only hash chain.

Each allowed ``tools/call`` appends one numbered receipt:
``prevDigest`` → ``thisDigest``. Editing an earlier event breaks every
later link. This is 2–3 chained events for the demo — not the full
SEP-3004 known-answer vector suite.
"""

from __future__ import annotations

from typing import Any, Mapping

from .models import (
    GENESIS_DIGEST,
    AuditEvent,
    canonical_json,
    digest_uri,
    utc_now,
)


def event_digest(payload: Mapping[str, Any]) -> str:
    """SHA-256 over the canonical event body (no ``thisDigest`` field)."""
    body = {k: v for k, v in payload.items() if k != "thisDigest"}
    return digest_uri(canonical_json(body))


class AuditChain:
    """Append-only hash-linked receipt book kept by the MCP server."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    @property
    def head(self) -> str:
        if not self._events:
            return GENESIS_DIGEST
        return self._events[-1].this_digest

    def append(
        self,
        *,
        tool_name: str,
        agent_id: str,
        args_digest: str,
        pin_hash: str,
        allowed: bool = True,
        now=None,
    ) -> AuditEvent:
        clock = now or utc_now()
        stamped = clock.isoformat().replace("+00:00", "Z") if hasattr(clock, "isoformat") else str(clock)
        unsigned = AuditEvent(
            seq=len(self._events) + 1,
            tool_name=tool_name,
            agent_id=agent_id,
            args_digest=args_digest,
            pin_hash=pin_hash,
            prev_digest=self.head,
            this_digest="",
            occurred_at=stamped,
            allowed=allowed,
        )
        digest = event_digest(unsigned.unsigned_payload())
        event = AuditEvent(**{**unsigned.__dict__, "this_digest": digest})
        self._events.append(event)
        return event

    def verify(self) -> bool:
        """Recompute every link. True only if the receipt book is intact."""
        expected_prev = GENESIS_DIGEST
        for event in self._events:
            if event.prev_digest != expected_prev:
                return False
            if event_digest(event.unsigned_payload()) != event.this_digest:
                return False
            expected_prev = event.this_digest
        return True
