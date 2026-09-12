"""SEP-3140-lite tool-list pin: wax seal on the advertised menu.

The MCP host/client computes ``contentHash`` over ``tools/list`` at connect
(or first list) and stores it. Before a ``tools/call``, both the host and
the MCP server recompute the hash over the tools just advertised. Any
schema or description swap is a rug-pull: the check fails closed.

This is not official SEP-3140 compliance. No signatures. No WebAuthn.
"""

from __future__ import annotations

from typing import Mapping, Sequence

from .models import (
    PinCheck,
    Reason,
    ToolAdvertisement,
    ToolPin,
    advertised_from,
    canonical_json,
    digest_uri,
    utc_now,
)


def tools_content_hash(tools: Sequence[ToolAdvertisement | Mapping[str, object]]) -> str:
    """SHA-256 over the canonical advertised surface (name, description, schema)."""
    ads = advertised_from(tools)
    projection = [tool.projection() for tool in sorted(ads, key=lambda t: t.name)]
    return digest_uri(canonical_json(projection))


class ToolListPin:
    """Store one contentHash and verify later advertised tools against it."""

    def __init__(self) -> None:
        self._pin: ToolPin | None = None

    @property
    def stored(self) -> ToolPin | None:
        return self._pin

    @property
    def content_hash(self) -> str | None:
        return self._pin.content_hash if self._pin else None

    def load(self, pin: ToolPin) -> ToolPin:
        """Replay a pin the MCP host/client already sealed (server-side check)."""
        self._pin = pin
        return pin

    def store(
        self,
        tools: Sequence[ToolAdvertisement | Mapping[str, object]],
        *,
        now=None,
    ) -> ToolPin:
        """Pin the tool menu at connect / first ``tools/list``."""
        ads = advertised_from(tools)
        clock = now or utc_now()
        stamped = clock.isoformat().replace("+00:00", "Z") if hasattr(clock, "isoformat") else str(clock)
        pin = ToolPin(
            content_hash=tools_content_hash(ads),
            tool_names=tuple(tool.name for tool in ads),
            pinned_at=stamped,
        )
        return self.load(pin)

    def verify(
        self,
        tools: Sequence[ToolAdvertisement | Mapping[str, object]],
        *,
        expected_hash: str | None = None,
    ) -> PinCheck:
        """Fail closed if the advertised menu drifted from the wax seal."""
        observed = tools_content_hash(tools)
        pinned = expected_hash or (self._pin.content_hash if self._pin else None)
        if pinned is None:
            reason = Reason(
                code="missing_pin",
                message=(
                    "MCP host/client has no stored tool-list contentHash. "
                    "Pin at connect / first tools/list. Fail closed."
                ),
                field="params._meta.toolListPin.contentHash",
            )
            return PinCheck(ok=False, pinned_hash="", observed_hash=observed, reasons=(reason,))
        if pinned != observed:
            reason = Reason(
                code="pin_mismatch",
                message=(
                    "Advertised tools drifted from the pinned contentHash. "
                    "Schema or description swap is a rug-pull. Fail closed."
                ),
                field="params._meta.toolListPin.contentHash",
                detail=f"pinned={pinned} observed={observed}",
            )
            return PinCheck(
                ok=False,
                pinned_hash=pinned,
                observed_hash=observed,
                reasons=(reason,),
            )
        return PinCheck(
            ok=True,
            pinned_hash=pinned,
            observed_hash=observed,
            reasons=(
                Reason(
                    code="pin_ok",
                    message="Advertised tools still match the pinned contentHash.",
                    field="params._meta.toolListPin.contentHash",
                ),
            ),
        )
