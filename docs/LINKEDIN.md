# LinkedIn assets

Quick links for posting:

- **Code:** https://github.com/sheshisheri-hi/mcp-call-attestation-lite
- **One-pager:** [`docs/one-pager.html`](one-pager.html)
- Related (door key, not this sample): https://github.com/sheshisheri-hi/mcp-meta-gate-showcase

---

# LinkedIn post (copy-paste ready)

Use this as a single post, or split the **Carousel** section into slides.

---

## Post

https://github.com/sheshisheri-hi/mcp-call-attestation-lite

Pin ≈ wax seal on the tool menu.
Attestation envelope ≈ signed shipping label on the call.
Hash chain ≈ numbered receipts you cannot rewrite later.

Approved tools ≠ what the model just saw.

MCP host/client pins `tools/list` at connect.
Mid-session rug-pull swaps the schema. Seal breaks. Fail closed.

A real `tools/call` gets a signed label: agent id + tool name + args digest.
MCP server checks the seal and the label. Then it writes a receipt.

Sibling meta-gate = door key.
This sample = seal + label + receipt book.

Weekend sample. CPU only. HMAC demo key. No network. No WebAuthn.
Drafts (SEP-2787, SEP-3140, SEP-3004) are inspiration. Not official compliance.

https://github.com/sheshisheri-hi/mcp-call-attestation-lite

#AISecurity #MCP #AgentSecurity #LLMOps

---

## Carousel (6 slides — paste one slide per card)

**Slide 1 — Hook**
Approved tools ≠ what the model just saw.

Pin ≈ wax seal on the tool menu.
https://github.com/sheshisheri-hi/mcp-call-attestation-lite

**Slide 2 — Three objects**
Seal = pinned `contentHash` (SEP-3140-lite).
Label = HMAC envelope on the call (SEP-2787-lite).
Receipt book = `prevDigest` → `thisDigest` (SEP-3004-lite).

**Slide 3 — Who does what**
MCP host/client interceptor stamps `_meta`.
MCP server gate verifies pin + attestation.

This is not that.

**Slide 4 — Rug-pull**
Connect: pin the menu. Seal intact.
Mid-session: description + schema swap.

Seal breaks. Fail closed.

**Slide 5 — Good call / bad label**
Good call → ALLOW + chained receipts.
Torn MAC or swapped args → DENY. No new receipt.

**Slide 6 — CTA**
Seal the menu.
Label the call.
Number the receipts.

Sibling = door key. This = seal + label + receipt book.
https://github.com/sheshisheri-hi/mcp-call-attestation-lite

---

## Comment you can pin under the post

Educational sample. SEP-2787 / SEP-3140 / SEP-3004 are drafts — not a conformance claim. HMAC demo key. Not production crypto.

Code: https://github.com/sheshisheri-hi/mcp-call-attestation-lite
Related (receipt ≠ door key): https://github.com/sheshisheri-hi/mcp-meta-gate-showcase
