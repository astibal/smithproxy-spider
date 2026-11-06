# TLS API follow-up backlog

Recorded 2026-11-06 at the user's request. These are intended follow-ups to
assess and implement where practical, not promises of current support.
First complete the shared native API and move the mitmproxy adapter onto it.
No new transport behavior is part of that first migration.

## Shared observations and developer experience

- [ ] Structured ClientHello: SNI, offered ALPN, cipher IDs and extensions.
- [ ] TLS outcome snapshot: protocol, side, attempt, version, cipher and ALPN.
- [ ] Public peer certificate chains on both legs, including empty client chains.
- [ ] Certificate accessors: subject, issuer, SAN, validity, certificate/SPKI fingerprints.
- [ ] Verification result and meaningful native failure categories.
- [ ] Full versus resumed handshake indication.
- [ ] STARTTLS attempt identity and plaintext-to-TLS continuity.
- [ ] Native handshake timing distinct from worker delivery/observation timing.
- [ ] Explicit per-event and per-transport editing capabilities.
- [ ] Original, requested and effective values for diagnostics.
- [ ] Deployment attribution for edits and termination reasons.
- [ ] ClientHello fingerprinting with an explicitly selected format.
- [ ] Consistent TCP TLS / QUIC view with documented capability differences.
- [ ] Examples, editor help and contract tests for every public capability.

## Meta editing

- [ ] Expose existing upstream SNI and ALPN edits through native drafts.
- [ ] Expose existing legacy cipher expression controls.
- [ ] Separate TCP TLS 1.3 cipher-suite selection.
- [ ] Minimum/maximum TLS version per session.
- [ ] Key-exchange group offers and order.
- [ ] Signature-algorithm offers.
- [ ] Upstream client identity selection: certificate, key and chain.
- [ ] Explicit per-session disable-resumption control.
- [ ] Selection of a stored trust bundle.
- [ ] Additional certificate/SPKI pin constraint.
- [ ] Explicit termination with an attributable reason.
- [ ] ClientHello bypass through existing supported native path.
- [ ] Atomic validated commit shared by native scripts and addon adapter.

Identity and negotiation changes must account for session-cache partitioning,
existing profile precedence, TLS 1.2/1.3 and transport capabilities. Prefer
stored identity references for mTLS; do not implicitly export private keys.

## Separate investigations, not low-impact promises

- [ ] QUIC downstream start / ClientHello interception at a truthful boundary.
- [ ] Richer ClientHello-shaped metadata mapped to supported OpenSSL options.
- [ ] Assess any future record rewrite/translate independently; do not imply
  arbitrary ClientHello serialization through current meta editing.

Live SSL exports, forced handshake scheduling and remote callbacks from inside
OpenSSL remain outside the current design. Feature differentiation is a goal,
not an unverified assertion that mitmproxy lacks each listed capability.
