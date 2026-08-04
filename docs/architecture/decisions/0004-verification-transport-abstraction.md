# ADR-0004: Pluggable verification transport abstraction

- **Status**: accepted
- **Date**: 2026-04-22
- **Author**: go-signal team

## Context

Phone-number verification is the first step of account registration. Java Signal-Server delegates this to an internal `registration-service` which invokes Twilio Verify. In practice, operators of a Go Signal port may want:

- The real Twilio Verify integration for production parity.
- AWS SES email verification for email-first registration.
- SMTP for local development and self-hosted deployments without external dependencies.
- Other transports (e.g., internal SMS gateways) under their own control.

Locking the server to Twilio would exclude self-hosted deployments. Locking it to SMTP would exclude production-grade phone verification.

## Decision

Verification is abstracted behind a `pkg/verification.Transport` interface. Three implementations ship with the project:

- `pkg/verification/smtp/` — SMTP email transport (existing, polish only).
- `pkg/verification/twilio/` — Twilio Verify REST API for SMS and voice.
- `pkg/verification/ses/` — AWS SES for email.

The active transport is chosen per channel in YAML config (`verification.sms.transport`, `verification.voice.transport`, `verification.email.transport`).

In Phase 3 this logic lives inside `signald`. In Phase 4 it moves into its own `registration-service` binary — the interface stays the same, the binary boundary moves.

## Alternatives considered

- **Embed Twilio directly** — Matches Java exactly. Rejected: excludes self-hosted deployments.
- **SMTP-only** — Keep what's present. Rejected: incompatible with real Signal clients that expect SMS.
- **Separate registration-service now** — Rejected for Phase 3 to avoid building inter-service plumbing before the single-binary version is exercised; deferred to Phase 4 once patterns are proven.

## Consequences

- New transport implementations drop in behind the interface without touching upstream verification logic.
- Testing requires mockable transports; the interface is narrow enough that fakes are easy to write.
- The transport abstraction must remain stable across the Phase 3 → Phase 4 boundary so extracting `registration-service` doesn't force a refactor.

## References

- Plan: `/home/jhahn/.claude/plans/fluttering-kindling-flask.md`, Phases 3.2 and 4.1.
- Existing: `pkg/verification/smtp/` and `pkg/verification/` interfaces.
