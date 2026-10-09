# ADR-0004: Pluggable verification transport abstraction

> **Status: REFERENCE** · Last verified: 2026-10-09
> Decision record, corrected to the as-built transport wiring.

- **Status**: accepted
- **Date**: 2026-04-22
- **Author**: go-signal team

## Context

Phone-number verification is the first step of registration. The Java Signal-Server delegates it to a `registration-service` that calls Twilio Verify. Operators of a Go port may want Twilio for production parity, email delivery, SMTP for self-hosted deployments, or their own gateway. Locking to any one of them excludes the others.

## Decision

Code delivery is abstracted behind the `pkg/verification.VerificationTransport` interface (`SendCode` and `Name`). The packages are:

- `pkg/verification/twilio/` — Twilio Verify
- `pkg/verification/ses/` — AWS SES email
- `pkg/verification/smtp/` — SMTP email (compiled with build tag `smtp`)

The factory (`pkg/verification/factory`) wires `stub` (the default when the key is empty) and `twilio`. The `ses` and `smtp` packages are not selectable through the factory.

The transport is chosen by the single config key `verification.transport`.

The verification engine runs in process in signald (`pkg/registration/core`), or in the `registration-service` binary when `verification.remoteAddr` is set. The transport interface is the same in both.

## Alternatives considered

- **Embed Twilio directly** — rejected: excludes self-hosted deployments.
- **SMTP only** — rejected: incompatible with clients that expect SMS.
- **Separate registration-service only** — rejected: the in-process engine keeps single-binary deployments working.

## Consequences

- A new transport drops in behind the interface; it must also be added to the factory to be selectable.
- The interface is narrow, so test fakes are small.

## References

- [../../verification/](../../verification/)
- [0002-external-services-as-separate-binaries.md](0002-external-services-as-separate-binaries.md)
