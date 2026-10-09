# ADR-0003: Skip payments in the port

> **Status: REFERENCE** · Last verified: 2026-10-09
> Decision record, corrected to the as-built payment endpoints.

- **Status**: accepted
- **Date**: 2026-04-22
- **Author**: go-signal team

## Context

The Java Signal-Server implements a large payments surface: Stripe and PayPal subscriptions, one-time donations, zero-knowledge receipt credentials for badges, and webhook processing. These features are optional for a functional Signal server, compliance-sensitive, orthogonal to every other subsystem, and expensive to port correctly.

## Decision

Payment processing is not ported.

- `/v1/subscription/*` and `/v1/donation/redeem-receipt` return `501 Not Implemented`.
- `/v1/payments/auth` returns stub credentials and `/v1/payments/conversions` returns an empty currency list. Neither is a `501`.
- The gRPC `Payments` service is registered, and its methods are unimplemented.
- There is no `pkg/subscriptions` package.

## Alternatives considered

- **Full port** — rejected: compliance burden and scope.
- **Stripe only with ZK receipts** — rejected for this port; could be revisited under a new ADR.
- **Stub with a pluggable interface** — rejected: designing the interface needs the same research as a minimal implementation, and an unused abstraction is a cost.

## Consequences

- Deployments that need donations or subscriptions cannot use go-signal as-is.
- The server is not feature-complete against the Java reference; payments are skipped by design.
- Reversing the decision needs a new ADR, new handlers and a new package for the payment logic.

## References

- [../../api/rest.md](../../api/rest.md)
- [../../api/grpc.md](../../api/grpc.md)
