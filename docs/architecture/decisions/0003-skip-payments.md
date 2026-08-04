# ADR-0003: Skip payments in the port

- **Status**: accepted
- **Date**: 2026-04-22
- **Author**: go-signal team

## Context

Java Signal-Server implements a substantial payments surface: Stripe subscriptions and one-time donations, Braintree/PayPal checkout, zero-knowledge receipt credentials for premium badges, idempotency handling, webhook processing, and PCI-sensitive request flows. The relevant Java controllers are `SubscriptionController` (46KB), `OneTimeDonationController` (21KB), `PaymentsController`, and `DonationController`.

These features are:

1. Optional for a functional Signal server — messaging, groups, calling, backups all work without them.
2. Compliance-sensitive — PCI considerations, per-jurisdiction payment regulations, webhook signature verification.
3. Orthogonal to every other subsystem — nothing else in the server depends on payments being wired up.
4. Expensive to port correctly — three payment processors, receipt credential issuance, and test coverage against sandbox environments for each.

## Decision

Payments are skipped entirely from the port. The existing endpoints under `/v1/payments/*`, `/v1/subscription/*`, and `/v1/donation/*` remain as stub handlers returning `501 Not Implemented`. No new work is planned against these subsystems.

The `pkg/subscriptions/` package exists only to satisfy package-layout expectations; it has no implementation and no tests.

The gRPC `Payments` proto service is scaffolded in Phase 1 (for proto compilation completeness) but its methods all return `codes.Unimplemented`.

## Alternatives considered

- **Full port** — Match Java 1:1. Rejected because of compliance burden and scope.
- **Stripe only with ZK receipts** — Most common payment path; would still deliver donation/subscription functionality. Rejected for this port but could be revisited later under a new ADR if a deployment requires it.
- **Stub with a pluggable interface ready to implement** — Rejected because designing the interface correctly requires the same research effort as building a minimum-viable implementation, and we'd rather not carry an unused abstraction.

## Consequences

- Deployments that need donations or subscriptions cannot use go-signal as-is. They must either use the Java Signal-Server for those flows, or add payment support under a new ADR.
- The server is not feature-complete against the Java reference, and the top-level completeness matrix will permanently mark payments as "Skipped by design."
- Removing this from scope reclaims 4-6 weeks of the original plan's estimate and removes a significant compliance surface from the threat model.
- If this decision is ever reversed, the work is cleanly isolated — adding payments touches only the `pkg/subscriptions/` package, a handful of REST/gRPC handlers, and a new `pkg/payments/` tree.

## References

- Plan: `/home/jhahn/.claude/plans/fluttering-kindling-flask.md` — payments exclusion.
- Java reference (for future readers): `/mnt/vm-host-1/Signal-Server/service/src/main/java/org/whispersystems/textsecuregcm/controllers/SubscriptionController.java`.
