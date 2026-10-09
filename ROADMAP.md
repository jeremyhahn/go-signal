# go-signal roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-08
> Changes are proposed by docs-only PR.

## Mission

Signal messaging server in Go, standalone, built before go-quicbaas.
Byte-wire compatible with the pinned Java Signal-Server commit in `SIGNAL_SERVER_REV`.
Stores through go-qrdb `sdk/go`; takes every crypto and wire-format primitive from go-libsignal.

## Current milestone

[Release candidate (M13)](../../milestone/13): target RC, projected 2027-01-07.
Blocking themes: credential strings ([#47](../../issues/47), [#77](../../issues/77), [#78](../../issues/78)) and a green `main`.

## Now

- [#84](../../issues/84) main green again with golangci-lint pinned to the runner image — blocked: pin v2.12.2 does not match runner v2.13.2
- [#16](../../issues/16) Go 1.27 toolchain wave adopted — open
- [#23](../../issues/23) getUserStatus reaches the CDSI service through a /cdsi route — blocked: architecture decision needed
- [#47](../../issues/47) credentials kept out of Go strings on the REST write and external-auth paths — open
- [#58](../../issues/58) go-qrdb sdk/go bump with *string IndexScan bounds — blocked: breaking change from go-qrdb#36
- [#60](../../issues/60) health/metrics sidecar listener configurable — open
- [#61](../../issues/61) secret sealing migrated off the removed go-libsignal Enclave API — open

## Next

- [#62](../../issues/62) swiss pin bumped for Go 1.27 — open
- [#64](../../issues/64) Integration Gate and Integration Tests green on main and posting status — open
- [#77](../../issues/77) credentials kept out of Go strings on the gRPC Basic-auth path — open
- [#78](../../issues/78) credentials kept out of Go strings on every remaining path — open
- [#79](../../issues/79) cron scheduler test stable under parallel load — open
- [#85](../../issues/85) release readiness for public release confirmed — open
- [#90](../../issues/90) every doc carries a status banner and stamp — open

## Later

Nothing accepted. New work arrives as issues.

## Dependencies

- Up: go-qrdb v0.7.0-alpha (with `sdk/go` v0.7.0-alpha), go-libsignal v0.1.2-alpha; indirect go-quicraft v0.6.2-alpha, go-objstore v0.2.2-alpha, go-codec v1.4.0.
- Down: go-quicbaas (Signal integration under the `signal` build tag).

## Non-goals

- Crypto and wire-format primitives present in Rust libsignal; those belong to go-libsignal.
- Storage engine internals; go-signal consumes go-qrdb only through `sdk/go`.
- Ownership boundaries per [docs/00](../handbook/software/docs/00-ownership-and-sdk-boundary.md); not restated here.
