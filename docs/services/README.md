# Services

> **Status: REFERENCE** · Last verified: 2026-10-09
> Index of the go-signal binaries; there are no per-binary documents in this folder yet.

The binaries live under `cmd/`: `signald`, `registration-service`, `svr2`, `cdsi`, `storage-service` and `key-transparency`. How they relate is described in [../architecture/topology.md](../architecture/topology.md) and [../architecture/decisions/0002-external-services-as-separate-binaries.md](../architecture/decisions/0002-external-services-as-separate-binaries.md).

| Binary | Documentation |
|---|---|
| `signald` | gRPC surface in [../api/grpc.md](../api/grpc.md), REST in [../api/rest.md](../api/rest.md) |
| `registration-service` | [../verification/verification.md](../verification/verification.md) |
| `svr2`, `cdsi`, `storage-service`, `key-transparency` | [../architecture/topology.md](../architecture/topology.md) |
