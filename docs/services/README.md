# Services

Each file in this directory documents one of the binaries in the go-signal topology. They get populated as the corresponding binaries are built.

| Binary                  | Document                                                     | Phase landed |
|-------------------------|--------------------------------------------------------------|--------------|
| `signald`               | Phase 1: gRPC surface documented in [../api/grpc.md](../api/grpc.md). Per-service deep dive lands with Phase 2. | Phase 2 |
| `registration-service`  | [registration-service.md](registration-service.md) — *pending* | Phase 4.1 |
| `svr2`                  | [svr2.md](svr2.md) — *pending*                               | Phase 4.2    |
| `cdsi`                  | [cdsi.md](cdsi.md) — *pending*                               | Phase 4.3    |
| `storage-service`       | [storage-service.md](storage-service.md) — *pending*         | Phase 4.4    |
| `key-transparency`      | [key-transparency.md](key-transparency.md) — *pending*       | Phase 4.5    |

See [../architecture/topology.md](../architecture/topology.md) for how the services relate to each other.
