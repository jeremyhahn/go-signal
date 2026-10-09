# Testing

> **Status: REFERENCE** · Last verified: 2026-10-09
> The Make targets for unit, integration and coverage runs, the coverage gate and its exclusions, and the CI pipeline.

The project enforces a 90% minimum total coverage (`COVER_MIN`). Tests split into unit tests (fast, in-memory) and integration tests (end to end, with a real signal-cli).

## Unit Tests

```bash
make test
```

Runs `go test -race -count=1 -v` with atomic coverage over `./pkg/... ./cmd/... ./sdk/... ./test/build/...`, under the repo build tags. Output goes to `build/coverage/coverage.out` and the log to `build/test.log`. The target fails if any test fails.

Per-package targets follow `test-<package>`:

```bash
make test-accounts
make test-keys
make test-messages
make test-rest
make test-websocket
make test-config
```

Build-tagged packages have their own targets: `make test-fido2`, `make test-smtp`. The Postgres store has `make test-storage-postgres`, which needs a reachable database (`TEST_POSTGRES_URL`, see the comment above the target in the Makefile).

Unit test rules:

- Never modify the host system.
- Never perform operations that could block indefinitely.
- Run in memory and execute quickly.
- Every function has at least 2 tests.

## Integration Tests

```bash
make integration-test
```

Integration tests live in `test/integration/` behind the `integration` build tag, with a 120-minute timeout. The runner has two modes:

- **`SIGNAL_SERVER_URL` set**: runs `go test -tags integration ./test/integration/...` directly against that server. This is the path inside the devcontainer.
- **Otherwise**: builds and starts the `.devcontainer/docker-compose.yml` stack, runs the `integration` service and writes `build/integration-test.log`.

`make integration-test-fido2` and `make integration-test-cli` run the FIDO2 and CLI-parity suites.

## Coverage

```bash
make coverage
```

Runs each package's tests separately, merges the profiles into `build/coverage/coverage.out`, prints a per-function summary, writes `build/coverage/coverage.html` and then runs `make coverage-gate`, which fails when total coverage is below `COVER_MIN` (90) or cannot be measured.

Coverage targets that exist for single areas: `make coverage-fido2`, `make coverage-smtp`, `make coverage-desktop` and `make coverage-storage-postgres`. There are no per-package `coverage-<package>` targets for the other packages.

### Exclusions

`make coverage` leaves out packages matching:

- `/test/`
- `/cmd/`
- `/genproto/`
- `/internal/frontend`
- `/securestorage/storagepb`
- `/websocket/proto`
- `/storage/postgres` (covered by its own target)
- `/wsproto`

## CI Pipeline

```bash
make ci
```

Runs, in order, and stops at the first failure:

1. `fmt`: fails if any file needs `gofmt`.
2. `vet`: `go vet ./...` under the repo tags, then again with the `integration` tag.
3. `lint`: `golangci-lint` with a 5-minute timeout, under the repo tags and again with the `integration` tag.
4. `security`: `gosec` (two passes, excluding G103, G104, G115, G304 and G118), `govulncheck`, module verification against `go.sum` and `trivy`.
5. `build`: compiles `signald` and the `signal` CLI.
6. `test`: the full unit suite with coverage.

Each step also runs standalone (`make lint`, `make gosec`, `make vuln`).
