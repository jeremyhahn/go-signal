# Development setup

> **Status: REFERENCE** · Last verified: 2026-10-09
> Local toolchain, sibling-module resolution, Make targets and build tags for working on go-signal.

## Prerequisites

- Go 1.27.4 (`go.mod` declares `go 1.27.4`).
- Make.
- Docker with the compose plugin, for `make integration-test` outside a devcontainer.
- `protoc` and its Go plugins at the versions the Makefile pins, for proto regeneration. `make proto-tools` verifies them.
- Node.js and npm, for the frontend targets (`build-frontend`, `dev-web`, `test-e2e`).

## Sibling modules

go-signal requires `github.com/jeremyhahn/go-libsignal`, `github.com/jeremyhahn/go-qrdb` and `github.com/jeremyhahn/go-qrdb/sdk/go` at published versions; `go-quicraft` arrives as an indirect dependency. `go.mod` commits no local-path `replace` directives. For local cross-repo development the sibling checkouts are tied together by a `go.work` file in a parent directory outside this repository, as the comment at the end of `go.mod` states. Crypto and wire-format primitives belong in go-libsignal, not here.

The company standards repo, `handbook`, is checked out beside this repository (`../handbook`).

## Build and test

```bash
make build              # build signald and the signal CLI
make build-all          # build the frontend, then signald and the CLI
make build-services     # build cdsi, svr2, key-transparency, registration-service and storage-service
make test               # unit tests with -race and coverage
make integration-test   # integration tests (devcontainer docker-compose, or directly when SIGNAL_SERVER_URL is set)
make coverage           # per-package coverage report with a 90% minimum gate
make ci                 # fmt + vet + lint + security + build + test
```

`make security` runs gosec, govulncheck, module verification and trivy.

Per-package targets follow `make test-<package>` (for example `make test-accounts`, `make test-storage-postgres`) and `make coverage-<package>` where defined. See the `Makefile` for the full list.

`make docs` and `make docs-check` currently run placeholder targets; no documentation is generated from source.

## Build tags

| Tag | Feature | Makefile switch |
|---|---|---|
| `fido2` | WebAuthn/FIDO2 authentication | `WITH_FIDO2` (default 1) |
| `smtp` | SMTP verification transport | `WITH_SMTP` (default 0) |
| `desktop` | Wails desktop client (with `codec_json`) | `WITH_DESKTOP` (default 1) |
| `signal` | QuicBaaS Signal integration (go-quicbaas only) | none |

Set a switch on the command line, for example `WITH_SMTP=1 make build`, or pass tags directly: `go build -tags fido2,smtp ./...`.

## Running the server locally

```bash
make dev                # go run ./cmd/signald/ start
make dev-web            # Vite dev server and signald together, with frontend hot reload
```

See [../deployment/building.md](../deployment/building.md) for release builds and [../deployment/docker.md](../deployment/docker.md) for containerized workflows.
