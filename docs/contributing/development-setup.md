# Development setup

This document covers local environment setup for working on go-signal.

## Prerequisites

- Go 1.26.1 or newer.
- Access to the development host `vm-host-1` (198.51.100.51) via SSH, or a local clone of the sibling repositories listed below.
- Make, Docker, `protoc` with `protoc-gen-go` + `protoc-gen-go-grpc` installed for proto regeneration.

## Source tree layout

go-signal depends on several sibling Go modules that are maintained in the same organization but are not published to a public proxy. These must be available on the local filesystem.

```
/mnt/vm-host-1/
├── go-signal/          ← this project
├── go-libsignal/       ← Signal protocol crypto primitives
├── go-qrdb/            ← primary KV storage backend
├── go-quicraft/        ← Raft + QUIC consensus
├── go-truststrap/      ← transitive dep via go-qrdb
├── go-frost/           ← transitive workspace dep
├── go-frostdkg/        ← transitive workspace dep
└── go.work             ← workspace file tying them together
```

On remote development hosts we mount the entire tree via SSHFS at `/mnt/vm-host-1/`. Go resolves modules through `go.work` using relative paths, so the workspace is portable across hosts.

## Required symlinks

Create `/home/jhahn/sources/go-*` symlinks for every sibling module. Some transitive deps resolve through this path, and editor tooling (gopls, IDE goto-definition) needs them to navigate across modules cleanly.

```bash
for d in /mnt/vm-host-1/go-*; do
  ln -s "$d" "/home/jhahn/sources/$(basename "$d")"
done
```

## Module resolution

`go-signal`'s `go.mod` contains `replace` directives pointing at `/mnt/vm-host-1/...` paths for the four local modules it imports directly:

- `github.com/jeremyhahn/go-libsignal`
- `github.com/jeremyhahn/go-qrdb`
- `github.com/jeremyhahn/go-qrdb/sdk/go`
- `github.com/jeremyhahn/go-quicraft`

The workspace file at `/mnt/vm-host-1/go.work` handles transitive local modules (go-truststrap, go-frost, go-frostdkg, etc.) through its `use` entries.

Verify module resolution:

```bash
cd /mnt/vm-host-1/go-signal
go mod verify           # expect: all modules verified
go build ./...          # expect: silent success
```

If `go mod verify` fails with an error about `/home/jhahn/sources/go-<name>` not being found, the symlinks in `/home/jhahn/sources/` are missing. Re-run the symlink loop above.

## Build and test

```bash
make build              # build signald and signal binaries
make test               # run all unit tests with race detector and coverage
make integration-test   # run integration tests (docker-compose)
make coverage           # per-package coverage report, enforce 90% minimum
make ci                 # fmt + vet + lint + gosec + vuln + build + test
make docs               # regenerate generated documentation
make docs-check         # fail if generated docs are stale
```

Per-package targets: `make test-accounts`, `make coverage-accounts`, etc. See `Makefile` for the complete list.

## Build tags

| Tag       | Feature                                          |
|-----------|--------------------------------------------------|
| `fido2`   | WebAuthn/FIDO2 authentication                    |
| `smtp`    | SMTP verification transport                      |
| `signal`  | QuicBaaS Signal integration (go-quicbaas only)   |
| `desktop` | Wails desktop client (build via `make build-desktop`) |

Enable at build time: `go build -tags fido2,smtp ./...` or via Makefile variables `WITH_FIDO2=1 WITH_SMTP=1 make build`.

## Editor configuration

For `gopls` to resolve cross-module navigation:

1. Open the workspace root (`/mnt/vm-host-1/`) in your editor rather than `go-signal` alone.
2. Ensure `GOWORK=/mnt/vm-host-1/go.work` is set in your environment.
3. Symlinks in `/home/jhahn/sources/` ensure absolute-path references work when the editor follows module paths from the module cache.

## Running the server locally

```bash
make dev                # go run ./cmd/signald/ start
make dev-web            # Vite + signald together with frontend hot reload
```

See [deployment/building.md](../deployment/building.md) for release builds and [deployment/docker.md](../deployment/docker.md) for containerized workflows.
