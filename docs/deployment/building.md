# Building

> **Status: REFERENCE** · Last verified: 2026-10-09
> Make targets, build tags, version injection and dependency handling for building go-signal.

go-signal produces the `signald` server and the `signal` CLI (`./cmd/signal`), plus five auxiliary service binaries (see [../architecture/topology.md](../architecture/topology.md)). The module is `github.com/jeremyhahn/go-signal` and requires Go 1.27.2. The build is pure Go and sets `CGO_ENABLED=0` in the container images.

## Build Commands

The Makefile is the primary build interface. Compiled binaries are written to `build/bin/`.

```bash
make build                      # signald and the signal CLI
make build-server               # signald only
make build-cli                  # signal CLI only
make build-all                  # frontend, then signald and the CLI
make build-services             # cdsi, svr2, key-transparency, registration-service, storage-service
make build-cdsi                 # a single auxiliary service (also build-svr2, build-key-transparency,
                                # build-registration-service, build-storage-service)
make proto                      # regenerate protobuf code (verifies pinned tool versions first)
```

## Build Tags

Tags are assembled from feature switches and passed to the compiler with `-tags`.

| Tag | Package | Description | Make switch |
|---|---|---|---|
| `fido2` | `pkg/fido2/` | WebAuthn/FIDO2 authentication | `WITH_FIDO2` (default 1) |
| `smtp` | `pkg/verification/smtp/` | SMTP verification transport | `WITH_SMTP` (default 0) |
| `desktop`, `codec_json` | desktop client | Wails desktop build | `WITH_DESKTOP` (default 1) |

```bash
WITH_SMTP=1 make build          # adds the smtp tag
WITH_FIDO2=0 make build         # drops the fido2 tag
```

The `fido2` tag needs no system library; the container images build with it and `CGO_ENABLED=0`.

## Version Injection

The build injects three variables into the binary through `-ldflags`:

| Variable | Source |
|---|---|
| `main.version` | the `VERSION` file in the project root (`0.0.1-alpha` if absent) |
| `main.gitCommit` | `git rev-parse --short HEAD` |
| `main.buildDate` | UTC timestamp at build time |

The values are reported by `signald version`.

## Development

`make dev` runs `go run ./cmd/signald/ start` without producing a binary. `make dev-web` starts the Vite frontend dev server and signald together.

## Dependencies

```bash
make deps
```

Runs `go mod download` followed by `go mod tidy`. `go.mod` commits no local-path `replace` directives; first-party modules (`go-libsignal`, `go-qrdb`) resolve as tagged versions. See [../contributing/development-setup.md](../contributing/development-setup.md) for local cross-repo development.

## Cleaning

`make clean` deletes the entire `build/` directory, including binaries, coverage reports and test logs.
