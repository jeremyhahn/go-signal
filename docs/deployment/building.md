# Building

go-signal produces two binaries: `signald` (the server) and `signalctl` (the CLI tool). Both are built from the `github.com/jeremyhahn/go-signal` module and require Go 1.26.

## Build Commands

The Makefile is the primary build interface. All compiled binaries are written to `build/bin/`.

```bash
# Build both server and CLI (no extensions)
make build

# Build individual targets
make build-server    # signald only
make build-cli       # signalctl only

# Build with optional extensions
make build-fido2     # Server with FIDO2/WebAuthn support
make build-smtp      # Server with SMTP verification
make build-all       # Server with all extensions (fido2,smtp)

# Generate protobuf code
make proto
```

Extension builds produce separate binaries named with a suffix: `signald-fido2`, `signald-smtp`, or `signald-all`.

## Build Tags

Build tags control which optional features are compiled into the server binary.

| Tag | Package | Description | External Dependency |
|---|---|---|---|
| `fido2` | `pkg/fido2/` | WebAuthn/FIDO2 authentication | `libfido2-dev` |
| `smtp` | `pkg/verification/smtp/` | SMTP-based verification transport | None |

Tags are passed to the Go compiler via `-tags`. For example, `make build-all` runs:

```bash
go build -tags "fido2,smtp" -o build/bin/signald-all ./cmd/signald/
```

The `fido2` tag requires `libfido2-dev` installed on the build host. Without it, the build will fail with missing CGo headers.

## Version Injection

The build injects three variables into the binary via `-ldflags`:

| Variable | Source | Example |
|---|---|---|
| `version` | `VERSION` file in the project root | `0.1.0` |
| `gitCommit` | `git rev-parse --short HEAD` | `a1b2c3d` |
| `buildDate` | UTC timestamp at build time | `2026-03-15T14:30:00Z` |

These values are available at runtime through the `signald version` command and `signalctl version`.

## Development

For local development, `make dev` runs the server directly without compiling a binary:

```bash
make dev
```

This executes `go run ./cmd/signald/ start`, which is faster for iteration since it skips the build step.

## Dependencies

Download and tidy module dependencies:

```bash
make deps
```

This runs `go mod download` followed by `go mod tidy`. The project uses local replace directives for `go-libsignal` and `go-xkms`, so those repositories must be cloned alongside go-signal.

## Cleaning

Remove all build artifacts:

```bash
make clean
```

This deletes the entire `build/` directory, including compiled binaries, coverage reports, and test logs.
