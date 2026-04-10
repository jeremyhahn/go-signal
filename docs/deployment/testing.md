# Testing

The project enforces a 90% minimum coverage threshold per package. Tests are split into unit tests (fast, in-memory) and integration tests (E2E with real signal-cli). The CI pipeline ties everything together with formatting, linting, and security checks.

## Unit Tests

```bash
make test
```

Runs all unit tests across `./pkg/...` and `./cmd/...` with race detection enabled and atomic coverage profiling. Output goes to `build/coverage/coverage.out` and a log to `build/test.log`.

Per-package tests use the `test-{package}` convention:

```bash
make test-accounts
make test-keys
make test-messages
make test-rest
make test-websocket
make test-config
```

Build-tagged packages have their own targets that pass the correct tags:

```bash
make test-fido2    # Runs with -tags fido2
make test-smtp     # Runs with -tags smtp
```

Unit test rules:

- Never modify the host system (no disk writes, no network calls)
- Never perform operations that could block indefinitely
- Always run in memory and execute quickly
- Every function should have at least 2 corresponding tests

## Integration Tests

```bash
make integration-test
```

Integration tests live in `test/integration/` and use the `integration` build tag. The timeout is set to 120 minutes to accommodate E2E scenarios with real signal-cli.

The test runner has two modes:

- **When `SIGNAL_SERVER_URL` is set**: Runs `go test` directly against the specified server. This is the path used inside the devcontainer where the server is already running.
- **Otherwise**: Brings up the docker-compose infrastructure (server, signal-cli, integration runner), runs the tests inside the container, and streams output to `build/integration-test.log`.

## Coverage

Full project coverage:

```bash
make coverage
```

This iterates over all packages (excluding test harness, CLI entry points, and generated code), merges the profiles, and produces both a console summary and an HTML report at `build/coverage/coverage.html`. If total coverage falls below 90%, the command exits with a failure.

Per-package coverage follows the `coverage-{package}` convention:

```bash
make coverage-accounts
make coverage-keys
make coverage-messages
make coverage-config/secrets
make coverage-api/rest
```

Build-tagged packages:

```bash
make coverage-fido2
make coverage-smtp
```

Each per-package target enforces the same 90% minimum threshold and produces its own profile in `build/coverage/`.

### Exclusions

The following paths are excluded from coverage reports:

- `/test/` -- test harness and integration tests
- `/cmd/signalctl` -- CLI entry point
- `/cmd/signald` -- server entry point
- `/wsproto` -- generated WebSocket protocol code

## CI Pipeline

```bash
make ci
```

The CI target runs the full quality pipeline in order:

1. `fmt` -- Checks that all files pass `gofmt`. Fails if any file needs formatting.
2. `vet` -- Runs `go vet ./...` for static analysis.
3. `lint` -- Runs `golangci-lint` with a 5-minute timeout.
4. `gosec` -- Runs the security scanner with exclusions for G103 (unsafe calls in tests), G104 (false positives on `hash.Write`), G115 (protocol-bounded integer conversions), and G304 (internally constructed config paths).
5. `vuln` -- Runs `govulncheck` against all dependencies.
6. `build` -- Compiles both `signald` and `signalctl`.
7. `test` -- Runs the full unit test suite with coverage.

Any step that fails stops the pipeline. Individual steps can be run standalone (e.g., `make lint`, `make gosec`).
