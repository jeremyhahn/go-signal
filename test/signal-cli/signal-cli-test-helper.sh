#!/bin/bash
# Runs signal-cli for integration tests: ./signal-cli-test-helper.sh <command> [args...]; env SIGNAL_CLI_BIN, SIGNAL_CLI_DATA, SIGNAL_CLI_ACCOUNT.

set -euo pipefail

SIGNAL_CLI="${SIGNAL_CLI_BIN:-signal-cli}"
DATA_DIR="${SIGNAL_CLI_DATA:-/var/lib/signal-cli}"
ACCOUNT="${SIGNAL_CLI_ACCOUNT:-+15555550100}"

exec "${SIGNAL_CLI}" --config "${DATA_DIR}" -a "${ACCOUNT}" "$@"
