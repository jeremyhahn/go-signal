#!/bin/bash
# Helper script for running signal-cli commands in integration tests.
# Usage: ./signal-cli-test-helper.sh <command> [args...]
#
# Environment variables:
#   SIGNAL_CLI_BIN     - Path to signal-cli binary (default: signal-cli)
#   SIGNAL_CLI_DATA    - Data directory (default: /var/lib/signal-cli)
#   SIGNAL_CLI_ACCOUNT - Phone number to use (default: +15555550100)

set -euo pipefail

SIGNAL_CLI="${SIGNAL_CLI_BIN:-signal-cli}"
DATA_DIR="${SIGNAL_CLI_DATA:-/var/lib/signal-cli}"
ACCOUNT="${SIGNAL_CLI_ACCOUNT:-+15555550100}"

exec "${SIGNAL_CLI}" --config "${DATA_DIR}" -a "${ACCOUNT}" "$@"
