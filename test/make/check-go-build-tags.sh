#!/usr/bin/env bash
# Regression check for #122: GO_BUILD_TAGS reaches the integration targets,
# each tag list with ONE separator (go reads "a,b c" as space-separated and
# drops tags), and the Docker path forwards it into the integration container.
# Dry runs only (make -n): nothing is built, run or started.
set -euo pipefail
cd "$(dirname "$0")/../.."

MAKE=${MAKE:-make}
tags='zzone zztwo'
fail=0

# expect NAME NEEDLE -- MAKE_ARGS...: the dry run must print NEEDLE verbatim.
expect() {
	local name=$1 needle=$2
	shift 3
	local out
	out=$("$@" 2>&1) || { echo "FAIL $name: make -n exited non-zero" >&2; fail=1; return; }
	if printf '%s\n' "$out" | grep -qF -- "$needle"; then
		echo "ok   $name: $needle"
	else
		echo "FAIL $name: no '$needle' in:" >&2
		printf '%s\n' "$out" | grep -F -- '-tags' >&2 || true
		fail=1
	fi
}

expect integration-test '-tags "integration zzone zztwo" ' -- \
	env SIGNAL_SERVER_URL=x "$MAKE" -n --no-print-directory integration-test GO_BUILD_TAGS="$tags"
expect integration-test-cli '-tags "integration zzone zztwo" ' -- \
	"$MAKE" -n --no-print-directory integration-test-cli GO_BUILD_TAGS="$tags"
expect integration-test-fido2 '-tags "integration,fido2,zzone,zztwo" ' -- \
	"$MAKE" -n --no-print-directory integration-test-fido2 GO_BUILD_TAGS="$tags"
expect integration-test/docker '-e GO_BUILD_TAGS="zzone zztwo" integration' -- \
	env -u SIGNAL_SERVER_URL "$MAKE" -n --no-print-directory integration-test GO_BUILD_TAGS="$tags"

# Empty GO_BUILD_TAGS keeps the original flags.
expect integration-test/empty '-tags integration ' -- \
	env SIGNAL_SERVER_URL=x "$MAKE" -n --no-print-directory integration-test GO_BUILD_TAGS=
expect integration-test-fido2/empty '-tags "integration,fido2" ' -- \
	"$MAKE" -n --no-print-directory integration-test-fido2 GO_BUILD_TAGS=

exit $fail
