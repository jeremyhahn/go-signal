#!/usr/bin/env bash
# Regression check for #122: a caller's GO_BUILD_TAGS reaches every tag
# consumer (build, vet, test, coverage, lint, gosec, govulncheck and the
# integration targets), each tag list with ONE separator (go reads "a,b c" as
# space-separated and drops tags), duplicates dropped, and the Docker path
# forwards it into the integration container. An empty GO_BUILD_TAGS changes
# nothing. Dry runs only (make -n): nothing is built, run or started.
# `make lint` runs it (make check-go-build-tags).
set -euo pipefail
cd "$(dirname "$0")/../.."

# Self-check: the script must pass when the caller disables a feature
# (WITH_FIDO2=0). CHECK_GO_BUILD_TAGS_NESTED stops the recursion.
if [ -z "${CHECK_GO_BUILD_TAGS_NESTED:-}" ]; then
	if CHECK_GO_BUILD_TAGS_NESTED=1 WITH_FIDO2=0 "$0" >/dev/null 2>&1; then
		echo "ok   WITH_FIDO2=0 in the caller's environment changes nothing"
	else
		echo "FAIL: the check fails when invoked with WITH_FIDO2=0" >&2
		exit 1
	fi
fi

# Run from inside make (make lint): drop what the parent passes down, or a
# caller's GO_BUILD_TAGS on the outer command line leaks into every case.
unset MAKEFLAGS MFLAGS MAKELEVEL MAKEOVERRIDES GO_BUILD_TAGS SIGNAL_SERVER_URL
# Same for the feature switches the Makefile reads (WITH_*): make exports a
# command-line `WITH_FIDO2=0` to recipes, which would drop fido2 from the
# fixture (make lint WITH_FIDO2=0). Unset them so the fixture is the default.
unset WITH_FIDO2 WITH_SMTP WITH_DESKTOP WITH_FTS
MAKE=${MAKE:-make}
# A fixed build date, so dry runs of build compare equal.
mk() { "$MAKE" -n --no-print-directory BUILD_DATE=fixed "$@" 2>&1; }

fail=0
# expect NAME NEEDLE MAKE_ARGS...: the dry run must print NEEDLE verbatim.
expect() {
	local name=$1 needle=$2 out
	shift 2
	if ! out=$(mk "$@"); then
		echo "FAIL $name: make -n exited non-zero" >&2
		fail=1
	elif printf '%s\n' "$out" | grep -qF -- "$needle"; then
		echo "ok   $name: $needle"
	else
		echo "FAIL $name: no '$needle' in:" >&2
		printf '%s\n' "$out" | grep -E -- '-tags|build-tags' >&2 || true
		fail=1
	fi
}
# same NAME TARGET: GO_BUILD_TAGS empty prints what no variable prints.
same() {
	if [ "$(mk "$2")" = "$(mk "$2" GO_BUILD_TAGS=)" ]; then
		echo "ok   $1: empty GO_BUILD_TAGS changes nothing"
	else
		echo "FAIL $1: empty GO_BUILD_TAGS changed the dry run" >&2
		fail=1
	fi
}

repo=$("$MAKE" -s --no-print-directory print-build-tags)
case " $repo " in *" fido2 "*) ;; *) echo "FAIL: repository tag set '$repo' lacks fido2" >&2; exit 1 ;; esac
comma() { printf '%s' "$*" | tr ' ' ','; }

for input in 'zzone zztwo' 'fido2 zzone'; do
	extra=${input/fido2 /}            # fido2 is in the repository set already
	s="$repo $extra"                  # space form
	c=$(comma "$repo $extra")         # comma form
	t="GO_BUILD_TAGS=$input"
	expect "build [$input]" "-tags \"$s\" -o" build "$t"
	expect "vet [$input]" "-tags \"$s\" ./..." vet "$t"
	expect "vet/integration [$input]" "-tags \"integration $s\" ./..." vet "$t"
	expect "test [$input]" "-tags \"$s\" -coverprofile" test "$t"
	expect "coverage [$input]" "-tags \"$s\" -coverprofile" coverage "$t"
	expect "lint [$input]" "--build-tags \"$s\" ./..." lint "$t"
	expect "lint/integration [$input]" "--build-tags \"integration $s\" ./..." lint "$t"
	expect "gosec [$input]" "-tags \"$c\" " gosec "$t"
	expect "gosec/integration [$input]" "-tags \"integration,$c\" ./..." gosec "$t"
	expect "vuln [$input]" "-tags \"$c\" ./..." vuln "$t"
	expect "security [$input]" "govulncheck -tags \"$c\" ./..." security "$t"
	expect "integration-test [$input]" "-tags \"integration $input\" " integration-test SIGNAL_SERVER_URL=x "$t"
	expect "integration-test-cli [$input]" "-tags \"integration $input\" " integration-test-cli "$t"
	expect "integration-test-fido2 [$input]" "-tags \"$(comma integration fido2 "$extra")\" " integration-test-fido2 "$t"
	expect "integration-test/docker [$input]" "-e GO_BUILD_TAGS=\"$input\" integration" integration-test "$t"
done

for target in build vet test coverage lint gosec vuln integration-test-fido2 integration-test-cli integration-test; do
	same "$target" "$target"
done
expect "integration-test [empty]" '-tags integration ' integration-test SIGNAL_SERVER_URL=x
expect "integration-test-fido2 [empty]" '-tags "integration,fido2" ' integration-test-fido2

exit $fail
