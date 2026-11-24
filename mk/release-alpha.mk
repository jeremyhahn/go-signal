# release-alpha: make release-alpha VERSION=vX.Y.Z-alpha cuts a signed, annotated tag from main via agent-git.sh and pushes only that commit and tag.
# Set AGENT_GIT (resolved from PATH), REPO_NAME (the literal repo name) and RELEASE_REMOTE near the top of the Makefile; the body is in release-common.mk.
# Fails closed: explicit version, CHANGELOG section, remote duplicate-tag check, single-quoted error messages.

# Settable inputs reach the recipe once, via target-specific exports read as $(value ...), and are unexported so a command-line value cannot execute.
.PHONY: release-alpha
# The export and unexport lines live in release-common.mk; override stops a command-line REL_* value from winning.
include $(dir $(lastword $(MAKEFILE_LIST)))release-common.mk
release-alpha:
	@test -n "$$REL_VERSION" || { echo 'ERROR: state the version explicitly: make release-alpha VERSION=vX.Y.Z-alpha (release-versioning.md decides patch/minor/major — the recipe refuses to guess)'; exit 1; }
	@printf '%s' "$$REL_VERSION" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-alpha$$' || { echo "ERROR: VERSION is not of the form vX.Y.Z-alpha (no leading zeroes): $$REL_VERSION"; exit 1; }
	$(RELEASE_GUARDS)
	$(RELEASE_MONOTONIC)
	$(RELEASE_CUT)
