#!/bin/sh
# require-tool.sh — make a Go analysis tool available at an EXACT pinned
# version, or fail the job. Called from .github/workflows/ci.yml.
#
#   require-tool.sh <binary> <pin> <module-path> [extra go-install args...]
#
# WHY THIS EXISTS (go-xkms #189)
#
# ci.yml used to `go install tool@version` at job time. The self-hosted runner
# image already BAKES these tools at pinned versions in /usr/local/bin, so the
# install did not add a tool — it OVERWROTE the baked one with a different
# version. Measured on this repo's CI Lint leg: the image carries
# golangci-lint v2.13.2 and the job printed "has version 2.12.2". The baked
# version is the one that can lint Go 1.27, so the workflow was actively
# undoing the fix that was already sitting on the runner.
#
# The install was also a live flake: every host in this fleet resolves an AAAA
# record for sum.golang.org and none has a default IPv6 route, and runner job
# containers use host networking, so they inherit that stack exactly. Go
# usually falls back v6 -> v4, which is why the failure was intermittent
# rather than constant. A failed install skips the analyser entirely and
# leaves a red check carrying no verdict on the code.
#
# Pinning alone was never enough for gosec: it takes its version string from
# ldflags rather than from the module path, so `go install ...@v2.29.0` still
# self-reports `dev`, which means results cannot be attributed to a scanner
# version and two runs of one commit can disagree. The ASSERTION below is
# therefore the deliverable, not the pin: whatever the binary is and wherever
# it came from, this refuses to continue unless it SAYS it is the pinned
# version.
#
# FAIL-CLOSED, in both directions:
#   - A tool missing on a self-hosted runner is an IMAGE defect. It is not
#     quietly papered over with a network install, because doing so would
#     restore precisely the flake this removes while reporting success.
#   - A tool whose self-report does not match the pin fails, rather than
#     scanning with an unknown version and calling the result a gate.
#   - A version that cannot be READ AT ALL fails. An unreadable self-report is
#     not evidence of a matching version.
#
# The github.com fallback is deliberate and narrow: this same workflow file
# runs on GitHub-hosted runners on the public mirror, where no image of ours
# exists and there is nothing to bake into. It is the only path here that
# touches the network, and it still has to satisfy the same assertion
# afterwards.
#
# Derived from the reference implementation in go-luks2, which is the repo
# that established this pattern.

set -eu

bin="${1:?usage: require-tool.sh <binary> <pin> <module-path> [go-install args...]}"
pin="${2:?missing pinned version}"
module="${3:?missing module path}"
shift 3

# The image records what it baked. Read it back when present: a version skew
# between this workflow's pin and the image's is a real inconsistency, and
# surfacing it here means it is caught before a scan runs rather than inferred
# afterwards from a result nobody can reproduce.
manifest=/etc/ci-runner-tools.txt
if [ -r "$manifest" ]; then
	echo "runner image tool manifest:"
	sed 's/^/  /' "$manifest"
fi

if ! command -v "$bin" >/dev/null 2>&1; then
	case "${GITHUB_SERVER_URL:-}" in
	https://github.com)
		echo "note: ${bin} is absent; installing ${module}@${pin} (GitHub-hosted runner, no baked image)"
		go install "$@" "${module}@${pin}"
		# actions/setup-go puts GOPATH/bin on PATH, which is what made the
		# install-then-run-bare arrangement work before. Assert it rather than
		# assume it, and assert it HERE: an exported PATH does not survive this
		# script, so if the binary is not reachable now it will not be reachable
		# in the step that runs it, and that failure would arrive looking like a
		# missing tool rather than a broken PATH.
		command -v "$bin" >/dev/null 2>&1 || {
			echo "FAIL: installed ${module}@${pin} but ${bin} is still not on PATH." >&2
			echo "Expected $(go env GOPATH)/bin to be on PATH (actions/setup-go)." >&2
			exit 1
		}
		;;
	*)
		echo "FAIL: ${bin} is not installed on this runner." >&2
		echo "It is supposed to be baked into the runner image at ${pin}." >&2
		echo "Refusing to install it over the network: that reinstates the" >&2
		echo "version overwrite and the intermittent ENETUNREACH failure this" >&2
		echo "arrangement exists to remove, and a job that silently does so" >&2
		echo "hides an image defect (#189)." >&2
		echo "Ask for the runner image to be rebuilt." >&2
		exit 1
		;;
	esac
fi

# Self-report. Tools disagree on the flag, so try both spellings; a tool that
# answers neither has not told us its version, and that is a failure.
if ! report="$("$bin" --version 2>&1)" || [ -z "$report" ]; then
	if ! report="$("$bin" -version 2>&1)" || [ -z "$report" ]; then
		echo "FAIL: ${bin} would not report a version." >&2
		echo "An unreadable version is not a matching version." >&2
		exit 1
	fi
fi

# EXTRACT THE VERSION TOKEN FROM EACH TOOL'S DOCUMENTED FORMAT, then compare it
# EXACTLY. A substring test (`case "$report" in *"$bare"*`) FAILS OPEN: a
# `v1.7.0` pin accepts a report saying `v11.7.0`, and a `v2.29.0` pin accepts
# `v12.29.0`. CI would then run an unintended scanner version and print `ok` —
# defeating the exact reproducibility assertion this check exists to make. A
# check looser than the property it claims is the same defect as no check,
# with a green tick on top.
#
# A GENERIC "find something version-shaped" regex is not the fix either, and
# govulncheck shows why: its output's FIRST version-shaped token is the Go
# toolchain's.
#
#	Go: go1.26.7
#	Scanner: govulncheck@v1.7.0
#
# A loose extractor pins the wrong number. So each tool is parsed by its own
# documented line, anchored at the start of it:
#
#	golangci-lint   golangci-lint has version 2.13.2 built with go1.26.7 ...
#	gosec           Version: v2.29.0
#	govulncheck     Scanner: govulncheck@v1.7.0
#
# An UNRECOGNISED tool is a hard failure rather than a fallback to something
# looser. A version format nobody has read is a version that cannot be
# verified, and guessing at it is how the substring test got written.
case "$bin" in
golangci-lint)
	got="$(printf '%s\n' "$report" |
		sed -n 's/^golangci-lint has version \([^[:space:]][^[:space:]]*\).*/\1/p' |
		head -1)"
	;;
gosec)
	got="$(printf '%s\n' "$report" |
		sed -n 's/^Version:[[:space:]][[:space:]]*\([^[:space:]][^[:space:]]*\)[[:space:]]*$/\1/p' |
		head -1)"
	;;
govulncheck)
	got="$(printf '%s\n' "$report" |
		sed -n 's/^Scanner:[[:space:]][[:space:]]*govulncheck@\([^[:space:]][^[:space:]]*\).*/\1/p' |
		head -1)"
	;;
*)
	echo "FAIL: no documented version format is known for '${bin}'." >&2
	echo "Refusing to verify it by guessing at its output. Add its format to" >&2
	echo "the case statement in .github/scripts/require-tool.sh, having read" >&2
	echo "what the tool actually prints." >&2
	exit 1
	;;
esac

if [ -z "$got" ]; then
	echo "FAIL: could not extract a version from ${bin}'s output." >&2
	echo "It said:" >&2
	printf '%s\n' "$report" | sed 's/^/  /' >&2
	echo "The expected format is the one documented in this script. A version" >&2
	echo "that could not be parsed is not a matching version — this fails" >&2
	echo "rather than falling back to a looser comparison." >&2
	exit 1
fi

# Compare exactly, with the `v` prefix optional on EITHER side: golangci-lint
# reports bare (2.13.2) while gosec and govulncheck report prefixed (v2.29.0),
# and the pins are written prefixed. Nothing else is normalised away.
if [ "${got#v}" != "${pin#v}" ]; then
	echo "FAIL: ${bin} is version ${got}, not the pinned ${pin}." >&2
	echo "It said:" >&2
	printf '%s\n' "$report" | sed 's/^/  /' >&2
	echo "Scan and lint results that cannot be attributed to a known version" >&2
	echo "are not reproducible, which is the defect this check exists for." >&2
	echo "Bump the pin in .github/workflows/ci.yml deliberately, together with" >&2
	echo "the runner image, or restore the image." >&2
	exit 1
fi

echo "ok  ${bin} ${pin}  ($(command -v "$bin"))"
