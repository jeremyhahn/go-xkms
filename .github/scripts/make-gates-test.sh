#!/bin/sh
# make-gates-test.sh — tests that the Makefile's actionlint and trivy gates
# fail closed (go-xkms#1434).
#
# WHY THIS EXISTS
#
# `make security` used to pass with trivy absent: the trivy targets printed a
# skip and exited 0. `make lint` ran no actionlint at all. A gate that can pass
# vacuously is worse than no gate, and the vacuous pass is invisible on a
# machine that happens to have the tool. So these tests take the tool away.
#
# The tools are fakes on a REPLACED PATH (prepending would leave a real trivy or
# actionlint reachable, and the "absent" cases would find it). GOPATH and the
# module cache point into the scratch directory and GOPROXY=off, so the
# install-the-pin path is exercised and fails without touching the network or
# the developer's GOPATH. No network, no host mutation; about a minute, almost
# all of it make parsing the Makefile once per case.

set -eu

here="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
root="$(CDPATH='' cd -- "${here}/../.." && pwd)"

real_go="$(command -v go)" || {
	echo "FAIL: go is required to run these tests" >&2
	exit 1
}
real_make="$(command -v make)" || {
	echo "FAIL: make is required to run these tests" >&2
	exit 1
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$work/bin" "$work/gopath" "$work/gomodcache" "$work/gocache"
# Linked by name: adding go's own directory to PATH could bring a baked
# actionlint or trivy living beside it back into reach.
ln -s "$real_go" "$work/bin/go"
ln -s "$real_make" "$work/bin/make"

PATH="$work/bin:/usr/bin:/bin"
GOPATH="$work/gopath"
GOMODCACHE="$work/gomodcache"
GOCACHE="$work/gocache"
GOPROXY=off
GOTOOLCHAIN=local
GOFLAGS=""
export PATH GOPATH GOMODCACHE GOCACHE GOPROXY GOTOOLCHAIN GOFLAGS

# The pin is passed on the command line so the fakes agree with it without
# these tests copying the Makefile's value.
pin="v9.9.9"
fails=0

# fake <name> <rc> [version]: a tool that prints <version> for -version or
# --version and otherwise records its arguments, one per line, in
# $work/<name>.args and exits <rc>.
fake() {
	cat > "$work/bin/$1" <<EOF
#!/bin/sh
if [ "\${1:-}" = "-version" ] || [ "\${1:-}" = "--version" ]; then
	echo "${3:-}"
	echo "installed by a test fake"
	exit 0
fi
printf '%s\n' "\$@" > "$work/$1.args"
exit $2
EOF
	chmod +x "$work/bin/$1"
}

unfake() {
	rm -f "$work/bin/$1"
}

# expect <want-rc: 0|nonzero> <description> <make args...>
expect() {
	want="$1"
	desc="$2"
	shift 2
	if make -s -C "$root" ACTIONLINT_VERSION="$pin" "$@" > "$work/out" 2>&1; then
		got=0
	else
		got=nonzero
	fi
	if [ "$got" = "$want" ]; then
		echo "ok    $desc"
	else
		echo "FAIL  $desc: want exit $want, got $got" >&2
		sed 's/^/      /' "$work/out" >&2
		fails=$((fails + 1))
	fi
}

# expect_args <name> <description> <args...>: the last run of fake <name> was
# passed every one of <args>.
expect_args() {
	name="$1"
	desc="$2"
	shift 2
	for arg in "$@"; do
		if ! grep -Fqx -- "$arg" "$work/$name.args" 2>/dev/null; then
			echo "FAIL  $desc: $name was not passed $arg" >&2
			sed 's/^/      /' "$work/$name.args" >&2 2>/dev/null || true
			fails=$((fails + 1))
			return
		fi
	done
	echo "ok    $desc"
}

# trivy
expect nonzero "make trivy fails when trivy is absent" trivy
expect nonzero "make trivy-image fails when trivy is absent" -o docker-build-all trivy-image
fake trivy 0
expect 0 "make trivy passes when trivy passes" trivy
fake trivy 1
expect nonzero "make trivy fails when trivy reports findings" trivy
fake trivy 0 "Version: ${pin#v}"
expect 0 "make install-trivy accepts trivy at the pin" TRIVY_VERSION="$pin" install-trivy
fake trivy 0 "Version: 0.0.1"
expect nonzero "make install-trivy reinstalls a trivy off the pin, and fails when it cannot" \
	TRIVY_VERSION="$pin" install-trivy
if grep -Fq "could not install trivy $pin" "$work/out"; then
	echo "ok    make install-trivy attempts the pin when trivy reports another version"
else
	echo "FAIL  make install-trivy did not attempt the pin over a trivy off the pin" >&2
	sed 's/^/      /' "$work/out" >&2
	fails=$((fails + 1))
fi
unfake trivy
expect nonzero "make install-trivy fails when trivy is absent and cannot be installed" \
	TRIVY_VERSION="$pin" install-trivy

# actionlint
fake actionlint 0 "$pin"
expect 0 "make actionlint passes at the pin when the workflows lint clean" actionlint
expect_args actionlint "make actionlint lints this repository's workflows with its config" \
	-config-file "$root/.github/actionlint.yaml" "$root/.github/workflows/ci.yml"
fake actionlint 1 "$pin"
expect nonzero "make actionlint fails when actionlint reports findings" actionlint
fake golangci-lint 0
expect nonzero "make lint fails when actionlint reports findings" lint
fake actionlint 0 "$pin"
expect 0 "make lint passes when actionlint and golangci-lint pass" lint

# make lint LINT_CI=1 (go-xkms#1553) cleans golangci-lint's cache before each
# pass whose tags differ from the previous pass's, and only then: sdk/go runs
# under root's tags and keeps root's analysis. Every pass is measured. A
# developer's plain `make lint` does neither.
cat > "$work/bin/golangci-lint" <<EOF
#!/bin/sh
echo "\$1" >> "$work/golangci-lint.calls"
EOF
chmod +x "$work/bin/golangci-lint"
# expect_lint_calls <description> <want>: the golangci-lint subcommands the
# last make lint ran, in order, and the number of disk-usage reports it printed.
expect_lint_calls() {
	got="$(tr '\n' ' ' < "$work/golangci-lint.calls")"
	reports="$(grep -c '^disk usage after golangci-lint' "$work/out" || true)"
	if [ "$got" = "$2" ] && [ "$reports" = "$3" ]; then
		echo "ok    $1"
	else
		echo "FAIL  $1: calls '$got' (want '$2'), $reports disk reports (want $3)" >&2
		sed 's/^/      /' "$work/out" >&2
		fails=$((fails + 1))
	fi
}
rm -f "$work/golangci-lint.calls"
expect 0 "make lint LINT_CI=1 passes" LINT_CI=1 lint
expect_lint_calls "make lint LINT_CI=1 cleans the lint cache only when the tags change, and measures every pass" \
	"run run cache run cache run cache run cache run " 6
rm -f "$work/golangci-lint.calls"
expect 0 "make lint passes without LINT_CI" lint
expect_lint_calls "make lint without LINT_CI neither cleans nor measures" "run run run run run run " 0
unfake golangci-lint
fake actionlint 0 "v0.0.1"
expect nonzero "make actionlint fails when the pin is not installed and cannot be" actionlint
fake actionlint 0 "$pin-dirty"
expect nonzero "make actionlint accepts only the exact pinned version" actionlint
fake actionlint 0 "$pin"
expect nonzero "make actionlint fails when its config is missing" \
	ACTIONLINT_CONFIG="$work/missing-actionlint.yaml" actionlint
mkdir -p "$work/no-workflows" "$work/late-workflows"
expect nonzero "make actionlint fails when there are no workflows to lint" \
	ACTIONLINT_WORKFLOW_DIR="$work/no-workflows" actionlint
# The workflow is created by a prerequisite of actionlint, after make has
# parsed the Makefile: only a list built when the recipe runs can contain it.
expect 0 "make actionlint lints a workflow created after make started" \
	ACTIONLINT_WORKFLOW_DIR="$work/late-workflows" \
	--eval "actionlint: late-workflow" \
	--eval "late-workflow: ; @touch $work/late-workflows/late.yml" actionlint
expect_args actionlint "make actionlint passes the run-time workflow list to actionlint" \
	"$work/late-workflows/late.yml"
unfake actionlint
expect nonzero "make actionlint fails when actionlint is absent and cannot be installed" actionlint

if [ "$fails" -ne 0 ]; then
	echo "${fails} case(s) failed" >&2
	exit 1
fi
echo "all make gate cases passed"
