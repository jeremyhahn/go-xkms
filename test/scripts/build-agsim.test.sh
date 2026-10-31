#!/usr/bin/env bash
#
# Tests for scripts/build-agsim.sh: fake `go` and `make` commands on PATH stand
# in for the module machinery and the arduino-generic build, so the suite
# checks the script's pinning and error reporting without a network or a C
# toolchain. The script reads its pins from agsim.sum beside it, so a copy of
# it runs from a work directory holding a test pin (DS-3754).
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
set +e
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n    want: %s\n    got:  %s\n' "$1" "$2" "$3" >&2; }
eq() { if [ "$2" = "$3" ]; then ok "$1"; else no "$1" "$2" "$3"; fi; }
has() { case "$3" in *"$2"*) ok "$1" ;; *) no "$1" "output containing '$2'" "$3" ;; esac; }
section() { printf '\n%s\n' "$1"; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

MODULE=github.com/jeremyhahn/arduino-generic
VERSION=v0.0.1-test
SUM='h1:pinnedpinnedpinnedpinnedpinnedpinnedpinnedpin='

mkdir -p "$WORK/scripts" "$WORK/bin" "$WORK/src"
cp "$ROOT/scripts/build-agsim.sh" "$WORK/scripts/"
printf '%s %s %s\n' "$MODULE" "$VERSION" "$SUM" > "$WORK/scripts/agsim.sum"

# go: FAKE_GO_LIST_FAIL makes `go list` fail; FAKE_GO_DOWNLOAD is ok (the
# pinned Sum), mismatch (another Sum) or error (an Error field and exit 1,
# the way `go mod download -json` reports a failure: on stdout only).
cat > "$WORK/bin/go" <<'EOF'
#!/usr/bin/env bash
case "$1 $2" in
"list -m")
	[ -z "${FAKE_GO_LIST_FAIL:-}" ] || { echo "go: module lookup disabled by GOPROXY=off" >&2; exit 1; }
	case "$5" in
	*/sdk/go) echo "$FAKE_VERSION" ;;
	*) echo "$FAKE_SRC" ;;
	esac
	;;
"mod download")
	case "${FAKE_GO_DOWNLOAD:-ok}" in
	ok) printf '{\n\t"Path": "%s",\n\t"Sum": "%s",\n\t"GoModSum": "h1:x="\n}\n' "$4" "$FAKE_SUM" ;;
	mismatch) printf '{\n\t"Path": "%s",\n\t"Sum": "h1:other=",\n\t"GoModSum": "h1:x="\n}\n' "$4" ;;
	error)
		printf '{\n\t"Path": "%s",\n\t"Error": "%s: verifying module: module lookup disabled by GOPROXY=off",\n\t"Info": "/x.info"\n}\n' "$4" "$4"
		exit 1
		;;
	esac
	;;
*) echo "fake go: unexpected: $*" >&2; exit 2 ;;
esac
EOF
# make -C DIR TARGET...: writes each TARGET into DIR/build/host.
cat > "$WORK/bin/make" <<'EOF'
#!/usr/bin/env bash
dir=$2
shift 2
mkdir -p "$dir/build/host"
for t in "$@"; do printf '#!/bin/sh\n' > "$dir/build/host/$t"; done
EOF
chmod +x "$WORK/bin/go" "$WORK/bin/make"

# run DIR [VAR=value...] -- runs the copied script into DIR with the fakes.
run() {
	local dir=$1
	shift
	env PATH="$WORK/bin:$PATH" FAKE_VERSION="$VERSION" FAKE_SUM="$SUM" FAKE_SRC="$WORK/src" "$@" \
		bash "$WORK/scripts/build-agsim.sh" "$dir" 2>&1
}

section "builds the pinned version"
OUT=$(run "$WORK/out1"); RC=$?
eq "exits 0" "0" "$RC"
has "reports the build" "agsim $VERSION built in $WORK/out1" "$OUT"
eq "installs agsim" "yes" "$([ -x "$WORK/out1/agsim" ] && echo yes)"
eq "installs agsim-atecc608a" "yes" "$([ -x "$WORK/out1/agsim-atecc608a" ] && echo yes)"
eq "stamps the version" "$VERSION" "$(cat "$WORK/out1/.version")"
OUT=$(run "$WORK/out1" FAKE_GO_DOWNLOAD=error); RC=$?
eq "a built DIR is left alone, with no download" "0" "$RC"
has "says it is already built" "already built" "$OUT"

section "reports a failed download"
OUT=$(run "$WORK/out2" FAKE_GO_DOWNLOAD=error); RC=$?
eq "exits 1" "1" "$RC"
has "names the failing command" "go mod download $MODULE@$VERSION failed" "$OUT"
has "carries go's error out of the JSON" "verifying module: module lookup disabled by GOPROXY=off" "$OUT"
has "says what an offline stage needs" "GOPRIVATE covering $MODULE" "$OUT"
eq "builds nothing" "no" "$([ -e "$WORK/out2" ] && echo yes || echo no)"

section "rejects a hash the pin does not match"
OUT=$(run "$WORK/out3" FAKE_GO_DOWNLOAD=mismatch); RC=$?
eq "exits 1" "1" "$RC"
has "names both hashes" "hashes to 'h1:other=', $WORK/scripts/agsim.sum pins '$SUM'" "$OUT"
eq "builds nothing" "no" "$([ -e "$WORK/out3" ] && echo yes || echo no)"

section "reports a failed version lookup"
OUT=$(run "$WORK/out4" FAKE_GO_LIST_FAIL=1); RC=$?
eq "exits 1" "1" "$RC"
has "names the failing command" "go list -m $MODULE/sdk/go failed" "$OUT"
has "keeps go's own error" "module lookup disabled by GOPROXY=off" "$OUT"

section "rejects a version with no pin"
OUT=$(run "$WORK/out5" FAKE_VERSION=v9.9.9); RC=$?
eq "exits 1" "1" "$RC"
has "names the missing pin" "$MODULE v9.9.9 has no hash" "$OUT"

printf '\nbuild-agsim.sh: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
