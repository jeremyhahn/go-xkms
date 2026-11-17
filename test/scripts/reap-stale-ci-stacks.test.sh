#!/usr/bin/env bash
# Tests for scripts/reap-stale-ci-stacks.sh: the image reclaim.
#
# #2243 (Codex P1-3): a CI_IMAGE_REGISTRY hit leaves two toolchain aliases,
# <registry>/go-xkms-toolchain:<hash> and go-xkms-toolchain:<hash>. Once no
# hold uses them and they are old enough, the reaper with the workflow's
# go-xkms-ci- prefix removes both; it keeps an image a live hold uses and
# touches nothing outside its scope.
#
# No Docker daemon is involved: a fake `docker` on PATH answers from a state
# file and records every removal. DOCKER_HOST points at a closed port, so a
# PATH mistake fails loudly.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_UNDER_TEST="$REPO_ROOT/scripts/reap-stale-ci-stacks.sh"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
FAKE_BIN="$WORK_DIR/bin"
CALL_LOG="$WORK_DIR/calls.log"
STATE="$WORK_DIR/images"
mkdir -p "$FAKE_BIN"

cat >"$FAKE_BIN/docker" <<'FAKE'
#!/bin/bash
# Fake docker. FAKE_STATE: one "<repository> <tag> <digest> <created> <last-tag-unix>"
# line per image name; FAKE_USED: the names a container (a live hold) uses.
echo "docker $*" >>"$FAKE_LOG"
removed() { grep -qxF "rm $1" "$FAKE_LOG.rm" 2>/dev/null; }
case "$1 $2" in
  "ps -aq")
    case "$4" in
      ancestor=*) case " ${FAKE_USED:-} " in *" ${4#ancestor=} "*) echo c0ffee000000 ;; esac ;;
    esac
    exit 0
    ;;
  "images --filter")
    want=${3#reference=}
    while read -r repo tag _ _ _; do
      [ "$repo" = "$want" ] || continue
      removed "$repo:$tag" || echo "$repo:$tag"
    done <"$FAKE_STATE"
    exit 0
    ;;
  "images --digests")
    while read -r repo tag digest _ _; do
      removed "$repo:$tag" || echo "$repo $tag $digest"
    done <"$FAKE_STATE"
    exit 0
    ;;
  "image inspect")
    ref=${*: -1}
    removed "$ref" && exit 1
    while read -r repo tag _ created tagged; do
      [ "$repo:$tag" = "$ref" ] || continue
      [ "$3" != -f ] || echo "$created $tagged"
      exit 0
    done <"$FAKE_STATE"
    exit 1
    ;;
  "image rm")
    case " ${FAKE_USED:-} " in *" $3 "*) echo "Error: conflict: image is in use" >&2; exit 1 ;; esac
    echo "rm $3" >>"$FAKE_LOG.rm"
    exit 0
    ;;
esac
exit 0
FAKE
chmod +x "$FAKE_BIN/docker"

FAILURES=0
start_case() { echo "--- $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }
pass() { echo "    ok: $1"; }

# run_reaper <prefix> [VAR=VALUE ...]: the reaper against $STATE.
run_reaper() {
  local prefix=$1
  shift
  : >"$CALL_LOG"
  : >"$CALL_LOG.rm"
  env -i PATH="$FAKE_BIN:/usr/bin:/bin" DOCKER_HOST="tcp://127.0.0.1:1" \
    FAKE_LOG="$CALL_LOG" FAKE_STATE="$STATE" "$@" \
    bash "$SCRIPT_UNDER_TEST" "$prefix" >"$WORK_DIR/stdout" 2>"$WORK_DIR/stderr"
  local rc=$?
  [ "$rc" -eq 0 ] || { fail "reaper exited $rc"; sed 's/^/      /' "$WORK_DIR/stderr" >&2; }
}
removed() {
  if grep -qxF "rm $1" "$CALL_LOG.rm"; then pass "removed $1"; else fail "kept $1"; fi
}
kept() {
  if grep -qxF "rm $1" "$CALL_LOG.rm"; then fail "removed $1"; else pass "kept $1"; fi
}

LAN=lan.invalid:5000
OLD=2020-01-01T00:00:00Z
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
NOW_UNIX=$(date +%s)
cat >"$STATE" <<EOF
$LAN/go-xkms-toolchain 0123456789abcdef <none> $OLD 1577836800
go-xkms-toolchain 0123456789abcdef <none> $OLD 1577836800
$LAN/go-xkms-toolchain 1111111111111111 <none> $OLD 1577836800
go-xkms-toolchain 1111111111111111 <none> $OLD 1577836800
$LAN/go-xkms-toolchain 2222222222222222 <none> $NOW $NOW_UNIX
go-xkms-toolchain 2222222222222222 <none> $NOW $NOW_UNIX
$LAN/team/go-xkms-toolchain 0123456789abcdef <none> $OLD 1577836800
team/go-xkms-toolchain 0123456789abcdef <none> $OLD 1577836800
registry.example:5000/go-xkms-toolchain 0123456789abcdef <none> $OLD 1577836800
localhost/go-xkms-toolchain 0123456789abcdef <none> $OLD 1577836800
other-toolchain 0123456789abcdef <none> $OLD 1577836800
go-xkms-toolchain-x 0123456789abcdef <none> $OLD 1577836800
redis 7 <none> $OLD 1577836800
EOF
HELD="$LAN/go-xkms-toolchain:1111111111111111 go-xkms-toolchain:1111111111111111"

start_case "reap: a released CI_IMAGE_REGISTRY hit's two toolchain aliases are removed"
run_reaper go-xkms-ci- FAKE_USED="$HELD"
removed "$LAN/go-xkms-toolchain:0123456789abcdef"
removed "go-xkms-toolchain:0123456789abcdef"
removed "registry.example:5000/go-xkms-toolchain:0123456789abcdef"
removed "localhost/go-xkms-toolchain:0123456789abcdef"

# Codex round 4 P1-1: a first path element with no "." or ":" and not
# "localhost" is a Docker Hub owner namespace, not a registry host.
start_case "reap: a Docker Hub owner's toolchain image is not an alias"
kept "team/go-xkms-toolchain:0123456789abcdef"

start_case "reap: the aliases of an image a live hold uses are kept"
kept "$LAN/go-xkms-toolchain:1111111111111111"
kept "go-xkms-toolchain:1111111111111111"

start_case "reap: aliases tagged within REAP_IMAGE_MIN_AGE are kept"
kept "$LAN/go-xkms-toolchain:2222222222222222"
kept "go-xkms-toolchain:2222222222222222"

start_case "reap: nothing outside the prefix's scope is touched"
kept "$LAN/team/go-xkms-toolchain:0123456789abcdef"
kept "other-toolchain:0123456789abcdef"
kept "go-xkms-toolchain-x:0123456789abcdef"
kept "redis:7"

start_case "reap: a prefix that names no CI images touches no toolchain alias"
run_reaper other-ci-
kept "$LAN/go-xkms-toolchain:0123456789abcdef"
kept "go-xkms-toolchain:0123456789abcdef"

start_case "reap: REAP_DRY_RUN=1 removes nothing"
run_reaper go-xkms-ci- REAP_DRY_RUN=1
kept "go-xkms-toolchain:0123456789abcdef"
if grep -qF "dry   docker image rm go-xkms-toolchain:0123456789abcdef" "$WORK_DIR/stdout"; then
  pass "says what it would remove"
else
  fail "no dry line for go-xkms-toolchain:0123456789abcdef"
fi

if [ "$FAILURES" -ne 0 ]; then
  echo "FAILED: $FAILURES assertion(s)"
  exit 1
fi
echo "PASS: reap-stale-ci-stacks.sh reclaims the toolchain aliases in its scope"
