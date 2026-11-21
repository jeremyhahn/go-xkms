#!/bin/bash
# Shell-level tests for scripts/trim-ci-caches.sh (Tenant Agent ruling 966 (4)).
#
# The script bounds this repo's CI cache volumes on a runner host. Before 966 it
# only removed volumes no container used, so a busy host's gobuild volume grew
# to 57G and filled the disk. These tests pin the in-use path: trim inside the
# volume, whole cache entries, oldest first; never per-file trims of the module
# cache; REAP_DRY_RUN=1 touches nothing; unused volumes still go whole.
#
# No Docker daemon is involved: a fake `docker` on PATH records every
# invocation (one line each, newlines folded), serves canned `volume ls`, `ps`
# and `du` answers, and runs an in-volume `sh -c <script>` trim against a local
# directory standing in for the volume, so the entry selection itself is
# exercised. DOCKER_HOST points at a closed port, so a PATH mistake fails
# loudly instead of reaching a real daemon.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_UNDER_TEST="$REPO_ROOT/scripts/trim-ci-caches.sh"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

FAKE_BIN="$WORK_DIR/bin"
CALL_LOG="$WORK_DIR/docker-calls.log"
SIZES="$WORK_DIR/sizes"
VOLROOT="$WORK_DIR/volumes"
mkdir -p "$FAKE_BIN"

cat > "$FAKE_BIN/docker" <<'FAKE'
#!/bin/bash
# Fake docker. FAKE_SIZES: lines "<volume> <KiB>"; FAKE_INUSE: volumes a
# container mounts; FAKE_ROOT/<volume>: the volume's content for in-volume
# `sh -c` runs.
args="$*"
printf '%s\n' "${args//$'\n'/ }" >> "$FAKE_DOCKER_LOG"
case "$1 ${2:-}" in
  "volume ls") cut -d' ' -f1 "$FAKE_SIZES"; exit 0 ;;
  "volume rm") exit 0 ;;
  "ps -aq")
    v=
    for a in "$@"; do case $a in volume=*) v=${a#volume=} ;; esac; done
    case " $FAKE_INUSE " in *" $v "*) echo c0ffee ;; esac
    exit 0 ;;
esac
[ "$1" = run ] || exit 0
shift
vol= ep=
while [ $# -gt 0 ]; do
  case $1 in
    -v) vol=${2%%:*}; shift 2 ;;
    --entrypoint) ep=$2; shift 3; break ;;   # entrypoint, then the image
    *) shift ;;
  esac
done
# A read-write run (trim or clean) marks the volume; FAKE_AFTER: lines
# "<volume> <KiB>", the size du reports once the volume was cleaned (a
# concurrent build refilled it). Without a line du keeps the canned size.
case $ep in sh | go) : > "$FAKE_ROOT/.cleaned-$vol" ;; esac
case $ep in
  du)
    if [ -e "$FAKE_ROOT/.cleaned-$vol" ] && [ -f "${FAKE_AFTER:-}" ]; then
      while read -r v k; do [ "$v" = "$vol" ] && { printf '%s\t/c\n' "$k"; exit 0; }; done < "$FAKE_AFTER"
    fi
    while read -r v k; do [ "$v" = "$vol" ] && printf '%s\t/c\n' "$k"; done < "$FAKE_SIZES"
    exit 0 ;;
  sh)
    # sh -c <script> <name> /c [args...]: run it on the local stand-in.
    [ "$1" = -c ] || exit 1
    script=$2 name=$3
    shift 4
    [ -d "$FAKE_ROOT/$vol" ] || { echo 0; exit 0; }
    exec sh -c "$script" "$name" "$FAKE_ROOT/$vol" "$@" ;;
esac
exit 0
FAKE
chmod +x "$FAKE_BIN/docker"

FAILURES=0

start_case() { echo "--- $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }
pass() { echo "    ok: $1"; }

# setup "<volume> <KiB>"...: the volumes the fake daemon has.
setup() {
    rm -rf "$VOLROOT"
    mkdir -p "$VOLROOT"
    : > "$SIZES"
    local line
    for line in "$@"; do echo "$line" >> "$SIZES"; done
}

# entry <volume> <dir> <touch-date>: one 8 KiB cache file in <volume>/<dir>,
# the directory's mtime set to <touch-date>.
entry() {
    mkdir -p "$VOLROOT/$1/$2"
    head -c 8192 /dev/zero > "$VOLROOT/$1/$2/$2$2-a"
    touch -d "$3" "$VOLROOT/$1/$2/$2$2-a" "$VOLROOT/$1/$2"
}

# file_at <volume> <bucket> <name> <touch-date>: one 8 KiB cache file
# <volume>/<bucket>/<name> with its own mtime; the bucket's mtime is untouched.
file_at() {
    mkdir -p "$VOLROOT/$1/$2"
    head -c 8192 /dev/zero > "$VOLROOT/$1/$2/$3"
    touch -d "$4" "$VOLROOT/$1/$2/$3"
}

# run_script <expected-exit> <in-use volumes> [VAR=VALUE ...]; max-gib is 1.
run_script() {
    local expected_exit="$1" inuse="$2"; shift 2
    : > "$CALL_LOG"
    (
        cd "$REPO_ROOT" || exit 99
        env -u REAP_DRY_RUN -u CI_CACHE_MAX_GIB -u IN_IMAGE_UID \
            PATH="$FAKE_BIN:$PATH" \
            DOCKER_HOST="tcp://127.0.0.1:1" \
            FAKE_DOCKER_LOG="$CALL_LOG" FAKE_SIZES="$SIZES" \
            FAKE_INUSE="$inuse" FAKE_ROOT="$VOLROOT" \
            "$@" \
            bash "$SCRIPT_UNDER_TEST" p-ci- toolchain:test 1 >"$WORK_DIR/stdout" 2>"$WORK_DIR/stderr"
    )
    local actual=$?
    if [ "$actual" -ne "$expected_exit" ]; then
        fail "expected exit $expected_exit, got $actual"
        cat "$WORK_DIR/stderr" >&2
    fi
}

# rw_mounted <volume>: a container mounted <volume> read-write.
rw_mounted() { grep -q -- "-v $1:/c " "$CALL_LOG"; }
has_files() { [ -n "$(find "$VOLROOT/$1" -type f)" ]; }

# 1 GiB bound = 1048576 KiB. Totals are set a few KiB over it, so the trim must
# free real KiB out of the local stand-in.

# --------------------------------------------------------------------------
start_case "an in-use gobuild volume over the bound is trimmed inside"
setup "p-ci-cache-t-gobuild 1000000" "p-ci-cache-t-gomod 48588"
entry p-ci-cache-t-gobuild aa "2026-01-01"
entry p-ci-cache-t-gobuild bb "2026-02-01"
entry p-ci-cache-t-gobuild cc "2026-03-01"
entry p-ci-cache-t-gobuild dd "2026-04-01"
echo keep > "$VOLROOT/p-ci-cache-t-gobuild/README"
run_script 0 "p-ci-cache-t-gobuild p-ci-cache-t-gomod"
if rw_mounted p-ci-cache-t-gobuild; then
    pass "a trim container mounts the gobuild volume read-write"
else
    fail "no trim run mounted the in-use gobuild volume"
fi
if grep -q "^volume rm" "$CALL_LOG"; then
    fail "removed a volume a container uses"
else
    pass "no docker volume rm of an in-use volume"
fi
if grep -q -- "-v p-ci-cache-t-gobuild:/c .*--network none" "$CALL_LOG" ||
   grep -q -- "--network none.*-v p-ci-cache-t-gobuild:/c " "$CALL_LOG"; then
    pass "the trim container has no network"
else
    fail "the trim container is not --network none"
fi

# --------------------------------------------------------------------------
start_case "entries go whole, oldest first, until under the bound"
# 12 KiB over; each entry frees 8 KiB: the two oldest go, the two newest stay.
if ! has_files p-ci-cache-t-gobuild/aa && ! has_files p-ci-cache-t-gobuild/bb; then
    pass "the two oldest entries are gone"
else
    fail "the oldest entries were not removed"
fi
if has_files p-ci-cache-t-gobuild/cc && has_files p-ci-cache-t-gobuild/dd; then
    pass "the newer entries stay once enough is freed"
else
    fail "trimmed more than the bound needs"
fi
if [ -f "$VOLROOT/p-ci-cache-t-gobuild/README" ]; then
    pass "files outside the xx/ entries stay"
else
    fail "removed a file that is not a cache entry"
fi

# --------------------------------------------------------------------------
start_case "entries go by their own mtime across buckets, not by bucket mtime"
# A bucket holds unrelated entries and reading one does not touch the bucket's
# mtime, so bucket mtimes deliberately disagree with their files: aa is the
# newest bucket but holds the oldest file; bb is the oldest bucket but holds
# only a middle-aged file. 12 KiB over, 8 KiB a file: the two oldest files go.
setup "p-ci-cache-t-gobuild 1000000" "p-ci-cache-t-gomod 48588"
file_at p-ci-cache-t-gobuild aa aa01-a "2026-01-01"
file_at p-ci-cache-t-gobuild aa aa02-a "2026-06-01"
file_at p-ci-cache-t-gobuild bb bb01-a "2026-03-01"
file_at p-ci-cache-t-gobuild cc cc01-a "2026-05-01"
touch -d "2026-07-01" "$VOLROOT/p-ci-cache-t-gobuild/aa"
touch -d "2025-01-01" "$VOLROOT/p-ci-cache-t-gobuild/bb"
touch -d "2025-02-01" "$VOLROOT/p-ci-cache-t-gobuild/cc"
run_script 0 "p-ci-cache-t-gobuild p-ci-cache-t-gomod"
g="$VOLROOT/p-ci-cache-t-gobuild"
if [ ! -e "$g/aa/aa01-a" ] && [ ! -e "$g/bb/bb01-a" ]; then
    pass "the two oldest files, in different buckets, are gone"
else
    fail "the oldest files by their own mtime were not removed"
fi
if [ -f "$g/aa/aa02-a" ]; then
    pass "a newer file in the same bucket as an evicted one stays"
else
    fail "evicted a recently used file with its bucket"
fi
if [ -f "$g/cc/cc01-a" ]; then
    pass "a newer file in an old bucket stays"
else
    fail "evicted by bucket mtime, not file mtime"
fi
if [ -d "$g/aa" ] && [ -d "$g/bb" ] && [ -d "$g/cc" ]; then
    pass "bucket directories stay"
else
    fail "removed a bucket directory"
fi

# --------------------------------------------------------------------------
start_case "a gobuild volume over the bound on its own gets go clean -cache"
setup "p-ci-cache-t-gobuild 2000000"
run_script 0 "p-ci-cache-t-gobuild"
if grep -q -- "-e GOCACHE=/c .*--entrypoint go toolchain:test clean -cache" "$CALL_LOG" &&
   rw_mounted p-ci-cache-t-gobuild; then
    pass "go clean -cache on the mounted volume"
else
    fail "no go clean -cache for a gobuild volume over the bound alone"
fi

# --------------------------------------------------------------------------
start_case "in-use golangci is cleaned whole; in-use gomod is only reported"
setup "p-ci-cache-t-gomod 900000" "p-ci-cache-t-golangci 300000"
entry p-ci-cache-t-golangci ab "2026-05-01"
entry p-ci-cache-t-gomod cd "2026-01-01"
run_script 0 "p-ci-cache-t-gomod p-ci-cache-t-golangci"
if rw_mounted p-ci-cache-t-golangci && ! has_files p-ci-cache-t-golangci &&
   [ -d "$VOLROOT/p-ci-cache-t-golangci" ]; then
    pass "the golangci cache is emptied whole"
else
    fail "the in-use golangci volume was not cleaned"
fi
if rw_mounted p-ci-cache-t-gomod || ! has_files p-ci-cache-t-gomod; then
    fail "the module cache was trimmed inside"
else
    pass "the module cache is never trimmed inside"
fi
if grep -q "keep  p-ci-cache-t-gomod" "$WORK_DIR/stdout"; then
    pass "the in-use gomod volume is reported"
else
    fail "the in-use gomod volume over the bound is not reported"
fi

# --------------------------------------------------------------------------
start_case "a cleaned golangci volume is remeasured; trimming goes on while over"
# The clean succeeds, but a concurrent build refills golangci to 800000 KiB:
# the total stays over the bound, so the gobuild volume is trimmed too and the
# report counts the data left behind (1100000 KiB, 1 GiB), not an empty volume.
setup "p-ci-cache-t-golangci 900000" "p-ci-cache-t-gobuild 300000"
entry p-ci-cache-t-golangci ab "2026-05-01"
entry p-ci-cache-t-gobuild aa "2026-01-01"
echo "p-ci-cache-t-golangci 800000" > "$WORK_DIR/after"
run_script 0 "p-ci-cache-t-golangci p-ci-cache-t-gobuild" FAKE_AFTER="$WORK_DIR/after"
if grep -q -- "-v p-ci-cache-t-golangci:/c:ro" "$CALL_LOG" &&
   [ "$(grep -c -- "-v p-ci-cache-t-golangci:/c:ro" "$CALL_LOG")" -ge 2 ]; then
    pass "the golangci volume is measured again after its clean"
else
    fail "the cleaned golangci volume was not remeasured"
fi
if rw_mounted p-ci-cache-t-gobuild; then
    pass "trimming goes on while the remeasured total is over the bound"
else
    fail "stopped as if the cleaned volume were empty"
fi
if grep -q "1 GiB left" "$WORK_DIR/stdout"; then
    pass "the reported total is the remeasured one"
else
    fail "the reported total ignores the data left after the clean"
fi

# --------------------------------------------------------------------------
start_case "a gobuild volume after go clean -cache is remeasured; trimming goes on"
# go clean -cache succeeds, a concurrent build leaves 1500000 KiB: golangci is
# cleaned as well and the report reads 1600000 KiB (1 GiB), not 100000 KiB.
setup "p-ci-cache-t-gobuild 2000000" "p-ci-cache-t-golangci 100000"
entry p-ci-cache-t-golangci ab "2026-05-01"
echo "p-ci-cache-t-gobuild 1500000" > "$WORK_DIR/after"
run_script 0 "p-ci-cache-t-gobuild p-ci-cache-t-golangci" FAKE_AFTER="$WORK_DIR/after"
if [ "$(grep -c -- "-v p-ci-cache-t-gobuild:/c:ro" "$CALL_LOG")" -ge 2 ]; then
    pass "the gobuild volume is measured again after go clean -cache"
else
    fail "the cleaned gobuild volume was not remeasured"
fi
if rw_mounted p-ci-cache-t-golangci; then
    pass "trimming goes on while the remeasured total is over the bound"
else
    fail "stopped as if go clean -cache had emptied the volume"
fi
if grep -q "1 GiB left" "$WORK_DIR/stdout"; then
    pass "the reported total is the remeasured one"
else
    fail "the reported total ignores the data left after go clean -cache"
fi

# --------------------------------------------------------------------------
start_case "REAP_DRY_RUN=1 removes and trims nothing"
setup "p-ci-cache-t-gobuild 1000000" "p-ci-cache-u-gomod 48588" "p-ci-cache-t-golangci 600000"
entry p-ci-cache-t-gobuild aa "2026-01-01"
entry p-ci-cache-t-golangci ab "2026-01-01"
run_script 0 "p-ci-cache-t-gobuild p-ci-cache-t-golangci" REAP_DRY_RUN=1
if grep -q "^volume rm" "$CALL_LOG" || rw_mounted p-ci-cache-t-gobuild ||
   rw_mounted p-ci-cache-t-golangci || grep -q -- "clean -cache" "$CALL_LOG"; then
    fail "a dry run removed or trimmed something"
else
    pass "no rm and no trim run"
fi
if has_files p-ci-cache-t-gobuild && has_files p-ci-cache-t-golangci; then
    pass "volume contents untouched"
else
    fail "a dry run deleted cache entries"
fi
if grep -q "^dry" "$WORK_DIR/stdout"; then
    pass "the dry run says what it would do"
else
    fail "the dry run printed nothing it would do"
fi

# --------------------------------------------------------------------------
start_case "an unused volume over the bound is still removed whole"
setup "p-ci-cache-u-gomod 2000000" "p-ci-cache-t-gobuild 1000"
run_script 0 "p-ci-cache-t-gobuild"
if grep -q "^volume rm p-ci-cache-u-gomod$" "$CALL_LOG"; then
    pass "docker volume rm of the unused volume"
else
    fail "the unused volume over the bound was not removed"
fi
if rw_mounted p-ci-cache-t-gobuild; then
    fail "trimmed an in-use volume though removing the unused one was enough"
else
    pass "in-use volumes untouched once under the bound"
fi

# --------------------------------------------------------------------------
if [ "$FAILURES" -eq 0 ]; then
    echo "PASS: trim-ci-caches.sh trims in-use volumes inside, whole entries"
    exit 0
fi
echo "FAILED: $FAILURES assertion(s)" >&2
exit 1
