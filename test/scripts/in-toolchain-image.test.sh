#!/usr/bin/env bash
#
# Tests for scripts/in-toolchain-image.sh's disk-backed scratch: a stage's
# TMPDIR, GOTMPDIR and TRIVY_CACHE_DIR live on the scratch volume, not the
# 3 GB /tmp tmpfs (trivy's Java DB filled /tmp on main runs 66181 and 68251),
# and a scratch directory the image lacks fails the stage by name. A fake
# `docker` on PATH runs the container's command here with the --env values
# `docker create` was given; a fake `trivy` records what it saw.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/scripts/in-toolchain-image.sh"
set +e
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n    want: %s\n    got:  %s\n' "$1" "$2" "$3" >&2; }
eq() { if [ "$2" = "$3" ]; then ok "$1"; else no "$1" "$2" "$3"; fi; }
has() { if grep -qxF -- "$3" "$2"; then ok "$1"; else no "$1" "line '$3' in $2" "$(tr '\n' ' ' <"$2")"; fi; }
section() { printf '\n%s\n' "$1"; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin" "$WORK/src" "$WORK/scratch"
export FAKE_STATE="$WORK/state"

cat >"$WORK/bin/docker" <<'EOF'
#!/usr/bin/env bash
# Fake docker: create records its arguments, the --env values and the
# `sh -c` command; start runs that command with only those values set.
case $1 in
  run)
    # A cache-lock holder (`sh -c <hold> ci-cache-lock /c <mode>`) runs here
    # on FAKE_ROOT/<volume>, the volume on the daemon host; any other run
    # does nothing.
    shift
    vol=
    while [ "$#" -gt 0 ]; do
      case $1 in
        -v) vol=${2%%:*}; shift 2 ;;
        --entrypoint) shift 3; break ;;
        *) shift ;;
      esac
    done
    if [ "${1:-}" = -c ] && [ "${3:-}" = ci-cache-lock ]; then
      mkdir -p "$FAKE_ROOT/$vol" 2>/dev/null
      exec sh -c "$2" "$3" "$FAKE_ROOT/$vol" "$5"
    fi
    exit 0 ;;
  cp) cat >/dev/null; exit 0 ;;
  rm) shift; printf '%s\n' "$@" >"$FAKE_STATE/rm.args"; exit 0 ;;
  create)
    shift
    printf '%s\n' "$@" >"$FAKE_STATE/create.args"
    : >"$FAKE_STATE/env"
    while [ "$#" -gt 0 ]; do
      case $1 in
        --env) case $2 in *=*) printf '%s\n' "$2" >>"$FAKE_STATE/env" ;; esac; shift 2 ;;
        sh) if [ "${2:-}" = -c ]; then printf '%s' "$3" >"$FAKE_STATE/cmd"; break; fi; shift ;;
        *) shift ;;
      esac
    done
    exit 0 ;;
  start)
    # FAKE_LOCK: a cache volume's lock file; records whether the stage runs
    # under a lock that keeps the trim's exclusive flock out.
    if [ -n "${FAKE_LOCK:-}" ]; then
      if [ ! -e "$FAKE_LOCK" ]; then echo missing
      elif flock -n -x "$FAKE_LOCK" true; then echo free
      else echo held; fi >"$FAKE_STATE/lock"
    fi
    # FAKE_TRIM: a trim in another job container on this volume's lock; it
    # evicts entries the stage resolved when it gets the exclusive lock while
    # the stage runs on the shared cache volume.
    if [ -n "${FAKE_TRIM:-}" ]; then
      mkdir -p "$(dirname "$FAKE_TRIM")"
      if ! flock -n -x "$FAKE_TRIM" true; then echo kept-out
      elif grep -q ':/cache/gobuild$' "$FAKE_STATE/create.args"; then echo evicted
      else echo private; fi >"$FAKE_STATE/trim"
    fi
    mapfile -t envs <"$FAKE_STATE/env"
    # The caller's Go caches, each only when set, before the container's -e
    # values (#2295).
    go_env=()
    for v in GOMODCACHE GOPATH GOFLAGS GOPROXY GOSUMDB GOCACHE; do
      if [ -n "${!v+x}" ]; then go_env+=("$v=${!v}"); fi
    done
    exec env -i PATH="$PATH" FAKE_STATE="$FAKE_STATE" "${go_env[@]}" "${envs[@]}" sh -c "$(cat "$FAKE_STATE/cmd")" ;;
esac
echo "fake docker: unexpected $*" >&2
exit 99
EOF
cat >"$WORK/bin/trivy" <<'EOF'
#!/usr/bin/env bash
printf 'TMPDIR=%s\nTRIVY_CACHE_DIR=%s\nargs=%s\n' "$TMPDIR" "$TRIVY_CACHE_DIR" "$*" >"$FAKE_STATE/trivy.out"
EOF
chmod +x "$WORK/bin/docker" "$WORK/bin/trivy"

# run [VAR=value...] -- runs the script on a trivy scan from an empty
# checkout, with a fresh fake-docker state; sets OUT and RC.
run() {
	rm -rf "$FAKE_STATE"
	mkdir -p "$FAKE_STATE"
	OUT=$(cd "$WORK/src" && env -u GOPRIVATE -u GIT_CONFIG_COUNT -u GIT_CONFIG_KEY_0 -u GIT_CONFIG_VALUE_0 \
		PATH="$WORK/bin:$PATH" IN_IMAGE_CPUS=2 IN_IMAGE_NETWORK=bridge \
		FAKE_ROOT="$WORK/vols" "$@" \
		"$SCRIPT" toolchain:test trivy image --input it-image.tar --exit-code 1 2>&1)
	RC=$?
}

# --- default: trivy's temp and cache on the /var/tmp scratch volume ----------
section "default scratch"
run
eq "the stage exits 0" "0" "$RC"
has "/var/tmp is an anonymous volume, not the tmpfs" "$FAKE_STATE/create.args" "/var/tmp"
has "TMPDIR is the scratch volume" "$FAKE_STATE/create.args" "TMPDIR=/var/tmp"
has "GOTMPDIR is the scratch volume" "$FAKE_STATE/create.args" "GOTMPDIR=/var/tmp"
has "TRIVY_CACHE_DIR is on the scratch volume" "$FAKE_STATE/create.args" "TRIVY_CACHE_DIR=/var/tmp/trivy"
has "trivy ran with TMPDIR on the scratch volume" "$FAKE_STATE/trivy.out" "TMPDIR=/var/tmp"
has "trivy ran with its cache on the scratch volume" "$FAKE_STATE/trivy.out" "TRIVY_CACHE_DIR=/var/tmp/trivy"
has "trivy got the step's arguments unchanged" "$FAKE_STATE/trivy.out" "args=image --input it-image.tar --exit-code 1"
has "teardown removes the scratch volume (docker rm -v)" "$FAKE_STATE/rm.args" "-v"

# --- IN_IMAGE_SCRATCH moves all three to one place ---------------------------
section "IN_IMAGE_SCRATCH"
run IN_IMAGE_SCRATCH="$WORK/scratch"
eq "the stage exits 0" "0" "$RC"
has "trivy's TMPDIR follows IN_IMAGE_SCRATCH" "$FAKE_STATE/trivy.out" "TMPDIR=$WORK/scratch"
has "trivy's cache follows IN_IMAGE_SCRATCH" "$FAKE_STATE/trivy.out" "TRIVY_CACHE_DIR=$WORK/scratch/trivy"
has "GOTMPDIR follows IN_IMAGE_SCRATCH" "$FAKE_STATE/create.args" "GOTMPDIR=$WORK/scratch"

# --- GOFLAGS: the caller's flags (-trimpath, #2309) survive the -p cap -------
section "GOFLAGS"
run GOFLAGS=-trimpath
eq "the stage exits 0" "0" "$RC"
has "the caller's GOFLAGS are kept before -p" "$FAKE_STATE/create.args" "GOFLAGS=-trimpath -p=2"
run GOFLAGS=
eq "the stage exits 0" "0" "$RC"
has "with no caller GOFLAGS only -p is set" "$FAKE_STATE/create.args" "GOFLAGS=-p=2"

# --- a missing scratch directory fails by name, before trivy runs ------------
section "missing scratch directory"
run IN_IMAGE_SCRATCH="$WORK/missing"
eq "the stage exits 2" "2" "$RC"
eq "the error names the missing directory" \
	"in-toolchain-image: scratch directory $WORK/missing is missing or not writable" "$OUT"
eq "trivy never ran" "no" "$([ -e "$FAKE_STATE/trivy.out" ] && echo yes || echo no)"

# --- a relative IN_IMAGE_SCRATCH is refused before any container -------------
section "relative IN_IMAGE_SCRATCH"
run IN_IMAGE_SCRATCH=var/tmp
eq "the script exits 2" "2" "$RC"
eq "the error names the variable" "IN_IMAGE_SCRATCH must be an absolute path: var/tmp" "$OUT"
eq "no container was created" "no" "$([ -e "$FAKE_STATE/create.args" ] && echo yes || echo no)"

# --- each cache volume is held shared for the whole run ----------------------
# scripts/trim-ci-caches.sh takes a volume's lock exclusively before it cleans
# or unlinks anything in it, so a held lock keeps it off a running build. The
# lock is <volume>/.ci-cache.lock, on the daemon host (FAKE_ROOT here), so the
# trim in another job container sees it.
section "cache volume locks"
for v in gobuild golangci gomod; do
	run FAKE_LOCK="$WORK/vols/src-ci-cache-pr-$v/.ci-cache.lock"
	eq "the stage exits 0 ($v)" "0" "$RC"
	eq "the $v volume's lock is held while the stage runs" "held" "$(cat "$FAKE_STATE/lock" 2>/dev/null)"
done
run FAKE_LOCK="$WORK/vols/src-ci-cache-pr-gobuild/.ci-cache.lock"
eq "the lock is released when the script exits" "free" \
	"$(if flock -n -x "$WORK/vols/src-ci-cache-pr-gobuild/.ci-cache.lock" true; then echo free; else echo held; fi)"
run FAKE_ROOT=/proc/no-such-volume-root
eq "a lock that cannot be taken never blocks the build" "0" "$RC"
eq "it warns and falls back to private caches" "yes" \
	"$(case $OUT in *"in-toolchain-image: warn: cache lock in volume src-ci-cache-pr-gobuild not taken; using private caches"*) echo yes ;; *) echo no ;; esac)"

# --- a stage without its cache lock never mounts the shared caches ------------
# A job-local mktemp or mkfifo failure leaves no shared lock: a trim in another
# job container then takes the volume's exclusive lock, so the stage must run
# on private caches, never on the shared volumes unlocked (Codex P1 on #2322).
section "lock setup failure"
mkdir -p "$WORK/failbin"
for tool in mktemp mkfifo; do
	rm -f "$WORK/failbin/"*
	printf '#!/bin/sh\nexit 1\n' >"$WORK/failbin/$tool"
	chmod +x "$WORK/failbin/$tool"
	run PATH="$WORK/failbin:$WORK/bin:$PATH" FAKE_TRIM="$WORK/vols/src-ci-cache-pr-gobuild/.ci-cache.lock"
	eq "the stage exits 0 when $tool fails" "0" "$RC"
	eq "a concurrent trim never evicts under the stage when $tool fails" "private" \
		"$(cat "$FAKE_STATE/trim" 2>/dev/null)"
	eq "no shared cache volume is mounted when $tool fails" "no" \
		"$(grep -q 'src-ci-cache-pr-' "$FAKE_STATE/create.args" && echo yes || echo no)"
	eq "GOCACHE is not the shared volume when $tool fails" "no" \
		"$(grep -q '^GOCACHE=/cache/' "$FAKE_STATE/env" && echo yes || echo no)"
done

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
exit $?
