#!/usr/bin/env bash
#
# Tests for scripts/in-toolchain-image.sh's disk-backed scratch: a stage's
# TMPDIR, GOTMPDIR and TRIVY_CACHE_DIR live on the scratch volume, not the
# 3 GB /tmp tmpfs (trivy's Java DB filled /tmp on main runs 66181 and 68251),
# and a scratch directory the image lacks fails the stage by name. A fake
# `docker` on PATH runs the container's command here with the --env values
# `docker create` was given; a fake `trivy` records what it saw.
#
# It also covers the daemon CPU cap: `docker info --format '{{.NCPU}}'`
# answers FAKE_NCPU (exit FAKE_NCPU_RC), and a positive integer below the
# computed bound lowers --cpus, GOMAXPROCS and GOFLAGS=-p to it; empty, 0,
# malformed or failed output leaves the bound as it was.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/scripts/in-toolchain-image.sh"
set +e
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n    want: %s\n    got:  %s\n' "$1" "$2" "$3" >&2; }
eq() { [ "$2" = "$3" ] && ok "$1" || no "$1" "$2" "$3"; }
has() { grep -qxF -- "$3" "$2" && ok "$1" || no "$1" "line '$3' in $2" "$(tr '\n' ' ' <"$2")"; }
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
  info)
    shift
    printf '%s\n' "$@" >"$FAKE_STATE/info.args"
    printf '%s\n' "${FAKE_NCPU:-}"
    exit "${FAKE_NCPU_RC:-0}" ;;
  run) exit 0 ;;
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
    mapfile -t envs <"$FAKE_STATE/env"
    exec env -i PATH="$PATH" FAKE_STATE="$FAKE_STATE" "${envs[@]}" sh -c "$(cat "$FAKE_STATE/cmd")" ;;
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
		PATH="$WORK/bin:$PATH" IN_IMAGE_CPUS=2 IN_IMAGE_NETWORK=bridge "$@" \
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

# --- the daemon's NCPU caps the CPU bound -----------------------------------
# cpus CASE WANT [VAR=value...] -- runs the script with the given environment
# and checks --cpus, GOMAXPROCS and GOFLAGS on `docker create` are all WANT.
cpus() {
	local name=$1 want=$2
	shift 2
	run "$@"
	eq "$name: the stage exits 0" "0" "$RC"
	local got
	got=$(sed -n '/^--cpus$/{n;p;q}' "$FAKE_STATE/create.args")
	eq "$name: --cpus" "$want" "$got"
	has "$name: GOMAXPROCS" "$FAKE_STATE/create.args" "GOMAXPROCS=$want"
	has "$name: GOFLAGS" "$FAKE_STATE/create.args" "GOFLAGS=-p=$want"
}
section "daemon CPU cap"
cpus "host 128, daemon 80" 80 IN_IMAGE_CPUS=128 FAKE_NCPU=80
has "the daemon is asked for its NCPU" "$FAKE_STATE/info.args" "{{.NCPU}}"
cpus "requested 4, daemon 80" 4 IN_IMAGE_CPUS=4 FAKE_NCPU=80
cpus "daemon equal to the bound" 16 IN_IMAGE_CPUS=16 FAKE_NCPU=16
cpus "daemon output empty" 128 IN_IMAGE_CPUS=128 FAKE_NCPU=
cpus "daemon output 0" 128 IN_IMAGE_CPUS=128 FAKE_NCPU=0
cpus "daemon output malformed" 128 IN_IMAGE_CPUS=128 FAKE_NCPU=abc
cpus "docker info fails with no output" 128 IN_IMAGE_CPUS=128 FAKE_NCPU= FAKE_NCPU_RC=1
# An unreachable daemon: the CLI still renders the template (NCPU 0) and exits 1.
cpus "docker info fails printing 0" 128 IN_IMAGE_CPUS=128 FAKE_NCPU=0 FAKE_NCPU_RC=1
# A failed lookup that still prints a positive count must not cap: only a zero exit counts.
cpus "docker info fails printing 80" 128 IN_IMAGE_CPUS=128 FAKE_NCPU=80 FAKE_NCPU_RC=1

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
exit $?
