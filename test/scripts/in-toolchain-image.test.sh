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

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
exit $?
