#!/usr/bin/env bash
#
# Tests for scripts/in-toolchain-image.sh's disk-backed scratch: a stage's
# TMPDIR, GOTMPDIR and TRIVY_CACHE_DIR live on the scratch volume, not the
# 3 GB /tmp tmpfs (trivy's Java DB filled /tmp on main runs 66181 and 68251),
# and a scratch directory the image lacks fails the stage by name. A fake
# `docker` on PATH runs the container's command here with the --env values
# `docker create` was given; a fake `trivy` records what it saw.
#
# IN_IMAGE_EXPORT has its cases too: a path outside /src is refused before any
# container, a path the stage did not produce fails the stage, and a produced
# one comes back under $PWD. The fake `trivy` leaves the files of
# $WORK/produced in the container's /src, where the fake `docker cp` finds them.
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
  cp)
    # Copy-in (`cp -a - NAME:/src`) swallows the tar stream; copy-back
    # (`cp NAME:/src/PATH DEST`) copies what the stage left in the container.
    if [ "$2" = -a ]; then cat >/dev/null; exit 0; fi
    from="$FAKE_STATE/src/${2#*:/src/}"
    [ -f "$from" ] || exit 1
    cp "$from" "$3"
    exit $? ;;
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
# The stage's outputs: what the test staged in produced/ lands in /src.
if [ -d "$FAKE_STATE/../produced" ]; then
  mkdir -p "$FAKE_STATE/src"
  cp -R "$FAKE_STATE/../produced/." "$FAKE_STATE/src/"
fi
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

# --- IN_IMAGE_EXPORT: only paths under /src, and every one must be produced --
section "IN_IMAGE_EXPORT"
run IN_IMAGE_EXPORT=/coverage/shard-1.out
eq "an absolute path exits 2" "2" "$RC"
eq "the error names the absolute path" \
	"IN_IMAGE_EXPORT paths must be relative to /src with no ..: /coverage/shard-1.out" "$OUT"
eq "no container was created for an absolute path" "no" "$([ -e "$FAKE_STATE/create.args" ] && echo yes || echo no)"

run IN_IMAGE_EXPORT="coverage/shard-1.out coverage/../../shard-2.out"
eq "a path with .. exits 2" "2" "$RC"
eq "the error names the path with .." \
	"IN_IMAGE_EXPORT paths must be relative to /src with no ..: coverage/../../shard-2.out" "$OUT"
eq "no container was created for a path with .." "no" "$([ -e "$FAKE_STATE/create.args" ] && echo yes || echo no)"

run IN_IMAGE_EXPORT=coverage/shard-1.out
eq "a path the stage did not produce exits 1" "1" "$RC"
eq "the error names the path that was not produced" \
	"in-toolchain-image: IN_IMAGE_EXPORT path coverage/shard-1.out was not produced" "$OUT"
eq "the stage ran before the export failed" "yes" "$([ -e "$FAKE_STATE/trivy.out" ] && echo yes || echo no)"
eq "nothing was copied back" "no" "$([ -e "$WORK/src/coverage/shard-1.out" ] && echo yes || echo no)"

mkdir -p "$WORK/produced/coverage"
printf 'mode: atomic\npkg/a.go:1.1,2.2 1 1\n' >"$WORK/produced/coverage/shard-1.out"
printf '{"Action":"pass"}\n' >"$WORK/produced/shard-1.json"
run IN_IMAGE_EXPORT="coverage/shard-1.out shard-1.json"
eq "a stage that produced its exports exits 0" "0" "$RC"
eq "the first export is copied back with the same bytes" "same" \
	"$(cmp -s "$WORK/produced/coverage/shard-1.out" "$WORK/src/coverage/shard-1.out" && echo same || echo differs)"
eq "the second export is copied back with the same bytes" "same" \
	"$(cmp -s "$WORK/produced/shard-1.json" "$WORK/src/shard-1.json" && echo same || echo differs)"
rm -rf "$WORK/produced"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
exit $?
