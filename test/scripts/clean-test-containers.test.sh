#!/bin/bash
# Shell-level tests for test/scripts/clean-test-containers.sh.
#
# The script under test decides WHICH Docker resources a CI run may destroy, on
# Actions hosts whose daemon is SHARED with every other repository (go-xkms#2,
# the 2026-08-17 shared-runner incident). These tests pin that safety boundary.
#
# History worth keeping, because it explains what the assertions are guarding
# against. Two branches fixed the same incident differently: issue #2 kept the
# host-global machinery (name-substring sweeps, fixed-port sweeps, prunes) and
# gated it behind XKMS_CLEAN_SCOPE=project under CI; issue #8 deleted the
# machinery outright and namespaced every compose project per run instead. The
# consolidation took issue #8's script, because a capability that is merely
# switched off can be switched back on by anyone who does not know why it was
# off — and rewrote these tests, which were issue #2's, to pin issue #8's
# boundary. The point of the file is unchanged: prove the script cannot reach
# outside this run.
#
# No Docker daemon is involved: a fake `docker` on PATH records every
# invocation and answers queries. DOCKER_HOST also points at a closed port, so
# a PATH mistake fails loudly instead of reaching a real daemon.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_UNDER_TEST="$REPO_ROOT/test/scripts/clean-test-containers.sh"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

FAKE_BIN="$WORK_DIR/bin"
CALL_LOG="$WORK_DIR/docker-calls.log"
mkdir -p "$FAKE_BIN"

cat > "$FAKE_BIN/docker" <<'FAKE'
#!/bin/bash
# Fake docker: record the full argument vector, one invocation per line, and
# succeed. The script under test only ever needs `compose ... down` and the two
# prunes, so nothing here needs to answer a query.
echo "$*" >> "$FAKE_DOCKER_LOG"
exit 0
FAKE
chmod +x "$FAKE_BIN/docker"

FAILURES=0

start_case() { echo "--- $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }
pass() { echo "    ok: $1"; }

# run_script <expected-exit> [VAR=VALUE ...]
run_script() {
    local expected_exit="$1"; shift
    : > "$CALL_LOG"
    (
        cd "$REPO_ROOT" || exit 99
        env -u CI -u GITHUB_ACTIONS -u COMPOSE_RUN_ID -u GITHUB_RUN_ID \
            PATH="$FAKE_BIN:$PATH" \
            DOCKER_HOST="tcp://127.0.0.1:1" \
            FAKE_DOCKER_LOG="$CALL_LOG" \
            "$@" \
            bash "$SCRIPT_UNDER_TEST" >"$WORK_DIR/stdout" 2>"$WORK_DIR/stderr"
    )
    local actual=$?
    if [ "$actual" -ne "$expected_exit" ]; then
        fail "expected exit $expected_exit, got $actual"
        sed 's/^/      /' "$WORK_DIR/stderr" >&2
    fi
}

# --------------------------------------------------------------------------
start_case "every teardown is scoped to this run's project name"
run_script 0 COMPOSE_RUN_ID=run42
if [ ! -s "$CALL_LOG" ]; then
    fail "the script issued no docker calls at all"
fi
# Every compose invocation must carry -p go-xkms-run42-<lane>.
bad=0
while read -r line; do
    case "$line" in
        compose\ *)
            case "$line" in
                *"-p go-xkms-run42-"*) ;;
                *) echo "      unscoped: $line" >&2; bad=1 ;;
            esac
            ;;
    esac
done < "$CALL_LOG"
if [ "$bad" -eq 0 ]; then
    pass "all compose teardowns carry -p go-xkms-<run-id>-<lane>"
else
    fail "a compose teardown ran without this run's project name"
fi

# --------------------------------------------------------------------------
start_case "the run id actually reaches the project name"
if grep -q -- "-p go-xkms-run42-" "$CALL_LOG"; then
    pass "COMPOSE_RUN_ID is interpolated into the project name"
else
    fail "COMPOSE_RUN_ID did not reach any project name"
fi
run_script 0
if grep -q -- "-p go-xkms-local-" "$CALL_LOG"; then
    pass "falls back to the 'local' run id off CI"
else
    fail "no fallback run id when COMPOSE_RUN_ID and GITHUB_RUN_ID are unset"
fi

# --------------------------------------------------------------------------
start_case "no host-global search of any kind"
# These are the exact capabilities that destroyed other repositories' jobs.
# The script must never regain them. `docker ps` in any form is a search of
# the whole daemon; stop/rm act on whatever such a search returned.
run_script 0 COMPOSE_RUN_ID=run42 CI=true
for forbidden in "ps " "stop " "rm " "network ls" "network rm" "volume ls" "volume rm" "kill "; do
    if grep -q "^${forbidden}" "$CALL_LOG"; then
        fail "script ran a host-global 'docker ${forbidden}'"
    else
        pass "never runs 'docker ${forbidden}'"
    fi
done
if grep -q -- "--filter" "$CALL_LOG"; then
    fail "script filtered the daemon's own object list"
else
    pass "never filters the daemon's object list"
fi
if grep -q -- "publish=" "$CALL_LOG"; then
    fail "script searched by published host port"
else
    pass "never searches by published host port"
fi

# --------------------------------------------------------------------------
start_case "prunes stay within what is provably unowned"
# Dangling images and build cache cannot orphan a running stack. `image prune
# -a` and `--volumes` can, and reach into other jobs.
if grep -qE "^image prune( -f)?$" "$CALL_LOG"; then
    pass "image prune is dangling-only"
else
    fail "expected a dangling-only 'image prune -f' under CI"
fi
if grep -qE "^image prune.*(-a|--all)" "$CALL_LOG"; then
    fail "image prune -a removes images other jobs are about to run"
else
    pass "never runs 'image prune -a'"
fi
if grep -q -- "--volumes" "$CALL_LOG"; then
    fail "a prune reached volumes, which other jobs may still hold"
else
    pass "never prunes volumes"
fi

start_case "prunes do not run off CI"
run_script 0 COMPOSE_RUN_ID=run42
if grep -q "^image prune" "$CALL_LOG" || grep -q "^builder prune" "$CALL_LOG"; then
    fail "pruned a developer's daemon, which this script does not own"
else
    pass "no prune outside CI"
fi

# --------------------------------------------------------------------------
start_case "the three deliberately-untouched projects stay untouched"
# devcontainer, the root dev stack and the emulators stack are owned by the
# targets that start them (make devcontainer-clean / compose-clean /
# emulator-stop). `make integration-test` runs this script first, so tearing
# the devcontainer down here would kill a developer's shell mid-suite.
run_script 0 COMPOSE_RUN_ID=run42
for owned_elsewhere in ".devcontainer/docker-compose.yml" "docker-compose.emulators.yml"; do
    if grep -q -- "$owned_elsewhere" "$CALL_LOG"; then
        fail "tore down $owned_elsewhere, which another target owns"
    else
        pass "leaves $owned_elsewhere alone"
    fi
done
# Stated positively, which is the only form that cannot pass vacuously: every
# compose file the script touches must live under one of the two integration
# trees. That covers the root dev stack (docker-compose.yml at the repo root)
# without having to enumerate what to exclude.
stray=0
while read -r line; do
    case "$line" in compose\ *) ;; *) continue ;; esac
    # shellcheck disable=SC2086
    set -- $line
    while [ $# -gt 0 ]; do
        if [ "$1" = "-f" ]; then
            case "$2" in
                */test/integration/*|*/xkey/test/integration/*) ;;
                *) echo "      outside the integration trees: $2" >&2; stray=1 ;;
            esac
        fi
        shift
    done
done < "$CALL_LOG"
if [ "$stray" -eq 0 ]; then
    pass "every compose file touched is under an integration tree"
else
    fail "tore down a compose stack outside the integration trees"
fi

# --------------------------------------------------------------------------
start_case "lane naming matches the Makefile's \$(call compose,<lane>)"
# A lane torn down under the wrong project name is simply not torn down, and
# the leak is silent. These three shapes are the ones that can drift.
run_script 0 COMPOSE_RUN_ID=run42
check_lane() {
    if grep -q -- "-p go-xkms-run42-$1 " "$CALL_LOG"; then
        pass "lane '$1'"
    else
        fail "lane '$1' was not torn down under its expected project name"
    fi
}
check_lane "vault"              # flat lane
check_lane "tpm2-idevid"        # nested lane, segments joined with '-'
check_lane "xkey-oidc"          # xkey module lane, prefixed

# --------------------------------------------------------------------------
if [ "$FAILURES" -eq 0 ]; then
    echo "PASS: clean-test-containers.sh stays inside its run"
    exit 0
fi
echo "FAILED: $FAILURES assertion(s)" >&2
exit 1
