#!/bin/bash
# Shell-level tests for test/scripts/clean-test-containers.sh.
#
# The script under test is the thing that decides WHICH Docker resources a CI
# run may destroy, on Actions hosts whose daemon is shared with every other
# repository (go-xkms#2). These tests pin the safety boundary: under CI it may
# only touch this repository's own compose projects and `go-xkms-*` containers,
# never a fixed host port, a loose name substring, a `*test*` network, the
# devcontainer, or any prune.
#
# No Docker daemon is involved: a fake `docker` on PATH records every
# invocation (with its working directory) and answers queries. DOCKER_HOST is
# also pointed at a closed port so that a PATH mistake fails loudly instead of
# reaching a real daemon.

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
# Fake docker: log "<cwd-basename>|<args>" and answer the queries the script
# makes. Failure injection:
#   FAKE_DOCKER_FAIL_PROJECT   `compose down` fails for that project directory
#   FAKE_DOCKER_FAIL_RM        `docker rm` fails when it names that container
#   FAKE_DOCKER_FAIL_STOP      `docker stop` fails when it names that container
echo "$(basename "$PWD")|$*" >> "$FAKE_DOCKER_LOG"

case "$1 $2" in
    "ps -q")
        # publish=<port> lookup during the broad-scope port sweep
        echo "cid-port"
        ;;
    "ps -aq")
        # name=<filter> lookup. The anchored project-owned sweep returns a
        # devcontainer plus an ordinary container; the loose broad-scope
        # sweeps return a container this repo does not own.
        case "$4" in
            "name=^go-xkms-(swtpm|softhsm|integration|unit|test-runner|vault|floci|floci-gcp|azure-kv)$")
                # Include the two development containers the daemon would
                # never actually return for this filter, so the exclusion
                # logic is exercised even if the filter regresses.
                echo "cid-devcontainer"
                echo "cid-dev"
                echo "cid-normal"
                ;;
            "name=^xkms-integration-(server|swtpm|softhsm|tests)$")
                echo "cid-integration"
                ;;
            "name=^xkms-test-(unix|rest|grpc|quic|mcp|frost|parity)$")
                echo "cid-protocol"
                ;;
            *)
                echo "cid-loose"
                ;;
        esac
        ;;
    "inspect --format")
        case "$4" in
            cid-devcontainer) echo "/go-xkms-devcontainer" ;;
            cid-dev)          echo "/go-xkms-dev" ;;
            cid-port)         echo "/foreign-repo-server" ;;
            cid-loose)        echo "/some-vault" ;;
            cid-integration)  echo "/xkms-integration-server" ;;
            cid-protocol)     echo "/xkms-test-rest" ;;
            *)                echo "/go-xkms-swtpm" ;;
        esac
        ;;
    "stop cid-normal"|"stop cid-loose"|"stop cid-integration"|"stop cid-protocol"|"stop cid-port")
        if [ -n "${FAKE_DOCKER_FAIL_STOP:-}" ] && [ "$2" = "$FAKE_DOCKER_FAIL_STOP" ]; then
            echo "fake failure: cannot stop $2" >&2
            exit 1
        fi
        ;;
    "rm -f")
        if [ -n "${FAKE_DOCKER_FAIL_RM:-}" ] && [ "$3" = "$FAKE_DOCKER_FAIL_RM" ]; then
            echo "fake failure: cannot remove $3" >&2
            exit 1
        fi
        ;;
    "network ls")
        echo "foreign-integration-net"
        echo "devcontainer_xkms-dev"
        ;;
    "compose -f")
        # `compose -f <path> down ...`; FAKE_DOCKER_FAIL_PROJECT names the
        # directory (= Compose v2 project) whose teardown should fail.
        if [ -n "${FAKE_DOCKER_FAIL_PROJECT:-}" ] && \
           [ "$(basename "$(dirname "$3")")" = "$FAKE_DOCKER_FAIL_PROJECT" ]; then
            echo "fake failure: project ${FAKE_DOCKER_FAIL_PROJECT} refused to stop" >&2
            exit 1
        fi
        ;;
esac
exit 0
FAKE
chmod +x "$FAKE_BIN/docker"

FAILURES=0
CURRENT_CASE=""

start_case() {
    CURRENT_CASE="$1"
    echo "--- $CURRENT_CASE"
}

fail() {
    echo "    FAIL: $1" >&2
    FAILURES=$((FAILURES + 1))
}

pass() {
    echo "    ok: $1"
}

# run_script <expected-exit> [VAR=VALUE ...] -- runs the script under test from
# the repo root with the fake docker first on PATH. Output lands in
# $WORK_DIR/stdout; docker invocations in $CALL_LOG (truncated per run).
run_script() {
    local expected_exit="$1"; shift
    : > "$CALL_LOG"
    (
        cd "$REPO_ROOT" || exit 99
        env -u CI -u GITHUB_ACTIONS -u XKMS_CLEAN_SCOPE -u FAKE_DOCKER_FAIL_PROJECT \
            -u FAKE_DOCKER_FAIL_RM -u FAKE_DOCKER_FAIL_STOP \
            PATH="$FAKE_BIN:$PATH" \
            DOCKER_HOST="tcp://127.0.0.1:1" \
            FAKE_DOCKER_LOG="$CALL_LOG" \
            "$@" bash "$SCRIPT_UNDER_TEST"
    ) > "$WORK_DIR/stdout" 2> "$WORK_DIR/stderr"
    local actual_exit=$?
    if [ "$actual_exit" -ne "$expected_exit" ]; then
        fail "expected exit $expected_exit, got $actual_exit (stderr: $(tr '\n' ' ' < "$WORK_DIR/stderr"))"
    fi
}

# calls_matching <extended-regex> -> count of docker invocations matching it
calls_matching() {
    grep -cE "$1" "$CALL_LOG"
}

assert_calls() {
    local pattern="$1" expected="$2" what="$3"
    local actual
    actual="$(calls_matching "$pattern")"
    if [ "$actual" = "$expected" ]; then
        pass "$what ($actual)"
    else
        fail "$what: expected $expected docker call(s) matching /$pattern/, got $actual"
    fi
}

assert_literal_calls() {
    local literal="$1" expected="$2" what="$3"
    local actual
    actual="$(grep -cF "$literal" "$CALL_LOG")"
    if [ "$actual" = "$expected" ]; then
        pass "$what ($actual)"
    else
        fail "$what: expected $expected docker call(s) containing '$literal', got $actual"
    fi
}

assert_no_calls() {
    local pattern="$1" what="$2"
    local actual
    actual="$(calls_matching "$pattern")"
    if [ "$actual" = "0" ]; then
        pass "$what"
    else
        fail "$what: expected none, got $actual: $(grep -E "$pattern" "$CALL_LOG" | head -3 | tr '\n' ' ')"
    fi
}

# Every compose project this repository owns. Populated with a plain
# `while read` loop rather than `mapfile`/`readarray`, which macOS's system
# bash (3.2) does not have -- `make test` runs this, so it has to work
# wherever the Go suite does.
COMPOSE_PATHS=()
while IFS= read -r compose_path; do
    [ -n "$compose_path" ] || continue
    COMPOSE_PATHS[${#COMPOSE_PATHS[@]}]="$compose_path"
done <<EOF
$(cd "$REPO_ROOT" && ls -d test/integration/*/ test/integration/*/*/ 2>/dev/null |
    while read -r d; do [ -f "$d/docker-compose.yml" ] && echo "${d}docker-compose.yml"; done | sort)
EOF
COMPOSE_PROJECT_COUNT=${#COMPOSE_PATHS[@]}

if [ "$COMPOSE_PROJECT_COUNT" -eq 0 ]; then
    echo "FAIL: found no test/integration compose projects to exercise" >&2
    exit 1
fi

echo "Testing $SCRIPT_UNDER_TEST against $COMPOSE_PROJECT_COUNT compose project(s)"

# ---------------------------------------------------------------------------
start_case "project scope: no host-global sweeps"
run_script 0 XKMS_CLEAN_SCOPE=project
assert_no_calls '\|ps -q --filter publish=' "no port sweep"
assert_no_calls '\|network rm ' "no network removal by name substring"
assert_no_calls '\|ps -aq --filter name=(swtpm|tpm-simulator|softhsm|vault|floci|azure|gcp)$' \
    "no loose substring container sweeps"
assert_literal_calls "|ps -aq --filter name=^go-xkms-(swtpm|softhsm|integration|unit|test-runner|vault|floci|floci-gcp|azure-kv)$" 1 "test containers selected by an exact-name allowlist"
assert_no_calls '\|ps -aq --filter name=\^go-xkms-\$?[^(]' "no bare go-xkms- prefix sweep"

# ---------------------------------------------------------------------------
start_case "no scope ever prunes"
assert_no_calls 'prune' "no prune of any kind in project scope"

# ---------------------------------------------------------------------------
start_case "compose teardown addresses each project by its own compose file"
assert_calls '\|compose -f test/integration/.*/docker-compose.yml down -v --remove-orphans$' \
    "$COMPOSE_PROJECT_COUNT" "one compose down per project, no extra flags"
for path in "${COMPOSE_PATHS[@]}"; do
    if ! grep -qF "|compose -f ${path} down -v --remove-orphans" "$CALL_LOG"; then
        fail "no compose down addressed $path"
    fi
done
pass "every compose project addressed by its own file"
assert_no_calls '\|compose .*--rmi' "compose teardown never widens to image removal"

# ---------------------------------------------------------------------------
start_case "project scope preserves development containers"
assert_no_calls '\|(stop|rm|kill) .*cid-devcontainer' "go-xkms-devcontainer never stopped or removed"
assert_no_calls '\|(stop|rm|kill) .*cid-dev( |$)' "go-xkms-dev (repo-root dev service) never stopped or removed"
assert_calls '\|stop .*cid-normal' 1 "an actual test container is stopped"

# ---------------------------------------------------------------------------
start_case "CI defaults to project scope"
run_script 0 CI=true
if grep -q "scope: project" "$WORK_DIR/stdout"; then
    pass "CI=true selects project scope"
else
    fail "CI=true did not select project scope: $(head -1 "$WORK_DIR/stdout")"
fi
assert_no_calls '\|ps -q --filter publish=' "no port sweep under CI"
assert_no_calls '\|compose .*--rmi' "CI teardown does not remove images either"

run_script 0 GITHUB_ACTIONS=true
if grep -q "scope: project" "$WORK_DIR/stdout"; then
    pass "GITHUB_ACTIONS=true selects project scope"
else
    fail "GITHUB_ACTIONS=true did not select project scope"
fi

# ---------------------------------------------------------------------------
start_case "local default is broad scope"
run_script 0
if grep -q "scope: broad" "$WORK_DIR/stdout"; then
    pass "no CI markers selects broad scope"
else
    fail "expected broad scope locally: $(head -1 "$WORK_DIR/stdout")"
fi
assert_calls '\|compose -f .* down -v --remove-orphans$' "$COMPOSE_PROJECT_COUNT" \
    "compose down keeps built images locally too"
assert_calls '\|ps -q --filter publish=' 7 "port sweep runs in broad scope"
assert_calls '\|network rm foreign-integration-net' 1 "test-named network removed in broad scope"
assert_no_calls '\|network rm devcontainer_' "devcontainer network preserved in broad scope"
assert_no_calls '\|(stop|rm|kill) .*cid-devcontainer' "devcontainer preserved in broad scope"
assert_no_calls 'prune' "no prune of any kind in broad scope"

# ---------------------------------------------------------------------------
start_case "explicit scope overrides the CI default"
run_script 0 CI=true XKMS_CLEAN_SCOPE=broad
if grep -q "scope: broad" "$WORK_DIR/stdout"; then
    pass "XKMS_CLEAN_SCOPE=broad overrides CI=true"
else
    fail "XKMS_CLEAN_SCOPE did not override the CI default"
fi

# ---------------------------------------------------------------------------
start_case "unknown scope is rejected rather than guessed"
run_script 2 XKMS_CLEAN_SCOPE=sideways
if grep -q "Unknown XKMS_CLEAN_SCOPE" "$WORK_DIR/stderr"; then
    pass "unknown scope reported on stderr"
else
    fail "unknown scope was not reported: $(cat "$WORK_DIR/stderr")"
fi
assert_no_calls '\|compose ' "nothing torn down under an unknown scope"

# ---------------------------------------------------------------------------
start_case "a failed teardown is reported, not swallowed"
run_script 1 CI=true FAKE_DOCKER_FAIL_PROJECT="storage"
if grep -q "compose down FAILED for test/integration/storage/docker-compose.yml" "$WORK_DIR/stderr"; then
    pass "failing project named on stderr"
else
    fail "failing project not named: $(tr '\n' ' ' < "$WORK_DIR/stderr")"
fi
if grep -q "refused to stop" "$WORK_DIR/stderr"; then
    pass "docker's own error text is surfaced"
else
    fail "docker error text was swallowed"
fi
assert_calls '\|compose -f ' "$COMPOSE_PROJECT_COUNT" "remaining projects are still torn down after a failure"

# ---------------------------------------------------------------------------
start_case "a container this repo owns that refuses removal fails the cleanup"
run_script 1 CI=true FAKE_DOCKER_FAIL_RM=cid-normal
if grep -q "docker rm -f FAILED for containers matching /\^go-xkms-" "$WORK_DIR/stderr"; then
    pass "the surviving project-owned container is reported"
else
    fail "surviving project-owned container not reported: $(tr '\n' ' ' < "$WORK_DIR/stderr")"
fi
if grep -q "cannot remove cid-normal" "$WORK_DIR/stderr"; then
    pass "docker's own error text is surfaced"
else
    fail "docker error text was swallowed"
fi

# ---------------------------------------------------------------------------
start_case "a failed stop that rm -f recovers is reported but not fatal"
run_script 0 CI=true FAKE_DOCKER_FAIL_STOP=cid-normal
if grep -q "docker stop failed for containers matching /\^go-xkms-" "$WORK_DIR/stderr"; then
    pass "the failed stop is reported"
else
    fail "failed stop was not reported: $(tr '\n' ' ' < "$WORK_DIR/stderr")"
fi

# ---------------------------------------------------------------------------
start_case "fixed-name containers this repo owns also fail closed"
run_script 1 CI=true FAKE_DOCKER_FAIL_RM=cid-integration
if grep -q "docker rm -f FAILED for containers matching /\^xkms-integration-" "$WORK_DIR/stderr"; then
    pass "surviving xkms-integration-* container fails the cleanup"
else
    fail "xkms-integration-* removal failure not reported: $(tr '\n' ' ' < "$WORK_DIR/stderr")"
fi

run_script 1 CI=true FAKE_DOCKER_FAIL_RM=cid-protocol
if grep -q "docker rm -f FAILED for containers matching /\^xkms-test-" "$WORK_DIR/stderr"; then
    pass "surviving xkms-test-* container fails the cleanup"
else
    fail "xkms-test-* removal failure not reported: $(tr '\n' ' ' < "$WORK_DIR/stderr")"
fi

# ---------------------------------------------------------------------------
start_case "fixed-name groups are matched exactly, not by substring"
run_script 0 CI=true
assert_calls '\|ps -aq --filter name=\^xkms-integration-\(server\|swtpm\|softhsm\|tests\)\$' 1 \
    "xkms-integration-* selected by an anchored exact-name filter"
assert_calls '\|ps -aq --filter name=\^xkms-test-\(unix\|rest\|grpc\|quic\|mcp\|frost\|parity\)\$' 1 \
    "xkms-test-* selected by an anchored exact-name filter"
assert_no_calls '\|kill ' "no blind docker kill over names that may not exist"

# ---------------------------------------------------------------------------
start_case "the broad-scope port sweep stays best-effort"
run_script 0 XKMS_CLEAN_SCOPE=broad FAKE_DOCKER_FAIL_RM=cid-port
assert_calls '\|rm -f cid-port' 7 "port sweep still attempted"
pass "a foreign container surviving the port sweep is not fatal"

# ---------------------------------------------------------------------------
start_case "loose broad-scope sweeps stay best-effort"
run_script 0 XKMS_CLEAN_SCOPE=broad FAKE_DOCKER_FAIL_RM=cid-loose
assert_calls '\|rm -f cid-loose' 7 "loose sweeps still attempted"
pass "a container this repo does not own surviving removal is not fatal"

# ---------------------------------------------------------------------------
if [ "$FAILURES" -eq 0 ]; then
    echo "clean-test-containers.sh: all checks passed"
    exit 0
fi

echo "clean-test-containers.sh: $FAILURES check(s) failed" >&2
exit 1
