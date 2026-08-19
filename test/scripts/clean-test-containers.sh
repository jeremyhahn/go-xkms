#!/bin/bash
# Clean up Docker containers left over from integration tests
# This prevents port conflicts when running tests
#
# IMPORTANT: This script preserves devcontainer infrastructure (xkms-dev-* containers
# and the devcontainer_xkms-dev network). Only test-specific containers are cleaned.

# Scope of this cleanup:
#
#   project  Only resources this repository owns: its own compose projects
#            and its own container names (`xkms-integration-*`,
#            `xkms-test-*`, `go-xkms-*`). This is the default under CI,
#            where the Docker daemon is SHARED with other repositories'
#            jobs -- freeing fixed host ports and matching loose name
#            substrings there would stop containers that belong to someone
#            else's run (2026-08-17 shared-runner incident, go-xkms#2).
#   broad    Additionally frees the fixed test ports and sweeps
#            loosely-named leftovers (swtpm, vault, softhsm, ...). Safe and
#            useful on a developer box, which owns its whole daemon.
#
# Override with XKMS_CLEAN_SCOPE=project|broad.
if [ -n "${XKMS_CLEAN_SCOPE:-}" ]; then
    CLEAN_SCOPE="$XKMS_CLEAN_SCOPE"
elif [ "${CI:-}" = "true" ] || [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    CLEAN_SCOPE="project"
else
    CLEAN_SCOPE="broad"
fi

case "$CLEAN_SCOPE" in
    project|broad) ;;
    *)
        echo "Unknown XKMS_CLEAN_SCOPE '$CLEAN_SCOPE' (expected 'project' or 'broad')" >&2
        exit 2
        ;;
esac

# Failure contract, uniform across this script:
#   * anything that removes a resource this repository OWNS (its exact
#     container names, its `go-xkms-*` containers, its compose projects) is
#     strict -- a failure is reported with docker's own error and counted in
#     cleanup_failures, and the script exits non-zero so the caller does not
#     start a suite on top of leftovers;
#   * the `broad`-scope sweeps (fixed ports, loose name substrings, `*test*`
#     networks) are best-effort by design -- they match names nobody
#     guarantees are ours, so a failure there is not this repository's to
#     fail on.
echo "Cleaning up integration test Docker containers (scope: $CLEAN_SCOPE)..."

# Containers this run could not remove. Non-zero at the end means this
# repository's leftovers are still on the host, so the caller must not treat
# the cleanup as done.
cleanup_failures=0

# Helper: stop and remove containers matching a name filter, excluding
# devcontainer-owned containers (xkms-dev-*, devcontainer-* and
# go-xkms-devcontainer -- the last one is reachable from the `^go-xkms-`
# prefix sweep below and must survive it).
#
#   clean_containers <name-filter> [strict]
#
# `strict` is for sweeps over names this repository owns: a container that
# survives removal there is a real problem (the next run hits a conflicting
# fixed container name or an occupied port), so it is reported and counted.
# The loose broad-scope sweeps stay best-effort on purpose -- they match
# names nobody guarantees are ours, so a failure there is not this repo's
# business to fail on.
clean_containers() {
    local filter="$1"
    local strict="${2:-}"
    local ids rm_output stop_output
    ids=$(docker ps -aq --filter "name=$filter" 2>/dev/null | while read -r id; do
        name=$(docker inspect --format '{{.Name}}' "$id" 2>/dev/null | sed 's|^/||')
        case "$name" in
            # Development infrastructure, never cleanup fodder: the devcontainer
            # itself and the repo-root `dev` service. Belt and braces -- the
            # filters above are exact-name allowlists that do not select these
            # -- but a future filter must not be able to reach them either.
            xkms-dev-*|devcontainer-*|*-devcontainer|go-xkms-dev) ;;
            *) echo "$id" ;;
        esac
    done)
    if [ -n "$ids" ]; then
        # A failed `stop` is reported but not counted: `rm -f` below kills the
        # container anyway, so it only matters if the removal ALSO fails.
        if ! stop_output=$(docker stop $ids 2>&1); then
            if [ "$strict" = "strict" ]; then
                echo "  ! docker stop failed for containers matching /$filter/ (continuing to rm -f):" >&2
                printf '%s\n' "$stop_output" | sed 's/^/    /' >&2
            fi
        fi
        if ! rm_output=$(docker rm -f $ids 2>&1); then
            if [ "$strict" = "strict" ]; then
                echo "  x docker rm -f FAILED for containers matching /$filter/ ($ids):" >&2
                printf '%s\n' "$rm_output" | sed 's/^/    /' >&2
                cleanup_failures=$((cleanup_failures + 1))
            fi
        fi
    fi
}

# First, stop any containers using the ports we need (broad scope only:
# a container publishing 8443 on a shared CI host is far more likely to
# belong to another repository's job than to a stale run of ours).
if [ "$CLEAN_SCOPE" = "broad" ]; then
echo "Checking for processes using test ports..."
for port in 8443 9443 8444 9444 9090 2321 2322; do
    container_id=$(docker ps -q --filter "publish=$port" 2>/dev/null)
    if [ -n "$container_id" ]; then
        # Check if this container belongs to the devcontainer
        name=$(docker inspect --format '{{.Name}}' "$container_id" 2>/dev/null | sed 's|^/||')
        case "$name" in
            xkms-dev-*|devcontainer-*)
                echo "Skipping devcontainer container on port $port: $name"
                ;;
            *)
                echo "Stopping container using port $port: $container_id ($name)"
                docker stop "$container_id" 2>/dev/null || true
                docker rm -f "$container_id" 2>/dev/null || true
                ;;
        esac
    fi
done
fi

# xkms integration test containers (API tests). Anchored exact names, run
# through the strict helper: it acts only on containers that actually exist
# (so the common "none of them are running" case is not an error), and a
# container of ours that survives removal is reported and fails the cleanup --
# the next run would otherwise walk into a fixed-name or fixed-port conflict.
clean_containers "^xkms-integration-(server|swtpm|softhsm|tests)$" strict

# Protocol-specific test containers, same contract.
clean_containers "^xkms-test-(unix|rest|grpc|quic|mcp|frost|parity)$" strict

# This project's own TEST containers, by exact name. An allowlist rather than
# a `^go-xkms-` prefix: that prefix also covers development infrastructure
# this script must preserve -- `go-xkms-dev` (the `dev` service in the
# repo-root docker-compose.yml) and `go-xkms-devcontainer` -- and killing a
# developer's session is exactly the kind of collateral damage this scoping
# work exists to stop. Anchored, so it cannot reach another repository's
# container called `vault` or `swtpm` either.
clean_containers "^go-xkms-(swtpm|softhsm|integration|unit|test-runner|vault|floci|floci-gcp|azure-kv)$" strict

if [ "$CLEAN_SCOPE" = "broad" ]; then
    # Loose substring sweeps: they catch leftovers whose names this repo
    # does not control, which is worth it on a machine we own and
    # unacceptable on a shared CI daemon.

    # Stop and remove test swtpm containers (but not xkms-dev-swtpm)
    clean_containers "swtpm"

    # Stop and remove TPM simulator containers
    clean_containers "tpm-simulator"

    # Stop and remove test SoftHSM containers (but not xkms-dev-softhsm)
    clean_containers "softhsm"

    # Stop and remove Vault containers
    clean_containers "vault"

    # Stop and remove emulator containers
    clean_containers "floci"
    clean_containers "azure"
    clean_containers "gcp"

    # Remove only test-specific networks (NOT the devcontainer network).
    # `*test*`/`*integration*` matches other repositories' networks just as
    # happily as ours, so it stays out of project scope; the compose
    # teardown below removes this project's own networks by project name.
    echo "Cleaning test-specific networks..."
    docker network ls --format '{{.Name}}' 2>/dev/null | while read -r net; do
        case "$net" in
            devcontainer_*|xkms-dev|bridge|host|none) ;;  # preserve these
            *test*|*integration*)
                echo "Removing test network: $net"
                docker network rm "$net" 2>/dev/null || true
                ;;
        esac
    done
fi

# Clean up any orphaned containers from all integration test compose files
# (top level plus nested ones, e.g. tpm2/idevid, tpm2/tpm_operations).
#
# `-f <path>` from the repo root is deliberate and already addresses the same
# project the Makefile targets do: Compose v2 derives the project directory
# from the directory of the first `-f` file, not from the shell's cwd, so
# this and `cd test/integration/storage && docker compose ...` both mean
# project "storage". Do not "fix" it by cd-ing, and do not widen it with
# `--rmi local`: these projects are named per directory, not per run, so on a
# shared CI host anything this pre-suite step destroys can belong to a
# concurrent run of this repository just as easily as to our own leftovers.
# Run-scoped identifiers are the prerequisite for widening this (go-xkms#15).
for compose_file in test/integration/*/docker-compose.yml test/integration/*/*/docker-compose.yml; do
    if [ -f "$compose_file" ]; then
        echo "Cleaning up $compose_file..."
        # Failures are reported and counted, not swallowed: `down` on a
        # project with nothing running exits 0, so a non-zero status here
        # means the teardown genuinely did not happen (bad invocation,
        # daemon trouble, a container that refused to stop) and this repo's
        # containers/volumes are still on the host.
        if ! down_output=$(docker compose -f "$compose_file" down -v --remove-orphans 2>&1); then
            echo "  x compose down FAILED for $compose_file:" >&2
            printf '%s\n' "$down_output" | sed 's/^/    /' >&2
            cleanup_failures=$((cleanup_failures + 1))
        fi
    fi
done

# No host-global `docker image prune` / `docker builder prune` here, and no
# `docker system prune` anywhere: this script runs BEFORE the integration
# suite (it is a prerequisite of `make integration-test`), so on a shared CI
# host it would be deleting images and build cache that other repositories'
# jobs -- and the image this job just built -- are relying on. Reclaiming
# this project's own image tags is the job teardown's business and lives in
# the "Clean up this job's Docker resources" step of .github/workflows/ci.yml,
# where it runs after the suite instead of before it.

if [ "$cleanup_failures" -gt 0 ]; then
    echo "Cleanup FAILED: $cleanup_failures teardown step(s) left this repository's resources on the host." >&2
    exit 1
fi

echo "Cleanup complete!"
