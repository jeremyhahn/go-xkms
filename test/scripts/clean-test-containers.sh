#!/bin/bash
# Tear down the docker resources this repo's integration suites create.
#
# SCOPE: this run's compose projects, and nothing else.
#
# The previous version of this script matched containers by NAME SUBSTRING
# ("swtpm", "vault", "floci", ...) and by PUBLISHED HOST PORT, then killed
# whatever it found. Both are host-global searches, so on a shared CI runner
# it happily destroyed the containers of other jobs that happened to be
# running a similarly named service -- including concurrent runs of this very
# suite. It also pruned images and build cache out from under them.
#
# Every stack is now namespaced per run (Makefile: COMPOSE_NS ->
# COMPOSE_PROJECT_NAME=go-xkms-$GITHUB_RUN_ID-<lane>), so `compose down`
# against each compose file with this run's project name removes exactly the
# containers, networks and volumes this run created and provably cannot touch
# another job's. Nothing here may search the host by name, port or image.
#
# The per-lane suites only. Three projects are deliberately NOT touched here:
#
#   devcontainer  `make integration-test` runs this script as its first
#                 prerequisite, and a developer's devcontainer is a long-lived
#                 shell that must survive that. CI tears it down separately
#                 with `make devcontainer-clean` in its if:always() step.
#   root          the docker-compose.yml dev stack -- `make compose-clean`.
#   emulators     docker-compose.emulators.yml -- `make emulator-stop`.
#
# Each is owned by the target that starts it, and each CI job cleans up
# exactly the projects it created.

set -u

COMPOSE_RUN_ID="${COMPOSE_RUN_ID:-${GITHUB_RUN_ID:-local}}"
REPO_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"

echo "Cleaning up integration test stacks for run '${COMPOSE_RUN_ID}'..."

# lane name == the compose file's directory, matching $(call compose,<lane>)
# in the Makefile. Keep the two in step: a lane cleaned under the wrong
# project name is simply not cleaned.
down_lane() {
    compose_file="$1"
    lane="$2"
    [ -f "${compose_file}" ] || return 0
    project="go-xkms-${COMPOSE_RUN_ID}-${lane}"
    # -p as well as the env var: -p outranks a compose file's top-level
    # `name:`, which the env var does not reliably do across versions.
    COMPOSE_PROJECT_NAME="${project}" \
        docker compose -p "${project}" -f "${compose_file}" \
        down -v --remove-orphans >/dev/null 2>&1 || true
}

for compose_file in "${REPO_ROOT}"/test/integration/*/docker-compose.yml; do
    [ -f "${compose_file}" ] || continue
    lane="$(basename "$(dirname "${compose_file}")")"
    echo "  ${lane}"
    down_lane "${compose_file}" "${lane}"
done

# Nested lanes (e.g. tpm2/idevid, tpm2/tpm_operations, pkcs11/module). The
# lane name joins the path segments with '-', again matching the Makefile.
for compose_file in "${REPO_ROOT}"/test/integration/*/*/docker-compose.yml; do
    [ -f "${compose_file}" ] || continue
    dir="$(dirname "${compose_file}")"
    lane="$(basename "$(dirname "${dir}")")-$(basename "${dir}")"
    echo "  ${lane}"
    down_lane "${compose_file}" "${lane}"
done

for compose_file in "${REPO_ROOT}"/xkey/test/integration/*/docker-compose.yml; do
    [ -f "${compose_file}" ] || continue
    lane="xkey-$(basename "$(dirname "${compose_file}")")"
    echo "  ${lane}"
    down_lane "${compose_file}" "${lane}"
done

# No prune of any kind (#1870). `docker image prune` and `docker builder
# prune` act on the whole daemon, and "dangling" or "unused" is not the same
# as "unowned": an image a concurrent build has created but not yet tagged is
# dangling, and the cache records it is about to hit are unused. The CI
# integration job is six parallel shards on one runner host, each running
# this script at its start and at its teardown, so a prune here broke another
# shard's `compose build` mid-bake (run 76161: shards 2 and 5 within two
# seconds of each other). The build cache is bounded by the daemon's own
# BuildKit garbage collector, which never removes a record a build holds.

echo "Cleanup complete!"
