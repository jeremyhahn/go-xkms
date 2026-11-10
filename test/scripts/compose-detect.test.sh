#!/usr/bin/env bash
#
# Tests for the Makefile's compose macro: it uses the host's `docker compose`
# plugin first, the standalone `docker-compose` binary when the plugin is
# missing, and stops with a clear message when the host has neither. Main CI
# run 42881658762 ran on a runner whose Docker CLI had no compose plugin:
# `docker compose -p ...` was parsed as `docker -p` and the job died at `tar`
# with Docker's usage text. Fake `docker` / `docker-compose` binaries on PATH
# stand in for the host; nothing here talks to a Docker daemon (`make -n`).
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
set +e
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n    want: %s\n    got:  %s\n' "$1" "$2" "$3" >&2; }
eq() { [ "$2" = "$3" ] && ok "$1" || no "$1" "$2" "$3"; }
contains() { case $3 in *"$2"*) ok "$1" ;; *) no "$1" "output containing '$2'" "$3" ;; esac; }
lacks() { case $3 in *"$2"*) no "$1" "output without '$2'" "$3" ;; *) ok "$1" ;; esac; }
section() { printf '\n%s\n' "$1"; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/plugin" "$WORK/standalone" "$WORK/none"

# A docker whose compose plugin answers `docker compose version`.
printf '#!/bin/sh\n[ "$1" = compose ] && exit 0\nexit 0\n' >"$WORK/plugin/docker"
# A docker without the plugin: `docker compose ...` fails as on the runner.
printf '#!/bin/sh\nif [ "$1" = compose ]; then echo "unknown command: docker compose" >&2; exit 125; fi\nexit 0\n' >"$WORK/standalone/docker"
cp "$WORK/standalone/docker" "$WORK/none/docker"
printf '#!/bin/sh\nexit 0\n' >"$WORK/standalone/docker-compose"
chmod +x "$WORK"/*/docker "$WORK/standalone/docker-compose"

# The host's own PATH without any directory that holds a real
# docker-compose, so the "neither" case does not depend on this host.
BASE_PATH=
IFS=: read -r -a dirs <<<"$PATH"
for d in "${dirs[@]}"; do
	[ -n "$d" ] && [ -x "$d/docker-compose" ] && continue
	BASE_PATH="${BASE_PATH:+$BASE_PATH:}$d"
done

# run <stub dir> -- dry-runs devcontainer-down with that host; sets OUT and RC.
run() {
	OUT=$(cd "$ROOT" && env -u COMPOSE_BIN -u IT_PROJECT GITHUB_RUN_ID=t42881658762 \
		PATH="$WORK/$1:$BASE_PATH" make -n -s --no-print-directory devcontainer-down 2>&1)
	RC=$?
}

section "host with the compose plugin"
run plugin
eq "make exits 0" "0" "$RC"
contains "the plugin is used" "docker compose -p go-xkms-t42881658762-devcontainer" "$OUT"

section "host with docker-compose only"
run standalone
eq "make exits 0" "0" "$RC"
contains "the standalone binary is used" "docker-compose -p go-xkms-t42881658762-devcontainer" "$OUT"
lacks "the missing plugin is not called" "docker compose -p" "$OUT"

section "host with neither"
run none
eq "make fails" "yes" "$([ "$RC" -ne 0 ] && echo yes || echo no)"
contains "the error says what is missing" "docker compose plugin or docker-compose is required" "$OUT"
lacks "no compose command line is printed" " -p go-xkms-" "$OUT"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
exit $?
