#!/usr/bin/env bash
#
# Tests for the Makefile's module-fetch credential resolution (GOMODAUTH_*):
# every compose file's GIT_CONFIG_* environment and the stage-gomodauth secret
# must carry the CI runner's injected rewrite when one is present, otherwise
# the FORGE_MODULE_TOKEN/GITEA_HOST rewrite, otherwise nothing. The nightly
# devcontainer once built its rewrite from FORGE_MODULE_TOKEN alone, which a CI
# checkout does not have, and failed every private module fetch.
#
# No Docker and no network: the compose `${A:-${B}}` interpolation is the same
# syntax as bash parameter expansion, so each compose expression is evaluated
# by bash inside a make recipe, with exactly the environment make exports.
# Every token here is a fake.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
set +e
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n    want: %s\n    got:  %s\n' "$1" "$2" "$3" >&2; }
eq() { [ "$2" = "$3" ] && ok "$1" || no "$1" "$2" "$3"; }
section() { printf '\n%s\n' "$1"; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

mapfile -t COMPOSE_FILES < <(grep -rl --include=docker-compose.yml --include=compose.yaml 'GIT_CONFIG_COUNT=' \
	"$ROOT/build/docker/devcontainer" "$ROOT/test/integration" | sort)

# probe.sh prints `<compose file> <VAR>=<interpolated value>` for each
# GIT_CONFIG_* entry of every compose file, as compose would interpolate it
# in the calling environment.
PROBE="$WORK/probe.sh"
cat > "$PROBE" <<'EOF'
#!/usr/bin/env bash
root="$1"
shift
for f in "$@"; do
	for k in GOPRIVATE GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0; do
		expr=$(sed -n "s/^ *- $k=//p" "$f")
		eval "v=\"$expr\""
		printf '%s %s=%s\n' "${f#"$root"/}" "$k" "$v"
	done
done
EOF

# via_make ENV... — runs the probe from a make recipe (so it sees make's
# exported environment) and stages the gomodauth secret into $WORK.
via_make() {
	env -i PATH="$PATH" HOME="$HOME" "$@" \
		make -s --no-print-directory -C "$ROOT" \
		GOMODAUTH_FILE="$WORK/gomodauth.env" \
		--eval "__gomodauth_probe: ; @bash $PROBE $ROOT ${COMPOSE_FILES[*]}" \
		__gomodauth_probe stage-gomodauth > "$WORK/probe.out" 2> "$WORK/make.err"
}

# expect_all VAR VALUE LABEL — every compose file interpolates VAR to VALUE.
expect_all() {
	local f rel got
	for f in "${COMPOSE_FILES[@]}"; do
		rel="${f#"$ROOT"/}"
		got=$(sed -n "s|^$rel $1=||p" "$WORK/probe.out")
		eq "$3: $rel $1" "$2" "$got"
	done
}

RUNNER_KEY='url.http://x:runner-token@forge.example.com/jeremyhahn/.insteadOf'
TOKEN_KEY='url.http://x:local-token@gitea.example.com/jeremyhahn/.insteadOf'
VALUE='https://github.com/jeremyhahn/'

section "compose files under test"
eq "the devcontainer compose file is covered" "yes" \
	"$(printf '%s\n' "${COMPOSE_FILES[@]}" | grep -qx "$ROOT/build/docker/devcontainer/compose.yaml" && echo yes)"

section "runner-injected credentials win over FORGE_MODULE_TOKEN"
via_make GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="$RUNNER_KEY" GIT_CONFIG_VALUE_0="$VALUE" \
	FORGE_MODULE_TOKEN=local-token GITEA_HOST=gitea.example.com
eq "make succeeds" "0" "$?"
expect_all GIT_CONFIG_COUNT 1 runner
expect_all GIT_CONFIG_KEY_0 "$RUNNER_KEY" runner
expect_all GIT_CONFIG_VALUE_0 "$VALUE" runner
eq "runner: gomodauth secret" \
	"$(printf 'export GOPRIVATE=\nexport GIT_CONFIG_COUNT=1\nexport GIT_CONFIG_KEY_0=%s\nexport GIT_CONFIG_VALUE_0=%s' "$RUNNER_KEY" "$VALUE")" \
	"$(cat "$WORK/gomodauth.env")"

section "runner credentials with no FORGE_MODULE_TOKEN (the CI checkout)"
via_make GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="$RUNNER_KEY" GIT_CONFIG_VALUE_0="$VALUE" \
	FORGE_MODULE_TOKEN= GITEA_HOST=gitea.example.com
eq "make succeeds" "0" "$?"
expect_all GIT_CONFIG_KEY_0 "$RUNNER_KEY" ci

section "a caller count above 1 forwards entry 0 with a count of 1"
via_make GIT_CONFIG_COUNT=2 GIT_CONFIG_KEY_0="$RUNNER_KEY" GIT_CONFIG_VALUE_0="$VALUE" \
	GIT_CONFIG_KEY_1=core.hooksPath GIT_CONFIG_VALUE_1=/dev/null
eq "make succeeds" "0" "$?"
expect_all GIT_CONFIG_COUNT 1 count2
expect_all GIT_CONFIG_KEY_0 "$RUNNER_KEY" count2
eq "count2: gomodauth secret" \
	"$(printf 'export GOPRIVATE=\nexport GIT_CONFIG_COUNT=1\nexport GIT_CONFIG_KEY_0=%s\nexport GIT_CONFIG_VALUE_0=%s' "$RUNNER_KEY" "$VALUE")" \
	"$(cat "$WORK/gomodauth.env")"

section "FORGE_MODULE_TOKEN and GITEA_HOST compose the rewrite"
via_make FORGE_MODULE_TOKEN=local-token GITEA_HOST=gitea.example.com
eq "make succeeds" "0" "$?"
expect_all GIT_CONFIG_COUNT 1 token
expect_all GIT_CONFIG_KEY_0 "$TOKEN_KEY" token
expect_all GIT_CONFIG_VALUE_0 "$VALUE" token
eq "token: gomodauth secret" \
	"$(printf 'export GOPRIVATE=\nexport GIT_CONFIG_COUNT=1\nexport GIT_CONFIG_KEY_0=%s\nexport GIT_CONFIG_VALUE_0=%s' "$TOKEN_KEY" "$VALUE")" \
	"$(cat "$WORK/gomodauth.env")"

section "no credentials resolve publicly"
via_make FORGE_MODULE_TOKEN= GITEA_HOST=
eq "make succeeds" "0" "$?"
expect_all GIT_CONFIG_COUNT 0 none
eq "none: gomodauth secret is empty" "" "$(cat "$WORK/gomodauth.env")"

section "compose loaded directly (devcontainer.json, no make)"
env -i FORGE_MODULE_TOKEN=local-token GITEA_HOST=gitea.example.com \
	bash "$PROBE" "$ROOT" "${COMPOSE_FILES[@]}" > "$WORK/probe.out"
expect_all GIT_CONFIG_COUNT 1 direct
expect_all GIT_CONFIG_KEY_0 "$TOKEN_KEY" direct
expect_all GIT_CONFIG_VALUE_0 "$VALUE" direct
env -i bash "$PROBE" "$ROOT" "${COMPOSE_FILES[@]}" > "$WORK/probe.out"
expect_all GIT_CONFIG_COUNT "" direct-public

# --- the caller's GOPRIVATE reaches the secret and every compose file ----------
# There is no in-house default (DS-7983): an empty GOPRIVATE above proves only
# that none is added, so a nonempty one must arrive unchanged, through make for
# both credential sources and through compose loaded directly.
PRIVATE=example.com/private
section "the caller's GOPRIVATE is forwarded"
eq "every compose file that sets GOPRIVATE is probed" "" \
	"$(grep -rl --include=docker-compose.yml --include=compose.yaml -- '- GOPRIVATE=' \
		"$ROOT/build/docker/devcontainer" "$ROOT/test/integration" | sort |
		comm -23 - <(printf '%s\n' "${COMPOSE_FILES[@]}"))"
via_make GOPRIVATE="$PRIVATE" GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="$RUNNER_KEY" GIT_CONFIG_VALUE_0="$VALUE"
eq "make succeeds" "0" "$?"
expect_all GOPRIVATE "$PRIVATE" private-runner
eq "private-runner: gomodauth secret" \
	"$(printf 'export GOPRIVATE=%s\nexport GIT_CONFIG_COUNT=1\nexport GIT_CONFIG_KEY_0=%s\nexport GIT_CONFIG_VALUE_0=%s' "$PRIVATE" "$RUNNER_KEY" "$VALUE")" \
	"$(cat "$WORK/gomodauth.env")"
via_make GOPRIVATE="$PRIVATE" FORGE_MODULE_TOKEN=local-token GITEA_HOST=gitea.example.com
eq "make succeeds" "0" "$?"
expect_all GOPRIVATE "$PRIVATE" private-token
eq "private-token: gomodauth secret" \
	"$(printf 'export GOPRIVATE=%s\nexport GIT_CONFIG_COUNT=1\nexport GIT_CONFIG_KEY_0=%s\nexport GIT_CONFIG_VALUE_0=%s' "$PRIVATE" "$TOKEN_KEY" "$VALUE")" \
	"$(cat "$WORK/gomodauth.env")"
env -i GOPRIVATE="$PRIVATE" bash "$PROBE" "$ROOT" "${COMPOSE_FILES[@]}" > "$WORK/probe.out"
expect_all GOPRIVATE "$PRIVATE" private-direct

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
