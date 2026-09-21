#!/bin/sh
#
# secure-analyzer-selftest.sh -- prove `make secure-analyzer`'s gate can
# actually go RED, not merely that it prints "clean" when nothing is wrong.
# Called by `make secure-analyzer-selftest`.
#
# WHY A CLEAN SWEEP IS NOT EVIDENCE ON ITS OWN
#
# `make secure-analyzer` is green on a clean tree, and so is a sweep whose
# analyzer failed to build and silently vetted nothing, whose -vettool never
# started, or whose allowlist swallowed a real finding under too broad a
# reason. All four print approximately the same thing. The instrument has to
# find a KNOWN violation first, or a green result is not a measurement.
#
# test/lint/secure/_fixtures holds the known instances: bad/bad.go trips all
# three rules and clean/clean.go trips none, same shape otherwise. Both are
# under a directory named with a leading underscore, which the Go toolchain
# excludes from `./...` package discovery (`go help packages`) -- so this is
# the ONLY thing in the repository that ever builds, vets or lints them, and
# `make build`/`make test`/`make vet`/`make lint` never touch this fixture.
#
# Exit status is checked separately from message text: a diagnostic printed
# by a `go vet` that still exits 0 fails to block a merge, which is the whole
# job of the gate this selftest is proving works.
set -eu

ROOT="${SECURE_ANALYZER_ROOT:-.}"
GO="${GO:-go}"

fails=0
note() { printf '  %s\n' "$@"; }
fail() {
	fails=$((fails + 1))
	printf 'FAIL: %s\n' "$1" >&2
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM

TOOL="$WORK/secure-analyzer"
"$ROOT/scripts/secure-analyzer.sh" --build "$TOOL"

sweep() {
	# $1 = fixture dir, $2 = output file. Exact import path, never a `...`
	# pattern -- the leading underscore excludes it from any pattern, not
	# from an exact path.
	set +e
	(cd "$ROOT" && $GO vet -vettool="$TOOL" "./test/lint/secure/_fixtures/$1") >"$2" 2>&1
	echo $?
	set -e
}

bad_out="$WORK/bad.out"
bad_rc=$(sweep bad "$bad_out")
echo "secure-analyzer selftest: bad fixture output (exit $bad_rc)"
sed 's/^/  | /' "$bad_out"

clean_out="$WORK/clean.out"
clean_rc=$(sweep clean "$clean_out")
echo "secure-analyzer selftest: clean fixture output (exit $clean_rc)"
sed 's/^/  | /' "$clean_out"

# --- The bad fixture must BLOCK, not merely comment. ------------------------
if [ "$bad_rc" -eq 0 ]; then
	fail "go vet exited 0 on the bad fixture. A diagnostic that does not fail
      the command does not block a merge, which is this gate's entire job."
else
	note "ok: bad fixture exit status $bad_rc -- the gate blocks"
fi

expect_hit() {
	if grep -q "$1" "$bad_out"; then
		note "ok: reported -- $2"
	else
		fail "NOT REPORTED in the bad fixture: $2"
	fi
}
expect_hit 'import of "github.com/awnumar/memguard" is forbidden' \
	'rule 1: raw memguard import'
expect_hit 'call to ssh.ParsePrivateKey is forbidden' \
	'rule 2: ssh.ParsePrivateKey'
expect_hit 'field "Password" holds sensitive material as string' \
	'rule 3: a holder field with no scope-clause cover'

# --- The clean fixture must stay silent AND exit 0. -------------------------
if [ "$clean_rc" -ne 0 ]; then
	fail "go vet exited $clean_rc on the clean fixture, which trips none of
      the three rules; the analyzer, or the fixture, regressed."
else
	note "ok: clean fixture exit status 0"
fi
if [ -s "$clean_out" ]; then
	fail "the clean fixture produced output; expected none:
      $(cat "$clean_out")"
else
	note "ok: clean fixture produced no diagnostics"
fi

if [ "$fails" -ne 0 ]; then
	printf '\nsecure-analyzer selftest: %d assertion(s) failed\n' "$fails" >&2
	exit 1
fi
echo "secure-analyzer selftest: the gate goes red on a known violation and stays green on its compliant counterpart"
