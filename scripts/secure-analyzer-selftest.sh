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
#
# A SECOND case, below the bad/clean pair, proves the allowlist's keying
# itself (go-xkms#607): that an entry survives an edit that only shifts the
# exempted finding's line number, and that the stale check still catches an
# entry whose finding is genuinely gone. It sources
# scripts/secure-analyzer-key.sh -- the same rule_for/symbol_for/
# allowed_reason/process_diagnostics/check_stale functions
# scripts/secure-analyzer.sh's real sweep uses -- against a throwaway
# module and a throwaway allowlist built at run time, never against
# scripts/secure-analyzer-allowlist.txt itself.
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

expect_hit 'secure.Buffer.Bytes holds no borrow across the read' \
	'rule 4: Buffer.Bytes with no borrow held'
expect_hit 'malformed //secure:unborrowed directive' \
	'rule 5: malformed unborrowed directive'
expect_hit 'string(...) converts protected bytes to a string' \
	'rule 6: string() of protected bytes'
expect_hit 'copies protected bytes into ordinary memory that is never wiped' \
	'rule 7: an unwiped copy of protected bytes'

# --- Every diagnostic must classify under a known rule and FAIL (rules 4-7
#     are never allowlistable), so a reworded upstream message cannot slip
#     through as "unrecognised" and a new finding cannot slip through as
#     allowed. Uses the real process_diagnostics against an empty allowlist.
SYMTOOL="$WORK/secure-analyzer-symbol"
"$ROOT/scripts/secure-analyzer.sh" --build-symtool "$SYMTOOL"
# shellcheck source=scripts/secure-analyzer-key.sh
. "$ROOT/scripts/secure-analyzer-key.sh"
ALLOWLIST="$WORK/empty-allowlist.txt"
: >"$ALLOWLIST"
: >"$WORK/hits"
classify_out="$WORK/classify.out"
before=$fails
process_diagnostics "$bad_out" "" "$(cd "$ROOT" && pwd)" >"$classify_out"
# process_diagnostics fails every rule 4-7 finding by design; those are the
# findings under test, not selftest failures. Reset here, before the
# assertions below, so a failed assertion still counts.
fails=$before
sed 's/^/  | /' "$classify_out"
if grep -q 'does not match any known securecheck rule message' "$classify_out"; then
	fail "a bad-fixture diagnostic was not recognised by rule_for"
else
	note "ok: every bad-fixture diagnostic classifies under a known rule"
fi
for r in 4 5 6 7; do
	if grep -q "\[rule $r\]" "$classify_out"; then
		note "ok: rule $r findings fail the gate, classified under their rule"
	else
		fail "rule $r finding was not failed under its own classification"
	fi
done

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

# --- KEYING regression (go-xkms#607): a line shift must not invalidate an
#     allowlist entry, and a genuinely removed finding must still go stale. -
echo "secure-analyzer selftest: keying regression (go-xkms#607)"

KEYWORK="$WORK/keying"
mkdir -p "$KEYWORK"
cat >"$KEYWORK/go.mod" <<-'EOF'
	module secureanalyzerkeyingfixture

	go 1.21
	EOF

write_keyed_baseline() {
	cat >"$KEYWORK/keyed.go" <<-'EOF'
		package keyed

		// holder is go-xkms#607's own throwaway rule-3 fixture: it is built and
		// vetted only inside this selftest's scratch directory, never as part
		// of this repository's real module tree or its real allowlist.
		type holder struct {
			Password string
		}
		EOF
}

write_keyed_baseline
keyed_out="$WORK/keyed.out"
(cd "$KEYWORK" && $GO vet -vettool="$TOOL" ./...) >"$keyed_out" 2>&1 || true
diagline=$(grep -E '^[^:]+\.go:[0-9]+:[0-9]+: field "Password"' "$keyed_out" || true)
if [ -z "$diagline" ]; then
	fail "keying fixture: expected a rule-3 finding on the baseline fixture, got:
      $(cat "$keyed_out")"
else
	relfile=$(printf '%s\n' "$diagline" | grep -Eo '^[^:]+')
	lineno=$(printf '%s\n' "$diagline" | sed -E 's/^[^:]+:([0-9]+):[0-9]+:.*/\1/')
	colno=$(printf '%s\n' "$diagline" | sed -E 's/^[^:]+:[0-9]+:([0-9]+):.*/\1/')
	msg=$(printf '%s\n' "$diagline" | sed -E 's/^[^:]+:[0-9]+:[0-9]+: //')
	rule=$(rule_for "$msg") || fail "keying fixture: baseline diagnostic did not classify as a known securecheck rule"
	symbol=$(symbol_for "$rule" "$KEYWORK/$relfile" "$lineno" "$colno" "$msg" "$KEYWORK") || fail "keying fixture: could not derive a symbol for the baseline finding"

	ALLOWLIST="$WORK/keying-allowlist.txt"
	printf '%s\t%s\t%s\treason: go-xkms#607 selftest fixture\n' "$relfile" "$rule" "$symbol" >"$ALLOWLIST"

	: >"$WORK/hits"
	before=$fails
	process_diagnostics "$keyed_out" "" "$KEYWORK"
	if [ "$fails" -eq "$before" ]; then
		note "ok: the baseline finding matches its freshly derived allowlist entry ($relfile [$rule] $symbol)"
	else
		fail "keying fixture: the baseline finding did not match its own freshly derived allowlist entry"
	fi

	# A comment inserted directly ABOVE the field shifts its line number and
	# changes nothing else about it -- go-xkms#607 exists because the
	# previous path:line key would stop matching here; path+rule+symbol
	# must not.
	cat >"$KEYWORK/keyed.go" <<-'EOF'
		package keyed

		// holder is go-xkms#607's own throwaway rule-3 fixture: it is built and
		// vetted only inside this selftest's scratch directory, never as part
		// of this repository's real module tree or its real allowlist.
		type holder struct {
			// This comment, inserted directly above the field by the selftest,
			// exists only to shift Password's line number.
			//
			//
			Password string
		}
		EOF
	shifted_out="$WORK/keyed-shifted.out"
	(cd "$KEYWORK" && $GO vet -vettool="$TOOL" ./...) >"$shifted_out" 2>&1 || true
	shifted_diag=$(grep -E '^[^:]+\.go:[0-9]+:[0-9]+: field "Password"' "$shifted_out" || true)
	if [ -z "$shifted_diag" ]; then
		fail "keying fixture: expected a rule-3 finding after shifting the field, got:
      $(cat "$shifted_out")"
	else
		shifted_line=$(printf '%s\n' "$shifted_diag" | sed -E 's/^[^:]+:([0-9]+):[0-9]+:.*/\1/')
		if [ "$shifted_line" = "$lineno" ]; then
			fail "keying fixture: the inserted comment did not move the field's line number ($lineno); this case proves nothing"
		else
			note "ok: the field's reported line moved $lineno -> $shifted_line"
			: >"$WORK/hits"
			before=$fails
			process_diagnostics "$shifted_out" "" "$KEYWORK"
			if [ "$fails" -eq "$before" ]; then
				note "ok: the SAME allowlist entry still matches after only a line shift -- go-xkms#607 is fixed"
			else
				fail "keying fixture: the allowlist entry stopped matching after only a line shift (the path:line regression go-xkms#607 fixes)"
			fi
		fi
	fi

	# Removing the field entirely makes the rule-3 finding, and so any hit
	# for it, disappear. check_stale -- the mechanism that actually protects
	# scripts/secure-analyzer-allowlist.txt from an outlived exemption -- must
	# still flag the now-unmatched entry rather than treat old hits as
	# current.
	cat >"$KEYWORK/keyed.go" <<-'EOF'
		package keyed

		type holder struct {
			Note string
		}
		EOF
	removed_out="$WORK/keyed-removed.out"
	(cd "$KEYWORK" && $GO vet -vettool="$TOOL" ./...) >"$removed_out" 2>&1 || true
	if grep -q 'field "Password"' "$removed_out"; then
		fail "keying fixture: the Password finding is still present after removing the field; this case proves nothing"
	else
		: >"$WORK/hits"
		before=$fails
		check_stale
		if [ "$fails" -gt "$before" ]; then
			note "ok: removing the field leaves the allowlist entry unmatched, and check_stale catches it"
			# check_stale's increment IS the assertion this branch just
			# confirmed -- a deliberately provoked, expected signal, not a
			# real selftest failure. Net it back out so it does not also
			# trip the overall pass/fail tally below.
			fails=$before
		else
			fail "keying fixture: check_stale did not flag an allowlist entry that matched nothing after its field was removed"
		fi
	fi
fi

if [ "$fails" -ne 0 ]; then
	printf '\nsecure-analyzer selftest: %d assertion(s) failed\n' "$fails" >&2
	exit 1
fi
echo "secure-analyzer selftest: the gate goes red on a known violation and stays green on its compliant counterpart"
