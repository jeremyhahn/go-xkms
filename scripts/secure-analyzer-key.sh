# secure-analyzer-key.sh -- shared key-derivation and allowlist-matching
# functions for scripts/secure-analyzer.sh and its selftest (go-xkms#607).
# Meant to be SOURCED, never executed: it only defines functions and
# touches no files by itself. Splitting these out of secure-analyzer.sh
# lets secure-analyzer-selftest.sh exercise the REAL matching logic against
# a throwaway fixture and allowlist, rather than a second copy of it that
# could silently drift from what the gate actually enforces.
#
# See scripts/secure-analyzer.sh's KEYING comment for why an entry keys on
# path + rule + symbol instead of path:line.
#
# Callers must set, before use:
#
#   SYMTOOL    absolute path to a built scripts/secure-analyzer-symbol
#              binary (symbol_for, for rule 2 and rule 3 findings).
#   ALLOWLIST  absolute path to a tab-separated allowlist file
#              (allowed_reason, check_stale).
#   WORK       a scratch directory; process_diagnostics appends allowed
#              hits to "$WORK/hits" and check_stale reads that file back.
#
# And must maintain a `fails` counter in the calling shell: every function
# here that finds a problem increments it rather than exiting, so a caller
# can keep sweeping after one bad finding and report a full tally at the
# end -- the same behavior scripts/secure-analyzer.sh's own sweep has.

# rule_for classifies MSG ($1, a diagnostic's text after "file:line:col: ")
# by the Reportf messages the pinned go-qrdb vet tool produces (verbatim, read
# from pkg/secure/analyzer in that dependency). Prints nothing and fails on
# anything else: an unrecognized shape is a hard failure, never a silently
# unkeyed finding.
#
#   1     raw memguard import (analyzer.go). go-qrdb v0.25 reworded it from
#         "... is forbidden outside pkg/secure" to "... is forbidden; use
#         ...", so the pattern stops at "is forbidden" and matches both.
#   2     ssh.ParsePrivateKey (analyzer.go).
#   3     string/[]byte holder field (analyzer.go).
#   4     unborrowed secure.Buffer.Bytes, or a malformed //secure:unborrowed
#         directive (unborrowed.go, go-qrdb#428).
#   copy  securecopy: a copy-out of protected bytes never wiped, returned or
#         consumed, or a string(...) of protected bytes (copyout.go,
#         go-qrdb#459).
#
# Rule 4 and securecopy carry their own per-site directives
# (//secure:unborrowed, //secure:unwiped) and are never allowlistable; see
# process_diagnostics.
rule_for() {
	case "$1" in
	'import of '*' is forbidden'*) echo 1 ;;
	'call to '*' is forbidden; use '*) echo 2 ;;
	'field '*' holds sensitive material as '*) echo 3 ;;
	'secure.Buffer.Bytes holds no borrow across the read'*) echo 4 ;;
	'malformed //secure:unborrowed directive'*) echo 4 ;;
	*' copies protected bytes into ordinary memory that is never wiped, returned or consumed'*) echo copy ;;
	'string(...) converts protected bytes to a string'*) echo copy ;;
	*) return 1 ;;
	esac
}

# per_site_rule reports whether RULE ($1) is one whose only exemption is a
# directive written at the site itself. go-qrdb#429 argued against an
# allowlist for these, and the analyzer already reads the directive, so a
# finding here is always a defect to fix (or to justify at the site).
per_site_rule() {
	case "$1" in
	4|copy) return 0 ;;
	*) return 1 ;;
	esac
}

# symbol_for prints the finding's symbol. $1 = rule (from rule_for),
# $2 = absolute path to the source file, $3 = line, $4 = col, $5 = the
# diagnostic message, $6 = the absolute module directory $2 is under
# (SYMTOOL's -root: the boundary it refuses to read outside of, via an
# os.Root opened on it -- see scripts/secure-analyzer-symbol's doc comment;
# gosec G703 flags a bare os.ReadFile(path-built-from-argv) as an
# unsanitized read, and Clean/Abs/Join don't count as sanitizers to it).
#
# Rule 1's symbol is already in the message -- the import path Reportf
# quotes is the constant bannedImport, so no source read is needed. Rules 2
# and 3 are not: rule 2's message is the same fixed string for every call
# site, and rule 3's never names the struct, so both call out to
# scripts/secure-analyzer-symbol (SYMTOOL) to read it back from the source
# at file:line:col.
symbol_for() {
	case "$1" in
	1) printf '%s\n' "$5" | sed -E 's/^import of "([^"]+)".*/\1/' ;;
	2) "$SYMTOOL" -root "$6" call "$2" "$3" "$4" ;;
	3) "$SYMTOOL" -root "$6" struct "$2" "$3" "$4" ;;
	esac
}

# allowed_reason prints the reason for path $1 + rule $2 + symbol $3 if that
# triple is a non-comment, non-blank line in ALLOWLIST, or nothing (and
# fails) if it is not.
allowed_reason() {
	awk -F'\t' -v p="$1" -v r="$2" -v s="$3" '
		/^[[:space:]]*#/ { next }
		NF < 4 { next }
		$1 == p && $2 == r && $3 == s { print $4; found=1; exit }
		END { if (!found) exit 1 }
	' "$ALLOWLIST"
}

# process_diagnostics reads OUT ($1), one `go vet` diagnostic per line, with
# paths relative to the directory `go vet` was run from. PREFIX ($2) is
# prepended to make each diagnostic's file into the repo-relative path
# ALLOWLIST keys on ("" for the root module, "sdk/go/" etc. otherwise).
# MODULE_DIR ($3) is that same directory made absolute, needed to hand
# SYMTOOL a path it can open.
#
# Every diagnostic line is classified (rule_for), keyed (symbol_for) and
# checked against ALLOWLIST (allowed_reason). An allowed finding's key is
# appended to "$WORK/hits" for check_stale to read back; anything else
# increments the caller's `fails`.
process_diagnostics() {
	out="$1"
	prefix="$2"
	moduledir="$3"
	while IFS= read -r diagline; do
		[ -n "$diagline" ] || continue
		if ! printf '%s\n' "$diagline" | grep -Eq '^[^:]+\.go:[0-9]+:[0-9]+: '; then
			# Not a diagnostic line (a build failure, a tool-start failure, a
			# panic) -- never suppressible, always a hard failure.
			fails=$((fails + 1))
			echo "  FAIL (not a securecheck diagnostic): $diagline"
			continue
		fi
		relfile=$(printf '%s\n' "$diagline" | grep -Eo '^[^:]+')
		lineno=$(printf '%s\n' "$diagline" | sed -E 's/^[^:]+:([0-9]+):[0-9]+:.*/\1/')
		colno=$(printf '%s\n' "$diagline" | sed -E 's/^[^:]+:[0-9]+:([0-9]+):.*/\1/')
		msg=$(printf '%s\n' "$diagline" | sed -E 's/^[^:]+:[0-9]+:[0-9]+: //')
		fullpath="${prefix}${relfile}"

		rule=$(rule_for "$msg") || {
			fails=$((fails + 1))
			echo "  FAIL (diagnostic does not match any known securecheck rule message): $diagline"
			continue
		}
		if per_site_rule "$rule"; then
			fails=$((fails + 1))
			echo "  FAIL [$rule] (fix it, or justify it with the analyzer's own directive at the site; the allowlist does not apply): ${prefix}${diagline}"
			continue
		fi
		symbol=$(symbol_for "$rule" "$moduledir/$relfile" "$lineno" "$colno" "$msg" "$moduledir") || {
			fails=$((fails + 1))
			echo "  FAIL (could not derive an allowlist symbol for): $diagline"
			continue
		}

		if reason=$(allowed_reason "$fullpath" "$rule" "$symbol"); then
			printf '%s\t%s\t%s\n' "$fullpath" "$rule" "$symbol" >>"$WORK/hits"
			echo "  ALLOWED $fullpath [$rule] $symbol -- $reason"
		else
			fails=$((fails + 1))
			echo "  FAIL $fullpath [$rule] $symbol: $diagline"
		fi
	done <"$out"
}

# check_stale fails (increments the caller's `fails`) on any ALLOWLIST entry
# that scored zero hits in "$WORK/hits" -- an exemption nothing matched is
# either already fixed (drop it) or was never reachable under any declared
# tag set (drop it or the reasoning that added it is wrong).
check_stale() {
	while IFS= read -r entry; do
		case "$entry" in
		''|'#'*) continue ;;
		esac
		key=$(printf '%s\n' "$entry" | cut -f1-3)
		[ -n "$key" ] || continue
		if ! grep -qxF "$key" "$WORK/hits" 2>/dev/null; then
			fails=$((fails + 1))
			echo "  FAIL: stale allowlist entry never matched by the sweep: $key"
		fi
	done <"$ALLOWLIST"
}
