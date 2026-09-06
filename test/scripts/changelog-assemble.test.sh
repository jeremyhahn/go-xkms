#!/usr/bin/env bash
#
# Unit tests for the pure functions in scripts/changelog-assemble.sh.
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
CHANGELOG_ASSEMBLE_LIB=1 . "$ROOT/scripts/changelog-assemble.sh"
set +e

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); }
bad()  { FAIL=$((FAIL+1)); echo "FAIL: $1"; }
check(){ if [ "$1" = "$2" ]; then ok; else bad "$3 (want [$2] got [$1])"; fi; }

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

mkcl() {
	cat > "$T/CHANGELOG.md" <<'CL'
# Changelog

## [Unreleased]

## [0.1.0] - 2026-01-01

### Fixed

- old entry
CL
}

# --- entry_section ------------------------------------------------------
check "$(entry_section "$T/fixed-a-thing-123.md")" "fixed" "entry_section fixed"
check "$(entry_section "$T/security-hole.md")" "security" "entry_section security"
entry_section "$T/bogus-prefix.md" >/dev/null 2>&1 && bad "unknown section accepted" || ok
entry_section "$T/nodash.md" >/dev/null 2>&1 && bad "sectionless name accepted" || ok

# --- assemble: empty dir is a no-op ------------------------------------
mkcl; mkdir -p "$T/e1"
out=$(assemble "$T/CHANGELOG.md" "$T/e1" "0.2.0" "2026-09-05"); rc=$?
check "$rc" "0" "empty dir rc"
check "$out" "" "empty dir output"
grep -q '0.2.0' "$T/CHANGELOG.md" && bad "no-op still wrote heading" || ok

# --- assemble: sections in fixed order, entries spliced, files listed ---
mkcl; mkdir -p "$T/e2"
printf -- '- **fix one** body\n  line2\n' > "$T/e2/fixed-one-1.md"
printf -- '- **sec one** body\n'          > "$T/e2/security-one-2.md"
printf -- '- **fix two** body\n'          > "$T/e2/fixed-two-3.md"
printf 'readme text\n'                    > "$T/e2/README.md"
out=$(assemble "$T/CHANGELOG.md" "$T/e2" "0.2.0" "2026-09-05"); rc=$?
check "$rc" "0" "assemble rc"
check "$(printf '%s\n' "$out" | wc -l | tr -d ' ')" "3" "three files listed"
printf '%s' "$out" | grep -q README && bad "README assembled" || ok
grep -q '^## \[0.2.0\] - 2026-09-05$' "$T/CHANGELOG.md" || bad "version heading missing"
# order: Unreleased, then new section, then 0.1.0; Security before Fixed
awk '/^## |^### /{print}' "$T/CHANGELOG.md" > "$T/headings"
check "$(cat "$T/headings" | tr '\n' '|')" "## [Unreleased]|## [0.2.0] - 2026-09-05|### Security|### Fixed|## [0.1.0] - 2026-01-01|### Fixed|" "heading order"
grep -q 'fix one' "$T/CHANGELOG.md" && grep -q 'sec one' "$T/CHANGELOG.md" && grep -q '  line2' "$T/CHANGELOG.md" && ok || bad "entry bodies not spliced verbatim"
# Unreleased stays empty (next line after it is blank then the new heading)
check "$(awk '/^## \[Unreleased\]/{getline; print; exit}' "$T/CHANGELOG.md")" "" "Unreleased left empty"

# --- assemble: backslashes and escapes survive verbatim (opencode finding) --
mkcl; mkdir -p "$T/e5"
printf -- '- **esc** path C:\\\\tmp and \\n literal and \\* star and a\\tb\n' > "$T/e5/fixed-esc-9.md"
want=$(cat "$T/e5/fixed-esc-9.md")
assemble "$T/CHANGELOG.md" "$T/e5" "0.2.0" "2026-09-05" >/dev/null; rc=$?
check "$rc" "0" "escape entry rc"
got=$(awk '/^- \*\*esc\*\*/{print; exit}' "$T/CHANGELOG.md")
check "$got" "$want" "backslash sequences spliced verbatim (no C-escape interpretation)"

# --- assemble: unknown section fails loudly, changelog untouched --------
mkcl; mkdir -p "$T/e3"
printf -- '- entry\n' > "$T/e3/typo-thing.md"
before=$(cat "$T/CHANGELOG.md")
assemble "$T/CHANGELOG.md" "$T/e3" "0.2.0" "2026-09-05" >/dev/null 2>&1 && bad "typo section accepted" || ok
check "$(cat "$T/CHANGELOG.md")" "$before" "changelog untouched on error"

# --- assemble: no Unreleased heading fails -----------------------------
printf '# Changelog\n' > "$T/CHANGELOG.md"; mkdir -p "$T/e4"; printf -- '- x\n' > "$T/e4/fixed-x.md"
assemble "$T/CHANGELOG.md" "$T/e4" "0.2.0" "2026-09-05" >/dev/null 2>&1 && bad "missing Unreleased accepted" || ok

# --- assemble: a SECOND Unreleased heading fails (go-xkms#356) ----------
# Two concatenated changelog documents make the splice point ambiguous, so
# the release notes are bounded by whichever heading the tool happened to
# pick. Refuse rather than write into an ambiguous file.
mkcl; printf '\n## [Unreleased]\n\n### Added\n\n- other document\n' >> "$T/CHANGELOG.md"
mkdir -p "$T/e6"; printf -- '- dup entry\n' > "$T/e6/fixed-dup.md"
before=$(cat "$T/CHANGELOG.md")
assemble "$T/CHANGELOG.md" "$T/e6" "0.2.0" "2026-09-05" >/dev/null 2>&1 && bad "duplicate Unreleased accepted" || ok
check "$(cat "$T/CHANGELOG.md")" "$before" "changelog untouched on duplicate Unreleased"

# --- the repository's own CHANGELOG.md is extractable (go-xkms#356) ----
# `make release` cuts a version's notes with
#   sed -n "/## \[$VERSION\]/,/^## \[/p"
# so a release section runs to the next line beginning `## [`. Two things
# follow, and neither is visible by reading one section in isolation.
CL="$ROOT/CHANGELOG.md"

check "$(grep -c '^## \[Unreleased\]' "$CL")" "1" "repo CHANGELOG has exactly one [Unreleased]"

# A repeated version heading restarts the sed range, so BOTH sections are
# emitted as that one version's notes.
check "$(grep '^## \[' "$CL" | sort | uniq -d | wc -l | tr -d ' ')" "0" \
	"repo CHANGELOG version headings are unique"

# The oldest release has no terminator unless whatever follows it is itself
# under a `## [` heading, so it would otherwise run to end of file.
oldest=$(grep -n '^## \[' "$CL" | tail -1 | cut -d: -f1)
total=$(wc -l < "$CL")
check "$([ "$oldest" -lt "$total" ] && echo yes)" "yes" \
	"repo CHANGELOG's last '## [' heading is not the final section"

# Concretely: the oldest go-xkms release must not publish the absorbed
# go-trusted-ca appendix as its own release notes.
notes=$(sed -n '/## \[0\.1\.0-alpha\]/,/^## \[/{/^## \[/d;p;}' "$CL")
printf '%s' "$notes" | grep -q 'Swagger UI' \
	&& bad "0.1.0-alpha notes swallow the go-trusted-ca appendix" || ok

# --- the --root seam (go-xkms#415, #416) --------------------------------
#
# Assembly is destructive: the CLI deletes every entry file it splices. A
# caller rehearsing a release must be able to point the whole operation at a
# scratch copy, so --root is the only thing standing between `--dry-run` and
# the repository's real entry files. Exercised through the CLI, not the
# `assemble` function, because the deletion lives in the CLI.
REPO_CL_BEFORE=$(sha256sum "$ROOT/CHANGELOG.md")
R="$T/root"
mkdir -p "$R/.changelog/unreleased"
printf '# Changelog\n\n## [Unreleased]\n' > "$R/CHANGELOG.md"
printf -- '- entry under a scratch root\n' > "$R/.changelog/unreleased/fixed-root-1.md"
printf 'notes\n' > "$R/.changelog/unreleased/README.md"
out=$(bash "$ROOT/scripts/changelog-assemble.sh" --root "$R" 0.3.0-alpha 2026-09-06 2>&1); rc=$?
check "$rc" "0" "--root rc"
grep -q '^## \[0.3.0-alpha\] - 2026-09-06$' "$R/CHANGELOG.md" && ok || bad "--root did not assemble into the named tree"
grep -q 'entry under a scratch root' "$R/CHANGELOG.md" && ok || bad "--root did not splice the entry"
test -f "$R/.changelog/unreleased/fixed-root-1.md" && bad "--root left the assembled entry behind" || ok
test -f "$R/.changelog/unreleased/README.md" && ok || bad "--root removed the entries README"

# The repository this script lives in is NOT the tree it was pointed at.
# Compared by content hash rather than by grepping for the version: this
# CHANGELOG is thirteen releases long and already mentions most version
# strings, so a grep would answer a question about its history.
check "$(sha256sum "$ROOT/CHANGELOG.md")" "$REPO_CL_BEFORE" "--root left the repository CHANGELOG untouched"

# --root=DIR is the same option.
R2="$T/root2"
mkdir -p "$R2/.changelog/unreleased"
printf '# Changelog\n\n## [Unreleased]\n' > "$R2/CHANGELOG.md"
printf -- '- x\n' > "$R2/.changelog/unreleased/fixed-x-1.md"
bash "$ROOT/scripts/changelog-assemble.sh" "--root=$R2" 0.3.0-alpha 2026-09-06 >/dev/null 2>&1; rc=$?
check "$rc" "0" "--root=DIR rc"
grep -q '^## \[0.3.0-alpha\]' "$R2/CHANGELOG.md" && ok || bad "--root=DIR did not assemble"

# A root that does not exist is a usage error, not a silent assembly against
# the repository -- which is the one outcome the option exists to prevent.
out=$(bash "$ROOT/scripts/changelog-assemble.sh" --root "$T/absent" 0.3.0-alpha 2>&1); rc=$?
check "$rc" "2" "--root on a missing directory exits 2"
printf '%s' "$out" | grep -q 'is not a directory' && ok || bad "--root on a missing directory says nothing useful"
out=$(bash "$ROOT/scripts/changelog-assemble.sh" --root 2>&1); rc=$?
check "$rc" "2" "--root with no value exits 2"
out=$(bash "$ROOT/scripts/changelog-assemble.sh" --root "$R" 2>&1); rc=$?
check "$rc" "2" "--root with no version exits 2"

echo "changelog-assemble.test.sh: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
