#!/usr/bin/env bash
#
# Tests for scripts/build-agsim.sh: a local fixture git repository stands in
# for the trusted-firmware repository, and fake `go` and `make` commands on
# PATH for the module lookup and the C build, so the suite checks the script's
# commit and tree pinning and its error reporting without a network or a C
# toolchain. The script reads its pins from agsim.sum beside it, so a copy of
# it runs from a work directory holding a test pin (DS-3754, DS-7409).
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
set +e
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n    want: %s\n    got:  %s\n' "$1" "$2" "$3" >&2; }
eq() { if [ "$2" = "$3" ]; then ok "$1"; else no "$1" "$2" "$3"; fi; }
has() { case "$3" in *"$2"*) ok "$1" ;; *) no "$1" "output containing '$2'" "$3" ;; esac; }
section() { printf '\n%s\n' "$1"; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

MODULE=github.com/jeremyhahn/trusted-firmware
VERSION=v0.0.1-test

mkdir -p "$WORK/scripts" "$WORK/bin" "$WORK/prefetch"
cp "$ROOT/scripts/build-agsim.sh" "$WORK/scripts/"

# The upstream fixture: a local repository with two commits, A and B, whose
# marker file names the commit, so a built binary shows which source it came from.
UP="$WORK/upstream"
git_() { git -c user.name=test -c user.email=test@example.invalid -c commit.gpgsign=false -c init.defaultBranch=main "$@"; }
git_ init -q "$UP"
printf 'a\n' > "$UP/marker"
git_ -C "$UP" add marker
git_ -C "$UP" commit -qm a
COMMIT_A=$(git -C "$UP" rev-parse 'HEAD^{commit}')
TREE_A=$(git -C "$UP" rev-parse 'HEAD^{tree}')
printf 'b\n' > "$UP/marker"
git_ -C "$UP" commit -qam b
TREE_B=$(git -C "$UP" rev-parse 'HEAD^{tree}')
COMMIT_B=$(git -C "$UP" rev-parse 'HEAD^{commit}')

# pin URL COMMIT TREE -- writes the one pin line the copied script reads.
pin() { printf '# test pin\n%s %s %s %s\n' "$1" "$VERSION" "$2" "$3" > "$WORK/scripts/agsim.sum"; }
# prefetch COMMIT -- the image's pre-fetched source: a shallow fetch of COMMIT.
prefetch() {
	rm -rf "$WORK/prefetch/$VERSION"
	git_ init -q "$WORK/prefetch/$VERSION"
	git_ -C "$WORK/prefetch/$VERSION" fetch -q --depth 1 "file://$UP" "$1"
	git_ -C "$WORK/prefetch/$VERSION" -c advice.detachedHead=false checkout -q FETCH_HEAD
}

# go: FAKE_GO_LIST_FAIL makes `go list` fail; otherwise it reports the
# sdk/go version go.mod pins.
cat > "$WORK/bin/go" <<'EOF'
#!/usr/bin/env bash
case "$1 $2 $5" in
"list -m "*/sdk/go)
	[ -z "${FAKE_GO_LIST_FAIL:-}" ] || { echo "go: module lookup disabled by GOPROXY=off" >&2; exit 1; }
	echo "$FAKE_VERSION"
	;;
*) echo "fake go: unexpected: $*" >&2; exit 2 ;;
esac
EOF
# make -C DIR TARGET...: writes each TARGET into DIR/build/host, holding DIR's
# marker, and records that it ran; FAKE_MAKE_FAIL makes it fail.
cat > "$WORK/bin/make" <<'EOF'
#!/usr/bin/env bash
[ -z "${FAKE_MAKE_FAIL:-}" ] || exit 2
touch "$FAKE_MAKE_RAN"
dir=$2
shift 2
mkdir -p "$dir/build/host"
for t in "$@"; do cp "$dir/marker" "$dir/build/host/$t"; done
EOF
chmod +x "$WORK/bin/go" "$WORK/bin/make"

# run DIR [VAR=value...] -- runs the copied script into DIR with the fakes and
# an empty pre-fetched source root unless AGSIM_SRC is given.
run() {
	local dir=$1
	shift
	rm -f "$WORK/make-ran"
	env PATH="$WORK/bin:$PATH" FAKE_VERSION="$VERSION" FAKE_MAKE_RAN="$WORK/make-ran" AGSIM_SRC="$WORK/none" "$@" \
		bash "$WORK/scripts/build-agsim.sh" "$dir" 2>&1
}
ran_make() { [ -e "$WORK/make-ran" ] && echo yes || echo no; }
built() { [ -e "$1" ] && echo yes || echo no; }

section "builds the pinned commit fetched from the pinned repository"
pin "file://$UP" "$COMMIT_A" "$TREE_A"
OUT=$(run "$WORK/out1"); RC=$?
eq "exits 0" "0" "$RC"
has "reports the build" "tfwsim $VERSION built in $WORK/out1" "$OUT"
eq "installs tfwsim from commit A" "a" "$(cat "$WORK/out1/tfwsim" 2>/dev/null)"
eq "installs tfwsim-atecc608a" "yes" "$([ -x "$WORK/out1/tfwsim-atecc608a" ] && echo yes)"
eq "stamps the version" "$VERSION" "$(cat "$WORK/out1/.version" 2>/dev/null)"
OUT=$(run "$WORK/out1" FAKE_MAKE_FAIL=1); RC=$?
eq "a built DIR is left alone, with no build" "0" "$RC"
has "says it is already built" "already built" "$OUT"

section "builds from a pre-fetched source, with no fetch from the repository"
pin "file://$WORK/absent" "$COMMIT_A" "$TREE_A"
prefetch "$COMMIT_A"
OUT=$(run "$WORK/out2" AGSIM_SRC="$WORK/prefetch"); RC=$?
eq "exits 0" "0" "$RC"
eq "installs tfwsim from commit A" "a" "$(cat "$WORK/out2/tfwsim" 2>/dev/null)"

section "rejects a pre-fetched source at a commit the pin does not name"
prefetch "$COMMIT_B"
OUT=$(run "$WORK/out3" AGSIM_SRC="$WORK/prefetch"); RC=$?
eq "exits 1" "1" "$RC"
has "names the source and the pinned commit" "git fetch $WORK/prefetch/$VERSION $COMMIT_A failed" "$OUT"
eq "runs no make" "no" "$(ran_make)"
eq "builds nothing" "no" "$(built "$WORK/out3")"

section "rejects a repository that does not hold the pinned commit"
pin "file://$UP" 0123456789abcdef0123456789abcdef01234567 "$TREE_A"
OUT=$(run "$WORK/out4"); RC=$?
eq "exits 1" "1" "$RC"
has "names the source and the pinned commit" "git fetch file://$UP 0123456789abcdef0123456789abcdef01234567 failed" "$OUT"
eq "runs no make" "no" "$(ran_make)"
eq "builds nothing" "no" "$(built "$WORK/out4")"

section "rejects a commit whose tree the pin does not match"
pin "file://$UP" "$COMMIT_A" "$TREE_B"
OUT=$(run "$WORK/out5"); RC=$?
eq "exits 1" "1" "$RC"
has "names both trees" "commit $COMMIT_A has tree '$TREE_A', $WORK/scripts/agsim.sum pins '$TREE_B'" "$OUT"
eq "runs no make" "no" "$(ran_make)"
eq "builds nothing" "no" "$(built "$WORK/out5")"

section "reports a failed version lookup"
pin "file://$UP" "$COMMIT_A" "$TREE_A"
OUT=$(run "$WORK/out6" FAKE_GO_LIST_FAIL=1); RC=$?
eq "exits 1" "1" "$RC"
has "names the failing command" "go list -m $MODULE/sdk/go failed" "$OUT"
has "keeps go's own error" "module lookup disabled by GOPROXY=off" "$OUT"

section "rejects a version with no pin"
OUT=$(run "$WORK/out7" FAKE_VERSION=v9.9.9); RC=$?
eq "exits 1" "1" "$RC"
has "names the missing pin" "trusted-firmware v9.9.9 has no pin in $WORK/scripts/agsim.sum" "$OUT"
eq "runs no make" "no" "$(ran_make)"

section "rejects a pin line with no tree"
printf '%s %s %s\n' "file://$UP" "$VERSION" "$COMMIT_A" > "$WORK/scripts/agsim.sum"
OUT=$(run "$WORK/out8"); RC=$?
eq "exits 1" "1" "$RC"
has "names the malformed pin" "trusted-firmware $VERSION has no pin in $WORK/scripts/agsim.sum" "$OUT"
eq "runs no make" "no" "$(ran_make)"

printf '\nbuild-agsim.sh: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
