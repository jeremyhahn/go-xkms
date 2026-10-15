#!/bin/sh
# Tests for disk-usage.sh (go-xkms#1553). The Lint job reads its disk budget
# off this script's output, and calls it between passes of the step being
# measured, so two things must hold:
#   1. Every cache is reported, by size and path, under the given label --
#      including golangci-lint's, wherever GOLANGCI_LINT_CACHE or the XDG
#      default puts it.
#   2. Measuring never fails the job: a cache not created yet prints
#      "absent", and so does everything when go itself is missing. Only a
#      missing label is an error.
#
# go is a FAKE on a replaced PATH, answering `go env` from two variables.
# No network, no host mutation, under a second.

set -eu

here="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
subject="${here}/disk-usage.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$work/bin" "$work/mod" "$work/build" "$work/home"
cat > "$work/bin/go" <<'FAKE'
#!/bin/sh
case "$2" in
	GOMODCACHE) echo "$FAKE_MODCACHE" ;;
	GOCACHE) echo "$FAKE_GOCACHE" ;;
	*) exit 1 ;;
esac
FAKE
chmod +x "$work/bin/go"
head -c 4096 /dev/zero > "$work/mod/blob"
head -c 4096 /dev/zero > "$work/build/blob"

# A size as `du -sh` / `df -h` print it: a number with a unit suffix, or with
# none -- an empty directory is a bare `0` on some filesystems (the Dell
# runners), `4.0K` on others.
size='[0-9.]+[KMGTPE]?'

failures=0
fail() {
	echo "FAIL: $*" >&2
	failures=$((failures + 1))
}

# run PATH-dirs -- runs the subject with a clean environment; output in $out.
run() {
	path="$1"
	shift
	rc=0
	out="$(env -i PATH="$path" HOME="$work/home" \
		FAKE_MODCACHE="$work/mod" FAKE_GOCACHE="$work/build" \
		"$@" "$subject" "${label-after make vet}" 2>&1)" || rc=$?
}

expect_line() {
	printf '%s\n' "$out" | grep -Eq -- "$1" || fail "$2: no line matching '$1' in:
$out"
}

# 1. Every cache reported under the label, golangci-lint's from the env.
mkdir -p "$work/lint"
head -c 4096 /dev/zero > "$work/lint/blob"
run "$work/bin:/usr/bin:/bin" GOLANGCI_LINT_CACHE="$work/lint"
[ "$rc" -eq 0 ] || fail "all present: exit $rc"
expect_line '^disk usage after make vet:$' "all present"
expect_line "^  GOMODCACHE +$size  $work/mod\$" "all present"
expect_line "^  GOCACHE +$size  $work/build\$" "all present"
expect_line "^  golangci-lint +$size  $work/lint\$" "all present"
expect_line "^  free +$size\$" "all present"

# 1b. Without GOLANGCI_LINT_CACHE the XDG default is the path reported.
run "$work/bin:/usr/bin:/bin" XDG_CACHE_HOME="$work/xdg"
expect_line "^  golangci-lint +absent  $work/xdg/golangci-lint\$" "XDG default"

# 1c. And without XDG_CACHE_HOME, golangci-lint's $HOME/.cache default.
mkdir -p "$work/home/.cache/golangci-lint"
run "$work/bin:/usr/bin:/bin"
[ "$rc" -eq 0 ] || fail "HOME default: exit $rc"
expect_line "^  golangci-lint +$size  $work/home/.cache/golangci-lint\$" "HOME default"

# 2. go missing: both Go caches absent, still exit 0.
mkdir -p "$work/nogo"
for tool in du cut df tail tr; do
	ln -s "$(command -v "$tool")" "$work/nogo/$tool"
done
run "$work/nogo"
[ "$rc" -eq 0 ] || fail "go missing: exit $rc, want 0"
expect_line '^  GOMODCACHE +absent' "go missing"
expect_line '^  GOCACHE +absent' "go missing"

# 2b. A missing label is the one usage error.
label="" run "$work/bin:/usr/bin:/bin"
[ "$rc" -eq 2 ] || fail "empty label: exit $rc, want 2"
expect_line '^usage: ' "empty label"

if [ "$failures" -ne 0 ]; then
	echo "disk-usage-test: $failures failure(s)" >&2
	exit 1
fi
echo "disk-usage-test: ok"
