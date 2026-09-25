#!/bin/sh
# changed-go-packages-test.sh -- the test suite for changed-go-packages.sh.
#
# Real git (a throwaway repo, no network, local-only) for the diff half; a
# FAKE `go` on a replaced PATH for the reverse-dependency half, because the
# real `go list -deps ./pkg/... ./cmd/...` needs this module's full
# dependency graph resolvable and would make this "fast, no host mutation"
# unit test into a multi-minute network-and-build step -- exactly what the
# subject script exists to keep OFF the fast tier's critical path.
#
# Each case is a way the script could report the wrong scope while still
# exiting 0, which a caller would never notice until a change it should have
# tested went untested:
#
#   1. No merge-base -> empty package set (nothing to scope).
#   2. Changes confined to sdk/go/xkey/web/desktop -> empty set: those
#      modules are nested-module-build's job, not this one's.
#   3. A changed root-module package is in the set, unexpanded, when `go` is
#      unavailable or reports nothing -- the documented fail-open fallback.
#   4. A changed leaf package pulls in its reverse dependent when `go list`
#      succeeds.
#
# No network, no host mutation, under a second.
set -eu

here="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
subject="${here}/changed-go-packages.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

git() { command git -c user.email=t@example.com -c user.name=t -c commit.gpgsign=false "$@"; }

repo="$work/repo"
mkdir -p "$repo/pkg/leaf" "$repo/pkg/caller" "$repo/sdk/go" "$repo/xkey" "$repo/web/desktop"
(
	cd "$repo"
	git init -q -b main
	echo 'package leaf' >pkg/leaf/leaf.go
	echo 'package caller' >pkg/caller/caller.go
	echo 'package go' >sdk/go/x.go
	echo 'package xkey' >xkey/x.go
	echo 'package desktop' >web/desktop/x.go
	git add -A
	git commit -q -m base
)
base_sha="$(cd "$repo" && git rev-parse HEAD)"

pass=0
fail=0
check() {
	label="$1"
	shift
	if "$@"; then
		printf '  PASS  %-62s\n' "$label"
		pass=$((pass + 1))
	else
		printf '  FAIL  %-62s\n' "$label"
		fail=$((fail + 1))
	fi
}

run() { # run <merge_base> <path-prefix-for-fake-go-or-empty>
	mb="$1"
	fake_go_dir="$2"
	out="$work/out"
	rm -f "$out"
	path="$fake_go_dir:/usr/bin:/bin"
	[ -z "$fake_go_dir" ] && path="/usr/bin:/bin"
	if (
		cd "$repo"
		GITHUB_OUTPUT="$out" MERGE_BASE="$mb" PATH="$path" sh "$subject" >"$work/log" 2>&1
	); then
		rc=0
	else
		rc=$?
	fi
}
outval() { grep '^packages=' "$work/out" | tail -1 | cut -d= -f2-; }

echo "== no merge-base: nothing to scope =="
run "" ""
check "exit 0" [ "$rc" -eq 0 ]
check "packages is empty" [ -z "$(outval)" ]

echo "== change confined to nested modules: empty set =="
(
	cd "$repo"
	git checkout -q -b nested-only
	echo 'package go' >>sdk/go/x.go
	echo 'package xkey' >>xkey/x.go
	echo 'package desktop' >>web/desktop/x.go
	git add -A
	git commit -q -m "nested only"
)
run "$base_sha" ""
check "exit 0" [ "$rc" -eq 0 ]
check "packages is empty" [ -z "$(outval)" ]
(cd "$repo" && git checkout -q main && git branch -q -D nested-only)

echo "== root-module change, no go on PATH: fail-open to the changed package alone =="
(
	cd "$repo"
	git checkout -q -b root-change
	echo 'package leaf' >>pkg/leaf/leaf.go
	git add -A
	git commit -q -m "leaf change"
)
run "$base_sha" ""
check "exit 0" [ "$rc" -eq 0 ]
check "packages is exactly ./pkg/leaf" [ "$(outval)" = "./pkg/leaf" ]

echo "== root-module change, go list finds a reverse dependent =="
fakebin="$work/fakebin"
mkdir -p "$fakebin"
cat >"$fakebin/go" <<'FAKE'
#!/bin/sh
case "$1 $2" in
"list -deps")
	# emit the two packages this fixture repo declares, caller depending
	# on leaf, in the -f '{{.ImportPath}} {{join .Deps ","}}' shape.
	echo "github.com/jeremyhahn/go-xkms/pkg/leaf "
	echo "github.com/jeremyhahn/go-xkms/pkg/caller github.com/jeremyhahn/go-xkms/pkg/leaf"
	exit 0
	;;
esac
case "$1" in
list)
	shift
	for p; do
		case "$p" in
		./pkg/leaf) echo "github.com/jeremyhahn/go-xkms/pkg/leaf" ;;
		esac
	done
	exit 0
	;;
esac
echo "unhandled fake go invocation: $*" >&2
exit 1
FAKE
chmod +x "$fakebin/go"
run "$base_sha" "$fakebin"
check "exit 0" [ "$rc" -eq 0 ]
result="$(outval)"
check "includes the changed leaf package" sh -c "case ' $result ' in *' ./pkg/leaf '*) exit 0;; *) exit 1;; esac"
check "includes the reverse-dependent caller package" sh -c "case ' $result ' in *' ./pkg/caller '*) exit 0;; *) exit 1;; esac"
(cd "$repo" && git checkout -q main && git branch -q -D root-change)

echo ""
echo "passed ${pass}, failed ${fail}"
[ "$fail" -eq 0 ] || exit 1
