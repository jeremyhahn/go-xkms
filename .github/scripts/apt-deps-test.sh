#!/bin/sh
# apt-deps-test.sh — the test suite for apt-deps.sh.
#
# The script has three properties worth a test each, because each is a way
# the step could report success while the job is not in the state it claims:
#
#   1. A package that is already present must not reach apt at all. If it
#      does, the network is back in the loop for every job and the
#      bake-into-the-image path buys nothing.
#   2. A transient apt failure must be retried, a persistent one must fail
#      the step naming the packages, and the attempt count must be the
#      configured one -- not one, not unbounded.
#   3. apt's exit status is not the verdict. A package dpkg still does not
#      have after a "successful" install is a failure.
#
# apt-get and dpkg-query are FAKES on a replaced PATH: dpkg-query answers from
# a state file, apt-get appends every invocation to a log, fails the first N
# install calls per a counter file, and on success marks the packages
# installed -- except when told to lie, which is what case 3 needs.
#
# MUTATION: run with --mutate to pin the attempt count to one in a COPY of
# apt-deps.sh and re-run everything. The transient-failure case must go red;
# if it does not, the retry is not being tested and the suite says so.
#
# No network, no host mutation, under a second.

set -eu

here="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
subject="${here}/apt-deps.sh"
mutate=""
[ "${1:-}" = "--mutate" ] && mutate=1

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$work/bin"
PATH="$work/bin:/usr/bin:/bin"
export PATH
export APT_DEPS_BACKOFF=0
export FAKE_STATE="$work/installed"
export FAKE_LOG="$work/apt.log"
export FAKE_FAILS="$work/fails"
export FAKE_LIE="$work/lie"

if [ -n "$mutate" ]; then
	# shellcheck disable=SC2016  # a sed script: expansion here would be the bug
	sed -e 's|^attempts="${APT_DEPS_ATTEMPTS:-5}"$|attempts=1|' "$subject" > "$work/subject.sh"
	chmod +x "$work/subject.sh"
	subject="$work/subject.sh"
	if ! grep -q '^attempts=1$' "$subject"; then
		echo "MUTATION DID NOT APPLY — the line it rewrites has changed." >&2
		exit 1
	fi
	echo "### MUTATED: attempt count pinned to one"
fi

cat > "$work/bin/dpkg-query" <<'FAKE'
#!/bin/sh
# dpkg-query -W -f='${Status}' <pkg>: the last argument is the package.
for last; do :; done
if grep -qx -- "$last" "$FAKE_STATE" 2>/dev/null; then
	printf 'install ok installed'
	exit 0
fi
echo "dpkg-query: no packages found matching $last" >&2
exit 1
FAKE
cat > "$work/bin/apt-get" <<'FAKE'
#!/bin/sh
echo "$*" >> "$FAKE_LOG"
for a; do
	case "$a" in
		update) exit 0 ;;
		install) break ;;
	esac
done
left=$(cat "$FAKE_FAILS" 2>/dev/null || echo 0)
if [ "$left" -gt 0 ]; then
	echo $((left - 1)) > "$FAKE_FAILS"
	echo "E: Failed to fetch (fake)" >&2
	exit 100
fi
[ -e "$FAKE_LIE" ] && exit 0
seen_install=""
for a; do
	if [ -n "$seen_install" ]; then
		case "$a" in -*) ;; *) echo "$a" >> "$FAKE_STATE" ;; esac
	fi
	[ "$a" = install ] && seen_install=1
done
exit 0
FAKE
chmod +x "$work/bin/dpkg-query" "$work/bin/apt-get"

reset() { # reset <installed pkgs...>
	: > "$FAKE_STATE"
	: > "$FAKE_LOG"
	rm -f "$FAKE_FAILS" "$FAKE_LIE"
	for p in "$@"; do echo "$p" >> "$FAKE_STATE"; done
}
installs() { grep -c ' install ' "$FAKE_LOG" 2>/dev/null || true; }

pass=0
fail=0
check() { # check <label> <condition...>
	label="$1"
	shift
	if "$@"; then
		printf '  PASS  %-62s\n' "$label"
		pass=$((pass + 1))
	else
		printf '  FAIL  %-62s\n' "$label"
		sed 's/^/          /' "$work/out" 2>/dev/null || true
		fail=$((fail + 1))
	fi
}
run() { # run <pkgs...>: runs the subject, records its exit status in $rc
	if "$subject" "$@" >"$work/out" 2>&1; then rc=0; else rc=$?; fi
}

echo "== present packages never reach apt =="
reset libicu-dev libusb-1.0-0-dev
run libicu-dev libusb-1.0-0-dev
check "exit 0 when everything is present" [ "$rc" -eq 0 ]
check "apt-get not invoked at all" [ ! -s "$FAKE_LOG" ]

echo "== only the missing packages are installed =="
reset libicu-dev
run libicu-dev libusb-1.0-0-dev softhsm2
check "exit 0" [ "$rc" -eq 0 ]
check "one install call" [ "$(installs)" -eq 1 ]
check "install names only the missing packages" grep -q ' install -y libusb-1.0-0-dev softhsm2$' "$FAKE_LOG"
check "install does not name the present package" sh -c '! grep -q "install.*libicu-dev" "$FAKE_LOG"'
check "IPv6 skipped on the fetch" grep -q 'Acquire::ForceIPv4=true install' "$FAKE_LOG"

echo "== a transient failure is retried =="
reset
echo 2 > "$FAKE_FAILS"
APT_DEPS_ATTEMPTS=5 run softhsm2
check "exit 0 after two failures then success" [ "$rc" -eq 0 ]
check "three install attempts" [ "$(installs)" -eq 3 ]

echo "== a persistent failure fails the step, bounded, naming the packages =="
reset
echo 99 > "$FAKE_FAILS"
APT_DEPS_ATTEMPTS=3 run softhsm2 libtss2-dev
check "exit 1" [ "$rc" -eq 1 ]
check "exactly the configured number of attempts" [ "$(installs)" -eq 3 ]
check "message names softhsm2" grep -q 'softhsm2' "$work/out"
check "message names libtss2-dev" grep -q 'libtss2-dev' "$work/out"
check "message says it gave up" grep -q 'giving up after 3' "$work/out"

echo "== apt's exit status is not the verdict =="
reset
: > "$FAKE_LIE"
APT_DEPS_ATTEMPTS=1 run softhsm2
check "exit 1 when apt says yes but dpkg says no" [ "$rc" -eq 1 ]
check "message names the package dpkg lacks" grep -q 'dpkg does not have' "$work/out"

echo "== usage =="
run
check "no arguments is usage, exit 2" [ "$rc" -eq 2 ]

echo ""
echo "passed ${pass}, failed ${fail}"

if [ -n "$mutate" ]; then
	if [ "$fail" -eq 0 ]; then
		echo "MUTATION SURVIVED: pinning the attempt count to one broke NOTHING." >&2
		exit 1
	fi
	echo "mutation killed by ${fail} case(s) — the retry tests are real."
	exit 0
fi

[ "$fail" -eq 0 ] || exit 1
