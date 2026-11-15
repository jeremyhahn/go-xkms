#!/usr/bin/env bash
# Tests for coverage-total.sh. A stub stands in for `go` (through the GO
# variable): it prints canned `go tool cover -func` output and exits with a
# chosen status, so no real coverage run is needed.
set -u

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/coverage-total.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

stub="$work/go"
cat > "$stub" <<'EOF'
#!/usr/bin/env bash
cat "$STUB_OUTPUT"
exit "$STUB_STATUS"
EOF
chmod +x "$stub"

fails=0

# run <name> <want-status: 0|nonzero> <want-stdout or empty> <stub-status> <stub-output>
run() {
	local name="$1" want="$2" want_out="$3" status="$4" output="$5"
	printf '%s' "$output" > "$work/out.txt"
	local got rc
	got="$(GO="$stub" STUB_OUTPUT="$work/out.txt" STUB_STATUS="$status" \
		bash "$script" "$work/profile.out" 2>/dev/null)"
	rc=$?
	if [ "$want" = 0 ]; then
		if [ "$rc" -ne 0 ]; then
			echo "FAIL $name: exit $rc, want 0"; fails=$((fails + 1)); return
		fi
		if [ "$got" != "$want_out" ]; then
			echo "FAIL $name: printed '$got', want '$want_out'"; fails=$((fails + 1)); return
		fi
	elif [ "$rc" -eq 0 ]; then
		echo "FAIL $name: exit 0 (printed '$got'), want non-zero"; fails=$((fails + 1)); return
	fi
	echo "ok   $name"
}

run "total row of a successful run" 0 "90.2" 0 \
'example.com/xkey/pkg/a/a.go:10:	Foo		100.0%
example.com/xkey/pkg/a/a.go:20:	Bar		50.0%
total:					(statements)	90.2%
'

run "partial output then tool failure" nonzero "" 1 \
'example.com/xkey/pkg/a/a.go:10:	Foo		100.0%
'

run "no total row and exit 0" nonzero "" 0 \
'example.com/xkey/pkg/a/a.go:10:	Foo		100.0%
example.com/xkey/pkg/a/a.go:20:	Bar		100.0%
'

run "empty output and exit 0" nonzero "" 0 ''

if [ "$fails" -ne 0 ]; then
	echo "coverage-total_test: $fails failed"
	exit 1
fi
echo "coverage-total_test: all passed"
