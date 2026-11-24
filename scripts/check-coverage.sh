#!/bin/bash
# Report per-package statement coverage against a threshold.

set -uo pipefail

THRESHOLD="${1:-}"
if [ -z "$THRESHOLD" ]; then
	echo "usage: check-coverage.sh THRESHOLD PROFILE [PROFILE...]" >&2
	exit 1
fi
shift
if [ "$#" -eq 0 ]; then
	echo "check-coverage.sh: no coverage profile given" >&2
	exit 1
fi

for f in "$@"; do
	if [ ! -f "$f" ]; then
		echo "check-coverage.sh: coverage profile not found: $f" >&2
		exit 1
	fi
done

# Excluded from the THRESHOLD REPORT only -- these still run under `go test`
# wherever a lane's package list reaches them (harmless: mocks/testutil have
# little or nothing to cover), they are just not production code held to the
# 90% bar. This is the one place the exclusion list is applied (issue #703):
#   /mocks, /testutil,        - generated/hand-written test doubles and
#   /storagetest, pkcs11test    shared test-support harnesses (storagetest
#                                holds storage.Backend's executable test
#                                contract, imported by other packages'
#                                _test.go files; it is not itself production
#                                code), not production code
#   /proto                    - generated protobuf stubs
#   yubikey, smartcardhsm    - tests that need physical hardware to exercise
EXCLUDE_PATTERN='(/mocks/|/testutil/|/storagetest/|/pkcs11test/|/proto/|/yubikey/|/smartcardhsm/)'

cat "$@" | awk -v threshold="$THRESHOLD" -v exclude="$EXCLUDE_PATTERN" '
	# Skip each profile'"'"'s "mode: ..." header line.
	/^mode: / { next }
	NF < 3 { next }
	{
		filespec = $1
		numstmt = $2 + 0
		count = $3 + 0

		colon = index(filespec, ":")
		file = (colon > 0) ? substr(filespec, 1, colon - 1) : filespec

		if (file ~ exclude) next

		slash = match(file, /\/[^\/]+\.go$/)
		pkg = (slash > 0) ? substr(file, 1, slash - 1) : file

		# A block appears once per merged lane: count its statements once,
		# and treat it as covered if any lane hit it.
		if (!(filespec in blockpkg)) {
			blockpkg[filespec] = pkg
			blockstmt[filespec] = numstmt
		}
		if (count > 0) {
			blockhit[filespec] = 1
		}
		seen[pkg] = 1
	}
	END {
		for (b in blockpkg) {
			total[blockpkg[b]] += blockstmt[b]
			if (b in blockhit) {
				coveredstmt[blockpkg[b]] += blockstmt[b]
			}
		}
		print "=== Per-Package Statement Coverage (Threshold: " threshold "%) ==="
		print ""

		n = 0
		for (pkg in seen) {
			pkgs[n] = pkg
			n++
		}
		# Stable, readable output: alphabetical.
		for (i = 0; i < n; i++) {
			for (j = i + 1; j < n; j++) {
				if (pkgs[j] < pkgs[i]) {
					tmp = pkgs[i]; pkgs[i] = pkgs[j]; pkgs[j] = tmp
				}
			}
		}

		failed = 0
		numpkgs = 0
		for (i = 0; i < n; i++) {
			pkg = pkgs[i]
			t = total[pkg] + 0
			c = coveredstmt[pkg] + 0
			if (t == 0) {
				continue
			}
			pct = 100.0 * c / t
			numpkgs++
			if (pct < threshold) {
				printf "  %-70s %5.1f%%  (%d/%d statements)\n", pkg, pct, c, t
				failed++
			}
		}

		print ""
		if (failed > 0) {
			printf "Found %d package(s) below %d%% threshold (of %d measured)\n", failed, threshold, numpkgs
			print "See issue #704, #705, #706 for tracking"
			exit 1
		} else if (numpkgs > 0) {
			printf "All %d measured packages meet %d%% threshold\n", numpkgs, threshold
			exit 0
		} else {
			print "No packages with statements found in the given profile(s)"
			exit 1
		}
	}
'
