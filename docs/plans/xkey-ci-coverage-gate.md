# xkey-ci-coverage: coverage profile and threshold gate in CI

Row: `xkey-ci-coverage` (docs/SPEC.md:181). Related: #704 (xkey coverage under 90%).

## Objective

CI's Nested Module Tests job enforces xkey's own `COVERAGE_THRESHOLD`
(90, `xkey/Makefile:154`). Today no target enforces it.

## Slice

1. `xkey/Makefile`: new target `coverage-gate`. It runs the package list and
   tags the CI steps used for their main `go test -race ... -count=1`
   command, with `-coverprofile=$(COVERAGE_DIR)/ci.out -covermode=atomic`,
   prints the `go tool cover -func` total line, and exits non-zero when the
   total is under `$(COVERAGE_THRESHOLD)` (awk on the total line).
2. `.github/workflows/ci.yml`: the two xkey steps ("xkey tests (toolchain
   image)" and "xkey tests (native)") call `make coverage-gate` in place of
   that long command. Every other line stays.
3. docs/SPEC.md:181: line reference 151 -> 154.

A make target has no unit test; the proof is the gate's behaviour at the
threshold extremes, recorded below.

## Out of scope

- The threshold's value (the coordinator decides if the total is under 90).
- New tests to raise coverage (#704).
- Any other workflow job.

## Results

(to follow: gate at 101, gate at 0, measured total)
