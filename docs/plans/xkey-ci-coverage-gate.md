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

Module setup as CI (DS-7500): fresh GOMODCACHE, GOWORK=off, -mod=mod,
GOPROXY=https://proxy.golang.org.

- Gate logic, on a one-package list (`COVERAGE_GATE_PKGS=./pkg/shellquote`,
  100.0%) to keep the run short:
  - `make coverage-gate COVERAGE_THRESHOLD=101`: exit 2,
    `FAIL xkey coverage 100.0% is under the threshold 101%`.
  - `make coverage-gate COVERAGE_THRESHOLD=0`: exit 0,
    `OK xkey coverage 100.0% meets the threshold 0%`.
- Real total, `make -C xkey coverage-gate` (CI's full package list and
  tags): 90.2% of statements, `OK ... meets the threshold 90%`, exit 0.
  The margin is 0.2 points, so a small drop fails CI.

## Status

- Done: the `coverage-gate` target (xkey/Makefile).
- Blocked: the lane's policy guard refused the edits to
  .github/workflows/ci.yml and docs/SPEC.md (LANE_POLICY_ALLOW not set
  for this session). Still to do: in both xkey steps, replace the
  `go test -race -timeout 60m -tags "codec_json tpm_simulator" -count=1 \`
  command and its package lines with `make coverage-gate`, and change
  docs/SPEC.md:181 from `xkey/Makefile:151` to `xkey/Makefile:154`.
