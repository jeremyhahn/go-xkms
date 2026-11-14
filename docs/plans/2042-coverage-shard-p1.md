# #2042 Codex P1: coverage-shard runs one test binary at a time

- Test: `TestCoverageTargetsRunOneTestBinary` (internal/buildgates/ci_coverage_memory_test.go) pins `GOMEMLIMIT := 5GiB` and a GOFLAGS line ending in `-p=1` for both `coverage` and `coverage-shard`.
- Fix: Makefile `coverage-shard: export GOFLAGS := $(strip $(GOFLAGS) -p=1)`, so each CI shard keeps make coverage's single-process bound in the 8 GiB swap-off container.
- Checks: buildgates unit tests (root module, codec tags) and `make lint`.
