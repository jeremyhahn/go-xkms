# 2042: hosted coverage jobs bound the toolchain container at 8g

## Cause (Codex P1 on #2042 head 2cdc6ba46a3c)

The workflow-level `IN_IMAGE_MEMORY` (ci.yml:617) is `24g` on main pushes
and same-repo PRs. The jobs `coverage` and `coverage-threshold` run on
`ubuntu-latest` on github.com and inherit it, so
scripts/in-toolchain-image.sh skips its cgroup detection and starts the
toolchain container with `--memory=24g` on a runner with less memory.

## Change

- `coverage` and `coverage-threshold` set `IN_IMAGE_MEMORY` in their own
  env: `8g` when `github.server_url == 'https://github.com'`, else the
  workflow expression (24g on bigdisk for push and same-repo PRs, empty
  for forks).
- Test: `TestHostedCoverageJobsBoundMemoryAt8g` in
  internal/buildgates/ci_coverage_memory_test.go, committed before the fix.

## Checks

- `go test -count=1 ./internal/buildgates/`
- `actionlint .github/workflows/ci.yml`
- `make lint`

Results to follow.
