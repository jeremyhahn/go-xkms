- **`make lint` gave golangci-lint a 10m wall-clock budget that the root
  module exceeds whenever the shared runner is loaded, reddening whichever PR
  is in the queue** (#360; closes #363, the same defect observed on PR #362).
  `--timeout` measures wall clock from process start, so on the oversubscribed
  fleet it measured fleet load rather than linter work: the root module took
  11m57s at load ~30 on 24 cores and was killed at 10m, and run 11456 printed
  "0 issues." before tripping the deadline on the way out. The budget now
  lives once, as `run.timeout: 30m` in `.golangci.yml` — sized to clear the
  worst observed contention with the same headroom `go test -timeout 30m`
  already assumes for Unit Tests in ci.yml — and the hard-coded
  `--timeout=10m` is removed from the root Makefile, along with the
  `--timeout=5m` args that would have kept overriding the config in
  `docker-tests.yml` and `coverage.yml`. Every other invocation site
  (`sdk/go/Makefile`, the ci.yml Lint job via `make lint`) already ran with
  no flag, so the config value is the only bound anywhere; golangci-lint v2
  has no default timeout, and `run.timeout` is a valid key in the schema of
  every pinned version (v2.6.2, v2.7.2, v2.12.2, v2.13.2). The ci.yml Lint
  job gains a `timeout-minutes: 60` backstop so a genuinely hung linter fails
  as a job timeout rather than running to the runner's implicit limit.
  Deliberately not a retry-on-timeout, which would hide a genuine slowdown.
  Verified with `golangci-lint config verify` and a green `make lint` over
  the root, `sdk/go` and `web/desktop` modules.
