# #1962: merge main to clear the red secure-analyzer selftest

## Cause

PR #1962 (feat/1748-ssh-migrator, head b50ed31fd9) has CI Gate and Static
Analysis red on run 42866381864: `make secure-analyzer-selftest` fails its
expectations on the fixture test/lint/secure/_fixtures/bad/bad.go (same
failure as #2020). The branch is behind main d55b1b73c. Main carries
6bd7101dc (#2056): the secure analyzer skips `go: downloading` lines
(scripts/secure-analyzer-key.sh), so a cold module cache no longer pollutes
the analyzer output the selftest compares.

## Method

One signed merge of main (`git merge -S --no-edit d55b1b73c`); conflicts
resolved for main on files #1962 does not own, both sides kept on files it
owns; then the selftest, the sweep, the PR package tests, make lint and
actionlint on the workflow files that differ from main. Code changes only if
the selftest or sweep still fails after the merge (test commit first).

The older local tip b70a35361 (8b16248b6 test, b70a35361 fix: ssh/migrate
accepts the ssh/ namespace view) never reached GitHub; it is held outside
the branch and is not recreated here.

## Results

- Merge: 844075d0a, parents fdd764830 (#1962 with this plan) and d55b1b73c
  (main). No conflicts.
- Module setup: fresh GOMODCACHE=/tmp/gomod, GOWORK=off, -mod=mod,
  GOPROXY=https://proxy.golang.org (cold cache, as CI); no missing module or
  checksum mismatch.
- `make secure-analyzer-selftest`: pass (exit 0), including the cold-cache
  `go: downloading` cases from #2056.
- `make secure-analyzer`: pass, clean on 5 rungs, 2 allowlist entries all
  still needed.
- PR package tests (`go test -count=1 -race -tags "codec_cbor codec_json
  codec_msgpack"`): pass on pkg/ssh/migrate, pkg/ssh/authorized,
  pkg/ssh/keys, pkg/ssh/known_hosts, pkg/ssh/profile.
- ssh/ namespace view: covered by TestRunMovesTheOldLayout (legacy keys
  seeded under the `ssh/` prefix) and TestRun_MigratesTheTenantNamedSSH
  (`ssh/ssh/...`, tenant named ssh), both passing above. The held
  b70a35361 fix is not recreated; the migrate package is unchanged here.
- `make lint`: pass, 0 issues on every module and tag set.
- actionlint: no workflow file differs from main after the merge, so
  nothing to lint.
- No code change beyond the merge was needed; no fixture or allowlist edit.
