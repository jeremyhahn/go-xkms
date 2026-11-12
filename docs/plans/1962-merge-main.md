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

Results to follow.
