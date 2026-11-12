# #2020: merge main to clear the red secure-analyzer selftest

## Cause

- Run 42889270616: CI Gate and Static Analysis red; `make secure-analyzer-selftest`
  fails its expectations on the fixture test/lint/secure/_fixtures/bad/bad.go.
- The branch (head 240be25422) is 12 commits behind main d55b1b73c.
- Main carries 6bd7101dc (#2056): the secure analyzer skips `go: downloading`
  lines (scripts/secure-analyzer-key.sh), so a cold module cache passes; the
  selftest has a cold-cache case for it.

## Method

- One signed merge of main d55b1b73c; conflicts on paths #2020 does not own take
  main's side, paths #2020 owns keep #2020's change with main's beside it.
- Checks on a cold module cache (GOMODCACHE=/tmp/gomod, GOPROXY=proxy.golang.org):
  make secure-analyzer-selftest, make secure-analyzer, the
  secure-analyzer-symbol race tests, make lint, actionlint on the workflow files
  the PR diff vs main touches.

## Results

Results to follow.
