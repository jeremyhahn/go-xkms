# Coverage hang: the unit test that stalls make coverage

Epic #1794 (E4 Test standard and suite audit).

## Symptom

- On main d55b1b73c the Devcontainer job dies inside `make coverage` with no
  failing step.
- #2042's Coverage shard 1/6 ran 95 min against its 90-min limit.
- #2071's Devcontainer job sat in `make coverage` for over 80 min.
- UNIT_TEST_TIMEOUT is 75m (Makefile), so one unit test package hangs until
  the job limit kills it before Go's own timeout panic can print.

## Method

1. Run `make test UNIT_TEST_TIMEOUT=12m` with the CI module setup
   (fresh GOMODCACHE, GOWORK=off, -mod=mod, proxy.golang.org).
2. Read the "panic: test timed out" goroutine dump: it names the running test.
3. Make that test finish (deadline context, closed channel, stopped server,
   bounded wait); no skips, no -short, no sleeps.
4. Fix production code only if the hang is there (missing Close or ctx check).
5. Prove it: `go test -count=3 -race -timeout 10m` on the package, and
   `make lint`.

## Results

Results to follow.
