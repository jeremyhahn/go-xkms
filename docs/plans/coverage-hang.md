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

Run 1 (lane hangcova) taught two things:

- A lane Bash call is cut at 10 minutes, so `make test` cannot finish in one
  foreground call; it runs under nohup with a pid file.
- The shared /gocache in the lane container is missing entries, so every
  package fails to build with it:
  `could not import context (open /gocache/...-d: no such file or directory)`.

Run 2 with a private GOCACHE (lane hangcovb):

- `make test UNIT_TEST_TIMEOUT=12m`: the main pass ran pkg/server in 320s
  and passed. The `test-nofrost` pass (`-race`, Makefile:1175) failed:
  `FAIL github.com/jeremyhahn/go-xkms/pkg/server 720.338s`, "panic: test
  timed out after 12m0s" while running
  `TestServer_UnregisterPhoneBackend_NotRegistered (13s)`
  (pkg/server/server_coverage_test.go:509).
- No single test hangs. The cause is a leak: tests built a Server with
  `New(cfg)` and never called Shutdown (for example
  `TestServer_MetricsGatherer_NoExtraGatherers`,
  pkg/server/metrics_gatherer_test.go:68), so each one left its in-process
  qrdb node running. Its compaction, retention and reclaim schedulers kept
  working on the removed t.TempDir() ("open /tmp/Test.../001/file: no
  such file or directory") for the rest of the run, and each later `New`
  went from about 5s to 15-25s under -race. On CI's slower runners this
  ran past the 75m unit timeout and the job limit.
  `TestServer_Reload_LogsWhenListenersRunning`
  (pkg/server/reload_i705_test.go:29) swapped `server.qrdbNode` so
  Shutdown never closed the original node.
- Fix (test code only): `newServerWithCleanup` (pkg/server/server_test.go)
  registers Shutdown with t.Cleanup (Shutdown is latched); 213 call sites
  in pkg/server tests use it; the reload test closes the original node.
  Production code is unchanged.
- After: `make test-nofrost UNIT_TEST_TIMEOUT=12m` passes; pkg/server 221s,
  no leaked-scheduler lines.
- `go test -count=3 -race -tags "codec_cbor codec_json codec_msgpack"
  ./pkg/server/`: 1 failure in 3 iterations,
  `TestServer_UnixGRPC_GetCACertificate_WithCA`
  (pkg/server/server_ca_grpc_unix_test.go:228, its 5s RPC deadline ran out
  during a qrdb "data-plane recycle"). That test already shut its server
  down, so this change does not touch it; alone it passed with -count=5
  -race. It is a separate flake under load, left for a later slice.
- `make lint`: passes (0 issues on every module and tag set).
