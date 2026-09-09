- **The Shamir ceremony test fixture keeps shares in protected memory.** The
  four copies of `testCaptureDistributor` in the xkms service, MCP, gRPC and
  REST barrier tests split the barrier secret with quicraft's deprecated
  string-share `Split` and retained every share as a Go string, which cannot
  be wiped, until the test process exited. They are replaced by the one
  `internal/shamirtest.CaptureDistributor`, built on `SplitProtected`: shares
  live as `ProtectedShare` in mlock'd guard-paged memory, a rekey destroys the
  previous round instead of dropping it, and the test's cleanup destroys the
  last one. The base64 text a request carries is materialised only where the
  request is built and is not retained. The eight `//nolint:staticcheck`
  directives that #45 added against the deprecated API are gone (#46).
