- **A FIPS-built artifact now keeps enforcing its approved-algorithm allowlist
  even when an operator sets `GODEBUG=fips140=off`** (#219, owner ruling on
  the policy question `pkg/crypto/fips/algorithms.go` left open in #568).
  `AlgorithmPermitted` disabled the allowlist whenever `Compiled() ||
  Enabled()` was false — the crypto actually in force — which let an
  operator turn a validated build's module off at runtime and have it accept
  any algorithm the caller already trusted, exactly as a non-FIPS build
  does. `AlgorithmPermitted` now also consults `Built`, the build-provenance
  signal #568 added: the allowlist stays active whenever the binary was
  built with an enabling `GOFIPS140`, regardless of the module's runtime
  state. A binary never built with `GOFIPS140` is unaffected — it still
  permits every algorithm whenever neither `Compiled` nor `Enabled` is
  active. Verified by unit tests driving `Built` through a package-private
  indirection (`builtFunc`): a forced `Built()=true` refuses every
  non-approved algorithm regardless of `GODEBUG=fips140=off`, and a forced
  `Built()=false` alongside an unactivated module and `GOFIPS140=off`
  permits them, matching the two new cases in `algorithms_test.go`.
