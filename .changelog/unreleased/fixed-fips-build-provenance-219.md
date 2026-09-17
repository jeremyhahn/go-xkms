- **The PKCS#11 module's FIPS labels now rest on the artifact's build
  provenance instead of the module state of the process that loaded it**
  (#219). `pkg/crypto/fips/fips.go`, `pkg/pkcs11/module/mechanism.go`.
  `fipsBuild` read `fips.Compiled` — `crypto/fips140.Enabled()` — which is
  runtime module state, not build provenance: `GODEBUG=fips140=off` turns it
  false on a binary genuinely built with `GOFIPS140`, and `GODEBUG=fips140=on`
  turns it true on one that was not. A user reading `CK_INFO.libraryDescription`
  or `CK_TOKEN_INFO.model` to confirm they hold a FIPS module could therefore be
  told the wrong thing in both directions: the shipped `libxkms_pkcs11_fips.so`
  denied being a FIPS build under `fips140=off`, and a stock build claimed to be
  one under `fips140=on`. New `fips.BuildSetting` and `fips.Built` read the
  `GOFIPS140` value the toolchain stamps into the binary at link time (the
  `build GOFIPS140=<value>` line of `go version -m`), which no environment
  variable alters and which survives into a c-shared library a foreign process
  `dlopen()`s; `fipsBuild` now reads `fips.Built`, so the label describes the
  artifact and nothing else. `BuildSetting` returns the selector the build ran
  with — `latest`, `inprocess`, `certified` or `v1.Y.Z` — so a compliance
  manifest can name the module version rather than only the fact of a FIPS
  build. **`AlgorithmPermitted` is deliberately unchanged**: the approved-only
  allowlist still follows `Compiled() || Enabled()`, the crypto actually in
  force, so an operator who sets `GODEBUG=fips140=off` has turned the module
  off and the predicate permits everything, exactly as in a non-FIPS build —
  whether a validated artifact may be talked out of its posture that way is the
  owner's policy call recorded on #219, and changing it means adding `Built` to
  that OR and nothing else. Verified by measuring a probe built both ways
  (`GOFIPS140=latest` records the setting and it persists under
  `GODEBUG=fips140=off`; an unset build and an explicit `GOFIPS140=off` build
  both record nothing, so absent and off read back alike through `Built` while
  `BuildSetting` still distinguishes them), by unit tests driving
  `buildSettingFrom`/`builtFrom` with synthetic build metadata including the nil
  and setting-absent cases, by tests pinning `BuildSetting` and `Built` against
  the `GOFIPS140` environment variable that must not move them, and by the
  PKCS#11 label suite, which re-execs itself under `GODEBUG=fips140=on` and
  `=off` and asserts the labels hold still in both.
