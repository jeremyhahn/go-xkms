- **A FIPS build now serves a bootstrap handshake instead of binding no
  listener at all.** #296 brought go-truststrap to `v0.4.0-alpha` and re-exported
  the approved suite (`SuiteP256AESGCM` / `TSBOOT1_P256_AESGCM_SHA256`) plus
  `EnsureSuiteAvailable` from `pkg/trust/bootstrap`, but nothing consumed them:
  `pkg/server` still imported `noiseproto` directly and loaded a Noise_NK static
  key unconditionally. Noise_NK mandates X25519, which SP 800-56A Rev. 3 does not
  approve, so in a FIPS build `loadNoiseStaticKey` failed and
  `startNoiseBootstrap` logged the error and returned — no listener on the port,
  no refused handshake, nothing for an operator to see but a connection timeout
  on every client. The approved suite was available in the same binary and needed
  only a key.

  **Measured before the change**, in `pkg/server`: built `-tags fips`,
  `loadNoiseStaticKey` returns `noise: X25519 is unavailable in FIPS build`;
  built `GOFIPS140=v1.0.0` with `GODEBUG=fips140=only` — the mode
  `.github/workflows/release.yml` actually ships, which passes no `fips` tag —
  it returns `noise: invalid key size: crypto/ecdh: use of X25519 is not allowed
  in FIPS 140-only mode`. `p256proto.GenerateStaticKey()` succeeded in both. The
  two mechanisms produce different errors and the same answer, which is why
  availability is derived by attempting the operation rather than by a FIPS
  predicate.

  The listener now resolves which suites the binary can run **while it is being
  configured**, loads a static key for each, and passes both to
  `noiseboot.ServerConfig`, which dispatches per connection on the suite byte in
  the client's first frame (go-trusted-platform#209's acceptance criterion). A
  suite the build cannot run is skipped; a suite that is configured but whose key
  will not load fails the whole listener rather than silently downgrading to the
  other one; a build that can run neither fails with the new typed
  `*server.ErrNoBootstrapSuite`, which names both rejection reasons and unwraps
  to `bootstrap.ErrSuiteUnavailable`.

  New configuration under `bootstrap.noise`: `p256_static_key_file` and
  `p256_static_key_hex`, alongside the existing Noise pair. New CLI verbs
  `xkmsctl bootstrap noise generate-p256-key` and `show-p256-key`, reusing the
  Noise verbs' file handling (mode 0600, refuses to overwrite, cleans up a
  partial write). Both keys are claimed, destroyed and retained together on
  shutdown under the rule the Noise key already had — only a confirmed drain
  permits destroying protected pages a handshake may still alias — and the
  incomplete-shutdown accounting now counts both.

  Files: `pkg/server/bootstrap_suite.go` (new), `pkg/server/server.go`,
  `pkg/server/errors.go`, `pkg/config/config.go`,
  `cmd/xkmsctl/bootstrap_p256.go` (new), `cmd/xkmsctl/bootstrap.go`; docs in
  `docs/trust-bootstrap/` (all five files); `Makefile` gains `test-server`,
  `test-server-fips` and `test-config`.

  Verified by `pkg/server/bootstrap_suite_test.go`, which runs under **both**
  sets of build tags and asserts the same invariants in each: the approved suite
  is always offered, the Noise key is loaded exactly when the build can run
  Noise, and a real `noiseboot.Client` completes a P-256 handshake against the
  listener and receives the CA bundle — an executed handshake, not a compile
  check. `make test-server-fips` is the lane that compiles go-truststrap's
  refusal; it did not exist before, so the FIPS half of this code had never been
  built by any target. Mutation-checked three ways, each turning its tests red:
  disabling the P-256 arm reproduces the exact pre-fix "no handshake suite"
  failure under `-tags fips`; letting a broken configured key fall through
  defeats the silent-downgrade guard; removing `P256StaticKey` from the listener
  config leaves a FIPS build with no server published.

  Four pre-existing `loadNoiseStaticKey` tests and the `newMinimalServer` helper
  were corrected rather than skipped: the helper left `s.ctx` nil, which no
  `New()` can produce, so a subject that ran far enough to reach a shutdown-race
  check paniced instead of failing its own assertion; the four Noise tests now
  assert the build's actual contract (the loader must refuse and return no key)
  instead of presuming the suite exists.

  Also fixed, in the same feature and the same defect class:
  `pkg/trust/bootstrap`'s `TestReExportsCompose` called `GenerateNoiseStaticKey`
  and failed the test on error, so the package was **red under `-tags fips` on
  `main`** before this branch (measured at 73ff6280) — nothing ran it that way,
  because no target passed the tag. It now asserts the refusal in a build that
  cannot run Noise, and composes the re-exports in one that can.

  **Not addressed here:** the bootstrap *client*. `pkg/trust/bootstrap`'s
  `fetchNoise` goes through `truststrap.NewNoiseBootstrapper`, whose
  `truststrap.NoiseConfig` carries no suite or P-256 field, so a FIPS client
  still cannot offer the approved suite through `Fetch`. The lower-level
  `noiseboot.ClientConfig` does support it; adopting it means replacing the
  high-level facade in a live path, which is an architectural call, not a bug
  fix. Tracked upstream as go-truststrap#44. Refs #269.
