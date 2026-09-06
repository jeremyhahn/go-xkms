- **The `logins` integration harness could not start its virtual
  authenticator: it still exec'd `--auto-uv`, a flag removed from the xkey
  CLI** (#409). `test/integration/logins/fido2_test.go` ran
  `xkey fido2 --require-touch=false --auto-uv --pin=false`; #365 removed
  `--auto-uv`, so Cobra rejected the unknown flag and every fido2 leg of the
  suite was dark. No CI job noticed, because the suite runs only inside the
  devcontainer.

  Nothing replaces the flag, because nothing in this ceremony needs it. The
  relying party's `user_verification` defaults to `preferred`, so the xkey
  client sets `options.uv=false` (`webauthn_ceremony.go`) and the
  authenticator's `deriveRPUVPolicy` reads the request as `discouraged`; the
  server applies no UV check of its own. What CTAP2 does require is user
  presence, and the harness already supplies it with its `xkey touch` pump.
  A no-PIN ceremony therefore completes and simply carries no UV — which is
  the honest outcome #280 removed `--auto-uv` to get.

  The exec argv moves to `test/integration/logins/argv.go`
  (`VirtualAuthenticatorArgv`). That file carries no build tag on purpose:
  the rest of the package is behind `integration && logins`, so the argv was
  unreachable to every test that runs in CI. Untagged, it is reachable from
  `xkey/cmd/xkey/cmd`, whose new `fido2_harness_test.go` resolves it against
  the real Cobra command tree — the subcommand must resolve to `fido2`, every
  word must be a registered flag, every value must be one the flag accepts,
  and the live flags are restored afterwards so the guard cannot leak state
  into the package's other tests. A flag removed or renamed on the CLI is now
  a red unit test instead of a suite that will not start. The four tests are
  named in CI's existing `require-tests.sh` list for `cmd/xkey/cmd`, the only
  step that runs that package.

  The `doc.go` and `integration-test-logins` Makefile comments no longer
  document the removed flag. `CHANGELOG.md`'s `--auto-uv` mention is the
  entry recording its removal and is left alone; the remaining `.md`
  references belong to the #376 docs sweep.
