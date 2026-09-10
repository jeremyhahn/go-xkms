- **A FIPS-built client can bootstrap over the Noise transport (#269, #436).**
  `ModeNoise` reached the wire through go-truststrap's `NewNoiseBootstrapper`
  facade, which carries one Curve25519 key and no suite selector, so a FIPS
  client could only ever offer Noise_NK and failed at the handshake under
  both mechanisms (`-tags fips` and `GOFIPS140` + `GODEBUG=fips140=only`),
  even against a server that #435 had already taught to serve the approved
  P-256 suite. `pkg/trust/bootstrap` now composes go-truststrap's
  suite-negotiating `noiseboot.Client` directly. `NoiseConfig` gains
  `ServerP256StaticKey` (the server's uncompressed P-256 point, as printed by
  `xkmsctl bootstrap noise show-p256-key`) and `Suite`; the suites offered
  are resolved by the same probe the listener uses, `EnsureSuiteAvailable`,
  never by a build tag. Resolution fails closed: an unavailable suite is
  skipped, a configured key that will not decode is a `SuiteError`, a pinned
  suite this build cannot run is a `SuiteError` rather than a fallback, a
  pinned suite reads only its own key (the other suite's key is never
  consulted), and
  nothing left to offer is a `NoSuiteError` naming the build as the
  constraint. The Curve25519 path is unchanged for every existing
  configuration. `xkmsctl bootstrap auto` takes `--p256-key`, the resolver's
  `noise:` scope takes `server-p256-static-key`, and the new errors are
  re-exported through `sdk/go/bootstrap`. `ModeAuto` now walks
  go-truststrap's method order over this package's own single-mode
  fetchers, so its Noise arm is the same suite-negotiating client and
  `xkmsctl bootstrap auto --p256-key` alone completes the approved
  handshake; go-truststrap's dispatcher built that arm from its facade and
  a P-256-only client failed under it with a misleading "mode not
  configured". The order, per-method timeout and aggregate error shape are
  unchanged.
