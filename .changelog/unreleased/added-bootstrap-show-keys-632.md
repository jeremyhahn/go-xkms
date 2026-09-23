- **Admin read capability for the trust-bootstrap listener's public keys, plus `xkmsctl bootstrap show-keys`.**
  Since the bootstrap listener began generating or unsealing its own Noise_NK
  and P-256 static keys (#35) and the deprecated config fields that used to
  supply them were removed (#631), nothing reported the listener's public
  key. `BootstrapListenerKeys` closes that gap: a `bootstrap:read`-gated,
  admin-only read on every transport (REST `GET /api/v1/bootstrap/keys`,
  gRPC/Unix `BootstrapListenerKeys`, QUIC the same JSON route, MCP
  `bootstrap.showKeys`, and the embedded SDK) reports the hex-encoded public
  key for each suite the listener currently offers, in exactly the form
  `NoiseConfig.ServerStaticKey`/`ServerP256StaticKey` (and `--noise-key`/
  `--p256-key`) already accept — there is no separate SPKI pin, since no
  consumer in the stack hashes this key before pinning it; the raw public
  key is the pin. Only public material ever crosses the boundary — the
  private scalars stay in `pkg/server/bootstrap_key_custody.go`'s protected
  memory — and a listener that has not finished starting, or is not
  configured, answers the typed `xkms.ErrBootstrapListenerNotEnabled`
  (503 / `Unavailable`) rather than a response with empty fields.
  `xkmsctl bootstrap show-keys` (`--output json` for machine-readable
  output) is the CLI surface; `test/integration/bootstrap` now discovers the
  running server's key through it, pins it into a real `NoiseConfig`, and
  completes a handshake, instead of relying on a pre-shared config value.
