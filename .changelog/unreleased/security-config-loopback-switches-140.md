- **Two hardcoded loopback literals that relaxed validation are now
  config-gated, off by default, on every surface that constructs the affected
  types (#140).** The ACME enrollment challenge handler substituted the
  request's client IP for the challenge validation target whenever an
  authorization's permanent-identifier was the literal `127.0.0.1`, with no
  way to turn the substitution off; the Azure Key Vault backend accepted any
  `localhost`/`127.0.0.1` vault URL unconditionally, in every build,
  including production. Both were flagged as benign-but-security-relevant in
  the #140 configuration audit and ruled on (owner, 2026-09-21, option A):
  make each an explicit, config-gated development switch, default false.

  `acme.enrollment.allow_loopback_identifier`
  (`XKMS_ACME_ENROLLMENT_ALLOW_LOOPBACK_IDENTIFIER`) now gates the
  substitution in `ChallengeHandler`; with it off (the default) a loopback
  identifier is refused with `ErrLoopbackIdentifierNotAllowed` before the
  challenge verifier runs, instead of silently validating against the
  caller's address. The standalone `TrustedCA` library
  (`pkg/acme/client`, not built through `pkg/config`/viper) carries the same
  switch as `TCAACMEConfig.AllowLoopbackIdentifier`
  (`allow_loopback_identifier`), threaded into the same `ChallengeHandler`
  through `handlers.Params.AllowLoopbackIdentifier`, also off by default.

  `backends.azurekv.allow_local_vault_url`
  (`XKMS_BACKENDS_AZUREKV_ALLOW_LOCAL_VAULT_URL`) gates the local-URL bypass
  in `azurekv.Config.Validate`; with it off (the default) a `localhost`/
  `127.0.0.1` vault URL fails with `ErrLocalVaultURLNotAllowed`. The
  `xkms.AutoInitialize` map-based construction path
  (`pkg/xkms/register_azurekv.go`) reads the same switch from its
  `BackendConfigs` map under `"allow_local_vault_url"`, parsed as a `bool`; a
  present value that is not a `bool` fails with the new
  `xkms.ErrInvalidBackendConfigValue` instead of being silently ignored, the
  one behavior on this surface that previously had no failure mode at all.

  All defaults are `false`, so anyone relying on the previous unconditional
  behavior for local development or testing must now set the corresponding
  key to `true` on whichever of these surfaces they use.

  Files: `pkg/acme/server/handlers/challenge.go`, `service.go`,
  `challenge_test.go`; `pkg/acme/client/trustedca_config.go`, `trustedca.go`,
  `trustedca_loopback_identifier_test.go`; `pkg/backend/azurekv/config.go`,
  `errors.go`, `config_test.go`; `pkg/config/acme.go`, `config.go`,
  `load_test.go`; `pkg/server/backend_azurekv.go`; `cmd/xkmsd/acme.go`;
  `pkg/xkms/register_azurekv.go`, `errors.go`, `register_azurekv_test.go`;
  `docs/acme-issuance/engineering.md`, `docs/crypto-backends/engineering.md`,
  `docs/backends/azurekv.md`; example configs
  `configs/xkmsd.yaml{,.example}`, `examples/config/config-server.yaml`.
  Verified by `go test` across `pkg/acme/server/handlers`,
  `pkg/acme/client` (`-tags codec_json`), `pkg/backend/azurekv`
  (`-tags azurekv`), `pkg/xkms` (`-tags azurekv`) and `pkg/config`: each key
  defaults to refusing the loopback/local case on every surface that builds
  the corresponding type, each is settable `true`, and — for the
  `pkg/config`-driven keys — the environment name wins over a file that says
  nothing.
