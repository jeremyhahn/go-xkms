- **Every remaining bare `errors.New`/`fmt.Errorf` return in production code
  is now a typed error.** 42 call sites across `xkey/cmd/xkey/cmd` (oidc.go,
  oidc_aws.go, ssh_connect.go, extension_serve.go, pin_tpm.go), `pkg/tpm2`
  (password.go, provision.go, tpm.go), `pkg/backend/pkcs11` (cert_config.go),
  `pkg/backup` (file.go), `pkg/trust/clusterca` (cache.go,
  keystrategy_tpmkek.go), `pkg/xkms` (piv_manager.go),
  `xkey/pkg/gui/services` (tpm_service.go), `cmd/xkmsctl` (ssh.go),
  `pkg/seal` (secret_sealer.go), `pkg/tpm2/store` (helpers.go) and
  `sdk/go/client/ssh` (mcp.go) now return package sentinels (`var
  ErrXxx = errors.New(...)`) or the shared `pkg/errs.Message`/`errs.Wrapped`
  typed values instead of constructing an error inline, so every caller can
  match them with `errors.Is`/`errors.As` (go-xkms#700). `cmd/xkmsd/acme.go`
  gained one more sentinel (`ErrACMENoClientCAPEM`) discovered while
  evaluating the guard below, and `acmeInitError.Unwrap` now returns both
  its `Sentinel` and `Err` (`Unwrap() []error`) so a cause stored in `Err`
  is reachable even when `Sentinel` is also set — previously `Unwrap`
  returned only one of the two. `cmd/xkmsd/acme.go`'s `acme.reuse_tls`
  placeholder error is deliberately left inline: go-xkms#694 deletes that
  config key outright. Every new site has an `errors.Is`/`errors.As`
  regression test. `.golangci.yml` documents, but does not yet enable,
  `err113` as the guard against regressions: golangci-lint v2.13.2's
  `err113` correctly ignores sentinel `var Err... = errors.New(...)`
  declarations and would report 0 issues against every file this change
  touched, but reports 107 pre-existing findings (inline dynamic errors and
  direct `==`/`!=` error comparisons) across 41 files this change did not
  touch — several under other open PRs (`pkg/tpm2/key.go`,
  `platform_keystore.go`) — so enabling it now would fail `make lint`
  outside this change's scope; a follow-up issue should clear that backlog
  before `err113` is turned on.