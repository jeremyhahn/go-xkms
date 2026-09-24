- **The standalone `TrustedCA`'s `TrustedCAConfig.MultiTenant` config section
  is deleted; `WithMultiTenant()` is now the only multi-tenant switch** (go-xkms#946).
  `MultiTenantConfig` (`Enabled`, `DefaultTenantID`,
  `TenantIsolation.{EnforceIsolation,AllowCrossTenantSuperAdmin}`) was
  defaulted by `DefaultTrustedCAConfig` and checked by `TrustedCAConfig.Validate`,
  but nothing in `pkg/acme/client` or `pkg/acme/admin` ever read it: the real
  switch was, and remains, the unexported `TrustedCA.multiTenant` bool set only
  by the `WithMultiTenant()` option, so an operator setting
  `multi_tenant.enabled: true` in a config file previously got a silent
  single-tenant server with no error. Investigation (go-trusted-ca heritage,
  and comparison with xkmsd's embedded ACME server, which has no
  `pkg/config.ACMEConfig` multi-tenant key and always constructs
  `admin.NewTenantAwareAdminService` directly in `cmd/xkmsd/admin.go`) found
  no runtime consumer for `DefaultTenantID` or `TenantIsolation` anywhere in
  the tree, so the config section was deleted rather than wired to a second,
  redundant switch. **BREAKING**: `TrustedCAConfig.MultiTenant`,
  `client.MultiTenantConfig`, and `client.TenantIsolationConfig` no longer
  exist; the `multi_tenant:` YAML/JSON key is gone. A caller that set
  `cfg.MultiTenant.Enabled = true` and expected multi-tenant mode must call
  `client.WithMultiTenant()` (with `client.WithQRDB(...)`) instead — `New`
  already fails closed with `ErrMissingQRDB` if `WithMultiTenant()` is used
  without a QRDB service. Files: `pkg/acme/client/trustedca_config.go`,
  `pkg/acme/client/options.go`, `pkg/acme/client/trustedca_test.go`,
  `pkg/acme/client/config_validation_test.go`,
  `docs/acme-issuance/engineering.md`.
