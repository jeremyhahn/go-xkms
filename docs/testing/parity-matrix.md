# xkey GUI / CLI / xkmsctl Parity Matrix

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: server-backed operations, their GUI / xkey CLI / xkmsctl entry points and REST routes, and their live-backend test status.

Surface-level map of every operation that round-trips to the xkms-server,
with the corresponding GUI service method, xkey CLI command, xkmsctl
command, and backend endpoint. This is the inventory used to plan the
live-backend Playwright test suite under `xkey/frontend/tests/e2e/live/`.

Status legend:
- `ok` — a live E2E test exists in `xkey/frontend/tests/e2e/live/`. None of
  them can pass today: the dev server they need does not start (see
  [live-e2e.md](live-e2e.md)).
- `none` — no coverage at the live-backend tier
- `n/a` — the surface is purely local, does not involve xkms-server

In the CLI and GUI columns, `none` means no such entry point exists.

Sources: GUI methods are on the services in `xkey/pkg/gui/services/`
(`trust_service.go`, `ca_service.go`, `key_service.go`,
`certificate_service.go`, `admin_service.go`, `tenant_service.go`,
`oidc_service.go`). xkey commands are in `xkey/cmd/xkey/cmd/`, xkmsctl
commands in `cmd/xkmsctl/`. REST routes are the `/api/v1` table in
`pkg/api/rest/routes.go`; line numbers below are that file's.

## Trust Store

| Operation | GUI (service.method) | xkey CLI | xkmsctl | Backend endpoint | Live test |
|---|---|---|---|---|---|
| Fetch CA bundle (Direct HTTPS) | `TrustService.ImportFromTrustStrap` method=direct | `xkey trust bootstrap --method=direct` | `xkmsctl bootstrap direct` (copies an operator-supplied bundle file; no fetch) | `GET /v1/ca/bootstrap` (`:131`) | none |
| Fetch CA bundle (SPKI pin) | `TrustService.ImportFromTrustStrap` method=spki | `xkey trust bootstrap --method=spki` | `xkmsctl bootstrap spki` | `GET /v1/ca/bootstrap` (SPKI-verified) | **ok** |
| Fetch CA bundle (Noise_NK) | `TrustService.ImportFromTrustStrap` method=noise | `xkey trust bootstrap --method=noise` | `xkmsctl bootstrap noise` | Noise_NK listener | **ok** |
| Fetch CA bundle (DANE/TLSA) | `TrustService.ImportFromTrustStrap` method=dane | `xkey trust bootstrap --method=dane` | `xkmsctl bootstrap dane` | DANE-verified `GET /v1/ca/bootstrap` | none (DNSSEC gap) |
| List certificates | `TrustService.ListCertificates` | `xkey trust list` | n/a (client local) | n/a | none |
| Import PEM | `TrustService.AddCertificatesPEM` | `xkey trust add <pem-file>` | n/a | n/a | none |
| Import file | `TrustService.ImportCertificateFile` | `xkey trust add <pem-file>` | n/a | n/a | none |
| Export bundle | `TrustService.ExportBrowserTrustBundle` | none | n/a | n/a | none |
| Install to system | `TrustService.InstallToSystem` | `xkey trust install <fingerprint>` | n/a | n/a | none |
| Remove | `TrustService.RemoveCertificate` | `xkey trust remove <fingerprint>` | n/a | n/a | none |

`xkey trust bootstrap` takes `--method` as a list (`xkey/cmd/xkey/cmd/trust.go:336`).

## CA (Certificate Authority)

| Operation | GUI (service.method) | xkey CLI | xkmsctl | Backend endpoint | Live test |
|---|---|---|---|---|---|
| Get CA bundle | `CAService.GetCABundle` | `xkey ca bundle` | `xkmsctl ca bundle` | `GET /api/v1/ca/bundle` (`:272`) | none |
| Get CA certificate | `CAService.GetCAInfo` | `xkey ca info` | `xkmsctl ca certificate` | `GET /api/v1/ca/certificate` (`:273`) | none |
| Sign CSR | `CAService.SignCSR` | `xkey ca sign-csr` | `xkmsctl ca sign-csr` | `POST /api/v1/ca/sign-csr` (`:274`) | none |
| Issue certificate | `CAService.IssueCertificate` | `xkey ca issue` | `xkmsctl ca issue` | `POST /api/v1/ca/issue` (`:275`) | none |
| Revoke certificate | `CAService.RevokeCertificate` | `xkey ca revoke <serial>` | `xkmsctl ca revoke` | `POST /api/v1/ca/revoke` (`:276`) | none |
| Generate / fetch CRL | `CAService.GenerateCRL` | `xkey ca crl` | `xkmsctl ca crl` | `POST /api/v1/ca/crl` (`:277`), `GET /api/v1/ca/crl` (`:278`) | none |
| Check revocation | `CAService.IsRevoked` | `xkey ca check-revocation <serial>` | `xkmsctl ca status --serial` | `GET /api/v1/ca/revoked/{serial}` (`:279`) | none |

## Keys

| Operation | GUI (service.method) | xkey CLI | xkmsctl | Backend endpoint | Live test |
|---|---|---|---|---|---|
| List keys | `KeyService.ListKeys` | none | `xkmsctl key list` | `GET /api/v1/keys` (`:158`) | none |
| Generate key | `KeyService.GenerateKey` | none | `xkmsctl key generate <key-id>` | `POST /api/v1/keys` (`:157`) | none |
| Delete key | `KeyService.DeleteKey` | none | `xkmsctl key delete <key-id>` | `DELETE /api/v1/keys/{id}` (`:160`) | none |
| Sign | `KeyService.SignData` | none | `xkmsctl key sign <key-id> <data>` | `POST /api/v1/keys/{id}/sign` (`:161`) | none |
| Verify | `KeyService.VerifySignature` | none | `xkmsctl key verify <key-id> <data> <signature>` | `POST /api/v1/keys/{id}/verify` (`:162`) | none |

## Certificates (server-side store)

| Operation | GUI (service.method) | xkey CLI | xkmsctl | Backend endpoint | Live test |
|---|---|---|---|---|---|
| List certificates | `CertificateService.ListCertificates` | none | `xkmsctl cert list` | `GET /api/v1/certs` (`:201`) | none |
| Get certificate | none | none | `xkmsctl cert get <key-id>` | `GET /api/v1/certs/{id}` (`:202`) | none |
| Store certificate | none | none | `xkmsctl cert save <key-id> <cert-file>` | `POST /api/v1/certs` (`:200`) | none |

## Admin / Backends

| Operation | GUI (service.method) | xkey CLI | xkmsctl | Backend endpoint | Live test |
|---|---|---|---|---|---|
| List backends | `AdminService.ListBackends` | none | `xkmsctl backends list` | `GET /api/v1/backends` (`:153`) | none |
| Backend detail | `AdminService.GetBackendInfo` | none | `xkmsctl backends info <backend>` | `GET /api/v1/backends/{id}` (`:154`) | none |

## Tenant

| Operation | GUI (service.method) | xkey CLI | xkmsctl | Backend endpoint | Live test |
|---|---|---|---|---|---|
| Create tenant | `TenantService.CreateTenant` | none | `xkmsctl tenant create` | `POST /api/v1/tenants/` (`:296`) | none |

## OIDC

| Operation | GUI (service.method) | xkey CLI | xkmsctl | Backend endpoint | Live test |
|---|---|---|---|---|---|
| Discover provider | `OIDCService.DiscoverProvider` | none | n/a | OIDC .well-known | none |
| Login / token | `OIDCService.Login` | `xkey oidc login`, `xkey oidc token` | n/a | IdP token endpoint | none |
| Callback / AWS flow | `OIDCService.Callback` | `xkey oidc aws` | n/a | varies | none |

## Purely local (no xkms-server — OUT OF SCOPE for live tests)

- Local FIDO2 virtual authenticator (`FIDO2DeviceService`)
- Local TPM operations (`TPMService`)
- Local PIN / barrier / seal (`PINService`, `BarrierService`, `SealService`)
- Local password vault (`StaticPasswordService`)
- OATH TOTP (`OATHService`)
- PIV smart card (`PIVService` — talks to local smart card, not server)
- Browser launch (`BrowserService`, `SecureBrowserService`)
- LUKS device mount (`StorageService`)

These are covered by the mocked-UI Playwright tier (`tests/e2e/*.spec.ts`)
plus the Go unit / integration tests. Adding a live-backend tier for them
has no value because there's no backend to talk to.

## Summary

| Category | Operations | Live tests |
|---|---:|---:|
| Trust Store | 10 | 2 |
| CA | 7 | 0 |
| Keys | 5 | 0 |
| Certificates (server) | 3 | 0 |
| Admin / Backends | 2 | 0 |
| Tenant | 1 | 0 |
| OIDC | 3 | 0 |
| **Total** | **31** | **2** |

29 of the 31 rows have no live-backend test; six of those (the client-local
trust-store rows) never reach the server. The only live specs are in
`xkey/frontend/tests/e2e/live/truststrap-import.spec.ts` (SPKI and Noise).
The pattern is reusable — each operation needs about one spec file with
2–4 test cases (happy path + error paths).
