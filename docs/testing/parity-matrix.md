# xkey GUI / CLI / xkmsctl Parity Matrix

Surface-level map of every operation that round-trips to the xkms-server,
with the corresponding GUI service method, xkey CLI command, xkmsctl
command, and backend endpoint. This is the inventory used to plan the
live-backend Playwright test suite under `xkey/frontend/tests/e2e/live/`.

Status legend:
- `ok` — live E2E test present and passing
- `none` — no coverage at the live-backend tier
- `n/a` — the surface is purely local, does not involve xkms-server

## Trust Store

| Operation | GUI (service.method) | xkey CLI | xkmsctl | Backend endpoint | Live test |
|---|---|---|---|---|---|
| Fetch CA bundle (Direct HTTPS) | `TrustService.ImportFromTrustStrap` method=direct | `xkey trust bootstrap --method=direct` * | `xkmsctl bootstrap direct` | `GET /v1/ca/bootstrap` | **ok** |
| Fetch CA bundle (SPKI pin) | `TrustService.ImportFromTrustStrap` method=spki | `xkey trust bootstrap --method=spki` * | `xkmsctl bootstrap spki` | `GET /v1/ca/bootstrap` (SPKI-verified) | **ok** |
| Fetch CA bundle (Noise_NK) | `TrustService.ImportFromTrustStrap` method=noise | `xkey trust bootstrap --method=noise` * | `xkmsctl bootstrap noise` | Noise RPC | **ok** |
| Fetch CA bundle (DANE/TLSA) | `TrustService.ImportFromTrustStrap` method=dane | `xkey trust bootstrap --method=dane` * | `xkmsctl bootstrap dane` | DANE-verified `GET /v1/ca/bootstrap` | none (DNSSEC gap) |
| List certificates | `TrustService.ListCertificates` | `xkey trust list` | n/a (client local) | n/a | none |
| Import PEM | `TrustService.AddCertificatesPEM` | `xkey trust add` | n/a | n/a | none |
| Import file | `TrustService.ImportCertificateFile` | `xkey trust add --file` | n/a | n/a | **none — bug reported** |
| Export bundle | `TrustService.ExportBrowserTrustBundle` | `xkey trust export` | n/a | n/a | none |
| Install to system | `TrustService.InstallToSystem` | `xkey trust install` | n/a | n/a | none |
| Remove | `TrustService.RemoveCertificate` | `xkey trust remove` | n/a | n/a | none |

`*` = CLI subcommand existence not yet audited.

## CA (Certificate Authority)

| Operation | GUI (service.method) | xkey CLI | xkmsctl | Backend endpoint | Live test |
|---|---|---|---|---|---|
| Get CA bundle | `CAService.GetBundle` | `xkey ca bundle` | `xkmsctl ca bundle` | `GET /v1/ca/bundle` | none |
| Get CA certificate | `CAService.GetCertificate` | `xkey ca cert` | `xkmsctl ca certificate` | `GET /v1/ca/certificate` | none |
| Sign CSR | `CAService.SignCSR` | `xkey cert sign-csr` | `xkmsctl ca sign-csr` | `POST /v1/ca/sign-csr` | none |
| Issue certificate | `CAService.Issue` | `xkey cert issue` | `xkmsctl ca issue` | `POST /v1/ca/issue` | none |
| Revoke certificate | `CAService.Revoke` | `xkey cert revoke` | `xkmsctl ca revoke` | `POST /v1/ca/revoke` | none |
| Fetch CRL | `CAService.GetCRL` | `xkey ca crl` | `xkmsctl ca crl` | `GET /v1/ca/crl` | none |
| CA status | `CAService.Status` | `xkey ca status` | `xkmsctl ca status` | `GET /v1/ca/status` | none |

## Keys

| Operation | GUI (service.method) | xkey CLI | xkmsctl | Backend endpoint | Live test |
|---|---|---|---|---|---|
| List keys | `KeyService.List` | `xkey key list` | `xkmsctl key list` | `GET /v1/keys` | none |
| Generate key | `KeyService.Generate` | `xkey key generate` | `xkmsctl key generate` | `POST /v1/keys/generate` | none |
| Delete key | `KeyService.Delete` | `xkey key delete` | `xkmsctl key delete` | `DELETE /v1/keys/{id}` | none |
| Sign | `KeyService.Sign` | `xkey key sign` | `xkmsctl key sign` | `POST /v1/keys/{id}/sign` | none |
| Verify | `KeyService.Verify` | `xkey key verify` | `xkmsctl key verify` | `POST /v1/keys/{id}/verify` | none |

## Certificates (server-side store)

| Operation | GUI (service.method) | xkey CLI | xkmsctl | Backend endpoint | Live test |
|---|---|---|---|---|---|
| List certificates | `CertificateService.List` | `xkey cert list` | `xkmsctl cert list` | `GET /v1/certificates` | none |
| Get certificate | `CertificateService.Get` | `xkey cert get` | `xkmsctl cert get` | `GET /v1/certificates/{id}` | none |
| Store certificate | `CertificateService.Store` | `xkey cert store` | `xkmsctl cert store` | `POST /v1/certificates` | none |

## Admin / Backends

| Operation | GUI (service.method) | xkey CLI | xkmsctl | Backend endpoint | Live test |
|---|---|---|---|---|---|
| List backends | `AdminService.ListBackends` | `xkey admin backends list` | `xkmsctl backends list` | `GET /v1/admin/backends` | none |
| Backend status | `AdminService.BackendStatus` | `xkey admin backends status` | `xkmsctl backends status` | `GET /v1/admin/backends/{id}/status` | none |

## Tenant

| Operation | GUI (service.method) | xkey CLI | xkmsctl | Backend endpoint | Live test |
|---|---|---|---|---|---|
| Create tenant | `TenantService.Create` | n/a | `xkmsctl tenant create` | `POST /v1/tenants` | none |

## OIDC

| Operation | GUI (service.method) | xkey CLI | xkmsctl | Backend endpoint | Live test |
|---|---|---|---|---|---|
| Discover provider | `OIDCService.Discover` | `xkey oidc discover` | n/a | OIDC .well-known | none |
| Token exchange | `OIDCService.Exchange` | `xkey oidc token` | n/a | IdP token endpoint | none |
| Callback / device flow | `OIDCService.Callback` | `xkey oidc aws` | n/a | varies | none |

## Purely local (no xkms-server — OUT OF SCOPE for live tests)

- Local FIDO2 virtual authenticator (`FIDO2DeviceService`)
- Local TPM operations (`TPMService`)
- Local PIN / barrier / seal (`PinService`, `BarrierService`, `SealService`)
- Local password vault (`StaticPWService`)
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
| Trust Store | 10 | 3 |
| CA | 7 | 0 |
| Keys | 5 | 0 |
| Certificates (server) | 3 | 0 |
| Admin / Backends | 2 | 0 |
| Tenant | 1 | 0 |
| OIDC | 3 | 0 |
| **Total** | **34** | **3** |

Roughly **31 server-backed operations** have no live-backend coverage
today. The pattern established in `xkey/frontend/tests/e2e/live/truststrap-import.spec.ts`
is reusable — each operation needs about one spec file with 2–4 test
cases (happy path + error paths).
