# CA: GUI API

`services.CAService` (`xkey/pkg/gui/services/ca_service.go`) is bound to the
frontend (`xkey/frontend/wailsjs/go/services/CAService.d.ts`).

| Method | Purpose |
| --- | --- |
| `GetCAMode()` | `"remote"`, `"local"` or `"none"` (`ca_service.go:108`) |
| `GetCAInfo()` | CA certificate fields (`ca_service.go:144`) |
| `IssueCertificate(profile, cn, org, sans, days, alg)` | issue a key and certificate (`ca_service.go:181`) |
| `SignCSR(csrPEM, profile)` | sign a CSR (`ca_service.go:224`) |
| `RevokeCertificate(serial, reason)` | revoke by serial, RFC 5280 reason (`ca_service.go:260`) |
| `GenerateCRL()` | CRL as PEM (`ca_service.go:277`) |
| `IsRevoked(serial)` | revocation check (`ca_service.go:292`) |
| `GetCABundle(storeType, alg)` | CA bundle as PEM (`ca_service.go:312`) |

Every method returns `ErrCAServiceNilClient` when the mode is `none`.
