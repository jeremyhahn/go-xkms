# Backend Credentials — CLI

> **Status: NORMATIVE** · Feature: `backend-credentials` · Repo: `go-xkms` · Last verified: 2026-10-12

Binary: `xkmsctl`, group `credential` (`cmd/xkmsctl/credential.go:50-67`,
registered at `cmd/xkmsctl/root.go:182`).

| Verb | Purpose | REST call |
|---|---|---|
| `credential submit` | Submit or replace a backend credential | `POST /api/v1/credentials/submit` (`credential.go:145`) |
| `credential list` (alias `ls`) | List the names of the credentials the server holds | `GET /api/v1/credentials` (`credential.go:239`) |
| `credential strategy` | Show the configured strategy and whether it unseals automatically | `GET /api/v1/credentials/strategy` (`credential.go:193`) |

There is no `rotate`, `get` or `delete` verb. To rotate a credential, run
`submit` again with the same name (`credential.go:64-66`).

## Connection

Each verb sends HTTPS requests to `--server` through the CLI's mTLS HTTP
client (`createServerHTTPClient`, `cmd/xkmsctl/httpclient.go:66`). The
`--transport` flag does not change this. Without `--server`, the verb fails
with `ErrServerRequired` (`credential.go:119-121`, `errors.go:104`).

| Global flag | Purpose | Source |
|---|---|---|
| `--server`, `-s` | Server base URL, e.g. `https://kms.example.com:8443` | `root.go:132` |
| `--tls-cert`, `--tls-key` | Client certificate and key for mTLS | `root.go:141-144` |
| `--tls-ca` | CA certificate that verifies the server | `root.go:145` |
| `--output`, `-o` | `text` (default) or `json` | `root.go:122` |
| `--verbose`, `-v` | Log each request | `root.go:124` |

## `credential submit`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--name` | string | `""` | Credential name, e.g. `pkcs11-user-pin` (required) |
| `--value` | string | `""` | Credential value (required); the CLI base64-encodes it |

Source: `credential.go:273-274`. A missing flag fails with
`ErrCredentialNameRequired` or `ErrCredentialValueRequired`
(`credential.go:129-134`, `errors.go:118`, `:121`).

```
xkmsctl credential submit --server https://kms.example.com:8443 \
  --tls-cert admin.pem --tls-key admin-key.pem --tls-ca ca.pem \
  --name pkcs11-user-pin --value "$USER_PIN"
```

Text output: `Credential "pkcs11-user-pin" submitted successfully (status: accepted)`.
JSON output: `{"name": ..., "status": ...}` (`credential.go:166-174`). Under
the `manual` strategy, a second submit of the same name returns HTTP 409
(see [`api.md`](api.md)).

The value is passed as a command-line argument, so it is visible in the
process list and in shell history.

## `credential list`

No flags.

```
xkmsctl credential list --server https://kms.example.com:8443 \
  --tls-cert admin.pem --tls-key admin-key.pem --tls-ca ca.pem
```

Text output: `Submitted credentials:` followed by one name per line, or
`No credentials submitted.` JSON output: `{"names": [...]}`
(`credential.go:255-268`).

## `credential strategy`

No flags.

```
xkmsctl credential strategy --server https://kms.example.com:8443 \
  --tls-cert admin.pem --tls-key admin-key.pem --tls-ca ca.pem
```

```
Credential Strategy:
  Strategy:    manual
  Auto-unseal: false
```

JSON output: `{"strategy": ..., "auto_unseal": ...}` (`credential.go:209-220`).
