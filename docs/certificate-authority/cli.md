# Certificate Authority — CLI

> **Status: NORMATIVE** · Feature: `certificate-authority` · Repo: `go-xkms` · Last verified: 2026-09-21

Binary: `xkmsctl`. Groups: `ca` (the authority), `cert` (certificate storage
against a key), `tls` (TLS material). Sources: `cmd/xkmsctl/ca.go`,
`cmd/xkmsctl/cert.go`, `cmd/xkmsctl/tls.go`.

Global flags — including `--backend`, `--transport`, `--server`, `--token` and
the TLS set — are documented in
[`../key-management/cli.md`](../key-management/cli.md) §Global flags.

ACME verbs are not here. See [`../acme-issuance/cli.md`](../acme-issuance/cli.md).

## `xkmsctl ca`

### `ca bundle`

Fetch the CA bundle. No flags. Works before authentication when the server's
public bootstrap route is used.

```
xkmsctl --server https://kms.example.com:8443 ca bundle > ca-bundle.pem
```

### `ca certificate`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--identity` | string | `""` | no — CA identity/CN; empty selects the default CA |

```
xkmsctl ca certificate --identity "Example Intermediate CA" -o json
```

### `ca sign-csr`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--csr` | string | — | **yes** — path to a CSR PEM file |
| `--profile` | string | `""` | no — certificate profile (`server`, `client`, …) |
| `--validity` | int | `0` | no — days; `0` uses the CA default |
| `--output` | string | `""` | no — write the signed certificate as PEM |

```
xkmsctl ca sign-csr --csr node.csr --profile server --validity 90 --output node.crt
```

### `ca issue`

Generate a key and a certificate in one step.

| Flag | Type | Default | Required |
|---|---|---|---|
| `--cn` | string | — | **yes** — common name |
| `--profile` | string | `""` | no |
| `--org` | string | `""` | no |
| `--sans` | string | `""` | no — comma-separated, e.g. `DNS:example.com,IP:198.51.100.7` |
| `--validity` | int | `0` | no — days; `0` uses the CA default |
| `--algorithm` | string | `""` | no — `ecdsa-p256`, `rsa2048`, `ed25519` |
| `--output` | string | `""` | no — write the certificate as PEM |

```
xkmsctl ca issue --cn gateway.example.com --profile server \
    --sans DNS:gateway.example.com,DNS:gw.example.com \
    --algorithm ecdsa-p256 --validity 90 --output gateway.crt
```

### `ca revoke`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--serial` | string | — | **yes** — hex serial |
| `--reason` | int | `0` | no — RFC 5280 reason code; `0` is unspecified |

```
xkmsctl ca revoke --serial 0a1b2c3d4e5f --reason 1
```

### `ca crl`

Forces regeneration of the CRL (`POST /ca/crl`) and writes the result, even
when a still-valid CRL is already published. There is no CLI verb for the
cheap read (`GET /ca/crl`, which only regenerates when necessary) yet; fetch
it directly — see [api.md](api.md).

| Flag | Type | Default |
|---|---|---|
| `--output` | string | `""` — stdout when omitted |

```
xkmsctl ca crl --output current.crl
```

### `ca status`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--serial` | string | — | **yes** — hex serial |

Reports whether the serial is revoked.

```
xkmsctl ca status --serial 0a1b2c3d4e5f
```

## `xkmsctl cert`

Certificate storage bound to a keystore key. These are storage verbs, not
issuance verbs.

| Verb | Args | Purpose |
|---|---|---|
| `cert save <key-id> <cert-file>` | key id, PEM file | Store a certificate against a key |
| `cert get <key-id>` | key id | Retrieve it |
| `cert delete <key-id>` | key id | Remove it |
| `cert list` | — | List stored certificates |
| `cert exists <key-id>` | key id | Existence check |
| `cert save-chain <key-id> <cert-file>...` | key id, PEM files | Store a chain |
| `cert get-chain <key-id>` | key id | Retrieve the chain |
| `cert generate-ca` | — | Generate a CA certificate |
| `cert issue` | — | Issue against the stored CA |

```
xkmsctl cert save web-tls web.crt
xkmsctl cert get-chain web-tls > web-chain.pem
xkmsctl cert exists web-tls && echo present
```

## `xkmsctl tls`

| Verb | Args | Purpose |
|---|---|---|
| `tls get <key-id>` | key id | Fetch the TLS certificate for a key, ready for a server |

```
xkmsctl tls get web-tls -o json
```

## DANE

TLSA record generation and DANE verification are verbs of the trust-bootstrap
group (`bootstrap dane`, `bootstrap generate-tlsa`,
`cmd/xkmsctl/bootstrap_dane.go`), not of `ca`. They are documented in
[`../trust-bootstrap/cli.md`](../trust-bootstrap/cli.md), because their purpose
is establishing trust in a server you have not met, not operating the CA.

## Exit codes

`0` on success; non-zero on any error, with the typed error on stderr.
`-o json` puts structured output on stdout.

## Parity coverage

`CommandDefinition` entries exist in
`test/integration/api/commands/commands.go` for `ca-bundle`, `ca-certificate`,
`ca-crl`, `ca-issue`, `ca-revoke`, `ca-sign-csr`, `ca-status`, `cert-info`,
`cert-list`, `tls-cert` — the `ca` group is the best-covered group in the repo.

**Defect (parity suite is behind):** `cert save`, `cert delete`, `cert exists`,
`cert save-chain`, `cert get-chain`, `cert generate-ca` and `cert issue` have no
definitions.
