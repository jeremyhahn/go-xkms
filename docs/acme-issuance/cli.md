# ACME Issuance — CLI

> **Status: NORMATIVE** · Feature: `acme-issuance` · Repo: `go-xkms` · Last verified: 2026-09-28

Two binaries cover ACME, on opposite sides of the protocol:

- **`trusted-acme-client`** (`cmd/acme-client`) is the automated client
  side — an ACME client that requests, renews, and deploys certificates.
  Command groups: `account`, `cert`, `device`, `service`, plus `serve` and
  `version`.
- **`xkmsctl acme`** (`cmd/xkmsctl`) is the CA operator's administration
  surface for the ACME server itself — accounts, issued certificates,
  external account bindings (EAB), and CA status/statistics — documented in
  [`xkmsctl acme` (admin)](#xkmsctl-acme-admin) below. It brings `xkmsctl` to
  parity with go-trusted-ca's retired `cactl` for account, certificate, EAB,
  and CA status/stats administration.

The CA operator's *certificate hierarchy* verbs (`ca sign-csr`, `ca issue`,
`ca revoke`, `ca crl`) are a separate, non-ACME surface documented at
[`../certificate-authority/cli.md`](../certificate-authority/cli.md).

## `cactl` is retired, not undocumented

The legacy `docs/acme/cli/cactl.md` documents a `cactl` binary. **There is no
`cmd/cactl` in go-xkms and there never was.** `cactl` belonged to a separate
standalone CA project that was decommissioned in August 2026, its CA
functionality having been folded into go-xkms as `TrustedCA` and the ACME
implementation documented here. `trusted-acme-client` is the surviving client.

One former live consequence: `test/integration/cactl` drove a `cactl` binary
that could not resolve, and the compose file that ran it
(`test/integration/acme-docker-compose.integration.yml`) built from a
sibling `go-trusted-ca` checkout that does not exist in this repository.
go-xkms#949 replaced that test package with `test/integration/acmeadmin`,
which drives `xkmsctl acme --acme-transport rest` instead, and replaced the
compose file with `test/integration/acmeadmin/docker-compose.yml`, which
builds `xkmsd` and `xkmsctl` from this repository.

## Global flags

Registered on the root command (`cmd/acme-client/main.go:116`):

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--config`, `-c` | string | `~/.trusted-acme-client.yaml` | Config file path |
| `--log-level` | string | `info` | `debug`, `info`, `warn`, `error` |
| `--log-format` | string | `json` | `json`, `text` |

All three are bound to viper, so the config file and the flags are one
namespace.

## `trusted-acme-client account`

| Verb | Args | Purpose |
|---|---|---|
| `account add <name>` | account name | Add an ACME account configuration |
| `account list` | — | List configured accounts |
| `account show <name>` | account name | Account detail |
| `account remove <name>` | account name | Remove an account |

### `account add <name>`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--directory` | string | — | **yes** — ACME directory URL |
| `--email` | string | — | **yes** — contact email |
| `--key-algorithm` | string | `ECDSA` | no — `ECDSA`, `RSA`, `ED25519` |
| `--key-store` | string | `software` | no — key storage backend |
| `--key-curve` | string | `P-256` | no — `P-256`, `P-384`, `P-521` |

```
trusted-acme-client account add prod \
    --directory https://kms.example.com:8443/api/v1/acme/directory \
    --email ops@example.com \
    --key-algorithm ECDSA --key-curve P-384 --key-store tpm2
```

`--key-store tpm2` puts the **account key** in the TPM, which is the point: an
account key in a file is a certificate-issuing capability sitting on disk.

`account add` only stores this configuration locally; it makes no ACME
`newAccount` request. The account is registered with the directory server
the first time a command that needs an order for it runs — `cert request`,
`cert renew`, or `device enroll`/`device attest` — and every later command
reuses the same registration, since it is idempotent server-side (RFC 8555
§7.3.1).

## `trusted-acme-client cert`

Certificates are named specs in the config file — subject, SANs, key
parameters and challenge type are configured once, and the verbs act on the
name.

| Verb | Args | Flags | Purpose |
|---|---|---|---|
| `cert request <name>` | spec name | — | Request a new certificate for the spec |
| `cert list` | — | `--account <name>` (filter) | List certificates |
| `cert show <name>` | spec name | — | Certificate detail |
| `cert renew <name>` | spec name | — | Renew |
| `cert revoke <name>` | spec name | `--reason <int>` (default `0`) | Revoke — `0` unspecified, `1` keyCompromise, `4` superseded |
| `cert deploy <name>` | spec name | — | Deploy the issued certificate per the spec |

```
trusted-acme-client cert request web-prod
trusted-acme-client cert list --account prod
trusted-acme-client cert renew web-prod
trusted-acme-client cert revoke web-prod --reason 1
trusted-acme-client cert deploy web-prod
```

## `trusted-acme-client device`

The hardware-identity path. This is what `enroll-01` and `device-attest-01`
exist for. Like certificates, devices are named specs in the config file
(`devices.<name>`) — the account, the TPM to open, the ACME permanent
identifier, the common name and the local challenge
server's bind address/port are configured once, and the verbs act on the
name. There is no flag-based, config-free form.

| Verb | Args | Purpose |
|---|---|---|
| `device enroll <name>` | spec name | Enroll the device via `enroll-01`, issuing its IAK and IDevID certificates |
| `device attest <name>` | spec name | Attest the device via `device-attest-01`: the IAK certifies the certificate key, which the TPM holds under the Platform SRK |

```
trusted-acme-client device enroll edge-gateway-01
trusted-acme-client device attest edge-gateway-01
```

A minimal device spec:

```yaml
devices:
  edge-gateway-01:
    account: prod
    common-name: edge-gateway-01.example.com
    identifier: edge-gateway-01.example.com   # ACME permanent-identifier value
    challenge:
      port: "8080"
    tpm:
      key-dir: /var/lib/trusted-acme/tpm-keys
      config:
        device: /dev/tpmrm0
```

`tpm` is optional. Left unset, the device opens go-xkms's own TPM2 defaults —
the in-process simulator, provisioned on first use — which is appropriate
only for development and testing; a production device spec must set
`tpm.config.device` (or `tpm.config.simulator: true` for an explicitly
simulated node) naming an already-provisioned TPM. go-xkms never
auto-provisions real hardware: an unprovisioned physical TPM is refused, not
silently provisioned, by this command.

`device attest` issues the certificate for a P-256 key the TPM holds under
the Platform SRK, named by `common-name`. The key is created on the first
attestation and reused on later ones. The evidence is a TPM2_Certify of that
key by the IAK, so the IAK certificate must already be installed in the TPM.
The evidence certifies a key, not PCR state, so a `pcr-selection` in the spec
does not reach the attestation.

## `trusted-acme-client service`

| Verb | Purpose |
|---|---|
| `service start` | Start the renewal service |
| `service status` | Renewal service status |

## `trusted-acme-client serve`

Runs the client's own HTTP surface (used for the GUI and for challenge
callbacks).

| Flag | Type | Default |
|---|---|---|
| `--addr` | string | `:8443` |
| `--api-base-url` | string | `""` — derived from `--addr` when empty |
| `--tls-cert` | string | `""` |
| `--tls-key` | string | `""` |
| `--no-tls` | bool | `false` — **development and testing only** |

Every flag is also `serve.<key>` in the config file and `ACME_CLIENT_SERVE_<KEY>`
in the environment (`serve.api_base_url` / `ACME_CLIENT_SERVE_API_BASE_URL`),
flag over environment over file.

```
trusted-acme-client serve --addr :8443 --tls-cert client.crt --tls-key client.key
```

`--api-base-url` is the origin the browser UI is told to reach the REST API
at, advertised verbatim: an absolute `http` or `https` URL, optionally with a
mount prefix, and never ending in `/api/v1`, because the UI appends `/api/v1`
and the endpoint path itself (a value ending in it is refused). When it is
empty the origin is derived from the listen address: a wildcard bind (`:8443`,
`0.0.0.0:8443`, `[::]:8443`) advertises `https://localhost:8443`, and a named
or literal bind advertises that host. Bind every interface but publish the
name clients use:

```
trusted-acme-client serve --addr 0.0.0.0:9443 --api-base-url https://acme.example.com:9443 \
    --tls-cert client.crt --tls-key client.key
```

The value is rendered into the served page as a JavaScript string literal, so
a quote or a closing tag in it cannot break out of the injected script.

Never run `--no-tls` anywhere real. It is in the flag set for local test loops.

## `trusted-acme-client version`

Prints version, commit and build date.

## `xkmsctl acme` (admin)

`xkmsctl acme` administers the ACME certificate authority go-xkms hosts on
its own dedicated HTTPS listener (`cfg.ACME.HTTPSAddr`) — a distinct service
from xkmsd's own keystore/control-plane surface. Every verb goes through the
ACME admin SDK (`sdk/go/acme`, `sdk/go/acme/client/admin`), never through
`pkg/acme/admin` directly, and the admin API is permission-gated
(`pkg/acme/admin`'s `PermissionGate`): a caller lacking the required role
gets a typed permission-denied error rather than a generic failure.

### Connecting

The ACME admin plane is not reachable through `xkmsctl`'s usual
`--server`/`--transport` flags — those address xkmsd. `acme` subcommands
take their own connection flags instead:

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--acme-server` | string | — | **required** — address of the ACME admin API (`https://host:8443`, `grpc://host:9443`, `grpcs://host:9443`, `quic://host:9444`, `mcp://host:9444`, `mcps://host:9444`, or a bare `host:port` routed by `--acme-transport`) |
| `--acme-transport` | string | `grpc` | transport to use when `--acme-server` carries no scheme: `rest`, `grpc`, `quic`, `mcp` (there is no `unix` adapter for the ACME admin plane) |

`xkmsctl`'s usual `--tls-cert`/`--tls-key`/`--tls-ca` flags supply client
TLS material for `grpcs://`/`mcps://`/`quic://` targets or a bare address
whose transport requires TLS.

```
xkmsctl acme --acme-server https://ca.example.com:8443 account list
xkmsctl acme --acme-server grpc://ca.example.com:9443 --tls-ca ca.pem cert get 01:02:03:04
```

### `xkmsctl acme account`

| Verb | Args | Flags | Purpose |
|---|---|---|---|
| `account list` | — | `--page`, `--per-page`, `--status` | List ACME accounts |
| `account get <id>` | account ID | — | Get an account by ID |
| `account disable <id>` | account ID | — | Disable an account (existing certificates remain valid until expiry) |

```
xkmsctl acme --acme-server https://ca.example.com:8443 account list --status valid
xkmsctl acme --acme-server https://ca.example.com:8443 account get 12345
xkmsctl acme --acme-server https://ca.example.com:8443 account disable 12345
```

### `xkmsctl acme cert`

| Verb | Args | Flags | Purpose |
|---|---|---|---|
| `cert list` | — | `--page`, `--per-page`, `--status` | List issued certificates |
| `cert get <serial>` | serial number | — | Get a certificate by serial number |
| `cert revoke <serial>` | serial number | `--reason` (default `unspecified`) | Revoke a certificate (RFC 5280 reasons: `unspecified`, `keyCompromise`, `caCompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `removeFromCRL`, `privilegeWithdrawn`, `aaCompromise`) |

```
xkmsctl acme --acme-server https://ca.example.com:8443 cert list --status valid
xkmsctl acme --acme-server https://ca.example.com:8443 cert get 01:02:03:04:05:06:07:08
xkmsctl acme --acme-server https://ca.example.com:8443 cert revoke 01:02:03:04:05:06:07:08 --reason keyCompromise
```

### `xkmsctl acme eab`

External Account Binding (RFC 8555 §7.3.4) lets an ACME client
pre-authorize account creation with a MAC key issued out of band. go-xkms's
ACME server is multi-tenant and EAB is scoped to a tenant, so every verb
requires `--tenant`. This has no `cactl` equivalent — go-trusted-ca is
single-tenant and never had EAB admin verbs.

| Verb | Args | Flags | Purpose |
|---|---|---|---|
| `eab create` | — | `--tenant` (required), `--purpose`, `--external-account-id`, `--contact` (repeatable), `--expires-in-days` | Create an EAB; the MAC key is printed once, at creation, and is not retrievable again |
| `eab get <kid>` | key ID | `--tenant` (required) | Get an EAB by key ID (never returns the MAC key) |
| `eab delete <kid>` | key ID | `--tenant` (required) | Delete an EAB |
| `eab list` | — | `--tenant` (required), `--page`, `--per-page`, `--status`, `--purpose` | List EABs for a tenant |

```
xkmsctl acme --acme-server https://ca.example.com:8443 eab create \
    --tenant acme --purpose device-enrollment --contact mailto:ops@example.com
xkmsctl acme --acme-server https://ca.example.com:8443 eab list --tenant acme
xkmsctl acme --acme-server https://ca.example.com:8443 eab get --tenant acme <kid>
xkmsctl acme --acme-server https://ca.example.com:8443 eab delete --tenant acme <kid>
```

### `xkmsctl acme status` / `xkmsctl acme stats`

| Verb | Purpose |
|---|---|
| `status` | CA identity, version, initialization state, algorithms, root/intermediate CA |
| `stats` | Certificate/account/order counts |

```
xkmsctl acme --acme-server https://ca.example.com:8443 status
xkmsctl acme --acme-server https://ca.example.com:8443 stats
```

### Errors

A permission-denied response from the admin API's `PermissionGate`
surfaces as a distinct typed error (`ACMEAdminForbiddenError`) rather than
the generic per-verb failure sentinel, and a missing resource surfaces as
`ACMEAdminNotFoundError` — both readable at a glance and distinguishable
with `errors.As` by anything scripting against the CLI's exit path.

## Exit codes

`0` on success. On any error the binary writes `error: <message>` to stderr and
exits non-zero (`cmd/acme-client/main.go`). `xkmsctl` follows the same
convention (`error: <message>` to stderr, exit `1`).

## Parity coverage

**Defect: the entire `trusted-acme-client` surface has no `CommandDefinition`
in `test/integration/api/commands/commands.go`.** The ACME suites under
`test/integration/{acme-client,acmeclient,acme-multiprotocol,rfc8555}` exercise
the protocol and the client library, but the CLI verbs themselves are not in the
table-driven multiprotocol parity runner. Every verb on this page is therefore
one side of a pair whose other side is missing.
