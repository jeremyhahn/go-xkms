# ACME Issuance — CLI

> **Status: NORMATIVE** · Feature: `acme-issuance` · Repo: `go-xkms` · Last verified: 2026-09-23

Binary: **`trusted-acme-client`** (`cmd/acme-client`). Command groups:
`account`, `cert`, `device`, `service`, plus `serve` and `version`.

`xkmsctl` has no ACME verbs. The CA operator verbs (`ca sign-csr`, `ca issue`,
`ca revoke`, `ca crl`) are [`../certificate-authority/cli.md`](../certificate-authority/cli.md);
ACME is the automated client side.

## `cactl` is retired, not undocumented

The legacy `docs/acme/cli/cactl.md` documents a `cactl` binary. **There is no
`cmd/cactl` in go-xkms and there never was.** `cactl` belonged to a separate
standalone CA project that was decommissioned in August 2026, its CA
functionality having been folded into go-xkms as `TrustedCA` and the ACME
implementation documented here. `trusted-acme-client` is the surviving client.

One live consequence: `test/integration/acme-docker-compose.integration.yml`
still sets `CACTL_BINARY` to a path inside a checkout of that retired project.
That reference cannot resolve and should be removed — a code change, not a
documentation one, so it is reported rather than made in this docs-only
migration.

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
| `account add <name>` | account name | Register an ACME account |
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
identifier, the common name, the PCR selection and the local challenge
server's bind address/port are configured once, and the verbs act on the
name. There is no flag-based, config-free form.

| Verb | Args | Purpose |
|---|---|---|
| `device enroll <name>` | spec name | Enroll the device via `enroll-01`, issuing its IAK and IDevID certificates |
| `device attest <name>` | spec name | Attest the device via `device-attest-01`, using the spec's PCR selection |

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
    pcr-selection: [0, 1, 2, 3, 4, 5, 6, 7]
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

Changing `pcr-selection` changes what the attestation certificate attests to.
The default set is the firmware and boot measurements; adding a PCR that
changes on every update makes the attestation fail after the next update,
which is sometimes exactly what you want and sometimes an outage.

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

## Exit codes

`0` on success. On any error the binary writes `error: <message>` to stderr and
exits non-zero (`cmd/acme-client/main.go`).

## Parity coverage

**Defect: the entire `trusted-acme-client` surface has no `CommandDefinition`
in `test/integration/api/commands/commands.go`.** The ACME suites under
`test/integration/{acme-client,acmeclient,acme-multiprotocol,rfc8555}` exercise
the protocol and the client library, but the CLI verbs themselves are not in the
table-driven multiprotocol parity runner. Every verb on this page is therefore
one side of a pair whose other side is missing.
