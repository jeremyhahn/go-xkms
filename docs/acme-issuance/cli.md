# ACME Issuance — CLI

> **Status: NORMATIVE** · Feature: `acme-issuance` · Repo: `go-xkms` · Last verified: 2026-08-19

Binary: **`trusted-acme-client`** (`cmd/acme-client`). Command groups:
`account`, `cert`, `device`, `service`, plus `serve` and `version`.

`xkmsctl` has no ACME verbs. The CA operator verbs (`ca sign-csr`, `ca issue`,
`ca revoke`, `ca crl`) are [`../certificate-authority/cli.md`](../certificate-authority/cli.md);
ACME is the automated client side.

## `cactl` is a different repository

`docs/acme/cli/cactl.md` in the legacy tree documents a `cactl` binary. **There
is no `cmd/cactl` in go-xkms.** The only reference in this repo is
`test/integration/acme-docker-compose.integration.yml`, which sets
`CACTL_BINARY` to a path inside a **`go-trusted-ca`** checkout. Documenting
another repository's binary here breaches the rule that nobody documents someone
else's code as if they owned it, so `cactl` is deliberately absent from this
folder. Resolving it — is `go-trusted-ca` a live repo, is `cactl` supposed to
move here, or is the integration test the thing that is wrong — is an owner
decision.

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
exist for.

### `device enroll`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--account` | string | — | **yes** |
| `--device-id` | string | — | **yes** |
| `--cn` | string | `""` | no — certificate common name |
| `--output-cert` | string | `""` | no — write the certificate |
| `--output-iak` | string | `""` | no — write the IAK certificate |

```
trusted-acme-client device enroll --account prod --device-id node-07 \
    --cn node-07.example.com --output-cert node.crt --output-iak node-iak.crt
```

### `device attest`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--account` | string | — | **yes** |
| `--device-id` | string | — | **yes** |
| `--cn` | string | `""` | no |
| `--pcrs` | string | `0,1,2,3,4,5,6,7` | no — comma-separated PCR indices |
| `--output-cert` | string | `""` | no |

```
trusted-acme-client device attest --account prod --device-id node-07 \
    --pcrs 0,1,2,3,4,5,6,7 --output-cert node-attested.crt
```

Changing `--pcrs` changes what the certificate attests to. The default set is
the firmware and boot measurements; adding a PCR that changes on every update
makes the attestation fail after the next update, which is sometimes exactly
what you want and sometimes an outage.

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
| `--tls-cert` | string | `""` |
| `--tls-key` | string | `""` |
| `--no-tls` | bool | `false` — **development and testing only** |

```
trusted-acme-client serve --addr :8443 --tls-cert client.crt --tls-key client.key
```

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
