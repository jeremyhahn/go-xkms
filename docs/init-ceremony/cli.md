# Init Ceremony — CLI

> **Status: NORMATIVE** · Feature: `init-ceremony` · Repo: `go-xkms` · Last verified: 2026-08-19

Two binaries. **`xkmsd init`** runs the ceremony on the server;
**`xkmsctl init`** is what a remote officer uses to claim what the ceremony
issued for them. Sources: `cmd/xkmsd/init_ceremony.go`, `cmd/xkmsctl/init.go`,
`cmd/xkmsctl/credential.go`.

## `xkmsd init` — the server side

Run once, on the server, by the operator conducting the ceremony. It stands up
the CA, initializes the barrier, registers officers, splits shares and enrolls
admin factors. Configuration comes from the server config file rather than
flags, because a ceremony is not something to drive from a shell history.

Note the shipped behaviour: **admin factors enrolled here are reported but not
stored** (`init_ceremony.go:403`). Do not build a process that assumes they
survive a restart.

## `xkmsctl init status`

No flags. Reports the ceremony state — what is pending, what has been claimed.

```
xkmsctl init status -o json
```

## `xkmsctl init claim-cert`

An officer claims their certificate. Two-phase under the hood: begin, prove key
possession, complete.

| Flag | Type | Default | Required |
|---|---|---|---|
| `--username` | string | — | **yes** |
| `--key` | string | — | **yes** — PEM private key matching the submitted CSR |
| `--spki-pin` | string | — | **yes** — SPKI SHA-256 pin of the server |
| `--output` | string | `""` | no — issued certificate (stdout when omitted) |
| `--ca-output` | string | `""` | no — CA bundle returned with the certificate |

```
xkmsctl init claim-cert --username alice --key alice.key \
    --spki-pin 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 \
    --output alice.crt --ca-output ca-bundle.pem
```

**`--spki-pin` is required, not optional.** An officer claiming a credential has
no CA bundle yet, so the pin is the only thing verifying the server. Get it from
the operator out of band — see
[`../trust-bootstrap/cli.md`](../trust-bootstrap/cli.md).

Use `--ca-output`: the bundle comes back with the certificate, and it is what
every later command needs.

## `xkmsctl init claim-share`

An officer claims their Shamir share, authenticated with the certificate they
just claimed.

| Flag | Type | Default | Required |
|---|---|---|---|
| `--username` | string | — | **yes** |
| `--cert` | string | — | **yes** — the officer certificate from `claim-cert` |
| `--key` | string | — | **yes** — private key matching that certificate |
| `--spki-pin` | string | — | **yes** |
| `--ca-cert` | string | `""` | no — CA bundle to verify the server; defaults to the SPKI pin |
| `--output` | string | `""` | no — where to write the share |

```
xkmsctl init claim-share --username alice --cert alice.crt --key alice.key \
    --spki-pin "$PIN" --ca-cert ca-bundle.pem --output alice.share
```

**Save the share.** It is emitted once, and nothing can reissue it.

## `xkmsctl init sign-csr`

Signs an officer CSR during the ceremony.

| Flag | Type | Default | Required |
|---|---|---|---|
| `--username` | string | — | **yes** — the requesting officer |
| `--csr` | string | — | **yes** — PEM CSR file |
| `--role` | string | — | **yes** — `so`, `admin`, `operator`, `user`, `auditor`, `custodian` |
| `--output` | string | `""` | no — signed certificate (stdout when omitted) |

```
xkmsctl init sign-csr --username alice --csr alice.csr --role custodian --output alice.crt
```

`--role` sets the certificate's authority. `so` is the security officer — the
control-plane credential, scoped to the `system` tenant so it works before any
tenant barrier unseals. Issue it deliberately.

## `xkmsctl credential`

| Verb | Purpose |
|---|---|
| `credential submit` | Submit a credential during the ceremony |
| `credential list` | List submitted credentials |
| `credential strategy` | Report the credential strategy in force |

```
xkmsctl credential strategy -o json
xkmsctl credential list
```

## Order of operations, for an officer

```
1. generate a key and CSR locally
2. hand the CSR to the operator; they run  init sign-csr --role …
3. xkmsctl init claim-cert  --username … --key … --spki-pin … --ca-output ca-bundle.pem
4. xkmsctl init claim-share --username … --cert … --key … --spki-pin …
5. store the share somewhere it will still exist in a year
```

## Exit codes

`0` on success; non-zero on a pin mismatch, a key that does not match the CSR or
certificate, an already-claimed credential, or a ceremony not in the right
state. A pin mismatch is the one to stop on rather than retry.

## Parity coverage

**Defect: no `init` or `credential` verb has a `CommandDefinition` in
`test/integration/api/commands/commands.go`**, despite the init routes existing
on REST, gRPC, QUIC, Unix and MCP. The end-to-end paths are covered by
`pkg/api/rest/init_ceremony_e2e_test.go` and the MCP/REST public-derivation
suites, but not by the table-driven multiprotocol parity runner.
