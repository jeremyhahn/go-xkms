# Trust Bootstrap — CLI

> **Status: NORMATIVE** · Feature: `trust-bootstrap` · Repo: `go-xkms` · Last verified: 2026-08-19

Binary: `xkmsctl`, group `bootstrap`. Sources: `cmd/xkmsctl/bootstrap.go`,
`bootstrap_dane.go`, `bootstrap_noise.go`, `bootstrap_spki.go`,
`bootstrap_trust.go`.

Subgroups: `bootstrap auto`, `bootstrap dane`, `bootstrap noise`,
`bootstrap spki`. Global flags: see
[`../key-management/cli.md`](../key-management/cli.md).

The client-side companion `xkey trust bootstrap|fetch|import-platform` is
documented in [`../../xkey/docs/platform-trust/cli.md`](../../xkey/docs/platform-trust/cli.md).

## `xkmsctl bootstrap auto`

Runs the configured modes in order and returns the first bundle that verifies.

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--server-url` | string | `""` | xkms server URL, e.g. `https://kms.example.com:8443` |
| `--config` | string | `""` | `xkmsd` config file; its `trust:` section supplies defaults |
| `--dane-hostname` | string | `""` | hostname for DANE/TLSA verification |
| `--dane-dns-server` | string | `""` | DNS server for DANE lookups, e.g. `198.51.100.53:53` |
| `--noise-key` | string | `""` | hex Noise static **public** key of the server |
| `--noise-addr` | string | `""` | Noise bootstrap server address `host:port` |
| `--spki-pin` | string | `""` | hex SHA-256 SPKI pin of the server certificate |
| `--direct` | bool | `false` | enable direct HTTPS fallback using the system trust store |
| `--bundle-path` | string | `""` | REST path for the bundle endpoint |
| `--bundle-output` | string | `""` | write the bundle here (stdout when omitted) |

A mode with no flags supplied is simply skipped. `--direct` is opt-in because
it is the one mode that verifies nothing beyond the public web PKI.

```
xkmsctl bootstrap auto \
    --server-url https://kms.example.com:8443 \
    --dane-hostname kms.example.com \
    --spki-pin 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 \
    --bundle-output ca-bundle.pem
```

**Note on `--bundle-path`:** the flag's help text says the default is
`/api/v1/ca/bundle`, while the library's `Config.BundlePath` documents empty as
meaning the canonical unauthenticated route `/v1/ca/bootstrap`. Both routes
exist; only the second answers before the client has credentials. If `bootstrap
auto` returns 401, pass `--bundle-path /v1/ca/bootstrap` explicitly. Reconciling
the two defaults is an open owner decision.

## `xkmsctl bootstrap dane`

| Verb | Purpose |
|---|---|
| `dane generate-tlsa` | Produce TLSA record(s) for a certificate |
| `dane verify-tlsa` | Verify a certificate against published TLSA records |
| `dane show-tlsa` | Show the TLSA records currently published |

### `dane generate-tlsa`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--cert-file` | string | `""` | PEM certificate |
| `--hostname` | string | `""` | hostname for the record, e.g. `kms.example.com` |
| `--port` | int | `443` | port for the record |
| `--usage` | int | trust-anchor assertion | TLSA certificate usage, 0–3 |
| `--selector` | int | SPKI | 0 = full certificate, 1 = SPKI |
| `--matching-type` | int | SHA-256 | 0 = exact, 1 = SHA-256, 2 = SHA-512 |
| `--all` | bool | `false` | generate all common combinations |

```
xkmsctl bootstrap dane generate-tlsa --cert-file kms.crt \
    --hostname kms.example.com --port 8443 --selector 1 --matching-type 1
```

Selector 1 (SPKI) survives certificate renewal when the key is reused; selector
0 does not, and publishing it means every renewal breaks DANE until DNS
catches up.

### `dane verify-tlsa`

| Flag | Type | Default |
|---|---|---|
| `--cert-file` | string | `""` |
| `--hostname` | string | `""` |
| `--port` | int | `443` |
| `--dns-server` | string | `""` |

```
xkmsctl bootstrap dane verify-tlsa --cert-file kms.crt \
    --hostname kms.example.com --port 8443
```

### `dane show-tlsa`

`--hostname`, `--port` (default `443`), `--dns-server`.

```
xkmsctl bootstrap dane show-tlsa --hostname kms.example.com --port 8443
```

## `xkmsctl bootstrap noise`

| Verb | Purpose |
|---|---|
| `noise generate-key` | Generate a Noise static keypair |
| `noise show-key` | Show the public key for a private key |
| `noise show-spki-pin` | Show the SPKI pin of a certificate |

| Flag | Applies to | Type | Default |
|---|---|---|---|
| `--output`, `-o` | `generate-key` | string | `""` — writes the private key at mode 0600 |
| `--key-file` | `show-key` | string | `""` — hex-encoded private key file |
| `--key-hex` | `show-key` | string | `""` — hex-encoded private key inline |
| `--cert-file` | `show-spki-pin` | string | `""` — PEM certificate |

```
xkmsctl bootstrap noise generate-key --output noise.key
xkmsctl bootstrap noise show-key --key-file noise.key
```

The **public** key is what clients need; distribute that. `--key-hex` puts a
private key on a command line, so it lands in shell history and process
listings — prefer `--key-file`.

## `xkmsctl bootstrap spki`

| Verb | Flag | Purpose |
|---|---|---|
| `spki show-pin` | `--cert-file <path>` | Print the SHA-256 SPKI pin of a certificate |

```
xkmsctl bootstrap spki show-pin --cert-file kms.crt
```

Run this on the server operator's side and publish the pin out of band; the
client passes it as `--spki-pin`.

## Exit codes

`0` when a bundle was fetched and verified; non-zero otherwise, with the typed
error on stderr. Under `auto`, a failure names the modes attempted — an
unconfigured mode and a failed mode are different messages, and they have
different fixes.

## Parity coverage

**Defect: no `bootstrap` verb has a `CommandDefinition` in
`test/integration/api/commands/commands.go`.** The library and the CLI paths are
covered by `pkg/trust/bootstrap/*_test.go`,
`cmd/xkmsctl/bootstrap_*_run_test.go` and `test/integration/bootstrap`, but the
verbs are absent from the table-driven multiprotocol parity runner. Bootstrap is
arguably the least important group to run on six transports — it is a
before-you-have-a-transport operation — but the absence should be a recorded
decision rather than an oversight.
