# Trust Bootstrap — CLI

> **Status: NORMATIVE** · Feature: `trust-bootstrap` · Repo: `go-xkms` · Last verified: 2026-09-22

Binary: `xkmsctl`, group `bootstrap`. Sources: `cmd/xkmsctl/bootstrap.go`,
`bootstrap_dane.go`, `bootstrap_noise.go`, `bootstrap_p256.go`,
`bootstrap_spki.go`,
`bootstrap_trust.go`.

Subgroups: `bootstrap auto`, `bootstrap show-keys`, `bootstrap dane`,
`bootstrap noise`, `bootstrap spki`. Global flags: see
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
| `--noise-key` | string | `""` | hex Noise_NK (Curve25519) static **public** key of the server; skipped where the build cannot run Noise_NK |
| `--p256-key` | string | `""` | hex P-256 static **public** point of the server for the FIPS-approved suite (what `noise show-p256-key` prints); the key a FIPS client needs |
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

## `xkmsctl bootstrap show-keys`

Reports the **running server's** trust-bootstrap listener public keys, over
the ordinary authenticated admin API (not the bootstrap channel itself) —
requires the `bootstrap:read` permission. Uses the same connection flags as
every other `xkmsctl` command (`--server`, `--token`, `--transport`, etc.;
see [`../key-management/cli.md`](../key-management/cli.md)), and the global
`-o`/`--output` flag for `json` vs. the default table.

```
xkmsctl bootstrap show-keys
xkmsctl bootstrap show-keys --output json
```

Sample table output:

```
Bootstrap Listener Keys:
  Noise_NK Public Key (--noise-key): 3b1a...c2
  P-256 Public Key (--p256-key):     04a1...9e
```

Each value is exactly the hex string to paste into the flag named beside it
on `bootstrap auto` (or the matching `NoiseConfig` field for SDK callers) —
there is no separate pin to distribute; the raw public key IS what a
first-contact client pins the listener by. A suite line is omitted when that
suite is not offered — a FIPS server never prints the `Noise_NK` line. If
the listener has not finished starting (or none is configured), the command
fails with the server's `503`/`Unavailable` rather than printing empty keys.

This is distinct from `bootstrap noise show-key` / `show-p256-key`, which
derive a public key **locally** from a private key file you already hold.
`show-keys` asks the server directly, which is what you want once the
server is up and you did not generate its key yourself (see Configuration
in [`engineering.md`](engineering.md) — the listener generates or unseals
its own key; there is no config field for it).

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

The group holds the static-key verbs for **both** bootstrap suites. The name is
historical: `generate-key` predates the second suite.

| Verb | Purpose |
|---|---|
| `noise generate-key` | Generate a Noise_NK (Curve25519) static keypair |
| `noise show-key` | Show the public key for a Noise private key |
| `noise generate-p256-key` | Generate a P-256 static keypair for the FIPS-approved suite |
| `noise show-p256-key` | Show the public point for a P-256 private key |
| `noise show-spki-pin` | Show the SPKI pin of a certificate |

| Flag | Applies to | Type | Default |
|---|---|---|---|
| `--output`, `-o` | `generate-key`, `generate-p256-key` | string | **required** — writes the private key at mode 0600 |
| `--key-file` | `show-key`, `show-p256-key` | string | `""` — hex-encoded private key file |
| `--key-hex` | `show-key`, `show-p256-key` | string | `""` — hex-encoded private key inline |
| `--cert-file` | `show-spki-pin` | string | `""` — PEM certificate |

```
xkmsctl bootstrap noise generate-key --output noise.key
xkmsctl bootstrap noise show-key --key-file noise.key

xkmsctl bootstrap noise generate-p256-key --output p256.key
xkmsctl bootstrap noise show-p256-key --key-file p256.key
```

Which one you need follows the build. A FIPS server cannot run Noise_NK, so
`generate-p256-key` is the only verb that produces a key it can serve; a
non-FIPS server can serve both at once. See
[`api.md`](api.md) §Two handshake suites on one port.

`generate-key` writes the private key to the file named by `--output` and
prints only the public key. Omitting `--output` is an error rather than a
request to print the private key: stdout is read by terminal scrollback, shell
history, pipes and CI logs, and none of those can be wiped afterwards. Inside
the process the key lives in protected memory — guard-paged, locked against
swap, and wiped on release — so the hex encoding exists only long enough to
reach the file.

The **public** key is what clients need; distribute that. `--key-hex` puts a
private key on a command line, so it lands in shell history and process
listings — prefer `--key-file`.

`generate-p256-key` and `show-p256-key` behave identically, through the same
file-writing code: mode 0600, refusal to overwrite, and cleanup of a partial
write. Their output is an uncompressed P-256 point (130 hex characters, leading
`04`), not a 64-character Curve25519 key.

**A length check cannot tell the two private keys apart.** Both curves use a
32-byte scalar, so both hex-encode to 64 characters, and a Noise key handed to
`show-p256-key` decodes cleanly into a *different, wrong* key. The check that
catches it is comparing the public key the server serves against the one clients
were given — which is what `show-p256-key --key-file` is for.

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
