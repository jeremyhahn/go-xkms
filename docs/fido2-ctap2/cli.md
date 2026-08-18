# FIDO2 / CTAP2 Client — CLI

> **Status: NORMATIVE** · Feature: `fido2-ctap2` · Repo: `go-xkms` · Last verified: 2026-08-19

Binary: `xkmsctl`, group `fido2` (`cmd/xkmsctl/fido2.go`). Global flags:
[`../key-management/cli.md`](../key-management/cli.md).

| Verb | Args | Purpose |
|---|---|---|
| `fido2 list-devices` | — | List attached FIDO2 authenticators |
| `fido2 wait-device` | — | Block until an authenticator is inserted |
| `fido2 info` | — | Report an authenticator's capabilities |
| `fido2 register <username>` | username | Enroll a credential |
| `fido2 authenticate` | — | Get an assertion and derive a key |

## `fido2 list-devices`

No flags.

```
xkmsctl fido2 list-devices
```

## `fido2 wait-device`

| Flag | Type | Default |
|---|---|---|
| `--timeout` | duration | `60s` |

```
xkmsctl fido2 wait-device --timeout 2m
```

## `fido2 info`

| Flag | Type | Default |
|---|---|---|
| `--device` | string | `""` — enumerate and pick |

```
xkmsctl fido2 info --device /dev/hidraw0
```

## `fido2 register <username>`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--rp-id` | string | `go-xkms` | relying-party id recorded on the credential |
| `--rp-name` | string | `Go xKMS` | relying-party display name |
| `--display-name` | string | `""` | user display name; defaults to the username |
| `--timeout` | duration | `30s` | user-presence timeout |
| `--device` | string | `""` | pin to a specific device |
| `--user-verification` | bool | `false` | require a PIN, not just a touch |

```
xkmsctl fido2 register alice --rp-id kms.example.com --rp-name "Example KMS" \
    --user-verification --timeout 60s
```

**`--rp-id` is not a label.** It is recorded on the credential, and
`fido2 authenticate` must use the same value or the authenticator will not find
the credential. The default `go-xkms` is a development value — set it to your
real relying-party id, and set it the same way on both verbs.

## `fido2 authenticate`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--credential-id` | string | `""` | credential id, base64 or hex |
| `--salt` | string | `""` | salt for `hmac-secret` derivation, base64 or hex |
| `--rp-id` | string | `go-xkms` | must match enrollment |
| `--timeout` | duration | `30s` | user-presence timeout |
| `--device` | string | `""` | pin to a specific device |
| `--user-verification` | bool | `false` | require a PIN |
| `--hex` | bool | `false` | output the derived key as hex instead of base64 |
| `--legacy-hmac-derivation` | bool | `false` | use the pre-existing derivation |

```
xkmsctl fido2 authenticate \
    --rp-id kms.example.com \
    --credential-id "$CRED_ID" \
    --salt "$SALT" \
    --user-verification --hex
```

The output is **key material**, not a status. It goes to stdout so it can be
piped — which also means it goes into your terminal scrollback if you do not
pipe it.

**`--legacy-hmac-derivation` matters.** A credential enrolled under one
derivation produces a *different* key under the other, and neither reports an
error — you simply get the wrong key. If a previously working unlock stopped
working after an upgrade, this flag is the first thing to try.

## Exit codes

`0` on success; non-zero on any failure, with the typed error on stderr. A
user-presence timeout, an absent device and a wrong PIN are all non-zero; none
of them fall back to anything.

## Parity coverage

`CommandDefinition` entries exist for `fido2-list-devices`, `fido2-wait-device`,
`fido2-info`, `fido2-register` and `fido2-authenticate` in
`test/integration/api/commands/commands.go` — **the whole group is covered**,
and it runs on every protocol. This is the shape the other groups should match.
