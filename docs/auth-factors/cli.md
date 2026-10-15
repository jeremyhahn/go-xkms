# Auth Factors — CLI

> **Status: NORMATIVE** · Feature: `auth-factors` · Repo: `go-xkms` · Last verified: 2026-10-12

The factor *implementations* have no verbs of their own: go-xkms registers them
into go-qrdb's `AuthFactorRegistry` in-process. What `xkmsctl` does have is a
client for go-qrdb's `UserAuthFactorService`, the service that keeps each
user's set of enrolled factors.

## `xkmsctl auth factor` and `xkmsctl auth login`

Factor records belong to go-qrdb. The CLI builds a qrdb SDK client and calls
`UserAuthFactors()` on it (`cmd/xkmsctl/auth_factor_handlers.go:217`). xkmsd's
embedded node serves that service on its TLS unix socket. The transport follows
the CLI's `--server` / `--transport` flags (`cmd/xkmsctl/cluster.go:204`): the
default unix socket when there is no `--server`, then `unix:///path`,
`grpc://host:port`, or `grpcs://host:port`. Every one of them speaks TLS with
the CLI's `--tls-cert/--tls-key/--tls-ca`; the unix socket included, since it
refuses anonymous callers.

| Verb | Arguments and flags | Source |
|---|---|---|
| `auth factor list` | `--user <id>` (numeric, required) | `auth_factor_handlers.go:310` |
| `auth factor add` | `--type`, `--label`, `--user` (all required), plus the per-type flags below | `auth_factor_handlers.go:325` |
| `auth factor remove <factor-id>` | `--force` allows removing the user's last factor | `auth_factor_handlers.go:341` |
| `auth factor rotate <factor-id>` | the same flags as `add`; `--user` is inherited | `auth_factor_handlers.go:360` |
| `auth factor relabel <factor-id>` | `--label` (required) | `auth_factor_handlers.go:379` |
| `auth login` | `--method`, plus `--cert` or `--credential-hex` | `auth_factor_handlers.go:289` |

The verbs are registered under `auth` in `cmd/xkmsctl/canonical.go:48`.
`--type` and `--method` accept `mtls`, `fido2`, `piv` and `pkcs11`
(`auth_factor_handlers.go:42,51`).

Per-type flags for `add` and `rotate` (`auth_factor_handlers.go:401`):

| Type | Credential | Metadata flags |
|---|---|---|
| `mtls` | `--cert <pem>`: the CLI stores the certificate's SPKI thumbprint (`qrdbsdk.ComputeSPKIThumbprint`) and records its CN, serial and validity | — |
| `fido2` | `--credential-hex`: the WebAuthn credential ID | `--device` |
| `piv` | `--credential-hex`: SHA-256 of the slot certificate | `--reader`, `--slot` (default `9a`) |
| `pkcs11` | `--credential-hex`: SHA-256 of the key's SubjectPublicKeyInfo DER | `--pkcs11-slot`, `--pkcs11-label` |

`--created-by` records provenance: `self` (the default), `admin` or `ceremony`.
The credential formats come from `xkmsCredentialAndMetadata`
(`auth_factor_handlers.go:666`) and `buildXKMSLoginLookupKey`
(`auth_factor_handlers.go:732`).

```
xkmsctl auth factor list    --user 42
xkmsctl auth factor add     --user 42 --type mtls --label laptop --cert alice.pem
xkmsctl auth factor add     --user 42 --type fido2 --label yubikey --credential-hex "$CRED_ID_HEX"
xkmsctl auth factor relabel f-123 --label "yubikey 5c"
xkmsctl auth factor remove  f-123 --force
xkmsctl auth login --method mtls --cert alice.pem
```

**`auth login` looks a principal up; it does not prove anything.** It sends the
`(method, lookup key)` pair to go-qrdb, which maps it to a user. The hardware
proof (a FIDO2 assertion, a PIV signature, an mTLS handshake) must be checked
by whoever treats the answer as an authenticated identity.

## Hardware behind each factor

| To work with… | Use | Documented in |
|---|---|---|
| the PIV card behind the `piv` factor | `xkmsctl piv …` | [`../piv-smartcard/cli.md`](../piv-smartcard/cli.md) |
| the token behind the `pkcs11` factor | `xkmsctl --backend pkcs11 …`, `xkmsctl pkcs11 …` | [`../crypto-backends/cli.md`](../crypto-backends/cli.md) |
| the authenticator behind the `fido2` factor | `xkmsctl fido2 …` | [`../fido2-ctap2/cli.md`](../fido2-ctap2/cli.md) |
| the certificate behind the `mtls` factor | `xkmsctl cert …`, `--tls-cert/--tls-key` | [`../certificate-authority/cli.md`](../certificate-authority/cli.md) |

On the desktop side, `xkey auth register` / `xkey auth login` drive headless
WebAuthn against a server whose FIDO2 factor is one of these — see
[`../../xkey/docs/headless-webauthn/cli.md`](../../xkey/docs/headless-webauthn/cli.md).

## Parity coverage

The `auth factor` verbs have unit tests in
`cmd/xkmsctl/auth_factor_handlers_test.go`, but no entry in
`test/integration/api/commands/commands.go`. The factors themselves are covered
by `pkg/factor/registry_wiring_test.go`, the per-factor suites, and
`test/integration/logins` end to end.
