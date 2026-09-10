# WebAuthn Relying Party — CLI

> **Status: NORMATIVE** · Feature: `webauthn` · Repo: `go-xkms` · Last verified: 2026-09-10

The relying party is a server component and has **no CLI verbs of its own**.
What the CLI offers is the client side of its ceremonies.

## Driving a ceremony from `xkmsctl`

`xkmsctl fido2` uses the headless client (`pkg/webauthn/client`) plus the CTAP2
layer to run registration and authentication against a real authenticator:

```
xkmsctl fido2 list-devices
xkmsctl fido2 register alice
xkmsctl fido2 authenticate
```

Full verb and flag detail: [`../fido2-ctap2/cli.md`](../fido2-ctap2/cli.md).

## Driving it headlessly from `xkey`

`xkey auth register` / `xkey auth login` run the same ceremonies with no browser
and no human, which is how agents and CI authenticate. See
[`../../xkey/docs/headless-webauthn/cli.md`](../../xkey/docs/headless-webauthn/cli.md).

## Registering and logging in from `xkmsctl`

`xkmsctl user register` / `xkmsctl user login` / `xkmsctl admin create` drive
the full server-side WebAuthn ceremony against a local CTAP2 authenticator. An
authenticator with a CTAP2 PIN set refuses either ceremony unless the request
carries the PIN, so all three verbs take the same three PIN sources, in the
same precedence order as the `xkey auth` verbs:

| Source | Precedence | Notes |
|---|---|---|
| `--pin-stdin` | 1 | reads the PIN from standard input; keeps it out of the process list |
| `XKMS_FIDO2_PIN` | 2 | environment variable |
| `--pin` | 3 | visible in `ps`; local development only |

```
printf '%s' "$PIN" | xkmsctl user register admin --pin-stdin --email admin@example.com
printf '%s' "$PIN" | xkmsctl user login admin@example.com --pin-stdin
```

The login key is the account's **email**, the key the server resolves the
account by. `user login <email>` and `user register --email` refuse a value
that is not a bare email address (a username, or a display-name form such as
`Alice <alice@example.com>`) before anything reaches the network, so a typo is
reported locally rather than as a remote authentication failure or a ceremony
run against a second principal keyed by that string. Surrounding whitespace is
trimmed.

An authenticator with no PIN configured needs none — supply nothing. A missing
PIN is reported as missing input naming these sources, and a wrong PIN reports
the authenticator's remaining attempts before lockout. This is the
authenticator's PIN, unrelated to the PKCS#11 `XKMS_SO_PIN` / `XKMS_USER_PIN`.

## Managing credentials

Credential listing and user management are identity-plane verbs, not RP verbs:

```
xkmsctl user get alice
xkmsctl user list
```

Configuration of the relying party — `RPID`, `RPOrigins`, `UserVerification`,
`AttestationPreference`, `ResidentKeyRequirement`, `AuthenticatorAttachment`,
`AllowPublicRegistration` — lives in the server's config file, documented in
[`engineering.md`](engineering.md) §Config. There is no CLI verb to change it,
deliberately: `RPID` and `RPOrigins` are security parameters, and a runtime flag
that could change them would be a way to re-anchor every credential.

## Parity coverage

`CommandDefinition` entries exist for `fido2-register`, `fido2-authenticate`,
`fido2-info`, `fido2-list-devices` and `fido2-wait-device` in
`test/integration/api/commands/commands.go`, so the client side of the
ceremonies runs on every protocol. The relying party itself has no verbs to
define.
