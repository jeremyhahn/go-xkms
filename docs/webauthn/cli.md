# WebAuthn Relying Party — CLI

> **Status: NORMATIVE** · Feature: `webauthn` · Repo: `go-xkms` · Last verified: 2026-08-19

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
