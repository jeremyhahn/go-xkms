# Auth Factors — User Guide

> **Status: NORMATIVE** · Feature: `auth-factors` · Repo: `go-xkms` · Last verified: 2026-08-19

## What a "factor" is here

A factor is one way of proving you are you, using something physical. go-xkms
supplies four:

| Factor | What you hold | What it proves |
|---|---|---|
| `piv` | a PIV smartcard | the card signed a challenge |
| `pkcs11` | an HSM or token | the token signed a challenge |
| `fido2` | a security key or an xkey | a WebAuthn assertion |
| `mtls` | a client certificate | possession of the enrolled certificate's key |

You do not interact with these directly. They sit behind whatever login your
deployment exposes; when a login asks you to touch a key or enter a card PIN,
one of these is doing the checking.

## Enrolling

Enrollment is done through the identity plane of whatever is deployed above
go-xkms — go-qrdb, or a product built on it — because that is where users live.
The hardware side is what you prepare here.

**A FIDO2 security key or an xkey:**

```
xkmsctl fido2 list-devices
xkmsctl fido2 register alice
```

**A PIV card:**

```
xkmsctl piv list
xkmsctl piv generate 9a
xkmsctl piv csr 9a
```

Then have the resulting certificate signed and stored — see
[`../piv-smartcard/user.md`](../piv-smartcard/user.md).

**A client certificate for mTLS:**

```
xkmsctl ca issue --cn alice --profile client --output alice.crt
```

and bind it to the user through the identity plane.

## Using them

```
xkmsctl fido2 authenticate
```

Or, from the desktop companion, headlessly — which is what agents and CI use:

```
xkey auth login --user alice
```

## Things worth knowing before you deploy

**Software PIV is not a smartcard.** If the deployment did not configure a
hardware PIV generator, the `piv` factor proves possession of a software key.
That is fine for development and misleading in production. Ask which one you
have.

**The relying-party id is baked into every FIDO2 enrollment.** If it changes,
existing credentials stop working and every user re-enrolls. Decide it once.

**Challenges expire in five minutes by default.** If your users are timing out,
that is the window — and lengthening it lengthens the replay window too.

**Nothing degrades.** If the card is absent, the token is locked, or the
challenge expired, authentication fails. There is no fallback to a weaker check,
which is deliberate: a factor that quietly downgrades is not a factor.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| "no devices found" | the authenticator is not visible to the process | check permissions on the HID device; on Linux this is usually a udev rule |
| PIN required | the card or token is locked | enter the PIN; see [`../pin-management/user.md`](../pin-management/user.md) |
| authentication fails immediately, every time | RP id mismatch between enrollment and login | the enrollment was made under a different relying-party id |
| worked yesterday, fails today | challenge TTL, or a clock skew between client and server | check both clocks first |
| a token that used to work is now refused | it is locked out after failed PIN attempts | reset the lockout — see the PIN guide |
| PIV login rejected but the card works for signing | the certificate is not bound to the user | bind it on the identity plane |

## Where to go next

- The WebAuthn relying party itself: [`../webauthn/user.md`](../webauthn/user.md)
- Talking to security keys directly: [`../fido2-ctap2/user.md`](../fido2-ctap2/user.md)
- PIV cards: [`../piv-smartcard/user.md`](../piv-smartcard/user.md)
- PINs and lockouts: [`../pin-management/user.md`](../pin-management/user.md)
