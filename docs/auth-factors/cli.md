# Auth Factors — CLI

> **Status: NORMATIVE** · Feature: `auth-factors` · Repo: `go-xkms` · Last verified: 2026-08-19

**No dedicated CLI surface.** Auth factors are a tier-2 composition-plane
capability: go-xkms registers them into go-qrdb's `AuthFactorRegistry`
in-process, and the enrollment and login verbs belong to whoever owns the user
— go-qrdb, or a composer above it.

What you *can* do from `xkmsctl` is exercise the hardware each factor wraps:

| To work with… | Use | Documented in |
|---|---|---|
| the PIV card behind the `piv` factor | `xkmsctl piv …` | [`../piv-smartcard/cli.md`](../piv-smartcard/cli.md) |
| the token behind the `pkcs11` factor | `xkmsctl --backend pkcs11 …`, `xkmsctl pkcs11 …` | [`../crypto-backends/cli.md`](../crypto-backends/cli.md) |
| the authenticator behind the `fido2` factor | `xkmsctl fido2 …` | [`../fido2-ctap2/cli.md`](../fido2-ctap2/cli.md) |
| the certificate behind the `mtls` factor | `xkmsctl cert …`, `--tls-cert/--tls-key` | [`../certificate-authority/cli.md`](../certificate-authority/cli.md) |

`xkmsctl auth` and `xkmsctl user` operate on the identity plane that consumes
these factors; the factor *implementations* have no verbs of their own because
there is nothing a human does to them directly.

On the desktop side, `xkey auth register` / `xkey auth login` drive headless
WebAuthn against a server whose FIDO2 factor is one of these — see
[`../../xkey/docs/headless-webauthn/cli.md`](../../xkey/docs/headless-webauthn/cli.md).

## Parity coverage

Not applicable: with no verbs there is nothing for
`test/integration/api/commands/commands.go` to define. The factors are covered
by `pkg/factor/registry_wiring_test.go` and the per-factor suites, and
end-to-end by `test/integration/logins`.
