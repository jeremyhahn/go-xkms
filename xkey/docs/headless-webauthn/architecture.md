# Headless WebAuthn — Architecture

> **Status: NORMATIVE** · Feature: `headless-webauthn` · Module: `go-xkms/xkey` · Last verified: 2026-09-23

## The problem

WebAuthn assumes a browser and a person. An agent, a CI job or a daemon has
neither, and yet those are exactly the identities that most need a credential
stronger than a token in a file.

`xkey auth register` and `xkey auth login` run the full WebAuthn ceremonies with
no browser and no human — using xkey's own virtual authenticator as the
credential holder.

## Shape chosen: the single ceremony driver's hardware adapter, plus xkey's own SDK-transport glue

- **`go-xkms/pkg/webauthn/client`**, re-exported at `sdk/go/webauthnclient` —
  the single canonical headless WebAuthn ceremony driver in the stack
  (go-xkms#721). xkey drives the authenticator half of both ceremonies
  through its `HardwareAdapter` (`webauthnclient.NewHardwareAdapter`), backed
  by `pkg/fido2` — the same adapter `xkmsctl` uses, and the same driver whose
  `RelyingParty` seam (`TransportRelyingParty`) speaks the SDK transport
  routes this feature runs over. Documented in
  [`../../../docs/webauthn/engineering.md`](../../../docs/webauthn/engineering.md)
  §"The headless client".
- **[`../virtual-authenticator/`](../virtual-authenticator/architecture.md)** —
  xkey's own CTAP2 authenticator (its uhid device), which the hardware
  adapter drives like any other attached security key: HID enumeration does
  not distinguish it from real hardware.

xkey's own code (`xkey/cmd/xkey/cmd/auth.go`) supplies the server-side
ceremony glue directly over its SDK transport connection — `BeginRegistration`
/ `FinishRegistration` / `BeginAuthentication` / `FinishAuthentication` — plus
the credential storage. Nothing about the relying party changes: from the
server's side this is an ordinary WebAuthn registration and an ordinary
login, just over the SDK ceremony routes rather than the browser ones.

Rejected alternatives:

- **A bearer token for agents.** Rejected — that is the thing this replaces. A
  token in a file is copyable, and the dogfooding mandate is that agent
  credentials move to xkey's FIDO2/PIV/mTLS surfaces rather than raw key files.
- **A separate "machine login" protocol.** Rejected: a second authentication
  path is a second set of bugs, and the relying party would have to trust it
  differently.
- **Driving a real headless browser.** Rejected: heavy, fragile, and it still
  needs a human for user presence.

## Component boundaries

| Piece | Where |
|---|---|
| Authenticator adapter | `go-xkms/pkg/webauthn/client.HardwareAdapter`, re-exported at `sdk/go/webauthnclient` |
| Authenticator | `xkey/pkg/authenticator`, `xkey/pkg/uhid` |
| CLI and server-side ceremony glue | `xkey/cmd/xkey/cmd/auth.go`, `xkey/cmd/xkey/cmd/webauthn_ceremony.go` |
| Session and token storage | `xkey/pkg/tokenstore`, `xkey/pkg/serverregistry` |
| PIV login alternative | `xkey/cmd/xkey/cmd/auth_piv.go`, `pkg/pivcert` |
| Relying party | `go-xkms/pkg/webauthn`, served over the SDK ceremony routes (`pkg/api/rest`'s `/api/v1/webauthn/sdk/...`) |

Capability row: **"Headless WebAuthn registration/login (no browser)"** under the
xkey product surface.

## Data flow

```
xkey auth register --server https://kms.example.com:8443 --spki-pin … --setup-token …
   → SDK transport: BeginRegistration (/api/v1/webauthn/sdk/registration/begin)
     → HardwareAdapter.MakeCredential  (presence satisfied locally)
   → SDK transport: FinishRegistration (/api/v1/webauthn/sdk/registration/finish)
   ← credential stored, token returned

xkey auth login --server … --email …
   → BeginAuthentication → HardwareAdapter.GetAssertion → FinishAuthentication
   ← session token, kept by the token store
```

`xkey auth login --piv` takes a different route entirely: mTLS with a PIV slot
certificate instead of a WebAuthn assertion. Same outcome, different evidence —
useful where the relying party already trusts a certificate.

## Trust boundaries

- **`--spki-pin` verifies the server before enrolling.** At registration time
  the client may have no CA bundle; the pin is what stops enrolment against an
  impostor. See [`../platform-trust/architecture.md`](../platform-trust/architecture.md).
- **`--setup-token` is a pre-authorized enrolment credential.** It is a
  bearer secret with a narrow purpose and should be short-lived — it authorizes
  creating a credential, which is the highest-value thing in this flow.
- **The credential is only as strong as the authenticator's backend.** A
  headless login backed by `--backend software` proves possession of a file.
- **User presence is satisfied without a human.** That is the entire point, and
  it is why this belongs to agents and CI rather than to workstations. See
  [`../agent-automation/architecture.md`](../agent-automation/architecture.md).
- **Tokens returned by login are session credentials** and are stored by
  `xkey/pkg/tokenstore` — which store, and whether it is encrypted, matters.

## What this feature deliberately does not do

- **It does not weaken the relying party.** The server runs its normal
  ceremonies with its normal policy; it does not have a "headless mode".
- **It does not replace the browser flow** for humans.
- **It is not an OIDC client** — that is xkey's OIDC surface.
