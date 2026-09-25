# xkeysigner — User Guide

> **Status: NORMATIVE** · Feature: `xkeysigner` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

xkeysigner isn't something you run directly — it's the piece that lets a
go-xkms client (the `xkmsd` server itself, another service, a CLI tool
built on the SDK) authenticate to another go-xkms endpoint using a
certificate that lives on **your** PIV key, through the xKey app, instead
of a certificate and private key file sitting on disk.

## What you need running

**The xKey desktop application must be open.** This is the one thing to
check first if authentication that's supposed to use your PIV key isn't
working: xkeysigner only talks to the GUI app's background IPC connection,
not to the headless `xkey fido2` command. If you normally only run `xkey
fido2` (for example, on a server), this path isn't available there —
xkeysigner is a desktop-with-a-PIV-key feature.

You'll also want a certificate loaded into PIV slot `9a` (authentication)
— that's the slot everything built on this always requests. If the app has
no certificate in that slot, authentication fails; see
`xkey/docs/piv-smartcard/` (root module docs) for getting a certificate
onto the slot.

## What using it looks like

Day to day, you don't interact with xkeysigner directly — a developer or
operator configures whatever tool is connecting to a go-xkms server to use
it (for example, passing `xkms.WithXKeyAuth("")` when building an SDK
client, or an equivalent configuration flag in a tool built on the SDK).
From that point on:

1. The tool connects to your local xKey app over a local socket — nothing
   leaves your machine for this step.
2. It asks the app for the certificate in your PIV slot, and uses it to
   present a client certificate during the TLS handshake to the remote
   go-xkms server.
3. When the remote server needs your signature to complete the handshake,
   the tool sends the data to the app; the app performs the actual signing
   operation with your PIV key (in hardware, if that's what backs the
   slot) and sends back only the signature — your private key material
   never leaves the app or the hardware behind it.

If your xKey barrier is sealed, this fails the same way any other
PIV/PKCS#11 operation through the app would — unseal it first.

## If it isn't working

- **"socket not found"** — the xKey app isn't running, or isn't the
  version/build that starts its IPC listener. Start it.
- **"no certificate available"** — nothing is provisioned in PIV slot
  `9a`; load one in the app or via `xkey piv`.
- **Signing hangs, then times out (the IPC call itself allows up to 5
  seconds)** — check the app for anything it might be waiting on you for
  (a PIN prompt, for example), depending on how the slot's key is backed.
