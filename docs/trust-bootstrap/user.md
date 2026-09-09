# Trust Bootstrap — User Guide

> **Status: NORMATIVE** · Feature: `trust-bootstrap` · Repo: `go-xkms` · Last verified: 2026-09-08

## What this is for

Before a client can verify anything an xkms server says, it needs the server's
CA bundle. Downloading the bundle over a connection you cannot verify, then
trusting it, proves nothing — an attacker in the middle simply hands you their
bundle instead.

Trust bootstrap is the set of ways to get that bundle while checking it against
something you already have.

## Pick your anchor

| You already have… | Use | Command |
|---|---|---|
| DNSSEC and control of the server's DNS | **DANE** | `--dane-hostname` |
| the server's SPKI pin, given to you out of band | **SPKI** | `--spki-pin` |
| the server's Noise public key, given to you out of band | **Noise** | `--noise-key` |
| a server with a publicly trusted certificate | **direct** | `--direct` |
| nothing | **TOFU** — read the warning below | opt-in only |

"Out of band" means: from a person, a provisioning system, a config-management
repository — anything that is not the connection you are about to make.

## The normal case

```
xkmsctl bootstrap auto \
    --server-url https://kms.example.com:8443 \
    --dane-hostname kms.example.com \
    --spki-pin 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 \
    --bundle-output ca-bundle.pem
```

`auto` tries what you configured and stops at the first success. Anything you
did not configure is skipped silently — which means a typo in a flag name
degrades you to the next anchor without saying so. Check the output for which
mode actually succeeded.

Then use the bundle:

```
xkmsctl --tls-ca ca-bundle.pem --server https://kms.example.com:8443 backends list
```

## If you get 401 from `bootstrap auto`

Pass the unauthenticated route explicitly:

```
xkmsctl bootstrap auto --server-url https://kms.example.com:8443 \
    --spki-pin "$PIN" --bundle-path /v1/ca/bootstrap --bundle-output ca-bundle.pem
```

The two candidate paths behave differently: `/v1/ca/bootstrap` is public and
answers before you have credentials; `/api/v1/ca/bundle` requires a session. The
flag help and the library default currently disagree about which is the default,
so being explicit is the reliable route.

## Setting it up as the server operator

**Publish an SPKI pin** — the simplest anchor to distribute:

```
xkmsctl bootstrap spki show-pin --cert-file kms.crt
```

Give that hex string to clients through whatever channel you already trust.

**Publish TLSA records** for DANE:

```
xkmsctl bootstrap dane generate-tlsa --cert-file kms.crt \
    --hostname kms.example.com --port 8443 --selector 1 --matching-type 1
```

Use selector `1` (SPKI). It survives certificate renewal as long as you keep the
key; selector `0` pins the whole certificate and breaks on every renewal until
DNS propagates.

Check what is actually published:

```
xkmsctl bootstrap dane show-tlsa --hostname kms.example.com --port 8443
xkmsctl bootstrap dane verify-tlsa --cert-file kms.crt --hostname kms.example.com --port 8443
```

**Run a Noise bootstrap channel:**

```
xkmsctl bootstrap noise generate-key --output noise.key
xkmsctl bootstrap noise show-key --key-file noise.key
```

Configure the private key on the server, publish the **public** key to clients.
`--output` is required: `generate-key` writes the private key to that file and
prints only the public key, because a private key on stdout survives in
scrollback, pipes and CI logs. Keep it in a file on the way back in too —
`--key-hex` exists but puts a private key into your shell history.

**On a FIPS server, generate a P-256 key instead:**

```
xkmsctl bootstrap noise generate-p256-key --output p256.key
xkmsctl bootstrap noise show-p256-key --key-file p256.key
```

A FIPS build cannot run Noise_NK — it mandates X25519, which SP 800-56A Rev. 3
does not approve — so the P-256 key is the only one such a server can serve.
Point `bootstrap.noise.p256_static_key_file` at the file and distribute the
public point to clients. A non-FIPS server can serve both suites at once by
configuring both keys; it selects per connection from what the client offers.

If you configure **neither** key, the server generates an ephemeral one at
startup and logs a warning. It works, but the key changes on every restart, so
every client that pinned the previous one stops connecting. Configure the file
in production.

If the server can run **no** suite at all it refuses at startup with
`bootstrap is enabled but this build can run no handshake suite`, naming why
each was rejected — rather than binding the port and failing every handshake.

The Noise port defaults to 8445 in the library, which collides with the MCP
port in the shipped configurations. `configs/xkmsd-local.yaml` moves it to 8447
for exactly that reason. **Set `noise_port` explicitly** and pass `--noise-addr`
on the client rather than relying on either default.

## About TOFU

Trust-on-first-use captures whatever the server presents on the first
connection and pins it for every connection afterwards. It protects you against
an attacker who shows up *later*. It does nothing at all against one who is
there the first time.

It is deliberately excluded from the `auto` chain: if DANE and SPKI both fail,
falling back to TOFU would turn a detected attack into a silently accepted one.
Enabling it under `auto` takes two explicit steps in configuration, and that is
by design.

TOFU works on two paths. Fetching a CA bundle (`bootstrap tofu`) pins the
bundle server. Verifying an endpoint directly — a BMC or any device that
presents a self-signed certificate and serves no bundle — uses the same pin
store through the resolver's TLS path (`tofu` in a scope's strategies with
the device as the endpoint) or through `NewTOFUTLSConfig` from the SDK. The
first connection records the device's key; if the recorded key ever changes
you get a pin-mismatch error and should investigate before clearing the pin
(#139).

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| `trust bootstrap: mode not configured` | you named a mode but gave it no config | supply that mode's flags, or use `auto` |
| `trust bootstrap: server URL required` | `--server-url` missing | every mode but pure Noise needs it |
| auto fails with nothing tried | no mode was configured | a flag typo silently disables a mode; check spelling |
| DANE fails but the record looks right | no DNSSEC validation, or the resolver does not validate | pass `--dane-dns-server` pointing at a validating resolver |
| DANE breaks after certificate renewal | you published selector 0 | republish with `--selector 1` |
| SPKI pin mismatch | the certificate changed, or something is in the middle | do not "fix" it by re-pinning without finding out which |
| Noise connection refused | port collision with MCP (8445) | set `noise_port` explicitly, pass `--noise-addr` |
| TOFU pin changed | either a legitimate rotation or an attack | investigate before clearing the pin |
| 401 from `bootstrap auto` | it used the authenticated bundle route | `--bundle-path /v1/ca/bootstrap` |

A pin mismatch or a TOFU pin change is the one failure in this list you should
never work around by clearing state. That failure is the feature doing its job.

## Where to go next

- Serving the bundle: [`../certificate-authority/user.md`](../certificate-authority/user.md)
- Getting a certificate once you trust the CA: [`../acme-issuance/user.md`](../acme-issuance/user.md)
- The client-side companion on the desktop: [`../../xkey/docs/platform-trust/user.md`](../../xkey/docs/platform-trust/user.md)
