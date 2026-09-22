# Trust Bootstrap — User Guide

> **Status: NORMATIVE** · Feature: `trust-bootstrap` · Repo: `go-xkms` · Last verified: 2026-09-22

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
| the server's Noise public key, given to you out of band | **Noise** | `--noise-key`, or `--p256-key` for the FIPS-approved suite |
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

**On a FIPS client, pass the P-256 public point:**

```
xkmsctl bootstrap auto \
    --server-url https://kms.example.com:8443 \
    --noise-addr kms.example.com:8447 \
    --p256-key 04<128 hex chars>
```

A FIPS-built client cannot run Noise_NK either, so `--noise-key` alone fails
before it connects with `no bootstrap suite can be offered`, naming the build
as the reason. Give it `--p256-key` — the output of `show-p256-key` on the
server — and it completes the approved handshake. A client may carry both keys;
it offers whichever its build can run, so one configuration serves a mixed
fleet. In the resolver's config file the same pair is `server-static-key` and
`server-p256-static-key` under the scope's `noise:` block.

If you configure **neither** key, the server persists one for you (go-xkms#35)
instead of generating a fresh one on every restart: sealed under the barrier
when you have one configured (`barrier.enabled: true`), or as a plaintext hex
file inside the server's data directory with a one-time warning if you don't.
Either way, the key it serves on the next boot is the same one, so a public
key you have already distributed to clients keeps working across restarts.
Configure `barrier.enabled: true` in production so this key gets the same
at-rest protection as everything else the barrier covers.

**Upgrading from a server that used `static_key_file` / `static_key_hex` /
`p256_static_key_file` / `p256_static_key_hex`:** leave the field in place for
one more restart. The server reads it exactly once, seals the key it names
into the barrier (or, with no barrier, into the persisted file above), and
logs that the config field is now deprecated. After that restart, confirm the
public key clients have did not change (`xkmsctl bootstrap noise show-key` /
`show-p256-key` against the key file you originally generated, or simply that
existing clients still connect), then delete the field from your
configuration — it will not be read again.

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
| `no bootstrap suite can be offered … suite unavailable in this build` | a FIPS client was given only `--noise-key` | pass `--p256-key` (from `show-p256-key` on the server) |
| `auto` with only `--p256-key` fails at the handshake | the server serves no P-256 suite (no `p256_static_key_file`), or the point is not the one `show-p256-key` prints | configure the server key (#435) and copy the point verbatim |
| `suite Noise_NK_25519_ChaChaPoly_SHA256: … suite unavailable` | Noise_NK was pinned on a FIPS client | unpin it, or pin `SuiteP256AESGCM` |
| `server static key invalid for suite` | the key is not hex or the wrong length for its suite (64 chars Noise, 130 chars P-256) | check which key went into which flag |
| TOFU pin changed | either a legitimate rotation or an attack | investigate before clearing the pin |
| 401 from `bootstrap auto` | it used the authenticated bundle route | `--bundle-path /v1/ca/bootstrap` |

A pin mismatch or a TOFU pin change is the one failure in this list you should
never work around by clearing state. That failure is the feature doing its job.

## Where to go next

- Serving the bundle: [`../certificate-authority/user.md`](../certificate-authority/user.md)
- Getting a certificate once you trust the CA: [`../acme-issuance/user.md`](../acme-issuance/user.md)
- The client-side companion on the desktop: [`../../xkey/docs/platform-trust/user.md`](../../xkey/docs/platform-trust/user.md)
