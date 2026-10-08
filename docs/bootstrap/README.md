# Bootstrap Architecture

go-xkms implements a secure bootstrap workflow for establishing trust
between clients and servers without pre-existing PKI infrastructure.

> The mode-dispatch logic that backs every CLI command and SDK accessor
> on this page lives in **one** canonical library:
> `pkg/trust/bootstrap`. See [trust/bootstrap.md](../trust/bootstrap.md)
> for the library surface (`Mode` enum, `Fetch`, `DeriveNoiseAddr`),
> the typed config shape, and the four consumers that route through it
> (`xkmsctl`, xkey GUI, QuicBaaS SDK, go-trusted-platform via the SDK).

## Trust Bootstrapping Methods

Four methods are available, tried in priority order by
`xkmsctl bootstrap auto`. Each maps directly to a `bootstrap.Mode` value
in the canonical library.

### 1. DANE (DNS-Based Authentication of Named Entities)

Uses DNSSEC-signed TLSA records (RFC 6698) to authenticate the server's CA certificate.

```bash
xkmsctl bootstrap dane generate-tlsa --cert-file /etc/xkms/ca.pem \
  --hostname kms.example.com --port 8443
```

### 2. Noise Protocol (Noise_NK)

Uses a pre-shared Curve25519 public key to establish an encrypted channel and retrieve the CA bundle. The server's Noise static key is distributed out-of-band.

```bash
xkmsctl bootstrap noise generate-key --output /etc/xkms/noise-static.key
xkmsctl bootstrap auto --server-url https://kms.example.com:8443 --noise-key <hex-pubkey>
```

### 3. SPKI Pinning (Trust-on-First-Use)

Uses the SHA-256 hash of the server's Subject Public Key Info for certificate pinning. The pin is printed by the server on first boot.

```bash
xkey auth register --server https://kms.example.com:8443 --spki-pin e5f6a7b8...
```

### 4. Direct HTTPS (Fallback)

Last-resort fallback using the system's default trust store. Requires the
server to already have a publicly-trusted (or OS-installed) certificate.
Enable with `--direct` so it participates in `ModeAuto`.

```bash
xkmsctl bootstrap auto --server-url https://kms.example.com:8443 --direct \
  --bundle-output /etc/xkms/ca-bundle.pem
```

## Auto-Bootstrap Flow

The `bootstrap auto` command tries configured methods in priority order
(DANE, Noise, SPKI, Direct). The first method that succeeds writes the CA
bundle.

```bash
xkmsctl bootstrap auto --server-url https://kms.example.com:8443 \
  --dane-hostname kms.example.com --bundle-output /etc/xkms/ca-bundle.pem
```

### Flags

| Flag | Description |
|------|-------------|
| `--server-url` | xkms server URL (e.g., `https://kms.example.com:8443`) |
| `--dane-hostname` | Hostname for DANE/TLSA verification |
| `--dane-dns-server` | DNS server for DANE lookups (e.g., `8.8.8.8:53`) |
| `--noise-key` | Hex-encoded Noise static public key of the server |
| `--noise-addr` | Noise bootstrap server address (`host:port`) |
| `--spki-pin` | Hex-encoded SHA-256 SPKI pin of server certificate |
| `--bundle-output` | Path to write CA bundle file (default: stdout) |

## Server First Boot

On first start, the server outputs three pieces of information:

1. **Setup Token** -- One-time JWT with 15-minute TTL for initial admin registration
2. **SPKI Pin** -- SHA-256 hash of the server's TLS certificate public key
3. **Hostname** -- Server address and port

## Custodians, Shares and Barriers

Custodian groups, Shamir share distribution, barrier unsealing and tenant
barriers belong to go-qrdb. xkms no longer exposes them: there is no
`xkmsctl custodian`, `xkmsctl barrier` or `xkey share` verb and no matching
route on any transport. Operate the barrier through go-qrdb's own surface; see
[`../sealing-and-barrier/`](../sealing-and-barrier/) for the hardware and cloud
seal strategies xkms contributes.

## See Also

- [Getting Started](../../xkey/docs/usage/getting-started.md) -- End-to-end setup walkthrough
- [xkey auth](../../xkey/docs/usage/cli/auth.md) -- Authentication commands
