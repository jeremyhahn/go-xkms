# Bootstrap CLI Commands

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: `xkmsctl bootstrap`, the go-xkms server CLI (`cmd/xkmsctl/bootstrap*.go`); the normative reference is [`docs/trust-bootstrap/cli.md`](../../../../docs/trust-bootstrap/cli.md).

> **Scope:** this page documents the go-xkms **server** CLI `xkmsctl bootstrap`
> (source: `cmd/xkmsctl/`), **not** the `xkey` desktop CLI. It lives under
> `xkey/docs/` for historical reasons.
> There is no `xkey` equivalent. For the xkey command tree see
> [the xkey CLI reference](README.md).

The `bootstrap` command group fetches a CA bundle for a first-contact client
before TLS trust exists, and manages the DANE/TLSA records, Noise keys and SPKI
pins that make the fetch verifiable. For the protocol see the
[trust bootstrap architecture](../../../../docs/trust-bootstrap/architecture.md).

## Command Tree

```
xkmsctl bootstrap
├── auto                      # Try DANE, Noise, SPKI, then Direct
├── direct                    # Accept an operator-supplied CA bundle file
├── show-keys                 # The running server's bootstrap public keys
├── dane
│   ├── generate-tlsa         # TLSA records from a certificate
│   ├── verify-tlsa           # Check a certificate against published TLSA records
│   └── show-tlsa             # Display published TLSA records
├── noise
│   ├── generate-key          # Curve25519 (Noise_NK) static keypair
│   ├── generate-p256-key     # P-256 static keypair (FIPS suite)
│   ├── show-key              # Public key from a Noise_NK private key
│   ├── show-p256-key         # Public key from a P-256 private key
│   └── show-spki-pin         # SPKI SHA-256 pin of a certificate
└── spki
    └── show-pin              # SPKI SHA-256 pin of a certificate
```

---

## bootstrap auto

Tries each configured method in priority order — DANE, Noise, SPKI, Direct —
and returns the first CA bundle that verifies. A method is tried only if its
flags (or the config file) configure it. Direct is a last-resort fallback over
plain HTTPS with the system trust store.

```bash
xkmsctl bootstrap auto [flags]
```

Flags are defined in `cmd/xkmsctl/bootstrap.go:326`:

| Flag | Default | Description |
|------|---------|-------------|
| `--server-url` | | xkms server URL, for example `https://kms.example.com:8443` |
| `--config` | | xkmsd config file; its `trust:` section's default scope supplies base values, flags override them |
| `--dane-hostname` | | Hostname for DANE/TLSA verification |
| `--dane-dns-server` | | DNS server for DANE lookups, for example `8.8.8.8:53` |
| `--noise-key` | | Hex Noise_NK (Curve25519) static public key of the server |
| `--p256-key` | | Hex P-256 static public key of the server, for the FIPS-approved suite |
| `--noise-addr` | | Noise bootstrap server address (`host:port`) |
| `--spki-pin` | | Hex SHA-256 SPKI pin of the server certificate |
| `--direct` | `false` | Enable the direct HTTPS fallback |
| `--bundle-path` | `/api/v1/ca/bundle` | REST path of the CA bundle endpoint |
| `--bundle-output` | stdout | File to write the CA bundle to |

```bash
xkmsctl bootstrap auto \
  --server-url https://kms.example.com:8443 \
  --dane-hostname kms.example.com \
  --noise-addr kms.example.com:8444 --noise-key <hex-public-key> \
  --bundle-output /etc/xkms/ca-bundle.pem
```

## bootstrap direct

Takes a CA bundle PEM file supplied out of band. The file must exist and must
not be a directory (`cmd/xkmsctl/canonical.go:113`).

```bash
xkmsctl bootstrap direct --bundle /path/to/ca.pem
```

## bootstrap show-keys

Asks the running server, over its admin API, for its bootstrap listener's
Noise_NK and P-256 public keys. Needs the `bootstrap:read` permission. A suite
the server does not offer is omitted. The raw public key is what a client pins:
pass it to `bootstrap auto --noise-key` or `--p256-key`
(`cmd/xkmsctl/bootstrap.go:111`).

```bash
xkmsctl bootstrap show-keys
xkmsctl bootstrap show-keys --output json
```

---

## bootstrap dane generate-tlsa

Generates TLSA records from a PEM certificate for a DNSSEC-signed zone
(`cmd/xkmsctl/bootstrap_dane.go:233`).

| Flag | Default | Description |
|------|---------|-------------|
| `--cert-file` | | PEM certificate |
| `--hostname` | | Hostname for the record, for example `kms.example.com` |
| `--port` | `443` | Port for the record |
| `--usage` | `2` | Certificate usage (0-3); 2 = DANE-TA |
| `--selector` | `1` | 0 = full certificate, 1 = SPKI |
| `--matching-type` | `1` | 0 = exact, 1 = SHA-256, 2 = SHA-512 |
| `--all` | `false` | Generate all common combinations |

Each record prints as `<name> IN TLSA <usage> <selector> <matching-type> <data>`,
with the name `_<port>._tcp.<hostname>.`:

```bash
xkmsctl bootstrap dane generate-tlsa \
  --cert-file /etc/xkms/ca.pem --hostname kms.example.com --port 8443
```

```
_8443._tcp.kms.example.com. IN TLSA 2 1 1 a1b2c3...
```

`--all` prints six records: `2 1 1`, `2 0 1`, `3 1 1`, `3 0 1`, `3 1 2` and
`3 0 2` (`cmd/xkmsctl/bootstrap_dane.go:488`).

## bootstrap dane verify-tlsa

Checks that a certificate matches the TLSA records published for a hostname and
port.

| Flag | Default | Description |
|------|---------|-------------|
| `--cert-file` | | PEM certificate to verify |
| `--hostname` | | Hostname to look up |
| `--port` | `443` | Port of the record |
| `--dns-server` | `8.8.8.8:53` when empty | DNS server for the lookup (`cmd/xkmsctl/bootstrap_dane.go:67`) |

```bash
xkmsctl bootstrap dane verify-tlsa \
  --cert-file /etc/xkms/ca.pem --hostname kms.example.com --port 8443
```

## bootstrap dane show-tlsa

Queries DNS for `_<port>._tcp.<hostname>` TLSA records and prints them in a
readable form. Flags: `--hostname`, `--port` (default `443`) and
`--dns-server` (`8.8.8.8:53` when empty).

```bash
xkmsctl bootstrap dane show-tlsa --hostname kms.example.com --port 8443
```

---

## bootstrap noise

### generate-key and generate-p256-key

Each writes a new private key, hex-encoded, to the file named by `-o`/`--output`
(required). The file is created with mode 0600 and must not already exist; the
private key is never printed. The public key is printed for distribution to
clients (`cmd/xkmsctl/bootstrap.go:311`).

`generate-p256-key` makes the key for the `TSBOOT1_P256_AESGCM_SHA256` suite,
the only suite a FIPS build serves, because Noise_NK needs X25519, which a FIPS
build cannot run. The server's bootstrap key is never config-supplied: to use a
key generated here, follow the placement instructions in
`xkmsctl bootstrap noise generate-p256-key --help`.

```bash
xkmsctl bootstrap noise generate-key --output /etc/xkms/noise.key
xkmsctl bootstrap noise generate-p256-key --output /etc/xkms/noise-p256.key
```

### show-key and show-p256-key

Print the public key for a private key given by `--key-file` or `--key-hex`.

```bash
xkmsctl bootstrap noise show-key --key-file /etc/xkms/noise.key
xkmsctl bootstrap noise show-p256-key --key-file /etc/xkms/noise-p256.key
```

### show-spki-pin

Same as `bootstrap spki show-pin`.

## bootstrap spki show-pin

Prints the SHA-256 hash of a certificate's SubjectPublicKeyInfo, the value for
`bootstrap auto --spki-pin`. The only flag is `--cert-file`.

```bash
openssl s_client -connect kms.example.com:8443 </dev/null | openssl x509 > server.pem
xkmsctl bootstrap spki show-pin --cert-file server.pem
```

---

## Workflow: publish DANE and bootstrap a client

```bash
# Server operator: generate the record and publish it in the signed zone
xkmsctl bootstrap dane generate-tlsa --cert-file /etc/xkms/ca.pem \
  --hostname kms.example.com --port 8443

# Once DNS has propagated, confirm what resolvers see
xkmsctl bootstrap dane verify-tlsa --cert-file /etc/xkms/ca.pem \
  --hostname kms.example.com --port 8443

# Client: fetch the bundle
xkmsctl bootstrap auto --server-url https://kms.example.com:8443 \
  --dane-hostname kms.example.com --bundle-output ca-bundle.pem
```

## Workflow: pin the server's Noise key

```bash
# Operator: read the running server's public keys
xkmsctl bootstrap show-keys

# Client: pin the key it was given out of band
xkmsctl bootstrap auto --noise-addr kms.example.com:8444 \
  --noise-key <hex-public-key> --bundle-output ca-bundle.pem
```

## See Also

- [Trust bootstrap architecture](../../../../docs/trust-bootstrap/architecture.md)
- [Trust bootstrap engineering](../../../../docs/trust-bootstrap/engineering.md#configuration) — the `trust:` config section
- [Trust bootstrap CLI](../../../../docs/trust-bootstrap/cli.md) — normative
