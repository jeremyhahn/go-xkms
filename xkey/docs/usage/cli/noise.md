# Noise Protocol Key Management

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: `xkmsctl bootstrap noise`, the go-xkms server CLI (`cmd/xkmsctl/bootstrap_noise.go`, `cmd/xkmsctl/bootstrap_p256.go`).

> **Scope:** this page documents the go-xkms **server** CLI
> `xkmsctl bootstrap noise` (source: `cmd/xkmsctl/bootstrap_noise.go`), **not**
> the `xkey` desktop CLI. It lives under `xkey/docs/` for historical reasons.
> `xkey` has no `noise` command — the Noise XX handshake it performs when
> pairing a phone is internal to `xkey device pair` and is not separately
> configurable. For the xkey command tree see
> [the xkey CLI reference](README.md).

`xkmsctl bootstrap noise` manages the Curve25519 static keys used for Noise NK
bootstrap, and computes the SPKI pins used for pinned-TLS bootstrap. Both exist
so a joining node can establish trust in a server it has never spoken to before.

The command group sits under `bootstrap`:

```
xkmsctl bootstrap noise generate-key
xkmsctl bootstrap noise generate-p256-key
xkmsctl bootstrap noise show-key
xkmsctl bootstrap noise show-p256-key
xkmsctl bootstrap noise show-spki-pin
```

Flags are defined in `cmd/xkmsctl/bootstrap.go:311`.

## generate-key

Generates a new Curve25519 static keypair. The private key is written, hex
encoded, to the file named by `--output`; the public key is displayed, for
distribution to clients.

The private key is never printed, and `--output` is therefore required rather
than optional. Stdout is read by terminal scrollback, shell history, pipes and
CI logs, none of which can be wiped after the fact. Inside the process the key
is held in protected memory — guard-paged, locked against swap, wiped on
release — so the hex encoding exists only for as long as it takes to reach the
file.

```bash
# Write the private key to a file, created with 0600 permissions
xkmsctl bootstrap noise generate-key --output /etc/xkms/noise.key
```

| Flag | Default | Description |
|------|---------|-------------|
| `--output`, `-o` | **required** | File to create the private key in, mode 0600; must not already exist |

## generate-p256-key

Generates a P-256 static keypair for the `TSBOOT1_P256_AESGCM_SHA256` bootstrap
suite, the one a FIPS build serves: Noise NK mandates X25519, which SP 800-56A
Rev. 3 does not approve (`cmd/xkmsctl/bootstrap_p256.go:46`). `--output`
behaves exactly as for `generate-key`. There is no config field pointing the
server at this file; to use it instead of a server-generated key, place it at
`<storage.path>/bootstrap-noise-p256.key` before the server's first boot.

```bash
xkmsctl bootstrap noise generate-p256-key --output /etc/xkms/noise-p256.key
```

## show-p256-key

Derives the uncompressed public point from a P-256 static private key; clients
pin this value with `bootstrap auto --p256-key`. Takes `--key-file` or
`--key-hex`, as `show-key` does.

```bash
xkmsctl bootstrap noise show-p256-key --key-file /etc/xkms/noise-p256.key
```

## show-key

Derives and displays the public key from a Noise static private key. Takes the
key from either a file or a hex string.

```bash
xkmsctl bootstrap noise show-key --key-file /etc/xkms/noise.key
xkmsctl bootstrap noise show-key --key-hex 4a3f...
```

| Flag | Default | Description |
|------|---------|-------------|
| `--key-file` | (none) | Path to a hex-encoded private key file |
| `--key-hex` | (none) | Hex-encoded private key |

## show-spki-pin

Computes the SHA-256 hash of a certificate's SubjectPublicKeyInfo. This is the
pin used for SPKI-pinned TLS bootstrap, and the value `--spki-pin` expects
elsewhere.

```bash
# Fetch the server's certificate, then pin it
openssl s_client -connect host:port </dev/null | openssl x509 > cert.pem
xkmsctl bootstrap noise show-spki-pin --cert-file cert.pem
```

| Flag | Default | Description |
|------|---------|-------------|
| `--cert-file` | (none) | Path to a PEM certificate file |

## Using the key to bootstrap

`xkmsctl bootstrap auto` consumes the server's public key and Noise address:

```bash
xkmsctl bootstrap auto \
  --noise-key <hex-encoded server static public key> \
  --noise-addr host:8447
```

| Flag | Description |
|------|-------------|
| `--noise-key` | Hex-encoded Noise static **public** key of the server |
| `--p256-key` | Hex-encoded P-256 static public key of the server, for the FIPS-approved suite |
| `--noise-addr` | Noise bootstrap server address (`host:port`) |

The server's Noise listener is configured by `server.noise_port` (8447 in
`configs/xkmsd-local.yaml`) and enabled with `protocols.noise`.

The underlying implementation is go-truststrap's `pkg/noiseproto`.

## See Also

- [Bootstrap CLI](bootstrap.md) -- the full bootstrap command group
- [Key management API](../../../../docs/key-management/api.md) -- where the Noise port sits among the transports
