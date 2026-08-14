# Noise Protocol Key Management

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
xkmsctl bootstrap noise show-key
xkmsctl bootstrap noise show-spki-pin
```

## generate-key

Generates a new Curve25519 static keypair. The private key is emitted hex
encoded and should be stored securely; the public key is also displayed, for
distribution to clients.

```bash
# Print the keypair
xkmsctl bootstrap noise generate-key

# Write the private key to a file, created with 0600 permissions
xkmsctl bootstrap noise generate-key --output /etc/xkms/noise.key
```

| Flag | Default | Description |
|------|---------|-------------|
| `--output`, `-o` | (stdout) | Write the private key to a file, with 0600 permissions |

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
| `--noise-addr` | Noise bootstrap server address (`host:port`) |

The server's Noise listener is configured by `server.noise_port` (8447 in
`configs/xkmsd-local.yaml`) and enabled with `protocols.noise`.

The underlying implementation is go-truststrap's `pkg/noiseproto`.

## See Also

- [Bootstrap CLI](bootstrap.md) -- the full bootstrap command group
- [Multi-Protocol API Support](../../../../docs/acme/protocols/README.md) -- where the Noise port sits among the transports
