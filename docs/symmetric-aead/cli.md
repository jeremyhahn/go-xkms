# Symmetric Encryption & AEAD — CLI

> **Status: NORMATIVE** · Feature: `symmetric-aead` · Repo: `go-xkms` · Last verified: 2026-09-24

Binary: `xkmsctl`. Symmetric keys share the generic `key` command group with
every other key type; there is no separate `xkmsctl symmetric` group.
Sources: `cmd/xkmsctl/key.go`.

Global flags — including `--backend`, `--transport`, `--server`, `--token` —
are documented in
[`../key-management/cli.md`](../key-management/cli.md) §Global flags.

## `key generate` — symmetric keys

```
xkmsctl key generate <key-id> --key-type symmetric [--algorithm <alg>] [--key-size <bits>]
```

| Flag | Default | Notes |
|---|---|---|
| `--key-type` | `tls` | help text: `"Key type (tls, signing, encryption, symmetric)"`; pass `symmetric` |
| `--algorithm` | `""` | help text: `"Algorithm (aes-128-gcm, aes-192-gcm, aes-256-gcm)"` — see below, the backend accepts more than the help text lists |
| `--key-size` | `2048` | for symmetric keys, bits (128/192/256) |
| `--exportable` | `false` | CKA_EXTRACTABLE-equivalent |
| `--sensitive` | `false` | never release plaintext (PKCS#11 CKA_SENSITIVE); independent of `--exportable` |

`--algorithm`'s help text lists only the three AES-GCM sizes, but the
server-side handler casts the string directly to `types.SymmetricAlgorithm`
(`pkg/api/rest/handlers.go:290-306`), so `--algorithm chacha20-poly1305` and
`--algorithm xchacha20-poly1305` are accepted even though the CLI does not
advertise them — see [`engineering.md`](engineering.md) for the full
algorithm table. If `--algorithm` is left empty when `--key-type symmetric`
is given, the CLI sends the literal `"symmetric"`, which the server resolves
to AES-256-GCM (`cmd/xkmsctl/key.go:83-97`; `pkg/api/rest/handlers.go:297-298`).

```
xkmsctl key generate my-secret --key-type symmetric --algorithm aes256-gcm
xkmsctl key generate my-secret --key-type symmetric --algorithm chacha20-poly1305
```

## `key encrypt` / `key decrypt`

```
xkmsctl key encrypt <key-id> <plaintext> [--aad <string>]
xkmsctl key decrypt <key-id> <ciphertext-base64> [--aad <string>] [--nonce <base64>] [--tag <base64>]
```

(`cmd/xkmsctl/key.go:403-421`, `:469-490`; flags registered at
`key.go:1805-1810`.) `key decrypt` base64-decodes its `<ciphertext>`
positional argument and the `--nonce`/`--tag` flag values before sending the
request.

**The CLI exposes only the default AEAD path.** There is no `--mode`,
`--iv`, or `--tag-size` flag on either command — `EncryptRequest.Mode`/`.IV`/
`.TagSize` and `DecryptRequest.Mode`/`.IV`/`.TagSize` exist on the wire (see
[`api.md`](api.md)) but nothing in `cmd/xkmsctl/key.go` sets them. AES-CBC,
AES-CBC-PAD, AES-ECB and a non-default (truncated) GCM tag size are reachable
only through the REST/gRPC/QUIC/MCP APIs directly or the embedded SDK — not
through `xkmsctl`.

```
xkmsctl key encrypt my-secret "hello world" --aad "context-string"
xkmsctl key decrypt my-secret <base64-ciphertext> --nonce <base64-nonce> --tag <base64-tag>
```

## `xkmsctl algorithms`

Symmetric AEAD algorithms appear in the same discovery inventory as every
other algorithm (see [`../post-quantum/cli.md`](../post-quantum/cli.md) for
the equivalent PQC section); they carry no `[post-quantum]` marker.

```
xkmsctl algorithms
```
