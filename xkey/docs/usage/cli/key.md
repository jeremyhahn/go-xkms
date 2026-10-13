# CLI Key Command Reference

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: `xkmsctl key`, the go-xkms server CLI (`cmd/xkmsctl/key.go`, `cmd/xkmsctl/key_version.go`); the normative reference is [`docs/key-management/cli.md`](../../../../docs/key-management/cli.md).

> **Scope:** this page documents the go-xkms **server** CLI `xkmsctl key`
> (source: `cmd/xkmsctl/`), **not** the `xkey` desktop CLI. It lives under
> `xkey/docs/` for historical reasons.
> There is no `xkey` equivalent. For the xkey command tree see
> [the xkey CLI reference](README.md).

## Overview

The `key` command group manages keys held by an xkmsd server. Every subcommand
connects to the server named by the global `-s/--server` flag (default
`xkms-data/xkms.sock`) and acts on the backend named by `--backend` (default
`software`). There is no local or offline mode: key material stays on the
server, and the CLI reads and writes only the files named on its command line.

The global flags that matter most here are `--backend`, `-s/--server`,
`--token`, the `--tls-*` flags and `-o/--output` (`text`, `json` or `table`).
Commands with their own `--output` file flag (`attest`, `derive-ecdh`,
`export-material`, `get-import-params`, `wrap-by-id`) hide the global
`-o/--output` there.

```
xkmsctl key
├── generate <key-id>                  ├── encrypt <key-id> <plaintext>
├── list                               ├── decrypt <key-id> <ciphertext>
├── get <key-id>                       ├── encrypt-asym <key-id> <plaintext>
├── delete <key-id>                    ├── derive-ecdh <key-id>
├── rotate <key-id>                    ├── export <key-id> <output-file>
├── rotate-all                         ├── export-material <key-id>
├── versions <key-id>                  ├── get-import-params <key-id>
├── version                            ├── import <key-id> <wrapped-key-file>
│   ├── enable <key-id> <version>      ├── wrap <material> <params> <output>
│   ├── enable-all <key-id>            ├── unwrap <wrapped> <params> <output>
│   ├── disable <key-id> <version>     ├── wrap-by-id <target-key-id>
│   ├── disable-all <key-id>           ├── unwrap-by-id <new-key-id>
│   └── retire <key-id> <version>      ├── copy <key-id> [<dest-key-id>]
├── sign <key-id> <data>               ├── attest <key-id>
└── verify <key-id> <data> <signature> └── policy <key-id>
```

## Lifecycle

### key generate

Flags are defined at `cmd/xkmsctl/key.go:1909` onward.

| Flag | Default | Description |
|------|---------|-------------|
| `--key-type` | `tls` | `tls`, `signing`, `encryption` or `symmetric` |
| `--key-algorithm` | `rsa` | Asymmetric algorithm: `rsa`, `ecdsa` or `ed25519` |
| `--key-size` | `2048` | RSA bits (2048 or more), or AES bits (128, 192, 256) |
| `--curve` | `P-256` | ECDSA curve: `P-256`, `P-384` or `P-521` |
| `--algorithm` | | Symmetric cipher: `aes-128-gcm`, `aes-192-gcm` or `aes-256-gcm` |
| `--exportable` | `false` | Allow the key to be exported |
| `--sensitive` | `false` | Never release the plaintext (PKCS#11 `CKA_SENSITIVE`); with `--exportable` the key can still be wrapped |
| `--tpm-policy` | built-in platform policy | TPM policy a `tpm2` key is bound to; see `xkmsctl tpm policy` |

A key is symmetric when `--key-type` is `symmetric` or `aes`, or when
`--algorithm` names an AES-GCM cipher. Without `--algorithm` the server picks
the cipher from `--key-size` (`cmd/xkmsctl/key.go:121`).

```bash
xkmsctl key generate web-tls                                   # RSA 2048, type tls
xkmsctl key generate signer --key-type signing --key-algorithm ecdsa --curve P-384
xkmsctl key generate data-key --key-type symmetric --key-size 256 --exportable
xkmsctl --backend tpm2 key generate device-key --key-algorithm ecdsa
```

### key list, get, delete

`list` takes no flags. `get` and `delete` take `--key-type` (default `tls`).

```bash
xkmsctl key list -o json
xkmsctl key get signer --key-type signing
xkmsctl key delete old-key
```

### key rotate and rotate-all

`rotate` generates the next version of a key with the same algorithm and
attributes and makes it current. Sign and encrypt move to it at once; earlier
versions stay enabled, so their signatures and ciphertext still verify and
decrypt. If the key has a certificate, `rotate` warns that the certificate
still certifies the previous version. `rotate` takes `--key-type` (default
`tls`).

`rotate-all` rotates every key of a tenant in every backend. A key that cannot
be rotated is reported and the rest are still rotated; the command then exits
non-zero. A system caller can name another tenant with `--tenant`.

```bash
xkmsctl key rotate signer --key-type signing
xkmsctl key rotate-all --tenant acme
```

### key versions and key version

`versions` lists each version's number, state (enabled, disabled or retired),
whether it is current, and when and by whom it was created.

| Command | Effect |
|---------|--------|
| `version disable <key-id> <version>` | No operation may use the version until it is enabled again; its material is kept. The current version cannot be disabled. |
| `version disable-all <key-id>` | Disable every enabled version except the current one |
| `version enable <key-id> <version>` | Let verify and decrypt use the version again. A retired version cannot be enabled. |
| `version enable-all <key-id>` | Enable every disabled version; retired ones stay retired |
| `version retire <key-id> <version>` | Delete the version's material for good. What it signed or encrypted can no longer be verified or decrypted. The current version cannot be retired. |

```bash
xkmsctl key versions signer
xkmsctl key version disable signer 1
```

## Cryptographic Operations

Data arguments to `sign`, `verify`, `encrypt` and `encrypt-asym` are taken as
literal strings (their UTF-8 bytes). Binary results are printed base64.

### key sign and key verify

`sign` prints the signature in base64; `-o json` gives `signature` and, when
the server reports one, `key_version`. `verify` takes that base64 signature.

| Flag | Default | Description |
|------|---------|-------------|
| `--hash` | `sha256` | `sha256`, `sha384` or `sha512` (both commands) |
| `--key-version` | every enabled version, newest first | `verify` only: the version to check against |

```bash
SIG=$(xkmsctl key sign signer "release v1.0")
xkmsctl key verify signer "release v1.0" "$SIG"
```

### key encrypt and key decrypt

`encrypt` uses a symmetric (AES) key. It prints the ciphertext, nonce and tag
in base64, the algorithm, and the key version; `-o json` gives `ciphertext`,
`nonce`, `tag`, `algorithm` and `key_version`. `--aad` adds associated data.

`decrypt` takes base64 ciphertext and works for symmetric and asymmetric keys.
It prints the plaintext base64-encoded (`cmd/xkmsctl/key.go:609`).

| `decrypt` flag | Description |
|----------------|-------------|
| `--nonce` | Nonce/IV from `encrypt` (base64); required for symmetric keys |
| `--tag` | Authentication tag from `encrypt` (base64); required for symmetric keys |
| `--aad` | The associated data given to `encrypt` |
| `--key-version` | The version `encrypt` reported. By default the server chooses; it is required for AES-CBC and RSA PKCS#1 v1.5 ciphertext once a key has several enabled versions. |

```bash
ENC=$(xkmsctl key encrypt data-key "secret" -o json)
xkmsctl key decrypt data-key "$(echo "$ENC" | jq -r .ciphertext)" \
  --nonce "$(echo "$ENC" | jq -r .nonce)" --tag "$(echo "$ENC" | jq -r .tag)" \
  | base64 -d
```

### key encrypt-asym

RSA-OAEP encryption with an RSA key. `--hash` selects the OAEP hash (`sha256`
by default, `sha384` or `sha512`). Prints the ciphertext in base64; decrypt it
with `key decrypt`.

```bash
CT=$(xkmsctl key encrypt-asym web-tls "secret")
xkmsctl key decrypt web-tls "$CT" | base64 -d
```

### key derive-ecdh

ECDH between the named private key and a peer public key, followed by a KDF.
The private key stays in the backend.

| Flag | Default | Description |
|------|---------|-------------|
| `--peer-key` | | Peer public key file, DER or uncompressed point, same curve (required) |
| `--kdf` | `HKDF` | `HKDF`, `SP800-108-COUNTER`, `SP800-108-FEEDBACK`, `SP800-56A` or `X963` |
| `--kdf-hash` | `SHA-256` | `SHA-256`, `SHA-384` or `SHA-512` |
| `--length` | `32` | Derived key length in bytes |
| `--salt` | | KDF salt (base64) |
| `--info` | | KDF context string |
| `--label` | | SP 800-108 label |
| `--output` | | Write the derived key to a file (mode 0600) instead of printing it |

```bash
xkmsctl key derive-ecdh my-ec-key --peer-key peer.der --kdf-hash SHA-384 --output shared.key
```

## Import, Export and Wrapping

### key export and key export-material

`export <key-id> <output-file>` writes the key wrapped for transport, as JSON,
to a file with mode 0600. `--algorithm` selects the wrapping algorithm
(default `RSAES_OAEP_SHA_256`). The key must be exportable.

`export-material <key-id>` returns the raw bytes of an extractable symmetric
key, **in plaintext**. It prints them base64, or writes them to `--output`
(mode 0600). It is refused for a `--sensitive` key. Prefer `export` for moving
keys between systems.

### key get-import-params, wrap, import

Importing external key material takes three steps:

1. `get-import-params <key-id>` fetches the server's wrapping public key and
   parameters. With `--output` they are saved as JSON (mode 0600); otherwise
   they are printed. Flags: `--algorithm` (default `RSAES_OAEP_SHA_256`),
   `--key-type` (default `tls`), `--key-algorithm` (default `rsa`),
   `--key-size` (default `2048`), `--curve` (default `P-256`).
2. `wrap <key-material-file> <params-file> <output-file>` wraps the raw
   material with those parameters and writes the wrapped key as JSON (mode
   0600).
3. `import <key-id> <wrapped-key-file>` imports it.

| `import` flag | Description |
|---------------|-------------|
| `--key-type` | Algorithm of the imported key: `rsa`, `ecdsa`, `ed25519` or `aes` (required) |
| `--key-size` | RSA modulus bits (2048, 3072, 4096); required for `rsa` |
| `--curve` | `P-256`, `P-384` or `P-521`; required for `ecdsa` |
| `--aes-key-size` | 128, 192 or 256; required for `aes` |
| `--hash` | Signing hash to associate with the key, for example `SHA-256` |
| `--exportable` | Whether the key may be exported again; when omitted the server default applies (`aes` exportable, others not) |
| `--sensitive` | Mark the key `CKA_SENSITIVE`; `export-material` is then refused |
| `--partition` | Backend partition to import into |

`unwrap <wrapped-key-file> <params-file> <output-file>` reverses `wrap` on the
server and writes the recovered material to a file with mode 0600.

```bash
xkmsctl key get-import-params imported-key --output params.json
xkmsctl key wrap aes.bin params.json wrapped.json
xkmsctl key import imported-key wrapped.json --key-type aes --aes-key-size 256
```

### key wrap-by-id and key unwrap-by-id

The CLI equivalents of PKCS#11 `C_WrapKey` and `C_UnwrapKey`, with both keys
named by their server-side IDs.

| `wrap-by-id` flag | Default | Description |
|-------------------|---------|-------------|
| `--wrapping-key` | | Wrapping key (KEK) ID (required) |
| `--algorithm` | `AES_KEY_WRAP` | Wrapping algorithm |
| `--wrapping-backend` | `--backend` | Backend holding the wrapping key |
| `--target-backend` | `--backend` | Backend holding the target key |
| `--output` | | Write the wrapped bytes to a file (mode 0600) instead of printing them base64 |

| `unwrap-by-id` flag | Default | Description |
|---------------------|---------|-------------|
| `--wrapped-file` | | Wrapped bytes, as written by `wrap-by-id --output` (required) |
| `--unwrapping-key` | | Unwrapping key ID (required) |
| `--algorithm` | `AES_KEY_WRAP` | Must match the wrap |
| `--key-type` | `symmetric` | `symmetric`, `rsa`, `ecdsa` or `ed25519` |
| `--key-size` | `256` | New key size in bits |
| `--curve` | | Curve for `ecdsa` keys |
| `--exportable` | `false` | Allow the new key to be exported |
| `--unwrapping-backend`, `--target-backend` | `--backend` | Where the unwrapping key is, and where the new key goes |

```bash
xkmsctl key wrap-by-id data-key --wrapping-key kek --output wrapped.bin
xkmsctl key unwrap-by-id restored-key --wrapped-file wrapped.bin --unwrapping-key kek
```

### key copy

Copies an exportable key from `--backend` to `--dest-backend` (default
`software`) by wrapping it on the server. The copy takes its algorithm, size,
curve, hash and partition from the source (`cmd/xkmsctl/key.go:991`). The
destination ID defaults to the source ID. `--algorithm` selects the wrapping
algorithm (default `RSAES_OAEP_SHA_256`). `--dest-keydir` is declared
(`cmd/xkmsctl/key.go:1965`) but not read.

```bash
xkmsctl --backend software key copy web-tls web-tls-hsm --dest-backend pkcs11
```

## Hardware

### key attest

Requests an attestation statement proving the key was created in hardware and
never left it. A random 32-byte nonce is used unless `--nonce` (base64) is
given. `--output` writes the statement to a JSON file (mode 0600); otherwise
the backend, format, signature algorithm, nonce, data, signature and
certificate count are printed.

```bash
xkmsctl --backend tpm2 key attest device-key --output attestation.json
```

### key policy

Shows the TPM policy a `tpm2` key was created under and its authPolicy digest.
`--sealed` reads a sealed object instead of a key; `--tenant` addresses another
tenant's TPM scope (system callers only).

```bash
xkmsctl --backend tpm2 key policy device-key
```

## See Also

- [Key management](../../../../docs/key-management/user.md) — the normative feature folder
- [Key Import/Export Guide](../key-import-export.md)
- [Advanced Cryptography Guide](../advanced-crypto.md)
- [Backend Documentation](../../../../docs/crypto-backends/user.md)
- [Certificate Management CLI](./cert.md)
