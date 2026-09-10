# Key Management — CLI

> **Status: NORMATIVE** · Feature: `key-management` · Repo: `go-xkms` · Last verified: 2026-08-19

Binary: `xkmsctl`. Command groups covered here: `key`, `backends`,
`algorithms`. Source: `cmd/xkmsctl/key.go`, `cmd/xkmsctl/root.go`,
`cmd/xkmsctl/algorithms.go`.

## Global flags

Registered on the root command (`cmd/xkmsctl/root.go`), available to every verb.

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--config` | string | — | Config file path |
| `--backend` | string | `software` | Backend to operate against |
| `--key-dir` | string | `xkms-data/keys` | Key directory for file-based backends |
| `--output`, `-o` | string | `text` | Output format (`text`, `json`) |
| `--verbose`, `-v` | bool | `false` | Verbose logging |
| `--transport` | string | build default | `embedded`, `rest`, `grpc`, `quic`, `unix`, `mcp` |
| `--protocol`, `-P` | string | build default | **Deprecated** — use `--transport` |
| `--server`, `-s` | string | — | Server address |
| `--tls-cert` / `--tls-key` / `--tls-ca` | string | — | Client mTLS material |
| `--token` | string | — | JWT bearer token |
| `--spki-pin` | string | — | SPKI pin for the server certificate |
| `--so-pin` | string | — | Security-officer PIN |
| `--pkcs11-module` | string | — | Path to the Cryptoki `.so` |
| `--pkcs11-slot` | int | `0` | PKCS#11 slot |
| `--pkcs11-pin` | string | — | PKCS#11 user PIN |

`--transport embedded` runs the whole keystore in-process with no server. Every
verb below works embedded.

## `xkmsctl backends` / `xkmsctl algorithms`

| Verb | Args | Purpose |
|---|---|---|
| `backends list` | — | List configured backends |
| `backends get <id>` | backend id | Backend detail and capabilities |
| `algorithms` | — | Algorithm vocabulary the server accepts |

```
xkmsctl --transport rest --server https://kms.example.com:8443 backends list -o json
```

## `xkmsctl key`

### `key generate <key-id>`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--key-type` | string | `tls` | no — one of `tls`, `signing`, `encryption`, `symmetric` |
| `--algorithm` | string | `""` | for symmetric — `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm` |
| `--key-algorithm` | string | `rsa` | no — `rsa`, `ecdsa`, `ed25519` |
| `--key-size` | int | `2048` | no — 128/192/256 for AES, 2048+ for RSA |
| `--curve` | string | `P-256` | no — `P-256`, `P-384`, `P-521` |
| `--exportable` | bool | `false` | no — allow export |
| `--sensitive` | bool | `false` | no — never allow export (terminal) |

```
xkmsctl key generate web-tls --key-algorithm ecdsa --curve P-384 --backend tpm2
```

### `key list` / `key get <key-id>` / `key delete <key-id>`

`get` and `delete` take `--key-type` (default `tls`).

```
xkmsctl key list --backend pkcs11
xkmsctl key get web-tls -o json
xkmsctl key delete web-tls --key-type tls
```

### `key sign <key-id> <data>` / `key verify <key-id> <data> <signature>`

Both take `--hash` (default `sha256`; `sha256`, `sha384`, `sha512`).

```
xkmsctl key sign web-tls "$(cat payload.b64)" --hash sha384
xkmsctl key verify web-tls "$(cat payload.b64)" "$SIG" --hash sha384
```

### `key encrypt <key-id> <plaintext>` / `key decrypt <key-id> <ciphertext>`

Symmetric AEAD. `encrypt` takes `--aad`; `decrypt` takes `--aad`, `--nonce`
(base64, required for symmetric), `--tag` (base64, required for symmetric).

```
xkmsctl key encrypt vault-dek "s3cret" --aad tenant=acme
xkmsctl key decrypt vault-dek "$CT" --nonce "$NONCE" --tag "$TAG" --aad tenant=acme
```

### `key encrypt-asym <key-id> <plaintext>`

RSA-OAEP. `--hash` (default `sha256`).

```
xkmsctl key encrypt-asym rsa-transport "hello" --hash sha256
```

### `key rotate <key-id>`

`--key-type` (default `tls`). Generates new material under the same ID.

```
xkmsctl key rotate web-tls --key-type tls
```

### `key import <key-id> <wrapped-key-file>`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--key-type` | string | `""` | **yes** — `rsa`, `ecdsa`, `ed25519`, `aes` |
| `--key-size` | int | `0` | required for `rsa` (2048, 3072, 4096) |
| `--aes-key-size` | int | `0` | required for `aes` (128, 192, 256) |
| `--curve` | string | `""` | required for `ecdsa` |
| `--hash` | string | `""` | signing hash to associate |
| `--partition` | string | `""` | backend partition |
| `--exportable` | bool | server default when omitted | `--exportable=false` imports non-extractable material; omitted, `aes` is exportable and the others are not |
| `--sensitive` | bool | `false` | CKA_SENSITIVE: the plaintext is never released |

```
xkmsctl key get-import-params imported-signer --output params.json
xkmsctl key wrap plain.key params.json wrapped.bin
xkmsctl key import imported-signer wrapped.bin --key-type rsa --key-size 3072
```

### `key export <key-id> <output-file>`

`--algorithm` (default `RSAES_OAEP_SHA_256`). Fails on a non-exportable key.

### `key export-material <key-id>`

`--output` writes raw bytes at mode 0600. Refused for `sensitive` keys.

### `key copy <key-id> <dest-key-id>`

`--dest-backend` (default `software`), `--dest-keydir`, `--key-type` (`tls`),
`--key-algorithm` (`rsa`), `--key-size` (`2048`), `--curve` (`P-256`),
`--algorithm` (`RSAES_OAEP_SHA_256`).

```
xkmsctl key copy web-tls web-tls-backup --dest-backend awskms
```

### `key get-import-params <key-id>`

`--key-type` (`tls`), `--key-algorithm` (`rsa`), `--key-size` (`2048`),
`--curve` (`P-256`), `--algorithm` (`RSAES_OAEP_SHA_256`), `--output` (JSON file).

### `key wrap <key-material-file> <params-file> <output-file>` / `key unwrap <wrapped-key-file> <params-file> <output-file>`

Client-side wrapping against import parameters. Prefer the by-ID pair below
when both keys are already in the service — it never materialises plaintext.

### `key wrap-by-id <target-key-id>`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--wrapping-key` | string | — | **yes** — KEK key ID |
| `--wrapping-backend` | string | `--backend` | no |
| `--target-backend` | string | `--backend` | no |
| `--algorithm` | string | `AES_KEY_WRAP` | no |
| `--output` | string | — | write wrapped bytes, mode 0600 |

### `key unwrap-by-id <new-key-id>`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--wrapped-file` | string | — | **yes** |
| `--unwrapping-key` | string | — | **yes** |
| `--unwrapping-backend` | string | `--backend` | no |
| `--target-backend` | string | `--backend` | no |
| `--algorithm` | string | `AES_KEY_WRAP` | must match the wrap |
| `--key-type` | string | `symmetric` | no |
| `--key-size` | int | `256` | no |
| `--curve` | string | `""` | for ECDSA |
| `--exportable` | bool | `false` | no |

```
xkmsctl key wrap-by-id tenant-dek --wrapping-key master-kek --output dek.wrapped
xkmsctl key unwrap-by-id tenant-dek-restored --wrapped-file dek.wrapped \
    --unwrapping-key master-kek --key-type symmetric --key-size 256
```

### `key attest <key-id>`

`--nonce` (base64; random 32 bytes when omitted), `--output` (JSON file).
Meaning is backend-specific.

```
xkmsctl key attest node-idevid --backend tpm2 --output attestation.json
```

### `key derive-ecdh <key-id>`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--peer-key` | string | — | **yes** — peer public key file (DER or uncompressed point) |
| `--kdf` | string | `HKDF` | `HKDF`, `SP800-108-COUNTER`, `SP800-108-FEEDBACK`, `SP800-56A`, `X963` |
| `--kdf-hash` | string | `SHA-256` | `SHA-256`, `SHA-384`, `SHA-512` |
| `--salt` | string | — | base64 |
| `--info` | string | — | context string |
| `--label` | string | — | SP 800-108 domain separation |
| `--length` | int | `32` | derived bytes |
| `--output` | string | — | write derived key, mode 0600 |

```
xkmsctl key derive-ecdh session-ec --peer-key peer.der --kdf HKDF --length 32
```

## Exit codes

`0` success; non-zero on any error, with the typed error rendered to stderr.
`-o json` puts the structured result on stdout so it can be piped.

## Parity coverage

`cli.md` and the integration parity definitions are two views of one surface.
Definitions exist today in `test/integration/api/commands/commands.go` for
`key-generate-rsa`, `key-generate-ecdsa`, `key-generate-ed25519`,
`key-generate-symmetric-exportable`, `key-generate-symmetric-sensitive`,
`key-list`, `key-info`, `key-delete`, `key-sign`, `key-verify`,
`backends-list`, `version`.

**Defect (parity suite is behind):** `key encrypt`, `key decrypt`,
`key encrypt-asym`, `key rotate`, `key import`, `key export`,
`key export-material`, `key copy`, `key get-import-params`, `key wrap`,
`key unwrap`, `key wrap-by-id`, `key unwrap-by-id`, `key attest`,
`key derive-ecdh`, `backends get` and `algorithms` have no
`CommandDefinition`. Adding them is mechanical — extend the table and the
runner picks them up on all protocols.
