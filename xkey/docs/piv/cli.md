# PIV Certificate Management — CLI

> **Status: NORMATIVE** · Feature: `piv` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

Binary: `xkey`. Parent command: `xkey piv` (`PIVCmd`, `cmd/xkey/cmd/piv.go`).

## Global (persistent) flags

Inherited by every `piv` subcommand.

| Flag | Default | Description |
|---|---|---|
| `--backend` | `software` | Key backend: `software`, `tpm2` (needs `-tags tpm2`), or `pkcs11` (needs `-tags pkcs11`) |
| `--piv-storage` | (matches backend) | Certificate storage override: `file`, `tpm2`, or `pkcs11` |
| `--storage-path` | `./data/piv` | Path for file storage |
| `--tpm-device` | `/dev/tpmrm0` | TPM device path |
| `--pkcs11-library` | `/usr/lib/softhsm/libsofthsm2.so` | PKCS#11 library path |
| `--pkcs11-token` | | PKCS#11 token label |
| `--pkcs11-pin` | | PKCS#11 user PIN |
| `--pkcs11-so-pin` | | PKCS#11 Security Officer PIN |

Storage defaults to match the key backend (software→file, tpm2→tpm2,
pkcs11→pkcs11); override with `--piv-storage`, e.g. TPM2 keys with
file-based certificate storage:

```
xkey piv --backend tpm2 --piv-storage file list
```

## `xkey piv store <slot> <cert-file>`

Stores a certificate (PEM or DER, auto-detected) in a slot.

```
xkey piv store 9a /path/to/cert.pem
xkey piv store 9c /path/to/cert.der
xkey piv store 82 /path/to/old-cert.pem   # a retired key-management slot
```

## `xkey piv show <slot>`

```
xkey piv show 9a
```

## `xkey piv list` (alias `ls`)

```
xkey piv list
xkey piv --backend tpm2 list
```

## `xkey piv export <slot>`

| Flag | Default | Description |
|---|---|---|
| `--format` | `pem` | `pem` or `der` |
| `--output` | (stdout) | Output file path |

```
xkey piv export 9a --format pem --output /tmp/cert.pem
xkey piv export 9a --format der --output /tmp/cert.der
```

## `xkey piv delete <slot>` (aliases `rm`, `remove`)

| Flag | Default | Description |
|---|---|---|
| `--force` | `false` | Skip the confirmation prompt |

```
xkey piv delete 9a
xkey piv delete --force 9c
```

## `xkey piv status`

```
xkey piv status
xkey piv --backend tpm2 status
```

## `xkey piv csr <slot>`

Generates a CSR for a slot's existing key.

| Flag | Description |
|---|---|
| `--cn` | Common Name (required) |
| `--organization`, `--organizational-unit`, `--country`, `--province`, `--locality` | Subject fields |
| `--san`, `--san-dns`, `--san-ip`, `--san-uri` | Repeatable SAN entries |
| `--output`/`-o` | Output file (default: stdout) |

```
xkey piv csr 9a --cn "alice@example.com" --san-dns alice.example.com -o auth.csr
```

## `xkey piv generate <slot>`

Generates a new key pair in a slot.

| Flag | Default | Description |
|---|---|---|
| `--algorithm`/`-a` | `ECCP256` | `ECCP256`, `ECCP384`, `Ed25519`, `RSA2048`, `RSA4096` |
| `--pin-policy` | `once` | `never`, `once`, `always` |
| `--touch-policy` | `never` | `never`, `cached`, `always` |
| `--force`/`-f` | `false` | Overwrite an existing key without confirmation |
| `--output-format` | `self-signed` | `self-signed`, `public-key`, `csr`, `ca-signed` |
| `--subject` | (slot name) | Certificate subject CN |
| `--organization`, `--country` | | Certificate subject fields |
| `--validity-days` | 0 (backend default) | Certificate validity |
| `--output`/`-o` | (stdout) | Output file for CSR or public key |

```
xkey piv generate 9a -a ECCP256 --output-format self-signed
xkey piv generate 9c --pin-policy always --touch-policy cached --output-format csr -o 9c.csr
xkey piv generate 9d --output-format ca-signed --subject "CN=Alice"
```

`--output-format ca-signed` only produces a certificate where a certificate
authority is configured for the active backend — the GUI's
`PIVService.GetCAAvailability()` reports the same thing per backend; see
[architecture.md](architecture.md#gui-a-localremote-split-mirroring-the-clis-backendstorage-split).

## `xkey piv import <slot> <cert-file>`

| Flag | Default | Description |
|---|---|---|
| `--verify` | `true` | Verify the certificate matches the slot's public key |
| `--force`/`-f` | `false` | Import even if verification fails |

```
xkey piv import 9a new-cert.pem
xkey piv import 9a new-cert.pem --force
```

## Phone-held PIV slots

`device phone-list`, `device phone-generate`, `device phone-push-cert`,
`device phone-pull-cert`, `device piv-sync` operate on a paired phone's PIV
material, not this device's local storage. See
[phone-hsm/cli.md](../phone-hsm/cli.md#piv-on-the-phone).

## mTLS login with a PIV certificate

`xkey auth login --piv --slot <slot> --backend software|pkcs11 [PIN flags]`
authenticates to a registered server over mTLS using a slot's certificate
instead of WebAuthn. See `cmd/xkey/cmd/auth.go` and `auth_piv.go`; this is a
sibling command tree to `piv` and does not share its persistent flags — set
`--backend`/`--slot` again on `auth login` itself.

## Example workflows

```bash
# Set up PIV authentication (external CSR/signing tools)
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout auth.key -out auth.csr -subj "/CN=Alice"
openssl x509 -req -in auth.csr -CA ca.pem -CAkey ca.key \
  -CAcreateserial -out auth.pem -days 730
xkey piv store 9a auth.pem
xkey piv show 9a

# Rotate a certificate
xkey piv export 9a --format pem --output /backup/9a.pem
xkey piv store 9a new-cert.pem

# Migrate storage backends
xkey piv export 9a --format pem --output /tmp/9a.pem
xkey piv --backend tpm2 store 9a /tmp/9a.pem
xkey piv --backend tpm2 status
```
