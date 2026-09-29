# FROST Threshold Signing — CLI

> **Status: NORMATIVE** · Feature: `frost-threshold-signing` · Repo: `go-xkms` · Last verified: 2026-09-29 (#1337)

`xkmsctl frost` requires a binary built with `-tags frost`
(`go build -tags frost ./cmd/xkmsctl`); without the tag, every subcommand
prints `Error: FROST support not compiled in` and exits 1
(`cmd/xkmsctl/frost_stub.go`).

**Every `xkmsctl frost` subcommand runs entirely on the operator's own
machine.** The global `--server` / `--transport` flags that every other
`xkmsctl` command group honors have no effect here — see
[`architecture.md`](architecture.md) §"Two independent surfaces". Keys are
read from and written to `--key-dir` (default `xkms-data/keys`, global
persistent flag), under `<key-dir>/frost/public` and `<key-dir>/frost/secrets`
(see "Local storage and the FROST passphrase" below).
The CLI has no tenant: every key it writes is stored at its bare key ID, the
platform namespace the server keeps apart from every tenant's keys (see
[`architecture.md`](architecture.md) §"Tenancy").

## Local storage and the FROST passphrase

`frostStoreDirs` (`cmd/xkmsctl/frost.go:1305`) creates `<key-dir>` (when
absent), `<key-dir>/frost`, `<key-dir>/frost/public` and
`<key-dir>/frost/secrets` with mode `0700`, and re-modes the three FROST
directories to `0700` if they already exist.

- `<key-dir>/frost/public` holds the group public key, verification shares,
  metadata and each key's **sealed** secret share (AES-256-GCM under a key
  HKDF-derived from the wrapping key).
- `<key-dir>/frost/secrets` holds that Ed25519 wrapping key and, once
  `frost recipient` has run, the ECDSA P-256 recipient key that dealer
  packages are encrypted to. Both are **encrypted PKCS#8** (PBES2, PBKDF2 +
  AES-256-CBC) under the FROST passphrase. The PKCS#8 backend holding them
  runs with `AllowPlaintextKeys` false, so it refuses to write a key
  unencrypted.

Read access to `--key-dir` therefore yields neither a share nor the key that
seals it without the passphrase.

The verbs that use those keys — `keygen` in participant mode, `recipient`,
`import`, `round1`, `round2` — require the passphrase
(`openFrostLocalStore`, `frost.go:1363`). `list`, `info`, `delete`,
`aggregate` and `verify` touch only public material and never ask for it.
The passphrase is taken from exactly one source, in precedence order
(`cmd/xkmsctl/frost_passphrase.go:81`); it is never accepted as a flag value:

| Source | Notes |
|---|---|
| `--passphrase-stdin` | Reads all of standard input. |
| `--passphrase-file <path>` | Reads the file. Mutually exclusive with `--passphrase-stdin`. |
| `XKMS_FROST_PASSPHRASE` | Environment variable, used when neither flag is set. |

One trailing `\n` or `\r\n` is removed from stdin and file input. The first
share verb run against a fresh `--key-dir` generates the wrapping key under
the passphrase it is given; every later run must supply the same one.

| Error (`cmd/xkmsctl/errors.go`) | When |
|---|---|
| `ErrFrostPassphraseRequired` | No source supplied. xkmsctl has no local hardware backend for the wrapping key, so it refuses to run. |
| `ErrFrostPassphraseEmpty` | The chosen source is empty. |
| `ErrReadFrostPassphraseFailed` | Stdin or the file could not be read. |
| `ErrFrostPassphraseRejected` | The stored wrapping key or recipient key does not decrypt under the passphrase: wrong passphrase, a store written before #1324, or corruption. |
| `ErrFrostWrapBackendUnsupported` | `--backend` is anything but `software`. The local store cannot hold its wrapping key in a TPM or HSM, so it refuses instead of ignoring the flag. |

```bash
# First use: the passphrase creates the wrapping key
xkmsctl frost import --package ./alice_participant_1.json --passphrase-file ./frost.passphrase

# Later runs supply the same passphrase
printf '%s' "$FROST_PASSPHRASE" | xkmsctl frost round1 --key-id demo --output r1.json --passphrase-stdin
```

## `xkmsctl frost keygen`

Generate FROST key packages using the trusted-dealer model
(`cmd/xkmsctl/frost.go:167`).

| Flag | Default | Meaning |
|---|---|---|
| `-a, --algorithm` | `FROST-Ed25519-SHA512` | One of the five RFC 9591 ciphersuites — see [`engineering.md`](engineering.md). |
| `-t, --threshold` | `2` | Minimum signers (M). |
| `-n, --total` | `3` | Total participants (N). |
| `-p, --participants` | — | Comma-separated participant names; length must equal `--total` if given. |
| `--key-id` | auto (`frost-key-<unixnano>`) | Custom key identifier. |
| `--participant-id` | `0` | This participant's ID, `1..total`. `0` selects dealer mode. |
| `--export-dir` | — | Export every participant's package to this directory (dealer mode). |
| `--recipient` | — | Dealer mode: `<participant-id>=<public-key-file>`, the recipient key that participant's package is encrypted to. One per participant, repeatable or comma-separated. |
| `--passphrase-stdin` / `--passphrase-file` | — | FROST passphrase source; participant mode only (see above). |

Two modes, selected by the flags above:

- **Dealer mode** (`--participant-id 0` or `--export-dir` set) — generates
  all N packages and writes one JSON file per participant to `--export-dir`
  (`participant_<id>.json`, or `<name>_participant_<id>.json` when
  `--participants` is given), mode `0600` in a `0700` directory. Requires
  `--export-dir`; its absence is `ErrDealerModeExportDirRequired`. Each file
  is encrypted to its participant's recipient key (see
  [`frost recipient`](#xkmsctl-frost-recipient)), so dealer mode needs a
  `--recipient` for every participant and no passphrase. Every recipient key
  is read and checked before anything is generated.
- **Participant mode** (`--participant-id N`, `1 <= N <= total`) — generates
  the full dealer output in memory, keeps only participant N's package, and
  stores it locally via a `client.FrostBackend` under `--key-dir`. Requires
  the FROST passphrase.

| Error (`cmd/xkmsctl/errors.go`) | When |
|---|---|
| `*FrostRecipientMissingError` | Dealer mode has no `--recipient` for participant `ID`. |
| `ErrFrostRecipientSpecInvalid` | A `--recipient` is not `<id>=<file>`, or its ID is outside `1..--total`. |
| `ErrFrostRecipientDuplicate` | Two `--recipient` values name the same participant. |
| `ErrFrostRecipientReused` | Two participants are given the same public key. One holder would get two shares, lowering the number of people needed to sign. |
| `ErrFrostRecipientKeyInvalid` | The file is unreadable or is not a PEM ECDSA P-256 public key. |
| `ErrFrostRecipientParticipantMode` | `--recipient` given in participant mode, which exports nothing. |

```bash
# Dealer mode: generate all packages, each encrypted to its participant
xkmsctl frost keygen --key-id mykey --threshold 2 --total 3 --export-dir ./packages \
  --recipient 1=alice.pem --recipient 2=bob.pem --recipient 3=carol.pem

# Participant mode: generate and store locally (participant 1)
xkmsctl frost keygen --key-id mykey --threshold 2 --total 3 --participant-id 1 \
  --passphrase-file ./frost.passphrase
```

## `xkmsctl frost recipient`

Create, on first use, the recipient key that the dealer encrypts this
participant's package to, and print its public half (`frost.go:558`). The
private key is stored in `<key-dir>/frost/secrets` as encrypted PKCS#8
under the FROST passphrase and is used only by `import`. Running it again
prints the same key.

| Flag | Meaning |
|---|---|
| `--public-key-file` | Also write the public key, PEM (PKIX), to this file (mode `0644`). |
| `--passphrase-stdin` / `--passphrase-file` | FROST passphrase source (see above). |

The output carries `public_key` (PEM) and `recipient_id`, the RFC 7638
SHA-256 JWK thumbprint of the key. Read `recipient_id` to the dealer over a
channel other than the one that carried the file: a dealer given a
substituted key encrypts your share to whoever substituted it.

```bash
xkmsctl frost recipient --public-key-file alice.pem --passphrase-file ./frost.passphrase
```

## `xkmsctl frost import`

Import a key package file received from a dealer (`frost.go:426`). Decrypts
the package with this `--key-dir`'s recipient key and seals the share, so it
requires the FROST passphrase. Nothing is stored until the package has
decrypted.

| Flag | Meaning |
|---|---|
| `--package` | Path to the exported package JSON (required). |
| `--passphrase-stdin` / `--passphrase-file` | FROST passphrase source (see above). |

| Error (`cmd/xkmsctl/errors.go`) | When |
|---|---|
| `ErrFrostRecipientKeyMissing` | This `--key-dir` has no recipient key: `frost recipient` was never run here. |
| `ErrFrostPackageRecipientMismatch` | The package is encrypted to a different recipient key: another participant's package, or another `--key-dir`. |
| `ErrFrostPackageDecryptFailed` | The package names this recipient key but fails authenticated decryption: modified or corrupt. |
| `ErrFrostPackageNotEncrypted` | The file has no encrypted package, for example a plaintext export from an earlier build. The dealer must re-export it with `--recipient`. |
| `ErrFrostPassphraseRejected` | The recipient key does not decrypt under the passphrase. |

```bash
xkmsctl frost import --package ./alice_participant_1.json --passphrase-file ./frost.passphrase
```

## `xkmsctl frost list`

List FROST keys stored under `--key-dir` (`frost.go:634`).

| Flag | Default | Meaning |
|---|---|---|
| `-f, --format` | `table` | `table` or `json`. |

## `xkmsctl frost info <key-id>`

Show details for one key (`frost.go:691`). Reads only the public key
package and metadata; it never unseals the share.

| Flag | Default | Meaning |
|---|---|---|
| `-f, --format` | `table` | `table` or `json` (accepted but the handler always prints JSON). |
| `--show-public-key` | `false` | Include the hex-encoded group public key. |

## `xkmsctl frost delete <key-id>`

Delete a key and its local data (`frost.go:745`). Prompts for confirmation
unless `-f, --force` is set.

## `xkmsctl frost round1`

Generate this participant's nonces and commitments (`frost.go:812`).
Unseals the share, so it requires the FROST passphrase.

| Flag | Meaning |
|---|---|
| `-k, --key-id` | Key identifier (required). |
| `-o, --output` | Output file for the public commitment (required). The secret nonces are written alongside it at `<output>.nonces` (mode `0600`); the commitment file itself is `0644`. |
| `--passphrase-stdin` / `--passphrase-file` | FROST passphrase source (see above). |

## `xkmsctl frost round2`

Generate this participant's signature share (`frost.go:895`). Unseals the
share, so it requires the FROST passphrase.

| Flag | Meaning |
|---|---|
| `-k, --key-id` | Key identifier (required). |
| `--nonces` | This participant's `round1` nonce file (`.nonces` suffix appended if omitted) (required). |
| `-c, --commitments` | Comma-separated list of commitment files from every participating signer (required). |
| `-o, --output` | Output file for the signature share (required). |
| `-m, --message` / `--message-file` / `--message-hex` | The data being signed — see "Message input" below. |
| `--passphrase-stdin` / `--passphrase-file` | FROST passphrase source (see above). |

## `xkmsctl frost aggregate`

Combine signature shares into the final signature (`frost.go:1037`).

| Flag | Default | Meaning |
|---|---|---|
| `-k, --key-id` | — | Key identifier (required). |
| `-c, --commitments` | — | Comma-separated commitment files (required). |
| `--shares` | — | Comma-separated signature-share files (required). |
| `-o, --output` | — | Output file for the signature (required). |
| `--format` | `raw` | `raw`, `hex`, or `base64`. |
| `--verify` | `true` | Verify the aggregated signature before writing it. |
| `-m, --message` / `--message-file` / `--message-hex` | — | The signed data. |

## `xkmsctl frost verify`

Verify a signature against the stored group public key (`frost.go:1170`).

| Flag | Meaning |
|---|---|
| `-k, --key-id` | Key identifier. |
| `--signature` / `--signature-hex` | The signature, as a file (auto-detects hex/base64 encoding) or a hex string. |
| `-m, --message` / `--message-file` / `--message-hex` | The signed data. |

## Message input (`round2`, `aggregate`, `verify`)

`getMessage` (`frost.go:1244`) resolves the signed payload from exactly one
of:

- `-m, --message <string>` — used verbatim as bytes.
- `--message-file <path>` — the file's contents are **SHA-256 hashed**
  before use, not signed raw.
- `--message-hex <hex>` — decoded (accepts an optional `0x` prefix).

Supplying none is `ErrMessageInputRequired`.

## Worked M-of-3 example (single operator, illustrative)

```bash
# Each participant creates a recipient key in their own key-dir and sends
# the public key to the dealer; the verbs below read the passphrase from
# the environment
read -rs XKMS_FROST_PASSPHRASE && export XKMS_FROST_PASSPHRASE
xkmsctl frost recipient --public-key-file alice.pem

# Dealer generates three packages, each encrypted to its participant
xkmsctl frost keygen --key-id demo --threshold 2 --total 3 \
  --participants alice,bob,charlie --export-dir ./packages \
  --recipient 1=alice.pem --recipient 2=bob.pem --recipient 3=charlie.pem

# Each participant imports their own package into the same key-dir
xkmsctl frost import --package ./packages/alice_participant_1.json

# Two of the three run round1
xkmsctl frost round1 --key-id demo --output round1-alice.json
xkmsctl frost round1 --key-id demo --output round1-bob.json

# ...then round2, each with the full commitment set
xkmsctl frost round2 --key-id demo -m "hello frost" \
  --nonces round1-alice.json --commitments round1-alice.json,round1-bob.json \
  --output share-alice.json
xkmsctl frost round2 --key-id demo -m "hello frost" \
  --nonces round1-bob.json --commitments round1-alice.json,round1-bob.json \
  --output share-bob.json

# Anyone aggregates
xkmsctl frost aggregate --key-id demo -m "hello frost" \
  --commitments round1-alice.json,round1-bob.json \
  --shares share-alice.json,share-bob.json \
  --output sig.bin

xkmsctl frost verify --key-id demo -m "hello frost" --signature sig.bin
```
