# FROST CLI Documentation

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: a flag-level summary of `xkmsctl frost`; the normative reference is [`docs/frost-threshold-signing/cli.md`](../../../../docs/frost-threshold-signing/cli.md).

> **Scope:** this page documents the go-xkms **server** CLI `xkmsctl frost`
> (source: `cmd/xkmsctl/`), **not** the `xkey` desktop CLI. It lives under
> `xkey/docs/` for historical reasons.
> There is no `xkey` equivalent. For the xkey command tree see
> [the xkey CLI reference](README.md).

## Overview

FROST (Flexible Round-Optimized Schnorr Threshold) signing lets M of N
participants produce one Schnorr signature without reconstructing the private
key. Signing has two rounds and an aggregation step:

1. **Round 1** (`frost round1`): each signer writes a public commitment and a
   secret `.nonces` file next to it.
2. **Round 2** (`frost round2`): each signer combines the collected commitments
   with its own nonces into a signature share.
3. **Aggregation** (`frost aggregate`): the shares become one signature.

The protocol, the security model and worked M-of-N sessions are in the
[FROST feature folder](../../../../docs/frost-threshold-signing/).

## Build Requirements

`xkmsctl frost` exists only in binaries built with the `frost` tag. The
Makefile sets it by default (`WITH_FROST ?= 1`, root `Makefile:42`):

```bash
make build                          # includes FROST
go build -tags frost ./cmd/xkmsctl  # direct build
```

## Supported Algorithms

From `xkmsctl frost --help` (`cmd/xkmsctl/frost.go:137`):

| Algorithm | Note |
|-----------|------|
| `FROST-Ed25519-SHA512` | Default, recommended |
| `FROST-ristretto255-SHA512` | |
| `FROST-Ed448-SHAKE256` | |
| `FROST-P256-SHA256` | FIPS compliant |
| `FROST-secp256k1-SHA256` | Blockchain compatible |

## The FROST passphrase

`keygen` in participant mode, `recipient`, `import`, `round1` and `round2`
seal or unseal this participant's secret material in `<key-dir>/frost/secrets`
and need the FROST passphrase. Supply it, in precedence order, with
`--passphrase-stdin`, `--passphrase-file <path>` or the
`XKMS_FROST_PASSPHRASE` environment variable. One trailing newline is removed
from stdin and file input. Dealer-mode `keygen` needs no passphrase.

## Command Reference

### frost recipient

Creates (on first use) and prints the public half of this participant's
recipient key, the key the dealer encrypts this participant's package to.
Running it again prints the same key. Confirm the printed `recipient_id` with
the dealer over a separate channel.

| Flag | Description |
|------|-------------|
| `--public-key-file` | Also write the recipient public key (PEM) to this file |

```bash
xkmsctl frost recipient --public-key-file alice.pem --passphrase-file ./frost.passphrase
```

### frost keygen

Generates key packages with the trusted-dealer model.

- **Dealer mode** (`--export-dir` set, or `--participant-id 0`): generates
  every participant's package and writes each one to a file encrypted to that
  participant's recipient key, named by one `--recipient` per participant.
- **Participant mode** (`--participant-id N`): generates and stores only this
  participant's package locally.

| Flag | Default | Description |
|------|---------|-------------|
| `-a`, `--algorithm` | `FROST-Ed25519-SHA512` | Ciphersuite |
| `-t`, `--threshold` | `2` | Minimum signers required (M) |
| `-n`, `--total` | `3` | Total participants (N) |
| `-p`, `--participants` | | Comma-separated participant names |
| `--key-id` | auto-generated | Key identifier |
| `--participant-id` | `0` | This participant's ID (1 to total); 0 = dealer mode |
| `--export-dir` | | Directory to export all packages to (dealer mode) |
| `--recipient` | | Dealer mode: `<participant-id>=<public-key-file>`; repeatable, one per participant |

```bash
# Dealer mode: each package encrypted to its participant's recipient key
xkmsctl frost keygen --key-id corp-signing-key --threshold 2 --total 3 \
  --export-dir ./packages \
  --recipient 1=alice.pem --recipient 2=bob.pem --recipient 3=carol.pem

# Participant mode
xkmsctl frost keygen --key-id corp-signing-key --threshold 2 --total 3 \
  --participant-id 1 --passphrase-file ./frost.passphrase
```

### frost import

Imports a package received from the dealer. The package must be encrypted to
this `--key-dir`'s recipient key; a package encrypted to another participant's
key, or not encrypted at all, is refused.

| Flag | Description |
|------|-------------|
| `--package` | Path to the key package file (required) |

```bash
xkmsctl frost import --package ./alice_participant_1.json --passphrase-stdin < frost.passphrase
```

### frost list

Lists the FROST keys in this key directory.

| Flag | Default | Description |
|------|---------|-------------|
| `-f`, `--format` | `table` | Output format: `table` or `json` |

### frost info

```bash
xkmsctl frost info <key-id> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-f`, `--format` | `table` | Output format: `table` or `json` |
| `--show-public-key` | `false` | Display the group public key |

### frost delete

```bash
xkmsctl frost delete <key-id> [--force]
```

`-f`, `--force` skips the confirmation prompt.

### frost round1

Generates nonces and commitments. The commitment goes to `--output`; the
secret nonces go to the same path with a `.nonces` suffix
(`cmd/xkmsctl/frost.go:870`). Never share or reuse the `.nonces` file.

| Flag | Description |
|------|-------------|
| `-k`, `--key-id` | Key identifier (required) |
| `-o`, `--output` | Output file for the commitment (required) |

### frost round2

Generates this participant's signature share.

| Flag | Description |
|------|-------------|
| `-k`, `--key-id` | Key identifier (required) |
| `-c`, `--commitments` | Comma-separated commitment files from every signer (required) |
| `--nonces` | This participant's nonce file from round 1 (required) |
| `-m`, `--message` / `--message-file` / `--message-hex` | The message to sign, given one way |
| `-o`, `--output` | Output file for the signature share (required) |

### frost aggregate

Combines the signature shares into the final signature.

| Flag | Default | Description |
|------|---------|-------------|
| `-k`, `--key-id` | | Key identifier (required) |
| `-c`, `--commitments` | | Comma-separated commitment files (required) |
| `--shares` | | Comma-separated signature share files (required) |
| `-m`, `--message` / `--message-file` / `--message-hex` | | The message that was signed |
| `-o`, `--output` | | Output file for the signature (required) |
| `--format` | `raw` | Signature format: `raw`, `hex` or `base64` |
| `--verify` | `true` | Verify the signature after aggregation |

### frost verify

Verifies a signature against the group public key.

| Flag | Description |
|------|-------------|
| `-k`, `--key-id` | Key identifier |
| `-m`, `--message` / `--message-file` / `--message-hex` | The original message |
| `--signature` / `--signature-hex` | The signature, as a file or a hex string |

## Example: one 2-of-3 signing session

```bash
# Alice and Bob each run round 1
xkmsctl frost round1 -k corp-signing-key -o alice.commit --passphrase-file ./frost.passphrase
xkmsctl frost round1 -k corp-signing-key -o bob.commit --passphrase-file ./frost.passphrase

# After exchanging commitments, each runs round 2 with its own nonces
xkmsctl frost round2 -k corp-signing-key -c alice.commit,bob.commit \
  --nonces alice.commit.nonces -m "release v1.0" -o alice.share \
  --passphrase-file ./frost.passphrase

# Any one party aggregates
xkmsctl frost aggregate -k corp-signing-key -c alice.commit,bob.commit \
  --shares alice.share,bob.share -m "release v1.0" -o release.sig
```

## See Also

- [FROST threshold signing](../../../../docs/frost-threshold-signing/) — the normative feature folder
