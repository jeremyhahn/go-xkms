# FROST Threshold Signing — CLI

> **Status: NORMATIVE** · Feature: `frost-threshold-signing` · Repo: `go-xkms` · Last verified: 2026-09-24

`xkmsctl frost` requires a binary built with `-tags frost`
(`go build -tags frost ./cmd/xkmsctl`); without the tag, every subcommand
prints `Error: FROST support not compiled in` and exits 1
(`cmd/xkmsctl/frost_stub.go`).

**Every `xkmsctl frost` subcommand runs entirely on the operator's own
machine.** The global `--server` / `--transport` flags that every other
`xkmsctl` command group honors have no effect here — see
[`architecture.md`](architecture.md) §"Two independent surfaces". Keys are
read from and written to `--key-dir` (default `xkms-data/keys`, global
persistent flag), under `<key-dir>/frost/public` and `<key-dir>/frost/secrets`.

## `xkmsctl frost keygen`

Generate FROST key packages using the trusted-dealer model
(`cmd/xkmsctl/frost.go:147`).

| Flag | Default | Meaning |
|---|---|---|
| `-a, --algorithm` | `FROST-Ed25519-SHA512` | One of the five RFC 9591 ciphersuites — see [`engineering.md`](engineering.md). |
| `-t, --threshold` | `2` | Minimum signers (M). |
| `-n, --total` | `3` | Total participants (N). |
| `-p, --participants` | — | Comma-separated participant names; length must equal `--total` if given. |
| `--key-id` | auto (`frost-key-<unixnano>`) | Custom key identifier. |
| `--participant-id` | `0` | This participant's ID, `1..total`. `0` selects dealer mode. |
| `--export-dir` | — | Export every participant's package to this directory (dealer mode). |

Two modes, selected by the flags above:

- **Dealer mode** (`--participant-id 0` or `--export-dir` set) — generates
  all N packages and writes one JSON file per participant to `--export-dir`
  (`participant_<id>.json`, or `<name>_participant_<id>.json` when
  `--participants` is given). Requires `--export-dir`; its absence is
  `ErrDealerModeExportDirRequired`.
- **Participant mode** (`--participant-id N`, `1 <= N <= total`) — generates
  the full dealer output in memory, keeps only participant N's package, and
  stores it locally via a `client.FrostBackend` under `--key-dir`.

```bash
# Dealer mode: generate and export all packages
xkmsctl frost keygen --key-id mykey --threshold 2 --total 3 --export-dir ./packages

# Participant mode: generate and store locally (participant 1)
xkmsctl frost keygen --key-id mykey --threshold 2 --total 3 --participant-id 1
```

## `xkmsctl frost import`

Import a key package file received from a dealer (`frost.go:364`).

| Flag | Meaning |
|---|---|
| `--package` | Path to the exported package JSON (required). |

```bash
xkmsctl frost import --package ./alice_participant_1.json
```

## `xkmsctl frost list`

List FROST keys stored under `--key-dir` (`frost.go:496`).

| Flag | Default | Meaning |
|---|---|---|
| `-f, --format` | `table` | `table` or `json`. |

## `xkmsctl frost info <key-id>`

Show details for one key (`frost.go:548`).

| Flag | Default | Meaning |
|---|---|---|
| `-f, --format` | `table` | `table` or `json` (accepted but the handler always prints JSON). |
| `--show-public-key` | `false` | Include the hex-encoded group public key. |

## `xkmsctl frost delete <key-id>`

Delete a key and its local data (`frost.go:597`). Prompts for confirmation
unless `-f, --force` is set.

## `xkmsctl frost round1`

Generate this participant's nonces and commitments (`frost.go:657`).

| Flag | Meaning |
|---|---|
| `-k, --key-id` | Key identifier (required). |
| `-o, --output` | Output file for the public commitment (required). The secret nonces are written alongside it at `<output>.nonces` (mode `0600`); the commitment file itself is `0644`. |

## `xkmsctl frost round2`

Generate this participant's signature share (`frost.go:733`).

| Flag | Meaning |
|---|---|
| `-k, --key-id` | Key identifier (required). |
| `--nonces` | This participant's `round1` nonce file (`.nonces` suffix appended if omitted) (required). |
| `-c, --commitments` | Comma-separated list of commitment files from every participating signer (required). |
| `-o, --output` | Output file for the signature share (required). |
| `-m, --message` / `--message-file` / `--message-hex` | The data being signed — see "Message input" below. |

## `xkmsctl frost aggregate`

Combine signature shares into the final signature (`frost.go:868`).

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

Verify a signature against the stored group public key (`frost.go:996`).

| Flag | Meaning |
|---|---|
| `-k, --key-id` | Key identifier. |
| `--signature` / `--signature-hex` | The signature, as a file (auto-detects hex/base64 encoding) or a hex string. |
| `-m, --message` / `--message-file` / `--message-hex` | The signed data. |

## Message input (`round2`, `aggregate`, `verify`)

`getMessage` (`frost.go:1064`) resolves the signed payload from exactly one
of:

- `-m, --message <string>` — used verbatim as bytes.
- `--message-file <path>` — the file's contents are **SHA-256 hashed**
  before use, not signed raw.
- `--message-hex <hex>` — decoded (accepts an optional `0x` prefix).

Supplying none is `ErrMessageInputRequired`.

## Worked M-of-3 example (single operator, illustrative)

```bash
# Dealer generates and exports three packages
xkmsctl frost keygen --key-id demo --threshold 2 --total 3 \
  --participants alice,bob,charlie --export-dir ./packages

# Each participant imports their own package (run once per identity/key-dir)
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
