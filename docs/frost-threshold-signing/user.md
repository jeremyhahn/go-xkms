# FROST Threshold Signing — User Guide

> **Status: NORMATIVE** · Feature: `frost-threshold-signing` · Repo: `go-xkms` · Last verified: 2026-09-28 (#1231)

## What this is for

FROST lets M of N people or systems jointly sign something without any one
of them ever holding the whole private key — not at setup, and not at
signing time. Use it when a single signing key would be too sensitive to
trust to one machine or one operator: a code-signing root, a treasury key,
a CA intermediate.

**This guide covers the local, operator-run tool.** Everything in it runs
on your own machine and stores key material under a local `--key-dir`. It
does not talk to a remote `xkms` server. The network API (REST, gRPC, MCP)
answers only when `xkmsd` has `backends.frost.enabled` set — see
[`architecture.md`](architecture.md).

**On a server, FROST keys belong to your tenant.** Keys you generate or
import over the network API are stored in your tenant, and every call that
names a key looks for it only there. Other tenants cannot list, read, delete
or sign with your key shares, and you cannot see theirs: naming another
tenant's key gets the same "not found" as naming a key that does not exist.
Two tenants may each use the same key ID.

## Prerequisites

A build with FROST support:

```bash
go build -tags frost ./cmd/xkmsctl
```

(`make build` alone does not include it — see [`cli.md`](cli.md).)

## Setting up a 2-of-3 group

One person (the "dealer") generates and distributes the key packages. This
example keeps everything on one machine for illustration; in practice each
package would be handed to its participant over a channel you trust (out of
band — this tool does not distribute packages for you).

```bash
xkmsctl frost keygen \
  --key-id treasury-key \
  --algorithm FROST-Ed25519-SHA512 \
  --threshold 2 --total 3 \
  --participants alice,bob,charlie \
  --export-dir ./treasury-packages
```

This writes three files: `alice_participant_1.json`,
`bob_participant_2.json`, `charlie_participant_3.json`. Each participant
imports **only their own file**, on their own machine:

```bash
xkmsctl frost import --package ./treasury-packages/alice_participant_1.json
```

The dealer's own copy of the packages should be deleted once every
participant has imported theirs — the dealer briefly held the whole key
during generation (trusted-dealer mode, by design; a future distributed
key-generation mode would avoid even that moment, but none ships today).

## Signing (2 of the 3 participate)

Signing is two rounds. Every participant who is signing runs round 1
independently:

```bash
# alice
xkmsctl frost round1 --key-id treasury-key --output r1-alice.json
# bob
xkmsctl frost round1 --key-id treasury-key --output r1-bob.json
```

Each produces two files: `r1-alice.json` (the public commitment — share
this) and `r1-alice.json.nonces` (secret — never share this, never reuse it
for a different message).

Collect every signer's commitment file, then each signer runs round 2 with
the **same** commitment set and message:

```bash
# alice
xkmsctl frost round2 --key-id treasury-key -m "release v1.2.3" \
  --nonces r1-alice.json --commitments r1-alice.json,r1-bob.json \
  --output share-alice.json
# bob
xkmsctl frost round2 --key-id treasury-key -m "release v1.2.3" \
  --nonces r1-bob.json --commitments r1-alice.json,r1-bob.json \
  --output share-bob.json
```

Anyone (not necessarily a signer) aggregates the shares into the final
signature and verifies it:

```bash
xkmsctl frost aggregate --key-id treasury-key -m "release v1.2.3" \
  --commitments r1-alice.json,r1-bob.json \
  --shares share-alice.json,share-bob.json \
  --output signature.bin

xkmsctl frost verify --key-id treasury-key -m "release v1.2.3" --signature signature.bin
```

## Signing a file instead of a short string

`--message-file` hashes the file with SHA-256 before signing — you are
signing the digest, not the raw bytes:

```bash
xkmsctl frost round2 --key-id treasury-key --message-file release.tar.gz \
  --nonces r1-alice.json --commitments r1-alice.json,r1-bob.json \
  --output share-alice.json
```

Every participant in the same signing session must use `--message-file` on
the same bytes (or `--message-hex` on the same digest) — a mismatch produces
a share that will not aggregate into a valid signature.

## Managing keys

```bash
xkmsctl frost list                                  # table of keys under --key-dir
xkmsctl frost list --format json
xkmsctl frost info treasury-key --show-public-key    # group public key, this participant's ID
xkmsctl frost delete treasury-key                    # prompts unless --force
```

## How your secret share is protected at rest

`xkmsctl frost keygen`/`import` never write a participant's secret share to
disk in the clear. Under `--key-dir/frost/secrets`, xkmsctl runs a real
software key-storage backend (the same one `xkmsd` uses for local software
keys) and provisions a dedicated Ed25519 wrapping key on it the first time
it runs; every secret share is then sealed under that key (AES-256-GCM,
derived via HKDF) before it touches disk, and the public components under
`--key-dir/frost/public` — group public key, verification shares, and each
key's sealed secret-share envelope — never carry the share in recoverable
form on their own. This is the same protection `xkmsd` applies when
`backends.frost.secret_backend` names `tpm2`, `pkcs11`, or a cloud KMS: the
mechanism differs by backend (TPM PCR-bound sealing, HSM/KMS envelope
encryption, or the software HKDF+AES-GCM path this CLI uses), but every
`secret_backend` protects the share the same way — none stores it verbatim.

If you are embedding go-xkms directly in a Go program instead of using
`xkmsctl` — `xkms.AutoInitialize` with `BackendConfigs[xkms.BackendFROST]`,
rather than the CLI's own `createFrostBackend`
(`cmd/xkmsctl/frost.go:1146`), which xkmsctl uses instead and is unaffected
— the same fail-closed rule applies one level lower: its internal `pkcs8`
secret store refuses to persist the wrapping key at all unless you set
`"allow_plaintext_keys": true` in that backend's config
(`pkg/xkms/register_frost.go:53`), and you accept that this in-memory,
per-process store has no other encryption-at-rest layer underneath it (see
[`engineering.md`](engineering.md)'s "Daemon backend registration" section).
There is no way to make it silently store the wrapping key in the clear —
go-xkms#1237.

## Things that will surprise you

- **Never reuse a `round1` nonce file.** FROST nonce reuse is catastrophic —
  it can recover the private key. Run `round1` fresh for every signing
  attempt, including retries after a failed `round2`.
- **`--key-dir` is per-identity, not per-group.** If you run both `keygen`
  (dealer) and `import` (participant) commands with the default `--key-dir`,
  you will overwrite your own participant data with the dealer's export
  directory contents unless you separate them (`--key-dir` per role, or run
  each role on a different machine as intended).
- **There is no server-backed FROST today.** Do not point `--server` /
  `--transport` at anything for `xkmsctl frost` — it is ignored. If your
  workflow needs a daemon to hold shares centrally, that is unstarted work;
  see [`architecture.md`](architecture.md).
- **A crypto.Signer only works at threshold 1.** If you need a drop-in
  `crypto.Signer` for existing tooling and are willing to accept a single
  point of trust, set `--threshold 1`; anything higher requires the explicit
  round workflow above.
