# FROST Threshold Signing — User Guide

> **Status: NORMATIVE** · Feature: `frost-threshold-signing` · Repo: `go-xkms` · Last verified: 2026-09-24

## What this is for

FROST lets M of N people or systems jointly sign something without any one
of them ever holding the whole private key — not at setup, and not at
signing time. Use it when a single signing key would be too sensitive to
trust to one machine or one operator: a code-signing root, a treasury key,
a CA intermediate.

**This is a local, operator-run tool today.** Everything in this guide runs
on your own machine and stores key material under a local `--key-dir`. It
does not talk to a remote `xkms` server — see
[`architecture.md`](architecture.md) if you were expecting the network API
your `xkmsd` exposes to work out of the box; it currently has no supported
way to be turned on.

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
