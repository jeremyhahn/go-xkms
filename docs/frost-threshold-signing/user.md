# FROST Threshold Signing — User Guide

> **Status: NORMATIVE** · Feature: `frost-threshold-signing` · Repo: `go-xkms` · Last verified: 2026-09-29 (#1337)

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

One person (the "dealer") generates the key packages, and each package is
encrypted so that only its own participant can import it. This tool does not
distribute packages for you: you move the files yourself.

**1. Each participant creates a recipient key** on their own machine,
choosing a FROST passphrase that protects their keys there:

```bash
xkmsctl frost recipient --public-key-file alice.pem \
  --passphrase-file ~/.config/xkms/frost.passphrase
```

The first command run against a `--key-dir` sets its passphrase; `import`,
`round1` and `round2` need the same one later. Supply it with
`--passphrase-stdin`, `--passphrase-file` or the `XKMS_FROST_PASSPHRASE`
environment variable — never on the command line. The examples below assume
it is exported:

```bash
read -rs XKMS_FROST_PASSPHRASE && export XKMS_FROST_PASSPHRASE
```

Send `alice.pem` to the dealer. It is a public key, so the file is not
secret, but its integrity matters: read the printed `recipient_id` to the
dealer over a different channel, such as a call, so a key swapped in transit
is caught.

**2. The dealer generates the packages**, naming each participant's
recipient key:

```bash
xkmsctl frost keygen \
  --key-id treasury-key \
  --algorithm FROST-Ed25519-SHA512 \
  --threshold 2 --total 3 \
  --participants alice,bob,charlie \
  --export-dir ./treasury-packages \
  --recipient 1=alice.pem --recipient 2=bob.pem --recipient 3=charlie.pem
```

This writes three files: `alice_participant_1.json`,
`bob_participant_2.json`, `charlie_participant_3.json`. Each is encrypted to
one participant's recipient key: the files can travel over any channel, and
neither the dealer nor anyone else can read the share back out of them.

**3. Each participant imports their own file** into the `--key-dir` that
holds their recipient key:

```bash
xkmsctl frost import --package ./treasury-packages/alice_participant_1.json
```

Another participant's file is refused ("encrypted to a different recipient
key").

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
disk in the clear, and nothing on disk unlocks it without your FROST
passphrase:

- A dealer package on its way to you is encrypted to your recipient key
  (JWE, ECDH-ES with AES-256 key wrap and AES-256-GCM). The recipient key is
  kept under `--key-dir/frost/secrets` as encrypted PKCS#8 under your
  passphrase, and only its public half ever leaves your machine.

- Each share is sealed (AES-256-GCM, with a key derived via HKDF from a
  dedicated Ed25519 wrapping key) and stored with the key's public parts
  under `--key-dir/frost/public`.
- The wrapping key is stored under `--key-dir/frost/secrets` as encrypted
  PKCS#8, protected by your passphrase. xkmsctl refuses to write it
  unencrypted.
- Both directories are created readable by you only (`0700`).

Someone who copies your `--key-dir` still needs the passphrase to recover a
share, so choose a strong one and keep it off the command line. A wrong
passphrase is refused ("FROST passphrase rejected") and nothing is changed.
Forgetting it makes the stored shares unrecoverable; re-import your key
package under a new `--key-dir` if you still have it.

`xkmsctl` cannot keep the wrapping key in a TPM or HSM: it has no local
hardware backend, and `--backend` values other than `software` are refused
for `xkmsctl frost`. To hold shares behind hardware, run them through
`xkmsd` with `backends.frost.secret_backend` set to `tpm2`, `pkcs11` or a
cloud KMS, where the share is protected by TPM sealing or HSM/KMS envelope
encryption instead.

If you are embedding go-xkms directly in a Go program instead of using
`xkmsctl` — `xkms.AutoInitialize` with `BackendConfigs[xkms.BackendFROST]`,
rather than the CLI's own `openFrostShareBackend`
(`cmd/xkmsctl/frost.go:1398`), which xkmsctl uses instead and is unaffected
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
- **Upgrading from a build before #1324.** A `--key-dir` written by an older
  xkmsctl holds a plaintext wrapping key, which every share verb now rejects
  as "FROST passphrase rejected". Re-import your key package into a fresh
  `--key-dir` with a passphrase, then delete the old directory.
- **Packages exported before #1337 cannot be imported.** They carry the
  share in plaintext, and `import` refuses them ("key package is not
  encrypted to a recipient key"). Run `frost recipient`, and have the dealer
  generate a new key with `--recipient` for everyone. Delete the old
  plaintext files.
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
