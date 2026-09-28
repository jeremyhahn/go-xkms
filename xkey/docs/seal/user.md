# Seal & Auto-Unseal — User Guide

> **Status: NORMATIVE** · Feature: `seal` · Module: `go-xkms/xkey` · Last verified: 2026-09-28

## Set up the barrier

```bash
xkey barrier init                    # auto-detects TPM 2.0, else asks for a password
xkey barrier init --strategy tpm2    # force TPM hardware sealing
xkey barrier init --strategy software

# Or seal to a cloud KMS instead of local hardware:
xkey barrier init --strategy aws_kms --aws-region us-east-1
# ...or seal under a CMK you already manage, instead of a new one xkey creates:
xkey barrier init --strategy aws_kms --aws-region us-east-1 \
  --aws-key-id arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab
xkey barrier init --strategy gcp_kms --gcp-project-id my-project \
  --gcp-location us-east1 --gcp-key-ring xkey-barrier
xkey barrier init --strategy azure_kv --azure-vault-url https://my-vault.vault.azure.net/
xkey barrier init --strategy vault --vault-address https://vault.example.com:8200
```

Once initialized, every barrier-aware command (`xkey oath`, `xkey backup`,
`xkey fido2 --storage barrier`, the OIDC token store, `xkey extension
serve`) encrypts its data at rest automatically.

A cloud KMS strategy authenticates with the provider's own ambient
credentials by default (the AWS SDK's default credential chain, GCP
Application Default Credentials, Azure `DefaultAzureCredential`, or Vault's
`VAULT_TOKEN` environment variable) — nothing further to set up if the
machine already has those. `xkey barrier init` remembers the strategy's
connection settings (region, project, vault URL, etc.) in the config file,
so `xkey barrier unseal` and `xkey extension serve` need no flags to find
the same key again. This binary must have been built with the matching Go
build tag (`awskms`, `gcpkms`, `azurekv`, or `vault`) for the strategy to be
available at all; a build without it reports which tag is missing rather
than silently falling back to another strategy.

## Let an agent (or a headless daemon) unseal without a password

This is the point of TPM auto-unseal: a human sets it up once, and from
then on nothing — not a human, not an agent — needs to hold the barrier
password.

```bash
# One-time human setup, on a TPM 2.0 machine with the barrier already
# initialized with --strategy tpm2:
xkey policy create boot-policy --pcrs 0,2,4,7 --bank sha256
xkey policy set-auto-unseal boot-policy
```

From then on:

```bash
# An agent runs this instead of ever touching a password:
xkey barrier unseal --auto

# Headless daemons try the same thing automatically before falling back:
xkey extension serve --socket /run/xkey/xkey.sock
xkey fido2 --storage barrier
```

If the platform's measured boot state ever changes (a firmware or kernel
update), the policy no longer matches and auto-unseal stops working — see
"Recover from a PCR mismatch" below. It fails loudly (a logged warning
naming the mismatch, then falls back to whatever the command's normal
fallback is — a direct TPM unseal, or a password) rather than silently
degrading, so this is something an operator will notice, not something
that quietly stops protecting the barrier.

For the agent-facing version of this guidance — including which commands
are safe to run unattended and which are human-only — see the
[xkey-agent skill](../../skills/xkey-agent/SKILL.md).

## Unseal manually

```bash
xkey barrier unseal                              # interactive password prompt
echo "$BARRIER_PASSWORD" | xkey barrier unseal   # piped, for scripts
xkey barrier unseal --auto                       # TPM policy only, no password ever
```

A barrier sealed with a cloud KMS strategy needs no password at all —
`xkey barrier unseal` (and `xkey extension serve`) rebuild the strategy from
the connection settings `xkey barrier init` persisted and authenticate with
the same ambient (or configured) credentials.

## Recover from a PCR mismatch

After a firmware, BIOS, or kernel update, the platform's PCR values change
and a previously-working auto-unseal policy stops matching:

```bash
xkey policy verify boot-policy
# Policy 'boot-policy': MISMATCH - 1 PCR(s) differ
#   PCR[ 7]:
#     Expected: ...
#     Current:  ...
```

If the new boot state is trusted (you made the update deliberately), re-capture it:

```bash
xkey policy refresh boot-policy
```

If it isn't trusted, leave the policy as-is: auto-unseal will keep refusing
until someone investigates, which is the intended fail-safe behavior.

## Check barrier status

```bash
xkey barrier status              # daemon's view if one is running, else on-disk (sealed)
xkey barrier status --json | jq .sealed
xkey barrier status --source disk   # inspect on-disk state even while a daemon runs
```

## Manage policies

```bash
xkey policy list                 # all saved policies, with an [auto-unseal] tag
xkey policy get boot-policy       # full detail, hex PCR digests
xkey policy export boot-policy    # JSON to stdout
xkey policy clear-auto-unseal     # stop auto-unsealing; the barrier falls back to a password
xkey policy delete old-policy     # refused if old-policy is the current auto-unseal designation
```

## GUI: PCR-bound LUKS volume auto-unseal

The desktop GUI has a separate, older auto-unseal path for a LUKS-encrypted
storage volume (as opposed to the barrier above): the first-run setup
wizard can seal the LUKS passphrase to the TPM, optionally bound to a
platform policy captured during setup, so the volume unlocks automatically
at GUI startup. This is configured entirely through the setup wizard, not
the CLI — see [setup-wizard/](../setup-wizard/) for that flow. It is
unrelated to the barrier auto-unseal above: a LUKS volume (if you chose
LUKS storage) is unlocked first, and the barrier that lives on top of it is
unlocked independently, by the mechanism this document describes.
