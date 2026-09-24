# Seal & Auto-Unseal — CLI

> **Status: NORMATIVE** · Feature: `seal` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

Every flag below is verified against `xkey <group> <verb> --help` built from
this checkout. See [architecture.md](architecture.md) for the auto-unseal
decision order these commands drive.

## `xkey barrier`

Persistent flags on the whole group: `--data-dir string` (default
`~/.xkey/data`), `--tpm-device string` (default `$TPM_DEVICE_PATH` or
`/dev/tpmrm0`), `--tpm-simulator` (in-process simulator, requires a
`-tags tpm_simulator` build; development/testing only).

### `xkey barrier init [flags]`

First-time setup: generates a root key and seals it.

| Flag | Default | Meaning |
|---|---|---|
| `--strategy string` | auto-detect (tpm2 if available, else software) | `software`, `tpm2`, `pkcs11`, `aws_kms`, `gcp_kms`, `azure_kv`, or `vault` |
| `--aws-region string` | none | AWS region for `--strategy aws_kms` |
| `--aws-endpoint string` | AWS default | Custom AWS KMS endpoint (testing only) |
| `--gcp-project-id string` | none | GCP project ID for `--strategy gcp_kms` |
| `--gcp-location string` | none | GCP KMS location (e.g. `us-east1`) |
| `--gcp-key-ring string` | none | GCP KMS key ring ID |
| `--gcp-credentials-file string` | Application Default Credentials | Path to a service account JSON key file |
| `--azure-vault-url string` | none | Azure Key Vault URL for `--strategy azure_kv` |
| `--azure-allow-local-vault-url` | `false` | Allow a localhost/127.0.0.1 vault URL (development only) |
| `--vault-address string` | none | HashiCorp Vault server address for `--strategy vault` |
| `--vault-mount-path string` | `transit` | Vault Transit engine mount path |

The four cloud KMS strategies need no PIN, HSM slot, or pre-provisioned key
identifier: the seal key is resolved (or created on first use) automatically
under a fixed name, the same one `xkmsd` uses, through the ONE composition
path both share (`sdk/go.BuildCloudKMSStrategy`, go-xkms#757). Only the
connection settings above are asked for. A credential is never a flag or any
other literal: leave the credential fields unset for ambient credentials —
the AWS SDK default chain, GCP Application Default Credentials, Azure
`DefaultAzureCredential`, or Vault's `VAULT_TOKEN` environment variable,
depending on the strategy — or set an explicit `*SecretValue` reference by
hand in the config file (`~/.config/xkey/xkey.yaml`, under
`barrier.cloud_kms.<provider>`). `xkey barrier init` persists the
non-secret connection settings there too, so a later `xkey barrier unseal`
or `xkey extension serve` needs no flags to rebuild the same strategy. A
binary built without the matching Go build tag (`awskms`, `gcpkms`,
`azurekv`, `vault`) reports a typed error naming the tag rather than
silently falling back to another strategy.

### `xkey barrier unseal [flags]`

Decrypts the root key and derives the DEK. Accepts a piped password on
stdin — it is not an interactive-only command:

```bash
echo "$BARRIER_PASSWORD" | xkey barrier unseal
```

| Flag | Default | Meaning |
|---|---|---|
| `--auto` | `false` | Unseal via the designated TPM PCR auto-unseal policy only. **Never prompts for or reads a password.** Fails with a typed error if no policy is set, the barrier's strategy isn't `tpm2`, or the current PCRs don't match. |

### `xkey barrier seal`

Zeroes the DEK. Idempotent.

### `xkey barrier status [flags]`

| Flag | Default | Meaning |
|---|---|---|
| `--json` | `false` | Output as JSON |
| `--socket string` | auto-detect | IPC socket of a running daemon |
| `--source string` | `auto` | `auto`, `daemon`, or `disk` — the running daemon owns the barrier, so its state is read over IPC when one is running; with none running, only the on-disk (necessarily sealed) state is available |

## `xkey policy`

PCR policy management. Persistent flags: `--store string` (default
`<data dir>/pcr_policies` — the same location the GUI uses, see
architecture.md), `--tpm-device string`, `--tpm-simulator` (same meaning as
`barrier`'s).

| Verb | Usage | Notes |
|---|---|---|
| `create` | `xkey policy create <name> --pcrs 0,2,4,7 [--bank sha256\|sha1\|sha384]` | Reads current PCR values from the TPM and saves them under `<name>` |
| `list` | `xkey policy list [--page N] [--page-size N]` | `ls` alias; unpaginated by default |
| `get` | `xkey policy get <name>` | Full detail, including hex PCR digests |
| `delete` | `xkey policy delete <name>` | `rm`/`remove` aliases; refuses on the currently-designated auto-unseal policy |
| `set-auto-unseal` | `xkey policy set-auto-unseal <name>` | Designates `<name>` for headless/GUI auto-unseal; replaces any previous designation |
| `clear-auto-unseal` | `xkey policy clear-auto-unseal` | Removes the designation; no barrier auto-unseals afterward |
| `refresh` | `xkey policy refresh <name>` | Re-reads current PCR values into an existing policy (e.g. after a firmware/kernel update) |
| `verify` | `xkey policy verify <name>` | Compares current PCRs against the saved policy; non-zero exit and a diff on mismatch |
| `export` | `xkey policy export <name>` | JSON to stdout, hex-encoded PCR values |

## Headless daemons that auto-unseal

`xkey extension serve` and `xkey fido2`/`fido2 start` (with `--storage
barrier`) both accept the barrier flags below. For a `tpm2`-strategy
barrier they try policy auto-unseal first, then a direct TPM unseal. For a
cloud KMS strategy (`aws_kms`, `gcp_kms`, `azure_kv`, `vault`) they rebuild
the backend from the connection settings `xkey barrier init` persisted to
the config file and unseal with it — no password. For `software` they need
a password. `pkcs11` and `shamir` are refused with a typed error naming the
interactive alternative: PKCS#11 needs a token PIN a headless process has
no source for yet, and Shamir needs an operator quorum no headless process
can collect.

| Flag | Commands | Meaning |
|---|---|---|
| `--barrier-password-file string` | `extension serve`, `fido2` | First line of the named file — prefer this over `--barrier-password` |
| `--barrier-password string` | `extension serve`, `fido2` | Plaintext on the command line; visible via `ps` |
| `--tpm-device string`, `--tpm-simulator` | `extension serve` (also `barrier`, `policy`) | Same TPM selection as `barrier` |
| `--no-barrier` | `extension serve` | Skip the barrier entirely, plain file storage (testing only) |

`XKEY_BARRIER_PASSWORD` is honored by both when no password flag is set.

## TPM device resolution

Shared by `barrier`, `policy`, and `extension serve` (`resolveTPMDevice`):

1. `--tpm-device` / `--tpm-simulator` flags
2. `TPM_DEVICE_PATH` environment variable
3. `/dev/tpmrm0` (default)

## Data directory resolution

Shared by every command that persists barrier, policy, or PIN state
(`resolveDataDir`):

1. The command's own `--data-dir` flag
2. `XKEY_DATA_DIR` environment variable
3. `data_dir` config key
4. `XKEY_HOME`-relative (or default `~/.xkey/`) `data/` subdirectory

## `barrier status` fields

| Field | Description |
|---|---|
| `initialized` | Whether the barrier has a root key on disk |
| `sealed` | Whether the barrier is currently sealed |
| `strategy` | Which sealing strategy protects the root key (`software`, `tpm2`, `pkcs11`, `aws_kms`, `gcp_kms`, `azure_kv`, `vault`) |
| `hardware_backed` | Whether the strategy uses dedicated cryptographic hardware |
| `data_dir` | Path to the data directory |
| `root_key_path` | Full path to the sealed root key blob |

## Examples

```bash
# First-time setup with TPM hardware sealing
xkey barrier init --strategy tpm2

# A human captures the current boot state and designates it for auto-unseal
xkey policy create boot-policy --pcrs 0,2,4,7 --bank sha256
xkey policy set-auto-unseal boot-policy

# From then on, an agent's unseal needs no password
xkey barrier unseal --auto

# ...and neither does a headless daemon
xkey extension serve --socket /run/xkey/xkey.sock

# After a firmware/kernel update changes the measured boot state
xkey policy verify boot-policy   # reports the mismatch, non-zero exit
xkey policy refresh boot-policy  # re-captures current PCRs
```
