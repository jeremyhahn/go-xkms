# Seal & Auto-Unseal — CLI

> **Status: NORMATIVE** · Feature: `seal` · Module: `go-xkms/xkey` · Last verified: 2026-10-07

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
| `--aws-key-id string` | none | Existing AWS KMS key ID, ARN, alias, or alias ARN to seal under instead of provisioning a CMK (go-xkms#842) |
| `--gcp-project-id string` | none | GCP project ID for `--strategy gcp_kms` |
| `--gcp-location string` | none | GCP KMS location (e.g. `us-east1`) |
| `--gcp-key-ring string` | none | GCP KMS key ring ID |
| `--gcp-credentials-file string` | Application Default Credentials | Path to a service account JSON key file |
| `--azure-vault-url string` | none | Azure Key Vault URL for `--strategy azure_kv` |
| `--azure-allow-local-vault-url` | `false` | Allow a localhost/127.0.0.1 vault URL (development only) |
| `--vault-address string` | none | HashiCorp Vault server address for `--strategy vault` |
| `--vault-mount-path string` | `transit` | Vault Transit engine mount path |
| `--pkcs11-library string` | none | PKCS#11 module path for `--strategy pkcs11` |
| `--pkcs11-token string` | none | PKCS#11 token label for `--strategy pkcs11` |

`--strategy pkcs11` saves the module and token label to the config file
(`barrier.pkcs11`), then reads the token user PIN and seals it under
this host's Platform SRK and the platform PCR policy (go-xkms#677). The PIN
is prompted for on a terminal, or read from the first line of piped
standard input, before the barrier password. It is never a flag and never
written to the config. Every later unseal releases the PIN from the TPM and
logs in to the token without asking again. The TPM must have the Platform SRK
enrolled (`xkey setup`). If the platform PCRs change, the PIN is no longer
released, and `barrier init` has to be run again on a fresh data directory.

The four cloud KMS strategies need no PIN or HSM slot, and no pre-provisioned
key identifier is required: left unset, the seal key is resolved (or created
on first use) automatically under a fixed name, the same one `xkmsd` uses,
through the ONE composition path both share (`sdk/go.BuildCloudKMSStrategy`,
go-xkms#757). `aws_kms` is the one strategy that also accepts an
operator-supplied identifier (`--aws-key-id`, go-xkms#842): set it to seal
under an existing CMK instead. A malformed value is rejected with a typed
error when the strategy is built; a well-formed one that names no key AWS
KMS actually has fails the same way, rather than silently provisioning an
unrelated CMK in its place. Otherwise, only the connection settings above are
asked for. A credential is never a flag or any other literal: leave the
credential fields unset for ambient credentials —
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
| `--auto` | `false` | Unseal with the password the TPM releases under the auto-unseal policy only (any strategy that takes a password). **Never prompts for or reads a password.** Fails with a typed error if no policy carries the auto-unseal mark, or the TPM refuses the policy (the PCRs changed, or the policy was revoked). |

### `xkey barrier seal`

Zeroes the DEK. Idempotent.

### `xkey barrier status [flags]`

| Flag | Default | Meaning |
|---|---|---|
| `--json` | `false` | Output as JSON |
| `--socket string` | auto-detect | IPC socket of a running daemon |
| `--source string` | `auto` | `auto`, `daemon`, or `disk` — the running daemon owns the barrier, so its state is read over IPC when one is running; with none running, only the on-disk (necessarily sealed) state is available |

## `xkey tpm policy auto-unseal`

The named TPM policies themselves are managed with `xkey tpm policy`,
documented in [docs/tpm-policies/cli.md](../../../docs/tpm-policies/cli.md).
The verb that belongs to this feature is `auto-unseal`:

| Usage | Notes |
|---|---|
| `xkey tpm policy auto-unseal <name>` | Makes `<name>` the auto-unseal policy and seals the barrier password (read from the terminal, or from stdin when piped) in the TPM under it; replaces any previous one |
| `xkey tpm policy auto-unseal --off` | Clears the mark and deletes the sealed password; the barrier then needs its password |
| `xkey tpm policy create <name> --pcrs ... --auto-unseal` | Creates the policy and enables auto-unseal in one step |

With `--xkmsd-url` (or `XKMSD_URL`) the verb sets the mark on the server's
policy instead, for the server's barrier.

## Headless daemons that auto-unseal

`xkey extension serve` and `xkey fido2`/`fido2 start` (with `--storage
barrier`) both accept the barrier flags below. For a `tpm2`-strategy
barrier they try TPM-policy auto-unseal first, then a direct TPM unseal. For a
cloud KMS strategy (`aws_kms`, `gcp_kms`, `azure_kv`, `vault`) they rebuild
the backend from the connection settings `xkey barrier init` persisted to
the config file and unseal with it — no password. For `pkcs11` they release
the token PIN that `xkey barrier init` sealed to the TPM, log in to the token
named in the config file, and unseal, again with no password. For `software`
they need a password. `shamir` is refused with a typed error naming the
interactive alternative, because no headless process can collect an operator
quorum.

| Flag | Commands | Meaning |
|---|---|---|
| `--barrier-password-stdin` | `extension serve`, `fido2` | Read the barrier password from standard input |
| `--barrier-password-file string` | `extension serve`, `fido2` | First line of the named file |
| `--tpm-device string`, `--tpm-simulator` | `extension serve` (also `barrier`) | Same TPM selection as `barrier` |
| `--no-barrier` | `extension serve` | Skip the barrier entirely, plain file storage (testing only) |

`XKEY_BARRIER_PASSWORD` is honored by both when no password flag is set.

## TPM device resolution

Shared by `barrier` and `extension serve` (`resolveTPMDevice`); `xkey tpm policy` uses the `tpm` group's `--device`/`--simulator`:

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
| `initialized` | Whether the data directory's storage engine holds a sealed root key |
| `sealed` | Whether the barrier is currently sealed |
| `strategy` | Which sealing strategy protects the root key (`software`, `tpm2`, `pkcs11`, `aws_kms`, `gcp_kms`, `azure_kv`, `vault`) |
| `hardware_backed` | Whether the strategy uses dedicated cryptographic hardware |
| `data_dir` | Path to the data directory (the go-qrdb file engine's root) |
| `root_key_entry` | Engine entry holding the sealed root key blob (`barrier/root_key`); not a file below `data_dir` |

On a fresh data directory run `xkey barrier init` before `xkey tpm` or
`xkey pin`: the file engine only claims an empty directory.

## Examples

```bash
# First-time setup with TPM hardware sealing
xkey barrier init --strategy tpm2

# A human captures the current boot state as a named TPM policy and seals
# the barrier password under it
xkey tpm policy create boot-policy --pcrs 0,2,4,7 --bank sha256
echo "$BARRIER_PASSWORD" | xkey tpm policy auto-unseal boot-policy

# From then on, an agent's unseal needs no password
xkey barrier unseal --auto

# ...and neither does a headless daemon
xkey extension serve --socket /run/xkey/xkey.sock

# A PKCS#11 token seals the root key; its PIN (first line) is sealed to the TPM
printf '%s\n%s\n%s\n' "$TOKEN_PIN" "$BARRIER_PASSWORD" "$BARRIER_PASSWORD" |
  xkey barrier init --strategy pkcs11 \
    --pkcs11-library /usr/lib/softhsm/libsofthsm2.so --pkcs11-token xkey-barrier

# After a firmware/kernel update changes the measured boot state
xkey tpm policy verify boot-policy   # reports the change, non-zero exit
xkey tpm policy update boot-policy   # re-captures and re-approves; nothing is re-sealed
```
