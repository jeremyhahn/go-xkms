# xkey CLI reference

Generated from the xkey cobra command tree by `make skill-reference`; do not edit by hand.

## Global flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--backend` | string |  | xkmsd backend to use (software, tpm2, pkcs11) |
| `--config` | string |  | config file path (default: ~/.config/xkey/xkey.yaml) |
| `--log-file` | string |  | log output file path (default: stderr) |
| `--log-level` | string | info | log level (debug, info, warn, error) |
| `--socket` | string |  | IPC socket path of the xkey instance to talk to (default: derived from XKEY_HOME, or $XDG_RUNTIME_DIR/xkey/xkey.sock, or a per-user fallback: $TMPDIR or ~/Library/Caches on macOS, ~/.xkey/run elsewhere; the directory must be mode 0700 and owned by you) |
| `--xkmsd-url` | string |  | xkmsd server URL (unix:// or grpc://) - enables server mode for all commands |

## xkey agent

Manage the agent server (master side)

Usage: `xkey agent`

## xkey agent approve

Approve a pending agent enrollment request

Usage: `xkey agent approve <request-id> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--cert-profile` | string | client | xkmsd CA profile used to sign or revoke agent certificates |
| `--cert-validity-days` | int | 0 | validity period for issued agent certificates (0 uses the CA default) |
| `--json` | bool | false | output the approval result as JSON |

## xkey agent code

Generate a one-time agent enrollment code

Usage: `xkey agent code [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--cert-profile` | string | client | xkmsd CA profile used to sign or revoke agent certificates |
| `--cert-validity-days` | int | 0 | validity period for issued agent certificates (0 uses the CA default) |
| `--json` | bool | false | output the code as JSON |
| `--validity` | duration | 0s | code validity duration (0 uses the configured default) |

## xkey agent pending

List pending agent enrollment requests

Usage: `xkey agent pending [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--cert-profile` | string | client | xkmsd CA profile used to sign or revoke agent certificates |
| `--cert-validity-days` | int | 0 | validity period for issued agent certificates (0 uses the CA default) |
| `--json` | bool | false | output pending requests as JSON |

## xkey agent reject

Reject a pending agent enrollment request

Usage: `xkey agent reject <request-id> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--cert-profile` | string | client | xkmsd CA profile used to sign or revoke agent certificates |
| `--cert-validity-days` | int | 0 | validity period for issued agent certificates (0 uses the CA default) |
| `--json` | bool | false | output the rejection result as JSON |
| `--reason` | string |  | reason recorded in the log and event for this rejection |

## xkey agent remove

Remove an enrolled agent

Usage: `xkey agent remove <agent-id> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--cert-profile` | string | client | xkmsd CA profile used to sign or revoke agent certificates |
| `--cert-validity-days` | int | 0 | validity period for issued agent certificates (0 uses the CA default) |
| `--json` | bool | false | output the removal result as JSON |

## xkey agent start

Start the agent server (master)

Usage: `xkey agent start [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--cert-profile` | string | client | xkmsd CA profile used to sign enrolling agent CSRs |
| `--cert-validity-days` | int | 0 | validity period for issued agent certificates (0 uses the CA default) |
| `--listen` | string |  | Listen address as host:port (default: agent.listen_address, :9443) |
| `--tls-ca` | string |  | TLS CA certificate file used to verify connecting agents (the xkmsd trust bundle comes from XKMSD_TLS_CA) |
| `--tls-cert` | string |  | TLS certificate file |
| `--tls-key` | string |  | TLS private key file |

## xkey agent status

Show agent server status and connections

Usage: `xkey agent status`

## xkey agent stop

Stop the agent server

Usage: `xkey agent stop`

## xkey auth

Manage server authentication

Usage: `xkey auth`

## xkey auth login

Authenticate to a registered server

Usage: `xkey auth login [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--backend` | string | software | PIV key backend: software or pkcs11 (used with --piv) |
| `--email` | string |  | Canonical email login key to authenticate (required) |
| `--pin-stdin` | bool | false | Read the PIN from standard input |
| `--piv` | bool | false | Authenticate with a PIV slot certificate over mTLS instead of WebAuthn |
| `--server` | string |  | Server URL (required) |
| `--slot` | string | 9a | PIV slot to authenticate with (used with --piv) |
| `--tls-ca` | string |  | PEM bundle of CA certificates to trust, in addition to the xKey trust store |

## xkey auth logout

Revoke the stored session and remove it locally

Usage: `xkey auth logout [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--server` | string |  | Server URL (required) |

## xkey auth refresh

Rotate the stored access/refresh token pair

Usage: `xkey auth refresh [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--server` | string |  | Server URL (required) |

## xkey auth register

Register with a new xkms server

Usage: `xkey auth register [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--display-name` | string |  | Human-readable account name (default: the login key) |
| `--email` | string |  | Canonical email login key to enroll (required) |
| `--pin-stdin` | bool | false | Read the PIN from standard input |
| `--server` | string |  | Server URL (required) |
| `--setup-token` | string |  | Pre-authorized enrollment token |
| `--spki-pin` | string |  | SPKI SHA-256 pin for certificate pinning (recorded on the server entry and reused by later runs) |
| `--tls-ca` | string |  | PEM bundle of CA certificates to trust, in addition to the xKey trust store |

## xkey auth status

Show authentication status

Usage: `xkey auth status [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--server` | string |  | Filter to a specific server URL |

## xkey auth token

Print current JWT token for a server

Usage: `xkey auth token [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--server` | string |  | Server URL (required) |

## xkey backup

Backup and restore xkey data

Usage: `xkey backup`

## xkey backup contents

Show contents of a backup

Usage: `xkey backup contents <file> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--key-stdin` | bool | false | Read the backup key from standard input |
| `--password-stdin` | bool | false | Read the backup password from standard input |

## xkey backup create

Create a backup of xkey data

Usage: `xkey backup create [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--oath-store` | string |  | OATH credential store file, bypassing the barrier (default: the barrier-encrypted store when a barrier is initialized, otherwise {xkey-home}/data/oath.json) |
| `--output`, `-o` | string |  | Output file path (default: ~/.xkey/backups/backup-{timestamp}.xkb) |
| `--password-stdin` | bool | false | Read the backup password from standard input |
| `--password-store` | string |  | Static password store directory (default: {xkey-home}/data/staticpw) |
| `--trust-store` | string |  | Trust store directory (default: {xkey-home}/data/trust) |

## xkey backup from-device

Restore backup from a paired phone

Usage: `xkey backup from-device [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--device` | string |  | Paired device name to restore from |
| `--key-stdin` | bool | false | Read the backup key from standard input |
| `--oath-store` | string |  | OATH credential store file, bypassing the barrier (default: the barrier-encrypted store when a barrier is initialized, otherwise {xkey-home}/data/oath.json) |
| `--password-stdin` | bool | false | Read the backup password from standard input |
| `--password-store` | string |  | Static password store directory (default: {xkey-home}/data/staticpw) |
| `--timeout` | duration | 1m0s | Operation timeout |
| `--trust-store` | string |  | Trust store directory (default: {xkey-home}/data/trust) |

## xkey backup list

List available backups

Usage: `xkey backup list`

## xkey backup restore

Restore xkey data from a backup

Usage: `xkey backup restore <file> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--key-stdin` | bool | false | Read the backup key from standard input |
| `--oath-store` | string |  | OATH credential store file, bypassing the barrier (default: the barrier-encrypted store when a barrier is initialized, otherwise {xkey-home}/data/oath.json) |
| `--password-stdin` | bool | false | Read the backup password from standard input |
| `--password-store` | string |  | Static password store directory (default: {xkey-home}/data/staticpw) |
| `--trust-store` | string |  | Trust store directory (default: {xkey-home}/data/trust) |

## xkey backup to-device

Send backup to a paired phone

Usage: `xkey backup to-device [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--device` | string |  | Paired device name to send backup to |
| `--oath-store` | string |  | OATH credential store file, bypassing the barrier (default: the barrier-encrypted store when a barrier is initialized, otherwise {xkey-home}/data/oath.json) |
| `--password-stdin` | bool | false | Read the backup password from standard input |
| `--password-store` | string |  | Static password store directory (default: {xkey-home}/data/staticpw) |
| `--timeout` | duration | 1m0s | Operation timeout |
| `--trust-store` | string |  | Trust store directory (default: {xkey-home}/data/trust) |

## xkey barrier

Barrier seal/unseal management

Usage: `xkey barrier`

Inherited by subcommands:

| Flag | Type | Default | Description |
|---|---|---|---|
| `--data-dir` | string |  | data directory for barrier storage (default: ~/.xkey/data) |
| `--tpm-device` | string |  | TPM device path for the tpm2 strategy (default: $TPM_DEVICE_PATH or /dev/tpmrm0) |
| `--tpm-simulator` | bool | false | Use the in-process TPM simulator instead of a hardware device (requires a simulator build) |

## xkey barrier init

Initialize the barrier (first-time setup)

Usage: `xkey barrier init [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--aws-endpoint` | string |  | Custom AWS KMS endpoint (optional; for testing against an emulator) |
| `--aws-key-id` | string |  | Existing AWS KMS key ID, ARN, alias, or alias ARN to seal under (optional; a CMK is created and persisted when unset) |
| `--aws-region` | string |  | AWS region for the aws_kms barrier strategy |
| `--azure-allow-local-vault-url` | bool | false | Allow a localhost/127.0.0.1 vault URL (development only) |
| `--azure-vault-url` | string |  | Azure Key Vault URL for the azure_kv barrier strategy |
| `--gcp-credentials-file` | string |  | Path to a GCP service account JSON key file (optional; Application Default Credentials are used when unset) |
| `--gcp-key-ring` | string |  | GCP KMS key ring ID |
| `--gcp-location` | string |  | GCP KMS location (e.g. us-east1) |
| `--gcp-project-id` | string |  | GCP project ID for the gcp_kms barrier strategy |
| `--strategy` | string |  | sealing strategy: software, tpm2, pkcs11, aws_kms, gcp_kms, azure_kv, vault (default: auto-detect) |
| `--vault-address` | string |  | HashiCorp Vault server address for the vault barrier strategy |
| `--vault-mount-path` | string |  | Vault Transit engine mount path (default: transit) |

## xkey barrier seal

Seal the barrier (lock it)

Usage: `xkey barrier seal`

## xkey barrier status

Show barrier status

Usage: `xkey barrier status [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--json` | bool | false | output status as JSON |
| `--source` | string | auto | Where to read state from: auto, daemon, disk |

## xkey barrier unseal

Unseal the barrier

Usage: `xkey barrier unseal [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--auto` | bool | false | Unseal via the TPM auto-unseal policy only (see 'xkey tpm policy auto-unseal'); never prompts for a password |

## xkey browser

Secure browser management

Usage: `xkey browser`

## xkey browser launch

Launch a browser with trusted CA certificates

Usage: `xkey browser launch [url] [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--browser` | string |  | absolute path to browser binary (default: auto-detect first available) |
| `--extension` | stringArray | [] | restrict --include-extensions to the given extension ID (repeatable; default: all) |
| `--include-extensions` | bool | false | import user-installed extensions from the system default Chrome profile (Chrome isolated mode only) |
| `--source-profile` | string |  | source Chrome profile dir to import extensions from (default: ~/.config/google-chrome/Default) |

## xkey ca

Certificate Authority operations

Usage: `xkey ca`

Inherited by subcommands:

| Flag | Type | Default | Description |
|---|---|---|---|
| `--tls-ca` | string |  | TLS CA certificate file used to verify the xkmsd server |

## xkey ca bundle

Get the CA certificate bundle

Usage: `xkey ca bundle [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--output` | string |  | output file path (default: stdout) |

## xkey ca check-revocation

Check if a certificate is revoked

Usage: `xkey ca check-revocation <serial>`

## xkey ca crl

Generate a Certificate Revocation List

Usage: `xkey ca crl [flags]`

Aliases: gen-crl

| Flag | Type | Default | Description |
|---|---|---|---|
| `--output` | string |  | output file path (default: stdout) |

## xkey ca info

Get CA certificate information

Usage: `xkey ca info`

## xkey ca issue

Issue a new certificate

Usage: `xkey ca issue [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--algorithm` | string |  | key algorithm (ecdsa-p256, ecdsa-p384, rsa2048, ed25519) |
| `--cn` | string |  | common name for the certificate subject |
| `--organization` | string |  | organization for the certificate subject |
| `--output` | string |  | output file path (default: stdout) |
| `--profile` | string |  | certificate profile (server, client) |
| `--san` | string |  | subject alternative names (comma-separated TYPE:VALUE pairs) |
| `--validity-days` | int | 0 | certificate validity in days (0 for CA default) |

## xkey ca revoke

Revoke a certificate

Usage: `xkey ca revoke <serial> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--reason` | string | unspecified | revocation reason (unspecified, key-compromise, ca-compromise, affiliation-changed, superseded, cessation-of-operation) |

## xkey ca sign-csr

Sign a certificate signing request

Usage: `xkey ca sign-csr [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--csr` | string |  | path to PEM-encoded CSR file |
| `--output` | string |  | output file path (default: stdout) |
| `--profile` | string |  | certificate profile (server, client) |
| `--validity-days` | int | 0 | certificate validity in days (0 for CA default) |

## xkey cert

Manage client certificates

Usage: `xkey cert`

## xkey cert export

Export certificate to a PEM file

Usage: `xkey cert export [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--file` | string |  | Output file path (required) |
| `--slot` | string | 9a | PIV slot to export certificate from (9a, 9c, 9d, 9e) |

## xkey cert request

Request a certificate from a server CA

Usage: `xkey cert request [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--cn` | string |  | Common Name for the certificate subject (required) |
| `--organization` | string |  | Organization for the certificate subject |
| `--profile` | string | client | Certificate profile (client, server) |
| `--server` | string |  | xkms server URL (required) |
| `--slot` | string | 9a | PIV slot to use for key and certificate (9a, 9c, 9d, 9e) |
| `--spki-pin` | string |  | SPKI SHA-256 pin for server certificate pinning (hex-encoded) |
| `--validity-days` | int | 0 | Certificate validity in days (0 for server default) |

## xkey cert show

Show current certificate details

Usage: `xkey cert show [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--slot` | string | 9a | PIV slot to read certificate from (9a, 9c, 9d, 9e) |

## xkey config

Manage xKey configuration

Usage: `xkey config`

## xkey config init

Create default configuration file

Usage: `xkey config init [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` | bool | false | overwrite existing configuration file |

## xkey config path

Show configuration file locations

Usage: `xkey config path`

## xkey config show

Display current configuration

Usage: `xkey config show`

## xkey device

Manage paired device connections

Usage: `xkey device`

Aliases: phone

Inherited by subcommands:

| Flag | Type | Default | Description |
|---|---|---|---|
| `--trust-new-devices` | bool | false | Allow connection to unpaired devices (empty prologue) (default: device.trust_new_devices, false) |

## xkey device attest

Request key attestation from a paired phone

Usage: `xkey device attest <key-id> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--device` | string |  | Specific paired device to use |
| `--no-verify` | bool | false | Skip certificate chain verification |
| `--timeout` | duration | 1m0s | Operation timeout (includes biometric wait) |

## xkey device attest-device

Verify phone device attestation

Usage: `xkey device attest-device [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--device` | string |  | Device name to attest (uses default if not specified) |
| `--force` | bool | false | Ignore grace period and re-attest anyway |
| `--set-grace-period` | duration | 0s | Set the attestation grace period for this device (e.g., 5m, 30m) |

## xkey device connect

Connect to a paired master

Usage: `xkey device connect <address> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--tls-ca` | string |  | TLS CA certificate file |
| `--tls-cert` | string |  | TLS certificate file |
| `--tls-key` | string |  | TLS private key file |

## xkey device device-info

Show detailed device information

Usage: `xkey device device-info [device-name]`

## xkey device enroll

Enroll with a master xKey instance

Usage: `xkey device enroll [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--cert-profile` | string | client | CA certificate profile for the agent certificate |
| `--code` | string |  | One-time enrollment code (redeemed by the master; not supported remotely) |
| `--name` | string |  | Agent name (default: hostname) |
| `--server` | string |  | Master server address as host:port (required) |
| `--validity-days` | int | 0 | Certificate validity in days (0 uses the CA default) |

## xkey device enroll-phone

Issue a device credential to a paired phone

Usage: `xkey device enroll-phone [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--allow-package` | stringSlice | [] | Android package name permitted to enroll (repeatable) |
| `--allow-signer` | stringSlice | [] | Hex SHA-256 signing certificate digest permitted (repeatable) |
| `--allow-unpinned` | bool | false | Permit an allow-listed package with no signing digest (development only) |
| `--ca` | string | local | Signing authority: local or xkms |
| `--device` | string |  | Device name to enroll (uses the default if unset) |
| `--min-security-level` | string | trusted_environment | Weakest key protection accepted: software, trusted_environment, strongbox |
| `--require-verified-boot` | bool | true | Refuse devices that are not verified-boot with a locked bootloader |
| `--subject` | string |  | Subject DN to request on the certificate |
| `--validity` | duration | 0s | Credential lifetime, and so the re-attestation cadence (default 90 days) |

## xkey device import

Import a shared key from a paired phone

Usage: `xkey device import <key-id> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--backend` | string | software | Target backend for imported key |
| `--device` | string |  | Paired device name to import from |
| `--timeout` | duration | 1m0s | Operation timeout |

## xkey device list

List paired devices

Usage: `xkey device list`

## xkey device listen

Listen for phone-initiated connections

Usage: `xkey device listen [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--allow-sync` | bool | false | Allow this session to export the password vault and OATH secrets to the phone via remote.sync* |
| `--attestation-mode` | string | auto | Attestation mode: auto, tpm2, software |
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--device` | string |  | Specific paired device to accept connections from |
| `--name` | string |  | Advertised device name (default: hostname) |
| `--so-pin-stdin` | bool | false | Read the SO PIN from standard input |
| `--timeout` | duration | 0s | Listen timeout (0 for indefinite) |
| `--tpm-device` | string |  | TPM2 device path (default: /dev/tpmrm0) |
| `--tpm-enrollment` | bool | false | Serve TCG-CSR-IDEVID device enrollment from this host's TPM |
| `--tpm-pcr-bank` | string |  | PCR bank for the platform policy digest (default: SHA-256); set only if this TPM's SHA-256 bank is not allocated |

## xkey device pair

Pair with a phone key backend

Usage: `xkey device pair [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--device` | string |  | Specific device name or address to pair |
| `--force` | bool | false | Force re-pairing even if already paired |
| `--so-pin-stdin` | bool | false | Read the SO PIN from standard input |
| `--timeout` | duration | 30s | Scan timeout duration (default: device.scan_timeout, 30s) |

## xkey device relay

Serve a paired phone's session over TCP instead of BLE

Usage: `xkey device relay [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--allow-sync` | bool | false | Allow this session to export the password vault and OATH secrets to the phone via remote.sync* |
| `--attestation-mode` | string | auto | Attestation mode: auto, tpm2, software |
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--device` | string |  | Specific paired device to accept connections from |
| `--listen` | string |  | TCP listen address as host:port (default: phone.relay_listen_address, 127.0.0.1:8444) |
| `--name` | string |  | Advertised device name (default: hostname) |
| `--so-pin-stdin` | bool | false | Read the SO PIN from standard input |
| `--timeout` | duration | 0s | Listen timeout (0 for indefinite) |
| `--tpm-device` | string |  | TPM2 device path (default: /dev/tpmrm0) |
| `--tpm-enrollment` | bool | false | Serve TCG-CSR-IDEVID device enrollment from this host's TPM |
| `--tpm-pcr-bank` | string |  | PCR bank for the platform policy digest (default: SHA-256); set only if this TPM's SHA-256 bank is not allocated |

## xkey device scan

Scan for nearby xKey devices

Usage: `xkey device scan [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--timeout` | duration | 30s | Scan timeout duration (default: device.scan_timeout, 30s) |

## xkey device share

Share a key with a paired phone

Usage: `xkey device share <backend> <key-id> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--device` | string |  | Paired device name to share with |
| `--label` | string |  | Label for the shared key on the phone |
| `--timeout` | duration | 1m0s | Operation timeout |

## xkey device share-policy

Manage key sharing policies

Usage: `xkey device share-policy`

## xkey device share-policy list

List key sharing policies

Usage: `xkey device share-policy list`

## xkey device share-policy remove

Remove sharing policy for a key

Usage: `xkey device share-policy remove <backend> <key-id>`

## xkey device share-policy set

Set sharing policy for a key

Usage: `xkey device share-policy set <backend> <key-id> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--allow` | bool | false | Allow sharing for this key |
| `--devices` | stringSlice | [] | Allowed device fingerprints (comma-separated) |
| `--share-private` | bool | false | Allow sharing private key (software keys only) |
| `--share-public` | bool | true | Allow sharing public key |
| `--share-symmetric` | bool | false | Allow sharing symmetric key material |

## xkey device status

Show device connection status

Usage: `xkey device status [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--device` | string |  | Specific device to check |

## xkey device sync

Sync data bidirectionally with a paired phone

Usage: `xkey device sync [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--all` | bool | true | Sync all stores (default) |
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--device` | string |  | Paired device name |
| `--dry-run` | bool | false | Show what would be synced without applying |
| `--oath` | bool | false | Sync OATH credentials |
| `--passwords` | bool | false | Sync password entries |
| `--timeout` | duration | 1m0s | Operation timeout |
| `--trust-store` | bool | false | Sync trust store certificates |

## xkey device sync-pull

Pull phone data to this device

Usage: `xkey device sync-pull [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--all` | bool | true | Pull all stores (default) |
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--device` | string |  | Paired device name |
| `--dry-run` | bool | false | Show what would be pulled without applying |
| `--oath` | bool | false | Pull OATH credentials |
| `--passwords` | bool | false | Pull password entries |
| `--timeout` | duration | 1m0s | Operation timeout |
| `--trust-store` | bool | false | Pull trust store certificates |

## xkey device sync-push

Push local data to a paired phone

Usage: `xkey device sync-push [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--all` | bool | true | Push all stores (default) |
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--device` | string |  | Paired device name |
| `--dry-run` | bool | false | Show what would be pushed without applying |
| `--oath` | bool | false | Push OATH credentials |
| `--passwords` | bool | false | Push password entries |
| `--timeout` | duration | 1m0s | Operation timeout |
| `--trust-store` | bool | false | Push trust store certificates |

## xkey device sync-status

Show sync status with a paired phone

Usage: `xkey device sync-status [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--device` | string |  | Paired device name |
| `--timeout` | duration | 1m0s | Operation timeout |

## xkey device unpair

Remove pairing with a device

Usage: `xkey device unpair <device-name> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` | bool | false | Skip confirmation prompt |

## xkey extension

Browser extension management

Usage: `xkey extension`

## xkey extension install

Install native messaging manifest

Usage: `xkey extension install [chrome|firefox|all] [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--allowed-origin` | string |  | Override Chrome extension allowed origin (e.g., chrome-extension://your_id/) |
| `--profile-dir` | string |  | Chrome profile's user-data directory to pair with this xkey instance (requires the "chrome" argument) |

## xkey extension pair-status

Show extension pairing status

Usage: `xkey extension pair-status`

## xkey extension serve

Run headless autofill IPC server

Usage: `xkey extension serve [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--auto-lock-minutes` | int | 15 | Inactivity lock timeout (0=disabled) |
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--log-file` | string |  | Log file path (default: stderr) |
| `--log-level` | string | info | Log level (debug, info, warn, error) |
| `--no-auth` | bool | false | Disable CTAP2 authentication for autofill (credentials returned without PIN/touch) |
| `--no-barrier` | bool | false | Skip barrier, use plain file storage (testing/development) |
| `--no-pairing` | bool | false | Disable extension identity verification (testing only) |
| `--pin-state` | string |  | PIN state directory path |
| `--so-pin-stdin` | bool | false | Read the SO PIN from standard input |
| `--tpm-device` | string |  | TPM device path for the tpm2 barrier strategy (default: $TPM_DEVICE_PATH or /dev/tpmrm0) |
| `--tpm-simulator` | bool | false | Use the in-process TPM simulator instead of a hardware device (requires a simulator build) |

## xkey extension status

Show native messaging manifest status

Usage: `xkey extension status`

## xkey extension uninstall

Uninstall native messaging manifest

Usage: `xkey extension uninstall [chrome|firefox|all] [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--profile-dir` | string |  | Chrome profile's user-data directory whose manifest to remove (requires the "chrome" argument) |

## xkey extension unpair

Remove paired browser extension identity

Usage: `xkey extension unpair`

## xkey fido2

Run as FIDO2/WebAuthn virtual USB device

Usage: `xkey fido2 [flags]`

Aliases: fido

| Flag | Type | Default | Description |
|---|---|---|---|
| `--attestation` | string | none | Attestation format: none, packed, or tpm |
| `--backend` | string | software | Key backend: software, tpm2, or phone |
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--cdp` | bool | false | Enable Chrome DevTools virtual authenticator bridge |
| `--cdp-host` | string | localhost | Chrome DevTools host |
| `--cdp-port` | int | 9222 | Chrome DevTools debugging port |
| `--default-password` | string |  | Password name to type on bare touch |
| `--interactive` | bool | false | Enable interactive mode (prompt for touch/PIN) |
| `--name` | string | xKey (go-xkms) | Device name visible to OS |
| `--notify` | string | dialog | Notification type: dialog (interactive), passive (desktop notification), log (log-only), or none |
| `--notify-command` | string |  | Custom notification command (overrides built-in notifications). Split into argv on whitespace (quote with ' or " to include a space in one argument); run exactly as given, never through a shell, and never modified. Request data (operation, RP ID, RP name, user name) reaches the command only via the XKEY_OPERATION/XKEY_RP_ID/XKEY_RP_NAME/XKEY_USER_NAME environment variables, for example: sh -c 'notify-send "Touch required" "$XKEY_RP_ID"' |
| `--password-store` | string |  | Path to static password store (default: ~/.xkey/data/staticpw, the same store `xkey password` uses) |
| `--phone-device` | string |  | Specific phone name or address to use (default: use default paired phone) |
| `--pin` | bool | true | Enable PIN support (required for FIDO 2.1 credential management) |
| `--require-touch` | bool | true | Require touch even after PIN verification (like hardware YubiKey) |
| `--serial` | string |  | Device serial number (auto-generated if empty) |
| `--set-pin-stdin` | bool | false | Read the PIN to establish from standard input |
| `--storage` | string | memory | Storage type: memory, file, or barrier |
| `--storage-path` | string |  | Path for file storage and the authenticator profile (default: ~/.xkey/data/fido2, see --data-dir/XKEY_DATA_DIR) |
| `--timeout` | duration | 30s | Timeout for user presence requests |
| `--tpm-device` | string | /dev/tpmrm0 | TPM device path |
| `--unified-pin` | bool | true | Propagate the host PIN service's user PIN to the virtual FIDO2 authenticator's CTAP2 PIN hash on every set/change/verify (it does not sync a separate PKCS#11 or file PIN store: there is exactly one governing PIN backend, see 'xkey pin status') |

## xkey fido2 change-so-pin

Change this device's Security Officer PIN (requires the current one)

Usage: `xkey fido2 change-so-pin`

## xkey fido2 init-token

Initialize this device's token by establishing its Security Officer PIN

Usage: `xkey fido2 init-token`

## xkey fido2 policy

Manage per-RP authentication policies

Usage: `xkey fido2 policy`

## xkey fido2 policy delete

Delete an RP policy

Usage: `xkey fido2 policy delete [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--rpid` | string |  | Relying party ID (required) |

## xkey fido2 policy get

Get an RP policy by RPID

Usage: `xkey fido2 policy get [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--rpid` | string |  | Relying party ID (required) |

## xkey fido2 policy list

List all RP policies

Usage: `xkey fido2 policy list`

## xkey fido2 policy set

Create or update an RP policy

Usage: `xkey fido2 policy set [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--attestation` | string |  | Attestation override: '', 'none', 'indirect', 'direct', 'enterprise' |
| `--blocked` | bool | false | Block all operations for this RP |
| `--enterprise` | bool | false | Mark as enterprise-trusted |
| `--rpid` | string |  | Relying party ID (required) |
| `--up` | string |  | UP override: 'true', 'false', '' (empty means no override) |
| `--uv` | string |  | UV override: '', 'required', 'preferred', 'discouraged' |

## xkey fido2 profile

Configure authenticator profile settings

Usage: `xkey fido2 profile`

## xkey fido2 profile set

Set authenticator profile settings

Usage: `xkey fido2 profile set [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--enterprise-attestation` | bool | false | Enable enterprise attestation |
| `--transports` | string |  | Comma-separated transports: usb, nfc, ble, internal, hybrid |

## xkey fido2 profile show

Show the persisted authenticator profile settings

Usage: `xkey fido2 profile show`

Aliases: get

## xkey fido2 provision-attestation

Provision this device's FIDO2 attestation identity (Security Officer)

Usage: `xkey fido2 provision-attestation [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--profile` | string |  | CA certificate profile to issue the attestation certificate under (default: the CA's own default) |
| `--rotate` | bool | false | Replace an existing attestation identity (invalidates every statement issued under the old key) |
| `--tls-ca` | string |  | CA bundle used to verify TLS transports to xkmsd |
| `--validity-days` | int | 0 | Certificate validity in days (default: the CA's own default) |

## xkey fido2 start

Run the FIDO2/WebAuthn virtual USB device (same as 'xkey fido2')

Usage: `xkey fido2 start [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--attestation` | string | none | Attestation format: none, packed, or tpm |
| `--backend` | string | software | Key backend: software, tpm2, or phone |
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--cdp` | bool | false | Enable Chrome DevTools virtual authenticator bridge |
| `--cdp-host` | string | localhost | Chrome DevTools host |
| `--cdp-port` | int | 9222 | Chrome DevTools debugging port |
| `--default-password` | string |  | Password name to type on bare touch |
| `--interactive` | bool | false | Enable interactive mode (prompt for touch/PIN) |
| `--name` | string | xKey (go-xkms) | Device name visible to OS |
| `--notify` | string | dialog | Notification type: dialog (interactive), passive (desktop notification), log (log-only), or none |
| `--notify-command` | string |  | Custom notification command (overrides built-in notifications). Split into argv on whitespace (quote with ' or " to include a space in one argument); run exactly as given, never through a shell, and never modified. Request data (operation, RP ID, RP name, user name) reaches the command only via the XKEY_OPERATION/XKEY_RP_ID/XKEY_RP_NAME/XKEY_USER_NAME environment variables, for example: sh -c 'notify-send "Touch required" "$XKEY_RP_ID"' |
| `--password-store` | string |  | Path to static password store (default: ~/.xkey/data/staticpw, the same store `xkey password` uses) |
| `--phone-device` | string |  | Specific phone name or address to use (default: use default paired phone) |
| `--pin` | bool | true | Enable PIN support (required for FIDO 2.1 credential management) |
| `--require-touch` | bool | true | Require touch even after PIN verification (like hardware YubiKey) |
| `--serial` | string |  | Device serial number (auto-generated if empty) |
| `--set-pin-stdin` | bool | false | Read the PIN to establish from standard input |
| `--storage` | string | memory | Storage type: memory, file, or barrier |
| `--storage-path` | string |  | Path for file storage and the authenticator profile (default: ~/.xkey/data/fido2, see --data-dir/XKEY_DATA_DIR) |
| `--timeout` | duration | 30s | Timeout for user presence requests |
| `--tpm-device` | string | /dev/tpmrm0 | TPM device path |
| `--unified-pin` | bool | true | Propagate the host PIN service's user PIN to the virtual FIDO2 authenticator's CTAP2 PIN hash on every set/change/verify (it does not sync a separate PKCS#11 or file PIN store: there is exactly one governing PIN backend, see 'xkey pin status') |

## xkey fido2 status

Report whether the FIDO2 virtual device daemon is running

Usage: `xkey fido2 status`

## xkey luks2

LUKS2 encrypted storage management

Usage: `xkey luks2`

## xkey luks2 import-data

Import data into a LUKS volume

Usage: `xkey luks2 import-data [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--backup` | bool | false | Create backup before cleanup (use with --cleanup) |
| `--cleanup` | bool | false | Remove original data after successful import |
| `--mount-point` | string |  | Final mount point for --unseal (default: ~/.xkey) |
| `--path` | string |  | LUKS file path (default: ~/.xkey.luks) |
| `--source` | string |  | Source directory to import from (default: ~/.xkey) |
| `--unseal` | bool | false | Unlock volume at mount point after import |

## xkey luks2 lock

Lock encrypted LUKS storage

Usage: `xkey luks2 lock [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--mount-point` | string |  | Custom mount point (default: ~/.xkey) |
| `--path` | string |  | Custom LUKS file path (default: ~/.xkey.luks) |

## xkey luks2 migrate

Migrate to a new/larger LUKS container

Usage: `xkey luks2 migrate [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--keep-old` | bool | false | Keep old container after migration |
| `--path` | string |  | New container path (default: same as current) |
| `--size` | string |  | New container size (default: 2x current size) |
| `--source-path` | string |  | Source container path (default: ~/.xkey.luks) |
| `--wipe` | bool | false | Securely wipe old container after migration |
| `--wipe-standard` | string | dod3 | Wipe standard: nist, dod3, dod7 |

## xkey luks2 seal

Create encrypted LUKS storage

Usage: `xkey luks2 seal [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--mount-point` | string |  | Custom mount point (default: ~/.xkey) |
| `--path` | string |  | Custom LUKS file path (default: ~/.xkey.luks) |
| `--size` | string | 100M | Volume size (e.g., 100M, 1G) |
| `--skip-migrate` | bool | false | Create volume without migrating existing data |
| `--unseal` | bool | false | Keep volume unlocked and mounted after creation |

## xkey luks2 unseal

Unlock encrypted LUKS storage

Usage: `xkey luks2 unseal [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--mount-point` | string |  | Custom mount point (default: ~/.xkey) |
| `--path` | string |  | Custom LUKS file path (default: ~/.xkey.luks) |

## xkey luks2 wipe

Securely destroy LUKS container

Usage: `xkey luks2 wipe [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` | bool | false | Skip confirmation prompt |
| `--mount-point` | string |  | Custom mount point (default: ~/.xkey) |
| `--path` | string |  | Container path (default: ~/.xkey.luks) |
| `--standard` | string | dod3 | Wipe standard: nist, dod3, dod7 |

## xkey oath

OATH TOTP/HOTP one-time password management

Usage: `xkey oath`

## xkey oath add

Add a new OATH credential

Usage: `xkey oath add [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--algorithm` | string | SHA1 | Hash algorithm: SHA1, SHA256, SHA512 |
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--digits` | int | 6 | Number of digits (6, 7, or 8) |
| `--issuer` | string |  | Service issuer name |
| `--name` | string |  | Credential name (e.g., GitHub) |
| `--period` | int | 30 | Time period in seconds (TOTP only) |
| `--secret-stdin` | bool | false | Read the OATH secret from standard input |
| `--store` | string |  | Path to credential store (default: ~/.xkey/data/oath.json) |
| `--type` | string | totp | OTP type: totp or hotp |
| `--uri` | string |  | otpauth:// URI (from QR code) |

## xkey oath generate

Generate OTP code(s)

Usage: `xkey oath generate [name] [flags]`

Aliases: gen, code

| Flag | Type | Default | Description |
|---|---|---|---|
| `--all` | bool | false | Generate codes for all credentials |
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--store` | string |  | Path to credential store (default: ~/.xkey/data/oath.json) |

## xkey oath list

List all credentials

Usage: `xkey oath list [flags]`

Aliases: ls

| Flag | Type | Default | Description |
|---|---|---|---|
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--secrets` | bool | false | Show secret keys |
| `--store` | string |  | Path to credential store (default: ~/.xkey/data/oath.json) |
| `--uri` | bool | false | Show otpauth:// URIs |

## xkey oath pull

Pull OATH credentials from a paired phone

Usage: `xkey oath pull [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--device` | string |  | Paired device name |
| `--store` | string |  | Path to credential store (default: ~/.xkey/data/oath.json) |
| `--timeout` | duration | 1m0s | Operation timeout |

## xkey oath push

Push OATH credential to a paired phone

Usage: `xkey oath push <name-or-id> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--device` | string |  | Paired device name |
| `--store` | string |  | Path to credential store (default: ~/.xkey/data/oath.json) |
| `--timeout` | duration | 1m0s | Operation timeout |

## xkey oath remove

Remove a credential

Usage: `xkey oath remove [name...] [flags]`

Aliases: rm, delete

| Flag | Type | Default | Description |
|---|---|---|---|
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--force` | bool | false | Don't prompt for confirmation |
| `--store` | string |  | Path to credential store (default: ~/.xkey/data/oath.json) |

## xkey oath scan

Scan screen for OTP QR code and add credential

Usage: `xkey oath scan [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--display` | int | -1 | Display index to scan (-1 for all displays) |
| `--index` | int | -1 | Select QR code by index when multiple are found |
| `--list-displays` | bool | false | List available displays and exit |
| `--name` | string |  | Override the credential name |
| `--store` | string |  | Path to credential store (default: ~/.xkey/data/oath.json) |
| `--yes`, `-y` | bool | false | Don't prompt for confirmation |

## xkey oath sync

Sync OATH credentials with a paired phone

Usage: `xkey oath sync [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--device` | string |  | Paired device name |
| `--store` | string |  | Path to credential store (default: ~/.xkey/data/oath.json) |
| `--timeout` | duration | 1m0s | Operation timeout |

## xkey oidc

OpenID Connect authentication

Usage: `xkey oidc`

Inherited by subcommands:

| Flag | Type | Default | Description |
|---|---|---|---|
| `--local` | bool | false | use the local OIDC backend even when an xkmsd server is configured |

## xkey oidc aws

AWS Console OIDC login

Usage: `xkey oidc aws [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--auto-refresh` | int | 0 | Auto-refresh interval in seconds (0 to disable) |
| `--background` | bool | false | Run auto-refresh in background (requires --auto-refresh) |
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--callback-host` | string |  | Host the local callback listener binds (default: oidc.callback_host, localhost) |
| `--callback-port` | int | 0 | Port of the default redirect URL (default: oidc.callback_port, 8085) |
| `--credentials-file` | string | ~/.aws/credentials | Path to AWS credentials file |
| `--cross-device` | bool | false | Enable cross-device authentication flow |
| `--exec` | string |  | Execute script after login (for --output exec) |
| `--log-file` | string |  | Log file for background refresh (default: ~/.xkey/logs/aws-{region}.log) |
| `--no-browser` | bool | false | Don't open browser, print URL instead |
| `--output`, `-o` | string | aws-credentials | Output mode: aws-credentials, json, exec, none |
| `--profile` | string | default | AWS profile name to write credentials to |
| `--region`, `-r` | string |  | AWS region (required) |
| `--session-store` | string | ~/.xkey/aws-session.json | Path to session store |

## xkey oidc import

Import an existing login as a server OIDC credential

Usage: `xkey oidc import <name> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--access-token` | string |  | access token; '-' reads it from stdin |
| `--codex-auth` | string |  | import the ChatGPT login of a codex auth.json |
| `--create` | bool | false | create the credential before importing |
| `--owner` | string |  | owner of a personal server credential (default: you) |
| `--refresh-token` | string |  | refresh token; '-' reads it from stdin |
| `--scope` | string |  | server credential scope: user (personal, default) or tenant (shared) |
| `--template` | string |  | provider template of a created credential |
| `--tenant` | string |  | tenant holding the server credential (default: your own) |

## xkey oidc login

Interactive browser-based login

Usage: `xkey oidc login [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--authorization-endpoint` | string |  | Manual authorization endpoint (skips discovery; requires --token-endpoint and --jwks-uri) |
| `--auto-refresh` | int | 0 | Auto-refresh interval in seconds (0 to disable) |
| `--background` | bool | false | Run auto-refresh in background (requires --auto-refresh) |
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--callback-host` | string |  | Host the local callback listener binds (default: oidc.callback_host, localhost) |
| `--callback-port` | int | 0 | Port of the default redirect URL (default: oidc.callback_port, 8085) |
| `--client-id` | string |  | OAuth2 client ID |
| `--client-secret` | string |  | OAuth2 client secret (optional) |
| `--exec` | string |  | Execute script after login (receives JSON payload via stdin) |
| `--issuer` | string |  | OIDC provider issuer URL |
| `--jwks-uri` | string |  | Manual JWKS URI (skips discovery; requires --authorization-endpoint and --token-endpoint) |
| `--log-file` | string |  | Log file for background refresh (default: auto-generated) |
| `--no-browser` | bool | false | Don't open browser, print URL instead |
| `--owner` | string |  | owner of a personal server credential (default: you) |
| `--provider` | string |  | Use saved provider configuration by name |
| `--redirect-url` | string |  | Callback URL (default: http://localhost:<oidc.callback_port>/callback) |
| `--scope` | string |  | server credential scope: user (personal, default) or tenant (shared) |
| `--scopes` | string | openid,profile,email | Scopes to request (comma-separated) |
| `--tenant` | string |  | tenant holding the server credential (default: your own) |
| `--token-encoding` | string |  | Token request body encoding: form (default) or json |
| `--token-endpoint` | string |  | Manual token endpoint (skips discovery; requires --authorization-endpoint and --jwks-uri) |
| `--token-store` | string | ~/.xkey/tokens.json | Path to token store |
| `--userinfo-endpoint` | string |  | Manual userinfo endpoint (optional; only used with manual endpoints) |

## xkey oidc logout

Clear stored tokens

Usage: `xkey oidc logout [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--all` | bool | false | Clear all stored tokens |
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--token-store` | string | ~/.xkey/tokens.json | Path to token store |

## xkey oidc providers

Manage OIDC providers

Usage: `xkey oidc providers`

## xkey oidc providers add

Add a provider

Usage: `xkey oidc providers add [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--authorization-endpoint` | string |  | Manual authorization endpoint (skips discovery; requires --token-endpoint and --jwks-uri) |
| `--auto-refresh` | int | 0 | Auto-refresh interval in seconds (0 to disable) |
| `--background` | bool | false | Run auto-refresh in background by default |
| `--callback-host` | string |  | Host the local callback listener binds (default: oidc.callback_host, localhost) |
| `--callback-port` | int | 0 | Port of the default redirect URL (default: oidc.callback_port, 8085) |
| `--client-id` | string |  | OAuth2 client ID (required for type=oidc) |
| `--client-secret` | string |  | OAuth2 client secret (optional) |
| `--credentials-file` | string | ~/.aws/credentials | AWS credentials file path |
| `--cross-device` | bool | false | Enable AWS cross-device authentication |
| `--device-endpoint` | string |  | server credential device authorization endpoint |
| `--device-style` | string |  | server credential device login protocol: rfc8628 (default) or openai |
| `--exec` | string |  | Script to execute after login |
| `--issuer` | string |  | OIDC provider issuer URL (required for type=oidc) |
| `--jwks-uri` | string |  | Manual JWKS URI (skips discovery; requires --authorization-endpoint and --token-endpoint) |
| `--log-file` | string |  | Log file for background refresh |
| `--name` | string |  | Provider name (required) |
| `--output`, `-o` | string | aws-credentials | AWS output mode: aws-credentials, json, exec, none |
| `--owner` | string |  | owner of a personal server credential (default: you) |
| `--profile` | string | default | AWS profile name |
| `--redirect-url` | string |  | Callback URL (default: http://localhost:<oidc.callback_port>/callback) |
| `--region`, `-r` | string |  | AWS region (required for type=aws) |
| `--scope` | string |  | server credential scope: user (personal, default) or tenant (shared) |
| `--scopes` | string |  | Scopes to request (comma-separated) |
| `--session-store` | string | ~/.xkey/aws-session.json | AWS session store path |
| `--template` | string |  | server credential provider template (openai, anthropic, google, ...) |
| `--tenant` | string |  | tenant holding the server credential (default: your own) |
| `--token-encoding` | string |  | Token request body encoding: form (default) or json |
| `--token-endpoint` | string |  | Manual token endpoint (skips discovery; requires --authorization-endpoint and --jwks-uri) |
| `--token-store` | string | ~/.xkey/tokens.json | Path to token store |
| `--type` | string | oidc | Provider type: oidc (default) or aws |
| `--userinfo-endpoint` | string |  | Manual userinfo endpoint (optional; only used with manual endpoints) |

## xkey oidc providers list

List configured providers

Usage: `xkey oidc providers list [flags]`

Aliases: ls

| Flag | Type | Default | Description |
|---|---|---|---|
| `--tenant` | string |  | tenant whose server credentials to list (default: your own) |
| `--token-store` | string | ~/.xkey/tokens.json | Path to token store |

## xkey oidc providers remove

Remove a provider

Usage: `xkey oidc providers remove [name] [flags]`

Aliases: rm, delete

| Flag | Type | Default | Description |
|---|---|---|---|
| `--owner` | string |  | owner of a personal server credential (default: you) |
| `--scope` | string |  | server credential scope: user (personal, default) or tenant (shared) |
| `--tenant` | string |  | tenant holding the server credential (default: your own) |
| `--token-store` | string | ~/.xkey/tokens.json | Path to token store |

## xkey oidc refresh

Refresh access token

Usage: `xkey oidc refresh [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--owner` | string |  | owner of a personal server credential (default: you) |
| `--provider` | string |  | Use saved provider configuration by name (required for manual-endpoint providers) |
| `--scope` | string |  | server credential scope: user (personal, default) or tenant (shared) |
| `--tenant` | string |  | tenant holding the server credential (default: your own) |
| `--token-store` | string | ~/.xkey/tokens.json | Path to token store |

## xkey oidc status

Show running background refresh processes

Usage: `xkey oidc status [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--token-store` | string | ~/.xkey/tokens.json | Path to token store |

## xkey oidc stop

Stop a background refresh process

Usage: `xkey oidc stop [provider] [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--all` | bool | false | Stop all background refresh processes |
| `--token-store` | string | ~/.xkey/tokens.json | Path to token store |

## xkey oidc token

Display current token info

Usage: `xkey oidc token [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--codex-auth-out` | string |  | write a codex auth.json (chatgptAuthTokens mode) for the server credential to this path |
| `--owner` | string |  | owner of a personal server credential (default: you) |
| `--provider` | string |  | server credential name (with an xkmsd configured) |
| `--scope` | string |  | server credential scope: user (personal, default) or tenant (shared) |
| `--show-full` | bool | false | Show full token values |
| `--tenant` | string |  | tenant holding the server credential (default: your own) |
| `--token-store` | string | ~/.xkey/tokens.json | Path to token store |

## xkey password

Static password management

Usage: `xkey password`

## xkey password access-mode

Set password store access mode

Usage: `xkey password access-mode [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--mode` | string |  | Access mode: pin_per_operation or session_based |

## xkey password add

Add a new static password

Usage: `xkey password add [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--charset` | string | all | Password charset: all, alphanumeric |
| `--generate` | bool | false | Generate a random password |
| `--length` | int | 32 | Generated password length |
| `--name` | string |  | Password name (e.g., DatabaseProd) |
| `--notes` | string |  | Optional notes |
| `--password-stdin` | bool | false | Read the password from standard input |
| `--store` | string |  | Path to password store (default: ~/.xkey/data/staticpw) |
| `--title` | string |  | Display title for credential |
| `--url` | string |  | Website URL for domain matching |
| `--username` | string |  | Username or login |

## xkey password get

Get a password by name

Usage: `xkey password get [name] [flags]`

Aliases: show

| Flag | Type | Default | Description |
|---|---|---|---|
| `--store` | string |  | Path to password store (default: ~/.xkey/data/staticpw) |

## xkey password list

List all passwords

Usage: `xkey password list [flags]`

Aliases: ls

| Flag | Type | Default | Description |
|---|---|---|---|
| `--show-passwords` | bool | false | Show password values (requires --source disk) |
| `--source` | string | auto | Where to read state from: auto, daemon, disk |
| `--store` | string |  | Path to password store (default: ~/.xkey/data/staticpw) |

## xkey password lock

Lock the password store

Usage: `xkey password lock`

## xkey password remove

Remove a password

Usage: `xkey password remove [name...] [flags]`

Aliases: rm, delete

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` | bool | false | Skip confirmation prompt |
| `--store` | string |  | Path to password store (default: ~/.xkey/data/staticpw) |

## xkey password status

Show password store status

Usage: `xkey password status [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--source` | string | auto | Where to read state from: auto, daemon, disk, xkmsd |
| `--store` | string |  | Path to password store (default: ~/.xkey/data/staticpw) |

## xkey password type

Type a password via virtual keyboard

Usage: `xkey password type [name]`

Aliases: emit

## xkey password unlock

Open your personal password session

Usage: `xkey password unlock [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--passkey` | bool | false | Unlock with a vault passkey on the attached FIDO2 security key |
| `--passphrase-stdin` | bool | false | Read the vault passphrase from standard input |
| `--pin-stdin` | bool | false | Read the PIN from standard input |

## xkey password vault

Manage your personal password vault on an xkmsd server

Usage: `xkey password vault`

## xkey password vault enroll

Enroll a passphrase or passkey on your personal vault

Usage: `xkey password vault enroll [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--label` | string |  | Label naming the factor (e.g. the device it is used on) |
| `--passkey` | bool | false | Enroll a passkey on the attached FIDO2 security key instead of a passphrase |
| `--passphrase-stdin` | bool | false | Read the vault passphrase from standard input |
| `--pin-stdin` | bool | false | Read the PIN from standard input |

## xkey password vault recover

Enroll a new passphrase or passkey with your one-time recovery code

Usage: `xkey password vault recover [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--label` | string |  | Label naming the new factor |
| `--passkey` | bool | false | Enroll a passkey on the attached FIDO2 security key instead of a passphrase |
| `--passphrase-stdin` | bool | false | Read the vault passphrase from standard input |
| `--pin-stdin` | bool | false | Read the PIN from standard input |
| `--recovery-code-stdin` | bool | false | Read the recovery code from standard input |

## xkey password vault remove

Remove an enrolled factor

Usage: `xkey password vault remove [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--factor-id` | string |  | ID of the factor to remove (see 'xkey password vault status') |

## xkey password vault rotate

Replace the passphrase of an enrolled factor

Usage: `xkey password vault rotate [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--factor-id` | string |  | ID of the factor to rotate (see 'xkey password vault status') |
| `--label` | string |  | New label for the factor (default: keep the current one) |
| `--passphrase-stdin` | bool | false | Read the vault passphrase from standard input |

## xkey password vault status

Show your personal vault status and factors

Usage: `xkey password vault status`

## xkey pin

PIN management

Usage: `xkey pin`

Inherited by subcommands:

| Flag | Type | Default | Description |
|---|---|---|---|
| `--data-dir` | string |  | data directory for PIN state (default: ~/.xkey/data) |
| `--tpm-device` | string |  | TPM device path probed when the governing PIN strategy is tpm2 (default: $TPM_DEVICE_PATH or /dev/tpmrm0) |
| `--tpm-simulator` | bool | false | use the in-process TPM simulator instead of a hardware device (requires a simulator build) |

## xkey pin change-so

Change the SO PIN

Usage: `xkey pin change-so`

## xkey pin change-user

Change the User PIN

Usage: `xkey pin change-user`

## xkey pin reset-lockout

Reset lockout counter (requires SO PIN)

Usage: `xkey pin reset-lockout`

## xkey pin set-so

Set the host PIN service's Security Officer PIN

Usage: `xkey pin set-so`

## xkey pin set-user

Set the User PIN (requires SO PIN)

Usage: `xkey pin set-user`

## xkey pin status

Show PIN and lockout status

Usage: `xkey pin status [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--json` | bool | false | output status as JSON |
| `--source` | string | auto | Where to read state from: auto, daemon, disk |

## xkey pin verify

Verify a PIN

Usage: `xkey pin verify [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--type` | string | user | PIN type to verify: 'so' or 'user' |

## xkey piv

PIV smart card certificate management

Usage: `xkey piv`

Inherited by subcommands:

| Flag | Type | Default | Description |
|---|---|---|---|
| `--backend` | string | software | Key backend: software, tpm2, or pkcs11 |
| `--piv-storage` | string |  | Certificate storage type override: file, tpm2, or pkcs11 (default: matches backend) |
| `--pkcs11-library` | string | /usr/lib/softhsm/libsofthsm2.so | PKCS#11 library path |
| `--pkcs11-pin-stdin` | bool | false | Read the PKCS#11 PIN from standard input |
| `--pkcs11-so-pin-stdin` | bool | false | Read the PKCS#11 Security Officer PIN from standard input |
| `--pkcs11-token` | string |  | PKCS#11 token label |
| `--storage-path` | string |  | Path for file storage (default: ~/.xkey/data/piv, see XKEY_DATA_DIR) |
| `--tpm-device` | string | /dev/tpmrm0 | TPM device path for tpm2 backend/storage |

## xkey piv csr

Generate a CSR for a PIV slot's key

Usage: `xkey piv csr <slot> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--cn` | string |  | Common Name (required) |
| `--country` | string |  | Country code (2 letters) |
| `--locality` | string |  | City or locality |
| `--organization` | string |  | Organization name |
| `--organizational-unit` | string |  | Organizational unit |
| `--output`, `-o` | string |  | Output file (default: stdout) |
| `--province` | string |  | State or province |
| `--san` | stringSlice | [] | Email SAN (can be repeated) |
| `--san-dns` | stringSlice | [] | DNS SAN (can be repeated) |
| `--san-ip` | stringSlice | [] | IP SAN (can be repeated) |
| `--san-uri` | stringSlice | [] | URI SAN (can be repeated) |

## xkey piv delete

Delete certificate from slot

Usage: `xkey piv delete <slot> [flags]`

Aliases: rm, remove

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` | bool | false | Don't prompt for confirmation |

## xkey piv export

Export certificate from slot

Usage: `xkey piv export <slot> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--format` | string | pem | Export format: pem or der |
| `--output` | string |  | Output file path (default: stdout) |

## xkey piv generate

Generate a key pair in a PIV slot

Usage: `xkey piv generate <slot> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--algorithm`, `-a` | string | ECCP256 | Key algorithm (ECCP256, ECCP384, Ed25519, RSA2048, RSA4096) |
| `--country` | string |  | X.509 Country (2-letter ISO code) for certificate subject |
| `--force`, `-f` | bool | false | Overwrite existing key without confirmation |
| `--organization` | string |  | X.509 Organization for certificate subject |
| `--output`, `-o` | string |  | Output file for CSR or public key (default: stdout) |
| `--output-format` | string | self-signed | Output format: self-signed, public-key, csr, ca-signed |
| `--pin-policy` | string | once | PIN policy (never, once, always) |
| `--subject` | string |  | Certificate subject CN (default: slot name) |
| `--touch-policy` | string | never | Touch policy (never, cached, always) |
| `--validity-days` | int | 0 | Certificate validity in days (0 = default) |

## xkey piv import

Import a certificate into a PIV slot

Usage: `xkey piv import <slot> <cert-file> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force`, `-f` | bool | false | Import even if verification fails |
| `--verify` | bool | true | Verify certificate matches slot's public key |

## xkey piv list

List certificates in all slots

Usage: `xkey piv list`

Aliases: ls

## xkey piv phone-generate

Generate key in a PIV slot on a paired phone

Usage: `xkey piv phone-generate <slot> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--algorithm`, `-a` | string | ECDSA-P256 | Key algorithm (ECDSA-P256, ECDSA-P384, RSA-2048) |
| `--device` | string |  | Paired device name |
| `--timeout` | duration | 1m0s | Operation timeout |

## xkey piv phone-list

List PIV slots on a paired phone

Usage: `xkey piv phone-list [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--device` | string |  | Paired device name |
| `--timeout` | duration | 1m0s | Operation timeout |

## xkey piv phone-pull-cert

Pull certificate from a PIV slot on a paired phone

Usage: `xkey piv phone-pull-cert <slot> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--device` | string |  | Paired device name |
| `--output` | string |  | Output file path (default: stdout) |
| `--timeout` | duration | 1m0s | Operation timeout |

## xkey piv phone-push-cert

Push certificate to a PIV slot on a paired phone

Usage: `xkey piv phone-push-cert <slot> <cert-file> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--device` | string |  | Paired device name |
| `--timeout` | duration | 1m0s | Operation timeout |

## xkey piv show

Show certificate details for a slot

Usage: `xkey piv show <slot>`

## xkey piv status

Show PIV storage status

Usage: `xkey piv status`

## xkey piv store

Store certificate in slot

Usage: `xkey piv store <slot> <cert-file>`

## xkey platform-store

Manage sealed secrets in the platform store

Usage: `xkey platform-store`

Inherited by subcommands:

| Flag | Type | Default | Description |
|---|---|---|---|
| `--tls-ca` | string |  | TLS CA certificate file used to verify the xkmsd server |

## xkey platform-store delete

Delete a secret from the platform store

Usage: `xkey platform-store delete <name>`

Aliases: rm

## xkey platform-store get

Retrieve a secret from the platform store

Usage: `xkey platform-store get <name> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--output` | string |  | Write secret to file instead of stdout |

## xkey platform-store list

List all secrets in the platform store

Usage: `xkey platform-store list`

Aliases: ls

## xkey platform-store put

Store a secret in the platform store

Usage: `xkey platform-store put <name> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--file` | string |  | Path to file containing the secret |
| `--value-stdin` | bool | false | Read the secret value from standard input |

## xkey platform-store reseal

Reseal a secret with the current sealing key

Usage: `xkey platform-store reseal [name] [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--all` | bool | false | Reseal all secrets |

## xkey platform-store status

Show platform store status

Usage: `xkey platform-store status`

## xkey provision

Provision a fresh xkey instance for one agent

Usage: `xkey provision [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--agent` | string |  | the agent's display name (required) |
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--chrome-profile-dir` | string |  | also pair a Chrome profile with this instance (see 'xkey extension install chrome --profile-dir') |
| `--force` | bool | false | provision a home that is already initialized |
| `--home` | string |  | xkey home to provision (default: XKEY_HOME; one of the two is required) |
| `--json` | bool | false | print the report as JSON |
| `--pin-stdin` | bool | false | Read the PIN from standard input |
| `--so-pin-stdin` | bool | false | Read the SO PIN from standard input |

## xkey secret-service

Run the freedesktop Secret Service daemon (org.freedesktop.secrets)

Usage: `xkey secret-service [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--barrier-password-file` | string |  | Read barrier password from file (first line) |
| `--barrier-password-stdin` | bool | false | Read the barrier password from standard input |
| `--bus` | string | session | D-Bus bus to own org.freedesktop.secrets on (session or system) |
| `--data-dir` | string |  | data directory for barrier storage (default: ~/.xkey/data) |
| `--strategy` | string |  | barrier seal strategy override (default: the strategy the barrier was initialized with) |
| `--tpm-device` | string |  | TPM device path for the tpm2 strategy (default: $TPM_DEVICE_PATH or /dev/tpmrm0) |
| `--tpm-simulator` | bool | false | use the in-process TPM simulator instead of a hardware device (requires a simulator build) |

## xkey share

Manage Shamir secret shares

Usage: `xkey share`

Inherited by subcommands:

| Flag | Type | Default | Description |
|---|---|---|---|
| `--tls-ca` | string |  | PEM CA bundle used to verify the xkmsd server |

## xkey share delete

Delete a locally stored share

Usage: `xkey share delete [flags]`

Aliases: rm

| Flag | Type | Default | Description |
|---|---|---|---|
| `--group-id` | string |  | Custodian group ID |
| `--server` | string |  | xkmsd server URL that issued the share |
| `--share-index` | int | 0 | 1-based share index within the group |

## xkey share export

Export a share to a JSON file

Usage: `xkey share export [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--file` | string |  | Output path for the exported share JSON |
| `--group-id` | string |  | Custodian group ID |
| `--server` | string |  | xkmsd server URL that issued the share |
| `--share-index` | int | 0 | 1-based share index within the group |

## xkey share import

Import a share from a JSON file

Usage: `xkey share import [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--file` | string |  | Path to JSON file containing the share |

## xkey share list

List locally stored shares

Usage: `xkey share list`

Aliases: ls

## xkey share receive

Receive shares from a server

Usage: `xkey share receive [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--server` | string |  | xkmsd server URL (e.g., grpc://host:9090) |

## xkey share unseal

Submit a share to unseal the server barrier

Usage: `xkey share unseal [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--group-id` | string |  | Custodian group ID |
| `--server` | string |  | xkmsd server URL to submit the share to |
| `--share-index` | int | 0 | 1-based share index within the group |

## xkey ssh

SSH key, host-key, and authorized-key management

Usage: `xkey ssh`

Inherited by subcommands:

| Flag | Type | Default | Description |
|---|---|---|---|
| `--server` | string |  | Remote xkmsd URL (e.g. grpcs://host:9443, quic://host:8444, unix:///path/xkms.sock) |
| `--tls-ca` | string |  | TLS CA certificate file used to verify the server |

## xkey ssh authorized-keys

Authorized-key management

Usage: `xkey ssh authorized-keys`

Aliases: authorized

## xkey ssh authorized-keys add

Add an authorized_keys line

Usage: `xkey ssh authorized-keys add [line] [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--name` | string |  | Entry name (required) |
| `--owner` | string |  | Owner identifier — defaults to $USER |
| `--scope` | string |  | Scope — defaults to user |

## xkey ssh authorized-keys list

List authorized_keys entries

Usage: `xkey ssh authorized-keys list [flags]`

Aliases: ls

| Flag | Type | Default | Description |
|---|---|---|---|
| `--owner` | string |  | Owner identifier — defaults to $USER |
| `--scope` | string |  | Scope — defaults to user |

## xkey ssh authorized-keys remove

Remove an authorized_keys entry

Usage: `xkey ssh authorized-keys remove [flags]`

Aliases: rm, delete

| Flag | Type | Default | Description |
|---|---|---|---|
| `--name` | string |  | Entry name (required) |
| `--owner` | string |  | Owner identifier — defaults to $USER |
| `--scope` | string |  | Scope — defaults to user |

## xkey ssh connect

Open an SSH session in the current terminal using an xkey key

Usage: `xkey ssh connect [profile|user@host] [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--identity` | string |  | Local identity to authenticate with: an identity file path (passed to ssh as -i) or agent:<SHA256-fingerprint> for an agent-held key (implies --local) |
| `--key` | string |  | SSH key name to authenticate with |
| `--key-owner` | string |  | Key owner (defaults to local for GUI keys, $USER for CLI keys) |
| `--key-scope` | string | user | Key scope |
| `--known-hosts-policy` | string | barrier | Where to record host-key pins: barrier\|system\|both |
| `--local` | bool | false | Authenticate using the local ssh-agent/~/.ssh identities instead of an xkey-managed key (plain passthrough `ssh`, no in-process agent) |
| `--port` | int | 0 | Target port (default 22) |
| `--ssh-config-alias` | string |  | ssh_config(5) Host alias to connect through (implies --local) |
| `--user` | string |  | Remote user (for user@host targets without an inline user) |

## xkey ssh console

Open an interactive SSH console in the current terminal

Usage: `xkey ssh console [profile|user@host] [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--identity` | string |  | Local identity to authenticate with: an identity file path or agent:<SHA256-fingerprint> (implies --local) |
| `--key` | string |  | SSH key name to authenticate with |
| `--key-owner` | string |  | Key owner (defaults to local) |
| `--key-scope` | string | user | Key scope |
| `--local` | bool | false | Authenticate using the local ssh-agent/~/.ssh identities instead of an xkey-managed key |
| `--port` | int | 0 | Target port (default 22) |
| `--user` | string |  | Remote user |

## xkey ssh host-keys

SSH host-key pin management

Usage: `xkey ssh host-keys`

Aliases: known-hosts

## xkey ssh host-keys add

Add (pin) a host key

Usage: `xkey ssh host-keys add [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--file` | string |  | Read the host key from a file instead of --key |
| `--host` | string |  | Target host (required) |
| `--key` | string |  | Host key as an authorized_keys-format line (required unless --file) |
| `--owner` | string |  | Owner identifier — defaults to $USER |
| `--scope` | string |  | Scope — defaults to user |
| `--source` | string |  | Provenance tag (manual, cert, ...) |

## xkey ssh host-keys list

List pinned host keys

Usage: `xkey ssh host-keys list [flags]`

Aliases: ls

| Flag | Type | Default | Description |
|---|---|---|---|
| `--owner` | string |  | Owner identifier — defaults to $USER |
| `--scope` | string |  | Scope — defaults to user |

## xkey ssh host-keys remove

Remove a pinned host key

Usage: `xkey ssh host-keys remove [flags]`

Aliases: rm, delete

| Flag | Type | Default | Description |
|---|---|---|---|
| `--host` | string |  | Target host (required) |
| `--owner` | string |  | Owner identifier — defaults to $USER |
| `--scope` | string |  | Scope — defaults to user |

## xkey ssh keys

SSH key management

Usage: `xkey ssh keys`

## xkey ssh keys delete

Delete an SSH key

Usage: `xkey ssh keys delete [flags]`

Aliases: rm, remove

| Flag | Type | Default | Description |
|---|---|---|---|
| `--name` | string |  | Key name (required) |
| `--owner` | string |  | Owner identifier — defaults to $USER |
| `--scope` | string |  | Scope (tenant\|user\|service) — defaults to user |

## xkey ssh keys export

Print the authorized_keys-format public half

Usage: `xkey ssh keys export [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--name` | string |  | Key name (required) |
| `--owner` | string |  | Owner identifier — defaults to $USER |
| `--scope` | string |  | Scope (tenant\|user\|service) — defaults to user |

## xkey ssh keys generate

Generate a new SSH key

Usage: `xkey ssh keys generate [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--backend` | string |  | Crypto backend to generate the key on (software, tpm2, pkcs11, cloud); empty uses the server/embedded default |
| `--bits` | int | 0 | RSA key size (default 4096 for rsa) |
| `--comment` | string |  | Free-form key comment |
| `--name` | string |  | Key name (required) |
| `--owner` | string |  | Owner identifier — defaults to $USER |
| `--scope` | string |  | Scope (tenant\|user\|service) — defaults to user |
| `--type` | string | ed25519 | Key algorithm (ed25519, rsa, ecdsa-p256, ecdsa-p384, ecdsa-p521) |

## xkey ssh keys get

Show metadata for a single SSH key

Usage: `xkey ssh keys get [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--name` | string |  | Key name (required) |
| `--owner` | string |  | Owner identifier — defaults to $USER |
| `--scope` | string |  | Scope (tenant\|user\|service) — defaults to user |

## xkey ssh keys import

Import an existing PEM-encoded SSH private key

Usage: `xkey ssh keys import [file] [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--comment` | string |  | Free-form key comment |
| `--name` | string |  | Key name (defaults to the imported file's basename) |
| `--owner` | string |  | Owner identifier — defaults to $USER |
| `--scope` | string |  | Scope (tenant\|user\|service) — defaults to user |

## xkey ssh keys list

List SSH keys

Usage: `xkey ssh keys list [flags]`

Aliases: ls

| Flag | Type | Default | Description |
|---|---|---|---|
| `--owner` | string |  | Owner identifier — defaults to $USER |
| `--scope` | string |  | Scope (tenant\|user\|service) — defaults to user |

## xkey ssh local

Discover local ssh_config hosts and ssh-agent/~/.ssh identities

Usage: `xkey ssh local`

## xkey ssh local hosts

List Host aliases resolved from ssh_config(5)

Usage: `xkey ssh local hosts`

Aliases: ls

## xkey ssh local keys

List keys visible via the local ssh-agent and ~/.ssh

Usage: `xkey ssh local keys`

## xkey ssh profile

Manage saved SSH connection profiles

Usage: `xkey ssh profile`

## xkey ssh profile add

Add an SSH connection profile

Usage: `xkey ssh profile add [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--folder` | string |  | Folder path (e.g. work/prod) |
| `--host` | string |  | Target host (required) |
| `--identity` | string |  | Local identity pin: an identity file path or agent:<SHA256-fingerprint> (implies --key-source=local) |
| `--key` | string |  | SSH key name |
| `--key-owner` | string |  | Key owner (defaults to local) |
| `--key-scope` | string | user | Key scope |
| `--key-source` | string |  | Authentication key source: "" (xkey-managed, default) or "local" (ssh-agent/~/.ssh) |
| `--name` | string |  | Profile name (required) |
| `--notes` | string |  | Free-form notes |
| `--persist-session` | bool | false | Record embedded-console sessions from this profile in the persistent session store (GUI tabs restored after reload/restart; default memory-only) |
| `--port` | int | 22 | Target port |
| `--ssh-config-alias` | string |  | ssh_config(5) Host alias to connect through when --key-source=local (implies --key-source=local) |
| `--user` | string |  | Remote user |

## xkey ssh profile get

Show an SSH connection profile

Usage: `xkey ssh profile get [name]`

## xkey ssh profile list

List SSH connection profiles

Usage: `xkey ssh profile list [flags]`

Aliases: ls

| Flag | Type | Default | Description |
|---|---|---|---|
| `--folder` | string |  | Limit to a folder (and its subfolders) |

## xkey ssh profile mv

Move a profile to a different folder

Usage: `xkey ssh profile mv [name] [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--folder` | string |  | Destination folder (required) |

## xkey ssh profile remove

Delete an SSH connection profile

Usage: `xkey ssh profile remove [name]`

Aliases: rm, delete

## xkey ssh sessions

Manage persistent embedded-console sessions

Usage: `xkey ssh sessions`

Aliases: session

## xkey ssh sessions list

List persistent console sessions

Usage: `xkey ssh sessions list`

Aliases: ls

## xkey ssh sessions remove

Delete a persistent console session record

Usage: `xkey ssh sessions remove [id]`

Aliases: rm, delete

## xkey touch

Approve pending user presence or type a password

Usage: `xkey touch [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--password` | string |  | Name of password to type |

## xkey tpm

TPM 2.0 operations

Usage: `xkey tpm`

Inherited by subcommands:

| Flag | Type | Default | Description |
|---|---|---|---|
| `--device` | string | /dev/tpmrm0 | TPM device path |
| `--hierarchy-auth` | string |  | Hierarchy authorization password |
| `--output`, `-o` | string | text | Output format (text, json) |
| `--simulator` | bool | false | Use TPM simulator instead of hardware TPM |
| `--verbose`, `-v` | bool | false | Enable verbose output |

## xkey tpm authority

TPM policy authority

Usage: `xkey tpm authority`

## xkey tpm authority rotate

Replace the policy authority

Usage: `xkey tpm authority rotate`

## xkey tpm clear

Clear TPM state

Usage: `xkey tpm clear [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` | bool | false | Force TPM clear via UEFI PPI (requires root, triggers reboot) |
| `--hierarchy` | string | lockout | Authorization hierarchy for standard clear (lockout, owner, platform) |
| `--lockout-auth` | string |  | Lockout hierarchy authorization password |
| `--yes`, `-y` | bool | false | Skip confirmation prompt |

## xkey tpm ek

Endorsement Key (EK) operations

Usage: `xkey tpm ek`

## xkey tpm ek backup

Backup all EK certificates to files

Usage: `xkey tpm ek backup [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--output` | string | . | Output directory for backup files |

## xkey tpm ek export

Export EK certificate to file

Usage: `xkey tpm ek export [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--ec` | bool | false | Export EC EK certificate instead of RSA (default) |
| `--output` | string |  | Output file path (use '-' for stdout) |

## xkey tpm ek restore

Restore EK certificate from backup (CAUTION)

Usage: `xkey tpm ek restore [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--ec` | bool | false | Restore EC EK certificate instead of RSA (default) |
| `--force` | bool | false | Force restore without public key verification |
| `--input` | string |  | Input PEM file containing EK certificate |

## xkey tpm ek show

Display EK public key and certificate

Usage: `xkey tpm ek show [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--ec` | bool | false | Show EC EK certificate instead of RSA (default) |

## xkey tpm iak

Initial Attestation Key (IAK) operations

Usage: `xkey tpm iak`

## xkey tpm iak create

Create a new IAK

Usage: `xkey tpm iak create [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` | bool | false | Force recreation even if IAK already exists |
| `--template` | string | rsa2048 | Key template (rsa2048, rsa-pss, ecc256) |

## xkey tpm iak csr

Generate CSR for IAK certificate

Usage: `xkey tpm iak csr [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--output` | string |  | Output file path for CSR |
| `--subject` | string |  | CSR subject (e.g., 'CN=device-001,O=Example') |

## xkey tpm iak export

Export IAK certificate to file

Usage: `xkey tpm iak export [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--output` | string |  | Output file path (use '-' for stdout) |

## xkey tpm iak show

Display IAK public key and certificate

Usage: `xkey tpm iak show`

## xkey tpm idevid

Initial Device Identifier (IDevID) operations

Usage: `xkey tpm idevid`

## xkey tpm idevid cert

IDevID certificate operations

Usage: `xkey tpm idevid cert`

## xkey tpm idevid cert import

Import signed IDevID certificate

Usage: `xkey tpm idevid cert import [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--cert` | string |  | Path to PEM-encoded certificate file |
| `--force` | bool | false | Force import without public key verification |

## xkey tpm idevid create

Create a new IDevID

Usage: `xkey tpm idevid create [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--force` | bool | false | Force recreation even if IDevID already exists |
| `--model` | string |  | Device model name |
| `--serial` | string |  | Device serial number |
| `--template` | string | rsa2048 | Key template (rsa2048, rsa-pss, ecc256) |

## xkey tpm idevid csr

Generate CSR for IDevID certificate

Usage: `xkey tpm idevid csr [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--output` | string |  | Output file path for CSR |
| `--subject` | string |  | CSR subject (e.g., 'CN=device-001,O=Example') |

## xkey tpm idevid csr export

Export IDevID CSR in PEM format

Usage: `xkey tpm idevid csr export [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--country` | string |  | Country code (overrides OpenSSL config) |
| `--locality` | string |  | City/Locality (overrides OpenSSL config) |
| `--organization` | string |  | Organization name (overrides OpenSSL config) |
| `--organizational-unit` | string |  | Organizational unit (overrides OpenSSL config) |
| `--output` | string |  | Output file path for CSR (use '-' for stdout) |
| `--province` | string |  | State/Province (overrides OpenSSL config) |

## xkey tpm idevid export

Export IDevID certificate to file

Usage: `xkey tpm idevid export [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--output` | string |  | Output file path (use '-' for stdout) |

## xkey tpm idevid show

Display IDevID key and certificate

Usage: `xkey tpm idevid show`

## xkey tpm info

Display TPM information

Usage: `xkey tpm info`

## xkey tpm install

Safely install xKey TPM keys (preserves manufacturer keys)

Usage: `xkey tpm install [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--auth` | string |  | Hierarchy authorization password to set |
| `--golden-pcrs` | string |  | Comma-separated list of PCR indices for golden measurement (e.g., "0,1,2,7") |
| `--pcr-bank` | string |  | Override the platform PCR bank (e.g., sha256, sha384) |
| `--platform-pcr` | int | 0 | Override which PCR to extend with golden measurement (e.g., 16) |

## xkey tpm pcrs

Display PCR values

Usage: `xkey tpm pcrs [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--bank` | string |  | PCR bank to display (sha1, sha256, sha384, sha512) |
| `--indices` | string |  | Comma-separated list of PCR indices (default: 0-23) |

## xkey tpm policy

Named TPM policies

Usage: `xkey tpm policy`

## xkey tpm policy auto-unseal

Set or clear the barrier auto-unseal policy

Usage: `xkey tpm policy auto-unseal [name] [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--off` | bool | false | Clear the auto-unseal policy |

## xkey tpm policy create

Create a named policy over the live PCR values

Usage: `xkey tpm policy create <name> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--auto-unseal` | bool | false | Also make it the barrier auto-unseal policy (see 'tpm policy auto-unseal') |
| `--bank` | string |  | PCR bank of --pcrs: sha1, sha256, sha384 or sha512 (default sha256) |
| `--branch` | stringArray | [] | A policy branch, e.g. 'pcr=sha256:0,7;auth_value;locality=0' (repeatable) |
| `--description` | string |  | Free-text description of the policy |
| `--pcrs` | string |  | PCR indices of a one-branch policy, e.g. 0,7 or 0-7 |

## xkey tpm policy delete

Delete a policy no object uses

Usage: `xkey tpm policy delete <name>`

Aliases: rm

## xkey tpm policy describe

Set a policy's description

Usage: `xkey tpm policy describe <name> <text>`

## xkey tpm policy get

Show a policy and its captured PCR values

Usage: `xkey tpm policy get <name>`

## xkey tpm policy key

Show the policy a TPM key is bound to

Usage: `xkey tpm policy key <key-id>`

## xkey tpm policy list

List policies with their object counts

Usage: `xkey tpm policy list`

Aliases: ls

## xkey tpm policy objects

List the keys and sealed objects bound to a policy

Usage: `xkey tpm policy objects <name>`

## xkey tpm policy revoke

Withdraw the policy's approval

Usage: `xkey tpm policy revoke <name>`

## xkey tpm policy update

Re-capture the PCR values and re-approve the policy

Usage: `xkey tpm policy update <name>`

## xkey tpm policy verify

Compare the live PCRs with the captured ones

Usage: `xkey tpm policy verify <name>`

## xkey tpm provision

Full TPM provisioning (DESTRUCTIVE - clears TPM)

Usage: `xkey tpm provision [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--auth` | string |  | Hierarchy authorization password to set |
| `--confirm` | bool | false | Confirm that you want to destroy manufacturer keys (REQUIRED) |
| `--golden-pcrs` | string |  | Comma-separated list of PCR indices for golden measurement (e.g., "0,1,2,7") |
| `--pcr-bank` | string |  | Override the platform PCR bank (e.g., sha256, sha384) |
| `--platform-pcr` | int | 0 | Override which PCR to extend with golden measurement (e.g., 16) |

## xkey tpm quote

Generate TPM quote for attestation

Usage: `xkey tpm quote [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--include-log` | bool | false | Include event log in output (when available) |
| `--nonce` | string |  | Nonce value (hex-encoded, will be generated if not provided) |
| `--output` | string |  | Output file path for quote data |
| `--pcrs` | string | 0,1,7 | Comma-separated list of PCR indices to include |

## xkey tpm status

Display TPM provisioning status

Usage: `xkey tpm status`

## xkey trust

Trust store management

Usage: `xkey trust`

## xkey trust add

Add certificates from PEM file

Usage: `xkey trust add <pem-file> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--purpose` | string |  | certificate purpose (general, tpm-manufacturer, android-hardware, user-ca, bootstrap-ca, idevid-issuer, synced) |
| `--source` | string |  | source of the certificate (e.g., manual, url:..., file:...) |

## xkey trust bootstrap

Bootstrap trust store from server

Usage: `xkey trust bootstrap [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--method` | stringSlice | [] | bootstrap methods to try (dane,noise,spki,direct) |
| `--timeout` | duration | 1m0s | overall timeout for bootstrap operation |

## xkey trust classify

Reclassify a certificate's purpose

Usage: `xkey trust classify <fingerprint> --purpose <purpose> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--purpose` | string |  | certificate purpose (required) |

## xkey trust fetch

Fetch a CA bundle from a platform node (SPKI-pinned)

Usage: `xkey trust fetch <url> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--install-system` | bool | false | after adding to xKey trust store, install root certificates to OS trust store |
| `--purpose` | string | bootstrap-ca | certificate purpose (default: bootstrap-ca) |
| `--source` | string |  | override the recorded source (default: "platform:<host>") |
| `--spki-pin` | string |  | SPKI SHA-256 hash (64-char hex) of the server's leaf certificate (required) |
| `--timeout` | duration | 30s | HTTP transaction timeout |

## xkey trust import-platform

Import a platform node's CA bundle (canonical URL, SPKI-pinned)

Usage: `xkey trust import-platform <host:port> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--install-system` | bool | false | after adding to xKey trust store, install root certificates to OS trust store |
| `--purpose` | string | bootstrap-ca | certificate purpose (default: bootstrap-ca) |
| `--source` | string |  | override the recorded source (default: "platform:<host>") |
| `--spki-pin` | string |  | SPKI SHA-256 hash (64-char hex) of the server's leaf certificate (required) |
| `--timeout` | duration | 30s | HTTP transaction timeout |

## xkey trust install

Install certificate to OS trust store

Usage: `xkey trust install <fingerprint>`

## xkey trust list

List trusted certificates

Usage: `xkey trust list`

Aliases: ls

## xkey trust remove

Remove a trusted certificate

Usage: `xkey trust remove <fingerprint>`

Aliases: rm, delete

## xkey trust show

Show certificate details

Usage: `xkey trust show <fingerprint>`

## xkey trust uninstall

Remove certificate from OS trust store

Usage: `xkey trust uninstall <fingerprint>`

## xkey unlock

Unlock a running xKey instance

Usage: `xkey unlock [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--pin-stdin` | bool | false | Read the PIN from standard input |

## xkey usb

USB disk image management

Usage: `xkey usb`

## xkey usb create

Create a USB image or prepare a USB device

Usage: `xkey usb create <device-or-image> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--binary` | stringArray | [] | Path to xKey binary to include (repeatable). Defaults to current binary. |
| `--size` | string | 4G | Total image size (e.g., 1G, 4G, 8G). Ignored for block devices. |

## xkey usb device

Virtual USB device management

Usage: `xkey usb device`

## xkey usb device start

Start the virtual CCID smartcard device

Usage: `xkey usb device start [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--device-backend` | string | software | PKCS#11 backend: software, tpm2, or pkcs11 |
| `--transport` | string | uhid | USB transport: uhid or gadget |
| `--udc` | string |  | UDC controller name for gadget mode (auto-detect if empty) |

## xkey usb device status

Show virtual CCID device status

Usage: `xkey usb device status`

## xkey usb device stop

Stop the virtual CCID smartcard device

Usage: `xkey usb device stop`

## xkey usb status

Show status of a USB image or device

Usage: `xkey usb status [device-or-image]`

## xkey usb update

Update xKey binaries on a USB image or device

Usage: `xkey usb update <device-or-image> [flags]`

| Flag | Type | Default | Description |
|---|---|---|---|
| `--binary` | stringArray | [] | Path to xKey binary to include (repeatable). Defaults to current binary. |

## xkey version

Show version information

Usage: `xkey version`

Aliases: v

