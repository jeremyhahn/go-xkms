# Credential Seal Strategies

How go-xkms protects the User PIN and other operational credentials at rest.

## Overview

During `xkmsd init`, the PKCS#11 User PIN is set on each backend token. The User PIN is required at every server startup to authenticate to the token and perform key operations. The **credential seal strategy** determines how this PIN is protected between restarts.

The SO PIN is **never stored** by go-xkms. It is verified against the actual PKCS#11 backend during init and during SO-authenticated operations. An SO must supply it interactively each time.

## Seal Strategies

| Strategy | Storage | Security Level | Use Case |
|----------|---------|---------------|----------|
| `manual` | Not stored | Highest | Operator enters PIN at every startup |
| `barrier` | Barrier-encrypted blob | High | Auto-start after barrier unseal |
| `tpm2` | TPM2-sealed blob | High | Hardware-bound, auto-start with TPM |
| `pkcs11` | HSM-wrapped blob | High | HSM-bound, auto-start with HSM |
| `aws_kms` | AWS KMS envelope encryption | High | Cloud-native, auto-start with IAM |
| `gcp_kms` | GCP KMS envelope encryption | High | Cloud-native, auto-start with SA |
| `azure_kv` | Azure KV envelope encryption | High | Cloud-native, auto-start with MI |
| `vault` | Vault transit encryption | High | HashiCorp Vault-backed |
| `software` | Password-encrypted file | Medium | Development, testing |

### Default: `manual`

The User PIN is not stored anywhere. An operator must enter it at every server startup. This is the most secure option and the default.

```yaml
credentials:
  seal_strategy: manual
```

Server startup with manual strategy:

```bash
$ xkmsd start --config /etc/xkms/xkmsd.yaml
Enter User PIN: ********
Server started on :8443
```

### Opt-In: `barrier`

The User PIN is encrypted with the barrier's AES-256-GCM root key and stored as a blob in the data directory. The PIN is automatically available after the barrier is unsealed.

```yaml
credentials:
  seal_strategy: barrier
```

Startup flow:

```
1. xkmsd start
2. Barrier unseal (manual or M-of-N shares)
3. User PIN auto-decrypted from barrier
4. PKCS#11 token login with decrypted PIN
5. Server operational
```

### Opt-In: `tpm2`

The User PIN is sealed to the TPM2 using a PCR policy. The PIN can only be recovered if the platform is in the expected state (boot chain integrity).

```yaml
credentials:
  seal_strategy: tpm2
  tpm2:
    device_path: /dev/tpmrm0
    pcr_selection: [0, 7]     # Seal to firmware + secure boot PCRs
    srk_handle: 0x81000001
```

### Opt-In: `pkcs11`

The User PIN is wrapped with a key stored on a separate PKCS#11 token. This is useful when a dedicated "credential HSM" protects operational credentials.

```yaml
credentials:
  seal_strategy: pkcs11
  pkcs11:
    library_path: /usr/lib/softhsm/libsofthsm2.so
    token_label: credential-hsm
    key_label: pin-wrap-key
```

### Opt-In: Cloud KMS

The User PIN is envelope-encrypted using a cloud KMS key. The server must have IAM credentials to decrypt at startup.

```yaml
# AWS KMS
credentials:
  seal_strategy: aws_kms
  aws_kms:
    region: us-east-1
    key_id: arn:aws:kms:us-east-1:123456789012:key/...

# GCP KMS
credentials:
  seal_strategy: gcp_kms
  gcp_kms:
    project_id: my-project
    location: us-central1
    key_ring: credentials
    key_name: pin-seal

# Azure Key Vault
credentials:
  seal_strategy: azure_kv
  azure_kv:
    vault_url: https://my-vault.vault.azure.net/
    key_name: pin-seal
```

### Opt-In: `vault`

The User PIN is encrypted using HashiCorp Vault's transit secrets engine.

```yaml
credentials:
  seal_strategy: vault
  vault:
    address: https://vault.example.com:8200
    transit_key: xkms-pin-seal
    auth_method: approle
```

### Opt-In: `software`

The User PIN is encrypted with a password-derived key (Argon2id) and stored as a file. Suitable for development and testing only.

```yaml
credentials:
  seal_strategy: software
  software:
    key_file: /var/lib/xkms/credential-key.enc
```

## CredentialService Architecture

The `CredentialService` provides a unified interface for storing and retrieving sealed credentials, regardless of the underlying seal strategy.

```
xkmsd init / xkmsd start
        |
        v
 CredentialService
        |
        +-- Resolve seal strategy from config
        |
        v
 CredentialSealer (interface)
        |
        +-- ManualSealer       (returns ErrManualPINRequired)
        +-- BarrierSealer      (delegates to barrier)
        +-- TPM2Sealer         (delegates to TPM2)
        +-- PKCS11Sealer       (delegates to PKCS#11)
        +-- AWSKMSSealer       (delegates to AWS KMS)
        +-- GCPKMSSealer       (delegates to GCP KMS)
        +-- AzureKVSealer      (delegates to Azure KV)
        +-- VaultSealer        (delegates to Vault)
        +-- SoftwareSealer     (password-based encryption)
```

### CredentialSealer Interface

```go
type CredentialSealer interface {
    // Seal encrypts a credential for at-rest storage.
    Seal(ctx context.Context, name string, plaintext []byte) ([]byte, error)

    // Unseal decrypts a previously sealed credential.
    Unseal(ctx context.Context, name string, ciphertext []byte) ([]byte, error)

    // Strategy returns the seal strategy identifier.
    Strategy() string
}
```

### Credential Names

Credentials are identified by name. The following names are used by the init system:

| Name | Description |
|------|-------------|
| `pkcs11-user-pin` | PKCS#11 User PIN for token authentication |
| `tpm2-auth-value` | TPM2 authorization value (if applicable) |
| `barrier-root-key` | Barrier root key (sealed via M-of-N, not via CredentialService) |

### External Credential Submission

Operators can submit credentials via CLI after init:

```bash
# Submit User PIN for a backend that was initialized externally
xkmsctl credential submit --server https://xkmsd:8443 \
  --name "pkcs11-user-pin" --value "user123"
```

This is useful when the credential seal strategy is `barrier` or another auto-seal method, and the operator wants to store the credential for auto-start after barrier unseal.

## Configuration Reference

### Full credentials section

```yaml
credentials:
  # How to protect the User PIN at rest.
  # Default: manual (operator enters PIN at every startup)
  seal_strategy: manual    # manual | barrier | tpm2 | pkcs11 | aws_kms | gcp_kms | azure_kv | vault | software

  # Strategy-specific configuration (only the selected strategy is used)

  tpm2:
    device_path: /dev/tpmrm0
    pcr_selection: [0, 7]
    srk_handle: 0x81000001

  pkcs11:
    library_path: /usr/lib/softhsm/libsofthsm2.so
    token_label: credential-hsm
    key_label: pin-wrap-key

  aws_kms:
    region: us-east-1
    key_id: arn:aws:kms:us-east-1:123456789012:key/...

  gcp_kms:
    project_id: my-project
    location: us-central1
    key_ring: credentials
    key_name: pin-seal

  azure_kv:
    vault_url: https://my-vault.vault.azure.net/
    key_name: pin-seal

  vault:
    address: https://vault.example.com:8200
    transit_key: xkms-pin-seal
    auth_method: approle

  software:
    key_file: /var/lib/xkms/credential-key.enc
```

## Decision Guide

```
Do you need unattended restarts?
  |
  +-- No  --> manual (default, most secure)
  |
  +-- Yes --> Is a barrier always unsealed before token login?
                |
                +-- Yes --> barrier
                |
                +-- No  --> Is TPM2 available?
                              |
                              +-- Yes --> tpm2
                              |
                              +-- No  --> Is a cloud KMS available?
                                            |
                                            +-- Yes --> aws_kms | gcp_kms | azure_kv
                                            |
                                            +-- No  --> Is Vault available?
                                                          |
                                                          +-- Yes --> vault
                                                          |
                                                          +-- No  --> software (dev only)
```

## Related Documentation

- [Init System Overview](README.md)
- [Init Ceremony](ceremony.md)
- [Threshold Architecture](threshold.md)
- [FIPS Roles](roles.md)
- [Configuration](../configuration/README.md)
