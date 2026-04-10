# Backend Security Levels

go-xkms assigns security levels to backends based on key protection strength. This enables the UI/CLI to automatically recommend the most secure available backend and sort options by security preference.

## Security Level Values

| Level | Value | Backends | Key Protection |
|-------|-------|----------|----------------|
| VeryHigh | 3 | TPM 2.0 | Hardware-bound, non-exportable, attestable |
| High | 2 | PKCS#11, Phone (TEE/StrongBox) | HSM-protected, local hardware control |
| Medium | 1 | AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault | Cloud-managed, network-dependent HSMs |
| Low | 0 | Software | File-based, software-protected encryption |

## Level Descriptions

### SecurityLevelVeryHigh (3) - TPM 2.0

Keys are generated in and never leave the Trusted Platform Module hardware. The TPM provides:
- Non-exportable keys (FixedTPM attribute)
- Hardware-bound key material
- Cryptographic attestation via TPM2_Certify
- PCR-bound sealing for additional protection
- Platform integrity measurement

### SecurityLevelHigh (2) - PKCS#11 HSM / Phone TEE

Keys are protected by local hardware security modules:
- **PKCS#11 HSMs**: Keys stored in dedicated HSM hardware (YubiKey, Nitrokey, SoftHSM)
- **Phone TEE/StrongBox**: Keys stored in Android's Trusted Execution Environment or StrongBox

Benefits:
- Local control over key material
- Hardware-protected storage
- No network dependency for operations

### SecurityLevelMedium (1) - Cloud KMS

Keys are managed by cloud provider HSM services:
- AWS KMS (FIPS 140-2 Level 3)
- GCP Cloud KMS (FIPS 140-2 Level 3)
- Azure Key Vault (FIPS 140-2 Level 2/3)
- HashiCorp Vault (software + optional HSM seal)

Characteristics:
- HSM-backed key storage
- Network-dependent operations
- Cloud provider manages infrastructure
- Subject to cloud provider policies

### SecurityLevelLow (0) - Software

Keys are protected by software encryption:
- Stored on disk in encrypted form
- Protected by HKDF-derived keys + AES-GCM
- No hardware isolation

Use cases:
- Development and testing
- Systems without hardware security
- Non-sensitive key material

## Usage in Code

### Querying SecurityLevel

```go
import "github.com/jeremyhahn/go-xkms/pkg/types"

// Get capabilities from a backend
caps := backend.Capabilities()

// Check security level
level := caps.GetSecurityLevel()

switch level {
case types.SecurityLevelVeryHigh:
    log.Println("TPM 2.0 - highest security")
case types.SecurityLevelHigh:
    log.Println("PKCS#11 HSM - local hardware")
case types.SecurityLevelMedium:
    log.Println("Cloud KMS - network-dependent")
case types.SecurityLevelLow:
    log.Println("Software - disk-based")
}
```

### Sorting Backends by Security

```go
import (
    "sort"
    "github.com/jeremyhahn/go-xkms/pkg/types"
)

// Sort backends by security level descending
sort.Slice(backends, func(i, j int) bool {
    return backends[i].Capabilities().SecurityLevel > backends[j].Capabilities().SecurityLevel
})

// First backend is now the most secure available
recommended := backends[0]
```

### Filtering Backends by Capability and Level

```go
// Find all backends that support sealing with at least High security
var sealingBackends []Backend
for _, b := range allBackends {
    caps := b.Capabilities()
    if caps.SupportsSealing() && caps.SecurityLevel >= types.SecurityLevelHigh {
        sealingBackends = append(sealingBackends, b)
    }
}
```

## UI Recommendations

When presenting backend options to users:

1. **Sort by SecurityLevel descending** - Most secure options first
2. **Mark recommended option** - First available backend with highest level
3. **Show security indicator** - Visual badge or icon for each level
4. **Explain trade-offs** - Network dependency for cloud, availability for TPM

Example UI presentation order:
1. TPM 2.0 (VeryHigh) - Recommended
2. PKCS#11 HSM (High)
3. AWS KMS (Medium)
4. Software (Low)

## Backend-Specific Notes

### TPM 2.0
- Requires TPM hardware
- Keys cannot be exported or migrated
- Provides attestation capabilities
- May require owner password for some operations

### PKCS#11
- Requires PKCS#11 library and token
- Token initialization requires SO PIN
- Operations require User PIN
- Key extractability depends on CKA_EXTRACTABLE attribute

### Cloud KMS
- Requires network connectivity
- Subject to cloud provider rate limits
- Keys managed by provider (cannot extract)
- Audit logging available

### Software
- Always available
- Portable across systems
- Keys can be backed up/restored
- Suitable for development

## See Also

- [Backend Overview](./overview.md)
- [PKCS#11 Backend](../backends/pkcs11.md)
- [TPM 2.0 Backend](../backends/tpm2.md)
