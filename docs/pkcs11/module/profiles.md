# PKCS#11 v3.0 Profiles

The PKCS#11 Provider Module implements three PKCS#11 v3.0 profiles as defined in the OASIS PKCS#11 Profiles Specification v3.0.

## Profile Overview

| Profile | ID | Description |
|---------|-----|-------------|
| Extended Provider | `CKP_EXTENDED_PROVIDER` | Full mechanism support with authentication |
| Authentication Token | `CKP_AUTHENTICATION_TOKEN` | Signing operations for authentication |
| Public Certificates Token | `CKP_PUBLIC_CERTIFICATES_TOKEN` | Certificate storage and retrieval |

## Profile Objects

Each supported profile is exposed as a `CKO_PROFILE` object:

```c
// List profile objects
pkcs11-tool --module $P11_MODULE --list-objects --type profile
```

## Extended Provider Profile (CKP_EXTENDED_PROVIDER)

The Extended Provider profile extends the Baseline Provider with mechanism queries and user authentication.

### Required Functions

| Function | Description | Status |
|----------|-------------|--------|
| `C_GetFunctionList` | Get function list | Planned |
| `C_GetInterfaceList` | Get interface list (v3.0) | Planned |
| `C_GetInterface` | Get interface (v3.0) | Planned |
| `C_Initialize` | Initialize library | Planned |
| `C_Finalize` | Finalize library | Planned |
| `C_GetInfo` | Get library info | Planned |
| `C_GetSlotList` | Get slot list | Planned |
| `C_GetSlotInfo` | Get slot info | Planned |
| `C_GetTokenInfo` | Get token info | Planned |
| `C_GetMechanismList` | List mechanisms | Planned |
| `C_GetMechanismInfo` | Get mechanism info | Planned |
| `C_OpenSession` | Open session | Planned |
| `C_CloseSession` | Close session | Planned |
| `C_GetSessionInfo` | Get session info | Planned |
| `C_Login` | User login | Planned |
| `C_LoginUser` | Extended login (v3.0) | Planned |
| `C_Logout` | User logout | Planned |
| `C_FindObjectsInit` | Start object search | Planned |
| `C_FindObjects` | Continue search | Planned |
| `C_FindObjectsFinal` | End search | Planned |
| `C_GetAttributeValue` | Get attributes | Planned |

### Use Cases
- General-purpose HSM replacement
- Key storage with access control
- Cryptographic operations requiring authentication

## Authentication Token Profile (CKP_AUTHENTICATION_TOKEN)

The Authentication Token profile supports signing operations for authentication purposes.

### Required Functions

All Extended Provider functions plus:

| Function | Description | Status |
|----------|-------------|--------|
| `C_SignInit` | Initialize signing | Planned |
| `C_Sign` | Single-part sign | Planned |
| `C_SignUpdate` | Multi-part sign (optional) | Planned |
| `C_SignFinal` | Finalize signing (optional) | Planned |

### Required Object Types

| Object Type | Description | Attributes |
|-------------|-------------|------------|
| `CKO_PRIVATE_KEY` | Private signing key | `CKA_SIGN=TRUE` |
| `CKO_PUBLIC_KEY` | Public verification key | `CKA_VERIFY=TRUE` |

### Use Cases
- TLS client authentication
- SSH authentication
- Code signing
- Document signing

## Public Certificates Token Profile (CKP_PUBLIC_CERTIFICATES_TOKEN)

The Public Certificates Token profile provides certificate storage accessible without authentication.

### Required Functions

All Extended Provider functions (login optional for certificate access).

### Required Object Types

| Object Type | Description | Requirements |
|-------------|-------------|--------------|
| `CKO_CERTIFICATE` | X.509 certificate | Readable without login |

### Attribute Requirements

| Attribute | Description | Requirement |
|-----------|-------------|-------------|
| `CKA_ID` | Object identifier | Must match between cert and key pair |
| `CKA_LABEL` | Human-readable label | Required |
| `CKA_CERTIFICATE_TYPE` | Certificate type | `CKC_X_509` |
| `CKA_VALUE` | DER-encoded certificate | Required |

### Use Cases
- PKI integration
- Certificate distribution
- TLS certificate storage
- Certificate chain management

## Mechanism Support Matrix

### RSA Mechanisms

| Mechanism | Key Gen | Sign | Verify | Encrypt | Decrypt | Status |
|-----------|---------|------|--------|---------|---------|--------|
| `CKM_RSA_PKCS_KEY_PAIR_GEN` | Yes | - | - | - | - | Planned |
| `CKM_RSA_PKCS` | - | Yes | Yes | Yes | Yes | Planned |
| `CKM_RSA_PKCS_PSS` | - | Yes | Yes | - | - | Planned |
| `CKM_RSA_PKCS_OAEP` | - | - | - | Yes | Yes | Planned |
| `CKM_SHA256_RSA_PKCS` | - | Yes | Yes | - | - | Planned |
| `CKM_SHA384_RSA_PKCS` | - | Yes | Yes | - | - | Planned |
| `CKM_SHA512_RSA_PKCS` | - | Yes | Yes | - | - | Planned |
| `CKM_SHA256_RSA_PKCS_PSS` | - | Yes | Yes | - | - | Planned |

### ECDSA Mechanisms

| Mechanism | Key Gen | Sign | Verify | Status |
|-----------|---------|------|--------|--------|
| `CKM_EC_KEY_PAIR_GEN` | Yes | - | - | Planned |
| `CKM_ECDSA` | - | Yes | Yes | Planned |
| `CKM_ECDSA_SHA256` | - | Yes | Yes | Planned |
| `CKM_ECDSA_SHA384` | - | Yes | Yes | Planned |
| `CKM_ECDSA_SHA512` | - | Yes | Yes | Planned |

### EdDSA Mechanisms

| Mechanism | Key Gen | Sign | Verify | Status |
|-----------|---------|------|--------|--------|
| `CKM_EC_EDWARDS_KEY_PAIR_GEN` | Yes | - | - | Planned |
| `CKM_EDDSA` | - | Yes | Yes | Planned |

### AES Mechanisms

| Mechanism | Key Gen | Encrypt | Decrypt | Status |
|-----------|---------|---------|---------|--------|
| `CKM_AES_KEY_GEN` | Yes | - | - | Planned |
| `CKM_AES_CBC` | - | Yes | Yes | Planned |
| `CKM_AES_CBC_PAD` | - | Yes | Yes | Planned |
| `CKM_AES_GCM` | - | Yes | Yes | Planned |

### Random Generation

| Mechanism | Description | Status |
|-----------|-------------|--------|
| `CKM_GENERIC_SECRET_KEY_GEN` | Generic secret key | Planned |

## Curve Support

### NIST Curves

| Curve | OID | Key Size | Status |
|-------|-----|----------|--------|
| P-256 (secp256r1) | 1.2.840.10045.3.1.7 | 256-bit | Planned |
| P-384 (secp384r1) | 1.3.132.0.34 | 384-bit | Planned |
| P-521 (secp521r1) | 1.3.132.0.35 | 521-bit | Planned |

### Other Curves

| Curve | OID | Key Size | Status |
|-------|-----|----------|--------|
| secp256k1 | 1.3.132.0.10 | 256-bit | Planned |
| Ed25519 | 1.3.101.112 | 256-bit | Planned |
| Ed448 | 1.3.101.113 | 448-bit | Planned |

## RSA Key Sizes

| Size | Description | Status |
|------|-------------|--------|
| 2048 bits | Minimum recommended | Planned |
| 3072 bits | Higher security | Planned |
| 4096 bits | Maximum security | Planned |

## v3.0 Specific Features

### New in PKCS#11 v3.0

| Feature | Description | Status |
|---------|-------------|--------|
| `C_GetInterfaceList` | List available interfaces | Planned |
| `C_GetInterface` | Get specific interface | Planned |
| `C_LoginUser` | Extended login with context | Planned |
| `CK_INTERFACE` type | Interface structure | Planned |
| `CKO_PROFILE` objects | Profile advertisement | Planned |
| `CKA_PROFILE_ID` | Profile identifier attribute | Planned |
| `CKA_UNIQUE_IDENTIFIER` | Unique object ID | Planned |

### Interface Support

```c
// v3.0 interface enumeration
CK_INTERFACE_PTR interfaces;
CK_ULONG count;

C_GetInterfaceList(NULL, &count);
interfaces = malloc(count * sizeof(CK_INTERFACE));
C_GetInterfaceList(interfaces, &count);

for (CK_ULONG i = 0; i < count; i++) {
    printf("Interface: %s version %d.%d\n",
           interfaces[i].pInterfaceName,
           interfaces[i].pFunctionList->version.major,
           interfaces[i].pFunctionList->version.minor);
}
```

## Compliance Verification

Verify profile compliance with pkcs11-tool:

```bash
# List supported mechanisms
pkcs11-tool --module $P11_MODULE --list-mechanisms

# List profile objects
pkcs11-tool --module $P11_MODULE --list-objects --type profile

# Test signing (Authentication Token)
pkcs11-tool --module $P11_MODULE --login --pin 123456 \
  --sign --mechanism RSA-PKCS --label test-key \
  --input-file message.txt

# Test certificate access without login (Public Certificates Token)
pkcs11-tool --module $P11_MODULE --list-objects --type cert
```

## References

- [PKCS#11 Base Specification v3.0](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html)
- [PKCS#11 Profiles Specification v3.0](https://docs.oasis-open.org/pkcs11/pkcs11-profiles/v3.0/pkcs11-profiles-v3.0.html)
- [PKCS#11 Current Mechanisms Specification v3.0](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/pkcs11-curr-v3.0.html)
