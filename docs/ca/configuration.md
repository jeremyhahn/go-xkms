# CA Configuration Reference

## Overview

The CA configuration defines the certificate authority hierarchy, key algorithms, storage backends, and operational parameters.

## Configuration Structure

```go
type Config struct {
    // Home directory for CA data
    HomeDir string `yaml:"home"`

    // Identity array - root CA at index 0, intermediates follow
    Identity []Identity `yaml:"identity"`

    // SelectedCA is the index of the identity to use as the issuing CA
    SelectedCA int `yaml:"platform-ca"`

    // Default certificate validity period in days
    DefaultValidityPeriod int `yaml:"default-validity"`

    // Whether to include localhost in SANs by default
    IncludeLocalhostSANS bool `yaml:"sans-include-localhost"`

    // Auto-import issuing CA certificates from AIA extension
    AutoImportIssuingCA bool `yaml:"auto-import-issuing-ca"`

    // Use system certificate pool for verification
    SystemCertPool bool `yaml:"system-cert-pool"`

    // LazyInitialization prevents automatic initialization in New()
    LazyInitialization bool
}
```

## Identity Configuration

Each CA identity (Root or Intermediate) is configured with:

```go
type Identity struct {
    // Subject information
    Subject Subject `yaml:"subject"`

    // Subject Alternative Names
    SANS *SubjectAlternativeNames `yaml:"sans"`

    // Certificate validity in years
    Valid int `yaml:"valid"`

    // Key algorithm: RSA, ECDSA, Ed25519
    KeyAlgorithm x509.PublicKeyAlgorithm
    KeyAlgorithmStr string `yaml:"key-algorithm"`

    // RSA key size (2048, 3072, 4096)
    KeySize int `yaml:"key-size"`

    // ECDSA curve (P256, P384, P521)
    ECCCurve string `yaml:"ecc-curve"`

    // Hash algorithm (SHA-256, SHA-384, SHA-512)
    Hash string `yaml:"hash"`

    // XKMS backend type (software, tpm2, pkcs11)
    KeystoreType string `yaml:"keystore-type"`

    // Multi-key support
    Keys []*types.KeyConfig `yaml:"keys"`

    // Per-identity keystore configurations
    Keystores map[string]interface{} `yaml:"keystores"`

    // Whether this is the root CA
    IsRoot bool `yaml:"is-root"`
}
```

## YAML Configuration Example

### Minimal Configuration

```yaml
certificate-authority:
  home: /var/lib/trustedca
  platform-ca: 1  # Use intermediate CA for signing
  default-validity: 365

  identity:
    # Root CA (index 0)
    - subject:
        cn: "My Root CA"
        organization: "My Organization"
        country: "US"
      valid: 10  # 10 years
      key-algorithm: RSA
      key-size: 4096
      keystore-type: software
      is-root: true

    # Intermediate CA (index 1)
    - subject:
        cn: "My Intermediate CA"
        organization: "My Organization"
        country: "US"
      valid: 5  # 5 years
      key-algorithm: ECDSA
      ecc-curve: P-256
      keystore-type: software
```

### Production Configuration with TPM

```yaml
certificate-authority:
  home: /var/lib/trustedca
  platform-ca: 1
  default-validity: 398
  sans-include-localhost: false
  auto-import-issuing-ca: true
  system-cert-pool: true

  identity:
    # Root CA - TPM-protected
    - subject:
        cn: "Production Root CA"
        organization: "Acme Corporation"
        organizational-unit: "PKI Operations"
        country: "US"
        province: "California"
        locality: "San Francisco"
      valid: 20
      key-algorithm: RSA
      key-size: 4096
      keystore-type: tpm2
      is-root: true
      keystores:
        tpm2:
          srk-handle: 0x81000001
          srk-auth: "${TPM_SRK_AUTH}"
          platform-policy: true

    # Intermediate CA - Multi-algorithm support
    - subject:
        cn: "Production Intermediate CA"
        organization: "Acme Corporation"
        organizational-unit: "PKI Operations"
        country: "US"
        province: "California"
        locality: "San Francisco"
      sans:
        dns:
          - "ca.acme.com"
          - "pki.acme.com"
      valid: 10
      key-algorithm: ECDSA
      ecc-curve: P-256
      keystore-type: tpm2
      keys:
        # TPM-backed ECDSA (primary)
        - algorithm: ECDSA
          ecc:
            curve: P-256
          signature-algorithm: ECDSA-SHA256
          hash: SHA-256
          store: tpm2
          platform-policy: true

        # TPM-backed RSA (compatibility)
        - algorithm: RSA
          rsa:
            size: 2048
          signature-algorithm: SHA256-RSA
          hash: SHA-256
          store: tpm2
          platform-policy: true

        # Software Ed25519 (performance)
        - algorithm: Ed25519
          signature-algorithm: Ed25519
          hash: SHA-256
          store: software
```

### HSM Configuration (PKCS#11)

```yaml
certificate-authority:
  home: /var/lib/trustedca
  platform-ca: 1
  default-validity: 398

  identity:
    # Root CA - HSM-protected
    - subject:
        cn: "HSM Root CA"
        organization: "Secure Corp"
        country: "US"
      valid: 25
      key-algorithm: ECDSA
      ecc-curve: P-384
      keystore-type: pkcs11
      is-root: true
      keystores:
        pkcs11:
          library: /usr/lib/softhsm/libsofthsm2.so
          config: /etc/softhsm/softhsm.conf
          slot: 0
          label: "RootCA-HSM"
          pin: "${HSM_PIN}"
          platform-policy: true

    # Intermediate CA - HSM-protected
    - subject:
        cn: "HSM Intermediate CA"
        organization: "Secure Corp"
        country: "US"
      valid: 10
      key-algorithm: ECDSA
      ecc-curve: P-256
      keystore-type: pkcs11
      keystores:
        pkcs11:
          library: /usr/lib/softhsm/libsofthsm2.so
          slot: 1
          label: "IntermediateCA-HSM"
          pin: "${HSM_PIN}"
```

## Subject Configuration

```go
type Subject struct {
    CommonName         string `yaml:"cn"`
    Organization       string `yaml:"organization"`
    OrganizationalUnit string `yaml:"organizational-unit"`
    Country            string `yaml:"country"`
    Province           string `yaml:"province"`
    Locality           string `yaml:"locality"`
    Address            string `yaml:"address"`
    PostalCode         string `yaml:"postal-code"`
}
```

Example:

```yaml
subject:
  cn: "My CA"
  organization: "Acme Inc"
  organizational-unit: "IT Security"
  country: "US"
  province: "California"
  locality: "San Francisco"
  address: "123 Main St"
  postal-code: "94105"
```

## Subject Alternative Names (SANs)

```go
type SubjectAlternativeNames struct {
    DNS   []string `yaml:"dns"`
    IPs   []string `yaml:"ips"`
    Email []string `yaml:"email"`
    URIs  []string `yaml:"uris"`
}
```

Example:

```yaml
sans:
  dns:
    - "ca.example.com"
    - "pki.example.com"
    - "*.internal.example.com"
  ips:
    - "10.0.0.1"
    - "192.168.1.100"
  email:
    - "admin@example.com"
  uris:
    - "spiffe://example.com/ca"
```

## Key Algorithm Configuration

### RSA

```yaml
key-algorithm: RSA
key-size: 2048  # or 3072, 4096
hash: SHA-256   # or SHA-384, SHA-512
```

| Key Size | Security Level | Use Case |
|----------|----------------|----------|
| 2048 | 112-bit | General purpose, legacy systems |
| 3072 | 128-bit | Enhanced security |
| 4096 | ~140-bit | Long-term keys, root CAs |

### ECDSA

```yaml
key-algorithm: ECDSA
ecc-curve: P-256  # or P-384, P-521
hash: SHA-256     # or SHA-384, SHA-512
```

| Curve | Security Level | TPM Support | Notes |
|-------|----------------|-------------|-------|
| P-256 | 128-bit | Yes | Recommended for most uses |
| P-384 | 192-bit | Yes | Enhanced security |
| P-521 | 256-bit | Software only | Maximum security |

### Ed25519

```yaml
key-algorithm: Ed25519
hash: SHA-256
```

- Fixed 128-bit security level
- Fastest signature generation/verification
- Software backend only (TPM does not support Ed25519)

## Keystore Backend Configuration

### Software (PKCS#8)

```yaml
keystore-type: software
keystores:
  software:
    password: "${KEY_PASSWORD}"
    platform-policy: true
```

### TPM 2.0

```yaml
keystore-type: tpm2
keystores:
  tpm2:
    srk-handle: 0x81000001
    srk-auth: "${TPM_SRK_AUTH}"
    platform-policy: true
```

| Parameter | Description |
|-----------|-------------|
| `srk-handle` | Storage Root Key persistent handle |
| `srk-auth` | SRK authorization value |
| `platform-policy` | Enable platform PCR policy |

### PKCS#11 (HSM)

```yaml
keystore-type: pkcs11
keystores:
  pkcs11:
    library: /usr/lib/pkcs11/libsofthsm2.so
    config: /etc/softhsm/softhsm.conf
    slot: 0
    label: "MyCA-HSM"
    pin: "${HSM_PIN}"
    platform-policy: true
```

| Parameter | Description |
|-----------|-------------|
| `library` | Path to PKCS#11 library (.so/.dll) |
| `config` | Optional configuration file path |
| `slot` | HSM slot number |
| `label` | Token label for key identification |
| `pin` | User PIN for HSM access |

## Multi-Key Configuration

Configure multiple keys per CA identity for algorithm agility:

```yaml
keys:
  # Primary signing key - ECDSA
  - algorithm: ECDSA
    ecc:
      curve: P-256
    signature-algorithm: ECDSA-SHA256
    hash: SHA-256
    store: tpm2
    platform-policy: true

  # Secondary key - RSA for compatibility
  - algorithm: RSA
    rsa:
      size: 2048
    signature-algorithm: SHA256-RSAPSS
    hash: SHA-256
    store: software
    password: "${RSA_KEY_PASSWORD}"

  # High-performance key - Ed25519
  - algorithm: Ed25519
    signature-algorithm: Ed25519
    hash: SHA-256
    store: software
```

## Certificate Validity Configuration

```yaml
# Root CA validity in years
identity:
  - valid: 20  # Root CA: 20 years

  # Intermediate CA validity
  - valid: 10  # Intermediate: 10 years

# Default end-entity validity in days
default-validity: 398  # ~13 months (CA/B Forum limit)
```

### Validity Guidelines

| Certificate Type | Recommended Validity |
|-----------------|---------------------|
| Root CA | 15-25 years |
| Intermediate CA | 5-10 years |
| End-Entity (TLS) | 398 days (CA/B Forum) |
| End-Entity (Internal) | 1-5 years |
| TPM Device Identity | 99991231235959Z (Indefinite) |

## Default Configuration

The `DefaultConfig()` function provides sensible defaults:

```go
func DefaultConfig() Config {
    return Config{
        HomeDir:               "./.trustedca",
        DefaultValidityPeriod: 365,
        DefaultKeyAlgorithm:   x509.ECDSA,
        DefaultHash:           crypto.SHA256,
        IncludeLocalhostSANS:  true,
        AutoImportIssuingCA:   true,
        SystemCertPool:        false,
        SelectedCA:            1,  // Use intermediate
        Identity: []Identity{
            {
                Subject: Subject{
                    CommonName:   "Trusted CA Root",
                    Organization: "Trusted CA",
                    Country:      "US",
                },
                Valid:        10,
                KeyAlgorithm: x509.RSA,
                KeySize:      2048,
                KeystoreType: "software",
                IsRoot:       true,
            },
            {
                Subject: Subject{
                    CommonName:   "intermediate-ca",
                    Organization: "Trusted CA",
                    Country:      "US",
                },
                Valid:        5,
                KeyAlgorithm: x509.RSA,
                KeySize:      2048,
                KeystoreType: "software",
            },
        },
    }
}
```

## Test Configuration

For unit tests, use `TestConfig()` which excludes TPM backends:

```go
config := ca.TestConfig()
// Uses software-only keys, no TPM dependencies
```

## Environment Variable Substitution

Configuration files support environment variable substitution for sensitive values:

```yaml
keystores:
  tpm2:
    srk-auth: "${TPM_SRK_AUTH}"
  pkcs11:
    pin: "${HSM_PIN}"
  software:
    password: "${CA_KEY_PASSWORD}"
```

## See Also

- [Architecture](architecture.md)
- [Certificate Types](certificate-types.md)
- [API Reference](api-reference.md)
