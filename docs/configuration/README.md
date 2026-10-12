# Configuration Documentation

This directory contains configuration guides for various aspects of go-xkms.

## Configuration Topics

### Build Configuration
- [Build toggles](../crypto-backends/engineering.md#build-toggles) - Build tags and the `WITH_*` Makefile toggles

### Encryption Configuration
- [Symmetric Encryption & AEAD](../symmetric-aead/) - Algorithm auto-selection, per-key byte budgets and symmetric key usage

### Bootstrap Configuration
- [CA Bundle Bootstrap](../trust-bootstrap/engineering.md#configuration) - Noise bootstrap listener and the resolver's `trust:` section

### Barrier and PIN Configuration

The barrier provides transparent at-rest encryption for all stored key material. PIN management controls access to the barrier via a PKCS#11-inspired dual-PIN model.

#### Barrier Configuration

```yaml
seal:
  # Sealing strategy for root key protection.
  # "auto" selects the best available hardware strategy, falling back to software.
  # Options: auto, software, tpm2, pkcs11, awskms, gcpkms, azurekv, vault
  strategy: auto

  # Storage key for the sealed root key blob.
  root_key_path: "sys/barrier/root-key"

  # Override the default strategy preference order.
  # The first available strategy in this list is used.
  # Default order: tpm2, pkcs11, awskms, gcpkms, azurekv, vault, software
  preference_order:
    - tpm2
    - pkcs11
    - software
```

#### PIN Configuration

```yaml
pin:
  # PIN management strategy.
  # "auto" selects tpm2 if available, then pkcs11, then software.
  # Options: auto, software, tpm2, pkcs11
  strategy: auto

  # Minimum PIN length (default: 6).
  min_length: 6

  # Override default state file location.
  # Default: <data-dir>/pin-state.json
  state_path: ""

  # Lockout protection settings.
  lockout:
    # Maximum failed attempts before lockout triggers (default: 5).
    max_attempts: 5

    # Base lockout duration (default: 5m).
    # With backoff enabled, this doubles on each consecutive lockout.
    duration: 5m

    # Enable exponential backoff on repeated lockouts (default: true).
    # Lockout duration doubles each time, capped at 1 hour.
    backoff: true
```

**Related documentation:**
- [Sealing and Barrier](../sealing-and-barrier/architecture.md)
- [PIN Management](../pin-management/architecture.md)
- [CLI PIN Commands](../../xkey/docs/usage/cli/pin.md)

### Backend-Specific Configuration
- [TPM2 Session Encryption](../tpm2/engineering.md#bus-protection) - TPM 2.0 session encryption (always on, not configurable)

### TPM Dashboard GUI

The TPM Dashboard provides a comprehensive web-based interface for managing TPM 2.0 devices and policies.

#### TPM Overview Tab

The Overview tab displays detailed TPM capabilities and information:

- **Supported Commands**: Lists all TPM commands the device supports (e.g., TPM2_Create, TPM2_Sign, TPM2_ActivateCredential)
- **ECC Curves**: Displays supported elliptic curves (e.g., NIST P-256, NIST P-384, NIST P-521)
- **Algorithm Information**: Shows human-readable names for all supported algorithms instead of hex codes
- **Manufacturer Details**: TPM vendor, firmware version, and specification level
- **Persistent Handles**: Lists all persistent keys stored in the TPM

#### Policy Management Tab

The Policies tab provides comprehensive policy lifecycle management:

**Basic Operations** (see [TPM policies](../tpm-policies/user.md)):
- **Create Policy**: one PCR selection (Simple), or branches combining PCR
  values, the object password and TPM localities (Advanced), with an
  optional description
- **Describe**: change a policy's description
- **Details**: each branch and the PCR values it captured
- **Verify / Update / Revoke**: compare each branch with the live PCRs,
  re-capture and re-approve, or withdraw the approval
- **Delete Policy**: refused while keys or sealed objects are bound to it

**Key Association:**
- **Assign Policy to Key**: Associate policies with persistent key handles (0x81xxxxxx format)
  - Enables key usage authorization via PCR state or password
  - Supports policy updates without re-creating keys

**Compound Policies:**
- **Create Composite Policies**: Combine multiple policy elements using AND/OR logic
  - Mix PCR-based and password-based policies
  - Example: (PCR[0,7] == expected_values) AND (password_required)
  - Enables fine-grained access control scenarios

## Configuration Best Practices

1. **Security**: Always use hardware-backed storage for production environments
2. **Key Types**: Choose appropriate key types and algorithms for your use case
3. **Storage**: Configure appropriate storage backends for your deployment model
4. **Encryption**: Enable session encryption for TPM2 backends in production

## See Also

- [Architecture Overview](../architecture/overview.md)
- [Backend Documentation](../crypto-backends/)
- [Getting Started Guide](../../xkey/docs/usage/getting-started.md)
