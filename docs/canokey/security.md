# CanoKey Security Considerations

## Hardware Security Model

### CanoKey Physical Device

CanoKey implements a hardware security boundary:

| Property | Description |
|----------|-------------|
| **Key Storage** | Private keys never leave the device |
| **Tamper Resistance** | Secure element with physical protections |
| **Side-Channel Protection** | Constant-time operations |
| **Firmware Verification** | Signed updates only |

### Attack Resistance

- **Key Extraction**: Private keys cannot be exported or extracted
- **Physical Attacks**: Limited by secure element design
- **Malware**: Keys protected even if host is compromised
- **Replay Attacks**: Signature counters prevent replay
- **Phishing**: FIDO2 origin binding prevents credential reuse

## PIN Protection

### PIV PIN Security

```
User PIN:
- 6-8 characters
- 3 retry attempts (configurable)
- Lockout requires SO PIN reset

Security Officer PIN:
- Used for administrative operations
- Required for PIN unlock after lockout
- Should be stored securely (not in config files)
```

### FIDO2 PIN Security

```
Client PIN:
- Minimum 4 characters (configurable per authenticator)
- 8 retry attempts typically
- Enforced by authenticator, not host
- PIN hash verified on-device
```

### Best Practices

```go
// DON'T: Hardcode PINs
config := &canokey.Config{
    PIN: "123456",  // BAD
}

// DO: Use environment or secure vault
config := &canokey.Config{
    PIN: os.Getenv("CANOKEY_PIN"),
}

// BETTER: Use secret manager
pin, err := vault.GetSecret("canokey/pin")
config := &canokey.Config{
    PIN: pin,
}
```

## FIDO2 Security Features

### User Presence (UP)

- Physical touch required for each operation
- Prevents silent credential use
- Hardware-enforced (LED, button)

### User Verification (UV)

- PIN verification for sensitive operations
- Optional or required per credential
- Protects against stolen device

### Attestation

```go
// Attestation proves the credential is from genuine hardware
result, err := handler.EnrollKey(config)
if err != nil {
    return err
}

// Attestation certificate chain
attestationCert := result.AttestationCertificate
attestationChain := result.AttestationChain

// Verify against known roots
err = verifyAttestationChain(attestationCert, attestationChain, knownRoots)
```

### Origin Binding

FIDO2 credentials are bound to relying party ID:
- Credential registered with `example.com` cannot be used on `evil.com`
- Prevents phishing attacks
- Enforced by authenticator hardware

## CanoKey QEMU Security

### Testing Only

CanoKey QEMU is **NOT** secure for production:

| Aspect | Physical Device | QEMU |
|--------|-----------------|------|
| Key Storage | Hardware-protected | Software file |
| User Presence | Physical button | Auto-approved |
| Tamper Resistance | Yes | No |
| Side-Channel Protection | Yes | No |
| Production Use | Yes | **NO** |

### CI/CD Usage

```yaml
# Acceptable: Testing and CI/CD
test:
  environment:
    CANOKEY_QEMU: "true"
  tags:
    - integration

# NOT Acceptable: Production
production:
  environment:
    CANOKEY_QEMU: "true"  # NEVER DO THIS
```

### Distinguishing Environments

```go
// Check if running with QEMU
if config.UseQEMU {
    log.Warn("Running with virtual CanoKey - NOT for production use")
}

// In production, verify physical device
if !backend.IsHardwareBacked() {
    return errors.New("production requires physical security key")
}
```

## Cryptographic Recommendations

### Algorithm Selection

| Use Case | Recommended | Notes |
|----------|-------------|-------|
| General Signing | ECDSA P-256 | Wide compatibility |
| High Security | ECDSA P-384 | Longer-term security |
| Modern Systems | Ed25519 | Requires firmware 3.0+ |
| Legacy Systems | RSA 2048 | Avoid if possible |
| Key Exchange | X25519 | Requires firmware 3.0+ |

### Key Rotation

```go
// Implement key rotation policy
type KeyPolicy struct {
    MaxAge        time.Duration
    SignatureLimit int64
}

func CheckKeyHealth(backend Backend, attrs *types.KeyAttributes) error {
    info, err := backend.GetKeyInfo(attrs)
    if err != nil {
        return err
    }

    // Check age
    if time.Since(info.Created) > policy.MaxAge {
        return ErrKeyRotationRequired
    }

    // Check signature count
    if info.SignatureCount > policy.SignatureLimit {
        return ErrKeyRotationRequired
    }

    return nil
}
```

## Threat Model

### In-Scope Threats

| Threat | Mitigation |
|--------|------------|
| Key theft from host | Keys never leave device |
| Malware signing | User presence required |
| Credential phishing | Origin binding |
| Brute-force PIN | Retry limits |
| Replay attacks | Signature counters |

### Out-of-Scope Threats

| Threat | Notes |
|--------|-------|
| Device theft with known PIN | Physical security required |
| Advanced side-channel | Depends on device model |
| Nation-state attacks | Beyond typical threat model |
| Supply chain attacks | Verify device authenticity |

## Compliance Considerations

### FIDO2 Certification

CanoKey implements FIDO2 standards:
- CTAP 2.0+ compliant
- WebAuthn L1+ compatible
- Attestation available

### PIV Compliance

CanoKey PIV implementation:
- NIST SP 800-73 compatible
- NIST SP 800-78 algorithms
- Common Access Card (CAC) compatible

### Recommendations

```go
// For regulated environments
config := &canokey.Config{
    // Use FIPS-approved algorithms
    AllowedAlgorithms: []string{"RSA-2048", "ECDSA-P256", "ECDSA-P384"},

    // Require user verification
    RequireUserVerification: true,

    // Enable audit logging
    AuditLog: true,
}
```

## Secure Configuration Checklist

- [ ] Never hardcode PINs in source code
- [ ] Use environment variables or secure vault for secrets
- [ ] Enable user verification for sensitive operations
- [ ] Verify attestation in FIDO2 flows
- [ ] Use QEMU only for testing, never production
- [ ] Implement key rotation policy
- [ ] Monitor signature counters
- [ ] Store credential IDs and salts securely
- [ ] Validate relying party ID matches expected domain
- [ ] Log security-relevant events
