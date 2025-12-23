# FROST Security Considerations

This document covers security considerations, best practices, and threat mitigations for the FROST backend.

## Security Model

FROST provides security against a malicious adversary who:
- Controls up to `threshold - 1` participants
- Can observe all network communications
- Can attempt to manipulate the signing protocol

### Security Guarantees

| Property | Description | Guarantee |
|----------|-------------|-----------|
| **Unforgeability** | Cannot forge signatures without threshold participants | Computational |
| **Key Privacy** | Private key never reconstructed | Information-theoretic |
| **Identifiable Abort** | Malicious signers can be identified | Yes |
| **Robustness** | Protocol completes if threshold honest | Threshold honest |

### Comparison with Shamir-Based Threshold

| Aspect | FROST | Shamir (existing) |
|--------|-------|-------------------|
| Key reconstruction | Never | Required for signing |
| Single point of failure | No | Yes (during signing) |
| Memory exposure | Partial (share only) | Full (reconstructed key) |
| Side-channel risk | Lower | Higher |

## Critical Security: Nonce Handling

**Nonce reuse is catastrophic.** If the same nonce is used twice with different messages, the private key share can be recovered.

### Nonce Reuse Attack

```
Given two signatures with the same nonce:
  sig1 = (R, z1) for message m1
  sig2 = (R, z2) for message m2  (same R means same nonce!)

Attacker can compute:
  private_key_share = (z1 - z2) / (H(m1) - H(m2))
```

### Protection Mechanisms

1. **Nonce Tracking (Enabled by Default)**

```go
config := &frost.Config{
    EnableNonceTracking: true,  // Default: true
    NonceStorage:        storage,
}
```

2. **Storage-Based Tracking**

```go
// Before signing
if used, _ := tracker.IsUsed(keyID, commitment); used {
    return nil, ErrNonceAlreadyUsed  // Abort!
}

// After signing
tracker.MarkUsed(keyID, commitment)
```

3. **Session Isolation**

Each signing session uses fresh nonces. Never reuse `NoncePackage` across sessions.

### Best Practices

```go
// GOOD: Generate fresh nonces for each signature
for each message {
    nonces := backend.GenerateNonces(keyID)
    share := backend.SignRound(keyID, message, nonces, commitments)
}

// BAD: Reusing nonces
nonces := backend.GenerateNonces(keyID)
share1 := backend.SignRound(keyID, message1, nonces, commitments)  // OK
share2 := backend.SignRound(keyID, message2, nonces, commitments)  // CATASTROPHIC!
```

## Secret Key Share Protection

### Storage Security

| Risk | Mitigation |
|------|------------|
| Disk theft | Use encrypted backends (TPM, HSM, KMS) |
| Memory dump | Zeroize secrets after use |
| Side-channel | Use constant-time operations |
| Backup exposure | Never backup decrypted shares |

### Recommended Backend Selection

| Environment | Recommended Backend |
|-------------|---------------------|
| Production (on-prem) | TPM2 or PKCS#11 HSM |
| Production (cloud) | Cloud KMS (AWS/GCP/Azure) |
| Multi-cloud | HashiCorp Vault |
| Development | Software (with encryption) |
| Air-gapped | SmartCard-HSM |

### Memory Handling

```go
// Secret shares implement Zeroize()
defer keyShare.Zeroize()

// Nonces are zeroized after signing
defer nonces.Zeroize()
```

## Network Security

### Commitment Exchange

Commitments are public but must be authentic:

```
┌─────────────┐                    ┌─────────────┐
│ Participant │  commitment (TLS)  │ Participant │
│     A       │ ─────────────────▶ │     B       │
└─────────────┘                    └─────────────┘
              ◄───────────────────
                commitment (TLS)
```

**Requirements:**
- Use TLS 1.3 for transport
- Authenticate participants (mTLS recommended)
- Verify commitment integrity

### Signature Share Exchange

```go
// Signature shares are bound to specific commitments
// Replaying old shares with new commitments fails verification
```

### Recommended Network Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Secure Network Zone                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    mTLS    ┌──────────────┐    mTLS          │
│  │ Participant 1│◄──────────▶│ Coordinator  │◄─────────────┐   │
│  └──────────────┘            └──────────────┘              │   │
│         ▲                           ▲                      │   │
│         │ mTLS                      │ mTLS                 │   │
│         ▼                           ▼                      ▼   │
│  ┌──────────────┐            ┌──────────────┐      ┌──────────┐│
│  │ Participant 2│            │ Participant 3│      │ ... N    ││
│  └──────────────┘            └──────────────┘      └──────────┘│
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Threat Mitigations

### Threat: Malicious Participant

**Attack:** A participant provides invalid signature shares.

**Mitigation:** FROST provides identifiable abort - invalid shares are detected during aggregation.

```go
signature, err := backend.Aggregate(keyID, message, commitments, shares)
if err != nil {
    var culpritErr *frost.CulpritError
    if errors.As(err, &culpritErr) {
        log.Printf("Malicious participant: %v", culpritErr.Culprits())
    }
}
```

### Threat: Coordinator Compromise

**Attack:** Compromised coordinator manipulates the protocol.

**Mitigation:**
- Coordinator only sees public data (commitments, shares)
- Cannot forge signatures without controlling threshold participants
- Distribute coordinator role across participants

### Threat: Replay Attack

**Attack:** Attacker replays old signature shares.

**Mitigation:**
- Signature shares are bound to specific commitment sets
- Session IDs prevent cross-session replay
- Nonce tracking prevents nonce reuse

### Threat: Key Share Theft

**Attack:** Attacker steals a participant's key share.

**Mitigation:**
- Single share is insufficient (need threshold)
- Use hardware backends (TPM, HSM)
- Enable key rotation

```go
// Rotate key after suspected compromise
err := backend.RotateKey(&types.KeyAttributes{CN: "compromised-key"})
```

### Threat: Side-Channel Attack

**Attack:** Extract secrets via timing, power, or cache analysis.

**Mitigation:**
- Use constant-time operations (provided by go-frost)
- Use hardware backends with side-channel protection
- Avoid branching on secret data

### Threat: Denial of Service

**Attack:** Malicious participant refuses to sign.

**Mitigation:**
- Set appropriate threshold (e.g., 3-of-5 tolerates 2 failures)
- Implement timeout mechanisms
- Have backup participants

```go
config := &frost.Config{
    DefaultThreshold: 3,
    DefaultTotal:     5,  // Tolerates 2 offline participants
}
```

## Operational Security

### Key Generation Ceremony

For high-security deployments, conduct key generation as a ceremony:

1. **Preparation**
   - Air-gapped machine for dealer
   - Secure communication channels established
   - Participant identity verified

2. **Generation**
   ```bash
   # On air-gapped machine
   keychain frost keygen \
     --algorithm FROST-P256-SHA256 \
     --threshold 3 \
     --total 5 \
     --participants "alice,bob,charlie,dave,eve" \
     --output /secure/keys/
   ```

3. **Distribution**
   - Transfer shares via secure channels (encrypted USB, secure file transfer)
   - Verify share integrity with checksums
   - Destroy dealer's copy of shares

4. **Verification**
   - Each participant verifies their share
   - Test signing with threshold participants

### Backup and Recovery

**DO:**
- Backup encrypted shares to separate secure locations
- Document recovery procedures
- Test recovery periodically

**DON'T:**
- Store all shares in one location
- Backup decrypted shares
- Email or message shares

### Monitoring and Alerting

```go
// Log all signing operations
backend.OnSign(func(event SignEvent) {
    log.Printf("Sign operation: key=%s, participant=%d, session=%s",
        event.KeyID, event.ParticipantID, event.SessionID)
})

// Alert on nonce reuse attempt
backend.OnNonceReuse(func(event NonceReuseEvent) {
    alert.Critical("NONCE REUSE DETECTED", event)
})
```

### Incident Response

**If nonce reuse is detected:**
1. Immediately disable the affected key
2. Investigate how reuse occurred
3. Rotate to new key
4. Review and fix nonce tracking

**If key share is compromised:**
1. Assess number of compromised shares
2. If < threshold: rotate key proactively
3. If >= threshold: assume key compromised, revoke and regenerate

## Compliance Considerations

### FIPS 140-2

For FIPS compliance:
- Use `FROST-P256-SHA256` algorithm
- Use FIPS-validated HSM (PKCS#11 with FIPS module)
- Ensure random number generation is FIPS-compliant

### PCI DSS

For payment card industry:
- Store shares in HSM or cloud KMS
- Enable audit logging
- Implement access controls
- Regular key rotation

### SOC 2

For service organizations:
- Document key management procedures
- Implement monitoring and alerting
- Maintain access logs
- Regular security assessments

## Security Checklist

### Configuration

- [ ] `EnableNonceTracking` is `true`
- [ ] `SecretBackend` uses hardware or cloud KMS
- [ ] Threshold is appropriate (recommend >= 3)
- [ ] Total allows for availability (recommend threshold + 2)

### Operations

- [ ] Key generation performed securely
- [ ] Shares distributed via secure channels
- [ ] Backup procedures documented and tested
- [ ] Monitoring and alerting configured
- [ ] Incident response plan documented

### Network

- [ ] TLS 1.3 for all communications
- [ ] mTLS for participant authentication
- [ ] Network segmentation in place
- [ ] Firewall rules configured

### Access Control

- [ ] Principle of least privilege applied
- [ ] Multi-factor authentication for operators
- [ ] Access logs enabled and reviewed
- [ ] Regular access reviews conducted

## Reporting Security Issues

If you discover a security vulnerability:

1. **Do not** disclose publicly
2. Email security@example.com with details
3. Include steps to reproduce
4. Allow reasonable time for fix before disclosure

We follow responsible disclosure practices and will credit reporters.
