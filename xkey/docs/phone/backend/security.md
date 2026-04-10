# Phone Backend Security

## Overview

The phone backend provides multiple layers of security to protect key material and operations. This document covers the threat model, security layers, and mitigations.

## Security Layers

| Layer | Protection | Mechanism |
|-------|-----------|-----------|
| 1. Hardware | Key material isolation | Android Keystore TEE/StrongBox |
| 2. Biometric | User presence/identity | Fingerprint/Face recognition |
| 3. Transport | Communication encryption | Noise XX protocol |
| 4. Pairing | Device authentication | Noise static key pairs |
| 5. Attestation | Hardware proof | Android Key Attestation X.509 chain |

## Threat Model

### Assets Protected

- Private keys (EC, RSA) stored in TEE/StrongBox
- Symmetric keys (AES-GCM) stored in TEE/StrongBox
- HMAC keys stored in TEE/StrongBox
- Session keys (Noise protocol)
- Pairing credentials (Noise static keys)

### Threat Actors

| Actor | Capability | Mitigations |
|-------|-----------|-------------|
| Network attacker | Intercept BLE/WiFi traffic | Noise XX encryption, no plaintext |
| Physical attacker (phone) | Has physical access to phone | Biometric + hardware keystore |
| Physical attacker (laptop) | Has physical access to laptop | Noise static keys encrypted at rest |
| Malicious app on phone | Code execution on phone | Android Keystore access controls, SELinux |
| Compromised laptop | Full control of laptop | Phone-side biometric still required |
| Supply chain | Modified firmware | Android Key Attestation verifies boot state |

### Attack Scenarios

**Scenario 1: Stolen phone**

- Attacker has phone but no fingerprint/face
- Keys are in TEE/StrongBox: cannot extract without biometric
- Noise static key is encrypted in app data: requires device unlock
- Mitigation: Strong - phone alone is insufficient

**Scenario 2: Stolen laptop**

- Attacker has laptop with Noise private key file
- Cannot connect to phone without BLE range
- Even with BLE connection, phone requires biometric for each key op
- Mitigation: Strong - laptop alone is insufficient

**Scenario 3: BLE eavesdropping**

- Attacker is within BLE range
- All traffic is Noise-encrypted: no plaintext exposure
- Cannot inject requests without Noise session
- Mitigation: Strong - Noise provides confidentiality and authenticity

**Scenario 4: ADB-enabled phone (USB transport Stage 1)**

- USB debugging is enabled for ADB port forwarding
- TCP server listens on localhost:8444 only (not network)
- Noise XX handshake still required (attacker needs static keys)
- Biometric still required for each operation
- Risk: ADB exposes broader attack surface on the phone
- Mitigation: Moderate - USB debugging is a known risk, eliminated in Stage 2

**Scenario 5: Compromised Go binary on laptop**

- Attacker controls the xkey binary
- Can send requests to phone, but still needs biometric approval
- Phone-side verification UI shows what operation is requested
- Mitigation: Moderate - biometric is last line of defense

## Hardware Security

### TEE (Trusted Execution Environment)

- ARM TrustZone-based isolated environment
- Keys generated and used inside TEE
- Private key material never enters main processor memory
- Available on all modern Android devices

### StrongBox (Dedicated Security Chip)

- Separate, tamper-resistant security module
- Physical protection against side-channel attacks
- Available on Pixel 3+ and select Samsung/other devices
- Preferred over TEE when available

### Security Level Verification

The attestation extension indicates the actual security level:

- `attestationSecurityLevel = 1` (TEE) - Key operations in TrustZone
- `attestationSecurityLevel = 2` (StrongBox) - Key operations in dedicated chip
- `attestationSecurityLevel = 0` (Software) - **Rejected** by phone backend verification

## Noise Protocol Security

### XX Pattern

```
-> e
<- e, ee, s, es
-> s, se
```

Properties:

- **Mutual authentication**: Both devices prove identity via static keys
- **Forward secrecy**: Ephemeral key exchange provides PFS
- **Identity hiding**: Static keys are encrypted during handshake
- **No pre-shared secrets**: Initial pairing can happen without prior relationship

### Key Material

| Key | Storage | Purpose |
|-----|---------|---------|
| Local static key | `~/.xkey/phone.yaml` (laptop) | Laptop identity |
| Remote static key | Phone app encrypted storage | Phone identity |
| Ephemeral keys | Memory only, per-session | Forward secrecy |
| Session keys | Memory only, derived from handshake | Encrypt/decrypt messages |

### Pairing Security

- First pairing displays a verification code on both devices
- User confirms codes match (prevents MITM)
- After pairing, static keys are stored for future connections
- Subsequent connections verify static keys match expected values

## Biometric Security

### Per-Operation Authentication

Every key operation (sign, decrypt, ECDH) requires fresh biometric authentication on the phone.

### Authentication Duration

- Configurable auth validity window (default: 5 seconds)
- After window expires, biometric must be re-presented
- Zero-duration mode: every single operation requires biometric

### Android Keystore Integration

- `setUserAuthenticationRequired(true)` - Key requires auth
- `setUserAuthenticationParameters(duration, AUTH_BIOMETRIC_STRONG)` - Biometric only
- `setIsStrongBoxBacked(true)` - Use StrongBox when available

## USB Transport Security (ADB - Stage 1)

### Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| USB debugging enabled | Medium | Required for Stage 1, eliminated in Stage 2 |
| ADB authorization | Low | Laptop must be ADB-authorized (RSA key) |
| localhost-only server | N/A | TCP server binds to 127.0.0.1 only |
| Noise handshake | N/A | Same encryption as BLE |
| Biometric | N/A | Same per-operation auth as BLE |

### Stage 2: Custom USB Driver

Future implementation eliminates the need for USB debugging by using:

- Android USB Accessory Mode (AOA)
- USB CDC-ACM serial communication
- Phone acts as USB accessory without debug mode

## Best Practices

1. **Enable StrongBox** when available for maximum hardware security
2. **Use short auth durations** (5 seconds or less) for sensitive keys
3. **Require biometric for all keys** - don't disable user authentication
4. **Verify attestation** before trusting a phone-backed key for high-security operations
5. **Use BLE transport** for wireless convenience, USB for higher bandwidth
6. **Disable USB debugging** when not needed (eliminates Stage 1 ADB risk)
7. **Rotate keys periodically** - generate new key, migrate, delete old

## See Also

- [Architecture](architecture.md)
- [Attestation](attestation.md)
- [Configuration](configuration.md)
- [xKey Phone Transport Security](../../../xkey/docs/phone/transport.md)
