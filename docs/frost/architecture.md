# FROST Backend Architecture

This document describes the system design and component architecture of the FROST backend integration in go-keychain.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Application Layer                               │
├─────────────────────────────────────────────────────────────────────────────┤
│  CLI Commands                          │  Go API                            │
│  ┌─────────────────────────────────┐   │  ┌─────────────────────────────┐   │
│  │ keychain frost keygen           │   │  │ backend.GenerateKey()       │   │
│  │ keychain frost sign             │   │  │ backend.Signer()            │   │
│  │ keychain frost round1/round2    │   │  │ backend.GenerateNonces()    │   │
│  │ keychain frost aggregate        │   │  │ backend.SignRound()         │   │
│  │ keychain frost verify           │   │  │ backend.Aggregate()         │   │
│  └─────────────────────────────────┘   │  └─────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              FROST Backend                                   │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                           FrostBackend                                  ││
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ ││
│  │  │ KeyGenerator │  │ NonceTracker │  │   Signer     │  │   Rounds    │ ││
│  │  │ (DKG/Dealer) │  │   (O(1))     │  │ (Orchestrated│  │ (Explicit)  │ ││
│  │  └──────────────┘  └──────────────┘  └──────────────┘  └─────────────┘ ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
┌─────────────────────────┐ ┌─────────────┐ ┌─────────────────────────────────┐
│     go-frost Library    │ │   Storage   │ │       Secret Backends           │
│  ┌───────────────────┐  │ │  ┌───────┐  │ │  ┌─────┐ ┌──────┐ ┌─────────┐  │
│  │ Ciphersuites      │  │ │  │ File  │  │ │  │TPM2 │ │PKCS11│ │Cloud KMS│  │
│  │ Key Generation    │  │ │  │Memory │  │ │  └─────┘ └──────┘ └─────────┘  │
│  │ Signing Protocol  │  │ │  │Custom │  │ │  ┌─────┐ ┌──────┐ ┌─────────┐  │
│  │ Verification      │  │ │  └───────┘  │ │  │ AWS │ │ GCP  │ │ Azure   │  │
│  └───────────────────┘  │ └─────────────┘ │  └─────┘ └──────┘ └─────────┘  │
└─────────────────────────┘                 └─────────────────────────────────┘
```

## Component Overview

### FrostBackend

The main backend implementation that satisfies the `types.Backend` interface.

```go
type FrostBackend struct {
    config       *Config
    service      *frost.FrostService    // go-frost service layer
    keystore     KeyStore               // Key package storage
    nonceTracker *NonceTracker          // Nonce reuse prevention
    closed       bool
    mu           sync.RWMutex

    // Session state for multi-round signing
    sessions     map[string]*SigningSession
    sessionsMu   sync.RWMutex
}
```

**Responsibilities:**
- Implements `types.Backend` interface for go-keychain integration
- Manages key generation via `KeyGenerator` interface
- Coordinates signing operations (both modes)
- Handles nonce tracking for security
- Manages session state for explicit round signing

### KeyGenerator Interface

Abstraction for key generation that supports both trusted dealer and custom DKG implementations.

```go
type KeyGenerator interface {
    Generate(config FrostConfig) (*KeyPackage, *PublicKeyPackage, error)
}
```

**Implementations:**
- `TrustedDealer` - RFC 9591 Appendix C trusted dealer key generation
- Custom implementations provided by the application

### Storage Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Storage Layer                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  PublicStorage (storage.Backend)                                │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  frost/                                                    │  │
│  │  ├── keys/{keyID}/                                        │  │
│  │  │   ├── metadata.json         # KeyAttributes            │  │
│  │  │   ├── group_public.json     # Group public key         │  │
│  │  │   └── verification_shares/  # Per-participant shares   │  │
│  │  │       ├── {participant_1}                              │  │
│  │  │       ├── {participant_2}                              │  │
│  │  │       └── ...                                          │  │
│  │  ├── nonces/{keyID}/                                      │  │
│  │  │   └── {commitment_hash}     # Used nonce markers       │  │
│  │  └── sessions/{sessionID}/                                │  │
│  │      ├── state.json            # Session metadata         │  │
│  │      └── commitments/          # Collected commitments    │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  SecretBackend (types.Backend)                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Stores secret key share using chosen backend:            │  │
│  │  - TPM2: Sealed key blob with PCR policy                 │  │
│  │  - PKCS#11: HSM private key object                       │  │
│  │  - AWS KMS: Encrypted data key                           │  │
│  │  - GCP KMS: Cloud-encrypted key material                 │  │
│  │  - Azure KV: Key Vault secret                            │  │
│  │  - Vault: Transit-encrypted secret                       │  │
│  │  - Software: Encrypted file                              │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Signing Modes

#### Mode 1: Orchestrated Signing

Uses the standard `crypto.Signer` interface for simplified integration:

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ Application  │────▶│ FrostSigner  │────▶│  Coordinator │
│              │     │              │     │   (Storage)  │
│  Sign(msg)   │     │ crypto.Signer│     │              │
└──────────────┘     └──────────────┘     └──────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ Participant 1│     │ Participant 2│     │ Participant 3│
│   (local)    │     │  (storage)   │     │  (storage)   │
└──────────────┘     └──────────────┘     └──────────────┘
```

#### Mode 2: Explicit Rounds

Fine-grained control for distributed signing scenarios:

```
Round 1: Nonce Generation
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ Participant 1│     │ Participant 2│     │ Participant 3│
│              │     │              │     │              │
│ GenerateNonces()   │ GenerateNonces()   │ GenerateNonces()
│      │             │      │             │      │
│      ▼             │      ▼             │      ▼
│ NoncePackage │     │ NoncePackage │     │ NoncePackage │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │
       └────────────────────┼────────────────────┘
                            ▼
                   Collect Commitments

Round 2: Signature Share Generation
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ Participant 1│     │ Participant 2│     │ Participant 3│
│              │     │              │     │              │
│ SignRound()  │     │ SignRound()  │     │ SignRound()  │
│      │             │      │             │      │
│      ▼             │      ▼             │      ▼
│ SignatureShare     │ SignatureShare     │ SignatureShare
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │
       └────────────────────┼────────────────────┘
                            ▼
                    Aggregate()
                            │
                            ▼
                   Final Signature
```

### Nonce Tracking

Simple O(1) storage-based nonce tracking to prevent catastrophic nonce reuse:

```
┌─────────────────────────────────────────────────────────────────┐
│                        NonceTracker                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  MarkUsed(keyID, commitment)                                    │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  1. hash = SHA256(commitment)                             │  │
│  │  2. key = "nonces/{keyID}/{hash}"                         │  │
│  │  3. if storage.Exists(key) → ErrNonceAlreadyUsed         │  │
│  │  4. storage.Put(key, marker)                              │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  IsUsed(keyID, commitment) → bool                               │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  1. hash = SHA256(commitment)                             │  │
│  │  2. key = "nonces/{keyID}/{hash}"                         │  │
│  │  3. return storage.Exists(key)  // O(1) lookup            │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Ciphersuite Selection

```
┌─────────────────────────────────────────────────────────────────┐
│                      Ciphersuite Layer                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  FrostAlgorithm                    go-frost Ciphersuite         │
│  ─────────────────────────────────────────────────────────────  │
│  FROST-Ed25519-SHA512      ──────▶  ed25519_sha512.New()        │
│  FROST-ristretto255-SHA512 ──────▶  ristretto255_sha512.New()   │
│  FROST-Ed448-SHAKE256      ──────▶  ed448_shake256.New()        │
│  FROST-P256-SHA256         ──────▶  p256_sha256.New()           │
│  FROST-secp256k1-SHA256    ──────▶  secp256k1_sha256.New()      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow

### Key Generation Flow

```
┌─────────────┐
│  GenerateKey │
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│  1. Validate KeyAttributes and FrostAttributes                  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. Select ciphersuite based on Algorithm                        │
└──────┬──────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. Call KeyGenerator.Generate()                                 │
│     - TrustedDealer: frost.TrustedDealerKeygen()                │
│     - Custom DKG: user-provided implementation                  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. Store components:                                            │
│     - Secret key share → SecretBackend                          │
│     - Group public key → PublicStorage                          │
│     - Verification shares → PublicStorage                       │
│     - Metadata → PublicStorage                                  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│  5. Return KeyAttributes with key ID                             │
└─────────────────────────────────────────────────────────────────┘
```

### Signing Flow (Explicit Rounds)

```
┌────────────────────────────────────────────────────────────────────────────┐
│                              Round 1                                        │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  GenerateNonces(keyID)                                                      │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │  1. Load key package from storage                                     │ │
│  │  2. Generate random nonces (hiding_nonce, binding_nonce)              │ │
│  │  3. Compute commitments                                               │ │
│  │  4. Store nonces in session (ephemeral, in-memory)                   │ │
│  │  5. Return NoncePackage with commitments (public)                    │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                        Collect all commitments
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                              Round 2                                        │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  SignRound(keyID, message, nonces, commitments)                            │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │  1. Check nonce not already used (NonceTracker)                       │ │
│  │  2. Load secret key share from SecretBackend                          │ │
│  │  3. Compute binding factor from commitments                           │ │
│  │  4. Generate signature share                                          │ │
│  │  5. Mark nonce as used                                                │ │
│  │  6. Zeroize secret material                                           │ │
│  │  7. Return SignatureShare                                             │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                        Collect signature shares
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                            Aggregation                                      │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Aggregate(keyID, message, commitments, shares)                            │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │  1. Verify minimum threshold of shares provided                       │ │
│  │  2. Validate each signature share                                     │ │
│  │  3. Combine shares into final signature (R, z)                        │ │
│  │  4. Verify final signature against group public key                   │ │
│  │  5. Return serialized signature                                       │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

## Build Tag Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Build Configuration                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  //go:build frost                                               │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  backend.go         Full implementation                   │  │
│  │  signer.go          FrostSigner implementation            │  │
│  │  rounds.go          Explicit round API                    │  │
│  │  keygen.go          KeyGenerator + TrustedDealer          │  │
│  │  storage.go         Storage abstraction                   │  │
│  │  nonce.go           NonceTracker                          │  │
│  │  ciphersuite.go     Ciphersuite mapping                   │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  //go:build !frost                                              │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  backend_stub.go    Returns "not compiled" errors         │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  Default: frost tag included via Makefile                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Integration with go-keychain

```
┌─────────────────────────────────────────────────────────────────┐
│                    go-keychain Integration                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  types.Backend Interface                                        │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Type()          → BackendTypeFrost                       │  │
│  │  Capabilities()  → {Signing: true, Keys: true, ...}      │  │
│  │  GenerateKey()   → Creates FROST key packages             │  │
│  │  GetKey()        → Loads key package                      │  │
│  │  DeleteKey()     → Removes key and all shares             │  │
│  │  ListKeys()      → Lists all FROST keys                   │  │
│  │  Signer()        → Returns FrostSigner                    │  │
│  │  Decrypter()     → ErrNotImplemented                      │  │
│  │  RotateKey()     → Regenerate with same config            │  │
│  │  Close()         → Cleanup resources                      │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  types.FrostAttributes                                          │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Threshold      int                                       │  │
│  │  Total          int                                       │  │
│  │  Algorithm      FrostAlgorithm                            │  │
│  │  Participants   []string                                  │  │
│  │  ParticipantID  uint32                                    │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Security Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                      Security Boundaries                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    Trusted Zone                          │    │
│  │  ┌─────────────────────────────────────────────────┐    │    │
│  │  │  Secret Key Share (never leaves SecretBackend)  │    │    │
│  │  │  Signing Nonces (ephemeral, in-memory only)     │    │    │
│  │  └─────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    Public Zone                           │    │
│  │  ┌─────────────────────────────────────────────────┐    │    │
│  │  │  Group Public Key                               │    │    │
│  │  │  Verification Shares                            │    │    │
│  │  │  Nonce Commitments                              │    │    │
│  │  │  Signature Shares                               │    │    │
│  │  │  Final Signatures                               │    │    │
│  │  └─────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  Key Invariant: Private key is NEVER reconstructed              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```
