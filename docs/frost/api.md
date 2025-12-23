# FROST Go API Reference

This document provides comprehensive Go API documentation for the FROST backend.

## Package Import

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/backend/frost"
    "github.com/jeremyhahn/go-keychain/pkg/types"
)
```

## FrostBackend

The main backend implementation.

### NewBackend

Create a new FROST backend instance.

```go
func NewBackend(config *Config) (*FrostBackend, error)
```

**Parameters:**
- `config` - Backend configuration (see [Configuration](configuration.md))

**Returns:**
- `*FrostBackend` - The backend instance
- `error` - Error if configuration is invalid

**Example:**

```go
backend, err := frost.NewBackend(&frost.Config{
    PublicStorage:       publicStorage,
    SecretBackend:       tpm2Backend,
    Algorithm:           types.FrostAlgorithmEd25519,
    ParticipantID:       1,
    DefaultThreshold:    3,
    DefaultTotal:        5,
    Participants:        []string{"alice", "bob", "charlie", "dave", "eve"},
    EnableNonceTracking: true,
})
if err != nil {
    log.Fatal(err)
}
defer backend.Close()
```

### Type

Returns the backend type identifier.

```go
func (b *FrostBackend) Type() types.BackendType
```

**Returns:**
- `types.BackendTypeFrost`

### Capabilities

Returns the backend capabilities.

```go
func (b *FrostBackend) Capabilities() types.Capabilities
```

**Returns:**

```go
types.Capabilities{
    Keys:                true,
    HardwareBacked:      false,  // Depends on SecretBackend
    Signing:             true,
    Decryption:          false,  // FROST is signing-only
    KeyRotation:         true,
    SymmetricEncryption: false,
    Import:              true,
    Export:              false,
    KeyAgreement:        false,
    ECIES:               false,
}
```

### GenerateKey

Generate a new FROST key using the trusted dealer or custom DKG.

```go
func (b *FrostBackend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error)
```

**Parameters:**
- `attrs` - Key attributes including FrostAttributes

**Returns:**
- `crypto.PrivateKey` - Key handle (not the actual private key)
- `error` - Error if generation fails

**Example:**

```go
attrs := &types.KeyAttributes{
    CN:      "my-frost-key",
    KeyType: types.KeyTypeFrost,
    FrostAttributes: &types.FrostAttributes{
        Threshold:     3,
        Total:         5,
        Algorithm:     types.FrostAlgorithmEd25519,
        Participants:  []string{"alice", "bob", "charlie", "dave", "eve"},
        ParticipantID: 1,
    },
}

key, err := backend.GenerateKey(attrs)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Generated key: %s\n", attrs.CN)
```

### GetKey

Retrieve an existing FROST key.

```go
func (b *FrostBackend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error)
```

**Parameters:**
- `attrs` - Key attributes (CN is used as key ID)

**Returns:**
- `crypto.PrivateKey` - Key handle
- `error` - `ErrKeyNotFound` if key doesn't exist

**Example:**

```go
attrs := &types.KeyAttributes{
    CN: "my-frost-key",
}

key, err := backend.GetKey(attrs)
if err != nil {
    if errors.Is(err, frost.ErrKeyNotFound) {
        log.Println("Key not found")
    }
    log.Fatal(err)
}
```

### DeleteKey

Delete a FROST key and all associated data.

```go
func (b *FrostBackend) DeleteKey(attrs *types.KeyAttributes) error
```

**Parameters:**
- `attrs` - Key attributes (CN is used as key ID)

**Returns:**
- `error` - Error if deletion fails

**Example:**

```go
err := backend.DeleteKey(&types.KeyAttributes{
    CN: "my-frost-key",
})
if err != nil {
    log.Fatal(err)
}
```

### ListKeys

List all FROST keys managed by this backend.

```go
func (b *FrostBackend) ListKeys() ([]*types.KeyAttributes, error)
```

**Returns:**
- `[]*types.KeyAttributes` - List of key attributes
- `error` - Error if listing fails

**Example:**

```go
keys, err := backend.ListKeys()
if err != nil {
    log.Fatal(err)
}

for _, key := range keys {
    fmt.Printf("Key: %s, Algorithm: %s, Threshold: %d/%d\n",
        key.CN,
        key.FrostAttributes.Algorithm,
        key.FrostAttributes.Threshold,
        key.FrostAttributes.Total,
    )
}
```

### Signer

Get a crypto.Signer for orchestrated signing.

```go
func (b *FrostBackend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error)
```

**Parameters:**
- `attrs` - Key attributes

**Returns:**
- `crypto.Signer` - Signer implementation
- `error` - Error if key not found

**Example:**

```go
signer, err := backend.Signer(&types.KeyAttributes{
    CN: "my-frost-key",
})
if err != nil {
    log.Fatal(err)
}

// Use with standard crypto.Signer interface
message := []byte("Hello, FROST!")
digest := sha256.Sum256(message)

signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
if err != nil {
    log.Fatal(err)
}
```

### Close

Close the backend and release resources.

```go
func (b *FrostBackend) Close() error
```

**Example:**

```go
defer backend.Close()
```

## Explicit Round API

For fine-grained control over the signing protocol.

### GenerateNonces

Generate nonces and commitments for Round 1.

```go
func (b *FrostBackend) GenerateNonces(keyID string) (*NoncePackage, error)
```

**Parameters:**
- `keyID` - Key identifier

**Returns:**
- `*NoncePackage` - Nonce package containing secret nonces and public commitments
- `error` - Error if generation fails

**Example:**

```go
noncePackage, err := backend.GenerateNonces("my-frost-key")
if err != nil {
    log.Fatal(err)
}

// Share commitments with other participants
commitments := noncePackage.Commitments
fmt.Printf("Commitments: %+v\n", commitments)

// Keep nonces secret for Round 2
// Do NOT share noncePackage.Nonces
```

### SignRound

Generate a signature share for Round 2.

```go
func (b *FrostBackend) SignRound(
    keyID string,
    message []byte,
    nonces *NoncePackage,
    commitments []*Commitment,
) (*SignatureShare, error)
```

**Parameters:**
- `keyID` - Key identifier
- `message` - Message to sign
- `nonces` - This participant's nonce package from Round 1
- `commitments` - Collected commitments from all signing participants

**Returns:**
- `*SignatureShare` - This participant's signature share
- `error` - Error if signing fails (including nonce reuse)

**Example:**

```go
// Collect commitments from all participants
commitments := []*frost.Commitment{
    aliceCommitment,
    bobCommitment,
    charlieCommitment,
}

// Generate signature share
share, err := backend.SignRound(
    "my-frost-key",
    []byte("Hello, FROST!"),
    myNoncePackage,
    commitments,
)
if err != nil {
    if errors.Is(err, frost.ErrNonceAlreadyUsed) {
        log.Fatal("CRITICAL: Nonce reuse detected!")
    }
    log.Fatal(err)
}

// Share signature share with aggregator
fmt.Printf("Signature share: %x\n", share.Share)
```

### Aggregate

Combine signature shares into a final signature.

```go
func (b *FrostBackend) Aggregate(
    keyID string,
    message []byte,
    commitments []*Commitment,
    shares []*SignatureShare,
) ([]byte, error)
```

**Parameters:**
- `keyID` - Key identifier
- `message` - Original message
- `commitments` - All commitments used in signing
- `shares` - Collected signature shares (at least threshold)

**Returns:**
- `[]byte` - Aggregated signature
- `error` - Error if aggregation fails

**Example:**

```go
// Collect signature shares
shares := []*frost.SignatureShare{
    aliceShare,
    bobShare,
    charlieShare,
}

// Aggregate into final signature
signature, err := backend.Aggregate(
    "my-frost-key",
    []byte("Hello, FROST!"),
    commitments,
    shares,
)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Final signature: %x\n", signature)
```

### Verify

Verify a FROST signature.

```go
func (b *FrostBackend) Verify(
    keyID string,
    message []byte,
    signature []byte,
) error
```

**Parameters:**
- `keyID` - Key identifier
- `message` - Original message
- `signature` - Signature to verify

**Returns:**
- `error` - `nil` if valid, error if invalid

**Example:**

```go
err := backend.Verify("my-frost-key", message, signature)
if err != nil {
    log.Fatal("Signature verification failed:", err)
}

fmt.Println("Signature verified successfully!")
```

## Types

### NoncePackage

Contains nonces and commitments from Round 1.

```go
type NoncePackage struct {
    // ParticipantID identifies which participant generated this
    ParticipantID uint32

    // SessionID groups nonces for a signing session
    SessionID string

    // Nonces are secret and must not be shared
    Nonces *SigningNonces

    // Commitments are public and shared with other participants
    Commitments *SigningCommitments
}
```

### SigningNonces

Secret nonces (never share these).

```go
type SigningNonces struct {
    HidingNonce  []byte
    BindingNonce []byte
}

// Zeroize securely erases the nonce material
func (n *SigningNonces) Zeroize()
```

### SigningCommitments

Public commitments (share with other participants).

```go
type SigningCommitments struct {
    ParticipantID    uint32
    HidingCommitment []byte
    BindingCommitment []byte
}
```

### Commitment

Wrapper for commitments with serialization.

```go
type Commitment struct {
    ParticipantID uint32
    Commitments   *SigningCommitments
}

// Serialize returns the commitment in wire format
func (c *Commitment) Serialize() []byte
```

### SignatureShare

A participant's signature share.

```go
type SignatureShare struct {
    ParticipantID uint32
    SessionID     string
    Share         []byte
}
```

### KeyGenerator

Interface for pluggable key generation.

```go
type KeyGenerator interface {
    Generate(config FrostConfig) (*KeyPackage, *PublicKeyPackage, error)
}
```

### TrustedDealer

Built-in trusted dealer implementation.

```go
type TrustedDealer struct{}

func (td *TrustedDealer) Generate(config FrostConfig) (*KeyPackage, *PublicKeyPackage, error)
```

### FrostConfig

Configuration for key generation.

```go
type FrostConfig struct {
    Threshold    int
    Total        int
    Algorithm    types.FrostAlgorithm
    Participants []string
}
```

## Error Types

```go
var (
    // ErrKeyNotFound indicates the requested key doesn't exist
    ErrKeyNotFound = errors.New("frost: key not found")

    // ErrInsufficientShares indicates not enough shares for threshold
    ErrInsufficientShares = errors.New("frost: insufficient signature shares")

    // ErrNonceAlreadyUsed indicates a nonce reuse attempt
    ErrNonceAlreadyUsed = errors.New("frost: nonce already used")

    // ErrInvalidSignature indicates signature verification failed
    ErrInvalidSignature = errors.New("frost: invalid signature")

    // ErrInvalidCommitment indicates malformed commitment data
    ErrInvalidCommitment = errors.New("frost: invalid commitment")

    // ErrInvalidShare indicates malformed signature share
    ErrInvalidShare = errors.New("frost: invalid signature share")

    // ErrSessionNotFound indicates the signing session doesn't exist
    ErrSessionNotFound = errors.New("frost: session not found")

    // ErrBackendClosed indicates the backend has been closed
    ErrBackendClosed = errors.New("frost: backend closed")

    // ErrNotImplemented indicates a feature is not supported
    ErrNotImplemented = errors.New("frost: not implemented")
)
```

## Complete Examples

### Example 1: Basic Key Generation and Signing

```go
package main

import (
    "crypto"
    "crypto/rand"
    "crypto/sha256"
    "fmt"
    "log"

    "github.com/jeremyhahn/go-keychain/pkg/backend/frost"
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
    "github.com/jeremyhahn/go-keychain/pkg/types"
)

func main() {
    // Create storage
    publicStorage := file.NewBackend("./frost-data/public")
    secretStorage := file.NewBackend("./frost-data/secret")

    // Create backend
    backend, err := frost.NewBackend(&frost.Config{
        PublicStorage:       publicStorage,
        SecretBackend:       secretStorage,
        Algorithm:           types.FrostAlgorithmEd25519,
        ParticipantID:       1,
        DefaultThreshold:    2,
        DefaultTotal:        3,
        Participants:        []string{"alice", "bob", "charlie"},
        EnableNonceTracking: true,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer backend.Close()

    // Generate key
    attrs := &types.KeyAttributes{
        CN:      "example-key",
        KeyType: types.KeyTypeFrost,
    }

    _, err = backend.GenerateKey(attrs)
    if err != nil {
        log.Fatal(err)
    }

    // Get signer
    signer, err := backend.Signer(attrs)
    if err != nil {
        log.Fatal(err)
    }

    // Sign message
    message := []byte("Hello, FROST!")
    digest := sha256.Sum256(message)

    signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Signature: %x\n", signature)

    // Verify
    err = backend.Verify("example-key", message, signature)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Signature verified!")
}
```

### Example 2: Explicit Round Signing (Distributed)

```go
package main

import (
    "fmt"
    "log"

    "github.com/jeremyhahn/go-keychain/pkg/backend/frost"
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
    "github.com/jeremyhahn/go-keychain/pkg/types"
)

// Simulates distributed signing with 3 participants
func main() {
    message := []byte("Transaction: Send 1 BTC to Alice")

    // Create backends for each participant
    participants := []struct {
        id      uint32
        name    string
        backend *frost.FrostBackend
    }{
        {1, "alice", nil},
        {2, "bob", nil},
        {3, "charlie", nil},
    }

    // Initialize backends
    for i := range participants {
        p := &participants[i]
        backend, err := frost.NewBackend(&frost.Config{
            PublicStorage:       file.NewBackend(fmt.Sprintf("./frost-data/%s/public", p.name)),
            SecretBackend:       file.NewBackend(fmt.Sprintf("./frost-data/%s/secret", p.name)),
            Algorithm:           types.FrostAlgorithmSecp256k1,
            ParticipantID:       p.id,
            DefaultThreshold:    2,
            DefaultTotal:        3,
            Participants:        []string{"alice", "bob", "charlie"},
            EnableNonceTracking: true,
        })
        if err != nil {
            log.Fatal(err)
        }
        defer backend.Close()
        p.backend = backend
    }

    keyID := "btc-signing-key"

    // Round 1: Generate nonces
    var noncePackages []*frost.NoncePackage
    var commitments []*frost.Commitment

    for _, p := range participants[:2] { // Only 2 of 3 needed
        nonces, err := p.backend.GenerateNonces(keyID)
        if err != nil {
            log.Fatal(err)
        }
        noncePackages = append(noncePackages, nonces)
        commitments = append(commitments, &frost.Commitment{
            ParticipantID: p.id,
            Commitments:   nonces.Commitments,
        })
    }

    // Round 2: Generate signature shares
    var shares []*frost.SignatureShare

    for i, p := range participants[:2] {
        share, err := p.backend.SignRound(keyID, message, noncePackages[i], commitments)
        if err != nil {
            log.Fatal(err)
        }
        shares = append(shares, share)
    }

    // Aggregate signature
    signature, err := participants[0].backend.Aggregate(keyID, message, commitments, shares)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Final signature: %x\n", signature)

    // Verify
    err = participants[0].backend.Verify(keyID, message, signature)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Signature verified!")
}
```

### Example 3: Using with Hardware Backend

```go
package main

import (
    "log"

    "github.com/jeremyhahn/go-keychain/pkg/backend/frost"
    "github.com/jeremyhahn/go-keychain/pkg/backend/tpm2"
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
    "github.com/jeremyhahn/go-keychain/pkg/types"
)

func main() {
    // Create TPM2 backend for secrets
    tpmBackend, err := tpm2.NewBackend(&tpm2.Config{
        Device: "/dev/tpmrm0",
    })
    if err != nil {
        log.Fatal(err)
    }
    defer tpmBackend.Close()

    // Create FROST backend with TPM-protected secrets
    backend, err := frost.NewBackend(&frost.Config{
        PublicStorage:       file.NewBackend("/var/lib/frost/public"),
        SecretBackend:       tpmBackend,
        Algorithm:           types.FrostAlgorithmP256,
        ParticipantID:       1,
        DefaultThreshold:    3,
        DefaultTotal:        5,
        EnableNonceTracking: true,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer backend.Close()

    // Use backend...
}
```

### Example 4: Custom DKG Integration

```go
package main

import (
    "log"

    "github.com/jeremyhahn/go-keychain/pkg/backend/frost"
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
    "github.com/jeremyhahn/go-keychain/pkg/types"
)

// MyDKG implements the KeyGenerator interface
type MyDKG struct {
    // Custom DKG state
}

func (d *MyDKG) Generate(config frost.FrostConfig) (*frost.KeyPackage, *frost.PublicKeyPackage, error) {
    // Implement your DKG protocol here
    // This might involve network communication with other participants
    return nil, nil, nil
}

func main() {
    backend, err := frost.NewBackend(&frost.Config{
        PublicStorage: file.NewBackend("./frost-data/public"),
        SecretBackend: file.NewBackend("./frost-data/secret"),
        DKG:           &MyDKG{}, // Use custom DKG
        Algorithm:     types.FrostAlgorithmEd25519,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer backend.Close()

    // GenerateKey will now use MyDKG instead of TrustedDealer
}
```
