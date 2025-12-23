# Custom DKG Integration Guide

This guide explains how to implement and integrate a custom Distributed Key Generation (DKG) protocol with the FROST backend.

## Overview

The FROST backend supports pluggable key generation through the `KeyGenerator` interface:

```go
type KeyGenerator interface {
    Generate(config FrostConfig) (*KeyPackage, *PublicKeyPackage, error)
}
```

By default, the backend uses `TrustedDealer` (RFC 9591 Appendix C), but you can provide your own DKG implementation for scenarios where no single party should have access to the complete secret.

## When to Use Custom DKG

| Scenario | Recommendation |
|----------|----------------|
| Single organization, trusted admin | TrustedDealer (default) |
| Multiple organizations | Custom DKG |
| No trusted dealer available | Custom DKG |
| Regulatory requirements | Custom DKG |
| Maximum security | Custom DKG |

## KeyGenerator Interface

### Interface Definition

```go
type KeyGenerator interface {
    // Generate creates key packages for a threshold signing group.
    //
    // Returns:
    //   - KeyPackage: This participant's secret key material
    //   - PublicKeyPackage: Public keys for all participants
    //   - error: Any error during generation
    Generate(config FrostConfig) (*KeyPackage, *PublicKeyPackage, error)
}
```

### FrostConfig

```go
type FrostConfig struct {
    // Threshold is the minimum number of signers (M)
    Threshold int

    // Total is the total number of participants (N)
    Total int

    // Algorithm is the FROST ciphersuite to use
    Algorithm types.FrostAlgorithm

    // Participants are the identifiers for each participant
    Participants []string

    // ParticipantID is this participant's identifier
    ParticipantID uint32
}
```

### KeyPackage

```go
type KeyPackage struct {
    // ParticipantID identifies this participant
    ParticipantID uint32

    // SecretShare is this participant's secret key share
    SecretShare *SecretKeyShare

    // GroupPublicKey is the threshold public key
    GroupPublicKey []byte

    // VerificationShares are public key shares for all participants
    VerificationShares map[uint32][]byte

    // Threshold parameters
    MinSigners uint32
    MaxSigners uint32
}

type SecretKeyShare struct {
    // Value is the secret scalar
    Value []byte

    // Zeroize securely erases the secret
    Zeroize()
}
```

### PublicKeyPackage

```go
type PublicKeyPackage struct {
    // GroupPublicKey is the threshold public key
    GroupPublicKey []byte

    // VerificationShares maps participant IDs to their public key shares
    VerificationShares map[uint32][]byte
}
```

## Implementing a Custom DKG

### Step 1: Create the DKG Structure

```go
package mydkg

import (
    "github.com/jeremyhahn/go-keychain/pkg/backend/frost"
    "github.com/jeremyhahn/go-keychain/pkg/types"
)

// MyDKG implements a custom Distributed Key Generation protocol
type MyDKG struct {
    // Network transport for DKG messages
    transport Transport

    // Participant's identity
    identity *Identity

    // DKG protocol state
    state *DKGState
}

type Transport interface {
    Broadcast(msg []byte) error
    Send(participantID uint32, msg []byte) error
    Receive() (uint32, []byte, error)
}

type Identity struct {
    ID         uint32
    PrivateKey []byte
    PublicKey  []byte
}

func NewMyDKG(transport Transport, identity *Identity) *MyDKG {
    return &MyDKG{
        transport: transport,
        identity:  identity,
    }
}
```

### Step 2: Implement the Generate Method

```go
func (d *MyDKG) Generate(config frost.FrostConfig) (*frost.KeyPackage, *frost.PublicKeyPackage, error) {
    // Validate configuration
    if err := d.validateConfig(config); err != nil {
        return nil, nil, err
    }

    // Initialize DKG state
    d.state = &DKGState{
        threshold:    config.Threshold,
        total:        config.Total,
        participants: config.Participants,
    }

    // Phase 1: Generate and broadcast commitments
    commitments, err := d.generateCommitments(config)
    if err != nil {
        return nil, nil, fmt.Errorf("commitment phase failed: %w", err)
    }

    // Phase 2: Exchange secret shares
    shares, err := d.exchangeShares(config, commitments)
    if err != nil {
        return nil, nil, fmt.Errorf("share exchange failed: %w", err)
    }

    // Phase 3: Verify and combine
    keyPackage, publicPackage, err := d.finalizeKeys(config, commitments, shares)
    if err != nil {
        return nil, nil, fmt.Errorf("key finalization failed: %w", err)
    }

    return keyPackage, publicPackage, nil
}
```

### Step 3: Implement DKG Phases

#### Phase 1: Commitment Generation

```go
func (d *MyDKG) generateCommitments(config frost.FrostConfig) (map[uint32]*Commitment, error) {
    // Generate random polynomial of degree (threshold - 1)
    polynomial, err := d.generatePolynomial(config.Threshold - 1)
    if err != nil {
        return nil, err
    }
    d.state.polynomial = polynomial

    // Create commitment to polynomial coefficients
    commitment := &Commitment{
        ParticipantID: d.identity.ID,
        Coefficients:  make([][]byte, len(polynomial)),
    }
    for i, coeff := range polynomial {
        commitment.Coefficients[i] = d.commitToCoefficient(coeff)
    }

    // Broadcast commitment
    commitmentBytes, _ := commitment.Marshal()
    if err := d.transport.Broadcast(commitmentBytes); err != nil {
        return nil, err
    }

    // Collect commitments from all participants
    commitments := make(map[uint32]*Commitment)
    commitments[d.identity.ID] = commitment

    for i := 0; i < config.Total-1; i++ {
        participantID, data, err := d.transport.Receive()
        if err != nil {
            return nil, err
        }

        var c Commitment
        if err := c.Unmarshal(data); err != nil {
            return nil, err
        }

        commitments[participantID] = &c
    }

    return commitments, nil
}
```

#### Phase 2: Share Exchange

```go
func (d *MyDKG) exchangeShares(
    config frost.FrostConfig,
    commitments map[uint32]*Commitment,
) (map[uint32][]byte, error) {
    // Evaluate polynomial at each participant's ID and send
    for i := uint32(1); i <= uint32(config.Total); i++ {
        if i == d.identity.ID {
            continue
        }

        share := d.evaluatePolynomial(d.state.polynomial, i)

        // Encrypt share for recipient
        encryptedShare, err := d.encryptShare(share, i)
        if err != nil {
            return nil, err
        }

        if err := d.transport.Send(i, encryptedShare); err != nil {
            return nil, err
        }
    }

    // Collect shares from all participants
    shares := make(map[uint32][]byte)

    // Include own share
    shares[d.identity.ID] = d.evaluatePolynomial(d.state.polynomial, d.identity.ID)

    for i := 0; i < config.Total-1; i++ {
        participantID, data, err := d.transport.Receive()
        if err != nil {
            return nil, err
        }

        // Decrypt and verify share
        share, err := d.decryptShare(data)
        if err != nil {
            return nil, err
        }

        // Verify share against commitment
        if err := d.verifyShare(share, participantID, commitments); err != nil {
            return nil, fmt.Errorf("invalid share from %d: %w", participantID, err)
        }

        shares[participantID] = share
    }

    return shares, nil
}
```

#### Phase 3: Key Finalization

```go
func (d *MyDKG) finalizeKeys(
    config frost.FrostConfig,
    commitments map[uint32]*Commitment,
    shares map[uint32][]byte,
) (*frost.KeyPackage, *frost.PublicKeyPackage, error) {
    // Combine received shares to get secret key share
    secretShare := d.combineShares(shares)

    // Compute group public key from commitments
    groupPublicKey := d.computeGroupPublicKey(commitments)

    // Compute verification shares for all participants
    verificationShares := make(map[uint32][]byte)
    for id := uint32(1); id <= uint32(config.Total); id++ {
        verificationShares[id] = d.computeVerificationShare(commitments, id)
    }

    // Create key packages
    keyPackage := &frost.KeyPackage{
        ParticipantID: d.identity.ID,
        SecretShare: &frost.SecretKeyShare{
            Value: secretShare,
        },
        GroupPublicKey:     groupPublicKey,
        VerificationShares: verificationShares,
        MinSigners:         uint32(config.Threshold),
        MaxSigners:         uint32(config.Total),
    }

    publicPackage := &frost.PublicKeyPackage{
        GroupPublicKey:     groupPublicKey,
        VerificationShares: verificationShares,
    }

    return keyPackage, publicPackage, nil
}
```

### Step 4: Register with FROST Backend

```go
package main

import (
    "github.com/jeremyhahn/go-keychain/pkg/backend/frost"
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
    "github.com/yourorg/mydkg"
)

func main() {
    // Create transport (implement based on your network architecture)
    transport := mydkg.NewGRPCTransport(...)

    // Create identity
    identity := &mydkg.Identity{
        ID: 1,
        // ... keys
    }

    // Create custom DKG
    dkg := mydkg.NewMyDKG(transport, identity)

    // Create FROST backend with custom DKG
    backend, err := frost.NewBackend(&frost.Config{
        PublicStorage: file.NewBackend("./frost-public"),
        SecretBackend: file.NewBackend("./frost-secret"),
        DKG:           dkg,  // Use custom DKG
        Algorithm:     types.FrostAlgorithmEd25519,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer backend.Close()

    // Generate key using custom DKG
    attrs := &types.KeyAttributes{
        CN:      "dkg-generated-key",
        KeyType: types.KeyTypeFrost,
        FrostAttributes: &types.FrostAttributes{
            Threshold:    3,
            Total:        5,
            Participants: []string{"node1", "node2", "node3", "node4", "node5"},
        },
    }

    _, err = backend.GenerateKey(attrs)
    if err != nil {
        log.Fatal(err)
    }
}
```

## Example: Pedersen DKG

A complete implementation of Pedersen's DKG protocol:

```go
package pedersen

import (
    "crypto/rand"
    "fmt"

    "github.com/jeremyhahn/go-keychain/pkg/backend/frost"
    "filippo.io/edwards25519"
)

type PedersenDKG struct {
    transport  Transport
    myID       uint32
    threshold  int
    total      int

    // Secret polynomial coefficients
    coefficients []*edwards25519.Scalar

    // Commitments from all participants
    commitments map[uint32][]*edwards25519.Point

    // Received shares
    receivedShares map[uint32]*edwards25519.Scalar
}

func NewPedersenDKG(transport Transport, myID uint32) *PedersenDKG {
    return &PedersenDKG{
        transport:      transport,
        myID:           myID,
        commitments:    make(map[uint32][]*edwards25519.Point),
        receivedShares: make(map[uint32]*edwards25519.Scalar),
    }
}

func (p *PedersenDKG) Generate(config frost.FrostConfig) (*frost.KeyPackage, *frost.PublicKeyPackage, error) {
    p.threshold = config.Threshold
    p.total = config.Total

    // Generate random polynomial
    if err := p.generatePolynomial(); err != nil {
        return nil, nil, err
    }

    // Broadcast commitments
    if err := p.broadcastCommitments(); err != nil {
        return nil, nil, err
    }

    // Collect commitments
    if err := p.collectCommitments(); err != nil {
        return nil, nil, err
    }

    // Send secret shares
    if err := p.sendShares(); err != nil {
        return nil, nil, err
    }

    // Receive and verify shares
    if err := p.receiveShares(); err != nil {
        return nil, nil, err
    }

    // Compute final key material
    return p.computeKeyPackages(config)
}

func (p *PedersenDKG) generatePolynomial() error {
    p.coefficients = make([]*edwards25519.Scalar, p.threshold)

    for i := 0; i < p.threshold; i++ {
        scalar, err := randomScalar()
        if err != nil {
            return err
        }
        p.coefficients[i] = scalar
    }

    return nil
}

func (p *PedersenDKG) broadcastCommitments() error {
    commitments := make([]*edwards25519.Point, p.threshold)

    for i, coeff := range p.coefficients {
        // C_i = g^{a_i}
        commitments[i] = new(edwards25519.Point).ScalarBaseMult(coeff)
    }

    p.commitments[p.myID] = commitments

    // Serialize and broadcast
    data := serializeCommitments(p.myID, commitments)
    return p.transport.Broadcast(data)
}

func (p *PedersenDKG) collectCommitments() error {
    for i := 0; i < p.total-1; i++ {
        senderID, data, err := p.transport.Receive()
        if err != nil {
            return err
        }

        _, commitments, err := deserializeCommitments(data)
        if err != nil {
            return err
        }

        p.commitments[senderID] = commitments
    }

    return nil
}

func (p *PedersenDKG) sendShares() error {
    for j := uint32(1); j <= uint32(p.total); j++ {
        if j == p.myID {
            continue
        }

        // Evaluate polynomial at j
        share := p.evaluateAt(j)

        // Encrypt share for participant j
        encryptedShare := p.encryptForParticipant(share, j)

        if err := p.transport.Send(j, encryptedShare); err != nil {
            return err
        }
    }

    return nil
}

func (p *PedersenDKG) receiveShares() error {
    // Own share
    p.receivedShares[p.myID] = p.evaluateAt(p.myID)

    for i := 0; i < p.total-1; i++ {
        senderID, data, err := p.transport.Receive()
        if err != nil {
            return err
        }

        share := p.decryptShare(data)

        // Verify: g^{s_{ij}} == prod_{k=0}^{t-1} C_{ik}^{j^k}
        if !p.verifyShare(share, senderID) {
            return fmt.Errorf("invalid share from participant %d", senderID)
        }

        p.receivedShares[senderID] = share
    }

    return nil
}

func (p *PedersenDKG) verifyShare(share *edwards25519.Scalar, senderID uint32) bool {
    // Left side: g^{s_{ij}}
    left := new(edwards25519.Point).ScalarBaseMult(share)

    // Right side: prod_{k=0}^{t-1} C_{ik}^{j^k}
    right := new(edwards25519.Point).Set(edwards25519.NewIdentityPoint())

    j := new(edwards25519.Scalar).SetUint64(uint64(p.myID))
    jPower := new(edwards25519.Scalar).One()

    for _, commitment := range p.commitments[senderID] {
        term := new(edwards25519.Point).ScalarMult(jPower, commitment)
        right.Add(right, term)
        jPower.Multiply(jPower, j)
    }

    return left.Equal(right) == 1
}

func (p *PedersenDKG) computeKeyPackages(config frost.FrostConfig) (*frost.KeyPackage, *frost.PublicKeyPackage, error) {
    // Secret share: sum of all received shares
    secretShare := new(edwards25519.Scalar).Set(edwards25519.NewScalar())
    for _, share := range p.receivedShares {
        secretShare.Add(secretShare, share)
    }

    // Group public key: sum of all constant term commitments
    groupPublicKey := new(edwards25519.Point).Set(edwards25519.NewIdentityPoint())
    for _, commitments := range p.commitments {
        groupPublicKey.Add(groupPublicKey, commitments[0])
    }

    // Verification shares
    verificationShares := make(map[uint32][]byte)
    for j := uint32(1); j <= uint32(p.total); j++ {
        vShare := p.computeVerificationShare(j)
        verificationShares[j] = vShare.Bytes()
    }

    keyPackage := &frost.KeyPackage{
        ParticipantID: p.myID,
        SecretShare: &frost.SecretKeyShare{
            Value: secretShare.Bytes(),
        },
        GroupPublicKey:     groupPublicKey.Bytes(),
        VerificationShares: verificationShares,
        MinSigners:         uint32(p.threshold),
        MaxSigners:         uint32(p.total),
    }

    publicPackage := &frost.PublicKeyPackage{
        GroupPublicKey:     groupPublicKey.Bytes(),
        VerificationShares: verificationShares,
    }

    return keyPackage, publicPackage, nil
}

func (p *PedersenDKG) evaluateAt(x uint32) *edwards25519.Scalar {
    result := new(edwards25519.Scalar).Set(edwards25519.NewScalar())
    xScalar := new(edwards25519.Scalar).SetUint64(uint64(x))
    xPower := new(edwards25519.Scalar).One()

    for _, coeff := range p.coefficients {
        term := new(edwards25519.Scalar).Multiply(coeff, xPower)
        result.Add(result, term)
        xPower.Multiply(xPower, xScalar)
    }

    return result
}

func (p *PedersenDKG) computeVerificationShare(j uint32) *edwards25519.Point {
    result := new(edwards25519.Point).Set(edwards25519.NewIdentityPoint())

    for _, commitments := range p.commitments {
        jScalar := new(edwards25519.Scalar).SetUint64(uint64(j))
        jPower := new(edwards25519.Scalar).One()

        for _, commitment := range commitments {
            term := new(edwards25519.Point).ScalarMult(jPower, commitment)
            result.Add(result, term)
            jPower.Multiply(jPower, jScalar)
        }
    }

    return result
}

func randomScalar() (*edwards25519.Scalar, error) {
    var b [64]byte
    if _, err := rand.Read(b[:]); err != nil {
        return nil, err
    }
    return edwards25519.NewScalar().SetUniformBytes(b[:])
}
```

## CLI Integration

Import DKG-generated keys using the CLI:

```bash
# Export key package from DKG (your implementation)
my-dkg-tool generate --output dkg-package.json

# Import into FROST backend
keychain frost import-dkg \
  --package dkg-package.json \
  --key-id my-dkg-key
```

## Testing Your DKG

```go
func TestMyDKG(t *testing.T) {
    // Create mock transports for testing
    transports := createMockTransports(5)

    // Create DKG instances
    var dkgs []*MyDKG
    for i := 0; i < 5; i++ {
        dkg := NewMyDKG(transports[i], &Identity{ID: uint32(i + 1)})
        dkgs = append(dkgs, dkg)
    }

    // Run DKG in parallel
    config := frost.FrostConfig{
        Threshold: 3,
        Total:     5,
        Algorithm: types.FrostAlgorithmEd25519,
    }

    var wg sync.WaitGroup
    results := make([]*frost.KeyPackage, 5)
    errors := make([]error, 5)

    for i, dkg := range dkgs {
        wg.Add(1)
        go func(idx int, d *MyDKG) {
            defer wg.Done()
            results[idx], _, errors[idx] = d.Generate(config)
        }(i, dkg)
    }

    wg.Wait()

    // Verify all succeeded
    for i, err := range errors {
        require.NoError(t, err, "DKG failed for participant %d", i+1)
    }

    // Verify all have same group public key
    for i := 1; i < 5; i++ {
        assert.Equal(t, results[0].GroupPublicKey, results[i].GroupPublicKey)
    }

    // Test threshold signing with DKG-generated keys
    // ...
}
```

## Security Considerations

### DKG Security Requirements

1. **Verifiable Secret Sharing**: All shares must be verifiable against commitments
2. **Complaint Protocol**: Mechanism to handle misbehaving participants
3. **Secure Channels**: Point-to-point messages must be encrypted
4. **Synchronization**: Ensure all participants complete each phase
5. **Abort Handling**: Clean up state if DKG fails

### Common Pitfalls

| Pitfall | Impact | Mitigation |
|---------|--------|------------|
| No share verification | Malicious shares accepted | Always verify against commitments |
| Unencrypted shares | Share theft | Use authenticated encryption |
| Missing participant | DKG hangs | Implement timeouts |
| State not cleared | Key material leaked | Always zeroize on error |
