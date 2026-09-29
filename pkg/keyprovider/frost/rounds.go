// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build frost

package frost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	gofrost "github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/signing"
)

// SignatureShare represents a participant's signature share.
type SignatureShare struct {
	// ParticipantID identifies who created this share
	ParticipantID uint32

	// SessionID identifies the signing session
	SessionID string

	// Share is the signature share bytes
	Share []byte
}

// DefaultSessionTimeout is the default timeout for signing sessions.
const DefaultSessionTimeout = 5 * time.Minute

// GenerateNonces generates nonces and commitments for Round 1 of FROST signing.
// The returned NoncePackage contains secret nonces (keep private) and
// public commitments (share with other participants).
//
// keyID is the key's storage key ID (see StorageKeyID), as it is for
// SignRound, Aggregate and Verify: the common name alone for a platform key,
// "{tenantID}:{cn}" for a tenant's key.
func (b *FrostBackend) GenerateNonces(keyID string) (*NoncePackage, error) {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return nil, ErrBackendClosed
	}
	b.mu.RUnlock()

	if err := validateStorageKeyID(keyID); err != nil {
		return nil, err
	}

	// Load key package - use participant ID from stored metadata (pass 0 to use metadata value)
	// This is critical for CLI usage where the config may use a default value
	// but the actual participant ID is stored in the key metadata.
	pkg, _, err := b.keystore.LoadKeyPackage(context.Background(), keyID, 0) // 0 = load from metadata; FROST round API carries no context
	if err != nil {
		return nil, err
	}
	participantID := pkg.ParticipantID

	// Get ciphersuite
	cs, err := GetCiphersuite(pkg.Algorithm)
	if err != nil {
		return nil, err
	}

	// Reconstruct go-frost KeyPackage for the participant
	grp := cs.Group()
	secretShare, err := grp.DeserializeScalar(pkg.SecretShare.Value)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to deserialize secret share", Err: err}
	}

	// Reconstruct group public key
	groupPublicKey, err := grp.DeserializeElement(pkg.GroupPublicKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to deserialize group public key", Err: err}
	}

	// Build verification shares
	var verificationShares []gofrost.VerificationShare
	for id, vsBytes := range pkg.VerificationShares {
		vs, err := grp.DeserializeElement(vsBytes)
		if err != nil {
			return nil, &errs.Wrapped{Msg: fmt.Sprintf("failed to deserialize verification share for participant %d", id), Err: err}
		}
		verificationShares = append(verificationShares, gofrost.VerificationShare{
			Identifier:      gofrost.Identifier(id),
			VerificationKey: vs,
		})
	}

	// Create go-frost KeyPackage
	gofrostPkg := gofrost.KeyPackage{
		Identifier:         gofrost.Identifier(participantID),
		SecretShare:        secretShare,
		GroupPublicKey:     groupPublicKey,
		VerificationShares: verificationShares,
		MinSigners:         pkg.MinSigners,
		MaxSigners:         pkg.MaxSigners,
	}

	// Create participant and generate nonces
	participant := signing.NewParticipant(gofrostPkg, cs)
	signingNonces, signingCommitments, err := participant.RoundOne()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate nonces", Err: err}
	}

	// Serialize nonces and commitments
	hidingNonceBytes := signingNonces.HidingNonce.Bytes()
	bindingNonceBytes := signingNonces.BindingNonce.Bytes()
	hidingCommitmentBytes := signingCommitments.HidingNonceCommitment.Bytes()
	bindingCommitmentBytes := signingCommitments.BindingNonceCommitment.Bytes()

	// Generate session ID
	sessionIDBytes := make([]byte, 16)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate session ID", Err: err}
	}
	sessionID := hex.EncodeToString(sessionIDBytes)

	noncePackage := &NoncePackage{
		ParticipantID: participantID,
		SessionID:     sessionID,
		Nonces: &SigningNonces{
			HidingNonce:  hidingNonceBytes,
			BindingNonce: bindingNonceBytes,
		},
		Commitments: &SigningCommitments{
			ParticipantID:     participantID,
			HidingCommitment:  hidingCommitmentBytes,
			BindingCommitment: bindingCommitmentBytes,
		},
	}

	// Store session for Round 2
	b.sessionsMu.Lock()
	b.sessions[sessionID] = &SigningSession{
		SessionID:     sessionID,
		KeyID:         keyID,
		ParticipantID: participantID,
		Nonces:        noncePackage,
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(DefaultSessionTimeout),
	}
	b.sessionsMu.Unlock()

	return noncePackage, nil
}

// SignRound generates a signature share for Round 2 of FROST signing.
// This requires the nonces from Round 1 and commitments from all signing participants.
func (b *FrostBackend) SignRound(
	keyID string,
	message []byte,
	nonces *NoncePackage,
	commitments []*Commitment,
) (*SignatureShare, error) {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return nil, ErrBackendClosed
	}
	b.mu.RUnlock()

	if err := validateStorageKeyID(keyID); err != nil {
		return nil, err
	}

	// Validate inputs
	if nonces == nil {
		return nil, ErrNonceNotFound
	}
	if len(commitments) == 0 {
		return nil, ErrInvalidCommitment
	}

	// Load key package
	participantID := nonces.ParticipantID
	pkg, _, err := b.keystore.LoadKeyPackage(context.Background(), keyID, participantID)
	if err != nil {
		return nil, err
	}

	// Check threshold
	if len(commitments) < int(pkg.MinSigners) {
		return nil, ErrInsufficientShares
	}

	// Check nonce reuse
	if b.config.EnableNonceTracking {
		commitmentBytes := nonces.Commitments.Serialize()
		if err := b.nonceTracker.MarkUsedWithDetails(
			keyID,
			participantID,
			nonces.SessionID,
			commitmentBytes,
		); err != nil {
			return nil, err
		}
	}

	// Get ciphersuite
	cs, err := GetCiphersuite(pkg.Algorithm)
	if err != nil {
		return nil, err
	}

	// Reconstruct go-frost types
	grp := cs.Group()
	secretShare, err := grp.DeserializeScalar(pkg.SecretShare.Value)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to deserialize secret share", Err: err}
	}
	defer func() {
		// Zeroize secret share after use
		pkg.SecretShare.Zeroize()
	}()

	// Reconstruct group public key
	groupPublicKey, err := grp.DeserializeElement(pkg.GroupPublicKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to deserialize group public key", Err: err}
	}

	// Build verification shares
	var verificationShares []gofrost.VerificationShare
	for id, vsBytes := range pkg.VerificationShares {
		vs, err := grp.DeserializeElement(vsBytes)
		if err != nil {
			return nil, &errs.Wrapped{Msg: fmt.Sprintf("failed to deserialize verification share for participant %d", id), Err: err}
		}
		verificationShares = append(verificationShares, gofrost.VerificationShare{
			Identifier:      gofrost.Identifier(id),
			VerificationKey: vs,
		})
	}

	// Create go-frost KeyPackage
	gofrostPkg := gofrost.KeyPackage{
		Identifier:         gofrost.Identifier(participantID),
		SecretShare:        secretShare,
		GroupPublicKey:     groupPublicKey,
		VerificationShares: verificationShares,
		MinSigners:         pkg.MinSigners,
		MaxSigners:         pkg.MaxSigners,
	}

	// Reconstruct nonces
	hidingNonce, err := grp.DeserializeScalar(nonces.Nonces.HidingNonce)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to deserialize hiding nonce", Err: err}
	}

	bindingNonce, err := grp.DeserializeScalar(nonces.Nonces.BindingNonce)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to deserialize binding nonce", Err: err}
	}

	// Reconstruct hiding/binding commitments
	hidingCommitment, err := grp.DeserializeElement(nonces.Commitments.HidingCommitment)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to deserialize hiding commitment", Err: err}
	}

	bindingCommitment, err := grp.DeserializeElement(nonces.Commitments.BindingCommitment)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to deserialize binding commitment", Err: err}
	}

	signingNonces := gofrost.SigningNonces{
		HidingNonce:  hidingNonce,
		BindingNonce: bindingNonce,
		Commitments: gofrost.SigningCommitments{
			Identifier:             gofrost.Identifier(participantID),
			HidingNonceCommitment:  hidingCommitment,
			BindingNonceCommitment: bindingCommitment,
		},
	}

	// Reconstruct commitments list
	var commitmentList gofrost.CommitmentList
	for _, c := range commitments {
		hc, err := grp.DeserializeElement(c.Commitments.HidingCommitment)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to deserialize hiding commitment", Err: err}
		}

		bc, err := grp.DeserializeElement(c.Commitments.BindingCommitment)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to deserialize binding commitment", Err: err}
		}

		commitmentList = append(commitmentList, gofrost.SigningCommitments{
			Identifier:             gofrost.Identifier(c.ParticipantID),
			HidingNonceCommitment:  hc,
			BindingNonceCommitment: bc,
		})
	}

	// Create participant and generate signature share
	participant := signing.NewParticipant(gofrostPkg, cs)
	signatureShare, err := participant.RoundTwo(signingNonces, message, commitmentList)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate signature share", Err: err}
	}

	// Serialize signature share
	shareBytes := signatureShare.SignatureShare.Bytes()

	// Zeroize nonces after use
	nonces.Nonces.Zeroize()

	return &SignatureShare{
		ParticipantID: participantID,
		SessionID:     nonces.SessionID,
		Share:         shareBytes,
	}, nil
}

// Aggregate combines signature shares into a final FROST signature.
// Requires at least threshold number of valid signature shares.
func (b *FrostBackend) Aggregate(
	keyID string,
	message []byte,
	commitments []*Commitment,
	shares []*SignatureShare,
) ([]byte, error) {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return nil, ErrBackendClosed
	}
	b.mu.RUnlock()

	if err := validateStorageKeyID(keyID); err != nil {
		return nil, err
	}

	// Load public key package
	pubPkg, _, err := b.keystore.LoadPublicKeyPackage(context.Background(), keyID)
	if err != nil {
		return nil, err
	}

	// Check threshold
	if len(shares) < int(pubPkg.MinSigners) {
		return nil, ErrInsufficientShares
	}

	// Get ciphersuite
	cs, err := GetCiphersuite(pubPkg.Algorithm)
	if err != nil {
		return nil, err
	}

	// Reconstruct group public key
	grp := cs.Group()
	groupPublicKey, err := grp.DeserializeElement(pubPkg.GroupPublicKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to deserialize group public key", Err: err}
	}

	// Reconstruct commitments
	var commitmentList gofrost.CommitmentList
	for _, c := range commitments {
		hc, err := grp.DeserializeElement(c.Commitments.HidingCommitment)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to deserialize hiding commitment", Err: err}
		}

		bc, err := grp.DeserializeElement(c.Commitments.BindingCommitment)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to deserialize binding commitment", Err: err}
		}

		commitmentList = append(commitmentList, gofrost.SigningCommitments{
			Identifier:             gofrost.Identifier(c.ParticipantID),
			HidingNonceCommitment:  hc,
			BindingNonceCommitment: bc,
		})
	}

	// Reconstruct signature shares
	var frostShares []gofrost.SignatureShare
	for _, share := range shares {
		s, err := grp.DeserializeScalar(share.Share)
		if err != nil {
			return nil, &errs.Wrapped{Msg: fmt.Sprintf("failed to deserialize signature share from participant %d", share.ParticipantID), Err: err}
		}

		frostShares = append(frostShares, gofrost.SignatureShare{
			Identifier:     gofrost.Identifier(share.ParticipantID),
			SignatureShare: s,
		})
	}

	// Create aggregator and aggregate signature
	aggregator := signing.NewAggregator(cs, pubPkg.MinSigners)
	signature, err := aggregator.Aggregate(groupPublicKey, commitmentList, message, frostShares)
	if err != nil {
		// Check if we can identify culprits
		return nil, &CulpritError{
			KeyID:  keyID,
			Reason: err.Error(),
		}
	}

	// Serialize signature (R || z)
	rBytes := signature.R.Bytes()
	zBytes := signature.Z.Bytes()
	signatureBytes := make([]byte, len(rBytes)+len(zBytes))
	copy(signatureBytes[:len(rBytes)], rBytes)
	copy(signatureBytes[len(rBytes):], zBytes)

	return signatureBytes, nil
}

// Verify verifies a FROST signature against the group public key.
func (b *FrostBackend) Verify(keyID string, message, signature []byte) error {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return ErrBackendClosed
	}
	b.mu.RUnlock()

	if err := validateStorageKeyID(keyID); err != nil {
		return err
	}

	// Load public key package
	pubPkg, _, err := b.keystore.LoadPublicKeyPackage(context.Background(), keyID)
	if err != nil {
		return err
	}

	// Get ciphersuite
	cs, err := GetCiphersuite(pubPkg.Algorithm)
	if err != nil {
		return err
	}

	// Reconstruct group public key
	grp := cs.Group()
	groupPublicKey, err := grp.DeserializeElement(pubPkg.GroupPublicKey)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to deserialize group public key", Err: err}
	}

	// Deserialize signature
	scalarSize := GetScalarSize(pubPkg.Algorithm)
	pubKeySize := GetPublicKeySize(pubPkg.Algorithm)
	expectedSize := pubKeySize + scalarSize
	if len(signature) != expectedSize {
		return &errs.Message{Msg: fmt.Sprintf("invalid signature size: got %d, expected %d", len(signature), expectedSize)}
	}

	// Split signature into R and z
	rBytes := signature[:pubKeySize]
	zBytes := signature[pubKeySize:]

	r, err := grp.DeserializeElement(rBytes)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to deserialize signature R", Err: err}
	}

	z, err := grp.DeserializeScalar(zBytes)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to deserialize signature z", Err: err}
	}

	// Create signature and verify
	sig := gofrost.Signature{
		R: r,
		Z: z,
	}

	aggregator := signing.NewAggregator(cs, pubPkg.MinSigners)
	if err := aggregator.Verify(message, sig, groupPublicKey); err != nil {
		return ErrInvalidSignature
	}

	return nil
}
