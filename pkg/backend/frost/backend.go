// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build frost

package frost

import (
	"crypto"
	"fmt"
	"sync"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// FrostBackend implements the types.Backend interface for FROST threshold signatures.
// It provides RFC 9591 compliant FROST operations with pluggable secret storage.
type FrostBackend struct {
	config       *Config
	keystore     *KeyStore
	nonceTracker *NonceTracker
	keyGenerator KeyGenerator
	closed       bool
	mu           sync.RWMutex

	// Session state for multi-round signing
	sessions   map[string]*SigningSession
	sessionsMu sync.RWMutex
}

// SigningSession tracks state for a multi-round signing operation.
type SigningSession struct {
	// SessionID uniquely identifies this session
	SessionID string

	// KeyID identifies the key being used
	KeyID string

	// ParticipantID identifies this participant
	ParticipantID uint32

	// Nonces is this participant's nonce package
	Nonces *NoncePackage

	// CollectedCommitments are commitments from other participants
	CollectedCommitments []*Commitment

	// CreatedAt is when the session was created
	CreatedAt time.Time

	// ExpiresAt is when the session expires
	ExpiresAt time.Time
}

// NewBackend creates a new FROST backend with the given configuration.
func NewBackend(config *Config) (*FrostBackend, error) {
	// Set defaults
	config.SetDefaults()

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid frost config: %w", err)
	}

	// Create keystore
	keystore := NewKeyStore(config.PublicStorage, config.SecretBackend)

	// Create nonce tracker
	nonceStorage := config.GetNonceStorage()
	nonceTracker := NewNonceTracker(nonceStorage)

	// Get key generator
	keyGenerator := config.GetKeyGenerator()

	return &FrostBackend{
		config:       config,
		keystore:     keystore,
		nonceTracker: nonceTracker,
		keyGenerator: keyGenerator,
		sessions:     make(map[string]*SigningSession),
	}, nil
}

// Type returns the backend type identifier.
func (b *FrostBackend) Type() types.BackendType {
	return types.BackendTypeFrost
}

// Capabilities returns what features this backend supports.
func (b *FrostBackend) Capabilities() types.Capabilities {
	// Check if secret backend is hardware-backed
	hardwareBacked := false
	if b.config.SecretBackend != nil {
		caps := b.config.SecretBackend.Capabilities()
		hardwareBacked = caps.HardwareBacked
	}

	return types.Capabilities{
		Keys:                true,
		HardwareBacked:      hardwareBacked,
		Signing:             true,
		Decryption:          false, // FROST is signing-only (RFC 9591)
		KeyRotation:         true,
		SymmetricEncryption: false,
		Sealing:             false,
		Import:              true,
		Export:              false, // Secret shares should not be exported
		KeyAgreement:        false,
		ECIES:               false,
	}
}

// GenerateKey generates a new FROST key with the given attributes.
func (b *FrostBackend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return nil, ErrBackendClosed
	}
	b.mu.RUnlock()

	// Validate attributes
	if err := attrs.Validate(); err != nil {
		return nil, fmt.Errorf("invalid attributes: %w", err)
	}

	// Get or create FROST attributes
	frostAttrs := attrs.FrostAttributes
	if frostAttrs == nil {
		frostAttrs = &types.FrostAttributes{
			Threshold:     b.config.DefaultThreshold,
			Total:         b.config.DefaultTotal,
			Algorithm:     b.config.Algorithm,
			Participants:  b.config.Participants,
			ParticipantID: b.config.ParticipantID,
		}
		attrs.FrostAttributes = frostAttrs
	}

	// Set defaults from config if not specified
	if frostAttrs.Threshold == 0 {
		frostAttrs.Threshold = b.config.DefaultThreshold
	}
	if frostAttrs.Total == 0 {
		frostAttrs.Total = b.config.DefaultTotal
	}
	if frostAttrs.Algorithm == "" {
		frostAttrs.Algorithm = b.config.Algorithm
	}
	if len(frostAttrs.Participants) == 0 && len(b.config.Participants) > 0 {
		frostAttrs.Participants = b.config.Participants
	}
	if frostAttrs.ParticipantID == 0 {
		frostAttrs.ParticipantID = b.config.ParticipantID
	}

	// Validate FROST attributes
	if err := frostAttrs.Validate(); err != nil {
		return nil, fmt.Errorf("invalid frost attributes: %w", err)
	}

	keyID := attrs.CN
	if keyID == "" {
		return nil, &ConfigError{Field: "CN", Message: "key ID (CN) is required"}
	}

	// Check if key already exists
	exists, err := b.keystore.KeyExists(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to check key existence: %w", err)
	}
	if exists {
		return nil, ErrKeyAlreadyExists
	}

	// Generate key packages
	genConfig := FrostConfig{
		Threshold:     frostAttrs.Threshold,
		Total:         frostAttrs.Total,
		Algorithm:     frostAttrs.Algorithm,
		Participants:  frostAttrs.Participants,
		ParticipantID: frostAttrs.ParticipantID,
	}

	packages, _, err := b.keyGenerator.Generate(genConfig)
	if err != nil {
		return nil, fmt.Errorf("key generation failed: %w", err)
	}

	// Get the package for this participant
	participantID := frostAttrs.ParticipantID
	if participantID == 0 {
		participantID = 1 // Default to first participant
	}
	if participantID > uint32(len(packages)) {
		return nil, fmt.Errorf("invalid participant ID: %d", participantID)
	}

	pkg := packages[participantID-1]

	// Create metadata
	metadata := &KeyMetadata{
		KeyID:             keyID,
		Algorithm:         frostAttrs.Algorithm,
		Threshold:         frostAttrs.Threshold,
		Total:             frostAttrs.Total,
		ParticipantID:     participantID,
		Participants:      frostAttrs.Participants,
		CreatedAt:         time.Now().Unix(),
		SecretBackendType: b.config.SecretBackend.Type(),
	}

	// Store key package
	if err := b.keystore.StoreKeyPackage(keyID, pkg, metadata); err != nil {
		return nil, fmt.Errorf("failed to store key package: %w", err)
	}

	// Update attributes with group public key
	frostAttrs.GroupPublicKey = pkg.GroupPublicKey

	// Return a handle to the key (not the actual private key)
	return &FrostKeyHandle{
		KeyID:          keyID,
		ParticipantID:  participantID,
		GroupPublicKey: pkg.GroupPublicKey,
		Algorithm:      frostAttrs.Algorithm,
	}, nil
}

// GetKey retrieves an existing FROST key by its attributes.
func (b *FrostBackend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return nil, ErrBackendClosed
	}
	b.mu.RUnlock()

	keyID := attrs.CN
	if keyID == "" {
		return nil, &ConfigError{Field: "CN", Message: "key ID (CN) is required"}
	}

	// Get participant ID from attributes or config
	participantID := uint32(0)
	if attrs.FrostAttributes != nil {
		participantID = attrs.FrostAttributes.ParticipantID
	}
	if participantID == 0 {
		participantID = b.config.ParticipantID
	}
	if participantID == 0 {
		participantID = 1 // Default to first participant
	}

	// Load key package
	pkg, metadata, err := b.keystore.LoadKeyPackage(keyID, participantID)
	if err != nil {
		return nil, err
	}

	// Return a handle to the key
	return &FrostKeyHandle{
		KeyID:          keyID,
		ParticipantID:  metadata.ParticipantID,
		GroupPublicKey: pkg.GroupPublicKey,
		Algorithm:      pkg.Algorithm,
	}, nil
}

// DeleteKey removes a FROST key identified by its attributes.
func (b *FrostBackend) DeleteKey(attrs *types.KeyAttributes) error {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return ErrBackendClosed
	}
	b.mu.RUnlock()

	keyID := attrs.CN
	if keyID == "" {
		return &ConfigError{Field: "CN", Message: "key ID (CN) is required"}
	}

	// Delete nonce markers for this key
	if b.config.EnableNonceTracking {
		_ = b.nonceTracker.DeleteKeyNonces(keyID)
	}

	// Delete key package
	return b.keystore.DeleteKey(keyID)
}

// ListKeys returns attributes for all FROST keys managed by this backend.
func (b *FrostBackend) ListKeys() ([]*types.KeyAttributes, error) {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return nil, ErrBackendClosed
	}
	b.mu.RUnlock()

	metadataList, err := b.keystore.ListKeysWithMetadata()
	if err != nil {
		return nil, err
	}

	var result []*types.KeyAttributes
	for _, metadata := range metadataList {
		attrs := &types.KeyAttributes{
			CN:        metadata.KeyID,
			StoreType: types.StoreFrost,
			FrostAttributes: &types.FrostAttributes{
				Threshold:     metadata.Threshold,
				Total:         metadata.Total,
				Algorithm:     metadata.Algorithm,
				Participants:  metadata.Participants,
				ParticipantID: metadata.ParticipantID,
			},
		}
		result = append(result, attrs)
	}

	return result, nil
}

// Signer returns a crypto.Signer for the key identified by attrs.
// This provides orchestrated signing that coordinates with other participants.
func (b *FrostBackend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return nil, ErrBackendClosed
	}
	b.mu.RUnlock()

	keyID := attrs.CN
	if keyID == "" {
		return nil, &ConfigError{Field: "CN", Message: "key ID (CN) is required"}
	}

	// Get participant ID
	participantID := uint32(0)
	if attrs.FrostAttributes != nil {
		participantID = attrs.FrostAttributes.ParticipantID
	}
	if participantID == 0 {
		participantID = b.config.ParticipantID
	}
	if participantID == 0 {
		participantID = 1
	}

	// Load key package
	pkg, _, err := b.keystore.LoadKeyPackage(keyID, participantID)
	if err != nil {
		return nil, err
	}

	return &FrostSigner{
		backend:    b,
		keyID:      keyID,
		keyPackage: pkg,
	}, nil
}

// Decrypter returns a crypto.Decrypter for the key identified by attrs.
// FROST does not support decryption (it's signing-only per RFC 9591).
func (b *FrostBackend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, ErrDecryptionNotSupported
}

// RotateKey rotates a FROST key by generating new key shares.
// This preserves the key ID but generates new key material.
func (b *FrostBackend) RotateKey(attrs *types.KeyAttributes) error {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return ErrBackendClosed
	}
	b.mu.RUnlock()

	keyID := attrs.CN
	if keyID == "" {
		return &ConfigError{Field: "CN", Message: "key ID (CN) is required"}
	}

	// Load existing metadata
	_, metadata, err := b.keystore.LoadPublicKeyPackage(keyID)
	if err != nil {
		return err
	}

	// Delete existing key
	if err := b.keystore.DeleteKey(keyID); err != nil {
		return fmt.Errorf("failed to delete old key: %w", err)
	}

	// Generate new key with same parameters
	genConfig := FrostConfig{
		Threshold:     metadata.Threshold,
		Total:         metadata.Total,
		Algorithm:     metadata.Algorithm,
		Participants:  metadata.Participants,
		ParticipantID: metadata.ParticipantID,
	}

	packages, _, err := b.keyGenerator.Generate(genConfig)
	if err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}

	pkg := packages[metadata.ParticipantID-1]

	// Update metadata timestamp
	newMetadata := &KeyMetadata{
		KeyID:             keyID,
		Algorithm:         metadata.Algorithm,
		Threshold:         metadata.Threshold,
		Total:             metadata.Total,
		ParticipantID:     metadata.ParticipantID,
		Participants:      metadata.Participants,
		CreatedAt:         time.Now().Unix(),
		SecretBackendType: b.config.SecretBackend.Type(),
	}

	// Store new key package
	if err := b.keystore.StoreKeyPackage(keyID, pkg, newMetadata); err != nil {
		return fmt.Errorf("failed to store rotated key: %w", err)
	}

	return nil
}

// Close releases resources held by the backend.
func (b *FrostBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	b.closed = true

	// Clear sessions
	b.sessionsMu.Lock()
	for sessionID, session := range b.sessions {
		if session.Nonces != nil && session.Nonces.Nonces != nil {
			session.Nonces.Nonces.Zeroize()
		}
		delete(b.sessions, sessionID)
	}
	b.sessionsMu.Unlock()

	return nil
}

// FrostKeyHandle is a handle to a FROST key (not the actual private key).
type FrostKeyHandle struct {
	KeyID          string
	ParticipantID  uint32
	GroupPublicKey []byte
	Algorithm      types.FrostAlgorithm
}

// Public returns the group public key.
func (h *FrostKeyHandle) Public() crypto.PublicKey {
	return h.GroupPublicKey
}

// KeyStore returns the keystore for direct access (used by gRPC service for import)
func (b *FrostBackend) KeyStore() *KeyStore {
	return b.keystore
}
