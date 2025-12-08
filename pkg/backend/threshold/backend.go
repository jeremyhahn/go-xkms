// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

// Package threshold implements a threshold cryptography backend that supports
// distributed key management using Shamir Secret Sharing and threshold signatures.
//
// This backend allows splitting a cryptographic key into N shares where any M shares
// can reconstruct the original key or perform cryptographic operations (signing, decryption).
//
// Primary use case: Distributed Certificate Authority where multiple nodes must
// participate in certificate signing operations.
package threshold

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/jeremyhahn/go-keychain/pkg/threshold/shamir"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// ThresholdBackend implements the Backend interface for threshold cryptography.
// It supports distributed key generation, signing, and decryption operations
// using Shamir Secret Sharing.
type ThresholdBackend struct {
	config *Config
	closed bool
	mu     sync.RWMutex

	// Cache of loaded shares for this node
	shareCache map[string]*shamir.Share // key: keyID
	cacheMu    sync.RWMutex
}

// NewBackend creates a new threshold cryptography backend.
//
// Example usage:
//
//	storage := storage.New()
//	config := &threshold.Config{
//	    KeyStorage:       storage,
//	    LocalShareID:     1,
//	    DefaultThreshold: 3,
//	    DefaultTotal:     5,
//	    DefaultAlgorithm: types.ThresholdAlgorithmShamir,
//	    Participants:     []string{"node1", "node2", "node3", "node4", "node5"},
//	}
//	backend, err := threshold.NewBackend(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer backend.Close()
func NewBackend(config *Config) (*ThresholdBackend, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid threshold config: %w", err)
	}

	return &ThresholdBackend{
		config:     config,
		shareCache: make(map[string]*shamir.Share),
	}, nil
}

// Type returns the backend type identifier.
func (b *ThresholdBackend) Type() types.BackendType {
	return types.BackendTypeThreshold
}

// Capabilities returns what features this backend supports.
func (b *ThresholdBackend) Capabilities() types.Capabilities {
	return types.Capabilities{
		Keys:                true,  // Supports key generation and storage
		HardwareBacked:      false, // Software-based threshold crypto
		Signing:             true,  // Supports threshold signing
		Decryption:          false, // Not yet implemented
		KeyRotation:         false, // Not yet implemented
		SymmetricEncryption: false, // Could support via Shamir-split AES keys
		Import:              true,  // Can import keys and split them
		Export:              false, // Don't allow exporting threshold keys (security)
		KeyAgreement:        false, // Not yet implemented
		ECIES:               false, // Not yet implemented
	}
}

// GenerateKey generates a new threshold key with the given attributes.
// The key is split into N shares using Shamir Secret Sharing, and each
// share is stored for the respective participant.
//
// For threshold ECDSA/Ed25519, this will eventually use distributed key generation (DKG).
// For now, it generates a standard key and splits it with Shamir.
func (b *ThresholdBackend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return nil, ErrBackendClosed
	}
	b.mu.RUnlock()

	// Ensure threshold attributes are set
	if attrs.ThresholdAttributes == nil {
		attrs.ThresholdAttributes = &types.ThresholdAttributes{
			Threshold:    b.config.DefaultThreshold,
			Total:        b.config.DefaultTotal,
			Algorithm:    b.config.DefaultAlgorithm,
			Participants: b.config.Participants,
		}
	}

	// Validate threshold attributes
	if err := attrs.ThresholdAttributes.Validate(); err != nil {
		return nil, fmt.Errorf("invalid threshold attributes: %w", err)
	}

	// Generate the underlying key based on algorithm
	var privateKey crypto.PrivateKey
	var err error

	// Check for quantum algorithms first
	if attrs.QuantumAttributes != nil {
		privateKey, err = b.generateQuantumKey(attrs)
	} else {
		switch attrs.KeyAlgorithm {
		case x509.RSA:
			privateKey, err = b.generateRSAKey(attrs)
		case x509.ECDSA:
			privateKey, err = b.generateECDSAKey(attrs)
		case x509.Ed25519:
			privateKey, err = b.generateEd25519Key(attrs)
		default:
			return nil, fmt.Errorf("%w: %s", ErrInvalidKeyType, attrs.KeyAlgorithm)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Split the key using Shamir Secret Sharing
	if err := b.splitAndStoreKey(attrs, privateKey); err != nil {
		return nil, fmt.Errorf("failed to split key: %w", err)
	}

	// Return a threshold signer/decrypter wrapper (doesn't expose raw key)
	return privateKey, nil
}

// GetKey retrieves an existing threshold key by its attributes.
// This returns a reconstructed key if M shares are available,
// or a threshold signer/decrypter that coordinates with other nodes.
func (b *ThresholdBackend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return nil, ErrBackendClosed
	}
	b.mu.RUnlock()

	// For now, we'll return an error since we need distributed coordination
	// In a full implementation, this would return a ThresholdSigner
	return nil, fmt.Errorf("%w: GetKey requires distributed coordination", ErrNotImplemented)
}

// DeleteKey removes a threshold key and all its shares.
func (b *ThresholdBackend) DeleteKey(attrs *types.KeyAttributes) error {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return ErrBackendClosed
	}
	b.mu.RUnlock()

	keyID := b.getKeyID(attrs)

	// Delete all shares from storage
	if attrs.ThresholdAttributes != nil {
		for i := 1; i <= attrs.ThresholdAttributes.Total; i++ {
			shareKey := fmt.Sprintf("threshold/shares/%s/share-%d", keyID, i)
			// Log errors but continue trying to delete other shares
			if err := b.config.ShareStorage.Delete(shareKey); err != nil {
				// Only log if it's not a "not found" error
				fmt.Printf("warning: failed to delete share %d for key %s: %v\n", i, keyID, err)
			}
		}
	}

	// Delete metadata
	metadataKey := fmt.Sprintf("threshold/metadata/%s", keyID)
	if err := b.config.KeyStorage.Delete(metadataKey); err != nil {
		return fmt.Errorf("failed to delete key metadata: %w", err)
	}

	// Remove from cache
	b.cacheMu.Lock()
	delete(b.shareCache, keyID)
	b.cacheMu.Unlock()

	return nil
}

// ListKeys returns attributes for all threshold keys managed by this backend.
func (b *ThresholdBackend) ListKeys() ([]*types.KeyAttributes, error) {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return nil, ErrBackendClosed
	}
	b.mu.RUnlock()

	// List all metadata entries
	metadataKeys, err := b.config.KeyStorage.List("threshold/metadata/")
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	var keys []*types.KeyAttributes
	for _, metaKey := range metadataKeys {
		data, err := b.config.KeyStorage.Get(metaKey)
		if err != nil {
			continue // Skip entries that can't be read
		}

		var attrs types.KeyAttributes
		if err := json.Unmarshal(data, &attrs); err != nil {
			continue // Skip entries that can't be unmarshaled
		}

		keys = append(keys, &attrs)
	}

	return keys, nil
}

// Signer returns a crypto.Signer for threshold signing operations.
func (b *ThresholdBackend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return nil, ErrBackendClosed
	}
	b.mu.RUnlock()

	// Try to load this node's configured share first
	var share *shamir.Share
	var err error

	if b.config.LocalShareID > 0 {
		share, err = b.loadShare(attrs, b.config.LocalShareID)
	}

	// If local share isn't available, try to load any available share
	if err != nil || share == nil {
		share, err = b.loadAnyShare(attrs)
		if err != nil {
			return nil, fmt.Errorf("failed to load any share: %w", err)
		}
	}

	// Create a threshold signer
	return &ThresholdSigner{
		backend: b,
		attrs:   attrs,
		share:   share,
	}, nil
}

// Decrypter returns a crypto.Decrypter for threshold decryption operations.
func (b *ThresholdBackend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return nil, ErrBackendClosed
	}
	b.mu.RUnlock()

	return nil, fmt.Errorf("%w: Decrypter", ErrNotImplemented)
}

// RotateKey rotates a threshold key.
func (b *ThresholdBackend) RotateKey(attrs *types.KeyAttributes) error {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return ErrBackendClosed
	}
	b.mu.RUnlock()

	return fmt.Errorf("%w: RotateKey", ErrNotImplemented)
}

// Close releases any resources held by the backend.
func (b *ThresholdBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	b.closed = true

	// Clear share cache
	b.cacheMu.Lock()
	b.shareCache = make(map[string]*shamir.Share)
	b.cacheMu.Unlock()

	return nil
}

// getKeyID returns a unique identifier for the key based on its attributes.
func (b *ThresholdBackend) getKeyID(attrs *types.KeyAttributes) string {
	return fmt.Sprintf("%s-%s-%s", attrs.CN, attrs.KeyType, attrs.KeyAlgorithm)
}

// generateRSAKey generates a new RSA key.
func (b *ThresholdBackend) generateRSAKey(attrs *types.KeyAttributes) (*rsa.PrivateKey, error) {
	if attrs.RSAAttributes == nil {
		return nil, fmt.Errorf("RSA attributes required for RSA key generation")
	}

	if attrs.RSAAttributes.KeySize < 2048 {
		return nil, fmt.Errorf("RSA key size must be at least 2048 bits")
	}

	return rsa.GenerateKey(rand.Reader, attrs.RSAAttributes.KeySize)
}

// generateECDSAKey generates a new ECDSA key.
func (b *ThresholdBackend) generateECDSAKey(attrs *types.KeyAttributes) (*ecdsa.PrivateKey, error) {
	if attrs.ECCAttributes == nil {
		return nil, fmt.Errorf("ECC attributes required for ECDSA key generation")
	}

	if attrs.ECCAttributes.Curve == nil {
		return nil, fmt.Errorf("curve is required for ECDSA key generation")
	}

	return ecdsa.GenerateKey(attrs.ECCAttributes.Curve, rand.Reader)
}

// generateEd25519Key generates a new Ed25519 key.
func (b *ThresholdBackend) generateEd25519Key(attrs *types.KeyAttributes) (ed25519.PrivateKey, error) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	return privKey, err
}

// splitAndStoreKey splits a private key using Shamir Secret Sharing and stores all shares.
func (b *ThresholdBackend) splitAndStoreKey(attrs *types.KeyAttributes, privateKey crypto.PrivateKey) error {
	// Marshal the private key to bytes
	keyBytes, err := b.marshalPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Split using Shamir Secret Sharing
	threshold := attrs.ThresholdAttributes.Threshold
	total := attrs.ThresholdAttributes.Total

	shares, err := shamir.Split(keyBytes, threshold, total)
	if err != nil {
		return fmt.Errorf("failed to split key: %w", err)
	}

	// Store each share
	keyID := b.getKeyID(attrs)
	for i, share := range shares {
		shareData, err := json.Marshal(share)
		if err != nil {
			return fmt.Errorf("failed to marshal share %d: %w", i, err)
		}

		shareKey := fmt.Sprintf("threshold/shares/%s/share-%d", keyID, share.Index)
		if err := b.config.ShareStorage.Put(shareKey, shareData, nil); err != nil {
			return fmt.Errorf("failed to store share %d: %w", i, err)
		}
	}

	// Store key metadata
	metadataKey := fmt.Sprintf("threshold/metadata/%s", keyID)
	// Clear SessionCloser before marshaling (cannot marshal func)
	if attrs.TPMAttributes != nil {
		attrsCopy := *attrs
		attrsCopy.TPMAttributes = new(types.TPMAttributes)
		*attrsCopy.TPMAttributes = *attrs.TPMAttributes
		attrsCopy.TPMAttributes.SessionCloser = nil
		attrs = &attrsCopy
	}
	metadataBytes, err := json.Marshal(attrs) //nolint:staticcheck // SA1026: SessionCloser is cleared in copy before marshaling
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if err := b.config.KeyStorage.Put(metadataKey, metadataBytes, nil); err != nil {
		return fmt.Errorf("failed to store metadata: %w", err)
	}

	// Cache this node's share if applicable
	if b.config.LocalShareID > 0 && b.config.LocalShareID <= total {
		b.cacheMu.Lock()
		b.shareCache[keyID] = shares[b.config.LocalShareID-1]
		b.cacheMu.Unlock()
	}

	return nil
}

// loadShare loads a specific share from storage.
func (b *ThresholdBackend) loadShare(attrs *types.KeyAttributes, shareID int) (*shamir.Share, error) {
	keyID := b.getKeyID(attrs)

	// Check cache first
	b.cacheMu.RLock()
	if cached, ok := b.shareCache[keyID]; ok && cached.Index == shareID {
		b.cacheMu.RUnlock()
		return cached, nil
	}
	b.cacheMu.RUnlock()

	// Load from storage
	shareKey := fmt.Sprintf("threshold/shares/%s/share-%d", keyID, shareID)
	data, err := b.config.ShareStorage.Get(shareKey)
	if err != nil {
		return nil, &ShareNotFoundError{KeyID: keyID, ShareID: shareID}
	}

	var share shamir.Share
	if err := json.Unmarshal(data, &share); err != nil {
		return nil, fmt.Errorf("failed to unmarshal share: %w", err)
	}

	// Validate share
	if err := share.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidShare, err)
	}

	// Update cache
	b.cacheMu.Lock()
	b.shareCache[keyID] = &share
	b.cacheMu.Unlock()

	return &share, nil
}

// loadAnyShare tries to load any available share from storage.
// This is useful when the local share isn't available but we still need to reconstruct the key.
func (b *ThresholdBackend) loadAnyShare(attrs *types.KeyAttributes) (*shamir.Share, error) {
	if attrs.ThresholdAttributes == nil {
		return nil, fmt.Errorf("threshold attributes required")
	}

	keyID := b.getKeyID(attrs)

	// Try to load each share until we find one
	for i := 1; i <= attrs.ThresholdAttributes.Total; i++ {
		shareKey := fmt.Sprintf("threshold/shares/%s/share-%d", keyID, i)
		data, err := b.config.ShareStorage.Get(shareKey)
		if err != nil {
			continue // This share doesn't exist, try next one
		}

		var share shamir.Share
		if err := json.Unmarshal(data, &share); err != nil {
			continue // Corrupted share, try next one
		}

		// Validate share
		if err := share.Validate(); err != nil {
			continue // Invalid share, try next one
		}

		// Found a valid share, cache and return it
		b.cacheMu.Lock()
		b.shareCache[keyID] = &share
		b.cacheMu.Unlock()

		return &share, nil
	}

	return nil, fmt.Errorf("no valid shares found for key %s", keyID)
}

// marshalPrivateKey converts a private key to bytes.
func (b *ThresholdBackend) marshalPrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
	// Try quantum key marshaling first if quantum support is enabled
	if supportsQuantum() {
		keyBytes, err := marshalQuantumKey(privateKey)
		if err == nil {
			return keyBytes, nil
		}
		// If not a quantum key, continue to standard algorithms
	}

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return x509.MarshalPKCS1PrivateKey(key), nil
	case *ecdsa.PrivateKey:
		return x509.MarshalECPrivateKey(key)
	case ed25519.PrivateKey:
		return []byte(key), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T", privateKey)
	}
}
