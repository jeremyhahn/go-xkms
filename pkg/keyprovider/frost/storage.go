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
	"encoding/json"
	"fmt"
	"path"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Storage paths for FROST key components
const (
	// keysPrefix is the base prefix for all FROST keys
	keysPrefix = "frost/keys"

	// metadataFile is the filename for key metadata
	metadataFile = "metadata.json"

	// groupPublicKeyFile is the filename for the group public key
	groupPublicKeyFile = "group_public.bin"

	// verificationSharesDir is the directory for verification shares
	verificationSharesDir = "verification_shares"

	// secretShareFile is the filename for the secret key share
	secretShareFile = "secret_share.bin"

	// sessionsPrefix is the base prefix for signing sessions
	sessionsPrefix = "frost/sessions"

	// noncesPrefix is the base prefix for used nonce tracking
	noncesPrefix = "frost/nonces"
)

// KeyMetadata contains metadata about a stored FROST key.
type KeyMetadata struct {
	// KeyID is the unique identifier for this key
	KeyID string `json:"key_id"`

	// Algorithm is the FROST ciphersuite
	Algorithm types.FrostAlgorithm `json:"algorithm"`

	// Threshold is the minimum number of signers (M)
	Threshold int `json:"threshold"`

	// Total is the total number of participants (N)
	Total int `json:"total"`

	// ParticipantID is this node's participant identifier
	ParticipantID uint32 `json:"participant_id"`

	// Participants contains identifiers for all participants
	Participants []string `json:"participants,omitempty"`

	// CreatedAt is the Unix timestamp of key creation
	CreatedAt int64 `json:"created_at"`

	// SecretBackendType indicates where the secret share is stored
	SecretBackendType types.BackendType `json:"secret_backend_type"`
}

// KeyStore manages storage of FROST key components.
type KeyStore struct {
	// publicStorage stores public components (metadata, group public key, verification shares)
	publicStorage storage.Backend

	// secretBackend stores the secret key share (can be any go-xkms backend)
	secretBackend types.KeyProvider
}

// NewKeyStore creates a new KeyStore with the given storage backends.
func NewKeyStore(publicStorage storage.Backend, secretBackend types.KeyProvider) *KeyStore {
	return &KeyStore{
		publicStorage: publicStorage,
		secretBackend: secretBackend,
	}
}

// keyPath returns the storage path for a key component.
func keyPath(keyID string, components ...string) string {
	parts := append([]string{keysPrefix, keyID}, components...)
	return path.Join(parts...)
}

// verificationSharePath returns the path for a participant's verification share.
func verificationSharePath(keyID string, participantID uint32) string {
	return keyPath(keyID, verificationSharesDir, fmt.Sprintf("%d.bin", participantID))
}

// StoreKeyPackage stores a FROST key package.
func (ks *KeyStore) StoreKeyPackage(ctx context.Context, keyID string, pkg *KeyPackage, metadata *KeyMetadata) error {

	// Store metadata
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to marshal metadata", Err: err}
	}
	if err := ks.publicStorage.Put(ctx, keyPath(keyID, metadataFile), metadataBytes); err != nil {
		return &errs.Wrapped{Msg: "failed to store metadata", Err: err}
	}

	// Store group public key
	if err := ks.publicStorage.Put(ctx, keyPath(keyID, groupPublicKeyFile), pkg.GroupPublicKey); err != nil {
		return &errs.Wrapped{Msg: "failed to store group public key", Err: err}
	}

	// Store verification shares
	for participantID, share := range pkg.VerificationShares {
		sharePath := verificationSharePath(keyID, participantID)
		if err := ks.publicStorage.Put(ctx, sharePath, share); err != nil {
			return &errs.Wrapped{Msg: fmt.Sprintf("failed to store verification share for participant %d", participantID), Err: err}
		}
	}

	// Store secret share using the secret backend
	// The secret backend handles encryption/protection
	attrs := &types.KeyAttributes{
		CN:        keyID,
		StoreType: types.StoreFrost,
		SealData:  types.NewSealData(pkg.SecretShare.Value),
	}

	if _, err := ks.secretBackend.GenerateKey(ctx, attrs); err != nil {
		// Clean up public components on failure
		_ = ks.DeleteKey(ctx, keyID)
		return &errs.Wrapped{Msg: "failed to store secret share", Err: err}
	}

	return nil
}

// LoadKeyPackage loads a FROST key package.
func (ks *KeyStore) LoadKeyPackage(ctx context.Context, keyID string, participantID uint32) (*KeyPackage, *KeyMetadata, error) {

	// Load metadata
	metadataBytes, err := ks.publicStorage.Get(ctx, keyPath(keyID, metadataFile))
	if err != nil {
		return nil, nil, &KeyNotFoundError{KeyID: keyID}
	}

	var metadata KeyMetadata
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return nil, nil, &errs.Wrapped{Msg: "failed to unmarshal metadata", Err: err}
	}

	// Load group public key
	groupPublicKey, err := ks.publicStorage.Get(ctx, keyPath(keyID, groupPublicKeyFile))
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: "failed to load group public key", Err: err}
	}

	// Load verification shares
	// Note: go-frost may return only threshold verification shares, not total.
	// We load all shares that exist without requiring a specific count.
	verificationShares := make(map[uint32][]byte)
	for i := uint32(1); i <= uint32(metadata.Total); i++ {
		sharePath := verificationSharePath(keyID, i)
		share, err := ks.publicStorage.Get(ctx, sharePath)
		if err != nil {
			// Skip missing verification shares - go-frost may only provide threshold shares
			continue
		}
		verificationShares[i] = share
	}

	// Ensure we have at least threshold verification shares
	if len(verificationShares) < metadata.Threshold {
		return nil, nil, &errs.Message{Msg: fmt.Sprintf("insufficient verification shares: have %d, need at least %d", len(verificationShares), metadata.Threshold)}
	}

	// Load secret share from secret backend
	attrs := &types.KeyAttributes{
		CN:        keyID,
		StoreType: types.StoreFrost,
	}

	secretKey, err := ks.secretBackend.GetKey(ctx, attrs)
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: "failed to load secret share", Err: err}
	}

	// Extract secret bytes from the returned key
	// The secret backend may return the key in different formats
	secretBytes, ok := secretKey.([]byte)
	if !ok {
		return nil, nil, &errs.Message{Msg: fmt.Sprintf("unexpected secret key type: %T", secretKey)}
	}

	// Use participant ID from metadata if not specified (0 means use metadata)
	actualParticipantID := participantID
	if actualParticipantID == 0 {
		actualParticipantID = metadata.ParticipantID
	}

	pkg := &KeyPackage{
		ParticipantID: actualParticipantID,
		SecretShare: &SecretKeyShare{
			Value: secretBytes,
		},
		GroupPublicKey:     groupPublicKey,
		VerificationShares: verificationShares,
		MinSigners:         uint32(metadata.Threshold),
		MaxSigners:         uint32(metadata.Total),
		Algorithm:          metadata.Algorithm,
	}

	return pkg, &metadata, nil
}

// LoadPublicKeyPackage loads only the public components of a FROST key.
func (ks *KeyStore) LoadPublicKeyPackage(ctx context.Context, keyID string) (*PublicKeyPackage, *KeyMetadata, error) {

	// Load metadata
	metadataBytes, err := ks.publicStorage.Get(ctx, keyPath(keyID, metadataFile))
	if err != nil {
		return nil, nil, &KeyNotFoundError{KeyID: keyID}
	}

	var metadata KeyMetadata
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return nil, nil, &errs.Wrapped{Msg: "failed to unmarshal metadata", Err: err}
	}

	// Load group public key
	groupPublicKey, err := ks.publicStorage.Get(ctx, keyPath(keyID, groupPublicKeyFile))
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: "failed to load group public key", Err: err}
	}

	// Load verification shares
	// Note: go-frost may return only threshold verification shares, not total.
	// We load all shares that exist without requiring a specific count.
	verificationShares := make(map[uint32][]byte)
	for i := uint32(1); i <= uint32(metadata.Total); i++ {
		sharePath := verificationSharePath(keyID, i)
		share, err := ks.publicStorage.Get(ctx, sharePath)
		if err != nil {
			// Skip missing verification shares - go-frost may only provide threshold shares
			continue
		}
		verificationShares[i] = share
	}

	// Ensure we have at least threshold verification shares
	if len(verificationShares) < metadata.Threshold {
		return nil, nil, &errs.Message{Msg: fmt.Sprintf("insufficient verification shares: have %d, need at least %d", len(verificationShares), metadata.Threshold)}
	}

	pkg := &PublicKeyPackage{
		GroupPublicKey:     groupPublicKey,
		VerificationShares: verificationShares,
		MinSigners:         uint32(metadata.Threshold),
		MaxSigners:         uint32(metadata.Total),
		Algorithm:          metadata.Algorithm,
	}

	return pkg, &metadata, nil
}

// DeleteKey deletes a FROST key and all its components.
func (ks *KeyStore) DeleteKey(ctx context.Context, keyID string) error {

	// Load metadata first to know how many verification shares to delete
	metadataBytes, err := ks.publicStorage.Get(ctx, keyPath(keyID, metadataFile))
	if err == nil {
		var metadata KeyMetadata
		if json.Unmarshal(metadataBytes, &metadata) == nil {
			// Delete verification shares
			for i := uint32(1); i <= uint32(metadata.Total); i++ {
				_ = ks.publicStorage.Delete(ctx, verificationSharePath(keyID, i))
			}
		}
	}

	// Delete public components
	_ = ks.publicStorage.Delete(ctx, keyPath(keyID, metadataFile))
	_ = ks.publicStorage.Delete(ctx, keyPath(keyID, groupPublicKeyFile))

	// Delete secret share
	attrs := &types.KeyAttributes{
		CN:        keyID,
		StoreType: types.StoreFrost,
	}
	_ = ks.secretBackend.DeleteKey(ctx, attrs)

	return nil
}

// KeyExists checks if a FROST key exists.
func (ks *KeyStore) KeyExists(ctx context.Context, keyID string) (bool, error) {
	return ks.publicStorage.Exists(ctx, keyPath(keyID, metadataFile))
}

// ListKeys lists all FROST key IDs.
func (ks *KeyStore) ListKeys(ctx context.Context) ([]string, error) {
	keys, err := ks.publicStorage.List(ctx, keysPrefix+"/")
	if err != nil {
		return nil, err
	}

	// Extract unique key IDs from paths
	keyIDSet := make(map[string]struct{})
	for _, k := range keys {
		// Extract key ID from path like "frost/keys/{keyID}/..."
		if len(k) > len(keysPrefix)+1 {
			rest := k[len(keysPrefix)+1:]
			// Find the next slash to get the key ID
			for i, c := range rest {
				if c == '/' {
					keyID := rest[:i]
					keyIDSet[keyID] = struct{}{}
					break
				}
			}
			// If no slash found, the whole rest is the key ID (shouldn't happen with valid paths)
			if _, exists := keyIDSet[rest]; !exists {
				keyIDSet[rest] = struct{}{}
			}
		}
	}

	result := make([]string, 0, len(keyIDSet))
	for keyID := range keyIDSet {
		result = append(result, keyID)
	}

	return result, nil
}

// ListKeysWithMetadata returns all keys with their metadata.
func (ks *KeyStore) ListKeysWithMetadata(ctx context.Context) ([]*KeyMetadata, error) {

	keyIDs, err := ks.ListKeys(ctx)
	if err != nil {
		return nil, err
	}

	var result []*KeyMetadata
	for _, keyID := range keyIDs {
		metadataBytes, err := ks.publicStorage.Get(ctx, keyPath(keyID, metadataFile))
		if err != nil {
			continue // Skip keys with missing metadata
		}

		var metadata KeyMetadata
		if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
			continue // Skip keys with corrupt metadata
		}

		result = append(result, &metadata)
	}

	return result, nil
}
