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
	"errors"
	"fmt"
	"path"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
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
	//
	// KeyType is required by types.KeyAttributes.Validate, which a real
	// backend (e.g. the software backend) enforces on GenerateKey; FROST is
	// signing-only (RFC 9591), so KeyTypeSigning is the only correct value.
	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
		SealData:  types.NewSealData(pkg.SecretShare.Value),
		FrostAttributes: &types.FrostAttributes{
			Threshold:     metadata.Threshold,
			Total:         metadata.Total,
			Algorithm:     metadata.Algorithm,
			ParticipantID: metadata.ParticipantID,
		},
	}

	if _, err := ks.secretBackend.GenerateKey(ctx, attrs); err != nil {
		// Clean up public components on failure
		cleanupErr := ks.DeleteKey(ctx, keyID)
		return errors.Join(&errs.Wrapped{Msg: "failed to store secret share", Err: err}, cleanupErr)
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
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
		FrostAttributes: &types.FrostAttributes{
			Threshold:     metadata.Threshold,
			Total:         metadata.Total,
			Algorithm:     metadata.Algorithm,
			ParticipantID: metadata.ParticipantID,
		},
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
//
// Deletion order is chosen so that a failure partway through leaves a key a
// retried DeleteKey can still find and finish deleting, rather than an
// orphaned remainder no path can reach: the secret share goes first
// (through the secret backend), then the verification shares and the group
// public key, and the metadata record — the one component KeyExists,
// LoadKeyPackage, and this method itself all use to find the key at all —
// goes last. Every failure is propagated (joined with errors.Join when more
// than one step fails) rather than ignored; a retry after a partial failure
// resumes at whichever step did not yet report success, since an already
// deleted component's own "not found" is not itself treated as failure
// (storage.ErrNotFound for public components; backend.ErrKeyNotFound, the
// one typed not-found errors.Is can match across every current secret
// backend implementation, for the secret share).
func (ks *KeyStore) DeleteKey(ctx context.Context, keyID string) error {
	metadataBytes, err := ks.publicStorage.Get(ctx, keyPath(keyID, metadataFile))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return &KeyNotFoundError{KeyID: keyID}
		}
		return &errs.Wrapped{Msg: "failed to load metadata", Err: err}
	}
	var metadata KeyMetadata
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return &errs.Wrapped{Msg: "failed to unmarshal metadata", Err: err}
	}

	// Delete the secret share first, through the secret backend.
	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
		FrostAttributes: &types.FrostAttributes{
			Threshold:     metadata.Threshold,
			Total:         metadata.Total,
			Algorithm:     metadata.Algorithm,
			ParticipantID: metadata.ParticipantID,
		},
	}
	if err := ks.secretBackend.DeleteKey(ctx, attrs); err != nil && !errors.Is(err, backend.ErrKeyNotFound) {
		return &errs.Wrapped{Msg: "failed to delete secret share", Err: err}
	}

	// Delete verification shares and the group public key next, collecting
	// every failure instead of stopping at the first so a retry has as
	// little left to redo as possible.
	var deleteErrs []error
	for i := uint32(1); i <= uint32(metadata.Total); i++ {
		if err := ks.publicStorage.Delete(ctx, verificationSharePath(keyID, i)); err != nil && !errors.Is(err, storage.ErrNotFound) {
			deleteErrs = append(deleteErrs, &errs.Wrapped{Msg: fmt.Sprintf("failed to delete verification share for participant %d", i), Err: err})
		}
	}
	if err := ks.publicStorage.Delete(ctx, keyPath(keyID, groupPublicKeyFile)); err != nil && !errors.Is(err, storage.ErrNotFound) {
		deleteErrs = append(deleteErrs, &errs.Wrapped{Msg: "failed to delete group public key", Err: err})
	}
	if len(deleteErrs) > 0 {
		return errors.Join(deleteErrs...)
	}

	// Metadata last: while it is still present, a retry resumes exactly
	// here rather than re-attempting steps that already succeeded.
	if err := ks.publicStorage.Delete(ctx, keyPath(keyID, metadataFile)); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return &errs.Wrapped{Msg: "failed to delete metadata", Err: err}
	}

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
