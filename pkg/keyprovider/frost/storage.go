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

	// secretShareFile is the filename for the sealed secret key share.
	// Sealing (see types.Sealer) is what makes it safe to hold this file in
	// publicStorage alongside the group's public components: the payload is
	// an opaque, backend-encrypted envelope (types.SealedData), not the
	// secret share in the clear.
	secretShareFile = "secret_share.json"

	// noncesPrefix is the base prefix for used nonce tracking
	noncesPrefix = "frost/nonces"
)

// KeyMetadata contains metadata about a stored FROST key.
type KeyMetadata struct {
	// KeyID is the key's common name, unique within its tenant.
	KeyID string `json:"key_id"`

	// TenantID is the tenant that owns the key, empty for a platform key.
	// Together with KeyID it determines the key's storage key ID (see
	// StorageKeyID), and a tenant-scoped view of the backend filters its
	// listing on it.
	TenantID string `json:"tenant_id,omitempty"`

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
	// publicStorage stores public components (metadata, group public key,
	// verification shares) AND the sealed secret share: sealing is what
	// makes storing the latter there safe (see secretShareFile).
	publicStorage storage.Backend

	// secretBackend seals and unseals the secret key share using its own
	// native mechanism (can be any go-xkms backend that implements
	// types.Sealer alongside types.KeyProvider).
	secretBackend types.SealingKeyProvider

	// secretSealKeyAttributes identifies the wrapping key secretBackend
	// seals/unseals with. See Config.SecretSealKeyAttributes for the three
	// forms this takes (nil, a fixed CN, or a CN-less template).
	secretSealKeyAttributes *types.KeyAttributes
}

// NewKeyStore creates a new KeyStore with the given storage backend, secret
// sealer, and wrapping-key attributes (see Config.SecretSealKeyAttributes
// for what secretSealKeyAttributes may be).
func NewKeyStore(publicStorage storage.Backend, secretBackend types.SealingKeyProvider, secretSealKeyAttributes *types.KeyAttributes) *KeyStore {
	return &KeyStore{
		publicStorage:           publicStorage,
		secretBackend:           secretBackend,
		secretSealKeyAttributes: secretSealKeyAttributes,
	}
}

// secretSealKeyAttributesFor returns the KeyAttributes to use as
// SealOptions.KeyAttributes / UnsealOptions.KeyAttributes when sealing or
// unsealing keyID's secret share.
//
// ks.secretSealKeyAttributes is nil when the secret backend needs no
// KeyAttributes at all. When its CN is already set, it identifies a single
// wrapping key reused for every FROST key in this store and is returned
// unchanged. When its CN is empty, it is a template (currently produced
// only by TPM2SecretSealKeyAttributes) and a clone with CN filled in from
// keyID is returned instead, so each FROST key gets its own TPM-sealed
// object identity -- sharing one CN across many FROST keys would make each
// new Seal silently overwrite the TPM backend's stored copy of a previous
// key's sealed object.
func (ks *KeyStore) secretSealKeyAttributesFor(keyID string) *types.KeyAttributes {
	if ks.secretSealKeyAttributes == nil {
		return nil
	}
	if ks.secretSealKeyAttributes.CN != "" {
		return ks.secretSealKeyAttributes
	}
	clone := *ks.secretSealKeyAttributes
	clone.CN = secretSealCN(keyID)
	return &clone
}

// secretSealCN names the per-key wrapping object a backend that seals
// directly under a hierarchy key (TPM2's Platform SRK) creates for keyID's
// secret share.
func secretSealCN(keyID string) string {
	return "frost-secret:" + keyID
}

// secretSealOptions builds the SealOptions StoreKeyPackage seals keyID's
// secret share with.
func (ks *KeyStore) secretSealOptions(keyID string) *types.SealOptions {
	attrs := ks.secretSealKeyAttributesFor(keyID)
	if attrs == nil {
		return nil
	}
	return &types.SealOptions{KeyAttributes: attrs}
}

// secretUnsealOptions builds the UnsealOptions LoadKeyPackage unseals
// keyID's secret share with.
func (ks *KeyStore) secretUnsealOptions(keyID string) *types.UnsealOptions {
	attrs := ks.secretSealKeyAttributesFor(keyID)
	if attrs == nil {
		return nil
	}
	return &types.UnsealOptions{KeyAttributes: attrs}
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
	if ks.secretBackend == nil || !ks.secretBackend.CanSeal() {
		return &ConfigError{Field: "SecretBackend", Message: "must be configured and support sealing"}
	}

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

	// Seal the secret share using the secret backend's own native
	// mechanism (TPM2: PCR-bound seal under the Platform SRK; PKCS#11/cloud
	// KMS: AES-GCM under a provisioned symmetric wrapping key;
	// software/PKCS#8: HKDF-derived AES-GCM key from a provisioned private
	// key) and persist the resulting envelope in public storage -- sealing
	// is exactly what makes that safe.
	sealed, err := ks.secretBackend.Seal(ctx, pkg.SecretShare.Value, ks.secretSealOptions(keyID))
	if err != nil {
		// Clean up public components on failure
		cleanupErr := ks.DeleteKey(ctx, keyID)
		return errors.Join(&errs.Wrapped{Msg: "failed to seal secret share", Err: err}, cleanupErr)
	}

	sealedBytes, err := json.Marshal(sealed)
	if err != nil {
		cleanupErr := ks.DeleteKey(ctx, keyID)
		return errors.Join(&errs.Wrapped{Msg: "failed to marshal sealed secret share", Err: err}, cleanupErr)
	}

	if err := ks.publicStorage.Put(ctx, keyPath(keyID, secretShareFile), sealedBytes); err != nil {
		cleanupErr := ks.DeleteKey(ctx, keyID)
		return errors.Join(&errs.Wrapped{Msg: "failed to store sealed secret share", Err: err}, cleanupErr)
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

	// Load and unseal the secret share from the secret backend.
	if ks.secretBackend == nil || !ks.secretBackend.CanSeal() {
		return nil, nil, &ConfigError{Field: "SecretBackend", Message: "must be configured and support sealing"}
	}

	sealedBytes, err := ks.publicStorage.Get(ctx, keyPath(keyID, secretShareFile))
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: "failed to load sealed secret share", Err: err}
	}

	var sealed types.SealedData
	if err := json.Unmarshal(sealedBytes, &sealed); err != nil {
		return nil, nil, &errs.Wrapped{Msg: "failed to unmarshal sealed secret share", Err: err}
	}

	secretBytes, err := ks.secretBackend.Unseal(ctx, &sealed, ks.secretUnsealOptions(keyID))
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: "failed to unseal secret share", Err: err}
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
// orphaned remainder no path can reach: the sealed secret share goes first,
// then the verification shares and the group public key, and the metadata
// record — the one component KeyExists, LoadKeyPackage, and this method
// itself all use to find the key at all — goes last. Every failure is
// propagated (joined with errors.Join when more than one step fails)
// rather than ignored; a retry after a partial failure resumes at whichever
// step did not yet report success, since an already deleted component's own
// storage.ErrNotFound is not itself treated as failure.
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

	// Delete the sealed secret share first.
	if err := ks.publicStorage.Delete(ctx, keyPath(keyID, secretShareFile)); err != nil && !errors.Is(err, storage.ErrNotFound) {
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
