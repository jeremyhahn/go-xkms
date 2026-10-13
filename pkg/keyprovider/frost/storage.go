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
	"errors"
	"fmt"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/types"
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

// KeyStore manages storage of FROST key components as go-qrdb entities in
// DatabaseName: one FrostKey per key, one FrostShare per verification share,
// and one FrostSecretShare holding this node's sealed secret share.
type KeyStore struct {
	keys    qrdbsdk.GenericDAO[*FrostKey]
	shares  qrdbsdk.GenericDAO[*FrostShare]
	secrets qrdbsdk.GenericDAO[*FrostSecretShare]

	// secretBackend seals and unseals the secret key share using its own
	// native mechanism (can be any go-xkms backend that implements
	// types.Sealer alongside types.KeyProvider).
	secretBackend types.SealingKeyProvider

	// secretSealKeyAttributes identifies the wrapping key secretBackend
	// seals/unseals with. See Config.SecretSealKeyAttributes for the three
	// forms this takes (nil, a fixed CN, or a CN-less template).
	secretSealKeyAttributes *types.KeyAttributes
}

// NewKeyStore creates a KeyStore over the FROST DAOs of daos, with the given
// secret sealer and wrapping-key attributes (see
// Config.SecretSealKeyAttributes for what secretSealKeyAttributes may be).
// It returns ErrNilDAOFactory when daos is nil and a *StoreError when a DAO
// cannot be opened.
func NewKeyStore(daos *qrdbsdk.DAOFactory, secretBackend types.SealingKeyProvider, secretSealKeyAttributes *types.KeyAttributes) (*KeyStore, error) {
	keys, err := newDAO(daos, keyEntityType, newFrostKey)
	if err != nil {
		return nil, err
	}
	shares, err := newDAO(daos, shareEntityType, newFrostShare)
	if err != nil {
		return nil, err
	}
	secrets, err := newDAO(daos, secretShareEntityType, newFrostSecretShare)
	if err != nil {
		return nil, err
	}
	return &KeyStore{
		keys:                    keys,
		shares:                  shares,
		secrets:                 secrets,
		secretBackend:           secretBackend,
		secretSealKeyAttributes: secretSealKeyAttributes,
	}, nil
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

// canSeal reports a *ConfigError unless the secret backend is configured
// and supports sealing.
func (ks *KeyStore) canSeal() error {
	if ks.secretBackend == nil || !ks.secretBackend.CanSeal() {
		return &ConfigError{Field: "SecretBackend", Message: "must be configured and support sealing"}
	}
	return nil
}

// StoreKeyPackage stores a FROST key package.
//
// The secret share is sealed before anything is written, so a sealing
// failure leaves nothing behind; only the sealed envelope is stored. The
// key record goes first, so a failure after it leaves a key DeleteKey can
// find, and is cleaned up with DeleteKey before the error is returned.
func (ks *KeyStore) StoreKeyPackage(ctx context.Context, keyID string, pkg *KeyPackage, metadata *KeyMetadata) error {
	if err := ks.canSeal(); err != nil {
		return err
	}

	// Seal the secret share using the secret backend's own native
	// mechanism (TPM2: PCR-bound seal under the Platform SRK; PKCS#11/cloud
	// KMS: AES-GCM under a provisioned symmetric wrapping key;
	// software/PKCS#8: HKDF-derived AES-GCM key from a provisioned private
	// key).
	sealed, err := ks.secretBackend.Seal(ctx, pkg.SecretShare.Value, ks.secretSealOptions(keyID))
	if err != nil {
		return &errs.Wrapped{Msg: "failed to seal secret share", Err: err}
	}

	key := &FrostKey{Name: keyID, Metadata: *metadata, GroupPublicKey: pkg.GroupPublicKey}
	if err := ks.keys.Save(ctx, key); err != nil {
		return &StoreError{Op: "save key", Key: keyID, Err: err}
	}

	if err := ks.storeShares(ctx, keyID, pkg, metadata, sealed); err != nil {
		return errors.Join(err, ks.DeleteKey(ctx, keyID))
	}
	return nil
}

// storeShares saves keyID's verification shares and its sealed secret share.
func (ks *KeyStore) storeShares(ctx context.Context, keyID string, pkg *KeyPackage, metadata *KeyMetadata, sealed *types.SealedData) error {
	for index, value := range pkg.VerificationShares {
		share := &FrostShare{Name: shareName(keyID, index), KeyID: keyID, Index: index, Share: value}
		if err := ks.shares.Save(ctx, share); err != nil {
			return &StoreError{Op: "save verification share", Key: share.Name, Err: err}
		}
	}

	secret := &FrostSecretShare{
		Name:   shareName(keyID, metadata.ParticipantID),
		KeyID:  keyID,
		Index:  metadata.ParticipantID,
		Sealed: *sealed,
	}
	if err := ks.secrets.Save(ctx, secret); err != nil {
		return &StoreError{Op: "save secret share", Key: secret.Name, Err: err}
	}
	return nil
}

// LoadKeyPackage loads a FROST key package. A zero participantID labels the
// package with the participant ID recorded in the key's metadata.
func (ks *KeyStore) LoadKeyPackage(ctx context.Context, keyID string, participantID uint32) (*KeyPackage, *KeyMetadata, error) {
	public, metadata, err := ks.LoadPublicKeyPackage(ctx, keyID)
	if err != nil {
		return nil, nil, err
	}
	if err := ks.canSeal(); err != nil {
		return nil, nil, err
	}

	secret, err := ks.secrets.GetByNaturalKey(ctx, shareName(keyID, metadata.ParticipantID))
	if err != nil {
		return nil, nil, &StoreError{Op: "load secret share", Key: keyID, Err: err}
	}
	secretBytes, err := ks.secretBackend.Unseal(ctx, &secret.Sealed, ks.secretUnsealOptions(keyID))
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: "failed to unseal secret share", Err: err}
	}

	if participantID == 0 {
		participantID = metadata.ParticipantID
	}
	pkg := &KeyPackage{
		ParticipantID:      participantID,
		SecretShare:        &SecretKeyShare{Value: secretBytes},
		GroupPublicKey:     public.GroupPublicKey,
		VerificationShares: public.VerificationShares,
		MinSigners:         public.MinSigners,
		MaxSigners:         public.MaxSigners,
		Algorithm:          public.Algorithm,
	}
	return pkg, metadata, nil
}

// LoadPublicKeyPackage loads only the public components of a FROST key.
func (ks *KeyStore) LoadPublicKeyPackage(ctx context.Context, keyID string) (*PublicKeyPackage, *KeyMetadata, error) {
	key, err := ks.loadKey(ctx, keyID)
	if err != nil {
		return nil, nil, err
	}
	metadata := key.Metadata

	// go-frost may hand back only threshold verification shares rather than
	// total, so every share that exists is loaded and a missing one skipped.
	verificationShares := make(map[uint32][]byte)
	for index := uint32(1); index <= uint32(metadata.Total); index++ {
		share, err := ks.shares.GetByNaturalKey(ctx, shareName(keyID, index))
		if qrdbsdk.IsDAONotFound(err) {
			continue
		}
		if err != nil {
			return nil, nil, &StoreError{Op: "load verification share", Key: shareName(keyID, index), Err: err}
		}
		verificationShares[index] = share.Share
	}
	if len(verificationShares) < metadata.Threshold {
		return nil, nil, &errs.Message{Msg: fmt.Sprintf("insufficient verification shares: have %d, need at least %d", len(verificationShares), metadata.Threshold)}
	}

	pkg := &PublicKeyPackage{
		GroupPublicKey:     key.GroupPublicKey,
		VerificationShares: verificationShares,
		MinSigners:         uint32(metadata.Threshold),
		MaxSigners:         uint32(metadata.Total),
		Algorithm:          metadata.Algorithm,
	}
	return pkg, &metadata, nil
}

// loadKey loads keyID's key record, reporting a *KeyNotFoundError when there
// is none and a *StoreError when the lookup fails.
func (ks *KeyStore) loadKey(ctx context.Context, keyID string) (*FrostKey, error) {
	key, err := ks.keys.GetByNaturalKey(ctx, keyID)
	if qrdbsdk.IsDAONotFound(err) {
		return nil, &KeyNotFoundError{KeyID: keyID}
	}
	if err != nil {
		return nil, &StoreError{Op: "load key", Key: keyID, Err: err}
	}
	return key, nil
}

// DeleteKey deletes a FROST key and all its components.
//
// Deletion order is chosen so that a failure partway through leaves a key a
// retried DeleteKey can still find and finish deleting, rather than an
// orphaned remainder no path can reach: the sealed secret share goes first,
// then the verification shares, and the key record — the one entity
// KeyExists, LoadKeyPackage, and this method itself all use to find the key
// at all — goes last. Every failure is propagated (joined with errors.Join
// when more than one step fails); an already deleted component is not itself
// a failure, so a retry resumes where the last attempt stopped.
func (ks *KeyStore) DeleteKey(ctx context.Context, keyID string) error {
	key, err := ks.loadKey(ctx, keyID)
	if err != nil {
		return err
	}

	if err := deleteByName(ctx, ks.secrets, shareName(keyID, key.Metadata.ParticipantID)); err != nil {
		return &StoreError{Op: "delete secret share", Key: keyID, Err: err}
	}

	var deleteErr error
	for index := uint32(1); index <= uint32(key.Metadata.Total); index++ {
		name := shareName(keyID, index)
		if err := deleteByName(ctx, ks.shares, name); err != nil {
			deleteErr = errors.Join(deleteErr, &StoreError{Op: "delete verification share", Key: name, Err: err})
		}
	}
	if deleteErr != nil {
		return deleteErr
	}

	if err := ks.keys.Delete(ctx, key); err != nil {
		return &StoreError{Op: "delete key", Key: keyID, Err: err}
	}
	return nil
}

// deleteByName deletes the entity of d whose natural key is name; an entity
// that does not exist is already deleted.
func deleteByName[E qrdbsdk.Entity](ctx context.Context, d qrdbsdk.GenericDAO[E], name string) error {
	entity, err := d.GetByNaturalKey(ctx, name)
	if qrdbsdk.IsDAONotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return d.Delete(ctx, entity)
}

// KeyExists checks if a FROST key exists.
func (ks *KeyStore) KeyExists(ctx context.Context, keyID string) (bool, error) {
	_, err := ks.loadKey(ctx, keyID)
	var notFound *KeyNotFoundError
	if errors.As(err, &notFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ListKeys lists all FROST key IDs.
func (ks *KeyStore) ListKeys(ctx context.Context) ([]string, error) {
	keys, err := ks.listKeys(ctx)
	if err != nil {
		return nil, err
	}
	keyIDs := make([]string, 0, len(keys))
	for _, key := range keys {
		keyIDs = append(keyIDs, key.Name)
	}
	return keyIDs, nil
}

// ListKeysWithMetadata returns all keys with their metadata.
func (ks *KeyStore) ListKeysWithMetadata(ctx context.Context) ([]*KeyMetadata, error) {
	keys, err := ks.listKeys(ctx)
	if err != nil {
		return nil, err
	}
	metadata := make([]*KeyMetadata, 0, len(keys))
	for _, key := range keys {
		metadata = append(metadata, &key.Metadata)
	}
	return metadata, nil
}

// listKeys loads every key record.
func (ks *KeyStore) listKeys(ctx context.Context) ([]*FrostKey, error) {
	var keys []*FrostKey
	err := ks.keys.ForEachPage(ctx, listQuery(), func(page qrdbsdk.PageResult[*FrostKey]) error {
		keys = append(keys, page.Entities...)
		return nil
	})
	if err != nil {
		return nil, &StoreError{Op: "list", Key: keyEntityType, Err: err}
	}
	return keys, nil
}
