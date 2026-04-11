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

package authenticator

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync/atomic"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

const (
	// daoCredentialEntityType is the DAO entity type namespace for FIDO2 credentials.
	daoCredentialEntityType = "fido2_credentials"

	// daoStateKey is the KVStore key for authenticator state persistence.
	daoStateKey = "fido2/authenticator/state"
)

// DAOCredentialStore implements StatefulCredentialStorage using a go-qrdb
// GenericDAO backed by a kvstore.KVStore. Credentials are stored as
// FIDO2CredentialEntity values with indexed fields for efficient lookup.
// Authenticator state is stored as a single JSON blob under a fixed key
// in the underlying KVStore directly (not as a DAO entity).
//
// All methods are safe for concurrent use via the atomic closed flag and
// the DAO's internal concurrency guarantees.
type DAOCredentialStore struct {
	closed  atomic.Bool
	kvStore qrdbsdk.KVStore
	dao     qrdbsdk.GenericDAO[*FIDO2CredentialEntity]
	idGen   *qrdbsdk.FieldHashGenerator
}

// Compile-time interface compliance checks.
var (
	_ StatefulCredentialStorage = (*DAOCredentialStore)(nil)
	_ CredentialStorage         = (*DAOCredentialStore)(nil)
	_ ClearableStorage          = (*DAOCredentialStore)(nil)
	_ ListableStorage           = (*DAOCredentialStore)(nil)
	_ CredentialEnumerator      = (*DAOCredentialStore)(nil)
)

// NewDAOCredentialStore creates a new DAOCredentialStore using the given
// kvstore.KVStore. The DAO uses CredentialIDHex as the deterministic
// entity ID field for deduplication.
func NewDAOCredentialStore(kvStore qrdbsdk.KVStore) (*DAOCredentialStore, error) {
	if kvStore == nil {
		return nil, ErrNilStorage
	}

	idGen := qrdbsdk.NewFieldHashGenerator("CredentialIDHex")

	credDAO, err := qrdbsdk.NewDAO[*FIDO2CredentialEntity](
		kvStore,
		daoCredentialEntityType,
		func() *FIDO2CredentialEntity { return &FIDO2CredentialEntity{} },
		qrdbsdk.WithIDGenerator(idGen),
	)
	if err != nil {
		return nil, ErrDAOCreation{Cause: err}
	}

	return &DAOCredentialStore{
		kvStore: kvStore,
		dao:     credDAO,
		idGen:   idGen,
	}, nil
}

// computeID returns the deterministic entity ID for a hex-encoded credential ID.
func (s *DAOCredentialStore) computeID(credIDHex string) uint64 {
	entity := &FIDO2CredentialEntity{CredentialIDHex: credIDHex}
	return s.idGen.NextID(entity)
}

// Store persists a credential. If a credential with the same ID already exists,
// it is overwritten (upsert behavior for sign count updates, etc.).
// Returns ErrInvalidCredentialID if the credential ID is nil or empty.
// Returns ErrStorageClosed if the store has been closed.
func (s *DAOCredentialStore) Store(credential *StoredCredential) error {
	if s.closed.Load() {
		return ErrStorageClosed
	}

	if credential == nil || len(credential.CredentialID) == 0 {
		return ErrInvalidCredentialID
	}

	entity := credentialToEntity(credential)
	entity.SetEntityID(s.computeID(entity.CredentialIDHex))

	if err := s.dao.Save(context.Background(), entity); err != nil {
		return wrapStorageError(err)
	}

	return nil
}

// Load retrieves a credential by its raw credential ID.
// Returns ErrCredentialNotFound if the credential does not exist.
// Returns ErrInvalidCredentialID if the credential ID is nil or empty.
// Returns ErrStorageClosed if the store has been closed.
func (s *DAOCredentialStore) Load(credentialID []byte) (*StoredCredential, error) {
	if s.closed.Load() {
		return nil, ErrStorageClosed
	}

	if len(credentialID) == 0 {
		return nil, ErrInvalidCredentialID
	}

	credIDHex := hex.EncodeToString(credentialID)
	entityID := s.computeID(credIDHex)

	entity, err := s.dao.Get(context.Background(), entityID)
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			return nil, ErrCredentialNotFound
		}
		return nil, wrapStorageError(err)
	}

	return entityToCredential(entity)
}

// LoadByRPID retrieves all credentials for a relying party.
// Uses the RPID index when the underlying KVStore supports indexing,
// and falls back to a full scan with filter otherwise.
// Returns an empty slice if no credentials exist.
// Returns ErrInvalidRPIDEmpty if the rpID is empty.
// Returns ErrStorageClosed if the store has been closed.
func (s *DAOCredentialStore) LoadByRPID(rpID string) ([]*StoredCredential, error) {
	if s.closed.Load() {
		return nil, ErrStorageClosed
	}

	if rpID == "" {
		return nil, ErrInvalidRPIDEmpty
	}

	// Try index-based lookup first.
	entities, err := s.dao.QueryByIndex(context.Background(), "RPID", rpID)
	if err != nil {
		return nil, wrapStorageError(err)
	}

	// If index returned results, use them directly.
	if len(entities) > 0 {
		return s.entitiesToCredentials(entities), nil
	}

	// Fall back to full scan with filter when the KVStore does not
	// support indexing (e.g., the kvadapter returns nil, nil).
	return s.loadByRPIDScan(rpID)
}

// loadByRPIDScan does a full scan and filters by RPID.
func (s *DAOCredentialStore) loadByRPIDScan(rpID string) ([]*StoredCredential, error) {
	var result []*StoredCredential
	err := s.dao.ForEachPage(context.Background(), qrdbsdk.PageQuery{Page: 1, PageSize: 100}, func(page qrdbsdk.PageResult[*FIDO2CredentialEntity]) error {
		for _, entity := range page.Entities {
			if entity.RPID == rpID {
				cred, convErr := entityToCredential(entity)
				if convErr != nil {
					continue
				}
				result = append(result, cred)
			}
		}
		return nil
	})
	if err != nil {
		return nil, wrapStorageError(err)
	}

	return result, nil
}

// entitiesToCredentials converts a slice of entities to StoredCredentials,
// skipping any that fail deserialization.
func (s *DAOCredentialStore) entitiesToCredentials(entities []*FIDO2CredentialEntity) []*StoredCredential {
	result := make([]*StoredCredential, 0, len(entities))
	for _, entity := range entities {
		cred, err := entityToCredential(entity)
		if err != nil {
			continue
		}
		result = append(result, cred)
	}
	return result
}

// Delete removes a credential by its raw credential ID.
// Returns ErrCredentialNotFound if the credential does not exist.
// Returns ErrInvalidCredentialID if the credential ID is nil or empty.
// Returns ErrStorageClosed if the store has been closed.
func (s *DAOCredentialStore) Delete(credentialID []byte) error {
	if s.closed.Load() {
		return ErrStorageClosed
	}

	if len(credentialID) == 0 {
		return ErrInvalidCredentialID
	}

	credIDHex := hex.EncodeToString(credentialID)
	entityID := s.computeID(credIDHex)

	// Verify existence before delete (DAO Delete is idempotent).
	_, err := s.dao.Get(context.Background(), entityID)
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			return ErrCredentialNotFound
		}
		return wrapStorageError(err)
	}

	stub := &FIDO2CredentialEntity{}
	stub.SetEntityID(entityID)
	if err := s.dao.Delete(context.Background(), stub); err != nil {
		return wrapStorageError(err)
	}

	return nil
}

// Count returns the total number of stored credentials.
// Returns ErrStorageClosed if the store has been closed.
func (s *DAOCredentialStore) Count() (int, error) {
	if s.closed.Load() {
		return 0, ErrStorageClosed
	}

	count, err := s.dao.Count(context.Background())
	if err != nil {
		return 0, wrapStorageError(err)
	}

	return count, nil
}

// CountDiscoverable returns the number of discoverable (resident) credentials.
// Returns ErrStorageClosed if the store has been closed.
func (s *DAOCredentialStore) CountDiscoverable() (int, error) {
	if s.closed.Load() {
		return 0, ErrStorageClosed
	}

	count := 0
	err := s.dao.ForEachPage(context.Background(), qrdbsdk.PageQuery{Page: 1, PageSize: 100}, func(result qrdbsdk.PageResult[*FIDO2CredentialEntity]) error {
		for _, entity := range result.Entities {
			if entity.Discoverable {
				count++
			}
		}
		return nil
	})
	if err != nil {
		return 0, wrapStorageError(err)
	}

	return count, nil
}

// EnumerateDiscoverable returns all discoverable credentials.
// This implements the CredentialEnumerator interface for credential management.
// Returns ErrStorageClosed if the store has been closed.
func (s *DAOCredentialStore) EnumerateDiscoverable() ([]*StoredCredential, error) {
	if s.closed.Load() {
		return nil, ErrStorageClosed
	}

	var result []*StoredCredential
	err := s.dao.ForEachPage(context.Background(), qrdbsdk.PageQuery{Page: 1, PageSize: 100}, func(page qrdbsdk.PageResult[*FIDO2CredentialEntity]) error {
		for _, entity := range page.Entities {
			if entity.Discoverable {
				cred, err := entityToCredential(entity)
				if err != nil {
					continue
				}
				result = append(result, cred)
			}
		}
		return nil
	})
	if err != nil {
		return nil, wrapStorageError(err)
	}

	return result, nil
}

// SaveState persists the authenticator state as a JSON blob under a fixed
// key in the underlying KVStore. This is not stored as a DAO entity because
// it is mutable runtime state with a single instance.
// Returns ErrStorageClosed if the store has been closed.
func (s *DAOCredentialStore) SaveState(state *AuthenticatorState) error {
	if s.closed.Load() {
		return ErrStorageClosed
	}

	if state == nil {
		return ErrInvalidParameter
	}

	serializable, err := stateToSerializable(state)
	if err != nil {
		return err
	}

	data, err := json.Marshal(serializable)
	if err != nil {
		return ErrSerializationFailed
	}

	if err := s.kvStore.Put(context.Background(), daoStateKey, data); err != nil {
		return wrapStorageError(err)
	}

	return nil
}

// LoadState retrieves the persisted authenticator state from the KVStore.
// Returns ErrStateNotFound if no state has been saved.
// Returns ErrStorageClosed if the store has been closed.
func (s *DAOCredentialStore) LoadState() (*AuthenticatorState, error) {
	if s.closed.Load() {
		return nil, ErrStorageClosed
	}

	data, err := s.kvStore.Get(context.Background(), daoStateKey)
	if err != nil {
		// The KVStore adapter wraps storage.ErrNotFound in a QRDBError.
		// Check the full error chain for the sentinel.
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrStateNotFound
		}
		return nil, wrapStorageError(err)
	}

	if data == nil {
		return nil, ErrStateNotFound
	}

	var serializable SerializableState
	if err := json.Unmarshal(data, &serializable); err != nil {
		return nil, ErrDeserializationFailed
	}

	return serializableToState(&serializable)
}

// Close marks the store as closed. The underlying KVStore lifecycle is
// managed externally and is not closed here.
// Close is idempotent and may be called multiple times safely.
func (s *DAOCredentialStore) Close() error {
	s.closed.Store(true)
	return nil
}

// Clear removes all stored credentials from the DAO.
// This implements the ClearableStorage interface.
// Returns ErrStorageClosed if the store has been closed.
func (s *DAOCredentialStore) Clear() error {
	if s.closed.Load() {
		return ErrStorageClosed
	}

	return s.dao.ForEachPage(context.Background(), qrdbsdk.PageQuery{Page: 1, PageSize: 100}, func(page qrdbsdk.PageResult[*FIDO2CredentialEntity]) error {
		for _, entity := range page.Entities {
			if err := s.dao.Delete(context.Background(), entity); err != nil {
				continue
			}
		}
		return nil
	})
}

// ListAll returns all credential IDs in storage.
// This implements the ListableStorage interface.
// Returns ErrStorageClosed if the store has been closed.
func (s *DAOCredentialStore) ListAll() ([][]byte, error) {
	if s.closed.Load() {
		return nil, ErrStorageClosed
	}

	var result [][]byte
	err := s.dao.ForEachPage(context.Background(), qrdbsdk.PageQuery{Page: 1, PageSize: 100}, func(page qrdbsdk.PageResult[*FIDO2CredentialEntity]) error {
		for _, entity := range page.Entities {
			credID, err := hex.DecodeString(entity.CredentialIDHex)
			if err != nil {
				continue
			}
			result = append(result, credID)
		}
		return nil
	})
	if err != nil {
		return nil, wrapStorageError(err)
	}

	return result, nil
}

// Page retrieves a paginated set of credential entities.
func (s *DAOCredentialStore) Page(ctx context.Context, query qrdbsdk.PageQuery) (qrdbsdk.PageResult[*FIDO2CredentialEntity], error) {
	if s.closed.Load() {
		return qrdbsdk.PageResult[*FIDO2CredentialEntity]{}, ErrStorageClosed
	}
	return s.dao.Page(ctx, query)
}

// credentialToEntity converts a StoredCredential to a FIDO2CredentialEntity.
// Binary fields are encoded to hex or base64 strings for indexed storage.
func credentialToEntity(cred *StoredCredential) *FIDO2CredentialEntity {
	entity := &FIDO2CredentialEntity{
		CredentialIDHex: hex.EncodeToString(cred.CredentialID),
		RPID:            cred.RPID,
		RPName:          cred.RPName,
		UserIDHex:       hex.EncodeToString(cred.UserID),
		UserName:        cred.UserName,
		UserDisplayName: cred.UserDisplayName,
		Algorithm:       cred.Algorithm,
		SignCount:       cred.SignCount,
		CreatedAt:       cred.CreatedAt,
		Discoverable:    cred.Discoverable,
		CredProtect:     cred.CredProtect,
		BackendID:       cred.BackendID,
	}

	if len(cred.PrivateKey) > 0 {
		entity.PrivateKeyPKCS8Base64 = base64.StdEncoding.EncodeToString(cred.PrivateKey)
	}

	if len(cred.PublicKeyCOSE) > 0 {
		entity.PublicKeyCOSEBase64 = base64.StdEncoding.EncodeToString(cred.PublicKeyCOSE)
	}

	if len(cred.HMACSecretKey) > 0 {
		entity.HMACSecretKeyBase64 = base64.StdEncoding.EncodeToString(cred.HMACSecretKey)
	}

	return entity
}

// entityToCredential converts a FIDO2CredentialEntity back to a StoredCredential.
// Encoded fields are decoded from hex or base64 strings.
func entityToCredential(entity *FIDO2CredentialEntity) (*StoredCredential, error) {
	credentialID, err := hex.DecodeString(entity.CredentialIDHex)
	if err != nil {
		return nil, ErrDeserializationFailed
	}

	var userID []byte
	if entity.UserIDHex != "" {
		userID, err = hex.DecodeString(entity.UserIDHex)
		if err != nil {
			return nil, ErrDeserializationFailed
		}
	}

	var privateKey []byte
	if entity.PrivateKeyPKCS8Base64 != "" {
		privateKey, err = base64.StdEncoding.DecodeString(entity.PrivateKeyPKCS8Base64)
		if err != nil {
			return nil, ErrDeserializationFailed
		}
	}

	var publicKeyCOSE []byte
	if entity.PublicKeyCOSEBase64 != "" {
		publicKeyCOSE, err = base64.StdEncoding.DecodeString(entity.PublicKeyCOSEBase64)
		if err != nil {
			return nil, ErrDeserializationFailed
		}
	}

	var hmacSecretKey []byte
	if entity.HMACSecretKeyBase64 != "" {
		hmacSecretKey, err = base64.StdEncoding.DecodeString(entity.HMACSecretKeyBase64)
		if err != nil {
			return nil, ErrDeserializationFailed
		}
	}

	return &StoredCredential{
		CredentialID:    credentialID,
		RPID:            entity.RPID,
		RPName:          entity.RPName,
		UserID:          userID,
		UserName:        entity.UserName,
		UserDisplayName: entity.UserDisplayName,
		PrivateKey:      privateKey,
		PublicKeyCOSE:   publicKeyCOSE,
		Algorithm:       entity.Algorithm,
		SignCount:       entity.SignCount,
		CreatedAt:       entity.CreatedAt,
		Discoverable:    entity.Discoverable,
		CredProtect:     entity.CredProtect,
		HMACSecretKey:   hmacSecretKey,
		BackendID:       entity.BackendID,
	}, nil
}
