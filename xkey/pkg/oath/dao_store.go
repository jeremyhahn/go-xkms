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

package oath

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-qrdb/pkg/dao"
	"github.com/jeremyhahn/go-qrdb/pkg/kvstore"
)

// ErrDAOCreation is returned when the DAO layer fails to initialize.
type ErrDAOCreation struct {
	Cause error
}

// Error implements the error interface.
func (e ErrDAOCreation) Error() string {
	return fmt.Sprintf("oath: failed to create DAO: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrDAOCreation) Unwrap() error {
	return e.Cause
}

// ErrNilKVStore is returned when a nil kvstore.KVStore is provided.
type ErrNilKVStore struct{}

// Error implements the error interface.
func (e ErrNilKVStore) Error() string {
	return "oath: nil kvstore"
}

// DAOStore implements Store using a go-qrdb GenericDAO backed by
// a kvstore.KVStore. Each OATH credential is stored as an
// OATHCredentialEntity with indexed fields for efficient lookup
// by name, issuer, and backend ID.
type DAOStore struct {
	closed atomic.Bool
	dao    dao.GenericDAO[*OATHCredentialEntity]
}

// Compile-time interface compliance check.
var _ Store = (*DAOStore)(nil)

// NewDAOStore creates a new DAOStore using the given kvstore.KVStore.
// The entity type namespace is "oath_credentials".
func NewDAOStore(kvStore kvstore.KVStore) (*DAOStore, error) {
	if kvStore == nil {
		return nil, ErrNilKVStore{}
	}

	credDAO, err := dao.New[*OATHCredentialEntity](
		kvStore,
		"oath_credentials",
		func() *OATHCredentialEntity { return &OATHCredentialEntity{} },
	)
	if err != nil {
		return nil, ErrDAOCreation{Cause: err}
	}

	return &DAOStore{
		dao: credDAO,
	}, nil
}

// Add adds a new credential to the store. It validates the credential,
// checks for duplicate names (case-insensitive), and persists it as
// an OATHCredentialEntity.
func (s *DAOStore) Add(cred *Credential) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	if err := cred.Validate(); err != nil {
		return err
	}

	ctx := context.Background()

	// Check for duplicate name (case-insensitive).
	if _, err := s.findEntityByName(ctx, cred.Name); err == nil {
		return ErrCredentialExists
	}

	entity := credentialToEntity(cred)
	return s.dao.Save(ctx, entity)
}

// Get retrieves a credential by ID or name (case-insensitive).
// It first attempts a match by name, then falls back to scanning
// all entities for a matching Credential.ID string.
func (s *DAOStore) Get(idOrName string) (*Credential, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}

	ctx := context.Background()

	// Try lookup by name (case-insensitive).
	entity, err := s.findEntityByName(ctx, idOrName)
	if err == nil {
		return entityToCredential(entity), nil
	}

	// Fall back to scanning for a matching Credential.ID (string ID).
	return s.findByCredentialID(ctx, idOrName)
}

// List returns all credentials sorted by name (case-insensitive).
func (s *DAOStore) List() ([]*Credential, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}

	ctx := context.Background()
	entities, err := s.allEntities(ctx)
	if err != nil {
		return nil, err
	}

	creds := make([]*Credential, 0, len(entities))
	for _, entity := range entities {
		creds = append(creds, entityToCredential(entity))
	}

	sort.Slice(creds, func(i, j int) bool {
		return strings.ToLower(creds[i].Name) < strings.ToLower(creds[j].Name)
	})

	return creds, nil
}

// Update updates an existing credential. The credential is located by
// its string ID, validated, and then persisted with an updated timestamp.
func (s *DAOStore) Update(cred *Credential) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	if err := cred.Validate(); err != nil {
		return err
	}

	ctx := context.Background()

	// Find existing entity by credential string ID.
	existing, err := s.findEntityByCredentialID(ctx, cred.ID)
	if err != nil {
		return err
	}

	// Check for name collision with a different credential.
	nameEntity, nameErr := s.findEntityByName(ctx, cred.Name)
	if nameErr == nil && nameEntity.EntityID() != existing.EntityID() {
		return ErrCredentialExists
	}

	updated := credentialToEntity(cred)
	updated.SetEntityID(existing.EntityID())
	updated.CreatedAt = existing.CreatedAt
	updated.UpdatedAt = time.Now()

	return s.dao.Save(ctx, updated)
}

// Delete removes a credential by ID or name. It first tries to find the
// credential by name, then falls back to string ID scan.
func (s *DAOStore) Delete(idOrName string) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	ctx := context.Background()

	// Try lookup by name first.
	entity, err := s.findEntityByName(ctx, idOrName)
	if err == nil {
		return s.dao.Delete(ctx, entity)
	}

	// Fall back to string ID scan.
	entity, err = s.findEntityByCredentialID(ctx, idOrName)
	if err != nil {
		return err
	}

	return s.dao.Delete(ctx, entity)
}

// Page retrieves a paginated set of credential entities.
func (s *DAOStore) Page(ctx context.Context, query dao.PageQuery) (dao.PageResult[*OATHCredentialEntity], error) {
	if s.closed.Load() {
		return dao.PageResult[*OATHCredentialEntity]{}, ErrStoreClosed
	}
	return s.dao.Page(ctx, query)
}

// Close marks the store as closed. The underlying DAO does not need
// explicit closing since its lifecycle is managed by the kvstore.
func (s *DAOStore) Close() error {
	s.closed.Store(true)
	return nil
}

// allEntities retrieves all entities using pagination.
func (s *DAOStore) allEntities(ctx context.Context) ([]*OATHCredentialEntity, error) {
	var entities []*OATHCredentialEntity
	err := s.dao.ForEachPage(ctx, dao.PageQuery{Page: 1, PageSize: 1000}, func(result dao.PageResult[*OATHCredentialEntity]) error {
		entities = append(entities, result.Entities...)
		return nil
	})
	return entities, err
}

// findEntityByName scans all entities to find one whose Name matches
// the given value (case-insensitive). Returns ErrCredentialNotFound
// if no match is found.
func (s *DAOStore) findEntityByName(ctx context.Context, name string) (*OATHCredentialEntity, error) {
	lower := strings.ToLower(name)

	var found *OATHCredentialEntity
	err := s.dao.ForEachPage(ctx, dao.PageQuery{Page: 1, PageSize: 500}, func(result dao.PageResult[*OATHCredentialEntity]) error {
		for _, entity := range result.Entities {
			if strings.ToLower(entity.Name) == lower {
				found = entity
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, ErrCredentialNotFound
	}
	return found, nil
}

// findByCredentialID scans all entities for one whose reconstructed
// Credential.ID matches the given value (case-insensitive).
func (s *DAOStore) findByCredentialID(ctx context.Context, credID string) (*Credential, error) {
	entity, err := s.findEntityByCredentialID(ctx, credID)
	if err != nil {
		return nil, err
	}
	return entityToCredential(entity), nil
}

// findEntityByCredentialID scans all entities for one whose
// reconstructed Credential.ID or name matches the given value
// (case-insensitive).
func (s *DAOStore) findEntityByCredentialID(ctx context.Context, credID string) (*OATHCredentialEntity, error) {
	lower := strings.ToLower(credID)

	var found *OATHCredentialEntity
	err := s.dao.ForEachPage(ctx, dao.PageQuery{Page: 1, PageSize: 500}, func(result dao.PageResult[*OATHCredentialEntity]) error {
		for _, entity := range result.Entities {
			if strings.ToLower(entity.Name) == lower {
				found = entity
				return nil
			}
			// Reconstruct the string credential ID from entity fields.
			reconstructedID := generateCredentialID(entity.Issuer, entity.AccountName)
			if strings.ToLower(reconstructedID) == lower {
				found = entity
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, ErrCredentialNotFound
	}
	return found, nil
}

// credentialToEntity converts a Credential to an OATHCredentialEntity.
func credentialToEntity(cred *Credential) *OATHCredentialEntity {
	now := time.Now()
	createdAt := cred.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}

	return &OATHCredentialEntity{
		Name:        cred.Name,
		Issuer:      cred.Issuer,
		AccountName: cred.AccountName,
		Type:        cred.Type,
		Secret:      cred.Secret,
		Algorithm:   cred.Algorithm,
		Digits:      cred.Digits,
		Period:      cred.Period,
		Counter:     cred.Counter,
		BackendID:   cred.BackendID,
		CreatedAt:   createdAt,
		UpdatedAt:   now,
	}
}

// entityToCredential converts an OATHCredentialEntity to a Credential.
func entityToCredential(entity *OATHCredentialEntity) *Credential {
	return &Credential{
		ID:          generateCredentialID(entity.Issuer, entity.AccountName),
		Name:        entity.Name,
		Issuer:      entity.Issuer,
		AccountName: entity.AccountName,
		Secret:      entity.Secret,
		Type:        entity.Type,
		Algorithm:   entity.Algorithm,
		Digits:      entity.Digits,
		Period:      entity.Period,
		Counter:     entity.Counter,
		BackendID:   entity.BackendID,
		CreatedAt:   entity.CreatedAt,
	}
}
