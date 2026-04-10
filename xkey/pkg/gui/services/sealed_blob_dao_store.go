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

package services

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-qrdb/pkg/dao"
	"github.com/jeremyhahn/go-qrdb/pkg/kvstore"
)

// Sealed blob DAO store errors.
var (
	// ErrSealDAONilKVStore is returned when a nil kvstore is provided.
	ErrSealDAONilKVStore = errors.New("sealed_blob_dao: nil kvstore")

	// ErrSealDAOStoreClosed is returned when operations are attempted on a closed store.
	ErrSealDAOStoreClosed = errors.New("sealed_blob_dao: store is closed")

	// ErrSealDAONotFound is returned when a sealed blob is not found.
	ErrSealDAONotFound = errors.New("sealed_blob_dao: blob not found")

	// ErrSealDAOInvalidLabel is returned when the label is empty.
	ErrSealDAOInvalidLabel = errors.New("sealed_blob_dao: label is required")

	// ErrSealDAONilEntity is returned when a nil entity is provided.
	ErrSealDAONilEntity = errors.New("sealed_blob_dao: nil entity")
)

// ErrSealDAOCreation is returned when the DAO layer fails to initialize.
type ErrSealDAOCreation struct {
	Cause error
}

// Error implements the error interface.
func (e ErrSealDAOCreation) Error() string {
	return fmt.Sprintf("sealed_blob_dao: failed to create DAO: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrSealDAOCreation) Unwrap() error {
	return e.Cause
}

// SealedBlobDAOStore implements sealed blob persistence using a go-qrdb
// GenericDAO backed by a kvstore.KVStore. Each blob is stored as a
// SealedBlobEntity with a deterministic ID derived from the label.
type SealedBlobDAOStore struct {
	closed atomic.Bool
	dao    dao.GenericDAO[*SealedBlobEntity]
	idGen  *dao.FieldHashGenerator
}

// NewSealedBlobDAOStore creates a new SealedBlobDAOStore using the given
// kvstore.KVStore. The entity type namespace is "sealed_blobs".
func NewSealedBlobDAOStore(kvStore kvstore.KVStore) (*SealedBlobDAOStore, error) {
	if kvStore == nil {
		return nil, ErrSealDAONilKVStore
	}

	idGen := dao.NewFieldHashGenerator("Label")

	blobDAO, err := dao.New[*SealedBlobEntity](
		kvStore,
		"sealed_blobs",
		func() *SealedBlobEntity { return &SealedBlobEntity{} },
		dao.WithIDGenerator(idGen),
	)
	if err != nil {
		return nil, ErrSealDAOCreation{Cause: err}
	}

	return &SealedBlobDAOStore{
		dao:   blobDAO,
		idGen: idGen,
	}, nil
}

// computeID returns the deterministic entity ID for a label.
func (s *SealedBlobDAOStore) computeID(label string) uint64 {
	entity := &SealedBlobEntity{Label: label}
	return s.idGen.NextID(entity)
}

// Save persists a sealed blob entity. If a blob with the same label
// already exists, it is overwritten (upsert behavior). The UpdatedAt
// timestamp is set automatically.
func (s *SealedBlobDAOStore) Save(ctx context.Context, entity *SealedBlobEntity) error {
	if s.closed.Load() {
		return ErrSealDAOStoreClosed
	}

	if entity == nil {
		return ErrSealDAONilEntity
	}

	if entity.Label == "" {
		return ErrSealDAOInvalidLabel
	}

	entity.UpdatedAt = time.Now().UTC()
	if entity.CreatedAt.IsZero() {
		entity.CreatedAt = entity.UpdatedAt
	}

	entity.SetEntityID(s.computeID(entity.Label))
	return s.dao.Save(ctx, entity)
}

// Load retrieves a sealed blob entity by its label.
func (s *SealedBlobDAOStore) Load(ctx context.Context, label string) (*SealedBlobEntity, error) {
	if s.closed.Load() {
		return nil, ErrSealDAOStoreClosed
	}

	if label == "" {
		return nil, ErrSealDAOInvalidLabel
	}

	entityID := s.computeID(label)
	entity, err := s.dao.Get(ctx, entityID)
	if err != nil {
		if dao.IsNotFound(err) {
			return nil, ErrSealDAONotFound
		}
		return nil, err
	}

	return entity, nil
}

// Delete removes a sealed blob entity by its label.
func (s *SealedBlobDAOStore) Delete(ctx context.Context, label string) error {
	if s.closed.Load() {
		return ErrSealDAOStoreClosed
	}

	if label == "" {
		return ErrSealDAOInvalidLabel
	}

	entityID := s.computeID(label)

	// Verify the entity exists before deleting.
	_, err := s.dao.Get(ctx, entityID)
	if err != nil {
		if dao.IsNotFound(err) {
			return ErrSealDAONotFound
		}
		return err
	}

	stub := &SealedBlobEntity{}
	stub.SetEntityID(entityID)
	return s.dao.Delete(ctx, stub)
}

// List returns all stored sealed blob entities sorted by label.
func (s *SealedBlobDAOStore) List(ctx context.Context) ([]*SealedBlobEntity, error) {
	if s.closed.Load() {
		return nil, ErrSealDAOStoreClosed
	}

	var entities []*SealedBlobEntity
	err := s.dao.ForEachPage(ctx, dao.PageQuery{Page: 1, PageSize: 1000}, func(result dao.PageResult[*SealedBlobEntity]) error {
		entities = append(entities, result.Entities...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(entities, func(i, j int) bool {
		return entities[i].Label < entities[j].Label
	})

	return entities, nil
}

// Page retrieves a paginated set of sealed blob entities.
func (s *SealedBlobDAOStore) Page(ctx context.Context, query dao.PageQuery) (dao.PageResult[*SealedBlobEntity], error) {
	if s.closed.Load() {
		return dao.PageResult[*SealedBlobEntity]{}, ErrSealDAOStoreClosed
	}
	return s.dao.Page(ctx, query)
}

// Close marks the store as closed. The underlying DAO does not need
// explicit closing since its lifecycle is managed by the kvstore.
func (s *SealedBlobDAOStore) Close() error {
	s.closed.Store(true)
	return nil
}
