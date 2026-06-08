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

package sealblobstore

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync/atomic"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// Sealed blob store errors.
var (
	// ErrNilKVStore is returned when a nil kvstore is provided.
	ErrNilKVStore = errors.New("sealblobstore: nil kvstore")

	// ErrStoreClosed is returned when operations are attempted on a closed store.
	ErrStoreClosed = errors.New("sealblobstore: store is closed")

	// ErrNotFound is returned when a sealed blob is not found.
	ErrNotFound = errors.New("sealblobstore: blob not found")

	// ErrInvalidLabel is returned when the label is empty.
	ErrInvalidLabel = errors.New("sealblobstore: label is required")

	// ErrNilEntity is returned when a nil entity is provided.
	ErrNilEntity = errors.New("sealblobstore: nil entity")
)

// ErrCreation is returned when the DAO layer fails to initialize.
type ErrCreation struct {
	Cause error
}

// Error implements the error interface.
func (e ErrCreation) Error() string {
	return fmt.Sprintf("sealblobstore: failed to create DAO: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrCreation) Unwrap() error {
	return e.Cause
}

// Store implements sealed blob persistence using a go-qrdb GenericDAO backed
// by a kvstore.KVStore. Each blob is stored as an Entity with a deterministic
// ID derived from the label.
type Store struct {
	closed atomic.Bool
	dao    qrdbsdk.GenericDAO[*Entity]
	idGen  *qrdbsdk.FieldHashGenerator
}

// NewStore creates a new Store using the given kvstore.KVStore. The entity
// type namespace is "sealed_blobs".
func NewStore(kvStore qrdbsdk.KVStore) (*Store, error) {
	if kvStore == nil {
		return nil, ErrNilKVStore
	}

	idGen := qrdbsdk.NewFieldHashGenerator("Label")

	blobDAO, err := qrdbsdk.NewDAO[*Entity](
		kvStore,
		"sealed_blobs",
		func() *Entity { return &Entity{} },
		qrdbsdk.WithIDGenerator(idGen),
	)
	if err != nil {
		return nil, ErrCreation{Cause: err}
	}

	return &Store{
		dao:   blobDAO,
		idGen: idGen,
	}, nil
}

// computeID returns the deterministic entity ID for a label.
func (s *Store) computeID(label string) uint64 {
	entity := &Entity{Label: label}
	return s.idGen.NextID(entity)
}

// Save persists a sealed blob entity. If a blob with the same label already
// exists, it is overwritten (upsert behavior). The UpdatedAt timestamp is set
// automatically.
func (s *Store) Save(ctx context.Context, entity *Entity) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	if entity == nil {
		return ErrNilEntity
	}

	if entity.Label == "" {
		return ErrInvalidLabel
	}

	entity.UpdatedAt = time.Now().UTC()
	if entity.CreatedAt.IsZero() {
		entity.CreatedAt = entity.UpdatedAt
	}

	entity.SetEntityID(s.computeID(entity.Label))
	return s.dao.Save(ctx, entity)
}

// Load retrieves a sealed blob entity by its label.
func (s *Store) Load(ctx context.Context, label string) (*Entity, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}

	if label == "" {
		return nil, ErrInvalidLabel
	}

	entityID := s.computeID(label)
	entity, err := s.dao.Get(ctx, entityID)
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return entity, nil
}

// Delete removes a sealed blob entity by its label.
func (s *Store) Delete(ctx context.Context, label string) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	if label == "" {
		return ErrInvalidLabel
	}

	entityID := s.computeID(label)

	// Verify the entity exists before deleting.
	_, err := s.dao.Get(ctx, entityID)
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			return ErrNotFound
		}
		return err
	}

	stub := &Entity{}
	stub.SetEntityID(entityID)
	return s.dao.Delete(ctx, stub)
}

// List returns all stored sealed blob entities sorted by label.
func (s *Store) List(ctx context.Context) ([]*Entity, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}

	var entities []*Entity
	err := s.dao.ForEachPage(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 1000}, func(result qrdbsdk.PageResult[*Entity]) error {
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
func (s *Store) Page(ctx context.Context, query qrdbsdk.PageQuery) (qrdbsdk.PageResult[*Entity], error) {
	if s.closed.Load() {
		return qrdbsdk.PageResult[*Entity]{}, ErrStoreClosed
	}
	return s.dao.Page(ctx, query)
}

// Close marks the store as closed. The underlying DAO does not need explicit
// closing since its lifecycle is managed by the kvstore.
func (s *Store) Close() error {
	s.closed.Store(true)
	return nil
}
