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

package serverregistry

import (
	"context"
	"sort"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-qrdb/pkg/dao"
	"github.com/jeremyhahn/go-qrdb/pkg/kvstore"
)

// DAOStore implements ServerRegistry using a go-qrdb GenericDAO backed by a
// kvstore.KVStore for persistence. Server entries are keyed by a deterministic
// hash of the URL field via dao.FieldHashGenerator, enabling O(1) lookups by
// URL without depending on secondary index support in the underlying store.
type DAOStore struct {
	closed atomic.Bool
	dao    dao.GenericDAO[*ServerEntity]
	idGen  *dao.FieldHashGenerator
}

// Compile-time interface compliance check.
var _ ServerRegistry = (*DAOStore)(nil)

// NewDAOStore creates a new DAOStore using the given kvstore.KVStore.
// The DAO uses "servers" as the entity type namespace and generates
// deterministic IDs by hashing the URL field.
func NewDAOStore(kvStore kvstore.KVStore) (*DAOStore, error) {
	if kvStore == nil {
		return nil, ErrNilKVStore
	}

	idGen := dao.NewFieldHashGenerator("URL")

	serverDAO, err := dao.New[*ServerEntity](
		kvStore,
		"servers",
		func() *ServerEntity { return &ServerEntity{} },
		dao.WithIDGenerator(idGen),
	)
	if err != nil {
		return nil, ErrDAOCreation{Cause: err}
	}

	return &DAOStore{
		dao:   serverDAO,
		idGen: idGen,
	}, nil
}

// computeID computes the deterministic entity ID for a server entry URL.
func (s *DAOStore) computeID(url string) uint64 {
	return s.idGen.NextID(&ServerEntity{URL: url})
}

// Register stores a new server entry. Returns ErrServerExists if the URL
// is already registered.
func (s *DAOStore) Register(ctx context.Context, entry *ServerEntry) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	if entry == nil {
		return ErrNilEntry
	}

	if err := entry.Validate(); err != nil {
		return err
	}

	// Check for duplicate using deterministic ID.
	entryID := s.computeID(entry.URL)
	_, err := s.dao.Get(ctx, entryID)
	if err == nil {
		return ErrServerExists
	}
	if !dao.IsNotFound(err) {
		return err
	}

	entry.RegisteredAt = time.Now().UTC()

	entity := ServerEntityFromEntry(entry)
	entity.SetEntityID(entryID)
	return s.dao.Save(ctx, entity)
}

// Lookup retrieves a server entry by URL.
func (s *DAOStore) Lookup(ctx context.Context, url string) (*ServerEntry, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}

	if url == "" {
		return nil, ErrInvalidURL
	}

	entryID := s.computeID(url)
	entity, err := s.dao.Get(ctx, entryID)
	if err != nil {
		if dao.IsNotFound(err) {
			return nil, ErrServerNotFound
		}
		return nil, err
	}

	return entity.ToServerEntry(), nil
}

// Update modifies an existing server entry. The entry must already exist.
// LastConnectedAt is automatically set to the current time.
func (s *DAOStore) Update(ctx context.Context, entry *ServerEntry) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	if entry == nil {
		return ErrNilEntry
	}

	if err := entry.Validate(); err != nil {
		return err
	}

	// Verify the server exists before updating.
	entryID := s.computeID(entry.URL)
	existing, err := s.dao.Get(ctx, entryID)
	if err != nil {
		if dao.IsNotFound(err) {
			return ErrServerNotFound
		}
		return err
	}

	// Preserve the original registration time.
	entry.RegisteredAt = existing.RegisteredAt
	entry.LastConnectedAt = time.Now().UTC()

	entity := ServerEntityFromEntry(entry)
	entity.SetEntityID(entryID)
	return s.dao.Save(ctx, entity)
}

// List returns all registered server entries sorted by URL.
func (s *DAOStore) List(ctx context.Context) ([]*ServerEntry, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}

	var entities []*ServerEntity
	err := s.dao.ForEachPage(ctx, dao.PageQuery{Page: 1, PageSize: 1000}, func(result dao.PageResult[*ServerEntity]) error {
		entities = append(entities, result.Entities...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	entries := make([]*ServerEntry, 0, len(entities))
	for _, entity := range entities {
		entries = append(entries, entity.ToServerEntry())
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].URL < entries[j].URL
	})

	return entries, nil
}

// Delete removes a server entry by URL.
func (s *DAOStore) Delete(ctx context.Context, url string) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	if url == "" {
		return ErrInvalidURL
	}

	entryID := s.computeID(url)

	// Verify the entry exists before deleting.
	_, err := s.dao.Get(ctx, entryID)
	if err != nil {
		if dao.IsNotFound(err) {
			return ErrServerNotFound
		}
		return err
	}

	stub := &ServerEntity{}
	stub.SetEntityID(entryID)
	return s.dao.Delete(ctx, stub)
}

// Page retrieves a page of server entities using the DAO pagination.
func (s *DAOStore) Page(ctx context.Context, query dao.PageQuery) (dao.PageResult[*ServerEntity], error) {
	if s.closed.Load() {
		return dao.NewPageResult[*ServerEntity](), ErrStoreClosed
	}

	return s.dao.Page(ctx, query)
}

// Close marks the registry as closed. The underlying KVStore is not closed
// since it may be shared with other components.
func (s *DAOStore) Close() error {
	s.closed.Store(true)
	return nil
}
