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

package tokenstore

import (
	"context"
	"sort"
	"sync/atomic"

	"github.com/jeremyhahn/go-qrdb/pkg/dao"
	"github.com/jeremyhahn/go-qrdb/pkg/kvstore"
)

// DAOStore implements TokenStore using a go-qrdb GenericDAO backed by
// a kvstore.KVStore. Each token entry is stored as a TokenEntity with
// a deterministic ID derived from the normalized server URL.
type DAOStore struct {
	closed atomic.Bool
	dao    dao.GenericDAO[*TokenEntity]
	idGen  *dao.FieldHashGenerator
}

// Compile-time interface compliance check.
var _ TokenStore = (*DAOStore)(nil)

// NewDAOStore creates a new DAOStore using the given kvstore.KVStore.
// The entity type namespace is "tokens".
func NewDAOStore(kvStore kvstore.KVStore) (*DAOStore, error) {
	if kvStore == nil {
		return nil, ErrNilBackend
	}

	idGen := dao.NewFieldHashGenerator("ServerURL")

	tokenDAO, err := dao.New[*TokenEntity](
		kvStore,
		"tokens",
		func() *TokenEntity { return &TokenEntity{} },
		dao.WithIDGenerator(idGen),
	)
	if err != nil {
		return nil, ErrDAOCreation{Cause: err}
	}

	return &DAOStore{
		dao:   tokenDAO,
		idGen: idGen,
	}, nil
}

// computeID returns the deterministic entity ID for a normalized server URL.
func (s *DAOStore) computeID(serverURL string) uint64 {
	entity := &TokenEntity{ServerURL: serverURL}
	return s.idGen.NextID(entity)
}

// Save persists a token entry keyed by its server URL. If a token for
// the same URL already exists, it is overwritten (upsert behavior).
func (s *DAOStore) Save(ctx context.Context, entry *TokenEntry) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	if entry == nil {
		return ErrNilEntry
	}

	if entry.ServerURL == "" {
		return ErrInvalidServer
	}

	normalized := normalizeServer(entry.ServerURL)
	entry.ServerURL = normalized

	entity := TokenEntityFromEntry(entry)
	entity.SetEntityID(s.computeID(normalized))

	return s.dao.Save(ctx, entity)
}

// Load retrieves the token entry for the given server URL.
func (s *DAOStore) Load(ctx context.Context, serverURL string) (*TokenEntry, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}

	if serverURL == "" {
		return nil, ErrInvalidServer
	}

	normalized := normalizeServer(serverURL)
	entityID := s.computeID(normalized)

	entity, err := s.dao.Get(ctx, entityID)
	if err != nil {
		if dao.IsNotFound(err) {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}

	return entity.ToTokenEntry(), nil
}

// Delete removes the token entry for the given server URL.
func (s *DAOStore) Delete(ctx context.Context, serverURL string) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	if serverURL == "" {
		return ErrInvalidServer
	}

	normalized := normalizeServer(serverURL)
	entityID := s.computeID(normalized)

	// Verify the entry exists before deleting.
	_, err := s.dao.Get(ctx, entityID)
	if err != nil {
		if dao.IsNotFound(err) {
			return ErrTokenNotFound
		}
		return err
	}

	stub := &TokenEntity{}
	stub.SetEntityID(entityID)
	return s.dao.Delete(ctx, stub)
}

// List returns all stored token entries sorted by server URL.
func (s *DAOStore) List(ctx context.Context) ([]*TokenEntry, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}

	var entities []*TokenEntity
	err := s.dao.ForEachPage(ctx, dao.PageQuery{Page: 1, PageSize: 1000}, func(result dao.PageResult[*TokenEntity]) error {
		entities = append(entities, result.Entities...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	entries := make([]*TokenEntry, 0, len(entities))
	for _, entity := range entities {
		entries = append(entries, entity.ToTokenEntry())
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ServerURL < entries[j].ServerURL
	})

	return entries, nil
}

// Page retrieves a paginated set of token entities.
func (s *DAOStore) Page(ctx context.Context, query dao.PageQuery) (dao.PageResult[*TokenEntity], error) {
	if s.closed.Load() {
		return dao.PageResult[*TokenEntity]{}, ErrStoreClosed
	}
	return s.dao.Page(ctx, query)
}

// Close marks the store as closed. The underlying DAO does not need
// explicit closing since its lifecycle is managed by the kvstore.
func (s *DAOStore) Close() error {
	s.closed.Store(true)
	return nil
}
