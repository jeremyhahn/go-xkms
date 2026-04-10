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

package sharestore

import (
	"context"
	"sort"
	"sync/atomic"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
)

// BackendShareStore implements ShareStore using a go-qrdb GenericDAO
// backed by a storage.Backend for persistence. Each share entry is
// stored as an individual JSON entity keyed by a deterministic hash
// of the composite key (ServerURL/GroupID/ShareIndex).
type BackendShareStore struct {
	closed atomic.Bool
	dao    qrdbsdk.GenericDAO[*ShareEntry]
	idGen  *shareEntryIDGenerator
}

// Compile-time interface compliance check.
var _ ShareStore = (*BackendShareStore)(nil)

// NewBackendShareStore creates a new BackendShareStore using the given
// storage backend. The prefix is used as the DAO entity type namespace.
func NewBackendShareStore(backend storage.Backend, prefix string) (*BackendShareStore, error) {
	if backend == nil {
		return nil, ErrNilBackend
	}

	kvStore, err := kvadapter.New(backend)
	if err != nil {
		return nil, ErrDAOCreation{Cause: err}
	}

	entityType := prefix
	if entityType == "" {
		entityType = "shares"
	}

	idGen := &shareEntryIDGenerator{}
	shareDAO, err := qrdbsdk.NewDAO(
		kvStore,
		entityType,
		func() *ShareEntry { return &ShareEntry{} },
		qrdbsdk.WithIDGenerator(idGen),
	)
	if err != nil {
		return nil, ErrDAOCreation{Cause: err}
	}

	return &BackendShareStore{
		dao:   shareDAO,
		idGen: idGen,
	}, nil
}

// computeID computes the deterministic entity ID for a share entry
// identified by its composite key fields.
func (s *BackendShareStore) computeID(serverURL, groupID string, shareIndex int) uint64 {
	entry := &ShareEntry{
		ServerURL:  serverURL,
		GroupID:    groupID,
		ShareIndex: shareIndex,
	}
	return s.idGen.NextID(entry)
}

// Save stores a share entry. Returns ErrShareExists if a share for
// the same server+group+shareIndex already exists.
func (s *BackendShareStore) Save(ctx context.Context, entry *ShareEntry) error {
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
	entryID := s.computeID(entry.ServerURL, entry.GroupID, entry.ShareIndex)
	_, err := s.dao.Get(ctx, entryID)
	if err == nil {
		return ErrShareExists
	}
	if !qrdbsdk.IsDAONotFound(err) {
		return err
	}

	if entry.ReceivedAt.IsZero() {
		entry.ReceivedAt = time.Now().UTC()
	}

	// Set deterministic ID before save so DAO does not auto-generate.
	entry.SetEntityID(entryID)
	return s.dao.Save(ctx, entry)
}

// Load retrieves a share by server URL, group ID, and share index.
func (s *BackendShareStore) Load(ctx context.Context, serverURL, groupID string, shareIndex int) (*ShareEntry, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}

	if serverURL == "" {
		return nil, ErrInvalidServerURL
	}

	if groupID == "" {
		return nil, ErrInvalidGroupID
	}

	entryID := s.computeID(serverURL, groupID, shareIndex)
	entry, err := s.dao.Get(ctx, entryID)
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			return nil, ErrShareNotFound
		}
		return nil, err
	}

	return entry, nil
}

// Delete removes a share by server URL, group ID, and share index.
func (s *BackendShareStore) Delete(ctx context.Context, serverURL, groupID string, shareIndex int) error {
	if s.closed.Load() {
		return ErrStoreClosed
	}

	if serverURL == "" {
		return ErrInvalidServerURL
	}

	if groupID == "" {
		return ErrInvalidGroupID
	}

	entryID := s.computeID(serverURL, groupID, shareIndex)

	// Verify the entry exists before deleting.
	_, err := s.dao.Get(ctx, entryID)
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			return ErrShareNotFound
		}
		return err
	}

	stub := &ShareEntry{}
	stub.SetEntityID(entryID)
	return s.dao.Delete(ctx, stub)
}

// List returns all stored shares sorted by composite key.
func (s *BackendShareStore) List(ctx context.Context) ([]*ShareEntry, error) {
	if s.closed.Load() {
		return nil, ErrStoreClosed
	}

	var entries []*ShareEntry
	err := s.dao.ForEachPage(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 1000}, func(result qrdbsdk.PageResult[*ShareEntry]) error {
		entries = append(entries, result.Entities...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	if entries == nil {
		entries = make([]*ShareEntry, 0)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Key() < entries[j].Key()
	})

	return entries, nil
}

// ListByServer returns all shares for a specific server URL.
func (s *BackendShareStore) ListByServer(ctx context.Context, serverURL string) ([]*ShareEntry, error) {
	if serverURL == "" {
		return nil, ErrInvalidServerURL
	}

	all, err := s.List(ctx)
	if err != nil {
		return nil, err
	}

	filtered := make([]*ShareEntry, 0)
	for _, entry := range all {
		if entry.ServerURL == serverURL {
			filtered = append(filtered, entry)
		}
	}

	return filtered, nil
}

// ListByGroup returns all shares for a specific group ID.
func (s *BackendShareStore) ListByGroup(ctx context.Context, groupID string) ([]*ShareEntry, error) {
	if groupID == "" {
		return nil, ErrInvalidGroupID
	}

	all, err := s.List(ctx)
	if err != nil {
		return nil, err
	}

	filtered := make([]*ShareEntry, 0)
	for _, entry := range all {
		if entry.GroupID == groupID {
			filtered = append(filtered, entry)
		}
	}

	return filtered, nil
}

// Close closes the store and marks it as closed.
// The underlying backend is not closed since it may be shared.
func (s *BackendShareStore) Close() error {
	s.closed.Store(true)
	return nil
}
