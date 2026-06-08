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

// Package sharestore provides a client-side, storage-backed vault for the
// Shamir secret shares a custodian holds locally.
//
// This is the CUSTODIAN'S OWN local holding of shares received from one or more
// servers — distinct from a server's share-collection, which the xkms server
// delegates to the hosted go-qrdb node. A custodian receives shares (over the
// SDK), stores them here in their local ~/.xkey data via a storage.Backend, and
// later submits a stored share back to a server during a barrier-unseal
// ceremony. The xkey GUI and CLI both consume this vault through the xkms SDK
// re-export so the local-storage logic lives in one reusable place.
package sharestore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// Errors returned by the share store.
var (
	// ErrShareExists is returned by Save when a share with the same
	// (server URL, group ID, share index) is already stored.
	ErrShareExists = errors.New("sharestore: share already exists")

	// ErrShareNotFound is returned by Load and Delete when no share matches
	// the given (server URL, group ID, share index).
	ErrShareNotFound = errors.New("sharestore: share not found")

	// ErrInvalidShare is returned by ShareEntry.Validate when a share is
	// missing required fields.
	ErrInvalidShare = errors.New("sharestore: invalid share entry")

	// ErrInvalidServerURL is returned by ShareEntry.Validate when the server
	// URL is empty.
	ErrInvalidServerURL = errors.New("sharestore: server URL is required")

	// ErrInvalidGroupID is returned by ShareEntry.Validate when the group ID
	// is empty.
	ErrInvalidGroupID = errors.New("sharestore: group ID is required")

	// ErrEmptyShareData is returned by ShareEntry.Validate when the share
	// material is empty.
	ErrEmptyShareData = errors.New("sharestore: share data is required")

	// ErrNilStorage is returned by NewBackendShareStore when the backing
	// storage is nil.
	ErrNilStorage = errors.New("sharestore: storage backend must not be nil")
)

// ShareEntry is a single Shamir share held locally by a custodian, together
// with the metadata needed to identify the issuing server, group, and slot.
type ShareEntry struct {
	// ServerURL identifies the server the share was received from.
	ServerURL string `json:"server_url"`
	// GroupID is the custodian group the share belongs to.
	GroupID string `json:"group_id"`
	// GroupName is the human-readable group name (optional).
	GroupName string `json:"group_name,omitempty"`
	// ShareIndex is the share's position within the group.
	ShareIndex int `json:"share_index"`
	// ShareData is the raw share material.
	ShareData []byte `json:"share_data"`
	// Purpose describes what the share unseals (e.g. "barrier").
	Purpose string `json:"purpose,omitempty"`
	// ReceivedAt is when the custodian received the share.
	ReceivedAt time.Time `json:"received_at"`
	// TenantID scopes the share to a tenant (optional).
	TenantID string `json:"tenant_id,omitempty"`
}

// Validate reports whether the entry carries the fields required to store and
// later submit it: a server URL, a group ID, and non-empty share material.
func (e *ShareEntry) Validate() error {
	if e == nil {
		return ErrInvalidShare
	}
	if e.ServerURL == "" {
		return ErrInvalidServerURL
	}
	if e.GroupID == "" {
		return ErrInvalidGroupID
	}
	if len(e.ShareData) == 0 {
		return ErrEmptyShareData
	}
	return nil
}

// ShareStore is a custodian's local vault of received shares.
type ShareStore interface {
	// Save persists a share. It returns ErrShareExists when a share with the
	// same (server URL, group ID, share index) is already present.
	Save(ctx context.Context, entry *ShareEntry) error
	// Load returns the share matching the given coordinates, or
	// ErrShareNotFound.
	Load(ctx context.Context, serverURL, groupID string, shareIndex int) (*ShareEntry, error)
	// List returns every stored share.
	List(ctx context.Context) ([]*ShareEntry, error)
	// Delete removes the share matching the given coordinates, or returns
	// ErrShareNotFound.
	Delete(ctx context.Context, serverURL, groupID string, shareIndex int) error
	// Close releases the underlying storage backend.
	Close() error
}

// backendShareStore implements ShareStore over a storage.Backend. Each share is
// stored as a JSON document under a deterministic key derived from its
// coordinates, so Load and Delete are direct lookups and List is a prefix scan.
type backendShareStore struct {
	backend storage.Backend
	prefix  string
}

// NewBackendShareStore returns a ShareStore backed by the given storage
// backend. The prefix namespaces the store's keys within the backend (it may
// be empty when the backend is already scoped, e.g. a PrefixBackend).
func NewBackendShareStore(backend storage.Backend, prefix string) (ShareStore, error) {
	if backend == nil {
		return nil, ErrNilStorage
	}
	return &backendShareStore{backend: backend, prefix: prefix}, nil
}

// key builds the deterministic storage key for a share's coordinates. The
// server URL is base64url-encoded so it cannot collide with the path
// separators used between segments.
func (s *backendShareStore) key(serverURL, groupID string, shareIndex int) string {
	return s.prefix +
		base64.RawURLEncoding.EncodeToString([]byte(serverURL)) + "/" +
		base64.RawURLEncoding.EncodeToString([]byte(groupID)) + "/" +
		strconv.Itoa(shareIndex)
}

func (s *backendShareStore) Save(ctx context.Context, entry *ShareEntry) error {
	if err := entry.Validate(); err != nil {
		return err
	}
	k := s.key(entry.ServerURL, entry.GroupID, entry.ShareIndex)
	exists, err := s.backend.Exists(ctx, k)
	if err != nil {
		return err
	}
	if exists {
		return ErrShareExists
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return s.backend.Put(ctx, k, data)
}

func (s *backendShareStore) Load(ctx context.Context, serverURL, groupID string, shareIndex int) (*ShareEntry, error) {
	data, err := s.backend.Get(ctx, s.key(serverURL, groupID, shareIndex))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrShareNotFound
		}
		return nil, err
	}
	var entry ShareEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func (s *backendShareStore) List(ctx context.Context) ([]*ShareEntry, error) {
	var entries []*ShareEntry
	err := s.backend.Scan(ctx, s.prefix, func(_ string, value []byte) error {
		var entry ShareEntry
		if err := json.Unmarshal(value, &entry); err != nil {
			return err
		}
		entries = append(entries, &entry)
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Deterministic order: group, then index.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].GroupID != entries[j].GroupID {
			return entries[i].GroupID < entries[j].GroupID
		}
		return entries[i].ShareIndex < entries[j].ShareIndex
	})
	return entries, nil
}

func (s *backendShareStore) Delete(ctx context.Context, serverURL, groupID string, shareIndex int) error {
	k := s.key(serverURL, groupID, shareIndex)
	exists, err := s.backend.Exists(ctx, k)
	if err != nil {
		return err
	}
	if !exists {
		return ErrShareNotFound
	}
	return s.backend.Delete(ctx, k)
}

// Close releases the underlying storage backend.
func (s *backendShareStore) Close() error {
	return s.backend.Close()
}

// memoryShareStore is an in-memory ShareStore for tests and ephemeral use.
type memoryShareStore struct {
	mu      sync.RWMutex
	entries map[string]*ShareEntry
}

// NewMemoryShareStore returns an in-memory ShareStore. It is intended for
// tests and ephemeral use; nothing is persisted.
func NewMemoryShareStore() ShareStore {
	return &memoryShareStore{entries: make(map[string]*ShareEntry)}
}

func memKey(serverURL, groupID string, shareIndex int) string {
	return serverURL + "\x00" + groupID + "\x00" + strconv.Itoa(shareIndex)
}

func (m *memoryShareStore) Save(_ context.Context, entry *ShareEntry) error {
	if err := entry.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	k := memKey(entry.ServerURL, entry.GroupID, entry.ShareIndex)
	if _, ok := m.entries[k]; ok {
		return ErrShareExists
	}
	clone := *entry
	m.entries[k] = &clone
	return nil
}

func (m *memoryShareStore) Load(_ context.Context, serverURL, groupID string, shareIndex int) (*ShareEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entry, ok := m.entries[memKey(serverURL, groupID, shareIndex)]
	if !ok {
		return nil, ErrShareNotFound
	}
	clone := *entry
	return &clone, nil
}

func (m *memoryShareStore) List(_ context.Context) ([]*ShareEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entries := make([]*ShareEntry, 0, len(m.entries))
	for _, e := range m.entries {
		clone := *e
		entries = append(entries, &clone)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].GroupID != entries[j].GroupID {
			return entries[i].GroupID < entries[j].GroupID
		}
		return entries[i].ShareIndex < entries[j].ShareIndex
	})
	return entries, nil
}

func (m *memoryShareStore) Delete(_ context.Context, serverURL, groupID string, shareIndex int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := memKey(serverURL, groupID, shareIndex)
	if _, ok := m.entries[k]; !ok {
		return ErrShareNotFound
	}
	delete(m.entries, k)
	return nil
}

// Close is a no-op for the in-memory store.
func (m *memoryShareStore) Close() error { return nil }
