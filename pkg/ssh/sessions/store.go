// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package sessions

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// defaultKeyPrefix is the storage namespace for session records.
const defaultKeyPrefix = "ssh/sessions/"

// Store is the persistence interface for embedded-console session records.
// Implementations MUST be safe for concurrent use.
type Store interface {
	// Save persists a record, assigning a fresh random ID when empty and
	// stamping CreatedAt on first save. An existing ID is overwritten.
	Save(s *Session) error
	Get(id string) (*Session, error)
	List() ([]*Session, error)
	Delete(id string) error
	Close() error
}

// BackendStore implements Store over a storage.Backend.
type BackendStore struct {
	mu      sync.RWMutex
	backend storage.Backend
	closed  bool
}

// NewStore constructs a BackendStore. Returns ErrNilBackend if backend is nil.
func NewStore(backend storage.Backend) (*BackendStore, error) {
	if backend == nil {
		return nil, ErrNilBackend
	}
	return &BackendStore{backend: backend}, nil
}

// Save persists a session record (see Store.Save).
func (s *BackendStore) Save(sess *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if err := sess.Validate(); err != nil {
		return err
	}
	now := time.Now().UTC()
	if sess.ID == "" {
		id, err := randomID()
		if err != nil {
			return err
		}
		sess.ID = id
		sess.CreatedAt = now
	}
	if sess.CreatedAt.IsZero() {
		sess.CreatedAt = now
	}
	if sess.LastConnectedAt.IsZero() {
		sess.LastConnectedAt = now
	}
	data, err := json.Marshal(sess)
	if err != nil {
		return &errs.Detail{Err: ErrMarshalFailed, Detail: fmt.Sprintf("%v", err)}
	}
	return s.backend.Put(context.Background(), defaultKeyPrefix+sess.ID, data)
}

// Get retrieves a session record by ID.
func (s *BackendStore) Get(id string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	data, err := s.backend.Get(context.Background(), defaultKeyPrefix+id)
	if err != nil {
		return nil, &errs.Detail{Err: ErrNotFound, Detail: fmt.Sprintf("%v", err)}
	}
	return unmarshalSession(data)
}

// List returns all session records, most recently connected first.
func (s *BackendStore) List() ([]*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	keys, err := s.backend.List(context.Background(), defaultKeyPrefix)
	if err != nil {
		return nil, &errs.Detail{Err: ErrNotFound, Detail: fmt.Sprintf("%v", err)}
	}
	out := make([]*Session, 0, len(keys))
	for _, key := range keys {
		data, getErr := s.backend.Get(context.Background(), key)
		if getErr != nil {
			continue
		}
		sess, uErr := unmarshalSession(data)
		if uErr != nil {
			continue
		}
		out = append(out, sess)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].LastConnectedAt.After(out[j].LastConnectedAt)
	})
	return out, nil
}

// Delete removes a session record by ID.
func (s *BackendStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	key := defaultKeyPrefix + id
	exists, err := s.backend.Exists(context.Background(), key)
	if err != nil || !exists {
		return &errs.Detail{Err: ErrNotFound, Detail: id}
	}
	return s.backend.Delete(context.Background(), key)
}

// Close marks the store closed; subsequent operations fail with
// ErrStoreClosed. The underlying backend is owned by the caller.
func (s *BackendStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func unmarshalSession(data []byte) (*Session, error) {
	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, &errs.Detail{Err: ErrUnmarshalFailed, Detail: fmt.Sprintf("%v", err)}
	}
	return &sess, nil
}

// randomID returns a 16-hex-char random session identifier.
func randomID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", &errs.Detail{Err: ErrMarshalFailed, Detail: fmt.Sprintf("%v", err)}
	}
	return hex.EncodeToString(b), nil
}
