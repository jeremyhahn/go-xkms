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

package webauthn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Clock reports the current time. It is the seam that lets a test advance time
// instead of sleeping for it.
//
// Session expiry is a comparison against the wall clock, and a test that
// establishes it by sleeping is asserting that the machine was not busy.
// time.Sleep guarantees a MINIMUM duration and no maximum, so "save a session
// with a 100ms TTL, then read it back and require success" fails whenever the
// two statements are more than 100ms apart -- which under -race on a shared
// runner they can be. That is go-xkms#287, and it is the same defect the nonce
// store carried in go-xkms#243.
type Clock func() time.Time

// MemorySessionStoreOption configures a MemorySessionStore.
type MemorySessionStoreOption func(*MemorySessionStore)

// WithClock replaces the store's time source. Production never calls it; it
// exists so tests can make expiry deterministic rather than probabilistic.
func WithClock(now Clock) MemorySessionStoreOption {
	return func(s *MemorySessionStore) {
		if now != nil {
			s.now = now
		}
	}
}

// WithMaxSessions caps how many unfinished ceremonies the store holds at
// once. A value below 1 keeps DefaultMaxSessions.
func WithMaxSessions(n int) MemorySessionStoreOption {
	return func(s *MemorySessionStore) {
		if n > 0 {
			s.maxSessions = n
		}
	}
}

// DefaultMaxSessions is the number of unfinished ceremonies a
// MemorySessionStore holds before it refuses new ones. A ceremony session is
// a few hundred bytes, so the cap bounds the store to a few MiB however many
// ceremonies unauthenticated callers begin and abandon.
const DefaultMaxSessions = 10_000

// MemorySessionStore is an in-memory implementation of SessionStore.
//
// Sessions leave the store when a ceremony claims them (Take), when they are
// deleted, or when a sweep (Cleanup, run periodically by SweepSessions)
// removes them after their TTL. The store holds at most maxSessions: at the
// cap, Save first sweeps expired sessions itself — so a store whose owner
// runs no sweeper still recovers — and refuses with *SessionLimitError only
// when every held session is still live.
type MemorySessionStore struct {
	mu          sync.RWMutex
	sessions    map[string]*sessionEntry
	ttl         time.Duration
	maxSessions int
	// now is the store's time source. Never nil once built by a constructor;
	// the accessor below keeps a bare struct literal usable too.
	now Clock
}

// clock returns the store's time source, defaulting to time.Now.
func (s *MemorySessionStore) clock() time.Time {
	if s.now == nil {
		return time.Now()
	}
	return s.now()
}

type sessionEntry struct {
	data      *webauthn.SessionData
	createdAt time.Time
	// pending is the account a public registration ceremony creates at
	// finish; nil for every other ceremony.
	pending *PendingRegistration
}

// NewMemorySessionStore creates a new in-memory session store.
func NewMemorySessionStore(opts ...MemorySessionStoreOption) *MemorySessionStore {
	return NewMemorySessionStoreWithTTL(2*time.Minute, opts...)
}

// NewMemorySessionStoreWithTTL creates a new in-memory session store with custom TTL.
// The options are a test seam and are empty in production; see WithClock.
func NewMemorySessionStoreWithTTL(ttl time.Duration, opts ...MemorySessionStoreOption) *MemorySessionStore {
	store := &MemorySessionStore{
		sessions:    make(map[string]*sessionEntry),
		ttl:         ttl,
		maxSessions: DefaultMaxSessions,
		now:         time.Now,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(store)
		}
	}
	return store
}

// Save stores session data and returns a session ID. It fails with
// *SessionLimitError when the store holds its maximum number of live
// sessions.
func (s *MemorySessionStore) Save(ctx context.Context, data *webauthn.SessionData) (string, error) {
	return s.SaveRegistration(ctx, data, nil)
}

// Byte limits of a pending registration. An anonymous caller chooses both
// fields and a store keeps them until the session expires, while the session
// cap counts entries, not bytes: the limits bound what one entry can hold.
const (
	// MaxRegistrationEmailBytes is the longest email a pending registration
	// carries: the 254-byte maximum of a deliverable address.
	MaxRegistrationEmailBytes = 254

	// MaxRegistrationDisplayNameBytes is the longest display name a pending
	// registration carries.
	MaxRegistrationDisplayNameBytes = 64
)

// Validate refuses a pending registration whose email or display name
// exceeds its byte limit with an error that wraps ErrInvalidRequest. A nil
// pending registration is valid: the session carries none.
func (p *PendingRegistration) Validate() error {
	if p == nil {
		return nil
	}
	if len(p.Email) > MaxRegistrationEmailBytes {
		return NewError("email exceeds 254 bytes", ErrInvalidRequest)
	}
	if len(p.DisplayName) > MaxRegistrationDisplayNameBytes {
		return NewError("display name exceeds 64 bytes", ErrInvalidRequest)
	}
	return nil
}

// SaveRegistration is Save for a public registration ceremony: the
// pending registration lives and expires with the session. It refuses a
// pending registration that fails Validate before it saves anything.
func (s *MemorySessionStore) SaveRegistration(ctx context.Context, data *webauthn.SessionData, pending *PendingRegistration) (string, error) {
	if err := pending.Validate(); err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if limit := s.limit(); len(s.sessions) >= limit {
		s.removeExpiredLocked()
		if len(s.sessions) >= limit {
			return "", &SessionLimitError{Limit: limit}
		}
	}

	// Generate random session ID
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return "", err
	}
	sessionID := hex.EncodeToString(idBytes)

	s.sessions[sessionID] = &sessionEntry{
		data:      data,
		createdAt: s.clock(),
		pending:   pending,
	}

	return sessionID, nil
}

// Get retrieves session data by its ID.
func (s *MemorySessionStore) Get(ctx context.Context, sessionID string) (*webauthn.SessionData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}

	// Check expiration
	if s.clock().Sub(entry.createdAt) > s.ttl {
		return nil, ErrSessionExpired
	}

	return entry.data, nil
}

// Take atomically claims a session, returning its data and removing it in one
// step. The whole operation runs under the write lock, so of two concurrent
// finish requests for one ceremony exactly one can claim the session and the
// other finds nothing.
//
// An expired session is consumed as well: leaving it behind would let a
// caller retry it, and it is worthless either way.
func (s *MemorySessionStore) Take(ctx context.Context, sessionID string) (*webauthn.SessionData, error) {
	data, _, err := s.TakeRegistration(ctx, sessionID)
	return data, err
}

// TakeRegistration is Take that also returns the PendingRegistration
// SaveRegistration stored with the session (nil for any other session).
func (s *MemorySessionStore) TakeRegistration(ctx context.Context, sessionID string) (*webauthn.SessionData, *PendingRegistration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.sessions[sessionID]
	if !ok {
		return nil, nil, ErrSessionNotFound
	}
	delete(s.sessions, sessionID)

	if s.clock().Sub(entry.createdAt) > s.ttl {
		return nil, nil, ErrSessionExpired
	}

	return entry.data, entry.pending, nil
}

// Delete removes session data by its ID.
func (s *MemorySessionStore) Delete(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, sessionID)
	return nil
}

// Count returns the number of sessions in the store.
func (s *MemorySessionStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

// Clear removes all sessions from the store.
func (s *MemorySessionStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = make(map[string]*sessionEntry)
}

// Cleanup removes expired sessions and returns how many it removed.
func (s *MemorySessionStore) Cleanup() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.removeExpiredLocked()
}

// limit returns the session cap, defaulting for a bare struct literal.
func (s *MemorySessionStore) limit() int {
	if s.maxSessions <= 0 {
		return DefaultMaxSessions
	}
	return s.maxSessions
}

// removeExpiredLocked removes expired sessions; s.mu must be write-locked.
func (s *MemorySessionStore) removeExpiredLocked() int {
	now := s.clock()
	removed := 0
	for id, entry := range s.sessions {
		if now.Sub(entry.createdAt) > s.ttl {
			delete(s.sessions, id)
			removed++
		}
	}
	return removed
}
