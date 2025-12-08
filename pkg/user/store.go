// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package user

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
)

const (
	// Storage key prefixes
	userPrefix       = "users/"
	userByIDPrefix   = "users/by-id/"
	userByNamePrefix = "users/by-name/"
	sessionPrefix    = "users/sessions/"

	// Default session TTL
	defaultSessionTTL = 5 * time.Minute
)

// Store defines the interface for user persistence.
type Store interface {
	// Create creates a new user.
	Create(ctx context.Context, username, displayName string, role Role) (*User, error)

	// GetByID retrieves a user by their ID.
	GetByID(ctx context.Context, id []byte) (*User, error)

	// GetByUsername retrieves a user by their username.
	GetByUsername(ctx context.Context, username string) (*User, error)

	// Update saves changes to a user.
	Update(ctx context.Context, user *User) error

	// Delete removes a user by their ID.
	Delete(ctx context.Context, id []byte) error

	// List returns all users.
	List(ctx context.Context) ([]*User, error)

	// Count returns the number of users.
	Count(ctx context.Context) (int, error)

	// HasAnyUsers returns true if at least one user exists.
	HasAnyUsers(ctx context.Context) (bool, error)

	// CountAdmins returns the number of users with admin role.
	CountAdmins(ctx context.Context) (int, error)

	// SaveSession stores a WebAuthn session for later retrieval.
	SaveSession(ctx context.Context, sessionID string, data []byte, ttl time.Duration) error

	// GetSession retrieves a WebAuthn session.
	GetSession(ctx context.Context, sessionID string) ([]byte, error)

	// DeleteSession removes a WebAuthn session.
	DeleteSession(ctx context.Context, sessionID string) error

	// Close releases resources.
	Close() error
}

// FileStore implements Store using the storage.Backend interface.
type FileStore struct {
	backend storage.Backend
	mu      sync.RWMutex
	closed  bool

	// Session cache with TTL (in-memory for performance)
	sessions        map[string]sessionEntry
	sessionMu       sync.RWMutex
	cleanupDone     chan struct{}
	cleanupInterval time.Duration
}

type sessionEntry struct {
	data      []byte
	expiresAt time.Time
}

// FileStoreOption is a functional option for configuring FileStore.
type FileStoreOption func(*FileStore)

// WithCleanupInterval sets the session cleanup interval.
// Default is 1 minute. Use a smaller value for testing.
func WithCleanupInterval(d time.Duration) FileStoreOption {
	return func(s *FileStore) {
		s.cleanupInterval = d
	}
}

// NewFileStore creates a new file-based user store.
func NewFileStore(backend storage.Backend, opts ...FileStoreOption) (*FileStore, error) {
	if backend == nil {
		return nil, fmt.Errorf("backend cannot be nil")
	}

	store := &FileStore{
		backend:         backend,
		sessions:        make(map[string]sessionEntry),
		cleanupDone:     make(chan struct{}),
		cleanupInterval: time.Minute, // default
	}

	// Apply options
	for _, opt := range opts {
		opt(store)
	}

	// Start session cleanup goroutine
	go store.cleanupSessions()

	return store, nil
}

// Create creates a new user.
func (s *FileStore) Create(ctx context.Context, username, displayName string, role Role) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrStorageClosed
	}

	// Validate username
	if username == "" {
		return nil, ErrInvalidUsername
	}
	username = strings.ToLower(strings.TrimSpace(username))

	// Validate role
	if !IsValidRole(role) {
		return nil, ErrInvalidRole
	}

	// Check if username already exists
	nameKey := userByNamePrefix + username
	exists, err := s.backend.Exists(nameKey)
	if err != nil {
		return nil, fmt.Errorf("failed to check username: %w", err)
	}
	if exists {
		return nil, ErrUserAlreadyExists
	}

	// Generate ID
	id := generateUserID(username)

	user := &User{
		ID:          id,
		Username:    username,
		DisplayName: displayName,
		Role:        role,
		Credentials: []Credential{},
		CreatedAt:   time.Now().UTC(),
		Enabled:     true,
	}

	// Store the user
	if err := s.saveUserLocked(user); err != nil {
		return nil, err
	}

	return user, nil
}

// GetByID retrieves a user by their ID.
func (s *FileStore) GetByID(ctx context.Context, id []byte) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStorageClosed
	}

	idKey := userByIDPrefix + base64.URLEncoding.EncodeToString(id)
	data, err := s.backend.Get(idKey)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %w", err)
	}

	return &user, nil
}

// GetByUsername retrieves a user by their username.
func (s *FileStore) GetByUsername(ctx context.Context, username string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStorageClosed
	}

	username = strings.ToLower(strings.TrimSpace(username))
	nameKey := userByNamePrefix + username

	// Get the user ID from the name index
	idData, err := s.backend.Get(nameKey)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by name: %w", err)
	}

	// Get the actual user data
	idKey := userByIDPrefix + string(idData)
	data, err := s.backend.Get(idKey)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %w", err)
	}

	return &user, nil
}

// Update saves changes to a user.
func (s *FileStore) Update(ctx context.Context, user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStorageClosed
	}

	// Verify user exists
	idKey := userByIDPrefix + base64.URLEncoding.EncodeToString(user.ID)
	exists, err := s.backend.Exists(idKey)
	if err != nil {
		return fmt.Errorf("failed to check user: %w", err)
	}
	if !exists {
		return ErrUserNotFound
	}

	return s.saveUserLocked(user)
}

// Delete removes a user by their ID.
func (s *FileStore) Delete(ctx context.Context, id []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStorageClosed
	}

	// Get the user first to get the username and role
	idKey := userByIDPrefix + base64.URLEncoding.EncodeToString(id)
	data, err := s.backend.Get(idKey)
	if err != nil {
		if err == storage.ErrNotFound {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to get user: %w", err)
	}

	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return fmt.Errorf("failed to unmarshal user: %w", err)
	}

	// Check if this is the last admin
	if user.Role == RoleAdmin {
		adminCount, err := s.countAdminsLocked()
		if err != nil {
			return fmt.Errorf("failed to count admins: %w", err)
		}
		if adminCount <= 1 {
			return ErrLastAdmin
		}
	}

	// Delete the name index
	nameKey := userByNamePrefix + user.Username
	_ = s.backend.Delete(nameKey) // Ignore error if not exists

	// Delete the user data
	if err := s.backend.Delete(idKey); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}

// List returns all users.
func (s *FileStore) List(ctx context.Context) ([]*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStorageClosed
	}

	keys, err := s.backend.List(userByIDPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	users := make([]*User, 0, len(keys))
	for _, key := range keys {
		data, err := s.backend.Get(key)
		if err != nil {
			continue // Skip invalid entries
		}

		var user User
		if err := json.Unmarshal(data, &user); err != nil {
			continue // Skip invalid entries
		}

		users = append(users, &user)
	}

	return users, nil
}

// Count returns the number of users.
func (s *FileStore) Count(ctx context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return 0, ErrStorageClosed
	}

	keys, err := s.backend.List(userByIDPrefix)
	if err != nil {
		return 0, fmt.Errorf("failed to count users: %w", err)
	}

	return len(keys), nil
}

// HasAnyUsers returns true if at least one user exists.
func (s *FileStore) HasAnyUsers(ctx context.Context) (bool, error) {
	count, err := s.Count(ctx)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// CountAdmins returns the number of users with admin role.
func (s *FileStore) CountAdmins(ctx context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return 0, ErrStorageClosed
	}

	return s.countAdminsLocked()
}

// SaveSession stores a WebAuthn session for later retrieval.
func (s *FileStore) SaveSession(ctx context.Context, sessionID string, data []byte, ttl time.Duration) error {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()

	if s.closed {
		return ErrStorageClosed
	}

	if ttl == 0 {
		ttl = defaultSessionTTL
	}

	s.sessions[sessionID] = sessionEntry{
		data:      data,
		expiresAt: time.Now().Add(ttl),
	}

	return nil
}

// GetSession retrieves a WebAuthn session.
func (s *FileStore) GetSession(ctx context.Context, sessionID string) ([]byte, error) {
	s.sessionMu.RLock()
	defer s.sessionMu.RUnlock()

	if s.closed {
		return nil, ErrStorageClosed
	}

	entry, ok := s.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}

	if time.Now().After(entry.expiresAt) {
		return nil, ErrSessionNotFound
	}

	return entry.data, nil
}

// DeleteSession removes a WebAuthn session.
func (s *FileStore) DeleteSession(ctx context.Context, sessionID string) error {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()

	if s.closed {
		return ErrStorageClosed
	}

	delete(s.sessions, sessionID)
	return nil
}

// Close releases resources.
func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true
	close(s.cleanupDone)

	return nil
}

// Helper functions

func (s *FileStore) saveUserLocked(user *User) error {
	data, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("failed to marshal user: %w", err)
	}

	idKey := userByIDPrefix + base64.URLEncoding.EncodeToString(user.ID)
	opts := storage.DefaultOptions()
	opts.Permissions = 0600 // Secure permissions for user data

	if err := s.backend.Put(idKey, data, opts); err != nil {
		return fmt.Errorf("failed to save user: %w", err)
	}

	// Create name index
	nameKey := userByNamePrefix + user.Username
	encodedID := base64.URLEncoding.EncodeToString(user.ID)
	if err := s.backend.Put(nameKey, []byte(encodedID), opts); err != nil {
		return fmt.Errorf("failed to save name index: %w", err)
	}

	return nil
}

func (s *FileStore) countAdminsLocked() (int, error) {
	keys, err := s.backend.List(userByIDPrefix)
	if err != nil {
		return 0, fmt.Errorf("failed to list users: %w", err)
	}

	count := 0
	for _, key := range keys {
		data, err := s.backend.Get(key)
		if err != nil {
			continue
		}

		var user User
		if err := json.Unmarshal(data, &user); err != nil {
			continue
		}

		if user.Role == RoleAdmin {
			count++
		}
	}

	return count, nil
}

func (s *FileStore) cleanupSessions() {
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.sessionMu.Lock()
			now := time.Now()
			for id, entry := range s.sessions {
				if now.After(entry.expiresAt) {
					delete(s.sessions, id)
				}
			}
			s.sessionMu.Unlock()
		case <-s.cleanupDone:
			return
		}
	}
}

func generateUserID(username string) []byte {
	// Use FNV-1a hash for deterministic ID generation
	var h uint64 = 14695981039346656037 // FNV offset basis
	for _, b := range []byte("user:" + username) {
		h ^= uint64(b)
		h *= 1099511628211 // FNV prime
	}
	id := make([]byte, 8)
	binary.BigEndian.PutUint64(id, h)
	return id
}

// GenerateSessionID generates a random session ID.
func GenerateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
