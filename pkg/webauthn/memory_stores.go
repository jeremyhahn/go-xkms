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

package webauthn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// MemoryUserStore is an in-memory implementation of UserStore.
// This is intended for development and testing only.
type MemoryUserStore struct {
	mu       sync.RWMutex
	byID     map[string]*DefaultUser
	byEmail  map[string]*DefaultUser
	idToMail map[string]string
}

// NewMemoryUserStore creates a new in-memory user store.
func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{
		byID:     make(map[string]*DefaultUser),
		byEmail:  make(map[string]*DefaultUser),
		idToMail: make(map[string]string),
	}
}

// GetByID retrieves a user by their WebAuthn ID.
func (s *MemoryUserStore) GetByID(ctx context.Context, userID []byte) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := hex.EncodeToString(userID)
	user, ok := s.byID[key]
	if !ok {
		return nil, ErrUserNotFound
	}
	return user, nil
}

// GetByEmail retrieves a user by their email address.
func (s *MemoryUserStore) GetByEmail(ctx context.Context, email string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, ok := s.byEmail[email]
	if !ok {
		return nil, ErrUserNotFound
	}
	return user, nil
}

// Create creates a new user with the given email and display name.
func (s *MemoryUserStore) Create(ctx context.Context, email, displayName string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if user already exists
	if _, ok := s.byEmail[email]; ok {
		return nil, ErrUserAlreadyExists
	}

	user := NewDefaultUserFromEmail(email, displayName)
	key := hex.EncodeToString(user.WebAuthnID())

	s.byID[key] = user
	s.byEmail[email] = user
	s.idToMail[key] = email

	return user, nil
}

// Save persists changes to an existing user.
func (s *MemoryUserStore) Save(ctx context.Context, user User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := hex.EncodeToString(user.WebAuthnID())
	defaultUser, ok := user.(*DefaultUser)
	if !ok {
		return ErrInvalidRequest
	}

	s.byID[key] = defaultUser
	s.byEmail[defaultUser.Email()] = defaultUser
	s.idToMail[key] = defaultUser.Email()

	return nil
}

// Delete removes a user by their WebAuthn ID.
func (s *MemoryUserStore) Delete(ctx context.Context, userID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := hex.EncodeToString(userID)
	email, ok := s.idToMail[key]
	if !ok {
		return ErrUserNotFound
	}

	delete(s.byID, key)
	delete(s.byEmail, email)
	delete(s.idToMail, key)

	return nil
}

// Count returns the number of users in the store.
func (s *MemoryUserStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}

// Clear removes all users from the store.
func (s *MemoryUserStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID = make(map[string]*DefaultUser)
	s.byEmail = make(map[string]*DefaultUser)
	s.idToMail = make(map[string]string)
}

// MemorySessionStore is an in-memory implementation of SessionStore.
// This is intended for development and testing only.
type MemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*sessionEntry
	ttl      time.Duration
}

type sessionEntry struct {
	data      *webauthn.SessionData
	createdAt time.Time
}

// NewMemorySessionStore creates a new in-memory session store.
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{
		sessions: make(map[string]*sessionEntry),
		ttl:      2 * time.Minute,
	}
}

// NewMemorySessionStoreWithTTL creates a new in-memory session store with custom TTL.
func NewMemorySessionStoreWithTTL(ttl time.Duration) *MemorySessionStore {
	return &MemorySessionStore{
		sessions: make(map[string]*sessionEntry),
		ttl:      ttl,
	}
}

// Save stores session data and returns a session ID.
func (s *MemorySessionStore) Save(ctx context.Context, data *webauthn.SessionData) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate random session ID
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return "", err
	}
	sessionID := hex.EncodeToString(idBytes)

	s.sessions[sessionID] = &sessionEntry{
		data:      data,
		createdAt: time.Now(),
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
	if time.Since(entry.createdAt) > s.ttl {
		return nil, ErrSessionExpired
	}

	return entry.data, nil
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

// Cleanup removes expired sessions.
func (s *MemorySessionStore) Cleanup() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	removed := 0
	for id, entry := range s.sessions {
		if now.Sub(entry.createdAt) > s.ttl {
			delete(s.sessions, id)
			removed++
		}
	}
	return removed
}

// MemoryCredentialStore is an in-memory implementation of CredentialStore.
// This is intended for development and testing only.
type MemoryCredentialStore struct {
	mu       sync.RWMutex
	byID     map[string]*Credential
	byUserID map[string][]*Credential
	idToUser map[string]string
}

// NewMemoryCredentialStore creates a new in-memory credential store.
func NewMemoryCredentialStore() *MemoryCredentialStore {
	return &MemoryCredentialStore{
		byID:     make(map[string]*Credential),
		byUserID: make(map[string][]*Credential),
		idToUser: make(map[string]string),
	}
}

// Save stores a new credential.
func (s *MemoryCredentialStore) Save(ctx context.Context, cred *Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	credKey := hex.EncodeToString(cred.ID)
	userKey := hex.EncodeToString(cred.UserID)

	// Check if credential already exists
	if _, ok := s.byID[credKey]; ok {
		return ErrCredentialAlreadyExists
	}

	s.byID[credKey] = cred
	s.byUserID[userKey] = append(s.byUserID[userKey], cred)
	s.idToUser[credKey] = userKey

	return nil
}

// GetByUserID retrieves all credentials for a user.
func (s *MemoryCredentialStore) GetByUserID(ctx context.Context, userID []byte) ([]*Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := hex.EncodeToString(userID)
	creds, ok := s.byUserID[key]
	if !ok {
		return []*Credential{}, nil
	}

	// Return a copy to prevent external modification
	result := make([]*Credential, len(creds))
	copy(result, creds)
	return result, nil
}

// GetByCredentialID retrieves a credential by its ID.
func (s *MemoryCredentialStore) GetByCredentialID(ctx context.Context, credID []byte) (*Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := hex.EncodeToString(credID)
	cred, ok := s.byID[key]
	if !ok {
		return nil, ErrCredentialNotFound
	}
	return cred, nil
}

// Update updates an existing credential.
func (s *MemoryCredentialStore) Update(ctx context.Context, cred *Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	credKey := hex.EncodeToString(cred.ID)
	if _, ok := s.byID[credKey]; !ok {
		return ErrCredentialNotFound
	}

	s.byID[credKey] = cred

	// Update in user's credential list
	userKey := hex.EncodeToString(cred.UserID)
	creds := s.byUserID[userKey]
	for i, c := range creds {
		if hex.EncodeToString(c.ID) == credKey {
			creds[i] = cred
			break
		}
	}

	return nil
}

// Delete removes a credential by its ID.
func (s *MemoryCredentialStore) Delete(ctx context.Context, credID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	credKey := hex.EncodeToString(credID)
	userKey, ok := s.idToUser[credKey]
	if !ok {
		return ErrCredentialNotFound
	}

	delete(s.byID, credKey)
	delete(s.idToUser, credKey)

	// Remove from user's credential list
	creds := s.byUserID[userKey]
	for i, c := range creds {
		if hex.EncodeToString(c.ID) == credKey {
			s.byUserID[userKey] = append(creds[:i], creds[i+1:]...)
			break
		}
	}

	return nil
}

// DeleteByUserID removes all credentials for a user.
func (s *MemoryCredentialStore) DeleteByUserID(ctx context.Context, userID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	userKey := hex.EncodeToString(userID)
	creds, ok := s.byUserID[userKey]
	if !ok {
		return nil
	}

	// Remove all credentials
	for _, cred := range creds {
		credKey := hex.EncodeToString(cred.ID)
		delete(s.byID, credKey)
		delete(s.idToUser, credKey)
	}

	delete(s.byUserID, userKey)
	return nil
}

// Count returns the total number of credentials in the store.
func (s *MemoryCredentialStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}

// Clear removes all credentials from the store.
func (s *MemoryCredentialStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID = make(map[string]*Credential)
	s.byUserID = make(map[string][]*Credential)
	s.idToUser = make(map[string]string)
}
