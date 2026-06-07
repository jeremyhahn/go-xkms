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
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// Storage key namespaces. Users and their credentials are persisted under
// these prefixes in the backing datastore so WebAuthn registrations survive
// restarts (and replicate under Raft) for any storage backend — not only when
// xkms hosts the qrdb identity plane.
const (
	userKeyPrefix       = "webauthn/users/"         // <hexUserID> -> persistedUser JSON
	userEmailKeyPrefix  = "webauthn/email/"         // <email>     -> hexUserID
	credKeyPrefix       = "webauthn/creds/"         // <hexCredID> -> Credential JSON
	credByUserKeyPrefix = "webauthn/creds-by-user/" // <hexUserID>/<hexCredID> -> marker
)

// persistedUser is the JSON-serializable form of a DefaultUser. DefaultUser
// has unexported fields, so it is projected through this DTO for storage.
type persistedUser struct {
	ID          []byte        `json:"id"`
	Email       string        `json:"email"`
	DisplayName string        `json:"display_name"`
	Credentials []*Credential `json:"credentials"`
	SessionData []byte        `json:"session_data,omitempty"`
}

func toPersistedUser(u *DefaultUser) persistedUser {
	return persistedUser{
		ID:          u.WebAuthnID(),
		Email:       u.Email(),
		DisplayName: u.DisplayName(),
		Credentials: u.Credentials(),
		SessionData: u.SessionData(),
	}
}

func (p persistedUser) toDefaultUser() *DefaultUser {
	u := NewDefaultUser(p.ID, p.Email, p.DisplayName)
	if len(p.Credentials) > 0 {
		u.SetCredentials(p.Credentials)
	}
	if len(p.SessionData) > 0 {
		u.SetSessionData(p.SessionData)
	}
	return u
}

// BackendUserStore is a durable UserStore backed by a storage.Backend.
type BackendUserStore struct {
	backend storage.Backend
}

// Compile-time assertion that BackendUserStore satisfies UserStore.
var _ UserStore = (*BackendUserStore)(nil)

// NewBackendUserStore creates a durable UserStore over the given backend.
func NewBackendUserStore(backend storage.Backend) *BackendUserStore {
	return &BackendUserStore{backend: backend}
}

func userKey(userID []byte) string { return userKeyPrefix + hex.EncodeToString(userID) }
func emailKey(email string) string { return userEmailKeyPrefix + email }

// GetByID retrieves a user by their WebAuthn ID.
func (s *BackendUserStore) GetByID(ctx context.Context, userID []byte) (User, error) {
	data, err := s.backend.Get(ctx, userKey(userID))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, &WebAuthnError{Op: "user store: get by id", Err: err}
	}
	var p persistedUser
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, &WebAuthnError{Op: "user store: unmarshal user", Err: err}
	}
	return p.toDefaultUser(), nil
}

// GetByEmail retrieves a user by their email address.
func (s *BackendUserStore) GetByEmail(ctx context.Context, email string) (User, error) {
	idHex, err := s.backend.Get(ctx, emailKey(email))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, &WebAuthnError{Op: "user store: get by email", Err: err}
	}
	userID, err := hex.DecodeString(string(idHex))
	if err != nil {
		return nil, &WebAuthnError{Op: "user store: decode email index", Err: err}
	}
	return s.GetByID(ctx, userID)
}

// Create creates a new user with the given email and display name.
func (s *BackendUserStore) Create(ctx context.Context, email, displayName string) (User, error) {
	if exists, err := s.backend.Exists(ctx, emailKey(email)); err != nil {
		return nil, &WebAuthnError{Op: "user store: check email", Err: err}
	} else if exists {
		return nil, ErrUserAlreadyExists
	}
	user := NewDefaultUserFromEmail(email, displayName)
	if err := s.put(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}

// Save persists changes to an existing user (credentials, session data, etc.).
func (s *BackendUserStore) Save(ctx context.Context, user User) error {
	defaultUser, ok := user.(*DefaultUser)
	if !ok {
		return ErrInvalidRequest
	}
	return s.put(ctx, defaultUser)
}

// put writes the user record and its email index.
func (s *BackendUserStore) put(ctx context.Context, user *DefaultUser) error {
	buf, err := json.Marshal(toPersistedUser(user))
	if err != nil {
		return &WebAuthnError{Op: "user store: marshal user", Err: err}
	}
	if err := s.backend.Put(ctx, userKey(user.WebAuthnID()), buf); err != nil {
		return &WebAuthnError{Op: "user store: put user", Err: err}
	}
	if err := s.backend.Put(ctx, emailKey(user.Email()), []byte(hex.EncodeToString(user.WebAuthnID()))); err != nil {
		return &WebAuthnError{Op: "user store: put email index", Err: err}
	}
	return nil
}

// Delete removes a user by their WebAuthn ID.
func (s *BackendUserStore) Delete(ctx context.Context, userID []byte) error {
	user, err := s.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.backend.Delete(ctx, userKey(userID)); err != nil {
		return &WebAuthnError{Op: "user store: delete user", Err: err}
	}
	// Best-effort email index cleanup; a missing index must not fail Delete.
	if err := s.backend.Delete(ctx, emailKey(user.Email())); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return &WebAuthnError{Op: "user store: delete email index", Err: err}
	}
	return nil
}

// BackendCredentialStore is a durable CredentialStore backed by a storage.Backend.
type BackendCredentialStore struct {
	backend storage.Backend
}

// Compile-time assertion that BackendCredentialStore satisfies CredentialStore.
var _ CredentialStore = (*BackendCredentialStore)(nil)

// NewBackendCredentialStore creates a durable CredentialStore over the backend.
func NewBackendCredentialStore(backend storage.Backend) *BackendCredentialStore {
	return &BackendCredentialStore{backend: backend}
}

func backendCredKey(credID []byte) string { return credKeyPrefix + hex.EncodeToString(credID) }

func credByUserKey(userID, credID []byte) string {
	return credByUserKeyPrefix + hex.EncodeToString(userID) + "/" + hex.EncodeToString(credID)
}

// Save stores a new credential and its user index.
func (s *BackendCredentialStore) Save(ctx context.Context, cred *Credential) error {
	if cred == nil {
		return ErrInvalidRequest
	}
	buf, err := json.Marshal(cred)
	if err != nil {
		return &WebAuthnError{Op: "cred store: marshal credential", Err: err}
	}
	if err := s.backend.Put(ctx, backendCredKey(cred.ID), buf); err != nil {
		return &WebAuthnError{Op: "cred store: put credential", Err: err}
	}
	if err := s.backend.Put(ctx, credByUserKey(cred.UserID, cred.ID), []byte{1}); err != nil {
		return &WebAuthnError{Op: "cred store: put user index", Err: err}
	}
	return nil
}

// GetByCredentialID retrieves a credential by its ID.
func (s *BackendCredentialStore) GetByCredentialID(ctx context.Context, credID []byte) (*Credential, error) {
	data, err := s.backend.Get(ctx, backendCredKey(credID))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrCredentialNotFound
		}
		return nil, &WebAuthnError{Op: "cred store: get credential", Err: err}
	}
	var cred Credential
	if err := json.Unmarshal(data, &cred); err != nil {
		return nil, &WebAuthnError{Op: "cred store: unmarshal credential", Err: err}
	}
	return &cred, nil
}

// GetByUserID retrieves all credentials for a user.
func (s *BackendCredentialStore) GetByUserID(ctx context.Context, userID []byte) ([]*Credential, error) {
	prefix := credByUserKeyPrefix + hex.EncodeToString(userID) + "/"
	keys, err := s.backend.List(ctx, prefix)
	if err != nil {
		return nil, &WebAuthnError{Op: "cred store: list user credentials", Err: err}
	}
	creds := make([]*Credential, 0, len(keys))
	for _, k := range keys {
		credIDHex := k[len(prefix):]
		credID, err := hex.DecodeString(credIDHex)
		if err != nil {
			continue
		}
		cred, err := s.GetByCredentialID(ctx, credID)
		if err != nil {
			if errors.Is(err, ErrCredentialNotFound) {
				continue
			}
			return nil, err
		}
		creds = append(creds, cred)
	}
	return creds, nil
}

// Update updates an existing credential.
func (s *BackendCredentialStore) Update(ctx context.Context, cred *Credential) error {
	if cred == nil {
		return ErrInvalidRequest
	}
	if exists, err := s.backend.Exists(ctx, backendCredKey(cred.ID)); err != nil {
		return &WebAuthnError{Op: "cred store: check credential", Err: err}
	} else if !exists {
		return ErrCredentialNotFound
	}
	return s.Save(ctx, cred)
}

// Delete removes a credential by its ID.
func (s *BackendCredentialStore) Delete(ctx context.Context, credID []byte) error {
	cred, err := s.GetByCredentialID(ctx, credID)
	if err != nil {
		return err
	}
	if err := s.backend.Delete(ctx, backendCredKey(credID)); err != nil {
		return &WebAuthnError{Op: "cred store: delete credential", Err: err}
	}
	if err := s.backend.Delete(ctx, credByUserKey(cred.UserID, credID)); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return &WebAuthnError{Op: "cred store: delete user index", Err: err}
	}
	return nil
}

// DeleteByUserID removes all credentials for a user.
func (s *BackendCredentialStore) DeleteByUserID(ctx context.Context, userID []byte) error {
	creds, err := s.GetByUserID(ctx, userID)
	if err != nil {
		return err
	}
	for _, cred := range creds {
		if err := s.Delete(ctx, cred.ID); err != nil && !errors.Is(err, ErrCredentialNotFound) {
			return err
		}
	}
	return nil
}
