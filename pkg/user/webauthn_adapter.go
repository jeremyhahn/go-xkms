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
	"encoding/json"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	pkgwebauthn "github.com/jeremyhahn/go-keychain/pkg/webauthn"
)

// WebAuthnUserAdapter adapts the user.Store to the webauthn.UserStore interface.
type WebAuthnUserAdapter struct {
	store       Store
	defaultRole Role
}

// WebAuthnUserAdapterOption configures the WebAuthnUserAdapter.
type WebAuthnUserAdapterOption func(*WebAuthnUserAdapter)

// WithDefaultRole sets the default role for newly created users.
func WithDefaultRole(role Role) WebAuthnUserAdapterOption {
	return func(a *WebAuthnUserAdapter) {
		a.defaultRole = role
	}
}

// NewWebAuthnUserAdapter creates a new WebAuthn user store adapter.
// By default, new users are created with RoleAdmin (first user bootstrap).
// Use WithDefaultRole to change this behavior.
func NewWebAuthnUserAdapter(store Store, opts ...WebAuthnUserAdapterOption) *WebAuthnUserAdapter {
	a := &WebAuthnUserAdapter{
		store:       store,
		defaultRole: RoleAdmin, // Default for first user bootstrap
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// GetByID retrieves a user by their WebAuthn ID (user handle).
func (a *WebAuthnUserAdapter) GetByID(ctx context.Context, userID []byte) (pkgwebauthn.User, error) {
	user, err := a.store.GetByID(ctx, userID)
	if err != nil {
		if err == ErrUserNotFound {
			return nil, pkgwebauthn.ErrUserNotFound
		}
		return nil, err
	}
	return &WebAuthnUser{user: user}, nil
}

// GetByEmail retrieves a user by their email/username.
func (a *WebAuthnUserAdapter) GetByEmail(ctx context.Context, email string) (pkgwebauthn.User, error) {
	user, err := a.store.GetByUsername(ctx, email)
	if err != nil {
		if err == ErrUserNotFound {
			return nil, pkgwebauthn.ErrUserNotFound
		}
		return nil, err
	}
	return &WebAuthnUser{user: user}, nil
}

// Create creates a new user with the given email and display name.
// The role is determined by the defaultRole setting (RoleAdmin by default).
func (a *WebAuthnUserAdapter) Create(ctx context.Context, email, displayName string) (pkgwebauthn.User, error) {
	user, err := a.store.Create(ctx, email, displayName, a.defaultRole)
	if err != nil {
		if err == ErrUserAlreadyExists {
			return nil, pkgwebauthn.ErrUserAlreadyExists
		}
		return nil, err
	}
	return &WebAuthnUser{user: user}, nil
}

// Save persists changes to an existing user.
func (a *WebAuthnUserAdapter) Save(ctx context.Context, user pkgwebauthn.User) error {
	webAuthnUser, ok := user.(*WebAuthnUser)
	if !ok {
		return ErrInvalidCredential
	}
	return a.store.Update(ctx, webAuthnUser.user)
}

// Delete removes a user by their WebAuthn ID.
func (a *WebAuthnUserAdapter) Delete(ctx context.Context, userID []byte) error {
	err := a.store.Delete(ctx, userID)
	if err == ErrUserNotFound {
		return pkgwebauthn.ErrUserNotFound
	}
	return err
}

// WebAuthnUser wraps a User to implement the pkgwebauthn.User interface.
type WebAuthnUser struct {
	user *User
}

// WebAuthnID returns the user's WebAuthn ID (user handle).
func (u *WebAuthnUser) WebAuthnID() []byte {
	return u.user.ID
}

// WebAuthnName returns the user's username.
func (u *WebAuthnUser) WebAuthnName() string {
	return u.user.Username
}

// WebAuthnDisplayName returns the user's display name.
func (u *WebAuthnUser) WebAuthnDisplayName() string {
	return u.user.WebAuthnDisplayName()
}

// WebAuthnCredentials returns the user's WebAuthn credentials.
func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.user.WebAuthnCredentials()
}

// AddCredential adds a new credential to the user.
func (u *WebAuthnUser) AddCredential(cred *pkgwebauthn.Credential) {
	userCred := &Credential{
		ID:              cred.ID,
		PublicKey:       cred.PublicKey,
		AttestationType: cred.AttestationType,
		AAGUID:          cred.Authenticator.AAGUID,
		SignCount:       cred.Authenticator.SignCount,
		Name:            "WebAuthn Credential",
		CreatedAt:       cred.CreatedAt,
	}
	if !cred.LastUsedAt.IsZero() {
		userCred.LastUsedAt = &cred.LastUsedAt
	}
	u.user.AddCredential(userCred)
}

// UpdateCredential updates an existing credential.
func (u *WebAuthnUser) UpdateCredential(cred *pkgwebauthn.Credential) {
	u.user.UpdateCredential(cred.ID, cred.Authenticator.SignCount)
}

// SetSessionData stores WebAuthn session data on the user.
func (u *WebAuthnUser) SetSessionData(data []byte) {
	u.user.SetSessionData(data)
}

// SessionData returns the stored WebAuthn session data.
func (u *WebAuthnUser) SessionData() []byte {
	return u.user.SessionData()
}

// Email returns the user's email/username.
func (u *WebAuthnUser) Email() string {
	return u.user.Username
}

// DisplayName returns the user's display name.
func (u *WebAuthnUser) DisplayName() string {
	return u.user.DisplayName
}

// User returns the underlying User object.
func (u *WebAuthnUser) User() *User {
	return u.user
}

// WebAuthnSessionAdapter adapts the user.Store session methods to the webauthn.SessionStore interface.
type WebAuthnSessionAdapter struct {
	store Store
	ttl   time.Duration
}

// NewWebAuthnSessionAdapter creates a new WebAuthn session store adapter.
func NewWebAuthnSessionAdapter(store Store, ttl time.Duration) *WebAuthnSessionAdapter {
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	return &WebAuthnSessionAdapter{store: store, ttl: ttl}
}

// Save stores session data and returns a session ID.
func (a *WebAuthnSessionAdapter) Save(ctx context.Context, data *webauthn.SessionData) (string, error) {
	sessionID, err := GenerateSessionID()
	if err != nil {
		return "", err
	}

	// Marshal the session data
	sessionBytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	if err := a.store.SaveSession(ctx, sessionID, sessionBytes, a.ttl); err != nil {
		return "", err
	}

	return sessionID, nil
}

// Get retrieves session data by its ID.
func (a *WebAuthnSessionAdapter) Get(ctx context.Context, sessionID string) (*webauthn.SessionData, error) {
	data, err := a.store.GetSession(ctx, sessionID)
	if err != nil {
		if err == ErrSessionNotFound {
			return nil, pkgwebauthn.ErrSessionNotFound
		}
		return nil, err
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(data, &sessionData); err != nil {
		return nil, err
	}
	return &sessionData, nil
}

// Delete removes session data by its ID.
func (a *WebAuthnSessionAdapter) Delete(ctx context.Context, sessionID string) error {
	return a.store.DeleteSession(ctx, sessionID)
}

// WebAuthnCredentialAdapter adapts the user.Store to the webauthn.CredentialStore interface.
type WebAuthnCredentialAdapter struct {
	store Store
}

// NewWebAuthnCredentialAdapter creates a new WebAuthn credential store adapter.
func NewWebAuthnCredentialAdapter(store Store) *WebAuthnCredentialAdapter {
	return &WebAuthnCredentialAdapter{store: store}
}

// Save stores a new credential.
func (a *WebAuthnCredentialAdapter) Save(ctx context.Context, cred *pkgwebauthn.Credential) error {
	// Get the user by user ID
	user, err := a.store.GetByID(ctx, cred.UserID)
	if err != nil {
		return err
	}

	// Add the credential to the user
	userCred := &Credential{
		ID:              cred.ID,
		PublicKey:       cred.PublicKey,
		AttestationType: cred.AttestationType,
		AAGUID:          cred.Authenticator.AAGUID,
		SignCount:       cred.Authenticator.SignCount,
		Name:            "WebAuthn Credential",
		CreatedAt:       cred.CreatedAt,
	}
	if !cred.LastUsedAt.IsZero() {
		userCred.LastUsedAt = &cred.LastUsedAt
	}
	user.AddCredential(userCred)

	// Save the user
	return a.store.Update(ctx, user)
}

// GetByUserID retrieves all credentials for a user.
func (a *WebAuthnCredentialAdapter) GetByUserID(ctx context.Context, userID []byte) ([]*pkgwebauthn.Credential, error) {
	user, err := a.store.GetByID(ctx, userID)
	if err != nil {
		if err == ErrUserNotFound {
			return []*pkgwebauthn.Credential{}, nil
		}
		return nil, err
	}

	creds := make([]*pkgwebauthn.Credential, len(user.Credentials))
	for i, uc := range user.Credentials {
		creds[i] = &pkgwebauthn.Credential{
			ID:              uc.ID,
			UserID:          user.ID,
			PublicKey:       uc.PublicKey,
			AttestationType: uc.AttestationType,
			Authenticator: pkgwebauthn.AuthenticatorData{
				AAGUID:    uc.AAGUID,
				SignCount: uc.SignCount,
			},
			CreatedAt: uc.CreatedAt,
		}
		if uc.LastUsedAt != nil {
			creds[i].LastUsedAt = *uc.LastUsedAt
		}
	}

	return creds, nil
}

// GetByCredentialID retrieves a credential by its ID.
func (a *WebAuthnCredentialAdapter) GetByCredentialID(ctx context.Context, credID []byte) (*pkgwebauthn.Credential, error) {
	// We need to search all users for this credential
	users, err := a.store.List(ctx)
	if err != nil {
		return nil, err
	}

	for _, user := range users {
		for _, uc := range user.Credentials {
			if string(uc.ID) == string(credID) {
				cred := &pkgwebauthn.Credential{
					ID:              uc.ID,
					UserID:          user.ID,
					PublicKey:       uc.PublicKey,
					AttestationType: uc.AttestationType,
					Authenticator: pkgwebauthn.AuthenticatorData{
						AAGUID:    uc.AAGUID,
						SignCount: uc.SignCount,
					},
					CreatedAt: uc.CreatedAt,
				}
				if uc.LastUsedAt != nil {
					cred.LastUsedAt = *uc.LastUsedAt
				}
				return cred, nil
			}
		}
	}

	return nil, pkgwebauthn.ErrCredentialNotFound
}

// Update updates an existing credential.
func (a *WebAuthnCredentialAdapter) Update(ctx context.Context, cred *pkgwebauthn.Credential) error {
	user, err := a.store.GetByID(ctx, cred.UserID)
	if err != nil {
		return err
	}

	user.UpdateCredential(cred.ID, cred.Authenticator.SignCount)
	return a.store.Update(ctx, user)
}

// Delete removes a credential by its ID.
func (a *WebAuthnCredentialAdapter) Delete(ctx context.Context, credID []byte) error {
	// Find the user with this credential
	users, err := a.store.List(ctx)
	if err != nil {
		return err
	}

	for _, user := range users {
		if user.RemoveCredential(credID) {
			return a.store.Update(ctx, user)
		}
	}

	return pkgwebauthn.ErrCredentialNotFound
}

// DeleteByUserID removes all credentials for a user.
func (a *WebAuthnCredentialAdapter) DeleteByUserID(ctx context.Context, userID []byte) error {
	user, err := a.store.GetByID(ctx, userID)
	if err != nil {
		if err == ErrUserNotFound {
			return nil
		}
		return err
	}

	user.Credentials = []Credential{}
	return a.store.Update(ctx, user)
}
