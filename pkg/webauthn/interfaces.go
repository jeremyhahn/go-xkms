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

	"github.com/go-webauthn/webauthn/webauthn"
)

// UserStore is the interface applications implement for user persistence.
// This interface is intentionally minimal - applications bring their own user model.
type UserStore interface {
	// GetByID retrieves a user by their WebAuthn ID (user handle).
	// Returns ErrUserNotFound if the user does not exist.
	GetByID(ctx context.Context, userID []byte) (User, error)

	// GetByEmail retrieves a user by their email address.
	// Returns ErrUserNotFound if the user does not exist.
	GetByEmail(ctx context.Context, email string) (User, error)

	// Create creates a new user with the given email and display name.
	// Returns the created user with its assigned ID.
	Create(ctx context.Context, email, displayName string) (User, error)

	// Save persists changes to an existing user (credentials, session data, etc.).
	Save(ctx context.Context, user User) error

	// Delete removes a user by their WebAuthn ID.
	// Returns ErrUserNotFound if the user does not exist.
	Delete(ctx context.Context, userID []byte) error
}

// SessionStore manages temporary WebAuthn session data during registration
// and authentication ceremonies. Sessions are typically short-lived (60-120 seconds).
type SessionStore interface {
	// Save stores session data and returns a session ID.
	// The session ID should be returned to the client for the finish operation.
	Save(ctx context.Context, data *webauthn.SessionData) (string, error)

	// Get retrieves session data by its ID.
	// Returns ErrSessionNotFound if the session does not exist or has expired.
	Get(ctx context.Context, sessionID string) (*webauthn.SessionData, error)

	// Delete removes session data by its ID.
	// This should be called after a ceremony completes (success or failure).
	Delete(ctx context.Context, sessionID string) error
}

// CredentialStore manages WebAuthn credential persistence.
// Credentials are the public key records stored by the Relying Party.
type CredentialStore interface {
	// Save stores a new credential.
	Save(ctx context.Context, cred *Credential) error

	// GetByUserID retrieves all credentials for a user.
	// Returns an empty slice if the user has no credentials.
	GetByUserID(ctx context.Context, userID []byte) ([]*Credential, error)

	// GetByCredentialID retrieves a credential by its ID.
	// Returns ErrCredentialNotFound if the credential does not exist.
	GetByCredentialID(ctx context.Context, credID []byte) (*Credential, error)

	// Update updates an existing credential (e.g., sign counter, last used).
	// Returns ErrCredentialNotFound if the credential does not exist.
	Update(ctx context.Context, cred *Credential) error

	// Delete removes a credential by its ID.
	// Returns ErrCredentialNotFound if the credential does not exist.
	Delete(ctx context.Context, credID []byte) error

	// DeleteByUserID removes all credentials for a user.
	DeleteByUserID(ctx context.Context, userID []byte) error
}

// JWTGenerator is an optional interface for generating tokens after
// successful registration or authentication. If not provided, the
// service returns the base64-encoded user ID.
type JWTGenerator interface {
	// GenerateToken creates a JWT or other token for the authenticated user.
	GenerateToken(ctx context.Context, user User) (string, error)
}

// SessionDataWrapper wraps webauthn.SessionData with additional metadata.
type SessionDataWrapper struct {
	*webauthn.SessionData
	UserID []byte `json:"user_id,omitempty"`
}
