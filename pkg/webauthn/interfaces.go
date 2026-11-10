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

// SessionCleaner is implemented by session stores that keep expired
// sessions until they are swept. SweepSessions drives it.
type SessionCleaner interface {
	// Cleanup removes expired sessions and returns how many it removed.
	Cleanup() int
}

// SessionStore manages temporary WebAuthn session data during registration
// and authentication ceremonies. Sessions are typically short-lived (60-120 seconds).
// PendingRegistration is the account a public registration ceremony creates
// at finish. The ceremony runs under the random user handle in the session's
// UserID; a SessionStore persists this record alongside the session.
type PendingRegistration struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

type SessionStore interface {
	// Save stores session data and returns a session ID.
	// The session ID should be returned to the client for the finish operation.
	Save(ctx context.Context, data *webauthn.SessionData) (string, error)

	// Get retrieves session data by its ID.
	// Returns ErrSessionNotFound if the session does not exist or has expired.
	Get(ctx context.Context, sessionID string) (*webauthn.SessionData, error)

	// Take atomically claims a session: it returns the session data AND
	// removes it in one indivisible operation, so exactly one caller can ever
	// observe a given session.
	//
	// A WebAuthn ceremony session is single-use. Finishing a ceremony must
	// claim it with Take BEFORE validating the authenticator response;
	// validating first and deleting afterwards leaves a window in which two
	// concurrent finish requests both validate against the same challenge and
	// both succeed. Authenticator sign counters do not close that window —
	// go-webauthn only raises CloneWarning, and passkeys commonly report a
	// counter of 0.
	//
	// Returns ErrSessionNotFound when no session was claimed (missing, or
	// already taken by a concurrent caller) and ErrSessionExpired when the
	// claimed session had aged out. An expired session is consumed all the
	// same, so it cannot be retried.
	//
	// Implementations that cannot make this atomic must not be used: a
	// non-atomic take is the defect this method exists to remove.
	Take(ctx context.Context, sessionID string) (*webauthn.SessionData, error)

	// SaveRegistration stores the session of a public registration ceremony
	// together with the account it will create at finish, and returns a
	// session ID. The account does not exist until finish (ruling 417(2)), so
	// the store must persist pending with the session.
	SaveRegistration(ctx context.Context, data *webauthn.SessionData, pending *PendingRegistration) (string, error)

	// TakeRegistration claims a session like Take and also returns the
	// PendingRegistration saved with it, or nil when the session was saved
	// with Save.
	TakeRegistration(ctx context.Context, sessionID string) (*webauthn.SessionData, *PendingRegistration, error)

	// Delete removes session data by its ID.
	// Use it to discard a session that was never claimed; a completed ceremony
	// consumes its session through Take instead.
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

// TokenPairGenerator is an optional extension of JWTGenerator. Generators
// that implement it mint an access/refresh pair at ceremony completion, so
// browser and desktop sessions renew without a new hardware ceremony. The
// ceremony handlers detect it with a type assertion; plain JWTGenerator
// implementations keep working unchanged.
type TokenPairGenerator interface {
	JWTGenerator

	// GenerateTokenPair creates the access and refresh tokens for the
	// authenticated user.
	GenerateTokenPair(ctx context.Context, user User) (access, refresh string, err error)
}

// SessionDataWrapper wraps webauthn.SessionData with additional metadata.
type SessionDataWrapper struct {
	*webauthn.SessionData
	UserID []byte `json:"user_id,omitempty"`
}
