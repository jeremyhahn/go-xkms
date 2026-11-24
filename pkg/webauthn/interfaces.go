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

	// TenantID is the tenant the store resolves accounts in: the relying
	// party's served tenant. It must never be empty; an empty tenant is
	// refused (UserStoreTenantUnsetError), never read as the system tenant
	// (ruling 1041 (1)).
	TenantID() string
}

// SessionCleaner is implemented by session stores that keep expired
// sessions until they are swept. SweepSessions drives it.
type SessionCleaner interface {
	// Cleanup removes expired sessions and returns how many it removed.
	Cleanup() int
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

	// ClaimFirstCredential claims, for userID, the right to store the
	// account's first credential. The claim is a create-if-absent in the
	// shared store, so across sessions and replicas exactly one caller wins
	// it; every other caller gets ErrFirstCredentialClaimed and must store
	// nothing. The winner saves its credential through the claim
	// (claim.Save, never a decorated Save) and then calls Commit; if the
	// save fails it calls Release so a later attempt can claim again. Only
	// after Commit succeeds does the Service call Save under the
	// committed-first-credential marker, so a decorator's Save side effects
	// for an account's first credential run only once its claim commits. A claim
	// that is neither committed nor released (the ceremony crashed) is
	// recovered by a later claimer once its lease has expired, provided the
	// account still has no credential; if the crashed claimer had saved its
	// credential, the claim is rolled forward instead. A credential's claim
	// commits unsettled, and SettleFirstCredential settles it once the
	// decorated Save completes. A claim left unsettled by a crash (after
	// Commit, or rolled forward) is repaired by the invite resume, which
	// repeats the decorated Save, so a decorator's Save for a first
	// credential must be idempotent. The committed claim stays in place
	// while the account holds credentials; removing its last credential
	// drops it.
	ClaimFirstCredential(ctx context.Context, userID []byte) (FirstCredentialClaim, error)

	// SettleFirstCredential records that the decorated Save of userID's
	// first credential has completed, so it is never repeated. It is a
	// no-op when the account's committed claim is already settled or absent.
	SettleFirstCredential(ctx context.Context, userID []byte) error
}

// committedFirstCredentialKey is the context key withCommittedFirstCredential
// uses.
type committedFirstCredentialKey struct{}

// withCommittedFirstCredential returns ctx marking a Save of an account's
// first credential that its claim has already persisted (FirstCredentialClaim
// Save) and committed. The Service calls the configured CredentialStore.Save
// under such a ctx only after Commit succeeds, so a decorator over the store
// applies its Save side effects (a composer's auth factor) only to a
// credential the account keeps: a ceremony fenced out at Commit, or one that
// crashed before it, leaves no side effect. The underlying store, seeing the
// marker, confirms the committed record instead of persisting it again, and
// refuses with ErrFirstCredentialSettled once the claim is settled. A crash
// after Commit, or a roll-forward of a crashed claimer, leaves the claim
// unsettled: the invite resume repeats the Save under this marker to repair
// the decorator's effect, so that Save must be idempotent.
func withCommittedFirstCredential(ctx context.Context) context.Context {
	return context.WithValue(ctx, committedFirstCredentialKey{}, true)
}

// isCommittedFirstCredential reports whether ctx carries the
// withCommittedFirstCredential marker.
func isCommittedFirstCredential(ctx context.Context) bool {
	marked, _ := ctx.Value(committedFirstCredentialKey{}).(bool)
	return marked
}

// FirstCredentialClaim is a won CredentialStore.ClaimFirstCredential.
type FirstCredentialClaim interface {
	// Save persists cred, the account's first credential, bound to this
	// claim: no read returns it until Commit succeeds, so a ceremony that
	// outlived its claim and crashed before Commit leaves no usable
	// credential.
	Save(ctx context.Context, cred *Credential) error
	// Commit makes the claim permanent once cred, the account's first
	// credential, is saved. If the claim was recovered by another ceremony
	// meanwhile (this one outlived the claim's lease), Commit removes cred
	// and returns ErrFirstCredentialClaimed: only the recoverer's credential
	// stays.
	Commit(ctx context.Context, cred *Credential) error
	// Release drops the claim after a failed save. It drops only this
	// claim, never one another ceremony recovered from it.
	Release(ctx context.Context) error
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
