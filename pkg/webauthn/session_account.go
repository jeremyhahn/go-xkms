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
	"encoding/base64"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// SessionAccount names the WebAuthn account an authenticated API session
// belongs to: the account BeginAddCredential adds a passkey to.
type SessionAccount struct {
	// UserID is the account's WebAuthn user handle.
	UserID []byte

	// Email is the account's email login key.
	Email string

	// TenantID is the tenant the session was minted in. It must be the
	// tenant the user store serves.
	TenantID string
}

// tenantScoped is implemented by a UserStore that serves exactly one tenant.
type tenantScoped interface {
	TenantID() string
}

// SessionAccountFromIdentity maps an authenticated identity onto the WebAuthn
// account it names. It is the inverse of the mapping the WebAuthn token
// adapter applies when a ceremony mints a session (pkg/api/rest
// WebAuthnTokenAdapter): the subject is the base64url user handle and the
// "email" metadata is the login key. It fails with ErrSessionAccountMismatch
// for a nil identity or one that carries neither; BeginAddCredential then
// verifies that both name the same existing account.
func SessionAccountFromIdentity(id *auth.Identity) (SessionAccount, error) {
	if id == nil || id.Subject == "" {
		return SessionAccount{}, ErrSessionAccountMismatch
	}
	// The subject kind is declared, never guessed: only a WebAuthn login
	// mints a subject that is a user handle. A username subject (mTLS, PIV,
	// certificate login) can be chosen to decode to another account's handle.
	if id.Metadata[auth.SubjectKindMetadataKey] != auth.SubjectKindUserHandle {
		return SessionAccount{}, ErrSessionAccountMismatch
	}
	handle, err := base64.RawURLEncoding.DecodeString(id.Subject)
	if err != nil || len(handle) == 0 {
		return SessionAccount{}, ErrSessionAccountMismatch
	}
	email := id.Metadata["email"]
	if email == "" {
		return SessionAccount{}, ErrSessionAccountMismatch
	}
	return SessionAccount{UserID: handle, Email: email, TenantID: id.TenantID}, nil
}
