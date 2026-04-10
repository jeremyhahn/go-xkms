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

// Package tokenstore provides a unified token store for all JWT tokens
// used by the xkey application, including OIDC login tokens, FIDO2
// authentication tokens, and bootstrap tokens. Tokens are stored as
// JSON entries keyed by normalized server URL, enabling encrypted
// storage when backed by a barrier.
package tokenstore

import (
	"context"
	"time"
)

// Token sources identify where a token was obtained.
const (
	SourceOIDC      = "oidc"
	SourceFIDO2     = "fido2"
	SourceBootstrap = "bootstrap"
)

// Token types.
const (
	TypeBearer  = "bearer"
	TypeRefresh = "refresh"
)

// TokenEntry stores a JWT with its metadata.
type TokenEntry struct {
	ServerURL string    `json:"server_url"`
	TokenType string    `json:"token_type"` // "bearer", "refresh"
	Source    string    `json:"source"`     // "oidc", "fido2", "bootstrap"
	Token     string    `json:"token"`      // The JWT
	ExpiresAt time.Time `json:"expires_at"`
	IssuedAt  time.Time `json:"issued_at"`
	Issuer    string    `json:"issuer"`  // JWT iss claim
	Subject   string    `json:"subject"` // JWT sub claim
}

// IsExpired reports whether the token has expired.
// A zero ExpiresAt is treated as never-expiring.
func (e *TokenEntry) IsExpired() bool {
	if e.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().UTC().After(e.ExpiresAt)
}

// Validate checks the entry for required fields.
func (e *TokenEntry) Validate() error {
	if e.ServerURL == "" {
		return ErrInvalidServer
	}
	if e.Token == "" {
		return ErrTokenNotFound
	}
	return nil
}

// TokenStore defines the persistence interface for JWT tokens.
type TokenStore interface {
	// Save persists a token entry keyed by its server URL.
	Save(ctx context.Context, entry *TokenEntry) error

	// Load retrieves the token entry for the given server URL.
	Load(ctx context.Context, serverURL string) (*TokenEntry, error)

	// Delete removes the token entry for the given server URL.
	Delete(ctx context.Context, serverURL string) error

	// List returns all stored token entries sorted by server URL.
	List(ctx context.Context) ([]*TokenEntry, error)

	// Close marks the store as closed. The underlying backend is
	// not closed since it may be shared.
	Close() error
}
