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
	SourcePIV       = "piv"
)

// Token types.
const (
	TypeBearer  = "bearer"
	TypeRefresh = "refresh"
)

// TokenEntry stores a JWT with its metadata.
type TokenEntry struct {
	ServerURL string `json:"server_url"`
	TokenType string `json:"token_type"` // "bearer", "refresh"
	Source    string `json:"source"`     // "oidc", "fido2", "bootstrap", "piv"
	Token     string `json:"token"`      // The JWT (bearer/access token)
	// RefreshToken rotates the pair at xkmsd's session login-plane
	// (POST /api/v1/auth/refresh). Empty when the issuing ceremony did not
	// mint a refresh token (e.g. the WebAuthn Servicer-plane ceremony).
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	IssuedAt     time.Time `json:"issued_at"`
	Issuer       string    `json:"issuer"`  // JWT iss claim
	Subject      string    `json:"subject"` // JWT sub claim

	// ServerID is the identity of the server the login authenticated to:
	// qrdb's SPKI SHA-256 thumbprint of the TLS leaf certificate it
	// presented. A server presents that certificate on every TLS transport,
	// so one login serves REST, gRPC, QUIC and MCP alike; a different
	// certificate is a different server, whatever its host.
	ServerID string `json:"server_id,omitempty"`

	// ServerName is the host name the login reached. It selects the login
	// on a transport without TLS (a Unix socket), where no certificate
	// identifies the server and the configured xkmsd server name does.
	ServerName string `json:"server_name,omitempty"`
}

// HasRefreshToken reports whether the entry carries a refresh token, i.e.
// whether it was issued by the session login-plane (PIV login, refresh)
// rather than the Servicer-plane WebAuthn ceremony.
func (e *TokenEntry) HasRefreshToken() bool {
	return e.RefreshToken != ""
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
