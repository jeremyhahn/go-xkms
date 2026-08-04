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

package auth

import (
	"context"
	"time"
)

// TokenClaims represents the claims extracted from a validated authentication token.
type TokenClaims struct {
	UserID      string    `json:"user_id"`
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	TenantID    string    `json:"tenant_id"`
	Roles       []string  `json:"roles"`
	Groups      []string  `json:"groups"`
	Permissions []string  `json:"permissions"`
	SessionID   string    `json:"session_id"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Valid       bool      `json:"valid"`
}

// Client defines the interface for authentication operations.
// Implementations delegate to external auth providers (e.g., QRDB).
type Client interface {
	ValidateToken(ctx context.Context, token string) (*TokenClaims, error)
	RefreshToken(ctx context.Context, token string) (string, error)
	RevokeToken(ctx context.Context, token string) error
}
