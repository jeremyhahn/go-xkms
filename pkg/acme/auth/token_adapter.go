// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package auth

import (
	"context"
)

// Compile-time interface check.
var _ Client = (*TokenAdapter)(nil)

// ValidateFunc is a function type for validating tokens.
type ValidateFunc func(ctx context.Context, token string) (*TokenClaims, error)

// RefreshFunc is a function type for refreshing tokens.
type RefreshFunc func(ctx context.Context, token string) (string, error)

// RevokeFunc is a function type for revoking tokens.
type RevokeFunc func(ctx context.Context, token string) error

// TokenAdapter delegates authentication operations to external auth provider
// functions injected via functional options.
type TokenAdapter struct {
	validateFn ValidateFunc
	refreshFn  RefreshFunc
	revokeFn   RevokeFunc
}

// TokenAdapterOption configures a TokenAdapter.
type TokenAdapterOption func(*TokenAdapter)

// WithValidateFunc sets the token validation function.
func WithValidateFunc(fn ValidateFunc) TokenAdapterOption {
	return func(a *TokenAdapter) {
		a.validateFn = fn
	}
}

// WithRefreshFunc sets the token refresh function.
func WithRefreshFunc(fn RefreshFunc) TokenAdapterOption {
	return func(a *TokenAdapter) {
		a.refreshFn = fn
	}
}

// WithRevokeFunc sets the token revocation function.
func WithRevokeFunc(fn RevokeFunc) TokenAdapterOption {
	return func(a *TokenAdapter) {
		a.revokeFn = fn
	}
}

// NewTokenAdapter creates a new TokenAdapter with the given options.
func NewTokenAdapter(opts ...TokenAdapterOption) *TokenAdapter {
	adapter := &TokenAdapter{}
	for _, opt := range opts {
		opt(adapter)
	}
	return adapter
}

// ValidateToken validates the given token using the injected validation function.
func (a *TokenAdapter) ValidateToken(ctx context.Context, token string) (*TokenClaims, error) {
	if a.validateFn == nil {
		return nil, &AuthServiceError{Message: "validate function not configured"}
	}
	return a.validateFn(ctx, token)
}

// RefreshToken refreshes the given token using the injected refresh function.
func (a *TokenAdapter) RefreshToken(ctx context.Context, token string) (string, error) {
	if a.refreshFn == nil {
		return "", &AuthServiceError{Message: "refresh function not configured"}
	}
	return a.refreshFn(ctx, token)
}

// RevokeToken revokes the given token using the injected revoke function.
func (a *TokenAdapter) RevokeToken(ctx context.Context, token string) error {
	if a.revokeFn == nil {
		return &AuthServiceError{Message: "revoke function not configured"}
	}
	return a.revokeFn(ctx, token)
}
