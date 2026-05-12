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
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Compile-time interface check.
var _ Client = (*MemoryClient)(nil)

// defaultTokenRefreshDuration is the default duration added when refreshing a token.
const defaultTokenRefreshDuration = 1 * time.Hour

// MemoryClient is an in-memory auth client suitable for unit testing.
// It uses sync.Map for lock-free concurrent access.
type MemoryClient struct {
	tokens sync.Map // map[string]*TokenClaims
}

// NewMemoryClient creates a new MemoryClient.
func NewMemoryClient() *MemoryClient {
	return &MemoryClient{}
}

// AddToken stores a token and its claims in the in-memory store.
func (c *MemoryClient) AddToken(token string, claims *TokenClaims) {
	c.tokens.Store(token, claims)
}

// RemoveToken removes a token from the in-memory store.
func (c *MemoryClient) RemoveToken(token string) {
	c.tokens.Delete(token)
}

// ValidateToken looks up the token, checks expiry, and returns the claims.
func (c *MemoryClient) ValidateToken(_ context.Context, token string) (*TokenClaims, error) {
	if token == "" {
		return nil, &InvalidTokenError{Reason: "empty token"}
	}

	val, ok := c.tokens.Load(token)
	if !ok {
		return nil, &InvalidTokenError{Reason: "token not found"}
	}

	claims, ok := val.(*TokenClaims)
	if !ok {
		return nil, &InvalidTokenError{Reason: "corrupted token data"}
	}

	if !claims.ExpiresAt.IsZero() && time.Now().After(claims.ExpiresAt) {
		return nil, &TokenExpiredError{ExpiredAt: claims.ExpiresAt}
	}

	return claims, nil
}

// RefreshToken generates a new token string, copies the claims with an
// extended expiry, stores the new token, and removes the old one.
func (c *MemoryClient) RefreshToken(_ context.Context, token string) (string, error) {
	if token == "" {
		return "", &InvalidTokenError{Reason: "empty token"}
	}

	val, ok := c.tokens.Load(token)
	if !ok {
		return "", &InvalidTokenError{Reason: "token not found"}
	}

	claims, ok := val.(*TokenClaims)
	if !ok {
		return "", &InvalidTokenError{Reason: "corrupted token data"}
	}

	newToken, err := generateToken()
	if err != nil {
		return "", &AuthServiceError{Message: "failed to generate token", Cause: err}
	}

	now := time.Now()
	refreshed := &TokenClaims{
		UserID:      claims.UserID,
		Username:    claims.Username,
		Email:       claims.Email,
		TenantID:    claims.TenantID,
		Roles:       claims.Roles,
		Groups:      claims.Groups,
		Permissions: claims.Permissions,
		SessionID:   claims.SessionID,
		IssuedAt:    now,
		ExpiresAt:   now.Add(defaultTokenRefreshDuration),
		Valid:       true,
	}

	c.tokens.Store(newToken, refreshed)
	c.tokens.Delete(token)

	return newToken, nil
}

// RevokeToken removes the token from the in-memory store.
func (c *MemoryClient) RevokeToken(_ context.Context, token string) error {
	if token == "" {
		return &InvalidTokenError{Reason: "empty token"}
	}

	_, ok := c.tokens.Load(token)
	if !ok {
		return &InvalidTokenError{Reason: "token not found"}
	}

	c.tokens.Delete(token)
	return nil
}

// generateToken produces a cryptographically random hex-encoded token string.
func generateToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
