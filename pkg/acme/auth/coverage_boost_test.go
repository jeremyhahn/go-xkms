//go:build codec_json

package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCoverageBoost_ValidateToken_CorruptedTokenData tests the corrupted token data
// path in ValidateToken where the sync.Map contains a non-*TokenClaims value.
func TestCoverageBoost_ValidateToken_CorruptedTokenData(t *testing.T) {
	client := NewMemoryClient()

	// Store a non-*TokenClaims value directly in the sync.Map
	client.tokens.Store("corrupted-token", "this is not a *TokenClaims")

	ctx := context.Background()
	result, err := client.ValidateToken(ctx, "corrupted-token")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, IsInvalidToken(err))
	assert.Contains(t, err.Error(), "corrupted token data")
}

// TestCoverageBoost_ValidateToken_CorruptedTokenDataInt tests with an integer
// stored instead of *TokenClaims.
func TestCoverageBoost_ValidateToken_CorruptedTokenDataInt(t *testing.T) {
	client := NewMemoryClient()

	client.tokens.Store("corrupted-int", 42)

	ctx := context.Background()
	result, err := client.ValidateToken(ctx, "corrupted-int")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, IsInvalidToken(err))
	assert.Contains(t, err.Error(), "corrupted token data")
}

// TestCoverageBoost_RefreshToken_CorruptedTokenData tests the corrupted token data
// path in RefreshToken where the sync.Map contains a non-*TokenClaims value.
func TestCoverageBoost_RefreshToken_CorruptedTokenData(t *testing.T) {
	client := NewMemoryClient()

	// Store a non-*TokenClaims value directly in the sync.Map
	client.tokens.Store("corrupted-token", struct{ Name string }{Name: "bad"})

	ctx := context.Background()
	newToken, err := client.RefreshToken(ctx, "corrupted-token")
	assert.Empty(t, newToken)
	require.Error(t, err)
	assert.True(t, IsInvalidToken(err))
	assert.Contains(t, err.Error(), "corrupted token data")
}

// TestCoverageBoost_RefreshToken_CorruptedTokenDataNil tests RefreshToken with
// a nil value stored in the sync.Map.
func TestCoverageBoost_RefreshToken_CorruptedTokenDataNil(t *testing.T) {
	client := NewMemoryClient()

	// Store nil (not *TokenClaims(nil)) in the sync.Map
	client.tokens.Store("nil-token", (*int)(nil))

	ctx := context.Background()
	newToken, err := client.RefreshToken(ctx, "nil-token")
	assert.Empty(t, newToken)
	require.Error(t, err)
	assert.True(t, IsInvalidToken(err))
	assert.Contains(t, err.Error(), "corrupted token data")
}
