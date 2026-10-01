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

package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCodeVerifier(t *testing.T) {
	t.Run("generates valid verifier", func(t *testing.T) {
		verifier, err := GenerateCodeVerifier()
		require.NoError(t, err)
		assert.NotEmpty(t, verifier)

		// Should be 43 characters (32 bytes base64url encoded without padding)
		assert.Equal(t, 43, len(verifier))
	})

	t.Run("generates unique verifiers", func(t *testing.T) {
		verifiers := make(map[string]bool)
		for i := 0; i < 100; i++ {
			verifier, err := GenerateCodeVerifier()
			require.NoError(t, err)
			assert.False(t, verifiers[verifier], "duplicate verifier generated")
			verifiers[verifier] = true
		}
	})

	t.Run("verifier is URL-safe base64", func(t *testing.T) {
		verifier, err := GenerateCodeVerifier()
		require.NoError(t, err)

		// Should be decodable as base64url
		decoded, err := base64.RawURLEncoding.DecodeString(verifier)
		require.NoError(t, err)
		assert.Equal(t, 32, len(decoded))
	})
}

func TestGenerateCodeChallenge(t *testing.T) {
	t.Run("generates valid challenge from verifier", func(t *testing.T) {
		verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		challenge := GenerateCodeChallenge(verifier)

		// Calculate expected challenge
		hash := sha256.Sum256([]byte(verifier))
		expected := base64.RawURLEncoding.EncodeToString(hash[:])

		assert.Equal(t, expected, challenge)
	})

	t.Run("challenge is 43 characters", func(t *testing.T) {
		verifier, err := GenerateCodeVerifier()
		require.NoError(t, err)

		challenge := GenerateCodeChallenge(verifier)
		// SHA256 = 32 bytes, base64url encoded = 43 characters
		assert.Equal(t, 43, len(challenge))
	})

	t.Run("same verifier produces same challenge", func(t *testing.T) {
		verifier := "test-verifier-12345"
		challenge1 := GenerateCodeChallenge(verifier)
		challenge2 := GenerateCodeChallenge(verifier)
		assert.Equal(t, challenge1, challenge2)
	})

	t.Run("different verifiers produce different challenges", func(t *testing.T) {
		verifier1, err := GenerateCodeVerifier()
		require.NoError(t, err)
		verifier2, err := GenerateCodeVerifier()
		require.NoError(t, err)

		challenge1 := GenerateCodeChallenge(verifier1)
		challenge2 := GenerateCodeChallenge(verifier2)
		assert.NotEqual(t, challenge1, challenge2)
	})

	t.Run("handles empty verifier", func(t *testing.T) {
		challenge := GenerateCodeChallenge("")
		assert.NotEmpty(t, challenge)
		// SHA256 of empty string is known
		hash := sha256.Sum256([]byte(""))
		expected := base64.RawURLEncoding.EncodeToString(hash[:])
		assert.Equal(t, expected, challenge)
	})
}

func TestGenerateState(t *testing.T) {
	t.Run("generates valid state", func(t *testing.T) {
		state, err := GenerateState()
		require.NoError(t, err)
		assert.NotEmpty(t, state)

		// Should be 43 characters (32 bytes base64url encoded without padding)
		assert.Equal(t, 43, len(state))
	})

	t.Run("generates unique states", func(t *testing.T) {
		states := make(map[string]bool)
		for i := 0; i < 100; i++ {
			state, err := GenerateState()
			require.NoError(t, err)
			assert.False(t, states[state], "duplicate state generated")
			states[state] = true
		}
	})

	t.Run("state is URL-safe base64", func(t *testing.T) {
		state, err := GenerateState()
		require.NoError(t, err)

		// Should be decodable as base64url
		decoded, err := base64.RawURLEncoding.DecodeString(state)
		require.NoError(t, err)
		assert.Equal(t, 32, len(decoded))
	})
}

func TestGenerateNonce(t *testing.T) {
	t.Run("generates valid nonce", func(t *testing.T) {
		nonce, err := GenerateNonce()
		require.NoError(t, err)
		assert.NotEmpty(t, nonce)

		// Should be 43 characters (32 bytes base64url encoded without padding)
		assert.Equal(t, 43, len(nonce))
	})

	t.Run("generates unique nonces", func(t *testing.T) {
		nonces := make(map[string]bool)
		for i := 0; i < 100; i++ {
			nonce, err := GenerateNonce()
			require.NoError(t, err)
			assert.False(t, nonces[nonce], "duplicate nonce generated")
			nonces[nonce] = true
		}
	})

	t.Run("nonce is URL-safe base64", func(t *testing.T) {
		nonce, err := GenerateNonce()
		require.NoError(t, err)

		// Should be decodable as base64url
		decoded, err := base64.RawURLEncoding.DecodeString(nonce)
		require.NoError(t, err)
		assert.Equal(t, 32, len(decoded))
	})
}

func TestValidateCodeVerifier(t *testing.T) {
	t.Run("accepts valid verifier length", func(t *testing.T) {
		// 43 characters (minimum)
		verifier43 := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		err := ValidateCodeVerifier(verifier43)
		assert.NoError(t, err)

		// 128 characters (maximum)
		verifier128 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
		err = ValidateCodeVerifier(verifier128)
		assert.NoError(t, err)
	})

	t.Run("rejects too short verifier", func(t *testing.T) {
		verifier := "too-short"
		err := ValidateCodeVerifier(verifier)
		assert.ErrorIs(t, err, ErrInvalidCodeVerifier)

		// 42 characters (one less than minimum)
		verifier42 := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX"
		err = ValidateCodeVerifier(verifier42)
		assert.ErrorIs(t, err, ErrInvalidCodeVerifier)
	})

	t.Run("rejects too long verifier", func(t *testing.T) {
		// 129 characters (one more than maximum)
		verifier129 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa12"
		err := ValidateCodeVerifier(verifier129)
		assert.ErrorIs(t, err, ErrInvalidCodeVerifier)
	})

	t.Run("rejects empty verifier", func(t *testing.T) {
		err := ValidateCodeVerifier("")
		assert.ErrorIs(t, err, ErrInvalidCodeVerifier)
	})
}

func TestValidateState(t *testing.T) {
	t.Run("accepts non-empty state", func(t *testing.T) {
		err := ValidateState("valid-state-parameter")
		assert.NoError(t, err)
	})

	t.Run("rejects empty state", func(t *testing.T) {
		err := ValidateState("")
		assert.ErrorIs(t, err, ErrInvalidState)
	})
}

func TestGeneratePKCEParams(t *testing.T) {
	t.Run("generates valid PKCE params", func(t *testing.T) {
		params, err := GeneratePKCEParams()
		require.NoError(t, err)
		assert.NotNil(t, params)
		assert.NotEmpty(t, params.CodeVerifier)
		assert.NotEmpty(t, params.CodeChallenge)

		// Verify challenge matches verifier
		expectedChallenge := GenerateCodeChallenge(params.CodeVerifier)
		assert.Equal(t, expectedChallenge, params.CodeChallenge)
	})

	t.Run("verifier is valid", func(t *testing.T) {
		params, err := GeneratePKCEParams()
		require.NoError(t, err)

		err = ValidateCodeVerifier(params.CodeVerifier)
		assert.NoError(t, err)
	})

	t.Run("generates unique params", func(t *testing.T) {
		params1, err := GeneratePKCEParams()
		require.NoError(t, err)
		params2, err := GeneratePKCEParams()
		require.NoError(t, err)

		assert.NotEqual(t, params1.CodeVerifier, params2.CodeVerifier)
		assert.NotEqual(t, params1.CodeChallenge, params2.CodeChallenge)
	})
}

func TestPKCE_RFC7636Compliance(t *testing.T) {
	// Test vectors from RFC 7636 Appendix B
	// Note: The RFC uses a specific verifier for its example
	t.Run("S256 method produces correct challenge", func(t *testing.T) {
		// Using a known verifier to test S256 transformation
		verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		challenge := GenerateCodeChallenge(verifier)

		// Verify the challenge is properly computed
		hash := sha256.Sum256([]byte(verifier))
		expected := base64.RawURLEncoding.EncodeToString(hash[:])
		assert.Equal(t, expected, challenge)
	})
}
