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

package rfc8555

import (
	"encoding/base64"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/nonce"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateNonce tests that the newNonce endpoint's underlying generator
// (pkg/acme/nonce.Service, RFC 8555 Section 7.2) produces well-formed nonces.
func TestGenerateNonce(t *testing.T) {
	svc, err := nonce.NewService()
	require.NoError(t, err)

	n, err := svc.Generate()
	require.NoError(t, err)
	assert.NotEmpty(t, n)

	// Verify it's base64url encoded
	_, decodeErr := base64.RawURLEncoding.DecodeString(n)
	assert.NoError(t, decodeErr)
}

// TestGenerateNonce_Uniqueness tests that repeated calls to newNonce return
// unique nonces.
func TestGenerateNonce_Uniqueness(t *testing.T) {
	svc, err := nonce.NewService()
	require.NoError(t, err)

	numNonces := 1000
	nonces := make(map[string]bool, numNonces)

	for i := 0; i < numNonces; i++ {
		n, err := svc.Generate()
		require.NoError(t, err)

		// Check for duplicates
		assert.False(t, nonces[n], "Duplicate nonce generated")
		nonces[n] = true
	}

	assert.Len(t, nonces, numNonces)
}

// TestGenerateNonce_Base64URLEncoding tests proper base64url encoding: RFC
// 8555 Section 7.2 requires the Replay-Nonce header value to be base64url
// without padding.
func TestGenerateNonce_Base64URLEncoding(t *testing.T) {
	svc, err := nonce.NewService()
	require.NoError(t, err)

	n, err := svc.Generate()
	require.NoError(t, err)

	// Should not contain standard base64 characters not in URL-safe variant
	assert.NotContains(t, n, "+")
	assert.NotContains(t, n, "/")
	assert.NotContains(t, n, "=") // No padding

	// Should be valid base64url
	decoded, err := base64.RawURLEncoding.DecodeString(n)
	require.NoError(t, err)
	assert.NotEmpty(t, decoded)
}

// TestGenerateNonce_FixedLength tests that every nonce pkg/acme/nonce mints
// decodes to the same length: the encrypted-counter design (12-byte GCM
// nonce + 8-byte counter + 16-byte tag) has no variable-length knob, unlike
// the random-bytes generator it replaced.
func TestGenerateNonce_FixedLength(t *testing.T) {
	svc, err := nonce.NewService()
	require.NoError(t, err)

	for i := 0; i < 4; i++ {
		n, err := svc.Generate()
		require.NoError(t, err)

		decoded, err := base64.RawURLEncoding.DecodeString(n)
		require.NoError(t, err)
		assert.Equal(t, nonce.NonceLen, len(decoded))
	}
}

// TestNonceValidation_RFC8555Compliance exercises the newNonce/badNonce
// contract end to end: a server-issued nonce validates once and is then
// consumed, and a nonce the server never issued is rejected.
func TestNonceValidation_RFC8555Compliance(t *testing.T) {
	svc, err := nonce.NewService()
	require.NoError(t, err)

	// Server must provide a fresh nonce via HEAD/GET to newNonce.
	n, err := svc.Generate()
	require.NoError(t, err)

	// Client includes the nonce in the JWS protected header; the server
	// redeems it exactly once.
	require.NoError(t, svc.Redeem(n))

	// Nonce must be consumed after successful validation.
	assert.Error(t, svc.Redeem(n))

	// Server must reject a nonce it never issued.
	assert.Error(t, svc.Redeem("never-issued-nonce"))
}
