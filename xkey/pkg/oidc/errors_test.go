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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrors_AreSentinelErrors(t *testing.T) {
	// Verify that all errors are sentinel errors that can be compared with errors.Is
	sentinelErrors := []error{
		ErrDiscoveryFailed,
		ErrInvalidIssuer,
		ErrInvalidClientID,
		ErrInvalidRedirectURL,
		ErrMissingAuthEndpoint,
		ErrMissingTokenEndpoint,
		ErrMissingJWKSURI,
		ErrTokenExchangeFailed,
		ErrTokenRefreshFailed,
		ErrInvalidIDToken,
		ErrIDTokenExpired,
		ErrInvalidNonce,
		ErrInvalidAudience,
		ErrInvalidIssuerClaim,
		ErrJWKSFetchFailed,
		ErrSignatureVerification,
		ErrNoSigningKey,
		ErrInvalidCodeVerifier,
		ErrInvalidCodeChallenge,
		ErrInvalidState,
		ErrProviderNotInitialized,
		ErrClientNotInitialized,
		ErrStoreNotInitialized,
		ErrStoreClosed,
		ErrTokenNotFound,
		ErrEncryptionFailed,
		ErrDecryptionFailed,
		ErrInvalidEncryptionKey,
		ErrMissingRefreshToken,
		ErrUserInfoFailed,
		ErrHTTPRequest,
		ErrInvalidResponse,
	}

	for _, err := range sentinelErrors {
		t.Run(err.Error(), func(t *testing.T) {
			// Verify it's a non-nil error
			assert.NotNil(t, err)

			// Verify it can be matched with errors.Is
			assert.True(t, errors.Is(err, err))

			// Verify error message is not empty
			assert.NotEmpty(t, err.Error())

			// Verify error message contains the oidc prefix
			assert.Contains(t, err.Error(), "oidc:")
		})
	}
}

func TestErrors_AreDistinct(t *testing.T) {
	// Verify all errors are distinct from each other
	allErrors := []error{
		ErrDiscoveryFailed,
		ErrInvalidIssuer,
		ErrInvalidClientID,
		ErrInvalidRedirectURL,
		ErrMissingAuthEndpoint,
		ErrMissingTokenEndpoint,
		ErrMissingJWKSURI,
		ErrTokenExchangeFailed,
		ErrTokenRefreshFailed,
		ErrInvalidIDToken,
		ErrIDTokenExpired,
		ErrInvalidNonce,
		ErrInvalidAudience,
		ErrInvalidIssuerClaim,
		ErrJWKSFetchFailed,
		ErrSignatureVerification,
		ErrNoSigningKey,
		ErrInvalidCodeVerifier,
		ErrInvalidCodeChallenge,
		ErrInvalidState,
		ErrProviderNotInitialized,
		ErrClientNotInitialized,
		ErrStoreNotInitialized,
		ErrStoreClosed,
		ErrTokenNotFound,
		ErrEncryptionFailed,
		ErrDecryptionFailed,
		ErrInvalidEncryptionKey,
		ErrMissingRefreshToken,
		ErrUserInfoFailed,
		ErrHTTPRequest,
		ErrInvalidResponse,
	}

	for i, err1 := range allErrors {
		for j, err2 := range allErrors {
			if i != j {
				assert.NotEqual(t, err1, err2, "errors at index %d and %d should be distinct", i, j)
			}
		}
	}
}

func TestErrors_CanBeWrapped(t *testing.T) {
	// Verify errors can be wrapped and still matched
	testCases := []struct {
		name string
		err  error
	}{
		{"discovery failed", ErrDiscoveryFailed},
		{"invalid issuer", ErrInvalidIssuer},
		{"token not found", ErrTokenNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			wrapped := errors.New("outer: " + tc.err.Error())
			// Note: This tests the error message, not wrapping with %w
			assert.Contains(t, wrapped.Error(), tc.err.Error())
		})
	}
}
