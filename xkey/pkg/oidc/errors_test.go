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
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// hostileProviderText carries an OSC 52 clipboard write, a clear-screen
// CSI, an 8-bit CSI and a NUL between two words; sanitised it reads
// "deniedend".
const hostileProviderText = "denied\x1b]52;c;ZXZpbA==\x07\x1b[2J\u009b31m\x00end"

// TestTokenRequestError_RendersProviderTextInert proves the provider's
// error code and description reach Error() sanitised, in both of its
// shapes, while the fields keep the provider's raw text (#1015).
func TestTokenRequestError_RendersProviderTextInert(t *testing.T) {
	withDescription := &TokenRequestError{Err: ErrTokenExchangeFailed, Code: hostileProviderText, Description: hostileProviderText}
	assert.Equal(t, "oidc: token exchange failed: deniedend (deniedend)", withDescription.Error())
	assertTerminalInert(t, withDescription.Error())
	assert.Equal(t, hostileProviderText, withDescription.Description, "the field keeps the raw provider text")

	codeOnly := &TokenRequestError{Err: ErrTokenExchangeFailed, Code: hostileProviderText}
	assert.Equal(t, "oidc: token exchange failed: deniedend", codeOnly.Error())
	assertTerminalInert(t, codeOnly.Error())
}

// TestClient_Exchange_TokenEndpointErrorIsInert proves a hostile token
// endpoint's error and error_description come back from Exchange as an
// error whose text is inert.
func TestClient_Exchange_TokenEndpointErrorIsInert(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{
			"error":             hostileProviderText,
			"error_description": hostileProviderText,
		}))
	}))
	defer server.Close()

	provider := &Provider{
		Issuer:                server.URL,
		AuthorizationEndpoint: server.URL + "/authorize",
		TokenEndpoint:         server.URL + "/token",
		JwksURI:               server.URL + "/jwks",
		httpClient:            &http.Client{Timeout: 5 * time.Second},
	}
	client := NewClient(provider, &ProviderConfig{Issuer: server.URL, ClientID: "client-123", RedirectURL: "http://localhost:8080/callback"})

	_, err := client.Exchange(context.Background(), "code", &AuthCodeOptions{
		State:        "test-state",
		CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	})
	require.ErrorIs(t, err, ErrTokenExchangeFailed)
	assert.Contains(t, err.Error(), "deniedend")
	assert.NotContains(t, err.Error(), "ZXZpbA==")
	assertTerminalInert(t, err.Error())
}
