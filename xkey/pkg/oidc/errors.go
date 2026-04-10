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

// Package oidc provides OpenID Connect client functionality for authentication.
package oidc

import (
	"errors"
	"fmt"
)

// TokenRequestError provides detailed error information from a failed token request.
// It wraps a sentinel error with the provider's OAuth2 error code and description
// so callers can still use errors.Is() while accessing provider-specific details.
type TokenRequestError struct {
	// Err is the wrapped sentinel error (e.g., ErrTokenExchangeFailed).
	Err error

	// Code is the OAuth2 error code from the provider (e.g., "invalid_grant").
	Code string

	// Description is the human-readable error description from the provider.
	Description string

	// StatusCode is the HTTP status code from the token endpoint.
	StatusCode int
}

// Error returns a formatted error string including provider details when available.
func (e *TokenRequestError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Err.Error(), e.Description, e.Code)
	}
	if e.Code != "" {
		return fmt.Sprintf("%s: %s", e.Err.Error(), e.Code)
	}
	return e.Err.Error()
}

// Unwrap returns the underlying sentinel error for use with errors.Is().
func (e *TokenRequestError) Unwrap() error {
	return e.Err
}

var (
	// ErrDiscoveryFailed is returned when OIDC discovery fails to retrieve provider metadata.
	ErrDiscoveryFailed = errors.New("oidc: discovery failed")

	// ErrInvalidIssuer is returned when the issuer URL is invalid or empty.
	ErrInvalidIssuer = errors.New("oidc: invalid issuer URL")

	// ErrInvalidClientID is returned when the client ID is empty.
	ErrInvalidClientID = errors.New("oidc: invalid client ID")

	// ErrInvalidRedirectURL is returned when the redirect URL is empty or invalid.
	ErrInvalidRedirectURL = errors.New("oidc: invalid redirect URL")

	// ErrMissingAuthEndpoint is returned when the authorization endpoint is not configured.
	ErrMissingAuthEndpoint = errors.New("oidc: missing authorization endpoint")

	// ErrMissingTokenEndpoint is returned when the token endpoint is not configured.
	ErrMissingTokenEndpoint = errors.New("oidc: missing token endpoint")

	// ErrMissingJWKSURI is returned when the JWKS URI is not configured.
	ErrMissingJWKSURI = errors.New("oidc: missing JWKS URI")

	// ErrTokenExchangeFailed is returned when the authorization code exchange fails.
	ErrTokenExchangeFailed = errors.New("oidc: token exchange failed")

	// ErrTokenRefreshFailed is returned when token refresh fails.
	ErrTokenRefreshFailed = errors.New("oidc: token refresh failed")

	// ErrInvalidIDToken is returned when the ID token is invalid or malformed.
	ErrInvalidIDToken = errors.New("oidc: invalid ID token")

	// ErrIDTokenExpired is returned when the ID token has expired.
	ErrIDTokenExpired = errors.New("oidc: ID token expired")

	// ErrInvalidNonce is returned when the nonce in the ID token doesn't match.
	ErrInvalidNonce = errors.New("oidc: nonce mismatch")

	// ErrInvalidAudience is returned when the audience claim doesn't match the client ID.
	ErrInvalidAudience = errors.New("oidc: audience mismatch")

	// ErrInvalidIssuerClaim is returned when the issuer claim doesn't match the provider.
	ErrInvalidIssuerClaim = errors.New("oidc: issuer claim mismatch")

	// ErrJWKSFetchFailed is returned when fetching the JWKS fails.
	ErrJWKSFetchFailed = errors.New("oidc: failed to fetch JWKS")

	// ErrSignatureVerification is returned when ID token signature verification fails.
	ErrSignatureVerification = errors.New("oidc: signature verification failed")

	// ErrNoSigningKey is returned when no suitable signing key is found in JWKS.
	ErrNoSigningKey = errors.New("oidc: no suitable signing key found")

	// ErrInvalidCodeVerifier is returned when the PKCE code verifier is invalid.
	ErrInvalidCodeVerifier = errors.New("oidc: invalid code verifier")

	// ErrInvalidCodeChallenge is returned when the PKCE code challenge is invalid.
	ErrInvalidCodeChallenge = errors.New("oidc: invalid code challenge")

	// ErrInvalidState is returned when the state parameter is invalid or missing.
	ErrInvalidState = errors.New("oidc: invalid state parameter")

	// ErrProviderNotInitialized is returned when operations are attempted on an uninitialized provider.
	ErrProviderNotInitialized = errors.New("oidc: provider not initialized")

	// ErrClientNotInitialized is returned when operations are attempted on an uninitialized client.
	ErrClientNotInitialized = errors.New("oidc: client not initialized")

	// ErrStoreNotInitialized is returned when the token store is not initialized.
	ErrStoreNotInitialized = errors.New("oidc: store not initialized")

	// ErrStoreClosed is returned when operations are attempted on a closed store.
	ErrStoreClosed = errors.New("oidc: store is closed")

	// ErrTokenNotFound is returned when a token is not found in the store.
	ErrTokenNotFound = errors.New("oidc: token not found")

	// ErrEncryptionFailed is returned when token encryption fails.
	ErrEncryptionFailed = errors.New("oidc: encryption failed")

	// ErrDecryptionFailed is returned when token decryption fails.
	ErrDecryptionFailed = errors.New("oidc: decryption failed")

	// ErrInvalidEncryptionKey is returned when the encryption key is invalid.
	ErrInvalidEncryptionKey = errors.New("oidc: invalid encryption key")

	// ErrMissingRefreshToken is returned when a refresh token is required but not present.
	ErrMissingRefreshToken = errors.New("oidc: missing refresh token")

	// ErrUserInfoFailed is returned when fetching user info fails.
	ErrUserInfoFailed = errors.New("oidc: failed to fetch user info")

	// ErrHTTPRequest is returned when an HTTP request fails.
	ErrHTTPRequest = errors.New("oidc: HTTP request failed")

	// ErrInvalidResponse is returned when a response from the provider is invalid.
	ErrInvalidResponse = errors.New("oidc: invalid response from provider")

	// ErrDPoPKeyGeneration is returned when DPoP key generation fails.
	ErrDPoPKeyGeneration = errors.New("oidc: DPoP key generation failed")

	// ErrDPoPInvalidProof is returned when a DPoP proof is invalid.
	ErrDPoPInvalidProof = errors.New("oidc: invalid DPoP proof")

	// ErrDPoPNonceRequired is returned when a DPoP nonce is required but not provided.
	ErrDPoPNonceRequired = errors.New("oidc: DPoP nonce required")

	// ErrTemplateNotFound is returned when a provider template is not found.
	ErrTemplateNotFound = errors.New("oidc: provider template not found")

	// ErrAWSResponseParseFailed is returned when parsing AWS token response fails.
	ErrAWSResponseParseFailed = errors.New("oidc: failed to parse AWS response")

	// ErrAWSCredentialsWriteFailed is returned when writing AWS credentials fails.
	ErrAWSCredentialsWriteFailed = errors.New("oidc: failed to write AWS credentials")
)
