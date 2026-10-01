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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

const (
	// PKCECodeVerifierLength is the length of the code verifier in bytes.
	// RFC 7636 recommends 32-96 bytes, we use 32 bytes (256 bits).
	PKCECodeVerifierLength = 32

	// StateLength is the length of the state parameter in bytes.
	StateLength = 32

	// NonceLength is the length of the nonce parameter in bytes.
	NonceLength = 32
)

// GenerateCodeVerifier generates a cryptographically random PKCE code verifier.
// The verifier is URL-safe base64 encoded with no padding, as per RFC 7636.
// Returns a string of 43 characters (32 bytes encoded).
func GenerateCodeVerifier() (string, error) {
	bytes := make([]byte, PKCECodeVerifierLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// GenerateCodeChallenge generates a PKCE code challenge from a verifier.
// Uses the S256 method (SHA-256 hash) as recommended by RFC 7636.
// The challenge is URL-safe base64 encoded with no padding.
func GenerateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// GenerateState generates a cryptographically random state parameter.
// The state is used to prevent CSRF attacks in the OAuth2 flow.
// Returns a URL-safe base64 encoded string.
func GenerateState() (string, error) {
	bytes := make([]byte, StateLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// GenerateNonce generates a cryptographically random nonce for the ID token.
// The nonce is used to associate a client session with an ID token
// and to mitigate replay attacks.
// Returns a URL-safe base64 encoded string.
func GenerateNonce() (string, error) {
	bytes := make([]byte, NonceLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// ValidateCodeVerifier validates that a code verifier meets RFC 7636 requirements.
// The verifier must be between 43 and 128 characters (inclusive).
func ValidateCodeVerifier(verifier string) error {
	length := len(verifier)
	if length < 43 || length > 128 {
		return ErrInvalidCodeVerifier
	}
	return nil
}

// ValidateState validates that a state parameter is present and non-empty.
func ValidateState(state string) error {
	if state == "" {
		return ErrInvalidState
	}
	return nil
}

// PKCEParams holds PKCE parameters for an authorization request.
type PKCEParams struct {
	CodeVerifier  string
	CodeChallenge string
}

// GeneratePKCEParams generates both the code verifier and code challenge.
// This is a convenience function for generating PKCE parameters in one call.
func GeneratePKCEParams() (*PKCEParams, error) {
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		return nil, err
	}
	return &PKCEParams{
		CodeVerifier:  verifier,
		CodeChallenge: GenerateCodeChallenge(verifier),
	}, nil
}
