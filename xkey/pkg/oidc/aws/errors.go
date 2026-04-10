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

// Package aws provides AWS-specific OIDC functionality.
package aws

import "errors"

var (
	// ErrMissingRegion is returned when the AWS region is not specified.
	ErrMissingRegion = errors.New("aws: region is required")

	// ErrMissingClientID is returned when the client ID is not specified.
	ErrMissingClientID = errors.New("aws: client ID is required")

	// ErrMissingDPoPKey is returned when DPoP key is required but not provided.
	ErrMissingDPoPKey = errors.New("aws: DPoP key is required for token requests")

	// ErrTokenRequestFailed is returned when the token request fails.
	ErrTokenRequestFailed = errors.New("aws: token request failed")

	// ErrAuthorizationFailed is returned when authorization fails.
	ErrAuthorizationFailed = errors.New("aws: authorization failed")

	// ErrInvalidResponse is returned when the AWS response is invalid.
	ErrInvalidResponse = errors.New("aws: invalid response format")

	// ErrMissingCredentials is returned when credentials are missing from response.
	ErrMissingCredentials = errors.New("aws: credentials missing from response")

	// ErrDPoPNonceRequired is returned when a DPoP nonce is required.
	ErrDPoPNonceRequired = errors.New("aws: DPoP nonce required, retry with nonce")

	// ErrCredentialsExpired is returned when credentials have expired.
	ErrCredentialsExpired = errors.New("aws: credentials have expired")

	// ErrNonceRetryExhausted is returned when nonce retry attempts are exhausted.
	ErrNonceRetryExhausted = errors.New("aws: nonce retry attempts exhausted")
)
