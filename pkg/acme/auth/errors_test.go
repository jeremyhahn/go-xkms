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
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestInvalidTokenError(t *testing.T) {
	err := &InvalidTokenError{Reason: "malformed header"}
	assert.Equal(t, "invalid token: malformed header", err.Error())
	assert.True(t, IsInvalidToken(err))
	assert.False(t, IsTokenExpired(err))
	assert.False(t, IsTokenRevoked(err))
}

func TestInvalidTokenErrorEmptyReason(t *testing.T) {
	err := &InvalidTokenError{}
	assert.Equal(t, "invalid token: ", err.Error())
	assert.True(t, IsInvalidToken(err))
}

func TestTokenExpiredError(t *testing.T) {
	expiry := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	err := &TokenExpiredError{ExpiredAt: expiry}
	assert.Equal(t, "token expired at 2025-06-15T12:00:00Z", err.Error())
	assert.True(t, IsTokenExpired(err))
	assert.False(t, IsInvalidToken(err))
	assert.False(t, IsTokenRevoked(err))
}

func TestTokenExpiredErrorZeroTime(t *testing.T) {
	err := &TokenExpiredError{}
	assert.Contains(t, err.Error(), "token expired at")
	assert.True(t, IsTokenExpired(err))
}

func TestTokenRevokedError(t *testing.T) {
	err := &TokenRevokedError{TokenID: "tok-abc-123"}
	assert.Equal(t, "token revoked: tok-abc-123", err.Error())
	assert.True(t, IsTokenRevoked(err))
	assert.False(t, IsInvalidToken(err))
	assert.False(t, IsTokenExpired(err))
}

func TestTokenRevokedErrorEmptyTokenID(t *testing.T) {
	err := &TokenRevokedError{}
	assert.Equal(t, "token revoked: ", err.Error())
	assert.True(t, IsTokenRevoked(err))
}

func TestAuthServiceError(t *testing.T) {
	cause := errors.New("connection refused")
	err := &AuthServiceError{Message: "failed to connect", Cause: cause}
	assert.Equal(t, "auth service error: failed to connect: connection refused", err.Error())
	assert.False(t, IsInvalidToken(err))
	assert.False(t, IsTokenExpired(err))
	assert.False(t, IsTokenRevoked(err))
}

func TestAuthServiceErrorNoCause(t *testing.T) {
	err := &AuthServiceError{Message: "service unavailable"}
	assert.Equal(t, "auth service error: service unavailable", err.Error())
}

func TestAuthServiceErrorUnwrap(t *testing.T) {
	cause := errors.New("timeout")
	err := &AuthServiceError{Message: "request failed", Cause: cause}
	assert.True(t, errors.Is(err, cause))
	assert.Equal(t, cause, errors.Unwrap(err))
}

func TestAuthServiceErrorUnwrapNil(t *testing.T) {
	err := &AuthServiceError{Message: "no cause"}
	assert.Nil(t, errors.Unwrap(err))
}

func TestIsHelperFunctionsWithNonAuthErrors(t *testing.T) {
	err := errors.New("generic error")
	assert.False(t, IsInvalidToken(err))
	assert.False(t, IsTokenExpired(err))
	assert.False(t, IsTokenRevoked(err))
}

func TestErrorsImplementErrorInterface(t *testing.T) {
	var _ error = (*InvalidTokenError)(nil)
	var _ error = (*TokenExpiredError)(nil)
	var _ error = (*TokenRevokedError)(nil)
	var _ error = (*AuthServiceError)(nil)
}
