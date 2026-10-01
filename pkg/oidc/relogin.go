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
	"net/http"
	"strings"
)

// reloginCodes are the token-endpoint error codes that mean the refresh
// token is dead: retrying the same request can never succeed, and only a new
// login (or an imported login) brings the credential back.
//
// invalid_grant is RFC 6749's code for an expired, revoked or reused grant.
// The refresh_token_* codes are what OpenAI's auth service answers when a
// rotating refresh token has expired, was already used, or was invalidated
// (openai/codex codex-rs/login/src/auth/manager.rs,
// classify_refresh_token_failure).
var reloginCodes = map[string]bool{
	"invalid_grant":             true,
	"refresh_token_expired":     true,
	"refresh_token_reused":      true,
	"refresh_token_invalidated": true,
}

// ReloginReason returns the provider's reason when err means the credential
// needs a new login, and ok=false for a failure a retry may fix (a network
// error, a 5xx, a rate limit).
//
// A refresh needs a new login when the provider rejected the refresh token
// (one of the reloginCodes, or HTTP 401), or when there is no refresh token
// to present at all.
func ReloginReason(err error) (reason string, ok bool) {
	if errors.Is(err, ErrMissingRefreshToken) {
		return "no refresh token", true
	}
	var tokenErr *TokenRequestError
	if !errors.As(err, &tokenErr) {
		return "", false
	}
	code := strings.ToLower(tokenErr.Code)
	if reloginCodes[code] {
		return code, true
	}
	if tokenErr.StatusCode == http.StatusUnauthorized {
		if code == "" {
			code = "unauthorized"
		}
		return code, true
	}
	return "", false
}

// ReloginRequired reports whether err means the credential needs a new
// login. See ReloginReason.
func ReloginRequired(err error) bool {
	_, ok := ReloginReason(err)
	return ok
}
