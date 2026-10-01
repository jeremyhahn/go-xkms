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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReloginReason(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		reason string
		ok     bool
	}{
		{"invalid_grant", &TokenRequestError{Err: ErrTokenExchangeFailed, Code: "invalid_grant", StatusCode: 400}, "invalid_grant", true},
		{"reused, any case", &TokenRequestError{Err: ErrTokenExchangeFailed, Code: "Refresh_Token_Reused", StatusCode: 401}, "refresh_token_reused", true},
		{"expired", &TokenRequestError{Err: ErrTokenExchangeFailed, Code: "refresh_token_expired"}, "refresh_token_expired", true},
		{"invalidated", &TokenRequestError{Err: ErrTokenExchangeFailed, Code: "refresh_token_invalidated"}, "refresh_token_invalidated", true},
		{"401 without code", &TokenRequestError{Err: ErrTokenExchangeFailed, StatusCode: 401}, "unauthorized", true},
		{"no refresh token", ErrMissingRefreshToken, "no refresh token", true},
		{"server error is transient", &TokenRequestError{Err: ErrTokenExchangeFailed, Code: "server_error", StatusCode: 503}, "", false},
		{"rate limit is transient", &TokenRequestError{Err: ErrTokenExchangeFailed, StatusCode: 429}, "", false},
		{"network error is transient", errors.New("dial tcp: refused"), "", false},
		{"nil", nil, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reason, ok := ReloginReason(tc.err)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.reason, reason)
			assert.Equal(t, tc.ok, ReloginRequired(tc.err))
		})
	}
}

// TestRefreshNestedErrorBody proves a refresh rejected with OpenAI's nested
// error object ({"error":{"code":...,"message":...}}) is classified as a
// re-login, as codex's own TokenErrorDetail classifies it.
func TestRefreshNestedErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusUnauthorized, map[string]any{
			"error": map[string]string{"code": "refresh_token_reused", "message": "already used"},
		})
	}))
	defer srv.Close()
	client := deviceTestClient(t, srv, "", TokenEncodingJSON)

	_, err := client.Refresh(context.Background(), "rt")
	require.Error(t, err)
	var tokenErr *TokenRequestError
	require.ErrorAs(t, err, &tokenErr)
	assert.Equal(t, "refresh_token_reused", tokenErr.Code)
	assert.Equal(t, "already used", tokenErr.Description)
	assert.True(t, ReloginRequired(err))
}

func TestParseTokenErrorResponseShapes(t *testing.T) {
	flat := parseTokenErrorResponse([]byte(`{"error":"invalid_grant","error_description":"gone"}`), 400, "application/json")
	assert.Equal(t, "invalid_grant", flat.Code)
	assert.Equal(t, "gone", flat.Description)

	topLevel := parseTokenErrorResponse([]byte(`{"code":"refresh_token_expired"}`), 401, "application/json")
	assert.Equal(t, "refresh_token_expired", topLevel.Code)

	notJSON := parseTokenErrorResponse([]byte(`<html>`), 502, "text/html")
	assert.Empty(t, notJSON.Code)
	assert.Contains(t, notJSON.Description, "HTTP 502")
}
