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

package xkms

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCodexAuthFile proves the projection a workload's codex reads: the
// host-owned chatgptAuthTokens mode, the served tokens, no refresh token,
// and the account from the ID token -- read back by the importer.
func TestCodexAuthFile(t *testing.T) {
	enc := base64.RawURLEncoding
	idToken := enc.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
		enc.EncodeToString([]byte(`{"https://api.openai.com/auth":{"chatgpt_account_id":"acct-1"}}`)) + ".sig"
	exp := time.Now().Add(time.Hour)
	data, err := CodexAuthFile(&OIDCAccessToken{AccessToken: "at", IDToken: idToken, ExpiresAt: &exp}, time.Now())
	require.NoError(t, err)

	auth, err := ParseCodexAuth(data)
	require.NoError(t, err)
	assert.Equal(t, "chatgptAuthTokens", auth.Mode)
	assert.Equal(t, "at", auth.Tokens.AccessToken)
	assert.Empty(t, auth.Tokens.RefreshToken)
	assert.Equal(t, "acct-1", auth.AccountID)
}

func TestCodexAuthFile_Refusals(t *testing.T) {
	_, err := CodexAuthFile(nil, time.Now())
	assert.Error(t, err)
	_, err = CodexAuthFile(&OIDCAccessToken{AccessToken: "at"}, time.Now())
	assert.Error(t, err, "codex needs the ID token")
}

func TestCodexAuthTokens(t *testing.T) {
	assert.Nil(t, CodexAuthTokens(nil))
	assert.Nil(t, CodexAuthTokens(&CodexAuth{}))

	enc := base64.RawURLEncoding
	access := enc.EncodeToString([]byte(`{"alg":"none"}`)) + "." + enc.EncodeToString([]byte(`{"exp":4102444800}`)) + ".sig"
	auth, err := ParseCodexAuth([]byte(`{"tokens":{"id_token":"i","access_token":"` + access + `","refresh_token":"r"}}`))
	require.NoError(t, err)
	tokens := CodexAuthTokens(auth)
	require.NotNil(t, tokens)
	assert.Equal(t, "r", tokens.RefreshToken)
	require.NotNil(t, tokens.ExpiresAt)
	assert.Equal(t, int64(4102444800), tokens.ExpiresAt.Unix())
}
