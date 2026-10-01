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
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testJWT returns an unsigned compact JWT carrying claims. Only the payload
// matters to the code under test, which never verifies these tokens.
func testJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + enc.EncodeToString(payload) + ".sig"
}

func TestParseCodexAuth(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	access := testJWT(t, map[string]any{"exp": exp})
	idToken := testJWT(t, map[string]any{codexAuthClaim: map[string]any{"chatgpt_account_id": "acct-from-claim"}})

	t.Run("codex's own login", func(t *testing.T) {
		data := `{"OPENAI_API_KEY":null,"tokens":{"id_token":"` + idToken + `","access_token":"` + access +
			`","refresh_token":"rt-1","account_id":"acct-1"},"last_refresh":"2026-09-01T10:00:00Z"}`
		auth, err := ParseCodexAuth([]byte(data))
		require.NoError(t, err)
		assert.Equal(t, "", auth.Mode)
		assert.Equal(t, "acct-1", auth.AccountID)
		assert.Equal(t, "rt-1", auth.Tokens.RefreshToken)
		assert.Equal(t, idToken, auth.Tokens.IDToken)
		assert.Equal(t, exp, auth.Tokens.Expiry.Unix(), "the expiry comes from the access token's exp claim")
		assert.Equal(t, time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC), auth.LastRefresh.UTC())
	})

	t.Run("account from the id token", func(t *testing.T) {
		data := `{"auth_mode":"chatgpt","tokens":{"id_token":"` + idToken + `","access_token":"` + access + `","refresh_token":"rt"}}`
		auth, err := ParseCodexAuth([]byte(data))
		require.NoError(t, err)
		assert.Equal(t, "acct-from-claim", auth.AccountID)
	})

	t.Run("refused", func(t *testing.T) {
		_, err := ParseCodexAuth([]byte(`not json`))
		assert.ErrorIs(t, err, ErrCodexAuthInvalid)
		_, err = ParseCodexAuth([]byte(`{"OPENAI_API_KEY":"sk-x"}`))
		assert.ErrorIs(t, err, ErrCodexAuthInvalid, "an API-key file holds no ChatGPT tokens")
		_, err = ParseCodexAuth([]byte(`{"auth_mode":"apikey","OPENAI_API_KEY":"sk-x"}`))
		assert.ErrorIs(t, err, ErrCodexAuthMode)
	})
}

func TestCodexAuthTokensFile(t *testing.T) {
	access := testJWT(t, map[string]any{"exp": time.Now().Add(time.Hour).Unix()})
	idToken := testJWT(t, map[string]any{codexAuthClaim: map[string]any{"chatgpt_account_id": "acct-9"}})
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

	data, err := CodexAuthTokensFile(access, idToken, "", now)
	require.NoError(t, err)

	// The shape codex's AuthDotJson reads: the host-owned mode, the raw ID
	// token string, no refresh token, OPENAI_API_KEY present as null.
	var raw map[string]any
	require.NoError(t, json.Unmarshal(data, &raw))
	assert.Equal(t, "chatgptAuthTokens", raw["auth_mode"])
	assert.Contains(t, raw, "OPENAI_API_KEY")
	assert.Nil(t, raw["OPENAI_API_KEY"])
	tokens := raw["tokens"].(map[string]any)
	assert.Equal(t, idToken, tokens["id_token"])
	assert.Equal(t, access, tokens["access_token"])
	assert.Equal(t, "", tokens["refresh_token"], "the refresh token never leaves the server")
	assert.Equal(t, "acct-9", tokens["account_id"])
	assert.Equal(t, "2026-09-30T12:00:00Z", raw["last_refresh"])

	back, err := ParseCodexAuth(data)
	require.NoError(t, err)
	assert.Equal(t, CodexAuthModeChatGPTAuthTokens, back.Mode)
	assert.Equal(t, access, back.Tokens.AccessToken)

	_, err = CodexAuthTokensFile("", idToken, "", now)
	assert.ErrorIs(t, err, ErrCodexAuthInvalid)
	_, err = CodexAuthTokensFile(access, "", "", now)
	assert.ErrorIs(t, err, ErrCodexIDTokenRequired)
}

func TestCodexAccountID(t *testing.T) {
	assert.Equal(t, "", CodexAccountID("not-a-jwt"))
	assert.Equal(t, "", CodexAccountID(testJWT(t, map[string]any{"sub": "x"})))
	assert.Equal(t, "a", CodexAccountID(testJWT(t, map[string]any{codexAuthClaim: map[string]any{"chatgpt_account_id": " a "}})))
}
