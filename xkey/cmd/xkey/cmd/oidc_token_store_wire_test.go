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

package cmd

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// legacyOIDCStoredToken is the at-rest form written when the tokens were Go
// strings. The stored record must still load, and re-encode byte for byte.
const legacyOIDCStoredToken = `{"provider":"https://idp.example.com","issuer":"https://idp.example.com","client_id":"cli","access_token":"acc\u003c\u0026\u003e\"ess","refresh_token":"ref\\resh","id_token":"id\ttoken","expires_at":"2030-01-02T03:04:05Z","scopes":["openid","email"]}`

func TestOIDCStoredToken_LegacyRecordRoundTripsByteIdentical(t *testing.T) {
	var token OIDCStoredToken
	require.NoError(t, json.Unmarshal([]byte(legacyOIDCStoredToken), &token))
	defer token.Destroy()

	access := token.AccessToken()
	defer secure.Wipe(access)
	assert.Equal(t, `acc<&>"ess`, string(access))

	out, err := json.Marshal(&token)
	require.NoError(t, err)
	assert.Equal(t, legacyOIDCStoredToken, string(out))
}

func TestOIDCStoredToken_UnmarshalRejectsNonStringToken(t *testing.T) {
	var token OIDCStoredToken
	err := json.Unmarshal([]byte(`{"access_token":42}`), &token)
	require.Error(t, err)
	token.Destroy()
}

func TestOIDCStoredToken_AccessorsReturnIndependentCopies(t *testing.T) {
	var token OIDCStoredToken
	defer token.Destroy()

	in := []byte("access-1")
	require.NoError(t, token.SetAccessToken(in))
	assert.Equal(t, []byte("access-1"), in, "Set must leave the caller's slice intact")

	first := token.AccessToken()
	secure.Wipe(first)
	second := token.AccessToken()
	defer secure.Wipe(second)
	assert.Equal(t, "access-1", string(second), "wiping a copy must not touch the protected original")

	assert.Nil(t, token.RefreshToken())
	assert.False(t, token.HasRefreshToken())
}

func TestOIDCStoredToken_EmptySetClearsField(t *testing.T) {
	var token OIDCStoredToken
	defer token.Destroy()

	require.NoError(t, token.SetRefreshToken([]byte("refresh")))
	require.True(t, token.HasRefreshToken())
	require.NoError(t, token.SetRefreshToken(nil))
	assert.False(t, token.HasRefreshToken())
}

func TestOIDCTokenResponse_DecodesLegacyBodyAndWipes(t *testing.T) {
	const body = `{"access_token":"a1","token_type":"Bearer","expires_in":3600,"refresh_token":"r1","id_token":"i1","scope":"openid"}`

	var resp OIDCTokenResponse
	require.NoError(t, json.Unmarshal([]byte(body), &resp))
	assert.Equal(t, "a1", string(resp.AccessToken))
	assert.Equal(t, int64(3600), resp.ExpiresIn)

	access := resp.AccessToken
	resp.Wipe()
	assert.Nil(t, resp.AccessToken)
	assert.Equal(t, make([]byte, len(access)), []byte(access), "Wipe must zero the backing array")

	var nilResp *OIDCTokenResponse
	assert.NotPanics(t, nilResp.Wipe)
}

func TestOIDCExecPayload_EncodesTokensAsStrings(t *testing.T) {
	payload := OIDCExecPayload{
		Provider:    "p",
		Issuer:      "i",
		ClientID:    "c",
		AccessToken: []byte("acc"),
		IDToken:     []byte("id"),
		ExpiresAt:   time.Unix(0, 0).UTC().Format(time.RFC3339),
		Scopes:      []string{"openid"},
	}

	out, err := json.Marshal(payload)
	require.NoError(t, err)
	assert.JSONEq(t, `{"provider":"p","issuer":"i","client_id":"c","access_token":"acc","id_token":"id","expires_at":"1970-01-01T00:00:00Z","expires_in":0,"scopes":["openid"]}`, string(out))
	assert.False(t, bytes.Contains(out, []byte("refresh_token")), "an empty refresh token stays omitted")
}
