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
	"encoding/json"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenEncoding_Validate(t *testing.T) {
	t.Run("empty, form, and json are valid", func(t *testing.T) {
		for _, encoding := range []TokenEncoding{"", TokenEncodingForm, TokenEncodingJSON} {
			assert.NoError(t, encoding.Validate())
		}
	})

	t.Run("unknown value is refused", func(t *testing.T) {
		err := TokenEncoding("yaml").Validate()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidTokenEncoding)
		assert.ErrorContains(t, err, "yaml")
	})
}

func TestEncodeTokenRequestBody(t *testing.T) {
	data := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {"abc123"},
		"client_id":  {"client-1"},
	}

	t.Run("form encoding is the default", func(t *testing.T) {
		body, contentType, err := EncodeTokenRequestBody("", data)
		require.NoError(t, err)
		assert.Equal(t, "application/x-www-form-urlencoded", contentType)

		decoded, err := url.ParseQuery(string(body))
		require.NoError(t, err)
		assert.Equal(t, "authorization_code", decoded.Get("grant_type"))
		assert.Equal(t, "abc123", decoded.Get("code"))
		assert.Equal(t, "client-1", decoded.Get("client_id"))
	})

	t.Run("json encoding marshals each field as a JSON string", func(t *testing.T) {
		body, contentType, err := EncodeTokenRequestBody(TokenEncodingJSON, data)
		require.NoError(t, err)
		assert.Equal(t, "application/json", contentType)

		var decoded map[string]string
		require.NoError(t, json.Unmarshal(body, &decoded))
		assert.Equal(t, "authorization_code", decoded["grant_type"])
		assert.Equal(t, "abc123", decoded["code"])
		assert.Equal(t, "client-1", decoded["client_id"])
	})

	t.Run("unknown encoding is refused", func(t *testing.T) {
		_, _, err := EncodeTokenRequestBody(TokenEncoding("xml"), data)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidTokenEncoding)
	})
}
