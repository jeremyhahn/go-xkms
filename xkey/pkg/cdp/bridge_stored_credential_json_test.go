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

package cdp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// legacyStoredCredential mirrors StoredCredential's on-disk shape from
// before go-xkms#587, when PrivateKey was an exported string field. It is
// the golden-fixture reference: StoredCredential's custom (Un)MarshalJSON
// must produce and accept exactly this historical shape.
type legacyStoredCredential struct {
	CredentialID         string
	IsResidentCredential bool
	RpID                 string
	PrivateKey           string
	UserHandle           string
	SignCount            int
}

// TestStoredCredential_JSON_GoldenFixture proves StoredCredential's
// protected private key round-trips through the historical wire format
// byte-for-byte: today's JSON form decodes into the protected type, and
// re-encoding it reproduces the identical bytes.
func TestStoredCredential_JSON_GoldenFixture(t *testing.T) {
	legacy := legacyStoredCredential{
		CredentialID:         "Y3JlZC0x",
		IsResidentCredential: true,
		RpID:                 "example.com",
		PrivateKey:           "cHJpdmF0ZS1rZXk",
		UserHandle:           "dXNlci0x",
		SignCount:            7,
	}

	golden, err := json.Marshal(legacy)
	require.NoError(t, err)

	var decoded StoredCredential
	require.NoError(t, json.Unmarshal(golden, &decoded))
	assert.Equal(t, legacy.CredentialID, decoded.CredentialID)
	assert.Equal(t, legacy.IsResidentCredential, decoded.IsResidentCredential)
	assert.Equal(t, legacy.RpID, decoded.RpID)
	assert.Equal(t, legacy.UserHandle, decoded.UserHandle)
	assert.Equal(t, legacy.SignCount, decoded.SignCount)
	assert.Equal(t, legacy.PrivateKey, privateKeyText(&decoded))

	reencoded, err := json.Marshal(decoded)
	require.NoError(t, err)
	assert.Equal(t, golden, reencoded, "byte-identical re-encoding of the historical form")
}

// TestStoredCredential_JSON_GoldenFixture_NoPrivateKey proves a credential
// with no private key still round-trips to the historical empty-string
// form.
func TestStoredCredential_JSON_GoldenFixture_NoPrivateKey(t *testing.T) {
	legacy := legacyStoredCredential{
		CredentialID: "Y3JlZC0y",
		RpID:         "example.com",
	}

	golden, err := json.Marshal(legacy)
	require.NoError(t, err)

	var decoded StoredCredential
	require.NoError(t, json.Unmarshal(golden, &decoded))
	assert.False(t, decoded.HasPrivateKey())
	assert.Equal(t, "", privateKeyText(&decoded))

	reencoded, err := json.Marshal(decoded)
	require.NoError(t, err)
	assert.Equal(t, golden, reencoded)
}

// TestStoredCredential_SetPrivateKey_RoundTrip proves SetPrivateKey stores
// key material that PrivateKeyString and HasPrivateKey can observe.
func TestStoredCredential_SetPrivateKey_RoundTrip(t *testing.T) {
	var cred StoredCredential
	assert.False(t, cred.HasPrivateKey())
	assert.Equal(t, "", privateKeyText(&cred))

	require.NoError(t, cred.SetPrivateKey([]byte("cHJpdmF0ZS1rZXk")))

	assert.True(t, cred.HasPrivateKey())
	assert.Equal(t, "cHJpdmF0ZS1rZXk", privateKeyText(&cred))
}

// TestStoredCredential_SetPrivateKey_EmptyClearsExisting proves
// SetPrivateKey with an empty string clears a previously stored key.
func TestStoredCredential_SetPrivateKey_EmptyClearsExisting(t *testing.T) {
	var cred StoredCredential
	require.NoError(t, cred.SetPrivateKey([]byte("will-be-cleared")))
	require.True(t, cred.HasPrivateKey())

	require.NoError(t, cred.SetPrivateKey([]byte("")))

	assert.False(t, cred.HasPrivateKey())
	assert.Equal(t, "", privateKeyText(&cred))
}

// TestStoredCredential_UnmarshalJSON_InvalidJSON proves malformed JSON is
// reported as a decode error rather than silently producing a zero-valued
// credential.
func TestStoredCredential_UnmarshalJSON_InvalidJSON(t *testing.T) {
	var cred StoredCredential
	err := json.Unmarshal([]byte("{not valid json"), &cred)
	require.Error(t, err)
}
