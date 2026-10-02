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

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TestCredential_EncodesByteIdenticalToStringKey proves the CDP wire
// credential encodes to the bytes it did while PrivateKey was a string, so
// Chrome receives exactly what it always has.
func TestCredential_EncodesByteIdenticalToStringKey(t *testing.T) {
	legacy, err := json.Marshal(struct {
		CredentialID         string `json:"credentialId"`
		IsResidentCredential bool   `json:"isResidentCredential"`
		RpID                 string `json:"rpId"`
		PrivateKey           string `json:"privateKey"`
		UserHandle           string `json:"userHandle,omitempty"`
		SignCount            int    `json:"signCount"`
	}{"Y3JlZA==", true, "example.com", "MIGHAgEA+/==", "", 3})
	require.NoError(t, err)

	cred := Credential{CredentialID: "Y3JlZA==", IsResidentCredential: true, RpID: "example.com", PrivateKey: xkms.SecretBytes("MIGHAgEA+/=="), SignCount: 3}
	defer cred.Wipe()
	got, err := json.Marshal(cred)
	require.NoError(t, err)
	assert.Equal(t, string(legacy), string(got))

	var back Credential
	require.NoError(t, json.Unmarshal(legacy, &back))
	assert.Equal(t, "MIGHAgEA+/==", string(back.PrivateKey))
}

func TestCredential_WipeZeroesKey(t *testing.T) {
	key := xkms.SecretBytes("MIGHAgEA")
	cred := Credential{PrivateKey: key}
	cred.Wipe()
	assert.Nil(t, cred.PrivateKey)
	assert.Equal(t, make([]byte, len(key)), []byte(key))
}

func TestStoredCredential_PrivateKeyAccessor(t *testing.T) {
	var cred StoredCredential
	none, err := cred.PrivateKey()
	require.NoError(t, err)
	assert.Nil(t, none)

	in := []byte("MIGHAgEA")
	require.NoError(t, cred.SetPrivateKey(in))
	assert.Equal(t, []byte("MIGHAgEA"), in, "SetPrivateKey must leave the caller's slice intact")

	first, err := cred.PrivateKey()
	require.NoError(t, err)
	first[0] = 'X'
	assert.Equal(t, "MIGHAgEA", privateKeyText(&cred), "a returned copy must not alias the protected original")

	var nilCred *StoredCredential
	none, err = nilCred.PrivateKey()
	require.NoError(t, err)
	assert.Nil(t, none)

	require.NoError(t, cred.SetPrivateKey(nil))
	assert.False(t, cred.HasPrivateKey())
}
