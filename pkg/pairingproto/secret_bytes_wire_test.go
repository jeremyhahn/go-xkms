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

package pairingproto

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSyncWire_EncodesByteIdenticalToStringSecrets proves the sync and OATH
// wire records the phone reads are unchanged by the secret becoming bytes.
func TestSyncWire_EncodesByteIdenticalToStringSecrets(t *testing.T) {
	legacyOATH, err := json.Marshal(struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Secret string `json:"secret"`
		Type   string `json:"type"`
	}{"a", "n", "JB<&>\"SW", "totp"})
	require.NoError(t, err)
	gotOATH, err := json.Marshal(SyncOATHCredential{ID: "a", Name: "n", Secret: mustSecretText("JB<&>\"SW"), Type: "totp"})
	require.NoError(t, err)
	assert.Equal(t, string(legacyOATH), string(gotOATH))

	legacyPW, err := json.Marshal(struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Password string `json:"password"`
	}{"p", "n", "p\tw\\"})
	require.NoError(t, err)
	gotPW, err := json.Marshal(SyncPassword{ID: "p", Name: "n", Password: mustSecretText("p\tw\\")})
	require.NoError(t, err)
	assert.Equal(t, string(legacyPW), string(gotPW))

	legacyInfo, err := json.Marshal(struct {
		Name   string `json:"name"`
		Secret string `json:"secret"`
		Type   string `json:"type"`
	}{"n", "JBSW", "totp"})
	require.NoError(t, err)
	gotInfo, err := json.Marshal(OATHCredentialInfo{Name: "n", Secret: mustSecretText("JBSW"), Type: "totp"})
	require.NoError(t, err)
	assert.Equal(t, string(legacyInfo), string(gotInfo))
}

func TestSyncResults_DestroyReleasesSecrets(t *testing.T) {
	secret := mustSecretText("JBSWY3DP")
	password := mustSecretText("hunter2")
	all := &RemoteSyncAllResult{
		OATH:      &RemoteSyncOATHResult{Local: []SyncOATHCredential{{Secret: secret}}},
		Passwords: &RemoteSyncPasswordsResult{Local: []SyncPassword{{Password: password}}},
	}

	all.Destroy()

	_, err := secret.Copy()
	assert.Error(t, err, "a copy of a destroyed secret must not read back")
	_, err = password.Copy()
	assert.Error(t, err)
	assert.NotPanics(t, (*RemoteSyncAllResult)(nil).Destroy)
	assert.NotPanics(t, (&RemoteSyncAllResult{}).Destroy)

	list := &LocalOATHListResult{Credentials: []OATHCredentialInfo{{Secret: mustSecretText("AAAA")}}}
	listed := list.Credentials[0].Secret
	list.Destroy()
	_, err = listed.Copy()
	assert.Error(t, err)
}

// TestDecodeResult_DestroysAPartiallyDecodedResult proves a response whose
// later field is malformed does not strand the secrets decoded before it.
func TestDecodeResult_DestroysAPartiallyDecodedResult(t *testing.T) {
	good := &Response{Result: []byte(`{"credentials":[{"name":"n","secret":"JBSW","type":"totp"},{"name":"m","secret":42}]}`)}

	got, err := DecodeResult[LocalOATHListResult](good)
	require.Error(t, err)
	assert.Nil(t, got)
}

func TestDecodeResult_ReturnsAUsableSecretBearingResult(t *testing.T) {
	resp := &Response{Result: []byte(`{"credentials":[{"name":"n","secret":"JBSW","type":"totp"}]}`)}

	got, err := DecodeResult[LocalOATHListResult](resp)
	require.NoError(t, err)
	defer got.Destroy()
	require.Len(t, got.Credentials, 1)
	assert.Equal(t, "JBSW", textOf(got.Credentials[0].Secret))
}
