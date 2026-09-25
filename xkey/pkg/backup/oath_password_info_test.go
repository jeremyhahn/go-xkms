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

package backup

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOATHCredentialInfo_SetSecret_EmptyClearsExisting verifies that
// SetSecret("") destroys a previously stored secret rather than leaving it
// live in protected memory with HasSecret still reporting true.
func TestOATHCredentialInfo_SetSecret_EmptyClearsExisting(t *testing.T) {
	cred := &OATHCredentialInfo{}
	require.NoError(t, cred.SetSecret("JBSWY3DPEHPK3PXP"))
	require.True(t, cred.HasSecret())

	require.NoError(t, cred.SetSecret(""))
	assert.False(t, cred.HasSecret())
	assert.Empty(t, cred.SecretString())
}

// TestOATHCredentialInfo_HasSecret_NilReceiver verifies HasSecret is safe to
// call on a nil *OATHCredentialInfo, matching SecretString's nil-safety.
func TestOATHCredentialInfo_HasSecret_NilReceiver(t *testing.T) {
	var cred *OATHCredentialInfo
	assert.False(t, cred.HasSecret())
}

// TestOATHCredentialInfo_SecretString_NilCases verifies SecretString returns
// "" for both a nil receiver and a receiver with no secret set, rather than
// panicking.
func TestOATHCredentialInfo_SecretString_NilCases(t *testing.T) {
	var nilCred *OATHCredentialInfo
	assert.Equal(t, "", nilCred.SecretString())

	empty := &OATHCredentialInfo{}
	assert.Equal(t, "", empty.SecretString())
}

// TestOATHCredentialInfo_MarshalJSON verifies the protected secret is
// exported into the historical "Secret" JSON key alongside the plain
// fields.
func TestOATHCredentialInfo_MarshalJSON(t *testing.T) {
	cred := withSecret(&OATHCredentialInfo{
		ID: "oath-1", Name: "GitHub", Issuer: "GitHub",
		AccountName: "user@example.com",
		Type:        "totp", Algorithm: "SHA1", Digits: 6, Period: 30, Counter: 5,
	}, "JBSWY3DPEHPK3PXP")

	data, err := json.Marshal(cred)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, "oath-1", decoded["ID"])
	assert.Equal(t, "JBSWY3DPEHPK3PXP", decoded["Secret"])
	assert.Equal(t, float64(6), decoded["Digits"])
}

// TestOATHCredentialInfo_UnmarshalJSON verifies the "Secret" JSON key is
// adopted into protected memory and the plain fields are copied across.
func TestOATHCredentialInfo_UnmarshalJSON(t *testing.T) {
	raw := `{"ID":"oath-1","Name":"GitHub","Issuer":"GitHub","AccountName":"user@example.com","Secret":"JBSWY3DPEHPK3PXP","Type":"totp","Algorithm":"SHA1","Digits":6,"Period":30,"Counter":5}`

	var cred OATHCredentialInfo
	require.NoError(t, json.Unmarshal([]byte(raw), &cred))

	assert.Equal(t, "oath-1", cred.ID)
	assert.Equal(t, "GitHub", cred.Name)
	assert.Equal(t, 6, cred.Digits)
	assert.Equal(t, int64(5), cred.Counter)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", cred.SecretString())
}

// TestOATHCredentialInfo_UnmarshalJSON_InvalidJSON verifies malformed JSON is
// reported as an error rather than leaving a partially populated value.
func TestOATHCredentialInfo_UnmarshalJSON_InvalidJSON(t *testing.T) {
	var cred OATHCredentialInfo
	err := json.Unmarshal([]byte(`{"ID": not-json`), &cred)
	assert.Error(t, err)
}

// TestPasswordInfo_SetPassword_EmptyClearsExisting verifies that
// SetPassword("") destroys a previously stored password.
func TestPasswordInfo_SetPassword_EmptyClearsExisting(t *testing.T) {
	info := &PasswordInfo{}
	require.NoError(t, info.SetPassword("s3cret!"))
	require.True(t, info.HasPassword())

	require.NoError(t, info.SetPassword(""))
	assert.False(t, info.HasPassword())
	assert.Empty(t, info.PasswordString())
}

// TestPasswordInfo_HasPassword_NilReceiver verifies HasPassword is safe to
// call on a nil *PasswordInfo.
func TestPasswordInfo_HasPassword_NilReceiver(t *testing.T) {
	var info *PasswordInfo
	assert.False(t, info.HasPassword())
}

// TestPasswordInfo_PasswordString_NilCases verifies PasswordString returns
// "" for both a nil receiver and a receiver with no password set.
func TestPasswordInfo_PasswordString_NilCases(t *testing.T) {
	var nilInfo *PasswordInfo
	assert.Equal(t, "", nilInfo.PasswordString())

	empty := &PasswordInfo{}
	assert.Equal(t, "", empty.PasswordString())
}

// TestPasswordInfo_MarshalJSON verifies the protected password is exported
// into the historical "Password" JSON key.
func TestPasswordInfo_MarshalJSON(t *testing.T) {
	info := withPassword(&PasswordInfo{
		ID: "pw-1", Name: "Server SSH", Title: "Production Server",
		Username: "admin", URL: "ssh://prod.example.com",
		Notes: "Primary server", FolderPath: "/servers",
	}, "s3cret!")

	data, err := json.Marshal(info)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, "pw-1", decoded["ID"])
	assert.Equal(t, "s3cret!", decoded["Password"])
	assert.Equal(t, "/servers", decoded["FolderPath"])
}

// TestPasswordInfo_UnmarshalJSON verifies the "Password" JSON key is adopted
// into protected memory and the plain fields are copied across.
func TestPasswordInfo_UnmarshalJSON(t *testing.T) {
	raw := `{"ID":"pw-1","Name":"Server SSH","Title":"Production Server","Username":"admin","Password":"s3cret!","URL":"ssh://prod.example.com","Notes":"Primary server","FolderPath":"/servers"}`

	var info PasswordInfo
	require.NoError(t, json.Unmarshal([]byte(raw), &info))

	assert.Equal(t, "pw-1", info.ID)
	assert.Equal(t, "admin", info.Username)
	assert.Equal(t, "s3cret!", info.PasswordString())
}

// TestPasswordInfo_UnmarshalJSON_InvalidJSON verifies malformed JSON is
// reported as an error rather than leaving a partially populated value.
func TestPasswordInfo_UnmarshalJSON_InvalidJSON(t *testing.T) {
	var info PasswordInfo
	err := json.Unmarshal([]byte(`{"ID": not-json`), &info)
	assert.Error(t, err)
}
