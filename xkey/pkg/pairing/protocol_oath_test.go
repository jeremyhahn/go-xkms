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

package pairing

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOATHMethodConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"MethodLocalOATHAdd", MethodLocalOATHAdd, "local.oathAdd"},
		{"MethodLocalOATHList", MethodLocalOATHList, "local.oathList"},
		{"MethodLocalOATHGenerate", MethodLocalOATHGenerate, "local.oathGenerate"},
		{"MethodLocalOATHRemove", MethodLocalOATHRemove, "local.oathRemove"},
		{"MethodRemoteOATHAdd", MethodRemoteOATHAdd, "remote.oathAdd"},
		{"MethodRemoteOATHGenerate", MethodRemoteOATHGenerate, "remote.oathGenerate"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}

	assert.Equal(t, 6, len(tests), "expected exactly 6 OATH method constants")
}

func TestIsOATHLocalMethod(t *testing.T) {
	t.Run("valid OATH local methods", func(t *testing.T) {
		validMethods := []string{
			MethodLocalOATHAdd,
			MethodLocalOATHList,
			MethodLocalOATHGenerate,
			MethodLocalOATHRemove,
		}
		for _, method := range validMethods {
			assert.True(t, IsOATHLocalMethod(method),
				"expected IsOATHLocalMethod(%q) to return true", method)
		}
	})

	t.Run("invalid methods", func(t *testing.T) {
		invalidMethods := []string{
			"",
			"local.sign",
			"remote.oathAdd",
			"local.oathAdd_typo",
			"local.oath",
		}
		for _, method := range invalidMethods {
			assert.False(t, IsOATHLocalMethod(method),
				"expected IsOATHLocalMethod(%q) to return false", method)
		}
	})
}

func TestIsOATHRemoteMethod(t *testing.T) {
	t.Run("valid OATH remote methods", func(t *testing.T) {
		validMethods := []string{
			MethodRemoteOATHAdd,
			MethodRemoteOATHGenerate,
		}
		for _, method := range validMethods {
			assert.True(t, IsOATHRemoteMethod(method),
				"expected IsOATHRemoteMethod(%q) to return true", method)
		}
	})

	t.Run("invalid methods", func(t *testing.T) {
		invalidMethods := []string{
			"",
			"remote.sign",
			"local.oathAdd",
			"remote.oathAdd_typo",
			"remote.oathList",
			"remote.oathRemove",
		}
		for _, method := range invalidMethods {
			assert.False(t, IsOATHRemoteMethod(method),
				"expected IsOATHRemoteMethod(%q) to return false", method)
		}
	})
}

func TestOATHMethodsRegisteredInGlobalMaps(t *testing.T) {
	// Verify OATH local methods are registered in the global localMethodNames map.
	assert.True(t, IsLocalMethod(MethodLocalOATHAdd))
	assert.True(t, IsLocalMethod(MethodLocalOATHList))
	assert.True(t, IsLocalMethod(MethodLocalOATHGenerate))
	assert.True(t, IsLocalMethod(MethodLocalOATHRemove))

	// Verify OATH remote methods are registered in the global remoteMethodNames map.
	assert.True(t, IsRemoteMethod(MethodRemoteOATHAdd))
	assert.True(t, IsRemoteMethod(MethodRemoteOATHGenerate))
}

// --- OATHCredentialInfo ---

func TestOATHCredentialInfo_JSONRoundTrip(t *testing.T) {
	original := OATHCredentialInfo{
		Name:        "GitHub",
		Issuer:      "GitHub",
		AccountName: "user@example.com",
		Secret:      "JBSWY3DPEHPK3PXP",
		Type:        "totp",
		Algorithm:   "SHA1",
		Digits:      6,
		Period:      30,
		Counter:     0,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded OATHCredentialInfo
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original, decoded)
}

func TestOATHCredentialInfo_JSONFieldNames(t *testing.T) {
	info := OATHCredentialInfo{
		Name:        "test",
		Issuer:      "TestCo",
		AccountName: "user@test.com",
		Secret:      "SECRET",
		Type:        "totp",
		Algorithm:   "SHA256",
		Digits:      8,
		Period:      60,
		Counter:     5,
	}

	data, err := json.Marshal(info)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{
		"name", "issuer", "account_name", "secret", "type",
		"algorithm", "digits", "period", "counter",
	}
	for _, field := range expectedFields {
		_, ok := raw[field]
		assert.True(t, ok, "expected JSON field %q to be present", field)
	}
}

func TestOATHCredentialInfo_OmitEmpty(t *testing.T) {
	info := OATHCredentialInfo{
		Name:   "minimal",
		Secret: "SECRET",
		Type:   "totp",
	}

	data, err := json.Marshal(info)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	// These fields have omitempty and should be absent when zero.
	assert.NotContains(t, raw, "issuer")
	assert.NotContains(t, raw, "account_name")
	assert.NotContains(t, raw, "algorithm")
	assert.NotContains(t, raw, "digits")
	assert.NotContains(t, raw, "period")
	assert.NotContains(t, raw, "counter")
}

func TestOATHCredentialInfo_HOTPCredential(t *testing.T) {
	original := OATHCredentialInfo{
		Name:    "AWS",
		Issuer:  "Amazon",
		Secret:  "NBSWY3DP",
		Type:    "hotp",
		Digits:  6,
		Counter: 42,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded OATHCredentialInfo
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "hotp", decoded.Type)
	assert.Equal(t, uint64(42), decoded.Counter)
}

// --- local.oathAdd ---

func TestLocalOATHAddParams_JSONRoundTrip(t *testing.T) {
	original := &LocalOATHAddParams{
		Credential: OATHCredentialInfo{
			Name:      "GitHub",
			Issuer:    "GitHub",
			Secret:    "JBSWY3DPEHPK3PXP",
			Type:      "totp",
			Algorithm: "SHA1",
			Digits:    6,
			Period:    30,
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalOATHAddParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Credential.Name, decoded.Credential.Name)
	assert.Equal(t, original.Credential.Secret, decoded.Credential.Secret)
	assert.Equal(t, original.Credential.Type, decoded.Credential.Type)
}

func TestLocalOATHAddResult_JSONRoundTrip(t *testing.T) {
	original := &LocalOATHAddResult{
		Success:      true,
		CredentialID: "cred-abc-123",
		Message:      "credential stored successfully",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalOATHAddResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Success, decoded.Success)
	assert.Equal(t, original.CredentialID, decoded.CredentialID)
	assert.Equal(t, original.Message, decoded.Message)
}

func TestLocalOATHAddResult_OmitEmptyMessage(t *testing.T) {
	result := LocalOATHAddResult{
		Success:      true,
		CredentialID: "c1",
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "message")
}

// --- local.oathList ---

func TestLocalOATHListParams_JSONRoundTrip(t *testing.T) {
	original := &LocalOATHListParams{}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalOATHListParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, *original, decoded)
}

func TestLocalOATHListResult_JSONRoundTrip(t *testing.T) {
	original := &LocalOATHListResult{
		Credentials: []OATHCredentialInfo{
			{
				Name:      "GitHub",
				Issuer:    "GitHub",
				Secret:    "JBSWY3DPEHPK3PXP",
				Type:      "totp",
				Algorithm: "SHA1",
				Digits:    6,
				Period:    30,
			},
			{
				Name:    "AWS",
				Issuer:  "Amazon",
				Secret:  "NBSWY3DP",
				Type:    "hotp",
				Digits:  6,
				Counter: 10,
			},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalOATHListResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.Len(t, decoded.Credentials, 2)
	assert.Equal(t, "GitHub", decoded.Credentials[0].Name)
	assert.Equal(t, "AWS", decoded.Credentials[1].Name)
}

func TestLocalOATHListResult_EmptyCredentials(t *testing.T) {
	original := &LocalOATHListResult{
		Credentials: []OATHCredentialInfo{},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalOATHListResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Empty(t, decoded.Credentials)
}

// --- local.oathGenerate ---

func TestLocalOATHGenerateParams_JSONRoundTrip(t *testing.T) {
	original := &LocalOATHGenerateParams{
		CredentialID: "cred-001",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalOATHGenerateParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.CredentialID, decoded.CredentialID)
}

func TestLocalOATHGenerateParams_JSONFieldNames(t *testing.T) {
	params := LocalOATHGenerateParams{
		CredentialID: "c1",
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Contains(t, raw, "credential_id")
}

func TestLocalOATHGenerateResult_JSONRoundTrip(t *testing.T) {
	original := &LocalOATHGenerateResult{
		Code:      "123456",
		ExpiresIn: 27,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalOATHGenerateResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "123456", decoded.Code)
	assert.Equal(t, 27, decoded.ExpiresIn)
}

func TestLocalOATHGenerateResult_OmitEmptyExpiresIn(t *testing.T) {
	result := LocalOATHGenerateResult{
		Code: "654321",
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "expires_in")
}

// --- local.oathRemove ---

func TestLocalOATHRemoveParams_JSONRoundTrip(t *testing.T) {
	original := &LocalOATHRemoveParams{
		CredentialID: "cred-to-delete",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalOATHRemoveParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.CredentialID, decoded.CredentialID)
}

func TestLocalOATHRemoveResult_JSONRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		deleted bool
	}{
		{"credential deleted", true},
		{"credential not deleted", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := LocalOATHRemoveResult{Deleted: tt.deleted}

			data, err := json.Marshal(original)
			require.NoError(t, err)

			var decoded LocalOATHRemoveResult
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			assert.Equal(t, tt.deleted, decoded.Deleted)
		})
	}
}

// --- remote.oathAdd ---

func TestRemoteOATHAddParams_JSONRoundTrip(t *testing.T) {
	original := &RemoteOATHAddParams{
		Credential: OATHCredentialInfo{
			Name:      "Slack",
			Issuer:    "Slack",
			Secret:    "NBSWY3DPEHPK3PXP",
			Type:      "totp",
			Algorithm: "SHA256",
			Digits:    6,
			Period:    30,
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteOATHAddParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Credential.Name, decoded.Credential.Name)
	assert.Equal(t, original.Credential.Secret, decoded.Credential.Secret)
}

func TestRemoteOATHAddResult_JSONRoundTrip(t *testing.T) {
	original := &RemoteOATHAddResult{
		Success:      true,
		CredentialID: "remote-cred-001",
		Message:      "credential received",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteOATHAddResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Success, decoded.Success)
	assert.Equal(t, original.CredentialID, decoded.CredentialID)
	assert.Equal(t, original.Message, decoded.Message)
}

func TestRemoteOATHAddResult_OmitEmptyMessage(t *testing.T) {
	result := RemoteOATHAddResult{
		Success:      true,
		CredentialID: "c1",
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "message")
}

// --- remote.oathGenerate ---

func TestRemoteOATHGenerateParams_JSONRoundTrip(t *testing.T) {
	original := &RemoteOATHGenerateParams{
		CredentialID: "remote-cred-001",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteOATHGenerateParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.CredentialID, decoded.CredentialID)
}

func TestRemoteOATHGenerateParams_JSONFieldNames(t *testing.T) {
	params := RemoteOATHGenerateParams{
		CredentialID: "c1",
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Contains(t, raw, "credential_id")
}

func TestRemoteOATHGenerateResult_JSONRoundTrip(t *testing.T) {
	original := &RemoteOATHGenerateResult{
		Code:      "789012",
		ExpiresIn: 15,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteOATHGenerateResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "789012", decoded.Code)
	assert.Equal(t, 15, decoded.ExpiresIn)
}

func TestRemoteOATHGenerateResult_OmitEmptyExpiresIn(t *testing.T) {
	result := RemoteOATHGenerateResult{
		Code: "000000",
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "expires_in")
}

// --- Zero-value and edge case tests ---

func TestOATHTypes_ZeroValues(t *testing.T) {
	tests := []struct {
		name string
		val  interface{}
	}{
		{"OATHCredentialInfo", &OATHCredentialInfo{}},
		{"LocalOATHAddParams", &LocalOATHAddParams{}},
		{"LocalOATHAddResult", &LocalOATHAddResult{}},
		{"LocalOATHListParams", &LocalOATHListParams{}},
		{"LocalOATHListResult", &LocalOATHListResult{}},
		{"LocalOATHGenerateParams", &LocalOATHGenerateParams{}},
		{"LocalOATHGenerateResult", &LocalOATHGenerateResult{}},
		{"LocalOATHRemoveParams", &LocalOATHRemoveParams{}},
		{"LocalOATHRemoveResult", &LocalOATHRemoveResult{}},
		{"RemoteOATHAddParams", &RemoteOATHAddParams{}},
		{"RemoteOATHAddResult", &RemoteOATHAddResult{}},
		{"RemoteOATHGenerateParams", &RemoteOATHGenerateParams{}},
		{"RemoteOATHGenerateResult", &RemoteOATHGenerateResult{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.val)
			require.NoError(t, err)
			require.NotEmpty(t, data)
			assert.True(t, json.Valid(data), "expected valid JSON for zero-value %s", tt.name)
		})
	}
}

// --- Error code mapping tests ---

func TestOATHErrorCodeMapping(t *testing.T) {
	t.Run("OATH credential not found maps correctly", func(t *testing.T) {
		mapped := MapRPCError(&RPCError{Code: ErrorCodeOATHNotFound, Message: "not found"})
		assert.Equal(t, ErrOATHCredentialNotFound, mapped)
	})

	t.Run("OATH generate failed maps correctly", func(t *testing.T) {
		mapped := MapRPCError(&RPCError{Code: ErrorCodeOATHGenerate, Message: "generation failed"})
		assert.Equal(t, ErrOATHGenerateFailed, mapped)
	})

	t.Run("OATH store failed maps correctly", func(t *testing.T) {
		mapped := MapRPCError(&RPCError{Code: ErrorCodeOATHStore, Message: "store failed"})
		assert.Equal(t, ErrOATHStoreFailed, mapped)
	})
}

// --- NewRequest integration tests ---

func TestNewRequest_OATHMethods(t *testing.T) {
	tests := []struct {
		name   string
		method string
		params interface{}
	}{
		{
			name:   "local oathAdd",
			method: MethodLocalOATHAdd,
			params: &LocalOATHAddParams{
				Credential: OATHCredentialInfo{
					Name:   "GitHub",
					Secret: "JBSWY3DPEHPK3PXP",
					Type:   "totp",
				},
			},
		},
		{
			name:   "local oathList",
			method: MethodLocalOATHList,
			params: &LocalOATHListParams{},
		},
		{
			name:   "local oathGenerate",
			method: MethodLocalOATHGenerate,
			params: &LocalOATHGenerateParams{
				CredentialID: "cred-001",
			},
		},
		{
			name:   "local oathRemove",
			method: MethodLocalOATHRemove,
			params: &LocalOATHRemoveParams{
				CredentialID: "cred-001",
			},
		},
		{
			name:   "remote oathAdd",
			method: MethodRemoteOATHAdd,
			params: &RemoteOATHAddParams{
				Credential: OATHCredentialInfo{
					Name:   "Slack",
					Secret: "NBSWY3DP",
					Type:   "totp",
				},
			},
		},
		{
			name:   "remote oathGenerate",
			method: MethodRemoteOATHGenerate,
			params: &RemoteOATHGenerateParams{
				CredentialID: "remote-cred-001",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := NewRequest(tt.method, tt.params)

			require.NotNil(t, req)
			assert.Equal(t, JSONRPCVersion, req.JSONRPC)
			assert.NotZero(t, req.ID)
			assert.Equal(t, tt.method, req.Method)
			assert.Equal(t, tt.params, req.Params)

			data, err := EncodeRequest(req)
			require.NoError(t, err)
			require.NotEmpty(t, data)

			var raw map[string]interface{}
			err = json.Unmarshal(data, &raw)
			require.NoError(t, err)
			assert.Equal(t, tt.method, raw["method"])
		})
	}
}
