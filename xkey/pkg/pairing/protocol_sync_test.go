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

func TestSyncMethodConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		// local.* sync methods
		{"MethodLocalSyncTrustStore", MethodLocalSyncTrustStore, "local.syncTrustStore"},
		{"MethodLocalSyncOATH", MethodLocalSyncOATH, "local.syncOATH"},
		{"MethodLocalSyncPasswords", MethodLocalSyncPasswords, "local.syncPasswords"},
		{"MethodLocalSyncStatus", MethodLocalSyncStatus, "local.syncStatus"},
		// remote.* sync methods
		{"MethodRemoteSyncTrustStore", MethodRemoteSyncTrustStore, "remote.syncTrustStore"},
		{"MethodRemoteSyncOATH", MethodRemoteSyncOATH, "remote.syncOATH"},
		{"MethodRemoteSyncPasswords", MethodRemoteSyncPasswords, "remote.syncPasswords"},
		{"MethodRemoteSyncAll", MethodRemoteSyncAll, "remote.syncAll"},
		{"MethodRemoteSyncStatus", MethodRemoteSyncStatus, "remote.syncStatus"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}

	assert.Equal(t, 9, len(tests), "expected exactly 9 sync method constants")
}

func TestIsSyncLocalMethod(t *testing.T) {
	t.Run("valid sync local methods", func(t *testing.T) {
		validMethods := []string{
			MethodLocalSyncTrustStore,
			MethodLocalSyncOATH,
			MethodLocalSyncPasswords,
			MethodLocalSyncStatus,
		}
		for _, method := range validMethods {
			assert.True(t, IsSyncLocalMethod(method),
				"expected IsSyncLocalMethod(%q) to return true", method)
		}
	})

	t.Run("invalid methods", func(t *testing.T) {
		invalidMethods := []string{
			"",
			"local.sign",
			"remote.syncTrustStore",
			"local.syncTrustStore_typo",
			"local.sync",
		}
		for _, method := range invalidMethods {
			assert.False(t, IsSyncLocalMethod(method),
				"expected IsSyncLocalMethod(%q) to return false", method)
		}
	})
}

func TestIsSyncRemoteMethod(t *testing.T) {
	t.Run("valid sync remote methods", func(t *testing.T) {
		validMethods := []string{
			MethodRemoteSyncTrustStore,
			MethodRemoteSyncOATH,
			MethodRemoteSyncPasswords,
			MethodRemoteSyncAll,
			MethodRemoteSyncStatus,
		}
		for _, method := range validMethods {
			assert.True(t, IsSyncRemoteMethod(method),
				"expected IsSyncRemoteMethod(%q) to return true", method)
		}
	})

	t.Run("invalid methods", func(t *testing.T) {
		invalidMethods := []string{
			"",
			"remote.sign",
			"local.syncTrustStore",
			"remote.syncAll_typo",
			"remote.sync",
			"remote.syncPasswords_",
		}
		for _, method := range invalidMethods {
			assert.False(t, IsSyncRemoteMethod(method),
				"expected IsSyncRemoteMethod(%q) to return false", method)
		}
	})
}

func TestSyncMethodsRegisteredInGlobalMaps(t *testing.T) {
	// Verify sync local methods are registered in the global localMethodNames map.
	assert.True(t, IsLocalMethod(MethodLocalSyncTrustStore))
	assert.True(t, IsLocalMethod(MethodLocalSyncOATH))
	assert.True(t, IsLocalMethod(MethodLocalSyncPasswords))
	assert.True(t, IsLocalMethod(MethodLocalSyncStatus))

	// Verify sync remote methods are registered in the global remoteMethodNames map.
	assert.True(t, IsRemoteMethod(MethodRemoteSyncTrustStore))
	assert.True(t, IsRemoteMethod(MethodRemoteSyncOATH))
	assert.True(t, IsRemoteMethod(MethodRemoteSyncPasswords))
	assert.True(t, IsRemoteMethod(MethodRemoteSyncAll))
	assert.True(t, IsRemoteMethod(MethodRemoteSyncStatus))
}

// --- SyncCertificate ---

func TestSyncCertificate_JSONRoundTrip(t *testing.T) {
	original := SyncCertificate{
		PEM:         "-----BEGIN CERTIFICATE-----\nMIIBxTCCAW...\n-----END CERTIFICATE-----",
		Fingerprint: "sha256:abc123def456",
		Purpose:     "tls-client",
		Source:      "phone",
		Tags:        []string{"production", "primary"},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded SyncCertificate
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original, decoded)
}

func TestSyncCertificate_JSONFieldNames(t *testing.T) {
	cert := SyncCertificate{
		PEM:         "test-pem",
		Fingerprint: "sha256:test",
		Purpose:     "tls",
		Source:      "laptop",
		Tags:        []string{"tag1"},
	}

	data, err := json.Marshal(cert)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{"pem", "fingerprint", "tags"}
	for _, field := range expectedFields {
		_, ok := raw[field]
		assert.True(t, ok, "expected JSON field %q to be present", field)
	}
}

func TestSyncCertificate_OmitEmpty(t *testing.T) {
	cert := SyncCertificate{
		PEM:         "test-pem",
		Fingerprint: "sha256:test",
	}

	data, err := json.Marshal(cert)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "purpose")
	assert.NotContains(t, raw, "source")
	assert.NotContains(t, raw, "tags")
}

// --- SyncOATHCredential ---

func TestSyncOATHCredential_JSONRoundTrip(t *testing.T) {
	original := SyncOATHCredential{
		ID:          "oath-001",
		Name:        "GitHub",
		Issuer:      "GitHub",
		AccountName: "user@example.com",
		Secret:      "JBSWY3DPEHPK3PXP",
		Type:        "totp",
		Algorithm:   "SHA1",
		Digits:      6,
		Period:      30,
		Counter:     0,
		UpdatedAt:   "2025-01-15T10:30:00Z",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded SyncOATHCredential
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original, decoded)
}

func TestSyncOATHCredential_OmitEmpty(t *testing.T) {
	cred := SyncOATHCredential{
		ID:     "oath-002",
		Name:   "Minimal",
		Secret: "SECRET",
		Type:   "totp",
	}

	data, err := json.Marshal(cred)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "issuer")
	assert.NotContains(t, raw, "account_name")
	assert.NotContains(t, raw, "algorithm")
	assert.NotContains(t, raw, "digits")
	assert.NotContains(t, raw, "period")
	assert.NotContains(t, raw, "counter")
	assert.NotContains(t, raw, "updated_at")
}

// --- SyncPassword ---

func TestSyncPassword_JSONRoundTrip(t *testing.T) {
	original := SyncPassword{
		ID:         "pwd-001",
		Name:       "GitHub Login",
		Title:      "GitHub",
		Username:   "user@example.com",
		Password:   "s3cret!",
		URL:        "https://github.com",
		Notes:      "Personal account",
		FolderPath: "Social/Code",
		UpdatedAt:  "2025-01-15T10:30:00Z",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded SyncPassword
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original, decoded)
}

func TestSyncPassword_OmitEmpty(t *testing.T) {
	pwd := SyncPassword{
		ID:       "pwd-002",
		Name:     "Minimal",
		Password: "pw",
	}

	data, err := json.Marshal(pwd)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "title")
	assert.NotContains(t, raw, "username")
	assert.NotContains(t, raw, "url")
	assert.NotContains(t, raw, "notes")
	assert.NotContains(t, raw, "folder_path")
	assert.NotContains(t, raw, "updated_at")
}

// --- local.syncTrustStore ---

func TestLocalSyncTrustStoreParams_JSONRoundTrip(t *testing.T) {
	original := &LocalSyncTrustStoreParams{
		Certificates: []SyncCertificate{
			{PEM: "cert1", Fingerprint: "fp1"},
			{PEM: "cert2", Fingerprint: "fp2", Purpose: "ca"},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalSyncTrustStoreParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.Len(t, decoded.Certificates, 2)
	assert.Equal(t, "cert1", decoded.Certificates[0].PEM)
	assert.Equal(t, "ca", decoded.Certificates[1].Purpose)
}

func TestLocalSyncTrustStoreResult_JSONRoundTrip(t *testing.T) {
	original := &LocalSyncTrustStoreResult{
		Added:   3,
		Skipped: 1,
		Remote: []SyncCertificate{
			{PEM: "remote-cert", Fingerprint: "fp-r"},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalSyncTrustStoreResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, 3, decoded.Added)
	assert.Equal(t, 1, decoded.Skipped)
	require.Len(t, decoded.Remote, 1)
	assert.Equal(t, "remote-cert", decoded.Remote[0].PEM)
}

// --- local.syncOATH ---

func TestLocalSyncOATHParams_JSONRoundTrip(t *testing.T) {
	original := &LocalSyncOATHParams{
		Credentials: []SyncOATHCredential{
			{ID: "c1", Name: "GitHub", Secret: "SECRET", Type: "totp"},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalSyncOATHParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.Len(t, decoded.Credentials, 1)
	assert.Equal(t, "GitHub", decoded.Credentials[0].Name)
}

func TestLocalSyncOATHResult_JSONRoundTrip(t *testing.T) {
	original := &LocalSyncOATHResult{
		Added:   2,
		Updated: 1,
		Skipped: 0,
		Remote: []SyncOATHCredential{
			{ID: "r1", Name: "Slack", Secret: "RSECRET", Type: "totp"},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalSyncOATHResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, 2, decoded.Added)
	assert.Equal(t, 1, decoded.Updated)
	assert.Equal(t, 0, decoded.Skipped)
	require.Len(t, decoded.Remote, 1)
}

// --- local.syncPasswords ---

func TestLocalSyncPasswordsParams_JSONRoundTrip(t *testing.T) {
	original := &LocalSyncPasswordsParams{
		Passwords: []SyncPassword{
			{ID: "p1", Name: "GitHub", Password: "pw1"},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalSyncPasswordsParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.Len(t, decoded.Passwords, 1)
	assert.Equal(t, "GitHub", decoded.Passwords[0].Name)
}

func TestLocalSyncPasswordsResult_JSONRoundTrip(t *testing.T) {
	original := &LocalSyncPasswordsResult{
		Added:   1,
		Updated: 0,
		Skipped: 2,
		Remote: []SyncPassword{
			{ID: "rp1", Name: "Remote Password", Password: "rpw"},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalSyncPasswordsResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, 1, decoded.Added)
	assert.Equal(t, 2, decoded.Skipped)
	require.Len(t, decoded.Remote, 1)
}

// --- local.syncStatus ---

func TestLocalSyncStatusParams_JSONRoundTrip(t *testing.T) {
	original := &LocalSyncStatusParams{}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalSyncStatusParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, *original, decoded)
}

func TestLocalSyncStatusResult_JSONRoundTrip(t *testing.T) {
	original := &LocalSyncStatusResult{
		LastSync:       "2025-01-15T10:30:00Z",
		DeviceID:       "phone-abc123",
		StoreChecksums: map[string]string{"trustStore": "sha256:abc", "oath": "sha256:def"},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalSyncStatusResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "2025-01-15T10:30:00Z", decoded.LastSync)
	assert.Equal(t, "phone-abc123", decoded.DeviceID)
	require.Len(t, decoded.StoreChecksums, 2)
	assert.Equal(t, "sha256:abc", decoded.StoreChecksums["trustStore"])
}

// --- remote.syncTrustStore ---

func TestRemoteSyncTrustStoreParams_JSONRoundTrip(t *testing.T) {
	original := &RemoteSyncTrustStoreParams{
		Certificates: []SyncCertificate{
			{PEM: "phone-cert-1", Fingerprint: "fp-pc1"},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteSyncTrustStoreParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.Len(t, decoded.Certificates, 1)
	assert.Equal(t, "phone-cert-1", decoded.Certificates[0].PEM)
}

func TestRemoteSyncTrustStoreResult_JSONRoundTrip(t *testing.T) {
	original := &RemoteSyncTrustStoreResult{
		Added:   2,
		Skipped: 0,
		Local: []SyncCertificate{
			{PEM: "laptop-cert", Fingerprint: "fp-lc"},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteSyncTrustStoreResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, 2, decoded.Added)
	assert.Equal(t, 0, decoded.Skipped)
	require.Len(t, decoded.Local, 1)
}

// --- remote.syncOATH ---

func TestRemoteSyncOATHParams_JSONRoundTrip(t *testing.T) {
	original := &RemoteSyncOATHParams{
		Credentials: []SyncOATHCredential{
			{ID: "pc1", Name: "Phone Cred", Secret: "PS", Type: "totp"},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteSyncOATHParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.Len(t, decoded.Credentials, 1)
	assert.Equal(t, "Phone Cred", decoded.Credentials[0].Name)
}

func TestRemoteSyncOATHResult_JSONRoundTrip(t *testing.T) {
	original := &RemoteSyncOATHResult{
		Added:   1,
		Updated: 2,
		Skipped: 3,
		Local: []SyncOATHCredential{
			{ID: "lc1", Name: "Laptop Cred", Secret: "LS", Type: "hotp"},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteSyncOATHResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, 1, decoded.Added)
	assert.Equal(t, 2, decoded.Updated)
	assert.Equal(t, 3, decoded.Skipped)
	require.Len(t, decoded.Local, 1)
}

// --- remote.syncPasswords ---

func TestRemoteSyncPasswordsParams_JSONRoundTrip(t *testing.T) {
	original := &RemoteSyncPasswordsParams{
		Passwords: []SyncPassword{
			{ID: "pp1", Name: "Phone PW", Password: "ppw"},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteSyncPasswordsParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.Len(t, decoded.Passwords, 1)
	assert.Equal(t, "Phone PW", decoded.Passwords[0].Name)
}

func TestRemoteSyncPasswordsResult_JSONRoundTrip(t *testing.T) {
	original := &RemoteSyncPasswordsResult{
		Added:   0,
		Updated: 1,
		Skipped: 0,
		Local: []SyncPassword{
			{ID: "lp1", Name: "Laptop PW", Password: "lpw"},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteSyncPasswordsResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, 0, decoded.Added)
	assert.Equal(t, 1, decoded.Updated)
	require.Len(t, decoded.Local, 1)
}

// --- remote.syncAll ---

func TestRemoteSyncAllParams_JSONRoundTrip(t *testing.T) {
	original := &RemoteSyncAllParams{
		IncludeTrustStore: true,
		IncludeOATH:       true,
		IncludePasswords:  false,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteSyncAllParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.True(t, decoded.IncludeTrustStore)
	assert.True(t, decoded.IncludeOATH)
	assert.False(t, decoded.IncludePasswords)
}

func TestRemoteSyncAllParams_JSONFieldNames(t *testing.T) {
	params := RemoteSyncAllParams{
		IncludeTrustStore: true,
		IncludeOATH:       true,
		IncludePasswords:  true,
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{"include_trust_store", "include_oath", "include_passwords"}
	for _, field := range expectedFields {
		_, ok := raw[field]
		assert.True(t, ok, "expected JSON field %q to be present", field)
	}
}

func TestRemoteSyncAllResult_JSONRoundTrip(t *testing.T) {
	original := &RemoteSyncAllResult{
		TrustStore: &RemoteSyncTrustStoreResult{
			Added:   1,
			Skipped: 0,
			Local:   []SyncCertificate{},
		},
		OATH: &RemoteSyncOATHResult{
			Added:   2,
			Updated: 1,
			Skipped: 0,
			Local:   []SyncOATHCredential{},
		},
		Passwords: &RemoteSyncPasswordsResult{
			Added:   0,
			Updated: 0,
			Skipped: 3,
			Local:   []SyncPassword{},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteSyncAllResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.NotNil(t, decoded.TrustStore)
	assert.Equal(t, 1, decoded.TrustStore.Added)
	require.NotNil(t, decoded.OATH)
	assert.Equal(t, 2, decoded.OATH.Added)
	assert.Equal(t, 1, decoded.OATH.Updated)
	require.NotNil(t, decoded.Passwords)
	assert.Equal(t, 3, decoded.Passwords.Skipped)
}

func TestRemoteSyncAllResult_OmitEmptySubResults(t *testing.T) {
	result := RemoteSyncAllResult{}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "trust_store")
	assert.NotContains(t, raw, "oath")
	assert.NotContains(t, raw, "passwords")
}

// --- remote.syncStatus ---

func TestRemoteSyncStatusParams_JSONRoundTrip(t *testing.T) {
	original := &RemoteSyncStatusParams{}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteSyncStatusParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, *original, decoded)
}

func TestRemoteSyncStatusResult_JSONRoundTrip(t *testing.T) {
	original := &RemoteSyncStatusResult{
		LastSync:       "2025-01-15T12:00:00Z",
		DeviceID:       "laptop-xyz789",
		StoreChecksums: map[string]string{"trustStore": "sha256:111", "passwords": "sha256:222"},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteSyncStatusResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "2025-01-15T12:00:00Z", decoded.LastSync)
	assert.Equal(t, "laptop-xyz789", decoded.DeviceID)
	require.Len(t, decoded.StoreChecksums, 2)
}

func TestRemoteSyncStatusResult_OmitEmpty(t *testing.T) {
	result := RemoteSyncStatusResult{
		DeviceID: "dev-1",
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	// last_sync has omitempty and should be omitted when empty.
	assert.NotContains(t, raw, "last_sync")
	// store_checksums is always present (nil serializes as null).
	assert.Contains(t, raw, "store_checksums")
}

// --- Zero-value and edge case tests ---

func TestSyncTypes_ZeroValues(t *testing.T) {
	tests := []struct {
		name string
		val  interface{}
	}{
		{"SyncCertificate", &SyncCertificate{}},
		{"SyncOATHCredential", &SyncOATHCredential{}},
		{"SyncPassword", &SyncPassword{}},
		{"LocalSyncTrustStoreParams", &LocalSyncTrustStoreParams{}},
		{"LocalSyncTrustStoreResult", &LocalSyncTrustStoreResult{}},
		{"LocalSyncOATHParams", &LocalSyncOATHParams{}},
		{"LocalSyncOATHResult", &LocalSyncOATHResult{}},
		{"LocalSyncPasswordsParams", &LocalSyncPasswordsParams{}},
		{"LocalSyncPasswordsResult", &LocalSyncPasswordsResult{}},
		{"LocalSyncStatusParams", &LocalSyncStatusParams{}},
		{"LocalSyncStatusResult", &LocalSyncStatusResult{}},
		{"RemoteSyncTrustStoreParams", &RemoteSyncTrustStoreParams{}},
		{"RemoteSyncTrustStoreResult", &RemoteSyncTrustStoreResult{}},
		{"RemoteSyncOATHParams", &RemoteSyncOATHParams{}},
		{"RemoteSyncOATHResult", &RemoteSyncOATHResult{}},
		{"RemoteSyncPasswordsParams", &RemoteSyncPasswordsParams{}},
		{"RemoteSyncPasswordsResult", &RemoteSyncPasswordsResult{}},
		{"RemoteSyncAllParams", &RemoteSyncAllParams{}},
		{"RemoteSyncAllResult", &RemoteSyncAllResult{}},
		{"RemoteSyncStatusParams", &RemoteSyncStatusParams{}},
		{"RemoteSyncStatusResult", &RemoteSyncStatusResult{}},
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

func TestSyncErrorCodeMapping(t *testing.T) {
	t.Run("SyncFailed maps correctly", func(t *testing.T) {
		mapped := MapRPCError(&RPCError{Code: ErrorCodeSyncFailed, Message: "sync failed"})
		assert.Equal(t, ErrSyncFailed, mapped)
	})

	t.Run("SyncConflict maps correctly", func(t *testing.T) {
		mapped := MapRPCError(&RPCError{Code: ErrorCodeSyncConflict, Message: "conflict"})
		assert.Equal(t, ErrSyncConflict, mapped)
	})

	t.Run("SyncRemoteUnavail maps correctly", func(t *testing.T) {
		mapped := MapRPCError(&RPCError{Code: ErrorCodeSyncRemoteUnavail, Message: "unavailable"})
		assert.Equal(t, ErrSyncRemoteUnavailable, mapped)
	})

	t.Run("SyncNoData maps correctly", func(t *testing.T) {
		mapped := MapRPCError(&RPCError{Code: ErrorCodeSyncNoData, Message: "no data"})
		assert.Equal(t, ErrSyncNoData, mapped)
	})

	t.Run("SyncVersionMismatch maps correctly", func(t *testing.T) {
		mapped := MapRPCError(&RPCError{Code: ErrorCodeSyncVersionMismatch, Message: "version mismatch"})
		assert.Equal(t, ErrSyncVersionMismatch, mapped)
	})
}

// --- NewRequest integration tests ---

func TestNewRequest_SyncMethods(t *testing.T) {
	tests := []struct {
		name   string
		method string
		params interface{}
	}{
		{
			name:   "local syncTrustStore",
			method: MethodLocalSyncTrustStore,
			params: &LocalSyncTrustStoreParams{
				Certificates: []SyncCertificate{
					{PEM: "cert", Fingerprint: "fp"},
				},
			},
		},
		{
			name:   "local syncOATH",
			method: MethodLocalSyncOATH,
			params: &LocalSyncOATHParams{
				Credentials: []SyncOATHCredential{
					{ID: "c1", Name: "Test", Secret: "S", Type: "totp"},
				},
			},
		},
		{
			name:   "local syncPasswords",
			method: MethodLocalSyncPasswords,
			params: &LocalSyncPasswordsParams{
				Passwords: []SyncPassword{
					{ID: "p1", Name: "Test", Password: "pw"},
				},
			},
		},
		{
			name:   "local syncStatus",
			method: MethodLocalSyncStatus,
			params: &LocalSyncStatusParams{},
		},
		{
			name:   "remote syncTrustStore",
			method: MethodRemoteSyncTrustStore,
			params: &RemoteSyncTrustStoreParams{
				Certificates: []SyncCertificate{
					{PEM: "phone-cert", Fingerprint: "fp"},
				},
			},
		},
		{
			name:   "remote syncOATH",
			method: MethodRemoteSyncOATH,
			params: &RemoteSyncOATHParams{
				Credentials: []SyncOATHCredential{
					{ID: "rc1", Name: "Remote", Secret: "RS", Type: "hotp"},
				},
			},
		},
		{
			name:   "remote syncPasswords",
			method: MethodRemoteSyncPasswords,
			params: &RemoteSyncPasswordsParams{
				Passwords: []SyncPassword{
					{ID: "rp1", Name: "Remote PW", Password: "rpw"},
				},
			},
		},
		{
			name:   "remote syncAll",
			method: MethodRemoteSyncAll,
			params: &RemoteSyncAllParams{
				IncludeTrustStore: true,
				IncludeOATH:       true,
				IncludePasswords:  false,
			},
		},
		{
			name:   "remote syncStatus",
			method: MethodRemoteSyncStatus,
			params: &RemoteSyncStatusParams{},
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

// --- Empty slices and collections ---

func TestSyncTypes_EmptyCollections(t *testing.T) {
	t.Run("empty certificates", func(t *testing.T) {
		original := RemoteSyncTrustStoreResult{
			Added:   0,
			Skipped: 0,
			Local:   []SyncCertificate{},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded RemoteSyncTrustStoreResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Empty(t, decoded.Local)
	})

	t.Run("empty OATH credentials", func(t *testing.T) {
		original := RemoteSyncOATHResult{
			Added:   0,
			Updated: 0,
			Skipped: 0,
			Local:   []SyncOATHCredential{},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded RemoteSyncOATHResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Empty(t, decoded.Local)
	})

	t.Run("empty passwords", func(t *testing.T) {
		original := RemoteSyncPasswordsResult{
			Added:   0,
			Updated: 0,
			Skipped: 0,
			Local:   []SyncPassword{},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded RemoteSyncPasswordsResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Empty(t, decoded.Local)
	})

	t.Run("empty store checksums", func(t *testing.T) {
		original := RemoteSyncStatusResult{
			DeviceID:       "dev-1",
			StoreChecksums: map[string]string{},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded RemoteSyncStatusResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Empty(t, decoded.StoreChecksums)
	})
}
