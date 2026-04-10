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

func TestBackupMethodConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"MethodLocalCreateBackup", MethodLocalCreateBackup, "local.createBackup"},
		{"MethodLocalRestoreBackup", MethodLocalRestoreBackup, "local.restoreBackup"},
		{"MethodRemoteCreateBackup", MethodRemoteCreateBackup, "remote.createBackup"},
		{"MethodRemoteRestoreBackup", MethodRemoteRestoreBackup, "remote.restoreBackup"},
		{"MethodRemoteListBackups", MethodRemoteListBackups, "remote.listBackups"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}

	assert.Equal(t, 5, len(tests), "expected exactly 5 backup method constants")
}

func TestIsBackupLocalMethod(t *testing.T) {
	t.Run("valid backup local methods", func(t *testing.T) {
		validMethods := []string{
			MethodLocalCreateBackup,
			MethodLocalRestoreBackup,
		}
		for _, method := range validMethods {
			assert.True(t, IsBackupLocalMethod(method),
				"expected IsBackupLocalMethod(%q) to return true", method)
		}
	})

	t.Run("invalid methods", func(t *testing.T) {
		invalidMethods := []string{
			"",
			"local.sign",
			"remote.createBackup",
			"local.createBackup_typo",
		}
		for _, method := range invalidMethods {
			assert.False(t, IsBackupLocalMethod(method),
				"expected IsBackupLocalMethod(%q) to return false", method)
		}
	})
}

func TestIsBackupRemoteMethod(t *testing.T) {
	t.Run("valid backup remote methods", func(t *testing.T) {
		validMethods := []string{
			MethodRemoteCreateBackup,
			MethodRemoteRestoreBackup,
			MethodRemoteListBackups,
		}
		for _, method := range validMethods {
			assert.True(t, IsBackupRemoteMethod(method),
				"expected IsBackupRemoteMethod(%q) to return true", method)
		}
	})

	t.Run("invalid methods", func(t *testing.T) {
		invalidMethods := []string{
			"",
			"remote.sign",
			"local.createBackup",
			"remote.createBackup_typo",
		}
		for _, method := range invalidMethods {
			assert.False(t, IsBackupRemoteMethod(method),
				"expected IsBackupRemoteMethod(%q) to return false", method)
		}
	})
}

func TestBackupMethodsRegisteredInGlobalMaps(t *testing.T) {
	// Verify backup local methods are registered in the global localMethodNames map.
	assert.True(t, IsLocalMethod(MethodLocalCreateBackup))
	assert.True(t, IsLocalMethod(MethodLocalRestoreBackup))

	// Verify backup remote methods are registered in the global remoteMethodNames map.
	assert.True(t, IsRemoteMethod(MethodRemoteCreateBackup))
	assert.True(t, IsRemoteMethod(MethodRemoteRestoreBackup))
	assert.True(t, IsRemoteMethod(MethodRemoteListBackups))
}

// --- local.createBackup ---

func TestLocalCreateBackupParams_JSONRoundTrip(t *testing.T) {
	original := &LocalCreateBackupParams{
		BackupData: []byte{0xDE, 0xAD, 0xBE, 0xEF},
		Label:      "daily-backup-2025-01-15",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalCreateBackupParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.BackupData, decoded.BackupData)
	assert.Equal(t, original.Label, decoded.Label)
}

func TestLocalCreateBackupParams_JSONFieldNames(t *testing.T) {
	params := LocalCreateBackupParams{
		BackupData: []byte{0x01},
		Label:      "test",
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Contains(t, raw, "backup_data")
	assert.Contains(t, raw, "label")
}

func TestLocalCreateBackupParams_OmitEmptyLabel(t *testing.T) {
	params := LocalCreateBackupParams{
		BackupData: []byte{0x01},
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "label")
}

func TestLocalCreateBackupResult_JSONRoundTrip(t *testing.T) {
	original := &LocalCreateBackupResult{
		Success:  true,
		BackupID: "backup-abc-123",
		Message:  "stored successfully",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalCreateBackupResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Success, decoded.Success)
	assert.Equal(t, original.BackupID, decoded.BackupID)
	assert.Equal(t, original.Message, decoded.Message)
}

func TestLocalCreateBackupResult_OmitEmptyMessage(t *testing.T) {
	result := LocalCreateBackupResult{
		Success:  true,
		BackupID: "b1",
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "message")
}

func TestLocalCreateBackupResult_NotSuccess(t *testing.T) {
	original := &LocalCreateBackupResult{
		Success:  false,
		BackupID: "",
		Message:  "storage full",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalCreateBackupResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.False(t, decoded.Success)
	assert.Empty(t, decoded.BackupID)
	assert.Equal(t, "storage full", decoded.Message)
}

// --- local.restoreBackup ---

func TestLocalRestoreBackupParams_JSONRoundTrip(t *testing.T) {
	t.Run("with backup ID", func(t *testing.T) {
		original := &LocalRestoreBackupParams{
			BackupID: "backup-specific-001",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalRestoreBackupParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.BackupID, decoded.BackupID)
	})

	t.Run("without backup ID (omitempty, latest)", func(t *testing.T) {
		original := &LocalRestoreBackupParams{}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.NotContains(t, raw, "backup_id")
	})
}

func TestLocalRestoreBackupResult_JSONRoundTrip(t *testing.T) {
	original := &LocalRestoreBackupResult{
		BackupData: []byte{0xCA, 0xFE, 0xBA, 0xBE},
		BackupID:   "backup-001",
		CreatedAt:  "2025-01-15T10:30:00Z",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalRestoreBackupResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.BackupData, decoded.BackupData)
	assert.Equal(t, original.BackupID, decoded.BackupID)
	assert.Equal(t, original.CreatedAt, decoded.CreatedAt)
}

func TestLocalRestoreBackupResult_JSONFieldNames(t *testing.T) {
	result := LocalRestoreBackupResult{
		BackupData: []byte{0x01},
		BackupID:   "b1",
		CreatedAt:  "2025-01-15T10:30:00Z",
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{"backup_data", "backup_id", "created_at"}
	for _, field := range expectedFields {
		assert.Contains(t, raw, field, "expected JSON field %q", field)
	}
}

// --- remote.createBackup ---

func TestRemoteCreateBackupParams_JSONRoundTrip(t *testing.T) {
	original := &RemoteCreateBackupParams{
		IncludeTrustStore: true,
		IncludeOATH:       true,
		IncludePasswords:  false,
		IncludeCA:         true,
		Label:             "full-backup",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteCreateBackupParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.IncludeTrustStore, decoded.IncludeTrustStore)
	assert.Equal(t, original.IncludeOATH, decoded.IncludeOATH)
	assert.Equal(t, original.IncludePasswords, decoded.IncludePasswords)
	assert.Equal(t, original.IncludeCA, decoded.IncludeCA)
	assert.Equal(t, original.Label, decoded.Label)
}

func TestRemoteCreateBackupParams_JSONFieldNames(t *testing.T) {
	params := RemoteCreateBackupParams{
		IncludeTrustStore: true,
		IncludeOATH:       true,
		IncludePasswords:  true,
		IncludeCA:         true,
		Label:             "test",
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{
		"include_trust_store", "include_oath", "include_passwords",
		"include_ca", "label",
	}
	for _, field := range expectedFields {
		assert.Contains(t, raw, field, "expected JSON field %q", field)
	}
}

func TestRemoteCreateBackupParams_OmitEmptyLabel(t *testing.T) {
	params := RemoteCreateBackupParams{
		IncludeTrustStore: true,
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "label")
}

func TestRemoteCreateBackupResult_JSONRoundTrip(t *testing.T) {
	original := &RemoteCreateBackupResult{
		BackupData: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		BackupID:   "backup-remote-001",
		ItemCount:  42,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteCreateBackupResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.BackupData, decoded.BackupData)
	assert.Equal(t, original.BackupID, decoded.BackupID)
	assert.Equal(t, original.ItemCount, decoded.ItemCount)
}

func TestRemoteCreateBackupResult_JSONFieldNames(t *testing.T) {
	result := RemoteCreateBackupResult{
		BackupData: []byte{0x01},
		BackupID:   "b1",
		ItemCount:  1,
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{"backup_data", "backup_id", "item_count"}
	for _, field := range expectedFields {
		assert.Contains(t, raw, field, "expected JSON field %q", field)
	}
}

// --- remote.restoreBackup ---

func TestRemoteRestoreBackupParams_JSONRoundTrip(t *testing.T) {
	original := &RemoteRestoreBackupParams{
		BackupData: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteRestoreBackupParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.BackupData, decoded.BackupData)
}

func TestRemoteRestoreBackupParams_JSONFieldNames(t *testing.T) {
	params := RemoteRestoreBackupParams{
		BackupData: []byte{0x01},
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Contains(t, raw, "backup_data")
}

func TestRemoteRestoreBackupResult_JSONRoundTrip(t *testing.T) {
	original := &RemoteRestoreBackupResult{
		Success:  true,
		Restored: []string{"trust_store", "oath", "ca"},
		Message:  "restored 42 items",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteRestoreBackupResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Success, decoded.Success)
	assert.Equal(t, original.Restored, decoded.Restored)
	assert.Equal(t, original.Message, decoded.Message)
}

func TestRemoteRestoreBackupResult_OmitEmptyMessage(t *testing.T) {
	result := RemoteRestoreBackupResult{
		Success:  true,
		Restored: []string{"trust_store"},
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "message")
}

func TestRemoteRestoreBackupResult_EmptyRestored(t *testing.T) {
	original := &RemoteRestoreBackupResult{
		Success:  false,
		Restored: []string{},
		Message:  "nothing to restore",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteRestoreBackupResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.False(t, decoded.Success)
	assert.Empty(t, decoded.Restored)
}

// --- remote.listBackups ---

func TestRemoteListBackupsParams_JSONRoundTrip(t *testing.T) {
	original := &RemoteListBackupsParams{}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteListBackupsParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Empty struct, just verify valid JSON round-trip.
	assert.Equal(t, *original, decoded)
}

func TestRemoteListBackupsResult_JSONRoundTrip(t *testing.T) {
	original := &RemoteListBackupsResult{
		Backups: []BackupInfo{
			{
				BackupID:  "backup-001",
				CreatedAt: "2025-01-14T08:00:00Z",
				Label:     "morning backup",
				Size:      1048576,
			},
			{
				BackupID:  "backup-002",
				CreatedAt: "2025-01-15T08:00:00Z",
				Size:      2097152,
			},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteListBackupsResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.Len(t, decoded.Backups, 2)
	assert.Equal(t, original.Backups[0].BackupID, decoded.Backups[0].BackupID)
	assert.Equal(t, original.Backups[0].CreatedAt, decoded.Backups[0].CreatedAt)
	assert.Equal(t, original.Backups[0].Label, decoded.Backups[0].Label)
	assert.Equal(t, original.Backups[0].Size, decoded.Backups[0].Size)
	assert.Equal(t, original.Backups[1].BackupID, decoded.Backups[1].BackupID)
	assert.Empty(t, decoded.Backups[1].Label)
}

func TestRemoteListBackupsResult_EmptyBackups(t *testing.T) {
	original := &RemoteListBackupsResult{
		Backups: []BackupInfo{},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteListBackupsResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Empty(t, decoded.Backups)
}

// --- BackupInfo ---

func TestBackupInfo_JSONRoundTrip(t *testing.T) {
	original := BackupInfo{
		BackupID:  "backup-info-001",
		CreatedAt: "2025-01-15T12:00:00Z",
		Label:     "test backup",
		Size:      512000,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded BackupInfo
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original, decoded)
}

func TestBackupInfo_JSONFieldNames(t *testing.T) {
	info := BackupInfo{
		BackupID:  "b1",
		CreatedAt: "2025-01-15T12:00:00Z",
		Label:     "test",
		Size:      100,
	}

	data, err := json.Marshal(info)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{"backup_id", "created_at", "label", "size"}
	for _, field := range expectedFields {
		assert.Contains(t, raw, field, "expected JSON field %q", field)
	}
}

func TestBackupInfo_OmitEmptyLabel(t *testing.T) {
	info := BackupInfo{
		BackupID:  "b1",
		CreatedAt: "2025-01-15T12:00:00Z",
		Size:      100,
	}

	data, err := json.Marshal(info)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "label")
}

// --- Zero-value and edge case tests ---

func TestBackupTypes_ZeroValues(t *testing.T) {
	tests := []struct {
		name string
		val  interface{}
	}{
		{"LocalCreateBackupParams", &LocalCreateBackupParams{}},
		{"LocalCreateBackupResult", &LocalCreateBackupResult{}},
		{"LocalRestoreBackupParams", &LocalRestoreBackupParams{}},
		{"LocalRestoreBackupResult", &LocalRestoreBackupResult{}},
		{"RemoteCreateBackupParams", &RemoteCreateBackupParams{}},
		{"RemoteCreateBackupResult", &RemoteCreateBackupResult{}},
		{"RemoteRestoreBackupParams", &RemoteRestoreBackupParams{}},
		{"RemoteRestoreBackupResult", &RemoteRestoreBackupResult{}},
		{"RemoteListBackupsParams", &RemoteListBackupsParams{}},
		{"RemoteListBackupsResult", &RemoteListBackupsResult{}},
		{"BackupInfo", &BackupInfo{}},
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

func TestBackupErrorCodeMapping(t *testing.T) {
	t.Run("backup failed maps correctly", func(t *testing.T) {
		mapped := MapRPCError(&RPCError{Code: ErrorCodeBackupFailed, Message: "failed"})
		assert.Equal(t, ErrBackupFailed, mapped)
	})

	t.Run("backup restore maps correctly", func(t *testing.T) {
		mapped := MapRPCError(&RPCError{Code: ErrorCodeBackupRestore, Message: "restore failed"})
		assert.Equal(t, ErrBackupRestoreFailed, mapped)
	})

	t.Run("backup not found maps correctly", func(t *testing.T) {
		mapped := MapRPCError(&RPCError{Code: ErrorCodeBackupNotFound, Message: "not found"})
		assert.Equal(t, ErrBackupNotFound, mapped)
	})
}

// --- NewRequest integration tests ---

func TestNewRequest_BackupMethods(t *testing.T) {
	tests := []struct {
		name   string
		method string
		params interface{}
	}{
		{
			name:   "local createBackup",
			method: MethodLocalCreateBackup,
			params: &LocalCreateBackupParams{
				BackupData: []byte{0x01, 0x02, 0x03},
				Label:      "test-backup",
			},
		},
		{
			name:   "local restoreBackup",
			method: MethodLocalRestoreBackup,
			params: &LocalRestoreBackupParams{
				BackupID: "backup-001",
			},
		},
		{
			name:   "remote createBackup",
			method: MethodRemoteCreateBackup,
			params: &RemoteCreateBackupParams{
				IncludeTrustStore: true,
				IncludeCA:         true,
				Label:             "full-backup",
			},
		},
		{
			name:   "remote restoreBackup",
			method: MethodRemoteRestoreBackup,
			params: &RemoteRestoreBackupParams{
				BackupData: []byte{0xDE, 0xAD, 0xBE, 0xEF},
			},
		},
		{
			name:   "remote listBackups",
			method: MethodRemoteListBackups,
			params: &RemoteListBackupsParams{},
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
