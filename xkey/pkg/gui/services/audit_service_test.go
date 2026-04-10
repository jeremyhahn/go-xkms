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

package services

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAuditService(t *testing.T) {
	svc := NewAuditService(nil)
	assert.NotNil(t, svc)
}

func TestAuditService_SetContext(t *testing.T) {
	svc := NewAuditService(nil)
	ctx := context.Background()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}

func TestAuditService_GetEntries_Empty(t *testing.T) {
	svc := NewAuditService(nil)
	entries, err := svc.GetEntries(nil)
	require.NoError(t, err)
	assert.NotNil(t, entries)
	assert.Empty(t, entries)
}

func TestAuditService_GetEntries_NilStoreWithFilter(t *testing.T) {
	svc := NewAuditService(nil)
	filter := &AuditFilter{
		Operation: "key_created",
		Limit:     10,
	}
	entries, err := svc.GetEntries(filter)
	require.NoError(t, err)
	assert.NotNil(t, entries)
	assert.Empty(t, entries)
}

func TestAuditService_GetEntries_WithStore(t *testing.T) {
	store, storeErr := audit.NewBackendStore(storage.NewMemory(), 100, nil)
	require.NoError(t, storeErr)
	store.LogKeyOperation(audit.OpKeyCreated, "software", "key1", true, nil, 100)
	store.LogKeyOperation(audit.OpKeyDeleted, "tpm2", "key2", true, nil, 50)
	store.LogCryptoOperation(audit.OpSignRequest, "software", "key1", "dev1", "My Device", true, nil, 25)

	svc := NewAuditService(store)

	t.Run("all entries no filter", func(t *testing.T) {
		entries, err := svc.GetEntries(nil)
		require.NoError(t, err)
		require.Len(t, entries, 3)

		assert.Equal(t, "key_created", entries[0].Operation)
		assert.Equal(t, "software", entries[0].Backend)
		assert.Equal(t, "key1", entries[0].KeyID)
		assert.True(t, entries[0].Success)
		assert.Equal(t, int64(100), entries[0].DurationMs)
	})

	t.Run("filter by operation", func(t *testing.T) {
		entries, err := svc.GetEntries(&AuditFilter{Operation: "key_deleted"})
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(t, "key_deleted", entries[0].Operation)
		assert.Equal(t, "tpm2", entries[0].Backend)
	})

	t.Run("filter by backend", func(t *testing.T) {
		entries, err := svc.GetEntries(&AuditFilter{Backend: "software"})
		require.NoError(t, err)
		require.Len(t, entries, 2)
	})

	t.Run("filter by key ID", func(t *testing.T) {
		entries, err := svc.GetEntries(&AuditFilter{KeyID: "key2"})
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(t, "key2", entries[0].KeyID)
	})

	t.Run("filter by device ID", func(t *testing.T) {
		entries, err := svc.GetEntries(&AuditFilter{DeviceID: "dev1"})
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(t, "dev1", entries[0].DeviceID)
		assert.Equal(t, "My Device", entries[0].DeviceName)
	})

	t.Run("filter by success", func(t *testing.T) {
		successTrue := true
		entries, err := svc.GetEntries(&AuditFilter{Success: &successTrue})
		require.NoError(t, err)
		assert.Len(t, entries, 3)
	})

	t.Run("filter with limit", func(t *testing.T) {
		entries, err := svc.GetEntries(&AuditFilter{Limit: 2})
		require.NoError(t, err)
		assert.Len(t, entries, 2)
	})

	t.Run("filter with time range", func(t *testing.T) {
		future := time.Now().Add(time.Hour)
		entries, err := svc.GetEntries(&AuditFilter{Since: future})
		require.NoError(t, err)
		assert.Empty(t, entries)
	})
}

func TestAuditService_GetEntries_ErrorField(t *testing.T) {
	store, storeErr := audit.NewBackendStore(storage.NewMemory(), 100, nil)
	require.NoError(t, storeErr)
	testErr := errors.New("operation failed")
	store.LogKeyOperation(audit.OpKeyCreated, "sw", "k1", false, testErr, 10)

	svc := NewAuditService(store)
	entries, err := svc.GetEntries(nil)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.False(t, entries[0].Success)
	assert.Equal(t, "operation failed", entries[0].Error)
}

func TestAuditService_ExportEntries_InvalidFormat(t *testing.T) {
	svc := NewAuditService(nil)
	_, err := svc.ExportEntries("xml", nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrAuditInvalidFormat))
}

func TestAuditService_ExportEntries_NoEntries_JSON(t *testing.T) {
	svc := NewAuditService(nil)
	_, err := svc.ExportEntries("json", nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrAuditNoEntries))
}

func TestAuditService_ExportEntries_NoEntries_CSV(t *testing.T) {
	svc := NewAuditService(nil)
	_, err := svc.ExportEntries("csv", nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrAuditNoEntries))
}

func TestAuditService_ExportEntries_JSON(t *testing.T) {
	store, storeErr := audit.NewBackendStore(storage.NewMemory(), 100, nil)
	require.NoError(t, storeErr)
	store.LogKeyOperation(audit.OpKeyCreated, "software", "test-key", true, nil, 42)
	store.LogKeyOperation(audit.OpKeyDeleted, "tpm2", "key2", true, nil, 10)

	svc := NewAuditService(store)

	data, err := svc.ExportEntries("json", nil)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	var entries []AuditEntry
	require.NoError(t, json.Unmarshal(data, &entries))
	require.Len(t, entries, 2)
	assert.Equal(t, "key_created", entries[0].Operation)
	assert.Equal(t, "key_deleted", entries[1].Operation)
}

func TestAuditService_ExportEntries_JSONWithFilter(t *testing.T) {
	store, storeErr := audit.NewBackendStore(storage.NewMemory(), 100, nil)
	require.NoError(t, storeErr)
	store.LogKeyOperation(audit.OpKeyCreated, "software", "k1", true, nil, 42)
	store.LogKeyOperation(audit.OpKeyDeleted, "tpm2", "k2", true, nil, 10)

	svc := NewAuditService(store)

	data, err := svc.ExportEntries("json", &AuditFilter{Backend: "tpm2"})
	require.NoError(t, err)

	var entries []AuditEntry
	require.NoError(t, json.Unmarshal(data, &entries))
	require.Len(t, entries, 1)
	assert.Equal(t, "key_deleted", entries[0].Operation)
}

func TestAuditService_ExportEntries_CSV(t *testing.T) {
	store, storeErr := audit.NewBackendStore(storage.NewMemory(), 100, nil)
	require.NoError(t, storeErr)
	store.LogKeyOperation(audit.OpSignRequest, "software", "sign-key", true, nil, 99)

	svc := NewAuditService(store)

	data, err := svc.ExportEntries("csv", nil)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	csvStr := string(data)
	lines := strings.Split(strings.TrimSpace(csvStr), "\n")
	require.Len(t, lines, 2) // header + 1 entry

	// Verify header.
	assert.Equal(t, "timestamp,operation,backend,key_id,device_id,device_name,success,error,duration_ms", lines[0])

	// Verify data line.
	assert.Contains(t, lines[1], "sign_request")
	assert.Contains(t, lines[1], "software")
	assert.Contains(t, lines[1], "sign-key")
	assert.Contains(t, lines[1], "true")
	assert.Contains(t, lines[1], "99")
}

func TestAuditService_ExportCSV_MultipleEntries(t *testing.T) {
	store, storeErr := audit.NewBackendStore(storage.NewMemory(), 100, nil)
	require.NoError(t, storeErr)
	store.LogKeyOperation(audit.OpKeyCreated, "sw", "k1", true, nil, 10)
	store.LogKeyOperation(audit.OpKeyDeleted, "hw", "k2", false, errors.New("denied"), 20)

	svc := NewAuditService(store)
	entries, err := svc.GetEntries(nil)
	require.NoError(t, err)

	data, csvErr := svc.exportCSV(entries)
	require.NoError(t, csvErr)

	csvStr := string(data)
	lines := strings.Split(strings.TrimSpace(csvStr), "\n")
	require.Len(t, lines, 3) // header + 2 entries

	assert.Contains(t, lines[1], "key_created")
	assert.Contains(t, lines[1], "true")
	assert.Contains(t, lines[2], "key_deleted")
	assert.Contains(t, lines[2], "false")
	assert.Contains(t, lines[2], "denied")
}

func TestBoolToStr(t *testing.T) {
	assert.Equal(t, "true", boolToStr(true))
	assert.Equal(t, "false", boolToStr(false))
}

func TestIntToStr(t *testing.T) {
	tests := []struct {
		input    int64
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{-1, "-1"},
		{12345, "12345"},
		{-9999, "-9999"},
	}
	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			assert.Equal(t, tc.expected, intToStr(tc.input))
		})
	}
}

func TestInt64ToStr(t *testing.T) {
	tests := []struct {
		input    int64
		expected string
	}{
		{0, "0"},
		{42, "42"},
		{-7, "-7"},
		{999999, "999999"},
	}
	for _, tc := range tests {
		result := int64ToStr(tc.input)
		assert.Equal(t, tc.expected, result)
	}
}
