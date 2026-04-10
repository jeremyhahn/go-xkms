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

//go:build linux

package services

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/autofill"
	"github.com/jeremyhahn/go-xkms/pkg/sharestore"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/tokenstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// Shared mock audit logger
// ===========================================================================

type miscCoverageAuditLogger struct {
	entries []audit.Entry
}

func (l *miscCoverageAuditLogger) Log(e audit.Entry) { l.entries = append(l.entries, e) }
func (l *miscCoverageAuditLogger) LogKeyOperation(op audit.OperationType, backend, keyID string, success bool, err error, durationMs int64) {
	l.Log(audit.Entry{Operation: op, Backend: backend, KeyID: keyID, Success: success})
}
func (l *miscCoverageAuditLogger) LogCryptoOperation(audit.OperationType, string, string, string, string, bool, error, int64) {
}
func (l *miscCoverageAuditLogger) LogConnectionEvent(audit.OperationType, string, string, map[string]any) {
}
func (l *miscCoverageAuditLogger) LogServiceEvent(op audit.OperationType, details map[string]any) {
	l.Log(audit.Entry{Operation: op, Details: details, Success: true})
}
func (l *miscCoverageAuditLogger) LogPINOperation(audit.OperationType, string, bool, error, map[string]any) {
}
func (l *miscCoverageAuditLogger) LogTPMOperation(audit.OperationType, bool, error, map[string]any) {
}
func (l *miscCoverageAuditLogger) LogPasswordStoreOperation(audit.OperationType, string, bool, error, map[string]any) {
}
func (l *miscCoverageAuditLogger) LogUserPresenceEvent(audit.OperationType, string, bool, map[string]any) {
}

// ===========================================================================
// StorageService tests
// ===========================================================================

func TestMiscServices_Coverage_StorageService_New(t *testing.T) {
	svc := NewStorageService()
	require.NotNil(t, svc)
	assert.NotNil(t, svc.log)
	assert.Nil(t, svc.elevator)
}

func TestMiscServices_Coverage_StorageService_SetContext(t *testing.T) {
	svc := NewStorageService()
	ctx := context.Background()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}

func TestMiscServices_Coverage_StorageService_SetElevator(t *testing.T) {
	svc := NewStorageService()
	elevator := &mockElevator{available: true}
	svc.SetElevator(elevator)
	assert.NotNil(t, svc.elevator)
}

func TestMiscServices_Coverage_ValidateVolumeSize(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		wantErr error
	}{
		{"valid min", 1, nil},
		{"valid mid", 50, nil},
		{"valid max", 100, nil},
		{"too small", 0, ErrStorageInvalidSize},
		{"too large", 101, ErrStorageInvalidSize},
		{"negative", -1, ErrStorageInvalidSize},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateVolumeSize(tc.size)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMiscServices_Coverage_ValidatePassphrase(t *testing.T) {
	tests := []struct {
		name       string
		passphrase string
		wantErr    error
	}{
		{"valid 8 chars", "12345678", nil},
		{"valid longer", "a-longer-passphrase", nil},
		{"too short 7", "1234567", ErrStorageWeakPassphrase},
		{"empty", "", ErrStorageWeakPassphrase},
		{"single char", "a", ErrStorageWeakPassphrase},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePassphrase(tc.passphrase)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMiscServices_Coverage_StorageService_RunElevatedCmd_NilElevator(t *testing.T) {
	svc := NewStorageService()
	err := svc.runElevatedCmd([]string{"test"}, nil)
	assert.ErrorIs(t, err, ErrStorageRequiresRoot)
}

func TestMiscServices_Coverage_StorageService_RunElevatedCmd_UnavailableElevator(t *testing.T) {
	svc := NewStorageService()
	svc.SetElevator(&mockElevator{available: false})
	err := svc.runElevatedCmd([]string{"test"}, nil)
	assert.ErrorIs(t, err, ErrStorageRequiresRoot)
}

func TestMiscServices_Coverage_StorageService_RunElevatedCmd_ElevatorError(t *testing.T) {
	svc := NewStorageService()
	svc.SetElevator(&mockElevator{available: true, err: errors.New("cmd failed")})
	err := svc.runElevatedCmd([]string{"test"}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cmd failed")
}

func TestMiscServices_Coverage_StorageService_RunElevatedCmd_Success(t *testing.T) {
	svc := NewStorageService()
	svc.SetElevator(&mockElevator{available: true})
	err := svc.runElevatedCmd([]string{"test"}, nil)
	assert.NoError(t, err)
}

func TestMiscServices_Coverage_StorageService_CreateVolume_InvalidSize(t *testing.T) {
	svc := NewStorageService()
	err := svc.CreateVolume(CreateVolumeParams{SizeGB: 0, Passphrase: "12345678"})
	assert.ErrorIs(t, err, ErrStorageInvalidSize)
}

func TestMiscServices_Coverage_StorageService_CreateVolume_WeakPassphrase(t *testing.T) {
	svc := NewStorageService()
	err := svc.CreateVolume(CreateVolumeParams{SizeGB: 5, Passphrase: "short"})
	assert.ErrorIs(t, err, ErrStorageWeakPassphrase)
}

func TestMiscServices_Coverage_StorageService_UnlockVolume_WeakPassphrase(t *testing.T) {
	svc := NewStorageService()
	err := svc.UnlockVolume("short")
	assert.ErrorIs(t, err, ErrStorageWeakPassphrase)
}

func TestMiscServices_Coverage_StorageService_MigrateToEncrypted_InvalidSize(t *testing.T) {
	svc := NewStorageService()
	err := svc.MigrateToEncrypted(0, "12345678", false)
	assert.ErrorIs(t, err, ErrStorageInvalidSize)
}

func TestMiscServices_Coverage_StorageService_MigrateToEncrypted_WeakPassphrase(t *testing.T) {
	svc := NewStorageService()
	err := svc.MigrateToEncrypted(5, "short", false)
	assert.ErrorIs(t, err, ErrStorageWeakPassphrase)
}

func TestMiscServices_Coverage_StorageService_WipeVolume_InvalidStandard(t *testing.T) {
	svc := NewStorageService()
	err := svc.WipeVolume("invalid-standard")
	assert.ErrorIs(t, err, ErrStorageInvalidStandard)
}

func TestMiscServices_Coverage_WipeStandards(t *testing.T) {
	_, ok := wipeStandards["nist"]
	assert.True(t, ok)
	_, ok = wipeStandards["dod3"]
	assert.True(t, ok)
	_, ok = wipeStandards["dod7"]
	assert.True(t, ok)
}

// ===========================================================================
// ShareService tests
// ===========================================================================

func TestMiscServices_Coverage_ShareService_New(t *testing.T) {
	svc := NewShareService()
	require.NotNil(t, svc)
	assert.NotNil(t, svc.log)
}

func TestMiscServices_Coverage_ShareService_SetContext(t *testing.T) {
	svc := NewShareService()
	ctx := context.Background()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}

func TestMiscServices_Coverage_ShareService_SetEventEmitter(t *testing.T) {
	svc := NewShareService()
	var emitted []events.Event
	svc.SetEventEmitter(func(e events.Event) {
		emitted = append(emitted, e)
	})
	assert.NotNil(t, svc.emitter)
}

func TestMiscServices_Coverage_ShareService_SetShareStore(t *testing.T) {
	svc := NewShareService()
	store := &mockShareStore{}
	svc.SetShareStore(store)
	assert.NotNil(t, svc.store)
}

func TestMiscServices_Coverage_ShareService_ListShares_NilStore(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())

	result, err := svc.ListShares()
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrShareStoreNil)
}

func TestMiscServices_Coverage_ShareService_ListShares_Success(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())

	store := &mockShareStore{
		listResult: []*sharestore.ShareEntry{
			{
				ServerURL:  "https://example.com",
				GroupID:    "grp1",
				ShareIndex: 0,
				ReceivedAt: time.Now(),
			},
		},
	}
	svc.SetShareStore(store)

	result, err := svc.ListShares()
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "https://example.com", result[0].ServerURL)
	assert.Equal(t, "grp1", result[0].GroupID)
}

func TestMiscServices_Coverage_ShareService_ListShares_Error(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())

	store := &mockShareStore{listErr: errors.New("list failed")}
	svc.SetShareStore(store)

	result, err := svc.ListShares()
	assert.Nil(t, result)
	assert.Error(t, err)
}

func TestMiscServices_Coverage_ShareService_ImportShare_EmptyPath(t *testing.T) {
	svc := NewShareService()
	result, err := svc.ImportShare("")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrEmptyFilePath)
}

func TestMiscServices_Coverage_ShareService_ImportShare_NilStore(t *testing.T) {
	svc := NewShareService()
	result, err := svc.ImportShare("/tmp/test.json")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrShareStoreNil)
}

func TestMiscServices_Coverage_ShareService_ImportShare_FileNotFound(t *testing.T) {
	svc := NewShareService()
	svc.SetShareStore(&mockShareStore{})
	result, err := svc.ImportShare("/nonexistent/share.json")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrShareImportFailed)
}

func TestMiscServices_Coverage_ShareService_ImportShare_InvalidJSON(t *testing.T) {
	svc := NewShareService()
	svc.SetShareStore(&mockShareStore{})

	tmpDir := t.TempDir()
	fp := filepath.Join(tmpDir, "bad.json")
	require.NoError(t, os.WriteFile(fp, []byte("not json"), 0600))

	result, err := svc.ImportShare(fp)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrShareImportFailed)
}

func TestMiscServices_Coverage_ShareService_DeleteShare_EmptyServerURL(t *testing.T) {
	svc := NewShareService()
	err := svc.DeleteShare("", "grp1", 0)
	assert.ErrorIs(t, err, ErrEmptyServerURL)
}

func TestMiscServices_Coverage_ShareService_DeleteShare_EmptyGroupID(t *testing.T) {
	svc := NewShareService()
	err := svc.DeleteShare("https://example.com", "", 0)
	assert.ErrorIs(t, err, ErrEmptyGroupID)
}

func TestMiscServices_Coverage_ShareService_DeleteShare_NilStore(t *testing.T) {
	svc := NewShareService()
	err := svc.DeleteShare("https://example.com", "grp1", 0)
	assert.ErrorIs(t, err, ErrShareStoreNil)
}

func TestMiscServices_Coverage_ShareService_DeleteShare_Success(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())

	var emittedEvents []events.Event
	svc.SetEventEmitter(func(e events.Event) {
		emittedEvents = append(emittedEvents, e)
	})

	store := &mockShareStore{}
	svc.SetShareStore(store)

	err := svc.DeleteShare("https://example.com", "grp1", 0)
	require.NoError(t, err)
	assert.Len(t, emittedEvents, 1)
	assert.Equal(t, events.EventShareDeleted, emittedEvents[0].Type)
}

func TestMiscServices_Coverage_ShareService_ReceiveShares_EmptyURL(t *testing.T) {
	svc := NewShareService()
	result, err := svc.ReceiveShares("", "")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrEmptyServerURL)
}

func TestMiscServices_Coverage_ShareService_ReceiveShares_NilStore(t *testing.T) {
	svc := NewShareService()
	result, err := svc.ReceiveShares("https://example.com", "")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrShareStoreNil)
}

func TestMiscServices_Coverage_ShareService_SubmitShare_EmptyURL(t *testing.T) {
	svc := NewShareService()
	err := svc.SubmitShare("", "grp1", 0, "")
	assert.ErrorIs(t, err, ErrEmptyServerURL)
}

func TestMiscServices_Coverage_ShareService_SubmitShare_EmptyGroupID(t *testing.T) {
	svc := NewShareService()
	err := svc.SubmitShare("https://example.com", "", 0, "")
	assert.ErrorIs(t, err, ErrEmptyGroupID)
}

func TestMiscServices_Coverage_ShareService_SubmitShare_NilStore(t *testing.T) {
	svc := NewShareService()
	err := svc.SubmitShare("https://example.com", "grp1", 0, "")
	assert.ErrorIs(t, err, ErrShareStoreNil)
}

func TestMiscServices_Coverage_ShareService_GetShareStatus_EmptyURL(t *testing.T) {
	svc := NewShareService()
	result, err := svc.GetShareStatus("", "grp1", "")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrEmptyServerURL)
}

func TestMiscServices_Coverage_ShareService_GetShareStatus_EmptyGroupID(t *testing.T) {
	svc := NewShareService()
	result, err := svc.GetShareStatus("https://example.com", "", "")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrEmptyGroupID)
}

func TestMiscServices_Coverage_ShareService_Emit_NilEmitter(t *testing.T) {
	svc := NewShareService()
	// Should not panic.
	svc.emit(events.EventShareImported, nil)
}

func TestMiscServices_Coverage_ShareService_Emit_WithEmitter(t *testing.T) {
	svc := NewShareService()
	var emitted []events.Event
	svc.SetEventEmitter(func(e events.Event) {
		emitted = append(emitted, e)
	})

	svc.emit(events.EventShareImported, "test-payload")
	require.Len(t, emitted, 1)
	assert.Equal(t, events.EventShareImported, emitted[0].Type)
}

func TestMiscServices_Coverage_EntryToShareInfo(t *testing.T) {
	now := time.Now()
	entry := &sharestore.ShareEntry{
		ServerURL:  "https://example.com",
		GroupID:    "grp-abc",
		GroupName:  "Test Group",
		ShareIndex: 2,
		Purpose:    "barrier-unseal",
		ReceivedAt: now,
		TenantID:   "tenant-1",
	}
	info := entryToShareInfo(entry)
	assert.Equal(t, "https://example.com", info.ServerURL)
	assert.Equal(t, "grp-abc", info.GroupID)
	assert.Equal(t, "Test Group", info.GroupName)
	assert.Equal(t, 2, info.ShareIndex)
	assert.Equal(t, "barrier-unseal", info.Purpose)
	assert.Equal(t, now.Format(time.RFC3339), info.ReceivedAt)
	assert.Equal(t, "tenant-1", info.TenantID)
}

// mockShareStore implements sharestore.ShareStore for testing.
type mockShareStore struct {
	listResult []*sharestore.ShareEntry
	listErr    error
	saveErr    error
	loadResult *sharestore.ShareEntry
	loadErr    error
	deleteErr  error
}

func (m *mockShareStore) Save(ctx context.Context, entry *sharestore.ShareEntry) error {
	return m.saveErr
}
func (m *mockShareStore) Load(ctx context.Context, serverURL, groupID string, shareIndex int) (*sharestore.ShareEntry, error) {
	return m.loadResult, m.loadErr
}
func (m *mockShareStore) Delete(ctx context.Context, serverURL, groupID string, shareIndex int) error {
	return m.deleteErr
}
func (m *mockShareStore) List(ctx context.Context) ([]*sharestore.ShareEntry, error) {
	return m.listResult, m.listErr
}
func (m *mockShareStore) ListByServer(ctx context.Context, serverURL string) ([]*sharestore.ShareEntry, error) {
	return nil, nil
}
func (m *mockShareStore) ListByGroup(ctx context.Context, groupID string) ([]*sharestore.ShareEntry, error) {
	return nil, nil
}
func (m *mockShareStore) Close() error { return nil }

// ===========================================================================
// AutoFillService tests
// ===========================================================================

func TestMiscServices_Coverage_AutoFillService_New(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	require.NotNil(t, svc)
	assert.False(t, svc.IsEnabled())
	assert.NotNil(t, svc.GetPolicy())
}

func TestMiscServices_Coverage_AutoFillService_SetContext(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	ctx := context.Background()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}

func TestMiscServices_Coverage_AutoFillService_SetEnabled(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)

	err := svc.SetEnabled(true)
	require.NoError(t, err)
	assert.True(t, svc.IsEnabled())

	err = svc.SetEnabled(false)
	require.NoError(t, err)
	assert.False(t, svc.IsEnabled())
}

func TestMiscServices_Coverage_AutoFillService_SetEnabled_EnterpriseBlocks(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	svc.SetEnterprisePolicy(&EnterpriseExtensionPolicy{Enabled: false})

	err := svc.SetEnabled(true)
	assert.ErrorIs(t, err, ErrAutoFillPolicyEnforced)
	assert.False(t, svc.IsEnabled())
}

func TestMiscServices_Coverage_AutoFillService_SetEnabled_EnterpriseAllows(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	svc.SetEnterprisePolicy(&EnterpriseExtensionPolicy{Enabled: true})

	err := svc.SetEnabled(true)
	require.NoError(t, err)
	assert.True(t, svc.IsEnabled())
}

func TestMiscServices_Coverage_AutoFillService_SetPolicyPersistFunc(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	called := false
	svc.SetPolicyPersistFunc(func(policy *autofill.AutoFillPolicy) error {
		called = true
		return nil
	})
	assert.NotNil(t, svc.persistPolicy)

	err := svc.persistPolicy(&autofill.AutoFillPolicy{})
	require.NoError(t, err)
	assert.True(t, called)
}

func TestMiscServices_Coverage_AutoFillService_SetRegistrationDir(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	svc.SetRegistrationDir("/tmp/test-dir")
	assert.Equal(t, "/tmp/test-dir", svc.registrationDir)
}

func TestMiscServices_Coverage_AutoFillService_SetAuthenticator(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	svc.SetAuthenticator(nil)
	assert.Nil(t, svc.auth)
	assert.Nil(t, svc.verifier)
	assert.Nil(t, svc.credID)
}

func TestMiscServices_Coverage_AutoFillService_SetEnterprisePolicy(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)

	ep := &EnterpriseExtensionPolicy{
		Enabled:               true,
		RequireAuthentication: true,
		ForceAudit:            true,
		MaxFillsPerMinute:     30,
	}
	svc.SetEnterprisePolicy(ep)

	got := svc.GetEnterprisePolicy()
	require.NotNil(t, got)
	assert.True(t, got.Enabled)
	assert.True(t, got.RequireAuthentication)
	assert.True(t, got.ForceAudit)
	assert.Equal(t, 30, got.MaxFillsPerMinute)
}

func TestMiscServices_Coverage_AutoFillService_SetEnterprisePolicy_Nil(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	svc.SetEnterprisePolicy(nil)
	assert.Nil(t, svc.GetEnterprisePolicy())
}

func TestMiscServices_Coverage_AutoFillService_SetPolicy_Nil(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	err := svc.SetPolicy(nil)
	assert.ErrorIs(t, err, ErrAutoFillNotConfigured)
}

func TestMiscServices_Coverage_AutoFillService_SetPolicy_Valid(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	policy := autofill.DefaultPolicy()
	policy.MaxFillsPerMinute = 20
	err := svc.SetPolicy(policy)
	require.NoError(t, err)

	got := svc.GetPolicy()
	assert.Equal(t, 20, got.MaxFillsPerMinute)
}

func TestMiscServices_Coverage_AutoFillService_GetRequireAuthentication(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	// Default policy has RequireAuthentication = true.
	assert.True(t, svc.GetRequireAuthentication())
}

func TestMiscServices_Coverage_AutoFillService_SetRequireAuthentication(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	err := svc.SetRequireAuthentication(false)
	require.NoError(t, err)
	assert.False(t, svc.GetRequireAuthentication())
}

func TestMiscServices_Coverage_AutoFillService_SetRequireAuthentication_EnterpriseBlocks(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	svc.SetEnterprisePolicy(&EnterpriseExtensionPolicy{
		Enabled:               true,
		RequireAuthentication: true,
	})

	err := svc.SetRequireAuthentication(false)
	assert.ErrorIs(t, err, ErrAutoFillPolicyEnforced)
}

func TestMiscServices_Coverage_AutoFillService_SetRequireAuthentication_WithPersist(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	var persisted *autofill.AutoFillPolicy
	svc.SetPolicyPersistFunc(func(policy *autofill.AutoFillPolicy) error {
		persisted = policy
		return nil
	})

	err := svc.SetRequireAuthentication(false)
	require.NoError(t, err)
	assert.NotNil(t, persisted)
	assert.False(t, persisted.RequireAuthentication)
}

func TestMiscServices_Coverage_AutoFillService_GetStatus(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	svc.SetEnabled(true)

	status := svc.GetStatus()
	require.NotNil(t, status)
	assert.False(t, status.Available) // passwordSvc is nil
	assert.False(t, status.AppLocked)
	assert.True(t, status.ExtensionEnabled)
}

func TestMiscServices_Coverage_AutoFillService_GetAutoFillPolicy(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	result := svc.GetAutoFillPolicy()
	require.NotNil(t, result)
	assert.NotEmpty(t, result.FillMode)
	assert.True(t, result.RequireAuthentication) // default
}

func TestMiscServices_Coverage_AutoFillService_CheckPreconditions_Disabled(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	err := svc.checkPreconditions()
	assert.ErrorIs(t, err, ErrAutoFillDisabled)
}

func TestMiscServices_Coverage_AutoFillService_CheckPreconditions_EnterpriseDisabled(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	svc.SetEnabled(true)
	svc.SetEnterprisePolicy(&EnterpriseExtensionPolicy{Enabled: false})

	err := svc.checkPreconditions()
	assert.ErrorIs(t, err, ErrAutoFillDisabled)
}

func TestMiscServices_Coverage_AutoFillService_CheckPreconditions_Enabled(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	svc.SetEnabled(true)

	err := svc.checkPreconditions()
	assert.NoError(t, err)
}

func TestMiscServices_Coverage_AutoFillService_SearchCredentials_Disabled(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	result, err := svc.SearchCredentials("example.com")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrAutoFillDisabled)
}

func TestMiscServices_Coverage_AutoFillService_GetCredential_Disabled(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	result, err := svc.GetCredential("id", "challenge")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrAutoFillDisabled)
}

func TestMiscServices_Coverage_AutoFillService_GetCredential_EmptyID(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	svc.SetEnabled(true)
	// Set policy to not require auth for this test.
	policy := autofill.DefaultPolicy()
	policy.RequireAuthentication = false
	svc.SetPolicy(policy)

	result, err := svc.GetCredential("", "")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrAutoFillInvalidID)
}

func TestMiscServices_Coverage_AutoFillService_GetTOTPForDomain_Disabled(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	result, err := svc.GetTOTPForDomain("example.com")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrAutoFillDisabled)
}

func TestMiscServices_Coverage_AutoFillService_GetTOTPByID_Disabled(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	result, err := svc.GetTOTPByID("id")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrAutoFillDisabled)
}

func TestMiscServices_Coverage_AutoFillService_GetTOTPByID_EmptyID(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	svc.SetEnabled(true)
	// oathSvc is nil, so ErrAutoFillNotConfigured is returned before checking empty ID.
	result, err := svc.GetTOTPByID("")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrAutoFillNotConfigured)
}

func TestMiscServices_Coverage_AutoFillService_GetTOTPByID_NilOathSvc(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	svc.SetEnabled(true)
	result, err := svc.GetTOTPByID("id")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrAutoFillNotConfigured)
}

func TestMiscServices_Coverage_AutoFillService_GetTOTPForDomain_NilOathSvc(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	svc.SetEnabled(true)
	result, err := svc.GetTOTPForDomain("example.com")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrAutoFillNotConfigured)
}

func TestMiscServices_Coverage_ExtractDomainBase(t *testing.T) {
	tests := []struct {
		domain   string
		expected string
	}{
		{"github.com", "github"},
		{"mail.google.com", "mail.google"},
		{"localhost", "localhost"},
		{"", ""},
		{"  EXAMPLE.COM  ", "example"},
		{".com", ".com"},
	}
	for _, tc := range tests {
		t.Run(tc.domain, func(t *testing.T) {
			result := extractDomainBase(tc.domain)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestMiscServices_Coverage_AutoFillService_IsEnterpriseDomainAllowed(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)

	tests := []struct {
		name     string
		ep       *EnterpriseExtensionPolicy
		domain   string
		expected bool
	}{
		{
			name:     "no restrictions",
			ep:       &EnterpriseExtensionPolicy{},
			domain:   "example.com",
			expected: true,
		},
		{
			name:     "blocked domain",
			ep:       &EnterpriseExtensionPolicy{BlockedDomains: []string{"evil.com"}},
			domain:   "evil.com",
			expected: false,
		},
		{
			name:     "allowed domain only",
			ep:       &EnterpriseExtensionPolicy{AllowedDomains: []string{"good.com"}},
			domain:   "good.com",
			expected: true,
		},
		{
			name:     "not in allowed list",
			ep:       &EnterpriseExtensionPolicy{AllowedDomains: []string{"good.com"}},
			domain:   "other.com",
			expected: false,
		},
		{
			name:     "case insensitive blocking",
			ep:       &EnterpriseExtensionPolicy{BlockedDomains: []string{"EVIL.COM"}},
			domain:   "evil.com",
			expected: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := svc.isEnterpriseDomainAllowed(tc.ep, tc.domain)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestMiscServices_Coverage_AutoFillService_AuditPreconditionFailure_NilAudit(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	// Should not panic.
	svc.auditPreconditionFailure(opAutoFillSearch, "detail", ErrAutoFillDisabled)
}

func TestMiscServices_Coverage_AutoFillService_AuditPreconditionFailure_WithAudit(t *testing.T) {
	al := &miscCoverageAuditLogger{}
	svc := NewAutoFillService(nil, nil, nil, al, nil)
	svc.auditPreconditionFailure(opAutoFillSearch, "example.com", ErrAutoFillDisabled)
	assert.Len(t, al.entries, 1)
}

// ---------------------------------------------------------------------------
// IPC AutofillHandler interface tests
// ---------------------------------------------------------------------------

func TestMiscServices_Coverage_AutoFillService_HandleAutofillStatus(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	result, err := svc.HandleAutofillStatus()
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotNil(t, result.Status)
}

func TestMiscServices_Coverage_AutoFillService_HandleAutofillPolicy(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	result, err := svc.HandleAutofillPolicy()
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotNil(t, result.Policy)
}

func TestMiscServices_Coverage_AutoFillService_HandleAutofillSearch_Disabled(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	result, err := svc.HandleAutofillSearch("example.com")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrAutoFillDisabled)
}

func TestMiscServices_Coverage_AutoFillService_HandleAutofillGet_Disabled(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	result, err := svc.HandleAutofillGet("id", "challenge")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrAutoFillDisabled)
}

func TestMiscServices_Coverage_AutoFillService_HandleAutofillTOTP_Disabled(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	result, err := svc.HandleAutofillTOTP("example.com")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrAutoFillDisabled)
}

func TestMiscServices_Coverage_AutoFillService_HandleAutofillTOTPByID_Disabled(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	result, err := svc.HandleAutofillTOTPByID("id")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrAutoFillDisabled)
}

// ---------------------------------------------------------------------------
// AutoFillService LoadRegistration / SaveRegistration coverage
// ---------------------------------------------------------------------------

func TestMiscServices_Coverage_AutoFillService_LoadRegistration_EmptyDir(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	// registrationDir is empty string.
	loaded := svc.loadRegistration()
	assert.False(t, loaded)
}

func TestMiscServices_Coverage_AutoFillService_LoadRegistration_FileNotFound(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	svc.SetRegistrationDir("/nonexistent/dir")
	loaded := svc.loadRegistration()
	assert.False(t, loaded)
}

func TestMiscServices_Coverage_AutoFillService_LoadRegistration_InvalidJSON(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	tmpDir := t.TempDir()
	svc.SetRegistrationDir(tmpDir)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, registrationFile), []byte("not json"), 0600))

	loaded := svc.loadRegistration()
	assert.False(t, loaded)
}

func TestMiscServices_Coverage_AutoFillService_LoadRegistration_EmptyFields(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	tmpDir := t.TempDir()
	svc.SetRegistrationDir(tmpDir)

	data, _ := json.Marshal(map[string]any{"credential_id": nil, "public_key_cose": nil})
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, registrationFile), data, 0600))

	loaded := svc.loadRegistration()
	assert.False(t, loaded)
}

func TestMiscServices_Coverage_AutoFillService_SaveRegistration_EmptyDir(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	// registrationDir is empty. Should silently return.
	svc.saveRegistration([]byte("pubkey"))
}

func TestMiscServices_Coverage_AutoFillService_MatchOATHAccount_EmptyDomain(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	matched, id := svc.matchOATHAccount("", nil)
	assert.False(t, matched)
	assert.Empty(t, id)
}

func TestMiscServices_Coverage_AutoFillService_MatchOATHAccount_NoMatch(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	accounts := []OATHAccount{
		{ID: "1", Type: "totp", Issuer: "OtherSite", AccountName: "user"},
	}
	matched, id := svc.matchOATHAccount("github.com", accounts)
	assert.False(t, matched)
	assert.Empty(t, id)
}

func TestMiscServices_Coverage_AutoFillService_MatchOATHAccount_IssuerMatch(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	accounts := []OATHAccount{
		{ID: "gh-1", Type: "totp", Issuer: "GitHub", AccountName: "user@github.com"},
	}
	matched, id := svc.matchOATHAccount("github.com", accounts)
	assert.True(t, matched)
	assert.Equal(t, "gh-1", id)
}

func TestMiscServices_Coverage_AutoFillService_MatchOATHAccount_AccountNameMatch(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	accounts := []OATHAccount{
		{ID: "g-1", Type: "totp", Issuer: "SomeService", AccountName: "github"},
	}
	matched, id := svc.matchOATHAccount("github.com", accounts)
	assert.True(t, matched)
	assert.Equal(t, "g-1", id)
}

func TestMiscServices_Coverage_AutoFillService_MatchOATHAccount_SkipsHOTP(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	accounts := []OATHAccount{
		{ID: "h-1", Type: "hotp", Issuer: "GitHub", AccountName: "user"},
	}
	matched, _ := svc.matchOATHAccount("github.com", accounts)
	assert.False(t, matched)
}

// Ensure the compile-time interface check compiles.
var _ ipc.AutofillHandler = (*AutoFillService)(nil)

// ===========================================================================
// FIDO2Service tests
// ===========================================================================

func TestMiscServices_Coverage_FIDO2Service_New(t *testing.T) {
	svc := NewFIDO2Service(nil)
	require.NotNil(t, svc)
	assert.Nil(t, svc.storage)
}

func TestMiscServices_Coverage_FIDO2Service_SetContext(t *testing.T) {
	svc := NewFIDO2Service(nil)
	ctx := context.Background()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}

func TestMiscServices_Coverage_FIDO2Service_SetStorage(t *testing.T) {
	svc := NewFIDO2Service(nil)
	storage := authenticator.NewMemoryStorage()
	svc.SetStorage(storage)
	assert.NotNil(t, svc.storage)
}

func TestMiscServices_Coverage_FIDO2Service_SetRPPolicyStore(t *testing.T) {
	svc := NewFIDO2Service(nil)
	store := &mockRPPolicyStore{}
	svc.SetRPPolicyStore(store)
	assert.NotNil(t, svc.rpPolicyStore)
}

func TestMiscServices_Coverage_FIDO2Service_SetClientFunc(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.SetClientFunc(nil)
	assert.Nil(t, svc.clientFunc)
}

func TestMiscServices_Coverage_FIDO2Service_SetAuditLogger(t *testing.T) {
	svc := NewFIDO2Service(nil)
	al := &miscCoverageAuditLogger{}
	svc.SetAuditLogger(al)
	assert.NotNil(t, svc.auditLogger)
}

func TestMiscServices_Coverage_FIDO2Service_SetTokenStore(t *testing.T) {
	svc := NewFIDO2Service(nil)
	store := &mockTokenStore{}
	svc.SetTokenStore(store)
	assert.NotNil(t, svc.tokenStore)
}

func TestMiscServices_Coverage_FIDO2Service_ListCredentials_NilStorage(t *testing.T) {
	svc := NewFIDO2Service(nil)
	result, err := svc.ListCredentials()
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestMiscServices_Coverage_FIDO2Service_GetCredential_EmptyID(t *testing.T) {
	svc := NewFIDO2Service(nil)
	result, err := svc.GetCredential("")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrFIDO2InvalidID)
}

func TestMiscServices_Coverage_FIDO2Service_GetCredential_NilStorage(t *testing.T) {
	svc := NewFIDO2Service(nil)
	result, err := svc.GetCredential("aabb")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrFIDO2StorageNotSet)
}

func TestMiscServices_Coverage_FIDO2Service_GetCredential_InvalidHex(t *testing.T) {
	svc := NewFIDO2Service(authenticator.NewMemoryStorage())
	result, err := svc.GetCredential("not-hex!")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrFIDO2InvalidID)
}

func TestMiscServices_Coverage_FIDO2Service_GetCredential_NotFound(t *testing.T) {
	svc := NewFIDO2Service(authenticator.NewMemoryStorage())
	result, err := svc.GetCredential("aabbccdd")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrFIDO2CredentialNotFound)
}

func TestMiscServices_Coverage_FIDO2Service_DeleteCredential_EmptyID(t *testing.T) {
	svc := NewFIDO2Service(nil)
	err := svc.DeleteCredential("")
	assert.ErrorIs(t, err, ErrFIDO2InvalidID)
}

func TestMiscServices_Coverage_FIDO2Service_DeleteCredential_NilStorage(t *testing.T) {
	svc := NewFIDO2Service(nil)
	err := svc.DeleteCredential("aabb")
	assert.ErrorIs(t, err, ErrFIDO2StorageNotSet)
}

func TestMiscServices_Coverage_FIDO2Service_DeleteCredential_InvalidHex(t *testing.T) {
	svc := NewFIDO2Service(authenticator.NewMemoryStorage())
	err := svc.DeleteCredential("not-hex!")
	assert.ErrorIs(t, err, ErrFIDO2InvalidID)
}

func TestMiscServices_Coverage_FIDO2Service_DeleteCredential_NotFound(t *testing.T) {
	svc := NewFIDO2Service(authenticator.NewMemoryStorage())
	err := svc.DeleteCredential("aabbccdd")
	assert.ErrorIs(t, err, ErrFIDO2CredentialNotFound)
}

func TestMiscServices_Coverage_FIDO2Service_GetRelyingParties_NilStorage(t *testing.T) {
	svc := NewFIDO2Service(nil)
	result, err := svc.GetRelyingParties()
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestMiscServices_Coverage_FIDO2Service_StopPhoneBridge_NotRunning(t *testing.T) {
	svc := NewFIDO2Service(nil)
	err := svc.StopPhoneBridge()
	assert.ErrorIs(t, err, ErrFIDO2BridgeStopped)
}

func TestMiscServices_Coverage_FIDO2Service_StartPhoneBridge_AlreadyRunning(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.bridgeRunning.Store(true)
	err := svc.StartPhoneBridge()
	assert.ErrorIs(t, err, ErrFIDO2BridgeRunning)
}

func TestMiscServices_Coverage_FIDO2Service_StartPhoneBridge_NoClientFunc(t *testing.T) {
	svc := NewFIDO2Service(nil)
	err := svc.StartPhoneBridge()
	assert.ErrorIs(t, err, ErrFIDO2BridgeNoClient)
}

func TestMiscServices_Coverage_FIDO2Service_StartPhoneBridge_ClientReturnsNil(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.SetClientFunc(func() xkms.Client { return nil })
	err := svc.StartPhoneBridge()
	assert.ErrorIs(t, err, ErrFIDO2BridgeNoClient)
}

func TestMiscServices_Coverage_FIDO2Service_GetBridgeStatus_NotRunning(t *testing.T) {
	svc := NewFIDO2Service(nil)
	status := svc.GetBridgeStatus()
	assert.False(t, status.Running)
	assert.Equal(t, int64(0), status.Requests)
}

func TestMiscServices_Coverage_FIDO2Service_GetBridgeStatus_Running(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.bridgeRunning.Store(true)
	svc.bridgeStart = time.Now().Add(-5 * time.Second)
	svc.bridgeReqs.Store(42)

	status := svc.GetBridgeStatus()
	assert.True(t, status.Running)
	assert.Equal(t, int64(42), status.Requests)
	assert.NotEmpty(t, status.Uptime)
	assert.False(t, status.StartedAt.IsZero())
}

func TestMiscServices_Coverage_FIDO2Service_HandleBridgeRequest_NotRunning(t *testing.T) {
	svc := NewFIDO2Service(nil)
	result, err := svc.HandleBridgeRequest("test", nil)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrFIDO2BridgeStopped)
}

func TestMiscServices_Coverage_FIDO2Service_StoreAuthResponse_NilTokenStore(t *testing.T) {
	svc := NewFIDO2Service(nil)
	err := svc.StoreAuthResponse(&FIDO2AuthResponse{Token: "tok"})
	assert.ErrorIs(t, err, ErrFIDO2TokenStoreNotSet)
}

func TestMiscServices_Coverage_FIDO2Service_StoreAuthResponse_NilResp(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.SetTokenStore(&mockTokenStore{})
	err := svc.StoreAuthResponse(nil)
	assert.ErrorIs(t, err, ErrFIDO2InvalidID)
}

func TestMiscServices_Coverage_FIDO2Service_StoreAuthResponse_EmptyToken(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.SetTokenStore(&mockTokenStore{})
	err := svc.StoreAuthResponse(&FIDO2AuthResponse{Token: ""})
	assert.ErrorIs(t, err, ErrFIDO2InvalidID)
}

func TestMiscServices_Coverage_FIDO2Service_StoreAuthResponse_Success(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.SetContext(context.Background())
	al := &miscCoverageAuditLogger{}
	svc.SetAuditLogger(al)

	store := &mockTokenStore{}
	svc.SetTokenStore(store)

	err := svc.StoreAuthResponse(&FIDO2AuthResponse{
		CredentialID: "cred-1",
		RPID:         "example.com",
		Token:        "jwt-token",
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
	assert.Len(t, al.entries, 1)
}

func TestMiscServices_Coverage_FIDO2Service_GetAuthResponses_NilStore(t *testing.T) {
	svc := NewFIDO2Service(nil)
	result := svc.GetAuthResponses()
	assert.Nil(t, result)
}

func TestMiscServices_Coverage_FIDO2Service_GetLatestToken_NilStore(t *testing.T) {
	svc := NewFIDO2Service(nil)
	result, err := svc.GetLatestToken("example.com")
	assert.Empty(t, result)
	assert.ErrorIs(t, err, ErrFIDO2TokenStoreNotSet)
}

func TestMiscServices_Coverage_FIDO2Service_GetLatestToken_NotFound(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.SetContext(context.Background())
	svc.SetTokenStore(&mockTokenStore{loadErr: errors.New("not found")})
	result, err := svc.GetLatestToken("example.com")
	assert.Empty(t, result)
	assert.ErrorIs(t, err, ErrFIDO2AuthResponseNotFound)
}

func TestMiscServices_Coverage_FIDO2Service_ListRPPolicies_NilStore(t *testing.T) {
	svc := NewFIDO2Service(nil)
	result, err := svc.ListRPPolicies()
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestMiscServices_Coverage_FIDO2Service_GetRPPolicy_NilStore(t *testing.T) {
	svc := NewFIDO2Service(nil)
	result, err := svc.GetRPPolicy("example.com")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrFIDO2RPPolicyStoreNotSet)
}

func TestMiscServices_Coverage_FIDO2Service_SetRPPolicy_NilStore(t *testing.T) {
	svc := NewFIDO2Service(nil)
	err := svc.SetRPPolicy(FIDO2RPPolicy{RPID: "example.com"})
	assert.ErrorIs(t, err, ErrFIDO2RPPolicyStoreNotSet)
}

func TestMiscServices_Coverage_FIDO2Service_DeleteRPPolicy_NilStore(t *testing.T) {
	svc := NewFIDO2Service(nil)
	err := svc.DeleteRPPolicy("example.com")
	assert.ErrorIs(t, err, ErrFIDO2RPPolicyStoreNotSet)
}

// ---------------------------------------------------------------------------
// rpPolicyToGUI / guiToRPPolicy conversion tests
// ---------------------------------------------------------------------------

func TestMiscServices_Coverage_RPPolicyToGUI(t *testing.T) {
	trueVal := true
	falseVal := false

	tests := []struct {
		name          string
		upOverride    *bool
		expectedUPStr string
	}{
		{"nil UP override", nil, ""},
		{"true UP override", &trueVal, "true"},
		{"false UP override", &falseVal, "false"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy := &authenticator.RPPolicy{
				RPID:                "example.com",
				UVOverride:          "required",
				UPOverride:          tc.upOverride,
				AttestationOverride: "direct",
				Enterprise:          true,
				Blocked:             false,
			}
			gui := rpPolicyToGUI(policy)
			assert.Equal(t, "example.com", gui.RPID)
			assert.Equal(t, "required", gui.UVOverride)
			assert.Equal(t, tc.expectedUPStr, gui.UPOverride)
			assert.Equal(t, "direct", gui.AttestationOverride)
			assert.True(t, gui.Enterprise)
			assert.False(t, gui.Blocked)
		})
	}
}

func TestMiscServices_Coverage_GUIToRPPolicy(t *testing.T) {
	tests := []struct {
		name          string
		upOverrideStr string
		expectedUP    *bool
	}{
		{"empty UP", "", nil},
		{"true UP", "true", boolPtr(true)},
		{"false UP", "false", boolPtr(false)},
		{"invalid UP", "maybe", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gui := FIDO2RPPolicy{
				RPID:                "example.com",
				UPOverride:          tc.upOverrideStr,
				UVOverride:          "discouraged",
				AttestationOverride: "enterprise",
				Enterprise:          true,
				Blocked:             true,
			}
			domain := guiToRPPolicy(gui)
			assert.Equal(t, "example.com", domain.RPID)
			assert.Equal(t, "discouraged", domain.UVOverride)
			assert.Equal(t, "enterprise", domain.AttestationOverride)
			assert.True(t, domain.Enterprise)
			assert.True(t, domain.Blocked)
			if tc.expectedUP == nil {
				assert.Nil(t, domain.UPOverride)
			} else {
				require.NotNil(t, domain.UPOverride)
				assert.Equal(t, *tc.expectedUP, *domain.UPOverride)
			}
		})
	}
}

func boolPtr(v bool) *bool { return &v }

// ---------------------------------------------------------------------------
// storedToFIDO2Credential / coseAlgorithmName tests
// ---------------------------------------------------------------------------

func TestMiscServices_Coverage_StoredToFIDO2Credential(t *testing.T) {
	credID := []byte{0xaa, 0xbb, 0xcc}
	stored := &authenticator.StoredCredential{
		CredentialID:    credID,
		RPID:            "example.com",
		RPName:          "Example",
		UserName:        "alice",
		UserDisplayName: "Alice",
		Algorithm:       -7,
		SignCount:       10,
		Discoverable:    true,
		CreatedAt:       time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Unix(),
		PrivateKey:      []byte("some-key"),
		BackendID:       "software",
	}
	cred := storedToFIDO2Credential(stored)
	assert.Equal(t, hex.EncodeToString(credID), cred.ID)
	assert.Equal(t, "example.com", cred.RelyingPartyID)
	assert.Equal(t, "Example", cred.RelyingParty)
	assert.Equal(t, "alice", cred.UserName)
	assert.Equal(t, "Alice", cred.UserDisplayName)
	assert.Equal(t, "ES256", cred.Algorithm)
	assert.Equal(t, "ECDSA P-256", cred.KeyType)
	assert.Equal(t, 10, cred.UseCount)
	assert.True(t, cred.Discoverable)
	assert.Equal(t, "software", cred.BackendType)
	assert.Equal(t, "software", cred.BackendID)
}

func TestMiscServices_Coverage_StoredToFIDO2Credential_HardwareBackend(t *testing.T) {
	stored := &authenticator.StoredCredential{
		CredentialID: []byte{0x01},
		BackendID:    "tpm2",
		Algorithm:    -7,
	}
	cred := storedToFIDO2Credential(stored)
	assert.Equal(t, "tpm2", cred.BackendType)
}

func TestMiscServices_Coverage_StoredToFIDO2Credential_NoBackendID_NilPrivKey(t *testing.T) {
	stored := &authenticator.StoredCredential{
		CredentialID: []byte{0x01},
		Algorithm:    -7,
	}
	cred := storedToFIDO2Credential(stored)
	assert.Equal(t, "hardware", cred.BackendType)
}

func TestMiscServices_Coverage_StoredToFIDO2Credential_UnknownAlgorithm(t *testing.T) {
	stored := &authenticator.StoredCredential{
		CredentialID: []byte{0x01},
		Algorithm:    -999,
		PrivateKey:   []byte("key"),
	}
	cred := storedToFIDO2Credential(stored)
	assert.Equal(t, "COSE(-999)", cred.Algorithm)
	assert.Contains(t, cred.KeyType, "Unknown(-999)")
}

func TestMiscServices_Coverage_CoseAlgorithmName(t *testing.T) {
	tests := []struct {
		alg      int
		expected string
	}{
		{-7, "ES256"},
		{-35, "ES384"},
		{-36, "ES512"},
		{-257, "RS256"},
		{-258, "RS384"},
		{-259, "RS512"},
		{-8, "EdDSA"},
		{999, "COSE(999)"},
	}
	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			assert.Equal(t, tc.expected, coseAlgorithmName(tc.alg))
		})
	}
}

// ===========================================================================
// FIDO2DeviceService tests
// ===========================================================================

func TestMiscServices_Coverage_FIDO2DeviceService_New(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	require.NotNil(t, svc)
	assert.NotNil(t, svc.log)
}

func TestMiscServices_Coverage_FIDO2DeviceService_SetContext(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	ctx := context.Background()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}

func TestMiscServices_Coverage_FIDO2DeviceService_SetEmitFunc(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	var emitted []string
	svc.SetEmitFunc(func(eventType string, data any) {
		emitted = append(emitted, eventType)
	})
	assert.NotNil(t, svc.emitFunc)

	// Test emit helper.
	svc.emit("test-event", nil)
	assert.Len(t, emitted, 1)
	assert.Equal(t, "test-event", emitted[0])
}

func TestMiscServices_Coverage_FIDO2DeviceService_Emit_NilFunc(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	// Should not panic.
	svc.emit("test-event", nil)
}

func TestMiscServices_Coverage_FIDO2DeviceService_SetLastError(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	svc.SetLastError("something went wrong")

	v := svc.lastError.Load()
	require.NotNil(t, v)
	assert.Equal(t, "something went wrong", v.(string))
}

func TestMiscServices_Coverage_FIDO2DeviceService_SetAuditLogger(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	al := &miscCoverageAuditLogger{}
	svc.SetAuditLogger(al)
	assert.NotNil(t, svc.auditLogger)
}

func TestMiscServices_Coverage_FIDO2DeviceService_SetAuthenticator(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	svc.SetAuthenticator(nil)
	assert.Nil(t, svc.externalAuth)
}

func TestMiscServices_Coverage_FIDO2DeviceService_SetWindowHideFunc(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	// SetWindowHideFunc is a no-op; just verify it doesn't panic.
	svc.SetWindowHideFunc(func() {})
}

func TestMiscServices_Coverage_FIDO2DeviceService_GetRequireUserPresence_NilAuth(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	// No external auth -> returns true (safe default).
	assert.True(t, svc.GetRequireUserPresence())
}

func TestMiscServices_Coverage_FIDO2DeviceService_SetRequireUserPresence_NilAuth(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	// Should not panic when external auth is nil.
	svc.SetRequireUserPresence(true)
}

func TestMiscServices_Coverage_FIDO2DeviceService_GetUserIntentCheck_NilAuth(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	// No external auth -> returns false.
	assert.False(t, svc.GetUserIntentCheck())
}

func TestMiscServices_Coverage_FIDO2DeviceService_SetUserIntentCheck_NilAuth(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	// Should not panic when external auth is nil.
	svc.SetUserIntentCheck(true)
}

func TestMiscServices_Coverage_FIDO2DeviceService_IsRunning_Default(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	assert.False(t, svc.IsRunning())
}

func TestMiscServices_Coverage_FIDO2DeviceService_IsRunning_Set(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	svc.running.Store(true)
	assert.True(t, svc.IsRunning())
}

func TestMiscServices_Coverage_FIDO2DeviceService_IsAuthenticatorPINSet_NotRunning(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	assert.False(t, svc.IsAuthenticatorPINSet())
}

func TestMiscServices_Coverage_FIDO2DeviceService_IsAuthenticatorPINSet_NilDevice(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	svc.running.Store(true)
	// device is nil.
	assert.False(t, svc.IsAuthenticatorPINSet())
}

func TestMiscServices_Coverage_FIDO2DeviceService_GetStatus_NotRunning(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	status := svc.GetStatus()
	assert.False(t, status.Running)
	assert.Empty(t, status.DeviceName)
}

func TestMiscServices_Coverage_FIDO2DeviceService_GetStatus_NotRunning_WithLastError(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	svc.SetLastError("UHID not available")
	status := svc.GetStatus()
	assert.False(t, status.Running)
	assert.Equal(t, "UHID not available", status.Reason)
}

func TestMiscServices_Coverage_FIDO2DeviceService_ApproveTouchRequest_NilHandler(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	result := svc.ApproveTouchRequest()
	assert.False(t, result)
}

func TestMiscServices_Coverage_FIDO2DeviceService_DenyTouchRequest_NilHandler(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	result := svc.DenyTouchRequest()
	assert.False(t, result)
}

func TestMiscServices_Coverage_FIDO2DeviceService_HasPendingTouch_NilHandler(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	result := svc.HasPendingTouch()
	assert.False(t, result)
}

func TestMiscServices_Coverage_FIDO2DeviceService_Stop_NotRunning(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	err := svc.Stop()
	assert.ErrorIs(t, err, ErrFIDO2DeviceNotRunning)
}

func TestMiscServices_Coverage_FIDO2DeviceService_Start_AlreadyRunning(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	svc.running.Store(true)
	err := svc.Start(authenticator.NewMemoryStorage(), nil)
	assert.ErrorIs(t, err, ErrFIDO2DeviceAlreadyRunning)
}

func TestMiscServices_Coverage_FIDO2DeviceService_Start_NilStorage(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	err := svc.Start(nil, nil)
	assert.ErrorIs(t, err, ErrFIDO2StorageRequired)

	// Verify lastError was set.
	v := svc.lastError.Load()
	require.NotNil(t, v)
	assert.Contains(t, v.(string), "storage is required")
}

// ===========================================================================
// Mock implementations for FIDO2 service
// ===========================================================================

type mockRPPolicyStore struct {
	policies  []*authenticator.RPPolicy
	getErr    error
	setErr    error
	deleteErr error
}

func (m *mockRPPolicyStore) SetPolicy(policy *authenticator.RPPolicy) error { return m.setErr }
func (m *mockRPPolicyStore) GetPolicy(rpID string) (*authenticator.RPPolicy, error) {
	return nil, m.getErr
}
func (m *mockRPPolicyStore) DeletePolicy(rpID string) error                   { return m.deleteErr }
func (m *mockRPPolicyStore) ListPolicies() ([]*authenticator.RPPolicy, error) { return m.policies, nil }

type mockTokenStore struct {
	entries    []*tokenstore.TokenEntry
	saveErr    error
	loadErr    error
	loadResult *tokenstore.TokenEntry
}

func (m *mockTokenStore) Save(ctx context.Context, entry *tokenstore.TokenEntry) error {
	return m.saveErr
}
func (m *mockTokenStore) Load(ctx context.Context, serverURL string) (*tokenstore.TokenEntry, error) {
	if m.loadResult != nil {
		return m.loadResult, nil
	}
	return nil, m.loadErr
}
func (m *mockTokenStore) Delete(ctx context.Context, serverURL string) error { return nil }
func (m *mockTokenStore) List(ctx context.Context) ([]*tokenstore.TokenEntry, error) {
	return m.entries, nil
}
func (m *mockTokenStore) Close() error { return nil }
