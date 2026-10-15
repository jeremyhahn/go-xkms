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
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Dispatch map tests ---

func TestBridge_DispatchMap_ContainsBackupMethods(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	backupMethods := []string{
		pairingproto.MethodRemoteCreateBackup,
		pairingproto.MethodRemoteRestoreBackup,
		pairingproto.MethodRemoteListBackups,
	}

	for _, method := range backupMethods {
		_, ok := b.handlers[method]
		assert.True(t, ok, "handler not registered for backup method %s", method)
	}
}

func TestBridge_DispatchMap_TotalHandlerCount_WithBackup(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// 16 original + 3 sharing + 3 backup + 2 OATH + 3 PIV + 5 sync
	// + 1 enrollment-certificate store = 33 total handlers.
	assert.Len(t, b.handlers, 33)
}

// --- handleCreateBackup tests ---

// TestBridge_HandleCreateBackup_NotConfigured verifies that remote.createBackup
// reports the feature as unconfigured (go-xkms#690: backup encryption key
// sourcing and persistence for phone-initiated backups is an open
// architecture question, see bridge_backup.go) rather than fabricating a
// successful, empty backup.
func TestBridge_HandleCreateBackup_NotConfigured(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(pairingproto.MethodRemoteCreateBackup, pairingproto.RemoteCreateBackupParams{
		IncludeTrustStore: true,
		IncludeOATH:       false,
		IncludePasswords:  false,
		IncludeCA:         true,
		Label:             "test-backup",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, pairingproto.ErrorCodeFeatureUnavailable)
}

func TestBridge_HandleCreateBackup_InvalidParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// Nil params
	req := newRemoteRequest(pairingproto.MethodRemoteCreateBackup, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, pairingproto.ErrorCodeInvalidParams)
}

func TestBridge_HandleCreateBackup_MinimalParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// All booleans false, no label - minimal valid params, still reports
	// unconfigured rather than an empty success.
	req := newRemoteRequest(pairingproto.MethodRemoteCreateBackup, pairingproto.RemoteCreateBackupParams{})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, pairingproto.ErrorCodeFeatureUnavailable)
}

// --- handleRestoreBackup tests ---

// TestBridge_HandleRestoreBackup_NotConfigured verifies that remote.restoreBackup
// reports the feature as unconfigured rather than discarding the phone's
// backup data while claiming success.
func TestBridge_HandleRestoreBackup_NotConfigured(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(pairingproto.MethodRemoteRestoreBackup, pairingproto.RemoteRestoreBackupParams{
		BackupData: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE},
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, pairingproto.ErrorCodeFeatureUnavailable)
}

func TestBridge_HandleRestoreBackup_InvalidParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// Nil params
	req := newRemoteRequest(pairingproto.MethodRemoteRestoreBackup, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, pairingproto.ErrorCodeInvalidParams)
}

func TestBridge_HandleRestoreBackup_EmptyBackupData(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(pairingproto.MethodRemoteRestoreBackup, pairingproto.RemoteRestoreBackupParams{
		BackupData: []byte{},
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, pairingproto.ErrorCodeInvalidParams)
}

func TestBridge_HandleRestoreBackup_NilBackupData(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(pairingproto.MethodRemoteRestoreBackup, pairingproto.RemoteRestoreBackupParams{
		BackupData: nil,
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, pairingproto.ErrorCodeInvalidParams)
}

// --- handleListBackupsForRestore tests ---

// TestBridge_HandleListBackups_NotConfigured verifies that remote.listBackups
// reports the feature as unconfigured rather than an empty-but-successful
// list, since no persistence/ID convention exists for phone-initiated
// backups yet (see bridge_backup.go).
func TestBridge_HandleListBackups_NotConfigured(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(pairingproto.MethodRemoteListBackups, pairingproto.RemoteListBackupsParams{})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, pairingproto.ErrorCodeFeatureUnavailable)
}

func TestBridge_HandleListBackups_NilParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// ListBackups does not require params; it still reports unconfigured.
	req := newRemoteRequest(pairingproto.MethodRemoteListBackups, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, pairingproto.ErrorCodeFeatureUnavailable)
}

// --- Error mapping tests ---

func TestMapErrorToRPC_BackupFailed(t *testing.T) {
	code, msg := mapErrorToRPC(pairingproto.ErrBackupFailed)
	assert.Equal(t, pairingproto.ErrorCodeBackupFailed, code)
	assert.Contains(t, msg, "backup creation failed")
}

func TestMapErrorToRPC_BackupRestoreFailed(t *testing.T) {
	code, msg := mapErrorToRPC(pairingproto.ErrBackupRestoreFailed)
	assert.Equal(t, pairingproto.ErrorCodeBackupRestore, code)
	assert.Contains(t, msg, "backup restore failed")
}

func TestMapErrorToRPC_BackupNotFound(t *testing.T) {
	code, msg := mapErrorToRPC(pairingproto.ErrBackupNotFound)
	assert.Equal(t, pairingproto.ErrorCodeBackupNotFound, code)
	assert.Contains(t, msg, "backup not found")
}

// --- Nil params tests for backup handlers ---

func TestBridge_NilParams_BackupHandlers(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// createBackup and restoreBackup require params.
	methodsRequiringParams := []string{
		pairingproto.MethodRemoteCreateBackup,
		pairingproto.MethodRemoteRestoreBackup,
	}

	for _, method := range methodsRequiringParams {
		t.Run(method, func(t *testing.T) {
			req := newRemoteRequest(method, nil)
			resp := b.HandleRequest(context.Background(), req)
			assertErrorResponse(t, resp, req.ID, pairingproto.ErrorCodeInvalidParams)
		})
	}
}

// --- Whole-node backup operations (go-xkms#728) ---

// --- Custodian group operations ---

// --- Share operations ---

// --- Tenant operations ---

func (m *mockTransportClient) CreateTenant(_ context.Context, _ *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) GetTenant(_ context.Context, _ string) (*transport.GetTenantResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) ListTenants(_ context.Context) (*transport.ListTenantsResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) DeleteTenant(_ context.Context, _ string) error {
	return nil
}

func (m *mockTransportClient) UpdateTenantEntitlements(_ context.Context, _ *transport.UpdateTenantEntitlementsRequest) (*transport.UpdateTenantEntitlementsResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) UpdateTenantQuotas(_ context.Context, _ *transport.UpdateTenantQuotasRequest) (*transport.UpdateTenantQuotasResponse, error) {
	return nil, nil
}

// Init ceremony operations

// Credential management operations

func (m *mockTransportClient) SubmitCredential(_ context.Context, _ *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) GetCredentialStrategy(_ context.Context) (*transport.CredentialStrategyResponse, error) {
	return nil, errNotImplemented
}

// Algorithm discovery

func (m *mockTransportClient) Algorithms(_ context.Context) (*transport.AlgorithmsResponse, error) {
	return nil, errNotImplemented
}

// Share custody read/delete

// Audit
