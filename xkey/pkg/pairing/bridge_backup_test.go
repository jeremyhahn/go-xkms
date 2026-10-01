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
		MethodRemoteCreateBackup,
		MethodRemoteRestoreBackup,
		MethodRemoteListBackups,
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

	req := newRemoteRequest(MethodRemoteCreateBackup, RemoteCreateBackupParams{
		IncludeTrustStore: true,
		IncludeOATH:       false,
		IncludePasswords:  false,
		IncludeCA:         true,
		Label:             "test-backup",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeFeatureUnavailable)
}

func TestBridge_HandleCreateBackup_InvalidParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// Nil params
	req := newRemoteRequest(MethodRemoteCreateBackup, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_HandleCreateBackup_MinimalParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// All booleans false, no label - minimal valid params, still reports
	// unconfigured rather than an empty success.
	req := newRemoteRequest(MethodRemoteCreateBackup, RemoteCreateBackupParams{})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeFeatureUnavailable)
}

// --- handleRestoreBackup tests ---

// TestBridge_HandleRestoreBackup_NotConfigured verifies that remote.restoreBackup
// reports the feature as unconfigured rather than discarding the phone's
// backup data while claiming success.
func TestBridge_HandleRestoreBackup_NotConfigured(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteRestoreBackup, RemoteRestoreBackupParams{
		BackupData: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE},
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeFeatureUnavailable)
}

func TestBridge_HandleRestoreBackup_InvalidParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// Nil params
	req := newRemoteRequest(MethodRemoteRestoreBackup, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_HandleRestoreBackup_EmptyBackupData(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteRestoreBackup, RemoteRestoreBackupParams{
		BackupData: []byte{},
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_HandleRestoreBackup_NilBackupData(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteRestoreBackup, RemoteRestoreBackupParams{
		BackupData: nil,
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
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

	req := newRemoteRequest(MethodRemoteListBackups, RemoteListBackupsParams{})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeFeatureUnavailable)
}

func TestBridge_HandleListBackups_NilParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// ListBackups does not require params; it still reports unconfigured.
	req := newRemoteRequest(MethodRemoteListBackups, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeFeatureUnavailable)
}

// --- Error mapping tests ---

func TestMapErrorToRPC_BackupFailed(t *testing.T) {
	code, msg := mapErrorToRPC(ErrBackupFailed)
	assert.Equal(t, ErrorCodeBackupFailed, code)
	assert.Contains(t, msg, "backup creation failed")
}

func TestMapErrorToRPC_BackupRestoreFailed(t *testing.T) {
	code, msg := mapErrorToRPC(ErrBackupRestoreFailed)
	assert.Equal(t, ErrorCodeBackupRestore, code)
	assert.Contains(t, msg, "backup restore failed")
}

func TestMapErrorToRPC_BackupNotFound(t *testing.T) {
	code, msg := mapErrorToRPC(ErrBackupNotFound)
	assert.Equal(t, ErrorCodeBackupNotFound, code)
	assert.Contains(t, msg, "backup not found")
}

// --- Nil params tests for backup handlers ---

func TestBridge_NilParams_BackupHandlers(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// createBackup and restoreBackup require params.
	methodsRequiringParams := []string{
		MethodRemoteCreateBackup,
		MethodRemoteRestoreBackup,
	}

	for _, method := range methodsRequiringParams {
		t.Run(method, func(t *testing.T) {
			req := newRemoteRequest(method, nil)
			resp := b.HandleRequest(context.Background(), req)
			assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
		})
	}
}

// --- Whole-node backup operations (go-xkms#728) ---

func (m *mockTransportClient) CreateBackup(_ context.Context, _ *transport.BackupRequest) (*transport.BackupInfo, error) {
	return nil, nil
}

func (m *mockTransportClient) ListBackups(_ context.Context) ([]transport.BackupInfo, error) {
	return nil, nil
}

func (m *mockTransportClient) GetBackup(_ context.Context, _ string) (*transport.BackupInfo, error) {
	return nil, nil
}

func (m *mockTransportClient) DeleteBackup(_ context.Context, _ string) error {
	return nil
}

func (m *mockTransportClient) RestoreBackup(_ context.Context, _ *transport.RestoreRequest) (*transport.RestoreResult, error) {
	return nil, nil
}

func (m *mockTransportClient) VerifyBackup(_ context.Context, _ string) (*transport.VerifyResult, error) {
	return nil, nil
}

// --- Custodian group operations ---

func (m *mockTransportClient) CreateCustodianGroup(_ context.Context, _ *transport.CreateCustodianGroupRequest) (*transport.CreateCustodianGroupResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) GetCustodianGroup(_ context.Context, _ string) (*transport.GetCustodianGroupResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) ListCustodianGroups(_ context.Context) (*transport.ListCustodianGroupsResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) DeleteCustodianGroup(_ context.Context, _ string) error {
	return nil
}

func (m *mockTransportClient) AddCustodianMember(_ context.Context, _ *transport.AddCustodianMemberRequest) (*transport.AddCustodianMemberResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) RemoveCustodianMember(_ context.Context, _ *transport.RemoveCustodianMemberRequest) error {
	return nil
}

// --- Share operations ---

func (m *mockTransportClient) DistributeShares(_ context.Context, _ *transport.DistributeSharesRequest) (*transport.DistributeSharesResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) SubmitShare(_ context.Context, _ *transport.SubmitShareRequest) (*transport.SubmitShareResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) ListShares(_ context.Context) (*transport.ListSharesResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) GetShareCollectionStatus(_ context.Context, _ string) (*transport.ShareCollectionStatus, error) {
	return nil, nil
}

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

func (m *mockTransportClient) TenantBarrierInit(_ context.Context, _ *transport.TenantBarrierInitRequest) error {
	return nil
}

func (m *mockTransportClient) TenantBarrierUnseal(_ context.Context, _ *transport.TenantBarrierUnsealRequest) error {
	return nil
}

func (m *mockTransportClient) TenantBarrierStatus(_ context.Context, _ string) (*transport.TenantBarrierStatusResponse, error) {
	return &transport.TenantBarrierStatusResponse{}, nil
}

func (m *mockTransportClient) UpdateTenantEntitlements(_ context.Context, _ *transport.UpdateTenantEntitlementsRequest) (*transport.UpdateTenantEntitlementsResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) UpdateTenantQuotas(_ context.Context, _ *transport.UpdateTenantQuotasRequest) (*transport.UpdateTenantQuotasResponse, error) {
	return nil, nil
}

// Init ceremony operations

func (m *mockTransportClient) GetInitStatus(_ context.Context) (*transport.InitStatusResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) ClaimCertBegin(_ context.Context, _ *transport.ClaimCertBeginRequest) (*transport.ClaimCertBeginResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) ClaimCertComplete(_ context.Context, _ *transport.ClaimCertCompleteRequest) (*transport.ClaimCertCompleteResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) ClaimShareBegin(_ context.Context, _ *transport.ClaimShareBeginRequest) (*transport.ClaimShareBeginResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) ClaimShareComplete(_ context.Context, _ *transport.ClaimShareCompleteRequest) (*transport.ClaimShareCompleteResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) SignCSRInit(_ context.Context, _ *transport.SignCSRInitRequest) (*transport.SignCSRInitResponse, error) {
	return nil, errNotImplemented
}

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

func (m *mockTransportClient) GetShare(_ context.Context, _, _ string, _ int) (*transport.ShareInfo, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) DeleteShare(_ context.Context, _, _ string, _ int) error {
	return errNotImplemented
}

// Audit

func (m *mockTransportClient) QueryAudit(_ context.Context, _ *transport.AuditFilter) (*transport.AuditPage, error) {
	return nil, errNotImplemented
}
