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

	// 16 original + 3 sharing + 3 backup + 2 OATH + 3 PIV + 5 sync = 32 total handlers.
	assert.Len(t, b.handlers, 32)
}

// --- handleCreateBackup tests ---

func TestBridge_HandleCreateBackup_Success(t *testing.T) {
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

	result := decodeResult[RemoteCreateBackupResult](t, resp)
	assert.Nil(t, result.BackupData)
	assert.Empty(t, result.BackupID)
	assert.Equal(t, 0, result.ItemCount)
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

	// All booleans false, no label - minimal valid params.
	req := newRemoteRequest(MethodRemoteCreateBackup, RemoteCreateBackupParams{})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteCreateBackupResult](t, resp)
	assert.Nil(t, result.BackupData)
}

// --- handleRestoreBackup tests ---

func TestBridge_HandleRestoreBackup_Success(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteRestoreBackup, RemoteRestoreBackupParams{
		BackupData: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE},
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteRestoreBackupResult](t, resp)
	assert.True(t, result.Success)
	assert.Equal(t, "backup received", result.Message)
	assert.Empty(t, result.Restored)
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

func TestBridge_HandleListBackups_Success(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteListBackups, RemoteListBackupsParams{})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteListBackupsResult](t, resp)
	assert.Empty(t, result.Backups)
}

func TestBridge_HandleListBackups_NilParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// ListBackups does not require params, should still succeed.
	req := newRemoteRequest(MethodRemoteListBackups, nil)
	resp := b.HandleRequest(context.Background(), req)

	// The handler ignores params, so nil is fine.
	require.Nil(t, resp.Error, "expected success but got error: %v", resp.Error)
	result := decodeResult[RemoteListBackupsResult](t, resp)
	assert.Empty(t, result.Backups)
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

func (m *mockTransportClient) ClaimShare(_ context.Context, _ *transport.ClaimShareRequest) (*transport.ClaimShareResponse, error) {
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
