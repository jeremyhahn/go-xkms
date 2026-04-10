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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Dispatch map tests ---

func TestBridge_DispatchMap_ContainsSyncMethods(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	syncMethods := []string{
		MethodRemoteSyncTrustStore,
		MethodRemoteSyncOATH,
		MethodRemoteSyncPasswords,
		MethodRemoteSyncAll,
		MethodRemoteSyncStatus,
	}

	for _, method := range syncMethods {
		_, ok := b.handlers[method]
		assert.True(t, ok, "handler not registered for sync method %s", method)
	}
}

func TestBridge_DispatchMap_TotalHandlerCount_WithSync(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// 16 original + 3 sharing + 3 backup + 2 OATH + 3 PIV + 5 sync = 32 total handlers.
	assert.Len(t, b.handlers, 32)
}

// --- handleSyncTrustStore tests ---

func TestBridge_HandleSyncTrustStore_Success(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncTrustStore, RemoteSyncTrustStoreParams{
		Certificates: []SyncCertificate{
			{PEM: "cert1", Fingerprint: "fp1"},
			{PEM: "cert2", Fingerprint: "fp2"},
		},
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteSyncTrustStoreResult](t, resp)
	assert.Equal(t, 0, result.Added)
	assert.Equal(t, 2, result.Skipped)
	assert.Empty(t, result.Local)
}

func TestBridge_HandleSyncTrustStore_InvalidParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncTrustStore, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_HandleSyncTrustStore_EmptyCertificates(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncTrustStore, RemoteSyncTrustStoreParams{
		Certificates: []SyncCertificate{},
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteSyncTrustStoreResult](t, resp)
	assert.Equal(t, 0, result.Added)
	assert.Equal(t, 0, result.Skipped)
}

// --- handleSyncOATH tests ---

func TestBridge_HandleSyncOATH_Success(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncOATH, RemoteSyncOATHParams{
		Credentials: []SyncOATHCredential{
			{ID: "c1", Name: "GitHub", Secret: "SEC", Type: "totp"},
			{ID: "c2", Name: "Slack", Secret: "SEC2", Type: "totp"},
			{ID: "c3", Name: "AWS", Secret: "SEC3", Type: "hotp"},
		},
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteSyncOATHResult](t, resp)
	assert.Equal(t, 0, result.Added)
	assert.Equal(t, 0, result.Updated)
	assert.Equal(t, 3, result.Skipped)
	assert.Empty(t, result.Local)
}

func TestBridge_HandleSyncOATH_InvalidParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncOATH, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

// --- handleSyncPasswords tests ---

func TestBridge_HandleSyncPasswords_Success(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncPasswords, RemoteSyncPasswordsParams{
		Passwords: []SyncPassword{
			{ID: "p1", Name: "GitHub", Password: "pw1"},
		},
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteSyncPasswordsResult](t, resp)
	assert.Equal(t, 0, result.Added)
	assert.Equal(t, 0, result.Updated)
	assert.Equal(t, 1, result.Skipped)
	assert.Empty(t, result.Local)
}

func TestBridge_HandleSyncPasswords_InvalidParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncPasswords, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

// --- handleSyncAll tests ---

func TestBridge_HandleSyncAll_AllIncluded(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncAll, RemoteSyncAllParams{
		IncludeTrustStore: true,
		IncludeOATH:       true,
		IncludePasswords:  true,
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteSyncAllResult](t, resp)
	require.NotNil(t, result.TrustStore)
	require.NotNil(t, result.OATH)
	require.NotNil(t, result.Passwords)
	assert.Equal(t, 0, result.TrustStore.Added)
	assert.Equal(t, 0, result.OATH.Added)
	assert.Equal(t, 0, result.Passwords.Added)
}

func TestBridge_HandleSyncAll_TrustStoreOnly(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncAll, RemoteSyncAllParams{
		IncludeTrustStore: true,
		IncludeOATH:       false,
		IncludePasswords:  false,
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteSyncAllResult](t, resp)
	require.NotNil(t, result.TrustStore)
	assert.Nil(t, result.OATH)
	assert.Nil(t, result.Passwords)
}

func TestBridge_HandleSyncAll_NoneIncluded(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncAll, RemoteSyncAllParams{
		IncludeTrustStore: false,
		IncludeOATH:       false,
		IncludePasswords:  false,
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteSyncAllResult](t, resp)
	assert.Nil(t, result.TrustStore)
	assert.Nil(t, result.OATH)
	assert.Nil(t, result.Passwords)
}

func TestBridge_HandleSyncAll_InvalidParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncAll, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

// --- handleSyncStatus tests ---

func TestBridge_HandleSyncStatus_Success(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{
		DeviceID: "laptop-test-123",
		Logger:   testLogger(),
	})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncStatus, nil)
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteSyncStatusResult](t, resp)
	assert.Equal(t, "laptop-test-123", result.DeviceID)
	assert.Empty(t, result.LastSync)
	assert.NotNil(t, result.StoreChecksums)
	assert.Empty(t, result.StoreChecksums)
}

func TestBridge_HandleSyncStatus_EmptyDeviceID(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncStatus, nil)
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteSyncStatusResult](t, resp)
	assert.Empty(t, result.DeviceID)
}

// --- Error mapping tests ---

func TestMapErrorToRPC_SyncFailed(t *testing.T) {
	code, msg := mapErrorToRPC(ErrSyncFailed)
	assert.Equal(t, ErrorCodeSyncFailed, code)
	assert.Contains(t, msg, "sync failed")
}

func TestMapErrorToRPC_SyncConflict(t *testing.T) {
	code, msg := mapErrorToRPC(ErrSyncConflict)
	assert.Equal(t, ErrorCodeSyncConflict, code)
	assert.Contains(t, msg, "sync conflict")
}

func TestMapErrorToRPC_SyncRemoteUnavailable(t *testing.T) {
	code, msg := mapErrorToRPC(ErrSyncRemoteUnavailable)
	assert.Equal(t, ErrorCodeSyncRemoteUnavail, code)
	assert.Contains(t, msg, "remote device unavailable")
}

func TestMapErrorToRPC_SyncNoData(t *testing.T) {
	code, msg := mapErrorToRPC(ErrSyncNoData)
	assert.Equal(t, ErrorCodeSyncNoData, code)
	assert.Contains(t, msg, "no data")
}

func TestMapErrorToRPC_SyncVersionMismatch(t *testing.T) {
	code, msg := mapErrorToRPC(ErrSyncVersionMismatch)
	assert.Equal(t, ErrorCodeSyncVersionMismatch, code)
	assert.Contains(t, msg, "version mismatch")
}

// --- Nil params tests for sync handlers ---

func TestBridge_NilParams_SyncHandlers(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// These handlers require params.
	methodsRequiringParams := []string{
		MethodRemoteSyncTrustStore,
		MethodRemoteSyncOATH,
		MethodRemoteSyncPasswords,
		MethodRemoteSyncAll,
	}

	for _, method := range methodsRequiringParams {
		t.Run(method, func(t *testing.T) {
			req := newRemoteRequest(method, nil)
			resp := b.HandleRequest(context.Background(), req)
			assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
		})
	}
}

func TestBridge_NilParams_SyncStatus_Succeeds(t *testing.T) {
	// SyncStatus does not require params.
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncStatus, nil)
	resp := b.HandleRequest(context.Background(), req)

	require.Nil(t, resp.Error, "expected success but got error: %v", resp.Error)
	result := decodeResult[RemoteSyncStatusResult](t, resp)
	assert.NotNil(t, result.StoreChecksums)
}
