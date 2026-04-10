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
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	filestorage "github.com/jeremyhahn/go-xkms/pkg/storage/file"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestStorage returns a MemoryStorage pre-populated with test credentials.
func newTestStorage(t *testing.T, creds ...*authenticator.StoredCredential) *authenticator.MemoryStorage {
	t.Helper()
	storage := authenticator.NewMemoryStorage()
	for _, c := range creds {
		require.NoError(t, storage.Store(c))
	}
	return storage
}

func testCredential(id []byte, rpID, rpName, userName string, alg int) *authenticator.StoredCredential {
	return &authenticator.StoredCredential{
		CredentialID:    id,
		RPID:            rpID,
		RPName:          rpName,
		UserName:        userName,
		UserDisplayName: userName,
		Algorithm:       alg,
		SignCount:       5,
		Discoverable:    true,
		CreatedAt:       time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC).Unix(),
	}
}

func TestNewFIDO2Service(t *testing.T) {
	svc := NewFIDO2Service(nil)
	assert.NotNil(t, svc)
}

func TestNewFIDO2Service_WithStorage(t *testing.T) {
	storage := authenticator.NewMemoryStorage()
	svc := NewFIDO2Service(storage)
	assert.NotNil(t, svc)
}

func TestFIDO2Service_SetContext(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.SetContext(context.Background())
}

// --- ListCredentials ---

func TestFIDO2Service_ListCredentials_NilStorage(t *testing.T) {
	svc := NewFIDO2Service(nil)
	creds, err := svc.ListCredentials()
	require.NoError(t, err)
	assert.NotNil(t, creds)
	assert.Empty(t, creds)
}

func TestFIDO2Service_ListCredentials_EmptyStorage(t *testing.T) {
	storage := authenticator.NewMemoryStorage()
	svc := NewFIDO2Service(storage)
	creds, err := svc.ListCredentials()
	require.NoError(t, err)
	assert.NotNil(t, creds)
	assert.Empty(t, creds)
}

func TestFIDO2Service_ListCredentials_WithCredentials(t *testing.T) {
	cred1 := testCredential([]byte{0x01, 0x02}, "example.com", "Example", "alice", -7)
	cred2 := testCredential([]byte{0x03, 0x04}, "test.org", "Test", "bob", -257)
	storage := newTestStorage(t, cred1, cred2)

	svc := NewFIDO2Service(storage)
	creds, err := svc.ListCredentials()
	require.NoError(t, err)
	assert.Len(t, creds, 2)

	// Verify credential data is properly converted.
	credMap := make(map[string]FIDO2Credential, len(creds))
	for _, c := range creds {
		credMap[c.ID] = c
	}

	c1, ok := credMap[hex.EncodeToString([]byte{0x01, 0x02})]
	require.True(t, ok)
	assert.Equal(t, "example.com", c1.RelyingPartyID)
	assert.Equal(t, "Example", c1.RelyingParty)
	assert.Equal(t, "alice", c1.UserName)
	assert.Equal(t, "ES256", c1.Algorithm)
	assert.Equal(t, 5, c1.UseCount)
	assert.True(t, c1.Discoverable)
	assert.True(t, c1.LastUsed.IsZero())

	c2, ok := credMap[hex.EncodeToString([]byte{0x03, 0x04})]
	require.True(t, ok)
	assert.Equal(t, "test.org", c2.RelyingPartyID)
	assert.Equal(t, "RS256", c2.Algorithm)
}

// --- GetCredential ---

func TestFIDO2Service_GetCredential_EmptyID(t *testing.T) {
	svc := NewFIDO2Service(nil)
	_, err := svc.GetCredential("")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrFIDO2InvalidID))
}

func TestFIDO2Service_GetCredential_NilStorage(t *testing.T) {
	svc := NewFIDO2Service(nil)
	_, err := svc.GetCredential("0102")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrFIDO2StorageNotSet))
}

func TestFIDO2Service_GetCredential_InvalidHex(t *testing.T) {
	storage := authenticator.NewMemoryStorage()
	svc := NewFIDO2Service(storage)
	_, err := svc.GetCredential("not-hex!")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrFIDO2InvalidID))
}

func TestFIDO2Service_GetCredential_NotFound(t *testing.T) {
	storage := authenticator.NewMemoryStorage()
	svc := NewFIDO2Service(storage)
	_, err := svc.GetCredential("aabb")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrFIDO2CredentialNotFound))
}

func TestFIDO2Service_GetCredential_Found(t *testing.T) {
	credID := []byte{0xaa, 0xbb}
	cred := testCredential(credID, "example.com", "Example", "alice", -8)
	storage := newTestStorage(t, cred)

	svc := NewFIDO2Service(storage)
	result, err := svc.GetCredential(hex.EncodeToString(credID))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "example.com", result.RelyingPartyID)
	assert.Equal(t, "Example", result.RelyingParty)
	assert.Equal(t, "alice", result.UserName)
	assert.Equal(t, "EdDSA", result.Algorithm)
	assert.Equal(t, 5, result.UseCount)
}

// --- DeleteCredential ---

func TestFIDO2Service_DeleteCredential_EmptyID(t *testing.T) {
	svc := NewFIDO2Service(nil)
	err := svc.DeleteCredential("")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrFIDO2InvalidID))
}

func TestFIDO2Service_DeleteCredential_NilStorage(t *testing.T) {
	svc := NewFIDO2Service(nil)
	err := svc.DeleteCredential("0102")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrFIDO2StorageNotSet))
}

func TestFIDO2Service_DeleteCredential_InvalidHex(t *testing.T) {
	storage := authenticator.NewMemoryStorage()
	svc := NewFIDO2Service(storage)
	err := svc.DeleteCredential("zzz")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrFIDO2InvalidID))
}

func TestFIDO2Service_DeleteCredential_NotFound(t *testing.T) {
	storage := authenticator.NewMemoryStorage()
	svc := NewFIDO2Service(storage)
	err := svc.DeleteCredential("aabb")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrFIDO2CredentialNotFound))
}

func TestFIDO2Service_DeleteCredential_Success(t *testing.T) {
	credID := []byte{0xaa, 0xbb}
	cred := testCredential(credID, "example.com", "Example", "alice", -7)
	storage := newTestStorage(t, cred)

	svc := NewFIDO2Service(storage)
	err := svc.DeleteCredential(hex.EncodeToString(credID))
	require.NoError(t, err)

	// Verify the credential is gone.
	_, err = svc.GetCredential(hex.EncodeToString(credID))
	assert.True(t, errors.Is(err, ErrFIDO2CredentialNotFound))
}

// --- GetRelyingParties ---

func TestFIDO2Service_GetRelyingParties_NilStorage(t *testing.T) {
	svc := NewFIDO2Service(nil)
	rps, err := svc.GetRelyingParties()
	require.NoError(t, err)
	assert.NotNil(t, rps)
	assert.Empty(t, rps)
}

func TestFIDO2Service_GetRelyingParties_EmptyStorage(t *testing.T) {
	storage := authenticator.NewMemoryStorage()
	svc := NewFIDO2Service(storage)
	rps, err := svc.GetRelyingParties()
	require.NoError(t, err)
	assert.NotNil(t, rps)
	assert.Empty(t, rps)
}

func TestFIDO2Service_GetRelyingParties_Aggregation(t *testing.T) {
	cred1 := testCredential([]byte{0x01}, "example.com", "Example", "alice", -7)
	cred2 := testCredential([]byte{0x02}, "example.com", "Example", "bob", -7)
	cred3 := testCredential([]byte{0x03}, "test.org", "Test Org", "charlie", -257)
	storage := newTestStorage(t, cred1, cred2, cred3)

	svc := NewFIDO2Service(storage)
	rps, err := svc.GetRelyingParties()
	require.NoError(t, err)
	assert.Len(t, rps, 2)

	rpMap := make(map[string]RelyingParty, len(rps))
	for _, rp := range rps {
		rpMap[rp.ID] = rp
	}

	exampleRP, ok := rpMap["example.com"]
	require.True(t, ok)
	assert.Equal(t, "Example", exampleRP.Name)
	assert.Equal(t, 2, exampleRP.CredentialCount)

	testRP, ok := rpMap["test.org"]
	require.True(t, ok)
	assert.Equal(t, "Test Org", testRP.Name)
	assert.Equal(t, 1, testRP.CredentialCount)
}

// --- Bridge ---

func TestFIDO2Service_StartBridge_NoClientFunc(t *testing.T) {
	svc := NewFIDO2Service(nil)
	err := svc.StartPhoneBridge()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrFIDO2BridgeNoClient))
}

func TestFIDO2Service_StartBridge_NilClient(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.SetClientFunc(func() xkms.Client { return nil })
	err := svc.StartPhoneBridge()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrFIDO2BridgeNoClient))
}

func TestFIDO2Service_StartStopBridge(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.SetClientFunc(func() xkms.Client { return &mockCAClient{} })

	// Initially not running.
	status := svc.GetBridgeStatus()
	assert.False(t, status.Running)

	// Start.
	err := svc.StartPhoneBridge()
	require.NoError(t, err)
	status = svc.GetBridgeStatus()
	assert.True(t, status.Running)
	assert.NotEmpty(t, status.Uptime)

	// Double start should fail.
	err = svc.StartPhoneBridge()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrFIDO2BridgeRunning))

	// Stop.
	err = svc.StopPhoneBridge()
	require.NoError(t, err)
	status = svc.GetBridgeStatus()
	assert.False(t, status.Running)

	// Double stop should fail.
	err = svc.StopPhoneBridge()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrFIDO2BridgeStopped))
}

func TestFIDO2Service_HandleBridgeRequest_NotRunning(t *testing.T) {
	svc := NewFIDO2Service(nil)
	_, err := svc.HandleBridgeRequest("remote.listKeys", nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrFIDO2BridgeStopped))
}

func TestFIDO2Service_GetBridgeStatus_NotRunning(t *testing.T) {
	svc := NewFIDO2Service(nil)
	status := svc.GetBridgeStatus()
	assert.False(t, status.Running)
	assert.Empty(t, status.Uptime)
	assert.True(t, status.StartedAt.IsZero())
}

// --- Delete and verify lifecycle ---

func TestFIDO2Service_DeleteCredential_VerifyRemoved(t *testing.T) {
	credID := []byte{0xde, 0xad, 0xbe, 0xef}
	cred := testCredential(credID, "example.com", "Example", "alice", -7)
	storage := newTestStorage(t, cred)

	svc := NewFIDO2Service(storage)
	hexID := hex.EncodeToString(credID)

	// Credential exists.
	got, err := svc.GetCredential(hexID)
	require.NoError(t, err)
	assert.Equal(t, "example.com", got.RelyingPartyID)

	// Delete it.
	require.NoError(t, svc.DeleteCredential(hexID))

	// Credential is gone from GetCredential.
	_, err = svc.GetCredential(hexID)
	assert.True(t, errors.Is(err, ErrFIDO2CredentialNotFound))

	// Credential is gone from ListCredentials.
	creds, err := svc.ListCredentials()
	require.NoError(t, err)
	assert.Empty(t, creds)

	// Relying parties should also be empty.
	rps, err := svc.GetRelyingParties()
	require.NoError(t, err)
	assert.Empty(t, rps)
}

func TestFIDO2Service_DeleteCredential_MultipleCredentials(t *testing.T) {
	cred1 := testCredential([]byte{0x01}, "example.com", "Example", "alice", -7)
	cred2 := testCredential([]byte{0x02}, "example.com", "Example", "bob", -7)
	cred3 := testCredential([]byte{0x03}, "other.org", "Other", "charlie", -257)
	storage := newTestStorage(t, cred1, cred2, cred3)

	svc := NewFIDO2Service(storage)

	// Delete one credential from a multi-credential RP.
	require.NoError(t, svc.DeleteCredential(hex.EncodeToString([]byte{0x01})))

	// Two credentials remain.
	creds, err := svc.ListCredentials()
	require.NoError(t, err)
	assert.Len(t, creds, 2)

	// RP example.com still exists with one credential.
	rps, err := svc.GetRelyingParties()
	require.NoError(t, err)
	assert.Len(t, rps, 2)
}

// --- coseAlgorithmName ---

func TestCoseAlgorithmName_Known(t *testing.T) {
	tests := []struct {
		alg  int
		name string
	}{
		{-7, "ES256"},
		{-35, "ES384"},
		{-36, "ES512"},
		{-257, "RS256"},
		{-258, "RS384"},
		{-259, "RS512"},
		{-8, "EdDSA"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.name, coseAlgorithmName(tt.alg))
	}
}

func TestCoseAlgorithmName_Unknown(t *testing.T) {
	assert.Equal(t, "COSE(-999)", coseAlgorithmName(-999))
	assert.Equal(t, "COSE(0)", coseAlgorithmName(0))
}

// --- storedToFIDO2Credential ---

func TestStoredToFIDO2Credential(t *testing.T) {
	unixTS := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	stored := &authenticator.StoredCredential{
		CredentialID:    []byte{0xde, 0xad},
		RPID:            "example.com",
		RPName:          "Example Site",
		UserName:        "alice",
		UserDisplayName: "Alice Smith",
		Algorithm:       -7,
		SignCount:       42,
		Discoverable:    true,
		CreatedAt:       unixTS,
	}

	result := storedToFIDO2Credential(stored)
	assert.Equal(t, "dead", result.ID)
	assert.Equal(t, "example.com", result.RelyingPartyID)
	assert.Equal(t, "Example Site", result.RelyingParty)
	assert.Equal(t, "alice", result.UserName)
	assert.Equal(t, "Alice Smith", result.UserDisplayName)
	assert.Equal(t, "ES256", result.Algorithm)
	assert.Equal(t, 42, result.UseCount)
	assert.True(t, result.Discoverable)
	assert.True(t, result.LastUsed.IsZero())
	// Compare Unix timestamps to avoid timezone-dependent equality issues.
	assert.Equal(t, unixTS, result.CreatedAt.Unix())
}

func TestFIDO2Service_SetStorage(t *testing.T) {
	// Start with nil storage.
	svc := NewFIDO2Service(nil)
	_, err := svc.GetCredential("0102")
	assert.ErrorIs(t, err, ErrFIDO2StorageNotSet)

	// Wire storage.
	backend, backendErr := filestorage.New(filepath.Join(t.TempDir(), "fido2"))
	require.NoError(t, backendErr)
	storage, storageErr := authenticator.NewBackendStorage(backend, "test/")
	require.NoError(t, storageErr)
	svc.SetStorage(storage)

	// Now listing should work.
	creds, err := svc.ListCredentials()
	assert.NoError(t, err)
	assert.Empty(t, creds)
}

// ---------------------------------------------------------------------------
// SetAuditLogger
// ---------------------------------------------------------------------------

// testFIDO2AuditLogger captures audit log entries for verification.
type testFIDO2AuditLogger struct {
	entries []audit.Entry
}

func (l *testFIDO2AuditLogger) Log(e audit.Entry) { l.entries = append(l.entries, e) }
func (l *testFIDO2AuditLogger) LogKeyOperation(op audit.OperationType, backend, keyID string, success bool, err error, durationMs int64) {
	l.Log(audit.Entry{Operation: op, Backend: backend, KeyID: keyID, Success: success})
}
func (l *testFIDO2AuditLogger) LogCryptoOperation(op audit.OperationType, backend, keyID, deviceID, deviceName string, success bool, err error, durationMs int64) {
	l.Log(audit.Entry{Operation: op})
}
func (l *testFIDO2AuditLogger) LogConnectionEvent(op audit.OperationType, deviceID, deviceName string, details map[string]any) {
	l.Log(audit.Entry{Operation: op})
}
func (l *testFIDO2AuditLogger) LogServiceEvent(op audit.OperationType, details map[string]any) {
	l.Log(audit.Entry{Operation: op, Success: true, Details: details})
}
func (l *testFIDO2AuditLogger) LogPINOperation(audit.OperationType, string, bool, error, map[string]any) {
}
func (l *testFIDO2AuditLogger) LogTPMOperation(audit.OperationType, bool, error, map[string]any) {
}
func (l *testFIDO2AuditLogger) LogPasswordStoreOperation(audit.OperationType, string, bool, error, map[string]any) {
}
func (l *testFIDO2AuditLogger) LogUserPresenceEvent(audit.OperationType, string, bool, map[string]any) {
}

func TestFIDO2Service_SetAuditLogger(t *testing.T) {
	svc := NewFIDO2Service(nil)
	assert.Nil(t, svc.auditLogger)

	logger := &testFIDO2AuditLogger{}
	svc.SetAuditLogger(logger)
	assert.NotNil(t, svc.auditLogger)
}

func TestFIDO2Service_SetAuditLogger_Nil(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.SetAuditLogger(nil)
	assert.Nil(t, svc.auditLogger)
}

func TestFIDO2Service_ListCredentials_WithAuditLogger(t *testing.T) {
	cred := testCredential([]byte{0x01}, "example.com", "Example", "alice", -7)
	storage := newTestStorage(t, cred)

	logger := &testFIDO2AuditLogger{}
	svc := NewFIDO2Service(storage)
	svc.SetAuditLogger(logger)

	_, err := svc.ListCredentials()
	require.NoError(t, err)

	// Audit logger should have been called.
	require.Len(t, logger.entries, 1)
	assert.Equal(t, audit.OpFIDO2CredentialAccessed, logger.entries[0].Operation)
}

func TestFIDO2Service_GetCredential_WithAuditLogger(t *testing.T) {
	credID := []byte{0xaa, 0xbb}
	cred := testCredential(credID, "example.com", "Example", "alice", -7)
	storage := newTestStorage(t, cred)

	logger := &testFIDO2AuditLogger{}
	svc := NewFIDO2Service(storage)
	svc.SetAuditLogger(logger)

	_, err := svc.GetCredential(hex.EncodeToString(credID))
	require.NoError(t, err)

	require.Len(t, logger.entries, 1)
	assert.Equal(t, audit.OpFIDO2CredentialAccessed, logger.entries[0].Operation)
	assert.Equal(t, hex.EncodeToString(credID), logger.entries[0].KeyID)
}

func TestFIDO2Service_DeleteCredential_WithAuditLogger(t *testing.T) {
	credID := []byte{0xaa, 0xbb}
	cred := testCredential(credID, "example.com", "Example", "alice", -7)
	storage := newTestStorage(t, cred)

	logger := &testFIDO2AuditLogger{}
	svc := NewFIDO2Service(storage)
	svc.SetAuditLogger(logger)

	err := svc.DeleteCredential(hex.EncodeToString(credID))
	require.NoError(t, err)

	require.Len(t, logger.entries, 1)
	assert.Equal(t, audit.OpFIDO2CredentialDeleted, logger.entries[0].Operation)
}

// ---------------------------------------------------------------------------
// HandleBridgeRequest - running bridge
// ---------------------------------------------------------------------------

func TestFIDO2Service_HandleBridgeRequest_Running_UnknownMethod(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.SetContext(context.Background())
	svc.SetClientFunc(func() xkms.Client { return &mockCAClient{} })

	err := svc.StartPhoneBridge()
	require.NoError(t, err)
	defer svc.StopPhoneBridge()

	// Sending an unknown method should return an error from the bridge.
	_, err = svc.HandleBridgeRequest("nonexistent.method", json.RawMessage(`{}`))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bridge")

	// Request counter should have been incremented.
	status := svc.GetBridgeStatus()
	assert.True(t, status.Running)
	assert.Greater(t, status.Requests, int64(0))
}

func TestFIDO2Service_HandleBridgeRequest_NilParams(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.SetContext(context.Background())
	svc.SetClientFunc(func() xkms.Client { return &mockCAClient{} })

	err := svc.StartPhoneBridge()
	require.NoError(t, err)
	defer svc.StopPhoneBridge()

	// Even with nil params, should attempt to handle and return bridge error.
	_, err = svc.HandleBridgeRequest("ping", nil)
	// ping should succeed or return a meaningful error.
	// The bridge handles ping internally, so this should work.
	if err != nil {
		assert.Contains(t, err.Error(), "bridge")
	}
}

// ---------------------------------------------------------------------------
// StartPhoneBridge with audit logger
// ---------------------------------------------------------------------------

func TestFIDO2Service_StartStopBridge_WithAuditLogger(t *testing.T) {
	logger := &testFIDO2AuditLogger{}
	svc := NewFIDO2Service(nil)
	svc.SetAuditLogger(logger)
	svc.SetClientFunc(func() xkms.Client { return &mockCAClient{} })

	err := svc.StartPhoneBridge()
	require.NoError(t, err)

	// Start should log a service event.
	startFound := false
	for _, e := range logger.entries {
		if e.Operation == audit.OpServiceStarted {
			startFound = true
			svcName, ok := e.Details["service"].(string)
			assert.True(t, ok)
			assert.Equal(t, "fido2_phone_bridge", svcName)
		}
	}
	assert.True(t, startFound, "expected service started audit entry")

	err = svc.StopPhoneBridge()
	require.NoError(t, err)

	// Stop should log a service event.
	stopFound := false
	for _, e := range logger.entries {
		if e.Operation == audit.OpServiceStopped {
			stopFound = true
		}
	}
	assert.True(t, stopFound, "expected service stopped audit entry")
}

// ---------------------------------------------------------------------------
// Error sentinels
// ---------------------------------------------------------------------------

func TestFIDO2Service_ErrorSentinels(t *testing.T) {
	sentinels := []struct {
		err      error
		contains string
	}{
		{ErrFIDO2CredentialNotFound, "credential not found"},
		{ErrFIDO2InvalidID, "invalid credential ID"},
		{ErrFIDO2BridgeRunning, "bridge already running"},
		{ErrFIDO2BridgeStopped, "bridge not running"},
		{ErrFIDO2StorageNotSet, "storage not configured"},
		{ErrFIDO2BridgeNoClient, "no server connection"},
	}
	for _, tt := range sentinels {
		assert.NotNil(t, tt.err)
		assert.Contains(t, tt.err.Error(), tt.contains, "sentinel %v", tt.err)
	}
}

// ---------------------------------------------------------------------------
// Key backend methods
// ---------------------------------------------------------------------------

// stubFIDO2Backend is a minimal FIDO2KeyBackend for testing service methods
// that only need a registered backend (not actual crypto operations).
type stubFIDO2Backend struct {
	bt types.BackendType
}

func (s *stubFIDO2Backend) Type() types.BackendType                  { return s.bt }
func (s *stubFIDO2Backend) Capabilities() keybackend.FIDO2KeyCapabilities { return keybackend.FIDO2KeyCapabilities{} }
func (s *stubFIDO2Backend) GenerateCredentialKey(int, []byte) (keybackend.KeyHandle, []byte, error) { return nil, nil, nil }
func (s *stubFIDO2Backend) Sign(keybackend.KeyHandle, int, []byte) ([]byte, error)                  { return nil, nil }
func (s *stubFIDO2Backend) LoadKey([]byte, int) (keybackend.KeyHandle, error)                        { return nil, nil }
func (s *stubFIDO2Backend) DeleteKey(keybackend.KeyHandle) error                                     { return nil }
func (s *stubFIDO2Backend) ExportPrivateKey(keybackend.KeyHandle) ([]byte, error)                    { return nil, nil }
func (s *stubFIDO2Backend) ImportPrivateKey([]byte, int, []byte) (keybackend.KeyHandle, error)       { return nil, nil }
func (s *stubFIDO2Backend) Close() error                                                              { return nil }

// newTestCompositeBackend creates a CompositeBackend with a stub backend
// registered under the given default type.
func newTestCompositeBackend(defaultType types.BackendType) *keybackend.CompositeBackend {
	cb := keybackend.NewCompositeBackend(defaultType)
	cb.Register(defaultType, &stubFIDO2Backend{bt: defaultType})
	return cb
}

func TestFIDO2Service_SetKeyBackend(t *testing.T) {
	svc := NewFIDO2Service(nil)
	assert.Nil(t, svc.keyBackend)

	cb := newTestCompositeBackend(types.BackendTypeSoftware)
	svc.SetKeyBackend(cb)
	assert.NotNil(t, svc.keyBackend)
}

func TestFIDO2Service_SetKeyBackend_Nil(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.SetKeyBackend(nil)
	assert.Nil(t, svc.keyBackend)
}

func TestFIDO2Service_SetDefaultBackend_NilKeyBackend(t *testing.T) {
	svc := NewFIDO2Service(nil)
	err := svc.SetDefaultBackend(types.BackendTypeSoftware)
	assert.ErrorIs(t, err, ErrFIDO2KeyBackendNotSet)
}

func TestFIDO2Service_SetDefaultBackend_BackendNotFound(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.SetKeyBackend(newTestCompositeBackend(types.BackendTypeSoftware))

	err := svc.SetDefaultBackend(types.BackendType("nonexistent"))
	assert.ErrorIs(t, err, ErrFIDO2BackendNotFound)
}

func TestFIDO2Service_SetDefaultBackend_Success(t *testing.T) {
	svc := NewFIDO2Service(nil)
	cb := keybackend.NewCompositeBackend(types.BackendTypeSoftware)
	cb.Register(types.BackendTypeSoftware, &stubFIDO2Backend{bt: types.BackendTypeSoftware})
	cb.Register(types.BackendType("other"), &stubFIDO2Backend{bt: types.BackendTypeSoftware})
	svc.SetKeyBackend(cb)

	// Default starts as "software".
	assert.Equal(t, types.BackendTypeSoftware, svc.DefaultBackend())

	// Switch to "other".
	err := svc.SetDefaultBackend(types.BackendType("other"))
	require.NoError(t, err)
	assert.Equal(t, types.BackendType("other"), svc.DefaultBackend())
}

func TestFIDO2Service_DefaultBackend_NilKeyBackend(t *testing.T) {
	svc := NewFIDO2Service(nil)
	assert.Equal(t, types.BackendType(""), svc.DefaultBackend())
}

func TestFIDO2Service_DefaultBackend_WithKeyBackend(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.SetKeyBackend(newTestCompositeBackend(types.BackendTypeSoftware))
	assert.Equal(t, types.BackendTypeSoftware, svc.DefaultBackend())
}

func TestFIDO2Service_ListKeyBackends_NilKeyBackend(t *testing.T) {
	svc := NewFIDO2Service(nil)
	assert.Nil(t, svc.ListKeyBackends())
}

func TestFIDO2Service_ListKeyBackends_WithBackends(t *testing.T) {
	svc := NewFIDO2Service(nil)
	cb := keybackend.NewCompositeBackend(types.BackendTypeSoftware)
	cb.Register(types.BackendTypeSoftware, &stubFIDO2Backend{bt: types.BackendTypeSoftware})
	cb.Register(types.BackendType("tpm2"), &stubFIDO2Backend{bt: types.BackendTypeSoftware})
	svc.SetKeyBackend(cb)

	ids := svc.ListKeyBackends()
	require.Len(t, ids, 2)
	assert.Contains(t, ids, types.BackendTypeSoftware)
	assert.Contains(t, ids, types.BackendType("tpm2"))
}
