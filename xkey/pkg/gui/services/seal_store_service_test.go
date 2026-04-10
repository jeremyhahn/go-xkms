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
	"errors"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSealStoreClient implements the transport.SealStoreService interface
// methods needed for testing. It embeds a nil transport.Client to satisfy the
// full interface while only implementing the SealStore methods.
type mockSealStoreClient struct {
	transport.Client // embed to satisfy interface; unused methods will panic

	mu      sync.RWMutex
	secrets map[string][]byte

	putErr    error
	getErr    error
	deleteErr error
	listErr   error
	resealErr error
	statusErr error

	resealedNames []string
	available     bool
	sealerID      string
}

func newMockSealStoreClient() *mockSealStoreClient {
	return &mockSealStoreClient{
		secrets:   make(map[string][]byte),
		available: true,
		sealerID:  "tpm2-sealer",
	}
}

func (m *mockSealStoreClient) SealStorePut(_ context.Context, req *transport.SealStorePutRequest) error {
	if m.putErr != nil {
		return m.putErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secrets[req.Name] = req.Secret
	return nil
}

func (m *mockSealStoreClient) SealStoreGet(_ context.Context, req *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	secret, ok := m.secrets[req.Name]
	if !ok {
		return nil, errors.New("not found")
	}
	return &transport.SealStoreGetResponse{
		Name:   req.Name,
		Secret: secret,
	}, nil
}

func (m *mockSealStoreClient) SealStoreDelete(_ context.Context, req *transport.SealStoreDeleteRequest) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.secrets[req.Name]; !ok {
		return errors.New("not found")
	}
	delete(m.secrets, req.Name)
	return nil
}

func (m *mockSealStoreClient) SealStoreList(_ context.Context) (*transport.SealStoreListResponse, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := make([]string, 0, len(m.secrets))
	for name := range m.secrets {
		names = append(names, name)
	}
	return &transport.SealStoreListResponse{Names: names}, nil
}

func (m *mockSealStoreClient) SealStoreReseal(_ context.Context, req *transport.SealStoreResealRequest) error {
	if m.resealErr != nil {
		return m.resealErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.secrets[req.Name]; !ok {
		return errors.New("not found")
	}
	m.resealedNames = append(m.resealedNames, req.Name)
	return nil
}

func (m *mockSealStoreClient) SealStoreStatus(_ context.Context) (*transport.SealStoreStatusResponse, error) {
	if m.statusErr != nil {
		return nil, m.statusErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := make([]string, 0, len(m.secrets))
	for name := range m.secrets {
		names = append(names, name)
	}
	return &transport.SealStoreStatusResponse{
		Available:   m.available,
		SealerID:    m.sealerID,
		SecretCount: len(m.secrets),
		SecretNames: names,
	}, nil
}

// newTestSealStoreService creates a SealStoreServiceGUI backed by a
// mock client for testing.
func newTestSealStoreService(t *testing.T) (*SealStoreServiceGUI, *mockSealStoreClient) {
	t.Helper()
	mock := newMockSealStoreClient()
	svc := NewSealStoreServiceGUI()
	svc.SetContext(context.Background())
	svc.SetClient(mock)
	return svc, mock
}

// --- Constructor and lifecycle ---

func TestNewSealStoreServiceGUI(t *testing.T) {
	svc := NewSealStoreServiceGUI()
	assert.NotNil(t, svc)
}

func TestSealStoreServiceGUI_SetContext(t *testing.T) {
	svc := NewSealStoreServiceGUI()
	svc.SetContext(context.Background())
	assert.Equal(t, context.Background(), svc.ctx)
}

func TestSealStoreServiceGUI_SetClient(t *testing.T) {
	svc := NewSealStoreServiceGUI()
	mock := newMockSealStoreClient()
	svc.SetClient(mock)

	client, err := svc.getClient()
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestSealStoreServiceGUI_GetClientNil(t *testing.T) {
	svc := NewSealStoreServiceGUI()
	client, err := svc.getClient()
	assert.Nil(t, client)
	assert.ErrorIs(t, err, ErrSealStoreNoClient)
}

func TestSealStoreServiceGUI_GetContextFallback(t *testing.T) {
	svc := NewSealStoreServiceGUI()
	// ctx is nil by default, should fall back to context.Background.
	ctx := svc.getContext()
	assert.NotNil(t, ctx)
}

// --- Put ---

func TestSealStoreServiceGUI_Put(t *testing.T) {
	svc, mock := newTestSealStoreService(t)

	err := svc.Put("api-key", "my-secret-value")
	require.NoError(t, err)

	// Verify the mock received the secret.
	assert.Equal(t, []byte("my-secret-value"), mock.secrets["api-key"])
}

func TestSealStoreServiceGUI_Put_EmptyName(t *testing.T) {
	svc, _ := newTestSealStoreService(t)

	err := svc.Put("", "some-secret")
	assert.ErrorIs(t, err, ErrSealStoreInvalidName)
}

func TestSealStoreServiceGUI_Put_EmptySecret(t *testing.T) {
	svc, _ := newTestSealStoreService(t)

	err := svc.Put("api-key", "")
	assert.ErrorIs(t, err, ErrSealStoreInvalidSecret)
}

func TestSealStoreServiceGUI_Put_NoClient(t *testing.T) {
	svc := NewSealStoreServiceGUI()
	svc.SetContext(context.Background())

	err := svc.Put("api-key", "secret")
	assert.ErrorIs(t, err, ErrSealStoreNoClient)
}

func TestSealStoreServiceGUI_Put_ClientError(t *testing.T) {
	svc, mock := newTestSealStoreService(t)
	mock.putErr = errors.New("storage full")

	err := svc.Put("api-key", "secret")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "storage full")
}

// --- Get ---

func TestSealStoreServiceGUI_Get(t *testing.T) {
	svc, mock := newTestSealStoreService(t)
	mock.secrets["db-password"] = []byte("super-secret")

	secret, err := svc.Get("db-password")
	require.NoError(t, err)
	assert.Equal(t, "super-secret", secret)
}

func TestSealStoreServiceGUI_Get_EmptyName(t *testing.T) {
	svc, _ := newTestSealStoreService(t)

	_, err := svc.Get("")
	assert.ErrorIs(t, err, ErrSealStoreInvalidName)
}

func TestSealStoreServiceGUI_Get_NoClient(t *testing.T) {
	svc := NewSealStoreServiceGUI()
	svc.SetContext(context.Background())

	_, err := svc.Get("some-name")
	assert.ErrorIs(t, err, ErrSealStoreNoClient)
}

func TestSealStoreServiceGUI_Get_NotFound(t *testing.T) {
	svc, _ := newTestSealStoreService(t)

	_, err := svc.Get("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestSealStoreServiceGUI_Get_ClientError(t *testing.T) {
	svc, mock := newTestSealStoreService(t)
	mock.getErr = errors.New("decryption failed")

	_, err := svc.Get("some-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decryption failed")
}

// --- Delete ---

func TestSealStoreServiceGUI_Delete(t *testing.T) {
	svc, mock := newTestSealStoreService(t)
	mock.secrets["old-key"] = []byte("value")

	err := svc.Delete("old-key")
	require.NoError(t, err)

	// Verify deletion.
	_, exists := mock.secrets["old-key"]
	assert.False(t, exists)
}

func TestSealStoreServiceGUI_Delete_EmptyName(t *testing.T) {
	svc, _ := newTestSealStoreService(t)

	err := svc.Delete("")
	assert.ErrorIs(t, err, ErrSealStoreInvalidName)
}

func TestSealStoreServiceGUI_Delete_NoClient(t *testing.T) {
	svc := NewSealStoreServiceGUI()
	svc.SetContext(context.Background())

	err := svc.Delete("some-name")
	assert.ErrorIs(t, err, ErrSealStoreNoClient)
}

func TestSealStoreServiceGUI_Delete_NotFound(t *testing.T) {
	svc, _ := newTestSealStoreService(t)

	err := svc.Delete("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestSealStoreServiceGUI_Delete_ClientError(t *testing.T) {
	svc, mock := newTestSealStoreService(t)
	mock.deleteErr = errors.New("permission denied")

	err := svc.Delete("some-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
}

// --- List ---

func TestSealStoreServiceGUI_List(t *testing.T) {
	svc, mock := newTestSealStoreService(t)
	mock.secrets["alpha"] = []byte("a")
	mock.secrets["beta"] = []byte("b")

	names, err := svc.List()
	require.NoError(t, err)
	assert.Len(t, names, 2)
	assert.Contains(t, names, "alpha")
	assert.Contains(t, names, "beta")
}

func TestSealStoreServiceGUI_List_Empty(t *testing.T) {
	svc, _ := newTestSealStoreService(t)

	names, err := svc.List()
	require.NoError(t, err)
	assert.Empty(t, names)
}

func TestSealStoreServiceGUI_List_NoClient(t *testing.T) {
	svc := NewSealStoreServiceGUI()
	svc.SetContext(context.Background())

	_, err := svc.List()
	assert.ErrorIs(t, err, ErrSealStoreNoClient)
}

func TestSealStoreServiceGUI_List_ClientError(t *testing.T) {
	svc, mock := newTestSealStoreService(t)
	mock.listErr = errors.New("connection lost")

	_, err := svc.List()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connection lost")
}

// --- Reseal ---

func TestSealStoreServiceGUI_Reseal(t *testing.T) {
	svc, mock := newTestSealStoreService(t)
	mock.secrets["my-secret"] = []byte("value")

	err := svc.Reseal("my-secret")
	require.NoError(t, err)

	assert.Contains(t, mock.resealedNames, "my-secret")
}

func TestSealStoreServiceGUI_Reseal_EmptyName(t *testing.T) {
	svc, _ := newTestSealStoreService(t)

	err := svc.Reseal("")
	assert.ErrorIs(t, err, ErrSealStoreInvalidName)
}

func TestSealStoreServiceGUI_Reseal_NoClient(t *testing.T) {
	svc := NewSealStoreServiceGUI()
	svc.SetContext(context.Background())

	err := svc.Reseal("some-name")
	assert.ErrorIs(t, err, ErrSealStoreNoClient)
}

func TestSealStoreServiceGUI_Reseal_NotFound(t *testing.T) {
	svc, _ := newTestSealStoreService(t)

	err := svc.Reseal("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestSealStoreServiceGUI_Reseal_ClientError(t *testing.T) {
	svc, mock := newTestSealStoreService(t)
	mock.resealErr = errors.New("sealer unavailable")

	err := svc.Reseal("some-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sealer unavailable")
}

// --- ResealAll ---

func TestSealStoreServiceGUI_ResealAll(t *testing.T) {
	svc, mock := newTestSealStoreService(t)
	mock.secrets["secret-a"] = []byte("a")
	mock.secrets["secret-b"] = []byte("b")

	err := svc.ResealAll()
	require.NoError(t, err)

	assert.Len(t, mock.resealedNames, 2)
	assert.Contains(t, mock.resealedNames, "secret-a")
	assert.Contains(t, mock.resealedNames, "secret-b")
}

func TestSealStoreServiceGUI_ResealAll_Empty(t *testing.T) {
	svc, mock := newTestSealStoreService(t)

	err := svc.ResealAll()
	require.NoError(t, err)

	assert.Empty(t, mock.resealedNames)
}

func TestSealStoreServiceGUI_ResealAll_NoClient(t *testing.T) {
	svc := NewSealStoreServiceGUI()
	svc.SetContext(context.Background())

	err := svc.ResealAll()
	assert.ErrorIs(t, err, ErrSealStoreNoClient)
}

func TestSealStoreServiceGUI_ResealAll_ListError(t *testing.T) {
	svc, mock := newTestSealStoreService(t)
	mock.listErr = errors.New("list failed")

	err := svc.ResealAll()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "list failed")
}

func TestSealStoreServiceGUI_ResealAll_ResealError(t *testing.T) {
	svc, mock := newTestSealStoreService(t)
	mock.secrets["secret-a"] = []byte("a")
	mock.secrets["secret-b"] = []byte("b")
	mock.resealErr = errors.New("reseal failed")

	err := svc.ResealAll()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reseal failed")
}

// --- GetStatus ---

func TestSealStoreServiceGUI_GetStatus(t *testing.T) {
	svc, mock := newTestSealStoreService(t)
	mock.secrets["key-1"] = []byte("val-1")
	mock.secrets["key-2"] = []byte("val-2")

	status, err := svc.GetStatus()
	require.NoError(t, err)
	require.NotNil(t, status)

	assert.True(t, status.Available)
	assert.Equal(t, "tpm2-sealer", status.SealerID)
	assert.Equal(t, 2, status.SecretCount)
	assert.Len(t, status.SecretNames, 2)
}

func TestSealStoreServiceGUI_GetStatus_NoClient(t *testing.T) {
	svc := NewSealStoreServiceGUI()
	svc.SetContext(context.Background())

	_, err := svc.GetStatus()
	assert.ErrorIs(t, err, ErrSealStoreNoClient)
}

func TestSealStoreServiceGUI_GetStatus_ClientError(t *testing.T) {
	svc, mock := newTestSealStoreService(t)
	mock.statusErr = errors.New("status unavailable")

	_, err := svc.GetStatus()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status unavailable")
}

func TestSealStoreServiceGUI_GetStatus_Empty(t *testing.T) {
	svc, _ := newTestSealStoreService(t)

	status, err := svc.GetStatus()
	require.NoError(t, err)
	require.NotNil(t, status)

	assert.True(t, status.Available)
	assert.Equal(t, 0, status.SecretCount)
	assert.Empty(t, status.SecretNames)
}

func TestSealStoreServiceGUI_GetStatus_NotAvailable(t *testing.T) {
	svc, mock := newTestSealStoreService(t)
	mock.available = false
	mock.sealerID = ""

	status, err := svc.GetStatus()
	require.NoError(t, err)
	require.NotNil(t, status)

	assert.False(t, status.Available)
	assert.Empty(t, status.SealerID)
}

// --- Put then Get round-trip ---

func TestSealStoreServiceGUI_PutThenGet(t *testing.T) {
	svc, _ := newTestSealStoreService(t)

	err := svc.Put("round-trip-key", "round-trip-value")
	require.NoError(t, err)

	secret, err := svc.Get("round-trip-key")
	require.NoError(t, err)
	assert.Equal(t, "round-trip-value", secret)
}

// --- Put then Delete then Get ---

func TestSealStoreServiceGUI_PutDeleteGet(t *testing.T) {
	svc, _ := newTestSealStoreService(t)

	err := svc.Put("transient-key", "transient-value")
	require.NoError(t, err)

	err = svc.Delete("transient-key")
	require.NoError(t, err)

	_, err = svc.Get("transient-key")
	assert.Error(t, err)
}

// --- List returns nil names as empty slice ---

func TestSealStoreServiceGUI_List_NilNamesReturnsEmptySlice(t *testing.T) {
	svc := NewSealStoreServiceGUI()
	svc.SetContext(context.Background())

	// Create a mock that returns nil names to verify defensive handling.
	mock := &mockSealStoreClientNilNames{}
	svc.SetClient(mock)

	names, err := svc.List()
	require.NoError(t, err)
	assert.NotNil(t, names)
	assert.Empty(t, names)
}

// mockSealStoreClientNilNames returns nil names to test defensive handling.
type mockSealStoreClientNilNames struct {
	transport.Client
}

func (m *mockSealStoreClientNilNames) SealStoreList(_ context.Context) (*transport.SealStoreListResponse, error) {
	return &transport.SealStoreListResponse{Names: nil}, nil
}
