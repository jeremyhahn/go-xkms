package xkms

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- ErrNotConfigured guards ---

func TestSealStorePut_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.SealStorePut(context.Background(), &transport.SealStorePutRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestSealStoreGet_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.SealStoreGet(context.Background(), &transport.SealStoreGetRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestSealStoreDelete_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.SealStoreDelete(context.Background(), &transport.SealStoreDeleteRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestSealStoreList_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.SealStoreList(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestSealStoreReseal_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.SealStoreReseal(context.Background(), &transport.SealStoreResealRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestSealStoreStatus_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.SealStoreStatus(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

// --- Nil request guards ---

func TestSealStorePut_NilRequest(t *testing.T) {
	svc, _ := setupServiceWithPlatformStore(t)

	err := svc.SealStorePut(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestSealStoreGet_NilRequest(t *testing.T) {
	svc, _ := setupServiceWithPlatformStore(t)

	_, err := svc.SealStoreGet(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestSealStoreDelete_NilRequest(t *testing.T) {
	svc, _ := setupServiceWithPlatformStore(t)

	err := svc.SealStoreDelete(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestSealStoreReseal_NilRequest(t *testing.T) {
	svc, _ := setupServiceWithPlatformStore(t)

	err := svc.SealStoreReseal(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

// --- Delegation tests ---

func setupServiceWithPlatformStore(t *testing.T) (*XKMSService, *mockPlatformStore) {
	t.Helper()
	svc, _, _ := setupServiceWithProviders(t)
	store := newMockPlatformStore()
	svc.SetPlatformStore(store)
	return svc, store
}

func TestSealStorePut_Success(t *testing.T) {
	svc, store := setupServiceWithPlatformStore(t)

	err := svc.SealStorePut(context.Background(), &transport.SealStorePutRequest{
		Name:   "my-secret",
		Secret: []byte("super-secret-value"),
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("super-secret-value"), store.secrets["my-secret"])
}

func TestSealStoreGet_Success(t *testing.T) {
	svc, store := setupServiceWithPlatformStore(t)
	store.secrets["test-key"] = []byte("test-value")

	resp, err := svc.SealStoreGet(context.Background(), &transport.SealStoreGetRequest{
		Name: "test-key",
	})
	require.NoError(t, err)
	assert.Equal(t, "test-key", resp.Name)
	assert.Equal(t, []byte("test-value"), resp.Secret)
}

func TestSealStoreGet_NotFound(t *testing.T) {
	svc, _ := setupServiceWithPlatformStore(t)

	_, err := svc.SealStoreGet(context.Background(), &transport.SealStoreGetRequest{
		Name: "missing",
	})
	require.Error(t, err)
}

func TestSealStoreDelete_Success(t *testing.T) {
	svc, store := setupServiceWithPlatformStore(t)
	store.secrets["del-me"] = []byte("value")

	err := svc.SealStoreDelete(context.Background(), &transport.SealStoreDeleteRequest{
		Name: "del-me",
	})
	require.NoError(t, err)
	_, exists := store.secrets["del-me"]
	assert.False(t, exists)
}

func TestSealStoreList_Success(t *testing.T) {
	svc, store := setupServiceWithPlatformStore(t)
	store.secrets["secret-a"] = []byte("a")
	store.secrets["secret-b"] = []byte("b")

	resp, err := svc.SealStoreList(context.Background())
	require.NoError(t, err)
	assert.Len(t, resp.Names, 2)
}

func TestSealStoreList_Empty(t *testing.T) {
	svc, _ := setupServiceWithPlatformStore(t)

	resp, err := svc.SealStoreList(context.Background())
	require.NoError(t, err)
	assert.Empty(t, resp.Names)
}

func TestSealStoreReseal_Success(t *testing.T) {
	svc, _ := setupServiceWithPlatformStore(t)

	err := svc.SealStoreReseal(context.Background(), &transport.SealStoreResealRequest{
		Name: "any-secret",
	})
	require.NoError(t, err)
}

func TestSealStoreStatus_Success(t *testing.T) {
	svc, store := setupServiceWithPlatformStore(t)
	store.secrets["s1"] = []byte("v1")
	store.secrets["s2"] = []byte("v2")

	resp, err := svc.SealStoreStatus(context.Background())
	require.NoError(t, err)
	assert.True(t, resp.Available)
	assert.Equal(t, 2, resp.SecretCount)
	assert.Len(t, resp.SecretNames, 2)
}

func TestSealStoreStatus_Empty(t *testing.T) {
	svc, _ := setupServiceWithPlatformStore(t)

	resp, err := svc.SealStoreStatus(context.Background())
	require.NoError(t, err)
	assert.True(t, resp.Available)
	assert.Equal(t, 0, resp.SecretCount)
}

// --- Error delegation tests ---

func TestSealStoreList_ListError(t *testing.T) {
	svc, store := setupServiceWithPlatformStore(t)
	store.err = errors.New("list failed")

	_, err := svc.SealStoreList(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list failed")
}

func TestSealStoreStatus_ListError(t *testing.T) {
	svc, store := setupServiceWithPlatformStore(t)
	store.err = errors.New("status list failed")

	_, err := svc.SealStoreStatus(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status list failed")
}
