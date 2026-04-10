package xkms

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- ErrNotConfigured guards ---

func TestListUsers_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ListUsers(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestGetUser_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetUser(context.Background(), "alice")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestDeleteUser_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.DeleteUser(context.Background(), "alice")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestEnableUser_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.EnableUser(context.Background(), "alice")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestDisableUser_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.DisableUser(context.Background(), "alice")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestListUserCredentials_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ListUserCredentials(context.Background(), "alice")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

// --- Delegation tests with mock user store ---

func setupServiceWithUserStore(t *testing.T) (*XKMSService, *mockUserStore) {
	t.Helper()
	svc, _, _ := setupServiceWithProviders(t)
	store := newMockUserStore()
	svc.SetUserStore(store)

	// Seed a test user
	ctx := context.Background()
	_, err := store.Create(ctx, "alice", "Alice Smith", user.RoleAdmin, "")
	require.NoError(t, err)

	return svc, store
}

func TestListUsers_Success(t *testing.T) {
	svc, store := setupServiceWithUserStore(t)
	ctx := context.Background()

	// Add a second user
	_, err := store.Create(ctx, "bob", "Bob Jones", user.RoleUser, "")
	require.NoError(t, err)

	resp, err := svc.ListUsers(ctx)
	require.NoError(t, err)
	assert.Len(t, resp.Users, 2)
}

func TestListUsers_Empty(t *testing.T) {
	svc, _, _ := setupServiceWithProviders(t)
	store := newMockUserStore()
	svc.SetUserStore(store)

	resp, err := svc.ListUsers(context.Background())
	require.NoError(t, err)
	assert.Empty(t, resp.Users)
}

func TestGetUser_Success(t *testing.T) {
	svc, _ := setupServiceWithUserStore(t)

	resp, err := svc.GetUser(context.Background(), "alice")
	require.NoError(t, err)
	assert.Equal(t, "alice", resp.User.Username)
	assert.Equal(t, "Alice Smith", resp.User.DisplayName)
	assert.Equal(t, "admin", resp.User.Role)
	assert.True(t, resp.User.Enabled)
}

func TestGetUser_NotFound(t *testing.T) {
	svc, _ := setupServiceWithUserStore(t)

	_, err := svc.GetUser(context.Background(), "nonexistent")
	require.Error(t, err)
}

func TestDeleteUser_Success(t *testing.T) {
	svc, store := setupServiceWithUserStore(t)

	err := svc.DeleteUser(context.Background(), "alice")
	require.NoError(t, err)

	_, exists := store.users["alice"]
	assert.False(t, exists)
}

func TestDeleteUser_NotFound(t *testing.T) {
	svc, _ := setupServiceWithUserStore(t)

	err := svc.DeleteUser(context.Background(), "ghost")
	require.Error(t, err)
}

func TestEnableUser_Success(t *testing.T) {
	svc, store := setupServiceWithUserStore(t)

	// First disable the user
	store.users["alice"].Enabled = false

	err := svc.EnableUser(context.Background(), "alice")
	require.NoError(t, err)
	assert.True(t, store.users["alice"].Enabled)
}

func TestEnableUser_NotFound(t *testing.T) {
	svc, _ := setupServiceWithUserStore(t)

	err := svc.EnableUser(context.Background(), "ghost")
	require.Error(t, err)
}

func TestDisableUser_Success(t *testing.T) {
	svc, store := setupServiceWithUserStore(t)

	err := svc.DisableUser(context.Background(), "alice")
	require.NoError(t, err)
	assert.False(t, store.users["alice"].Enabled)
}

func TestDisableUser_NotFound(t *testing.T) {
	svc, _ := setupServiceWithUserStore(t)

	err := svc.DisableUser(context.Background(), "ghost")
	require.Error(t, err)
}

func TestListUserCredentials_Success(t *testing.T) {
	svc, store := setupServiceWithUserStore(t)

	// Add credentials to the user
	store.users["alice"].Credentials = []user.Credential{
		{ID: []byte("cred-1"), Name: "My Key"},
		{ID: []byte("cred-2"), Name: "Backup Key"},
	}

	resp, err := svc.ListUserCredentials(context.Background(), "alice")
	require.NoError(t, err)
	assert.Len(t, resp.Credentials, 2)
	assert.Equal(t, "My Key", resp.Credentials[0].DisplayName)
}

func TestListUserCredentials_UserNotFound(t *testing.T) {
	svc, _ := setupServiceWithUserStore(t)

	_, err := svc.ListUserCredentials(context.Background(), "ghost")
	require.Error(t, err)
}

// --- ListUsers error delegation ---

func TestListUsers_StoreError(t *testing.T) {
	svc, store := setupServiceWithUserStore(t)
	store.err = errors.New("store failure")

	_, err := svc.ListUsers(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list users")
}
