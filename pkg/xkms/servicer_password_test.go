package xkms

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- ErrNotConfigured guards ---

func TestPasswordAdd_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.PasswordAdd(context.Background(), &transport.PasswordAddRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestPasswordGet_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.PasswordGet(context.Background(), &transport.PasswordGetRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestPasswordList_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.PasswordList(context.Background(), &transport.PasswordListRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestPasswordUpdate_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.PasswordUpdate(context.Background(), &transport.PasswordUpdateRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestPasswordDelete_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.PasswordDelete(context.Background(), &transport.PasswordDeleteRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestPasswordStoreUnlock_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.PasswordStoreUnlock(context.Background(), &transport.PasswordStoreUnlockRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestPasswordStoreLock_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.PasswordStoreLock(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestPasswordStoreStatus_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.PasswordStoreStatus(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestPasswordStoreSetAccessMode_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.PasswordStoreSetAccessMode(context.Background(), &transport.PasswordStoreSetAccessModeRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestPasswordGenerate_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.PasswordGenerate(context.Background(), &transport.PasswordGenerateRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

// --- Nil request guards ---

func setupServiceWithPasswordStore(t *testing.T) *XKMSService {
	t.Helper()
	svc, _, _ := setupServiceWithProviders(t)
	backend := storage.NewMemory()
	store := staticpw.NewStore(backend)
	svc.SetPasswordStore(store)
	return svc
}

func TestPasswordAdd_NilRequest(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)

	_, err := svc.PasswordAdd(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestPasswordGet_NilRequest(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)

	_, err := svc.PasswordGet(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestPasswordList_NilRequest(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)

	_, err := svc.PasswordList(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestPasswordUpdate_NilRequest(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)

	err := svc.PasswordUpdate(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestPasswordDelete_NilRequest(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)

	err := svc.PasswordDelete(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestPasswordGenerate_NilRequest(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)

	_, err := svc.PasswordGenerate(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

// --- Delegation tests ---

func TestPasswordAdd_Success(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)

	resp, err := svc.PasswordAdd(context.Background(), &transport.PasswordAddRequest{
		Name:     "My Email",
		Username: "user@example.com",
		Password: "s3cr3t!",
		URL:      "https://mail.example.com",
		Notes:    "Main email account",
	})
	require.NoError(t, err)
	assert.Equal(t, "My Email", resp.Name)
	assert.NotEmpty(t, resp.ID)
	assert.NotEmpty(t, resp.CreatedAt)
}

func TestPasswordGet_Success(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)
	ctx := context.Background()

	addResp, err := svc.PasswordAdd(ctx, &transport.PasswordAddRequest{
		Name:     "Lookup Test",
		Username: "test",
		Password: "pass123",
	})
	require.NoError(t, err)

	getResp, err := svc.PasswordGet(ctx, &transport.PasswordGetRequest{ID: addResp.ID})
	require.NoError(t, err)
	assert.Equal(t, "Lookup Test", getResp.Name)
	assert.Equal(t, "test", getResp.Username)
	assert.Equal(t, "pass123", getResp.Password)
}

func TestPasswordGet_NotFound(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)

	_, err := svc.PasswordGet(context.Background(), &transport.PasswordGetRequest{ID: "nonexistent"})
	require.Error(t, err)
}

func TestPasswordList_Success(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)
	ctx := context.Background()

	_, err := svc.PasswordAdd(ctx, &transport.PasswordAddRequest{
		Name: "PW-1", Username: "u1", Password: "p1",
	})
	require.NoError(t, err)
	_, err = svc.PasswordAdd(ctx, &transport.PasswordAddRequest{
		Name: "PW-2", Username: "u2", Password: "p2",
	})
	require.NoError(t, err)

	resp, err := svc.PasswordList(ctx, &transport.PasswordListRequest{})
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Total)
	assert.Len(t, resp.Passwords, 2)
}

func TestPasswordList_Empty(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)

	resp, err := svc.PasswordList(context.Background(), &transport.PasswordListRequest{})
	require.NoError(t, err)
	assert.Equal(t, 0, resp.Total)
	assert.Empty(t, resp.Passwords)
}

func TestPasswordList_ByFolder(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)
	ctx := context.Background()

	_, err := svc.PasswordAdd(ctx, &transport.PasswordAddRequest{
		Name: "In Folder", Username: "u1", Password: "p1", FolderPath: "work",
	})
	require.NoError(t, err)
	_, err = svc.PasswordAdd(ctx, &transport.PasswordAddRequest{
		Name: "No Folder", Username: "u2", Password: "p2",
	})
	require.NoError(t, err)

	resp, err := svc.PasswordList(ctx, &transport.PasswordListRequest{FolderPath: "work"})
	require.NoError(t, err)
	assert.Equal(t, 1, resp.Total)
}

func TestPasswordUpdate_Success(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)
	ctx := context.Background()

	addResp, err := svc.PasswordAdd(ctx, &transport.PasswordAddRequest{
		Name: "Original", Username: "user", Password: "old-pass",
	})
	require.NoError(t, err)

	newName := "Updated"
	newPass := "new-pass"
	err = svc.PasswordUpdate(ctx, &transport.PasswordUpdateRequest{
		ID:       addResp.ID,
		Name:     &newName,
		Password: &newPass,
	})
	require.NoError(t, err)

	// ID is deterministic from name+folder, so renaming changes the ID.
	newID := staticpw.GenerateID("Updated", "")
	getResp, err := svc.PasswordGet(ctx, &transport.PasswordGetRequest{ID: newID})
	require.NoError(t, err)
	assert.Equal(t, "Updated", getResp.Name)
	assert.Equal(t, "new-pass", getResp.Password)
}

func TestPasswordUpdate_NotFound(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)

	newName := "x"
	err := svc.PasswordUpdate(context.Background(), &transport.PasswordUpdateRequest{
		ID:   "ghost",
		Name: &newName,
	})
	require.Error(t, err)
}

func TestPasswordDelete_Success(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)
	ctx := context.Background()

	addResp, err := svc.PasswordAdd(ctx, &transport.PasswordAddRequest{
		Name: "Delete Me", Username: "user", Password: "pass",
	})
	require.NoError(t, err)

	err = svc.PasswordDelete(ctx, &transport.PasswordDeleteRequest{ID: addResp.ID})
	require.NoError(t, err)

	_, err = svc.PasswordGet(ctx, &transport.PasswordGetRequest{ID: addResp.ID})
	require.Error(t, err)
}

func TestPasswordStoreUnlock_ReturnsNotSupported(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)

	err := svc.PasswordStoreUnlock(context.Background(), &transport.PasswordStoreUnlockRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

func TestPasswordStoreLock_ReturnsNotSupported(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)

	err := svc.PasswordStoreLock(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

func TestPasswordStoreSetAccessMode_ReturnsNotSupported(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)

	err := svc.PasswordStoreSetAccessMode(context.Background(), &transport.PasswordStoreSetAccessModeRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

func TestPasswordStoreStatus_Success(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)
	ctx := context.Background()

	_, err := svc.PasswordAdd(ctx, &transport.PasswordAddRequest{
		Name: "Status Test", Username: "u", Password: "p",
	})
	require.NoError(t, err)

	resp, err := svc.PasswordStoreStatus(ctx)
	require.NoError(t, err)
	assert.Equal(t, "direct", resp.AccessMode)
	assert.False(t, resp.IsLocked)
	assert.True(t, resp.AutoUnsealed)
	assert.Equal(t, 1, resp.PasswordCount)
}

func TestPasswordGenerate_Success(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)

	resp, err := svc.PasswordGenerate(context.Background(), &transport.PasswordGenerateRequest{
		Length: 32,
	})
	require.NoError(t, err)
	assert.Len(t, resp.Password, 32)
}

func TestPasswordGenerate_WithFlags(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)

	resp, err := svc.PasswordGenerate(context.Background(), &transport.PasswordGenerateRequest{
		Length: 16,
		Upper:  true,
		Lower:  true,
		Digits: true,
	})
	require.NoError(t, err)
	assert.Len(t, resp.Password, 16)
}

func TestPasswordAdd_WithExpiration(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)

	resp, err := svc.PasswordAdd(context.Background(), &transport.PasswordAddRequest{
		Name:      "Expiring",
		Username:  "user",
		Password:  "pass",
		ExpiresAt: "2030-01-01T00:00:00Z",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.ID)
}

func TestPasswordAdd_InvalidExpiration(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)

	_, err := svc.PasswordAdd(context.Background(), &transport.PasswordAddRequest{
		Name:      "Bad Expiry",
		Username:  "user",
		Password:  "pass",
		ExpiresAt: "not-a-date",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidKeyAttributes))
}

// --- Password update extended tests ---

func TestPasswordUpdate_AllFields(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)
	ctx := context.Background()

	addResp, err := svc.PasswordAdd(ctx, &transport.PasswordAddRequest{
		Name:     "update-all",
		Username: "user",
		Password: "pass",
	})
	require.NoError(t, err)

	name := "updated-name"
	username := "updated-user"
	password := "updated-pass"
	url := "https://example.com"
	notes := "some notes"
	folder := "/personal"
	err = svc.PasswordUpdate(ctx, &transport.PasswordUpdateRequest{
		ID:         addResp.ID,
		Name:       &name,
		Username:   &username,
		Password:   &password,
		URL:        &url,
		Notes:      &notes,
		FolderPath: &folder,
	})
	require.NoError(t, err)

	// ID is deterministic from name+folder, so renaming changes the ID.
	newID := staticpw.GenerateID("updated-name", "/personal")
	getResp, err := svc.PasswordGet(ctx, &transport.PasswordGetRequest{ID: newID})
	require.NoError(t, err)
	assert.Equal(t, "updated-name", getResp.Name)
	assert.Equal(t, "updated-user", getResp.Username)
	assert.Equal(t, "https://example.com", getResp.URL)
	assert.Equal(t, "some notes", getResp.Notes)
	assert.Equal(t, "/personal", getResp.FolderPath)
}

func TestPasswordUpdate_WithExpiration(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)
	ctx := context.Background()

	addResp, err := svc.PasswordAdd(ctx, &transport.PasswordAddRequest{
		Name:     "expire-update",
		Username: "user",
		Password: "pass",
	})
	require.NoError(t, err)

	expires := "2030-01-01T00:00:00Z"
	err = svc.PasswordUpdate(ctx, &transport.PasswordUpdateRequest{
		ID:        addResp.ID,
		ExpiresAt: &expires,
	})
	require.NoError(t, err)
}

func TestPasswordUpdate_ClearExpiration(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)
	ctx := context.Background()

	addResp, err := svc.PasswordAdd(ctx, &transport.PasswordAddRequest{
		Name:      "clear-expire",
		Username:  "user",
		Password:  "pass",
		ExpiresAt: "2030-01-01T00:00:00Z",
	})
	require.NoError(t, err)

	empty := ""
	err = svc.PasswordUpdate(ctx, &transport.PasswordUpdateRequest{
		ID:        addResp.ID,
		ExpiresAt: &empty,
	})
	require.NoError(t, err)
}

func TestPasswordUpdate_InvalidExpiration(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)
	ctx := context.Background()

	addResp, err := svc.PasswordAdd(ctx, &transport.PasswordAddRequest{
		Name:     "bad-expire",
		Username: "user",
		Password: "pass",
	})
	require.NoError(t, err)

	badDate := "not-a-date"
	err = svc.PasswordUpdate(ctx, &transport.PasswordUpdateRequest{
		ID:        addResp.ID,
		ExpiresAt: &badDate,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidKeyAttributes))
}

// --- Tenant-aware servicer tests ---

// setupServiceWithPasswordManager creates an XKMSService with a
// TenantPasswordStoreManager backed by a registered and unsealed tenant.
func setupServiceWithPasswordManager(t *testing.T) (*XKMSService, *seal.BarrierRegistry) {
	t.Helper()
	svc, _, _ := setupServiceWithProviders(t)

	// Create a system barrier with a software strategy.
	sysBackend, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	sysBarrier, err := seal.NewBarrier(
		slog.Default(),
		sysBackend,
		seal.BarrierConfig{
			RootKeyPath:     "root-key",
			PreferenceOrder: []seal.StrategyID{seal.StrategySoftware},
		},
		seal.NewSoftwareStrategy(),
	)
	require.NoError(t, err)

	ctx := context.Background()
	err = sysBarrier.Initialize(ctx, seal.Credentials{Secret: "test-pw"})
	require.NoError(t, err)

	// Create registry and register a tenant.
	registry, err := seal.NewBarrierRegistry(sysBarrier)
	require.NoError(t, err)

	_, err = registry.RegisterTenant("tenant-1")
	require.NoError(t, err)
	err = registry.InitializeTenant(ctx, "tenant-1", seal.Credentials{Secret: "tenant-pw"})
	require.NoError(t, err)

	// Create system password store and tenant manager.
	systemBackend := storage.NewMemory()
	systemStore := staticpw.NewStore(systemBackend)
	svc.SetPasswordStore(systemStore)

	manager, err := staticpw.NewTenantPasswordStoreManager(registry, systemStore)
	require.NoError(t, err)
	svc.SetPasswordStoreManager(manager)

	return svc, registry
}

// contextWithTenant returns a context with an auth identity containing the given tenant ID.
func contextWithTenant(tenantID string) context.Context {
	identity := &auth.Identity{Subject: "test-user", TenantID: tenantID}
	return auth.WithIdentity(context.Background(), identity)
}

func TestPasswordStoreLock_WithManager(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	ctx := contextWithTenant("tenant-1")

	// Unlock first.
	err := svc.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{})
	require.NoError(t, err)

	// Lock.
	err = svc.PasswordStoreLock(ctx)
	require.NoError(t, err)

	// Verify locked: unlock should succeed again if it was locked.
	err = svc.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{})
	require.NoError(t, err)
}

func TestPasswordStoreLock_NoManager(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)

	// No manager, no tenant context. Returns ErrOperationNotSupported.
	err := svc.PasswordStoreLock(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOperationNotSupported)
}

func TestPasswordStoreLock_NoTenantID(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)

	// Manager is configured but context has no tenant ID.
	// Falls through to system store path which returns ErrOperationNotSupported.
	err := svc.PasswordStoreLock(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOperationNotSupported)
}

func TestPasswordStoreUnlock_WithManager(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	ctx := contextWithTenant("tenant-1")

	err := svc.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{})
	require.NoError(t, err)
}

func TestPasswordStoreUnlock_NoTenantID(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)

	// Manager is configured but no tenant ID in context. Falls through to
	// system store path which returns ErrOperationNotSupported.
	err := svc.PasswordStoreUnlock(context.Background(), &transport.PasswordStoreUnlockRequest{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOperationNotSupported)
}

func TestPasswordStoreUnlock_TenantSealed(t *testing.T) {
	svc, registry := setupServiceWithPasswordManager(t)
	ctx := contextWithTenant("tenant-1")

	// Seal the tenant barrier so unlock fails.
	err := registry.SealTenant("tenant-1")
	require.NoError(t, err)

	err = svc.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{})
	require.Error(t, err)
	assert.ErrorIs(t, err, seal.ErrTenantSealed)
}

func TestPasswordStoreStatus_WithManager(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	ctx := contextWithTenant("tenant-1")

	resp, err := svc.PasswordStoreStatus(ctx)
	require.NoError(t, err)
	assert.Equal(t, "tenant", resp.AccessMode)
	assert.True(t, resp.IsLocked) // starts locked
	assert.False(t, resp.BarrierSealed)
}

func TestPasswordStoreStatus_SystemFallback(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)

	// No tenant in context. Falls through to system store.
	resp, err := svc.PasswordStoreStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "direct", resp.AccessMode)
	assert.False(t, resp.IsLocked)
	assert.True(t, resp.AutoUnsealed)
}

func TestPasswordStoreStatus_TenantUnlocked(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	ctx := contextWithTenant("tenant-1")

	// Unlock the tenant first.
	err := svc.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{})
	require.NoError(t, err)

	resp, err := svc.PasswordStoreStatus(ctx)
	require.NoError(t, err)
	assert.Equal(t, "tenant", resp.AccessMode)
	assert.False(t, resp.IsLocked)
	assert.Equal(t, 0, resp.PasswordCount) // empty store
}

func TestResolvePasswordStore_TenantStore(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	ctx := contextWithTenant("tenant-1")

	// Unlock tenant so resolvePasswordStore returns the tenant store.
	err := svc.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{})
	require.NoError(t, err)

	// Add a password via the tenant store.
	resp, err := svc.PasswordAdd(ctx, &transport.PasswordAddRequest{
		Name:     "Tenant Entry",
		Username: "user",
		Password: "pass",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.ID)

	// Verify the system store does not have it (isolation).
	sysCtx := context.Background() // no tenant
	sysResp, err := svc.PasswordList(sysCtx, &transport.PasswordListRequest{})
	require.NoError(t, err)
	assert.Equal(t, 0, sysResp.Total)
}

func TestResolvePasswordStore_SystemStore(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	ctx := context.Background() // no tenant ID

	// Add via system store.
	resp, err := svc.PasswordAdd(ctx, &transport.PasswordAddRequest{
		Name:     "System Entry",
		Username: "user",
		Password: "pass",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.ID)

	// Verify system store has it.
	listResp, err := svc.PasswordList(ctx, &transport.PasswordListRequest{})
	require.NoError(t, err)
	assert.Equal(t, 1, listResp.Total)
}

func TestResolvePasswordStore_TenantLocked(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	ctx := contextWithTenant("tenant-1")

	// Tenant starts locked. Attempting to add a password should fail.
	_, err := svc.PasswordAdd(ctx, &transport.PasswordAddRequest{
		Name:     "Should Fail",
		Username: "user",
		Password: "pass",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, staticpw.ErrStoreLocked)
}

// --- buildCharset tests ---

func TestBuildCharset_DefaultAll(t *testing.T) {
	req := &transport.PasswordGenerateRequest{}
	charset := buildCharset(req)
	assert.Equal(t, "all", charset)
}

func TestBuildCharset_UpperOnly(t *testing.T) {
	req := &transport.PasswordGenerateRequest{Upper: true}
	charset := buildCharset(req)
	assert.Contains(t, charset, "A")
	assert.Contains(t, charset, "Z")
	assert.NotContains(t, charset, "a")
	assert.NotContains(t, charset, "0")
}

func TestBuildCharset_Mixed(t *testing.T) {
	req := &transport.PasswordGenerateRequest{Lower: true, Digits: true}
	charset := buildCharset(req)
	assert.Contains(t, charset, "a")
	assert.Contains(t, charset, "0")
	assert.NotContains(t, charset, "A")
	assert.NotContains(t, charset, "!")
}

func TestBuildCharset_AllFlags(t *testing.T) {
	req := &transport.PasswordGenerateRequest{
		Upper: true, Lower: true, Digits: true, Symbols: true,
	}
	charset := buildCharset(req)
	assert.Contains(t, charset, "A")
	assert.Contains(t, charset, "a")
	assert.Contains(t, charset, "0")
	assert.Contains(t, charset, "!")
}

// --- tenantIDFromContext tests ---

func TestTenantIDFromContext_WithTenant(t *testing.T) {
	ctx := contextWithTenant("my-tenant")
	assert.Equal(t, "my-tenant", tenantIDFromContext(ctx))
}

func TestTenantIDFromContext_NoIdentity(t *testing.T) {
	ctx := context.Background()
	assert.Equal(t, "", tenantIDFromContext(ctx))
}

func TestTenantIDFromContext_EmptyTenantID(t *testing.T) {
	identity := &auth.Identity{Subject: "user", TenantID: ""}
	ctx := auth.WithIdentity(context.Background(), identity)
	assert.Equal(t, "", tenantIDFromContext(ctx))
}

// --- Scoped password (personal/shared) tests ---

func TestPasswordAdd_SharedFlag(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	ctx := contextWithTenant("tenant-1")

	// Unlock the tenant store.
	err := svc.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{})
	require.NoError(t, err)

	// Add a shared password.
	_, err = svc.PasswordAdd(ctx, &transport.PasswordAddRequest{
		Name:     "Team AWS",
		Password: "secret",
		Shared:   true,
	})
	require.NoError(t, err)

	// Add a personal password (Shared defaults to false).
	_, err = svc.PasswordAdd(ctx, &transport.PasswordAddRequest{
		Name:     "My Gmail",
		Password: "secret",
	})
	require.NoError(t, err)

	// List all with empty scope returns both entries.
	allResp, err := svc.PasswordList(ctx, &transport.PasswordListRequest{})
	require.NoError(t, err)
	assert.Equal(t, 2, allResp.Total)

	// List with scope "shared" returns only the shared entry.
	sharedResp, err := svc.PasswordList(ctx, &transport.PasswordListRequest{Scope: "shared"})
	require.NoError(t, err)
	assert.Equal(t, 1, sharedResp.Total)
	assert.Equal(t, "Team AWS", sharedResp.Passwords[0].Name)

	// List with scope "personal" returns only the personal entry.
	personalResp, err := svc.PasswordList(ctx, &transport.PasswordListRequest{Scope: "personal"})
	require.NoError(t, err)
	assert.Equal(t, 1, personalResp.Total)
	assert.Equal(t, "My Gmail", personalResp.Passwords[0].Name)
}

func TestPasswordList_ScopeAwareWithScopedStore(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	ctx := contextWithTenant("tenant-1")

	// Unlock the tenant store.
	err := svc.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{})
	require.NoError(t, err)

	// Add a shared entry.
	_, err = svc.PasswordAdd(ctx, &transport.PasswordAddRequest{
		Name:     "Shared DB Creds",
		Password: "db-pass",
		Shared:   true,
	})
	require.NoError(t, err)

	// Add a personal entry.
	_, err = svc.PasswordAdd(ctx, &transport.PasswordAddRequest{
		Name:     "Personal SSH Key",
		Password: "ssh-pass",
	})
	require.NoError(t, err)

	// Scope "all" returns both entries.
	allResp, err := svc.PasswordList(ctx, &transport.PasswordListRequest{Scope: "all"})
	require.NoError(t, err)
	assert.Equal(t, 2, allResp.Total)

	// Scope "shared" returns only shared entries.
	sharedResp, err := svc.PasswordList(ctx, &transport.PasswordListRequest{Scope: "shared"})
	require.NoError(t, err)
	assert.Equal(t, 1, sharedResp.Total)
	assert.Equal(t, "Shared DB Creds", sharedResp.Passwords[0].Name)

	// Scope "personal" returns only personal entries.
	personalResp, err := svc.PasswordList(ctx, &transport.PasswordListRequest{Scope: "personal"})
	require.NoError(t, err)
	assert.Equal(t, 1, personalResp.Total)
	assert.Equal(t, "Personal SSH Key", personalResp.Passwords[0].Name)
}

func TestPasswordList_InvalidScope(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	ctx := contextWithTenant("tenant-1")

	// Unlock the tenant store.
	err := svc.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{})
	require.NoError(t, err)

	// List with an invalid scope value.
	_, err = svc.PasswordList(ctx, &transport.PasswordListRequest{Scope: "invalid"})
	require.Error(t, err)
	assert.ErrorIs(t, err, staticpw.ErrInvalidScope)
}

func TestPasswordList_ScopeFallbackNonScopedStore(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)
	ctx := context.Background()

	// Add two entries via the non-scoped system store.
	_, err := svc.PasswordAdd(ctx, &transport.PasswordAddRequest{
		Name:     "Entry-1",
		Password: "pass1",
	})
	require.NoError(t, err)

	_, err = svc.PasswordAdd(ctx, &transport.PasswordAddRequest{
		Name:     "Entry-2",
		Password: "pass2",
	})
	require.NoError(t, err)

	// Listing with scope "personal" on a non-ScopedStore falls back to List()
	// and returns all entries.
	resp, err := svc.PasswordList(ctx, &transport.PasswordListRequest{Scope: "personal"})
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Total)
}

func TestPasswordGet_ReturnsOwnerAndShared(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	ctx := contextWithTenant("tenant-1")

	// Unlock the tenant store.
	err := svc.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{})
	require.NoError(t, err)

	// Add a shared password.
	addResp, err := svc.PasswordAdd(ctx, &transport.PasswordAddRequest{
		Name:     "Shared Secret",
		Password: "top-secret",
		Shared:   true,
	})
	require.NoError(t, err)

	// Get the password and verify OwnerID and Shared fields.
	getResp, err := svc.PasswordGet(ctx, &transport.PasswordGetRequest{ID: addResp.ID})
	require.NoError(t, err)
	assert.Equal(t, "test-user", getResp.OwnerID)
	assert.True(t, getResp.Shared)
}

func TestPasswordAdd_SharedPersonalIsolation(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)

	// Unlock tenant-1 using a generic tenant context.
	unlockCtx := contextWithTenant("tenant-1")
	err := svc.PasswordStoreUnlock(unlockCtx, &transport.PasswordStoreUnlockRequest{})
	require.NoError(t, err)

	// Create user-specific contexts for alice and bob.
	aliceCtx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject:  "alice",
		TenantID: "tenant-1",
	})
	bobCtx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject:  "bob",
		TenantID: "tenant-1",
	})

	// Alice adds a personal password.
	_, err = svc.PasswordAdd(aliceCtx, &transport.PasswordAddRequest{
		Name:     "Alice Private Key",
		Password: "alice-secret",
	})
	require.NoError(t, err)

	// Bob lists personal scope and should see 0 entries (alice's personal
	// passwords are invisible to bob).
	bobPersonal, err := svc.PasswordList(bobCtx, &transport.PasswordListRequest{Scope: "personal"})
	require.NoError(t, err)
	assert.Equal(t, 0, bobPersonal.Total)

	// Bob adds his own personal password.
	_, err = svc.PasswordAdd(bobCtx, &transport.PasswordAddRequest{
		Name:     "Bob SSH Key",
		Password: "bob-secret",
	})
	require.NoError(t, err)

	// Bob lists personal scope and should see exactly 1 entry (his own).
	bobPersonal, err = svc.PasswordList(bobCtx, &transport.PasswordListRequest{Scope: "personal"})
	require.NoError(t, err)
	assert.Equal(t, 1, bobPersonal.Total)
	assert.Equal(t, "Bob SSH Key", bobPersonal.Passwords[0].Name)
}

// --- checkSharedPasswordOwnership tests ---

func TestCheckSharedPasswordOwnership_OwnerAllowed(t *testing.T) {
	// Owner (alice) can modify her own shared password.
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject:  "alice",
		TenantID: "tenant-1",
	})
	pw := &staticpw.StaticPassword{
		OwnerID: "alice",
		Shared:  true,
	}
	err := checkSharedPasswordOwnership(ctx, pw)
	assert.NoError(t, err)
}

func TestCheckSharedPasswordOwnership_NonOwnerDenied(t *testing.T) {
	// Non-owner (bob) cannot modify alice's shared password.
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject:  "bob",
		TenantID: "tenant-1",
	})
	pw := &staticpw.StaticPassword{
		OwnerID: "alice",
		Shared:  true,
	}
	err := checkSharedPasswordOwnership(ctx, pw)
	assert.ErrorIs(t, err, staticpw.ErrNotOwner)
}

func TestCheckSharedPasswordOwnership_AdminBypass(t *testing.T) {
	// Admin can modify any shared password regardless of ownership.
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject:  "bob",
		TenantID: "tenant-1",
		Claims:   map[string]interface{}{"roles": []string{"admin"}},
	})
	pw := &staticpw.StaticPassword{
		OwnerID: "alice",
		Shared:  true,
	}
	err := checkSharedPasswordOwnership(ctx, pw)
	assert.NoError(t, err)
}

func TestCheckSharedPasswordOwnership_SOBypass(t *testing.T) {
	// SO role can modify any shared password regardless of ownership.
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject:  "bob",
		TenantID: "tenant-1",
		Claims:   map[string]interface{}{"roles": []string{"so"}},
	})
	pw := &staticpw.StaticPassword{
		OwnerID: "alice",
		Shared:  true,
	}
	err := checkSharedPasswordOwnership(ctx, pw)
	assert.NoError(t, err)
}

func TestCheckSharedPasswordOwnership_PersonalSkipped(t *testing.T) {
	// Personal passwords (Shared=false) skip ownership checks entirely.
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject:  "bob",
		TenantID: "tenant-1",
	})
	pw := &staticpw.StaticPassword{
		OwnerID: "alice",
		Shared:  false,
	}
	err := checkSharedPasswordOwnership(ctx, pw)
	assert.NoError(t, err)
}

func TestCheckSharedPasswordOwnership_NilIdentity(t *testing.T) {
	// No identity in context means the caller cannot modify a shared password.
	ctx := context.Background()
	pw := &staticpw.StaticPassword{
		OwnerID: "alice",
		Shared:  true,
	}
	err := checkSharedPasswordOwnership(ctx, pw)
	assert.ErrorIs(t, err, staticpw.ErrNotOwner)
}

// --- Shared password ownership enforcement in PasswordUpdate/PasswordDelete ---

func TestPasswordUpdate_SharedOwnershipDenied(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)

	// Unlock the tenant.
	unlockCtx := contextWithTenant("tenant-1")
	err := svc.PasswordStoreUnlock(unlockCtx, &transport.PasswordStoreUnlockRequest{})
	require.NoError(t, err)

	// Alice adds a shared password.
	aliceCtx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject:  "alice",
		TenantID: "tenant-1",
	})
	addResp, err := svc.PasswordAdd(aliceCtx, &transport.PasswordAddRequest{
		Name:     "Alice Shared Secret",
		Password: "alice-pass",
		Shared:   true,
	})
	require.NoError(t, err)

	// Bob (non-owner, no admin/SO role) tries to update it.
	bobCtx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject:  "bob",
		TenantID: "tenant-1",
	})
	newName := "Hijacked"
	err = svc.PasswordUpdate(bobCtx, &transport.PasswordUpdateRequest{
		ID:   addResp.ID,
		Name: &newName,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, staticpw.ErrNotOwner)
}

func TestPasswordDelete_SharedOwnershipDenied(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)

	// Unlock the tenant.
	unlockCtx := contextWithTenant("tenant-1")
	err := svc.PasswordStoreUnlock(unlockCtx, &transport.PasswordStoreUnlockRequest{})
	require.NoError(t, err)

	// Alice adds a shared password.
	aliceCtx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject:  "alice",
		TenantID: "tenant-1",
	})
	addResp, err := svc.PasswordAdd(aliceCtx, &transport.PasswordAddRequest{
		Name:     "Alice Shared DB Creds",
		Password: "alice-db-pass",
		Shared:   true,
	})
	require.NoError(t, err)

	// Bob (non-owner, no admin/SO role) tries to delete it.
	bobCtx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject:  "bob",
		TenantID: "tenant-1",
	})
	err = svc.PasswordDelete(bobCtx, &transport.PasswordDeleteRequest{ID: addResp.ID})
	require.Error(t, err)
	assert.ErrorIs(t, err, staticpw.ErrNotOwner)
}

func TestPasswordUpdate_SharedOwnershipAllowedForAdmin(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)

	// Unlock the tenant.
	unlockCtx := contextWithTenant("tenant-1")
	err := svc.PasswordStoreUnlock(unlockCtx, &transport.PasswordStoreUnlockRequest{})
	require.NoError(t, err)

	// Alice adds a shared password.
	aliceCtx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject:  "alice",
		TenantID: "tenant-1",
	})
	addResp, err := svc.PasswordAdd(aliceCtx, &transport.PasswordAddRequest{
		Name:     "Alice Team Secret",
		Password: "alice-team-pass",
		Shared:   true,
	})
	require.NoError(t, err)

	// Admin user (bob with admin role) can update alice's shared password.
	adminCtx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject:  "bob",
		TenantID: "tenant-1",
		Claims:   map[string]interface{}{"roles": []string{"admin"}},
	})
	newName := "Admin Updated"
	err = svc.PasswordUpdate(adminCtx, &transport.PasswordUpdateRequest{
		ID:   addResp.ID,
		Name: &newName,
	})
	require.NoError(t, err)

	// ID is deterministic from name+folder, so renaming changes the ID.
	newID := staticpw.GenerateID("Admin Updated", "")
	getResp, err := svc.PasswordGet(aliceCtx, &transport.PasswordGetRequest{ID: newID})
	require.NoError(t, err)
	assert.Equal(t, "Admin Updated", getResp.Name)
}

// --- PasswordGenerate error coverage ---

func TestPasswordGenerate_InvalidLength(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)

	_, err := svc.PasswordGenerate(context.Background(), &transport.PasswordGenerateRequest{
		Length: 1, // Below MinLength (8), triggers ErrInvalidLength
	})
	require.Error(t, err)
}

// --- staticPasswordToGetResponse ExpiresAt branch ---

func TestPasswordGet_WithExpiresAt(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)
	ctx := context.Background()

	// Add a password with a future expiration date.
	addResp, err := svc.PasswordAdd(ctx, &transport.PasswordAddRequest{
		Name:      "Expiring Entry",
		Username:  "user",
		Password:  "pass123",
		ExpiresAt: "2030-06-15T12:00:00Z",
	})
	require.NoError(t, err)

	// Retrieve it -- this exercises staticPasswordToGetResponse with non-zero ExpiresAt.
	getResp, err := svc.PasswordGet(ctx, &transport.PasswordGetRequest{ID: addResp.ID})
	require.NoError(t, err)
	assert.Equal(t, "Expiring Entry", getResp.Name)
	assert.Equal(t, "2030-06-15T12:00:00Z", getResp.ExpiresAt)
}
