package xkms

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
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

// The system-level store is barrier protected and has no session or PIN
// strategy, so neither staticpw mode can be enforced for it.
func TestPasswordStoreSetAccessMode_SystemStoreReportsBoundary(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)

	for _, mode := range []staticpw.AccessMode{staticpw.AccessSessionBased, staticpw.AccessPINPerOperation} {
		err := svc.PasswordStoreSetAccessMode(context.Background(), &transport.PasswordStoreSetAccessModeRequest{
			Mode: string(mode),
		})
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrOperationNotSupported), "mode %s", mode)
	}
}

func TestPasswordStoreSetAccessMode_NilRequest(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)

	err := svc.PasswordStoreSetAccessMode(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestPasswordStoreSetAccessMode_InvalidMode(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)

	for _, mode := range []string{"", "session-based", "PIN_PER_OPERATION", "direct"} {
		err := svc.PasswordStoreSetAccessMode(context.Background(), &transport.PasswordStoreSetAccessModeRequest{
			Mode: mode,
		})
		require.Error(t, err, "mode %q", mode)
		assert.True(t, errors.Is(err, ErrInvalidAccessMode), "mode %q", mode)
	}
}

// A tenant store is session based, so requesting that mode is the idempotent
// success path and requesting the PIN-per-operation strategy is refused.
func TestPasswordStoreSetAccessMode_TenantSessionBased(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	ctx := contextWithTenant("tenant-1")

	err := svc.PasswordStoreSetAccessMode(ctx, &transport.PasswordStoreSetAccessModeRequest{
		Mode: string(staticpw.AccessSessionBased),
	})
	require.NoError(t, err)

	err = svc.PasswordStoreSetAccessMode(ctx, &transport.PasswordStoreSetAccessModeRequest{
		Mode: string(staticpw.AccessPINPerOperation),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

func TestPasswordAccessMode_ReportsEffectiveStrategy(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)

	tenantMode, err := svc.PasswordAccessMode(contextWithTenant("tenant-1"))
	require.NoError(t, err)
	assert.Equal(t, staticpw.AccessSessionBased, tenantMode)

	systemMode, err := svc.PasswordAccessMode(context.Background())
	require.NoError(t, err)
	assert.Equal(t, staticpw.AccessMode(""), systemMode)
}

func TestPasswordAccessMode_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.PasswordAccessMode(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
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

// testPasswordStoreUserPIN is the user PIN provisioned on the PIN backend that
// setupServiceWithPasswordManager wires into the service. Unlocking a tenant
// password store verifies this PIN, so tests that expect a successful unlock
// must supply it.
const testPasswordStoreUserPIN = "654321"

// unlockRequest builds a password store unlock request carrying the PIN
// provisioned by setupServiceWithPasswordManager.
func unlockRequest() *transport.PasswordStoreUnlockRequest {
	return &transport.PasswordStoreUnlockRequest{UserPIN: testPasswordStoreUserPIN}
}

// setupServiceWithPasswordManager creates an XKMSService with a
// TenantPasswordStoreManager backed by a registered and unsealed tenant, and a
// PIN backend holding testPasswordStoreUserPIN so unlocks can be authorized.
func setupServiceWithPasswordManager(t *testing.T) (*XKMSService, *seal.BarrierRegistry) {
	t.Helper()
	svc, _, _ := setupServiceWithProviders(t)
	svc.SetPINManager(&mockPINManager{soPin: "123456", userPin: testPasswordStoreUserPIN})

	// Create a system barrier with a software strategy.
	sysBackend, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	sysBarrier, err := seal.NewBarrier(
		slog.Default(),
		sysBackend,
		seal.BarrierConfig{
			RootKeyPath:     "root-key",
			PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase},
		},
		seal.NewSoftwareStrategy(),
	)
	require.NoError(t, err)

	ctx := context.Background()
	sysCreds, err := seal.CredentialsFor([]byte("test-pw"))
	require.NoError(t, err)
	defer sysCreds.Secret.Destroy()
	err = sysBarrier.Initialize(ctx, sysCreds)
	require.NoError(t, err)

	// Create registry and register a tenant.
	registry, err := seal.NewBarrierRegistry(sysBarrier)
	require.NoError(t, err)

	_, err = registry.RegisterTenant("tenant-1")
	require.NoError(t, err)
	tenantCreds, err := seal.CredentialsFor([]byte("tenant-pw"))
	require.NoError(t, err)
	defer tenantCreds.Secret.Destroy()
	err = registry.InitializeTenant(ctx, "tenant-1", tenantCreds)
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
	err := svc.PasswordStoreUnlock(ctx, unlockRequest())
	require.NoError(t, err)

	// Lock.
	err = svc.PasswordStoreLock(ctx)
	require.NoError(t, err)

	// Verify locked: unlock should succeed again if it was locked.
	err = svc.PasswordStoreUnlock(ctx, unlockRequest())
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

	err := svc.PasswordStoreUnlock(ctx, unlockRequest())
	require.NoError(t, err)
}

func TestPasswordStoreUnlock_NoTenantID(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)

	// Manager is configured but no tenant ID in context. Falls through to
	// system store path which returns ErrOperationNotSupported.
	err := svc.PasswordStoreUnlock(context.Background(), unlockRequest())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOperationNotSupported)
}

func TestPasswordStoreUnlock_TenantSealed(t *testing.T) {
	svc, registry := setupServiceWithPasswordManager(t)
	ctx := contextWithTenant("tenant-1")

	// Seal the tenant barrier so unlock fails.
	err := registry.SealTenant("tenant-1")
	require.NoError(t, err)

	err = svc.PasswordStoreUnlock(ctx, unlockRequest())
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
	err := svc.PasswordStoreUnlock(ctx, unlockRequest())
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
	err := svc.PasswordStoreUnlock(ctx, unlockRequest())
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

// --- scopedTenantIDFromContext tests ---

func TestScopedTenantIDFromContext_WithTenant(t *testing.T) {
	ctx := contextWithTenant("my-tenant")
	assert.Equal(t, "my-tenant", scopedTenantIDFromContext(ctx))
}

func TestScopedTenantIDFromContext_NoIdentity(t *testing.T) {
	ctx := context.Background()
	assert.Equal(t, "", scopedTenantIDFromContext(ctx))
}

func TestScopedTenantIDFromContext_EmptyTenantID(t *testing.T) {
	identity := &auth.Identity{Subject: "user", TenantID: ""}
	ctx := auth.WithIdentity(context.Background(), identity)
	assert.Equal(t, "", scopedTenantIDFromContext(ctx))
}

// A caller in the reserved system tenant is platform-scoped, so it resolves to
// the system store — NOT to a per-tenant store literally named "system". This
// is the regression guard for the drift that made the transports reject
// system-tenant identities outright.
func TestScopedTenantIDFromContext_SystemTenantIsPlatformScoped(t *testing.T) {
	identity := &auth.Identity{Subject: "admin", TenantID: qrdbsdk.SystemTenantID}
	ctx := auth.WithIdentity(context.Background(), identity)
	assert.Equal(t, "", scopedTenantIDFromContext(ctx))
}

// A tenant whose name merely resembles the reserved one is an ordinary tenant
// and must stay scoped.
func TestScopedTenantIDFromContext_SystemLookalikeStaysScoped(t *testing.T) {
	for _, id := range []string{"system-2", "System", "systems"} {
		identity := &auth.Identity{Subject: "user", TenantID: id}
		ctx := auth.WithIdentity(context.Background(), identity)
		assert.Equal(t, id, scopedTenantIDFromContext(ctx), "tenant %q must remain scoped", id)
	}
}

// --- Scoped password (personal/shared) tests ---

func TestPasswordAdd_SharedFlag(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	ctx := contextWithTenant("tenant-1")

	// Unlock the tenant store.
	err := svc.PasswordStoreUnlock(ctx, unlockRequest())
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
	err := svc.PasswordStoreUnlock(ctx, unlockRequest())
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
	err := svc.PasswordStoreUnlock(ctx, unlockRequest())
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
	err := svc.PasswordStoreUnlock(ctx, unlockRequest())
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

	aliceCtx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject:  "alice",
		TenantID: "tenant-1",
	})
	bobCtx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject:  "bob",
		TenantID: "tenant-1",
	})

	// Sessions are per user: each opens their own.
	require.NoError(t, svc.PasswordStoreUnlock(aliceCtx, unlockRequest()))
	require.NoError(t, svc.PasswordStoreUnlock(bobCtx, unlockRequest()))

	// Alice adds a personal password and a shared one.
	private, err := svc.PasswordAdd(aliceCtx, &transport.PasswordAddRequest{
		Name:     "Alice Private Key",
		Password: "alice-secret",
	})
	require.NoError(t, err)
	_, err = svc.PasswordAdd(aliceCtx, &transport.PasswordAddRequest{
		Name:     "Team Wiki",
		Password: "wiki-secret",
		Shared:   true,
	})
	require.NoError(t, err)

	// Bob sees none of alice's personal passwords, cannot address hers by ID,
	// and sees the shared one.
	bobPersonal, err := svc.PasswordList(bobCtx, &transport.PasswordListRequest{Scope: "personal"})
	require.NoError(t, err)
	assert.Equal(t, 0, bobPersonal.Total)
	_, err = svc.PasswordGet(bobCtx, &transport.PasswordGetRequest{ID: private.ID})
	assert.ErrorIs(t, err, staticpw.ErrPasswordNotFound)
	assert.ErrorIs(t, svc.PasswordDelete(bobCtx, &transport.PasswordDeleteRequest{ID: private.ID}), staticpw.ErrPasswordNotFound)
	bobShared, err := svc.PasswordList(bobCtx, &transport.PasswordListRequest{Scope: "shared"})
	require.NoError(t, err)
	assert.Equal(t, 1, bobShared.Total)

	// Bob adds his own personal password and sees exactly it.
	_, err = svc.PasswordAdd(bobCtx, &transport.PasswordAddRequest{
		Name:     "Bob SSH Key",
		Password: "bob-secret",
	})
	require.NoError(t, err)
	bobPersonal, err = svc.PasswordList(bobCtx, &transport.PasswordListRequest{Scope: "personal"})
	require.NoError(t, err)
	assert.Equal(t, 1, bobPersonal.Total)
	assert.Equal(t, "Bob SSH Key", bobPersonal.Passwords[0].Name)

	// Alice's entry survived bob's attempts.
	got, err := svc.PasswordGet(aliceCtx, &transport.PasswordGetRequest{ID: private.ID})
	require.NoError(t, err)
	assert.Equal(t, "alice-secret", got.Password)
}

// TestPasswordStoreSessions_ArePerUser proves one user's unlock or lock never
// opens or closes another user's personal session, and that shared entries
// stay usable while a session is locked.
func TestPasswordStoreSessions_ArePerUser(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	aliceCtx := sharedPasswordCtx("alice")
	bobCtx := sharedPasswordCtx("bob")

	require.NoError(t, svc.PasswordStoreUnlock(aliceCtx, unlockRequest()))
	bobStatus, err := svc.PasswordStoreStatus(bobCtx)
	require.NoError(t, err)
	assert.True(t, bobStatus.IsLocked, "alice unlocking must not unlock bob")

	// Bob, locked, still reads and writes shared entries.
	_, err = svc.PasswordAdd(bobCtx, &transport.PasswordAddRequest{Name: "shared", Password: "pw", Shared: true})
	require.NoError(t, err)
	_, err = svc.PasswordAdd(bobCtx, &transport.PasswordAddRequest{Name: "personal", Password: "pw"})
	assert.ErrorIs(t, err, staticpw.ErrStoreLocked)

	require.NoError(t, svc.PasswordStoreUnlock(bobCtx, unlockRequest()))
	require.NoError(t, svc.PasswordStoreLock(aliceCtx))
	bobStatus, err = svc.PasswordStoreStatus(bobCtx)
	require.NoError(t, err)
	assert.False(t, bobStatus.IsLocked, "alice locking must not lock bob")
	aliceStatus, err := svc.PasswordStoreStatus(aliceCtx)
	require.NoError(t, err)
	assert.True(t, aliceStatus.IsLocked)
	assert.ErrorIs(t, svc.PasswordStoreLock(aliceCtx), staticpw.ErrStoreAlreadyLocked)
}

// TestPasswordStore_SystemTenantHasItsOwnStore is the regression for the
// system-tenant "Tenant not found": a system-tenant identity is served from
// the system tenant's own store, isolated from every tenant's.
func TestPasswordStore_SystemTenantHasItsOwnStore(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	rootCtx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "root", TenantID: qrdbsdk.SystemTenantID})
	tenantCtx := sharedPasswordCtx("alice")

	require.NoError(t, svc.PasswordStoreUnlock(rootCtx, unlockRequest()))
	_, err := svc.PasswordAdd(rootCtx, &transport.PasswordAddRequest{Name: "sys-shared", Password: "pw", Shared: true})
	require.NoError(t, err)
	_, err = svc.PasswordAdd(rootCtx, &transport.PasswordAddRequest{Name: "sys-personal", Password: "pw"})
	require.NoError(t, err)

	status, err := svc.PasswordStoreStatus(rootCtx)
	require.NoError(t, err)
	assert.Equal(t, 2, status.PasswordCount)

	listed, err := svc.PasswordList(tenantCtx, &transport.PasswordListRequest{})
	require.NoError(t, err)
	assert.Equal(t, 0, listed.Total, "a tenant must not see the system tenant's entries")

	// The unscoped store serving requests without an identity is separate.
	flat, err := svc.PasswordList(context.Background(), &transport.PasswordListRequest{})
	require.NoError(t, err)
	assert.Equal(t, 0, flat.Total)
	assert.ErrorIs(t, svc.PasswordStoreUnlock(context.Background(), unlockRequest()), ErrOperationNotSupported)
}

// --- checkSharedPasswordOwnership tests ---

// sharedPasswordTenant is the tenant the ownership tests run in: the tenant
// setupServiceWithPasswordManager registers a barrier for.
const sharedPasswordTenant = "tenant-1"

// seedPasswordRoles wires svc to a first-boot-seeded qrdb node on which
// sharedPasswordTenant has been provisioned, and returns a function resolving
// a built-in role name to the identifier that tenant's role is persisted
// under -- exactly what a real user record carries in RoleIDs.
func seedPasswordRoles(t *testing.T, svc *XKMSService) func(string) string {
	t.Helper()
	n, err := testutil.NewFirstBootNode(t)
	require.NoError(t, err)
	require.NoError(t, n.ProvisionTenant(sharedPasswordTenant))
	svc.SetUserClients(n.Client().Users(), n.Client().Roles())
	return func(roleName string) string {
		id, err := n.RoleID(sharedPasswordTenant, roleName)
		require.NoError(t, err)
		return id
	}
}

// sharedPasswordCtx returns a context whose identity is subject in
// sharedPasswordTenant holding exactly roles.
func sharedPasswordCtx(subject string, roles ...string) context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{
		Subject:  subject,
		TenantID: sharedPasswordTenant,
		Roles:    roles,
	})
}

// alicesSharedPassword is a shared entry owned by alice.
func alicesSharedPassword() *staticpw.StaticPassword {
	return &staticpw.StaticPassword{OwnerID: "alice", Shared: true}
}

func TestCheckSharedPasswordOwnership_OwnerAllowed(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)
	err := svc.checkSharedPasswordOwnership(sharedPasswordCtx("alice"), alicesSharedPassword())
	assert.NoError(t, err)
}

// TestCheckSharedPasswordOwnership_AdministratorRoleIDsAllowed proves a member
// of the tenant's Admin or SO role -- identified by the role IDs the identity
// actually carries -- may modify a shared password it does not own.
func TestCheckSharedPasswordOwnership_AdministratorRoleIDsAllowed(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)
	roleID := seedPasswordRoles(t, svc)

	for _, roleName := range []string{qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameSO} {
		ctx := sharedPasswordCtx("bob", roleID(qrdbsdk.RoleNameUser), roleID(roleName))
		assert.NoError(t, svc.checkSharedPasswordOwnership(ctx, alicesSharedPassword()), roleName)
	}
}

// TestCheckSharedPasswordOwnership_NonAdministratorDenied proves a non-owner
// holding only non-administrator roles is refused.
func TestCheckSharedPasswordOwnership_NonAdministratorDenied(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)
	roleID := seedPasswordRoles(t, svc)

	for _, roles := range [][]string{
		nil,
		{roleID(qrdbsdk.RoleNameUser)},
		{roleID(qrdbsdk.RoleNameOperator)},
		{roleID(qrdbsdk.RoleNameAuditor)},
	} {
		err := svc.checkSharedPasswordOwnership(sharedPasswordCtx("bob", roles...), alicesSharedPassword())
		assert.ErrorIs(t, err, staticpw.ErrNotOwner, "roles %v", roles)
	}
}

// TestCheckSharedPasswordOwnership_RoleNameConfersNothing is the #1074
// regression: an identity whose Roles spell "admin" or "so" -- the shape an
// unverified token claim produces -- used to take the administrator override.
// Role names are not role identifiers and confer nothing.
func TestCheckSharedPasswordOwnership_RoleNameConfersNothing(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)
	seedPasswordRoles(t, svc)

	for _, name := range []string{qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameSO} {
		err := svc.checkSharedPasswordOwnership(sharedPasswordCtx("bob", name), alicesSharedPassword())
		assert.ErrorIs(t, err, staticpw.ErrNotOwner, name)
	}
}

// TestCheckSharedPasswordOwnership_OtherTenantsAdminDenied proves the override
// is scoped to the caller's tenant: the system tenant's Admin ID does not make
// a tenant identity an administrator of that tenant's vault.
func TestCheckSharedPasswordOwnership_OtherTenantsAdminDenied(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)
	n, err := testutil.NewFirstBootNode(t)
	require.NoError(t, err)
	require.NoError(t, n.ProvisionTenant(sharedPasswordTenant))
	svc.SetUserClients(n.Client().Users(), n.Client().Roles())
	systemAdminID, err := n.RoleID(qrdbsdk.SystemTenantID, qrdbsdk.RoleNameAdmin)
	require.NoError(t, err)

	err = svc.checkSharedPasswordOwnership(sharedPasswordCtx("bob", systemAdminID), alicesSharedPassword())
	assert.ErrorIs(t, err, staticpw.ErrNotOwner)
}

func TestCheckSharedPasswordOwnership_PersonalSkipped(t *testing.T) {
	// Personal passwords (Shared=false) skip ownership checks entirely.
	svc := setupServiceWithPasswordStore(t)
	pw := &staticpw.StaticPassword{OwnerID: "alice", Shared: false}
	assert.NoError(t, svc.checkSharedPasswordOwnership(sharedPasswordCtx("bob"), pw))
}

func TestCheckSharedPasswordOwnership_NilIdentity(t *testing.T) {
	// No identity in context means the caller cannot modify a shared password.
	svc := setupServiceWithPasswordStore(t)
	err := svc.checkSharedPasswordOwnership(context.Background(), alicesSharedPassword())
	assert.ErrorIs(t, err, staticpw.ErrNotOwner)
}

// TestCheckSharedPasswordOwnership_NoRoleClientDenied proves that without a
// role store the override cannot be established, so a non-owner is refused
// whatever it carries.
func TestCheckSharedPasswordOwnership_NoRoleClientDenied(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)
	n, err := testutil.NewFirstBootNode(t)
	require.NoError(t, err)
	adminID, err := n.RoleID(qrdbsdk.SystemTenantID, qrdbsdk.RoleNameAdmin)
	require.NoError(t, err)

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "bob", TenantID: qrdbsdk.SystemTenantID, Roles: []string{adminID}})
	err = svc.checkSharedPasswordOwnership(ctx, alicesSharedPassword())
	assert.ErrorIs(t, err, staticpw.ErrNotOwner)
}

// TestCheckSharedPasswordOwnership_RoleResolutionFailure proves a role store
// that cannot answer fails the request closed with the typed resolution error
// rather than granting or silently refusing.
func TestCheckSharedPasswordOwnership_RoleResolutionFailure(t *testing.T) {
	svc, _, _ := setupServiceWithUserClients(t) // mockRoleClient answers GetRoleByName with (nil, nil)

	err := svc.checkSharedPasswordOwnership(sharedPasswordCtx("bob", "some-role-id"), alicesSharedPassword())
	var resErr *auth.RoleResolutionError
	require.ErrorAs(t, err, &resErr)
	assert.Equal(t, sharedPasswordTenant, resErr.TenantID)
}

// --- Shared password ownership enforcement in PasswordUpdate/PasswordDelete ---

// addAlicesSharedPassword unlocks sharedPasswordTenant's store and has alice
// add a shared entry, returning its ID.
func addAlicesSharedPassword(t *testing.T, svc *XKMSService, name string) string {
	t.Helper()
	require.NoError(t, svc.PasswordStoreUnlock(contextWithTenant(sharedPasswordTenant), unlockRequest()))
	addResp, err := svc.PasswordAdd(sharedPasswordCtx("alice"), &transport.PasswordAddRequest{
		Name:     name,
		Password: "alice-pass",
		Shared:   true,
	})
	require.NoError(t, err)
	return addResp.ID
}

func TestPasswordUpdate_SharedOwnershipDenied(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	roleID := seedPasswordRoles(t, svc)
	id := addAlicesSharedPassword(t, svc, "Alice Shared Secret")

	newName := "Hijacked"
	for _, roles := range [][]string{nil, {roleID(qrdbsdk.RoleNameOperator)}, {qrdbsdk.RoleNameAdmin}} {
		err := svc.PasswordUpdate(sharedPasswordCtx("bob", roles...), &transport.PasswordUpdateRequest{ID: id, Name: &newName})
		assert.ErrorIs(t, err, staticpw.ErrNotOwner, "roles %v", roles)
	}
}

func TestPasswordDelete_SharedOwnershipDenied(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	roleID := seedPasswordRoles(t, svc)
	id := addAlicesSharedPassword(t, svc, "Alice Shared DB Creds")

	for _, roles := range [][]string{nil, {roleID(qrdbsdk.RoleNameOperator)}, {qrdbsdk.RoleNameSO}} {
		err := svc.PasswordDelete(sharedPasswordCtx("bob", roles...), &transport.PasswordDeleteRequest{ID: id})
		assert.ErrorIs(t, err, staticpw.ErrNotOwner, "roles %v", roles)
	}
}

func TestPasswordUpdate_SharedOwnershipAllowedForAdmin(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	roleID := seedPasswordRoles(t, svc)
	id := addAlicesSharedPassword(t, svc, "Alice Team Secret")

	// bob holds the tenant's Admin role by ID, as a seeded user record does.
	newName := "Admin Updated"
	err := svc.PasswordUpdate(sharedPasswordCtx("bob", roleID(qrdbsdk.RoleNameAdmin)), &transport.PasswordUpdateRequest{
		ID:   id,
		Name: &newName,
	})
	require.NoError(t, err)

	// ID is deterministic from name+folder, so renaming changes the ID.
	getResp, err := svc.PasswordGet(sharedPasswordCtx("alice"), &transport.PasswordGetRequest{ID: staticpw.GenerateID("Admin Updated", "")})
	require.NoError(t, err)
	assert.Equal(t, "Admin Updated", getResp.Name)
}

func TestPasswordDelete_SharedOwnershipAllowedForSO(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	roleID := seedPasswordRoles(t, svc)
	id := addAlicesSharedPassword(t, svc, "Alice Retired Secret")

	require.NoError(t, svc.PasswordDelete(sharedPasswordCtx("bob", roleID(qrdbsdk.RoleNameSO)), &transport.PasswordDeleteRequest{ID: id}))
	_, err := svc.PasswordGet(sharedPasswordCtx("alice"), &transport.PasswordGetRequest{ID: id})
	assert.Error(t, err)
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

// --- Password store unlock credential enforcement ---

// A wrong user PIN must not open the vault, and the store must stay locked.
func TestPasswordStoreUnlock_WrongPINKeepsStoreLocked(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	ctx := contextWithTenant("tenant-1")

	err := svc.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{
		UserPIN: "000000",
	})
	require.Error(t, err)

	status, err := svc.PasswordStoreStatus(ctx)
	require.NoError(t, err)
	assert.True(t, status.IsLocked, "store must stay locked after a wrong PIN")

	// A locked session must not serve personal entries.
	_, err = svc.PasswordList(ctx, &transport.PasswordListRequest{Scope: "personal"})
	assert.ErrorIs(t, err, staticpw.ErrStoreLocked)
}

// Regression: unlocking used to succeed with no credential at all because the
// supplied PIN was never verified. An empty PIN must now fail closed.
func TestPasswordStoreUnlock_MissingPINRejected(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	ctx := contextWithTenant("tenant-1")

	err := svc.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPasswordStoreUserPINRequired)

	status, err := svc.PasswordStoreStatus(ctx)
	require.NoError(t, err)
	assert.True(t, status.IsLocked, "store must stay locked when no PIN is supplied")

	_, err = svc.PasswordAdd(ctx, &transport.PasswordAddRequest{Name: "personal", Password: "pw"})
	assert.ErrorIs(t, err, staticpw.ErrStoreLocked)
}

// The correct user PIN opens the session and the store becomes readable.
func TestPasswordStoreUnlock_CorrectPINUnlocks(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	ctx := contextWithTenant("tenant-1")

	require.NoError(t, svc.PasswordStoreUnlock(ctx, unlockRequest()))

	status, err := svc.PasswordStoreStatus(ctx)
	require.NoError(t, err)
	assert.False(t, status.IsLocked)

	resp, err := svc.PasswordList(ctx, &transport.PasswordListRequest{})
	require.NoError(t, err)
	assert.Equal(t, 0, resp.Total)
}

// A deployment with no PIN backend has no credential to verify, so the unlock
// is refused rather than performed without one.
func TestPasswordStoreUnlock_NoPINBackendFailsClosed(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	svc.SetPINManager(nil)
	ctx := contextWithTenant("tenant-1")

	err := svc.PasswordStoreUnlock(ctx, unlockRequest())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPasswordStoreUserPINNotProvisioned)

	status, err := svc.PasswordStoreStatus(ctx)
	require.NoError(t, err)
	assert.True(t, status.IsLocked)
}

// A PIN backend that has never had a user PIN set is the same explicit state:
// there is nothing to verify, so the unlock fails closed.
func TestPasswordStoreUnlock_UserPINNotSetFailsClosed(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	svc.SetPINManager(&mockPINManager{soPin: "123456"})
	ctx := contextWithTenant("tenant-1")

	err := svc.PasswordStoreUnlock(ctx, unlockRequest())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPasswordStoreUserPINNotProvisioned)

	status, err := svc.PasswordStoreStatus(ctx)
	require.NoError(t, err)
	assert.True(t, status.IsLocked)
}

// A nil unlock request is rejected before any credential handling.
func TestPasswordStoreUnlock_NilRequest(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	ctx := contextWithTenant("tenant-1")

	err := svc.PasswordStoreUnlock(ctx, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNilRequest)
}

// --- PasswordGet session state handling ---

// On an unlocked session, Get returns the entry exactly as stored:
// confidentiality at rest is provided by the tenant barrier, not by a
// per-request decryption step.
func TestPasswordGet_UnlockedSessionReturnsEntry(t *testing.T) {
	svc := setupServiceWithPasswordStore(t)
	ctx := context.Background()

	addResp, err := svc.PasswordAdd(ctx, &transport.PasswordAddRequest{
		Name: "Plain Get", Username: "user", Password: "pass",
	})
	require.NoError(t, err)

	getResp, err := svc.PasswordGet(ctx, &transport.PasswordGetRequest{ID: addResp.ID})
	require.NoError(t, err)
	assert.Equal(t, "pass", getResp.Password)
	assert.False(t, getResp.Encrypted)
}

// On a locked tenant session, Get fails with the same typed
// staticpw.ErrStoreLocked as every other password operation --
// resolvePasswordStore is shared, so Get has no special case.
func TestPasswordGet_LockedSessionReturnsErrStoreLocked(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	ctx := contextWithTenant("tenant-1")

	_, err := svc.PasswordGet(ctx, &transport.PasswordGetRequest{ID: "does-not-matter"})
	require.Error(t, err)
	assert.ErrorIs(t, err, staticpw.ErrStoreLocked)
}
