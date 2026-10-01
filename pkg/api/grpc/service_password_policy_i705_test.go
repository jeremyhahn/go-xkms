// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package grpc

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// This file covers pkg/api/grpc/service_password.go (go-xkms#705, batch 4):
// every existing test in service_password_test.go builds its Service around
// either a nil xkmsService (proving only the "unavailable" guard) or a nil
// request (proving only validation), so the RPC bodies that actually call
// into XKMSService and translate its response/error back to protobuf were
// never exercised. These tests wire a real XKMSService backed by an
// in-memory password store, so the success paths and the domain-error ->
// gRPC-status mappings run for real.

// --- Password success/error-mapping coverage ---

// newPasswordGRPCService wires a fresh XKMSService over an in-memory
// system password store and returns the gRPC Service in front of it.
func newPasswordGRPCService(t *testing.T) *Service {
	t.Helper()
	xkmsSvc := &xkms.XKMSService{}
	xkmsSvc.SetPasswordStore(staticpw.NewStore(storage.NewMemory()))
	return NewService(nil, nil, xkmsSvc)
}

func TestServicePasswordAdd_Success(t *testing.T) {
	svc := newPasswordGRPCService(t)
	resp, err := svc.PasswordAdd(context.Background(), &pb.PasswordAddRequest{
		Name:     "db-prod",
		Username: "admin",
		Password: "hunter2",
		Url:      "https://db.example.com",
		Notes:    "rotate quarterly",
	})
	require.NoError(t, err)
	assert.Equal(t, "db-prod", resp.Name)
	assert.NotEmpty(t, resp.Id)
	assert.NotEmpty(t, resp.CreatedAt)
}

func TestServicePasswordAdd_Conflict(t *testing.T) {
	svc := newPasswordGRPCService(t)
	req := &pb.PasswordAddRequest{Name: "db-prod", Password: "hunter2"}
	_, err := svc.PasswordAdd(context.Background(), req)
	require.NoError(t, err)

	_, err = svc.PasswordAdd(context.Background(), req)
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
}

func TestServicePasswordAdd_InvalidExpiresAt(t *testing.T) {
	svc := newPasswordGRPCService(t)
	_, err := svc.PasswordAdd(context.Background(), &pb.PasswordAddRequest{
		Name:      "db-prod",
		Password:  "hunter2",
		ExpiresAt: "not-a-timestamp",
	})
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestServicePasswordGet_Success(t *testing.T) {
	svc := newPasswordGRPCService(t)
	_, err := svc.PasswordAdd(context.Background(), &pb.PasswordAddRequest{Name: "db-prod", Password: "hunter2"})
	require.NoError(t, err)

	resp, err := svc.PasswordGet(context.Background(), &pb.PasswordGetRequest{Id: "db-prod"})
	require.NoError(t, err)
	assert.Equal(t, "db-prod", resp.Entry.Name)
	assert.Equal(t, "hunter2", resp.Entry.Password)
}

func TestServicePasswordGet_NotFound(t *testing.T) {
	svc := newPasswordGRPCService(t)
	_, err := svc.PasswordGet(context.Background(), &pb.PasswordGetRequest{Id: "missing"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestServicePasswordList_Success(t *testing.T) {
	svc := newPasswordGRPCService(t)
	_, err := svc.PasswordAdd(context.Background(), &pb.PasswordAddRequest{Name: "a", Password: "1"})
	require.NoError(t, err)
	_, err = svc.PasswordAdd(context.Background(), &pb.PasswordAddRequest{Name: "b", Password: "2", FolderPath: "team"})
	require.NoError(t, err)

	resp, err := svc.PasswordList(context.Background(), &pb.PasswordListRequest{})
	require.NoError(t, err)
	assert.Equal(t, int32(2), resp.Total)
	assert.Len(t, resp.Passwords, 2)

	byFolder, err := svc.PasswordList(context.Background(), &pb.PasswordListRequest{FolderPath: "team"})
	require.NoError(t, err)
	assert.Equal(t, int32(1), byFolder.Total)
}

func TestServicePasswordUpdate_Success(t *testing.T) {
	svc := newPasswordGRPCService(t)
	_, err := svc.PasswordAdd(context.Background(), &pb.PasswordAddRequest{Name: "db-prod", Password: "hunter2"})
	require.NoError(t, err)

	newUsername := "root"
	resp, err := svc.PasswordUpdate(context.Background(), &pb.PasswordUpdateRequest{Id: "db-prod", Username: &newUsername})
	require.NoError(t, err)
	assert.Equal(t, staticpw.GenerateID("db-prod", ""), resp.Id, "the response names the entry's ID, not the name the request used")

	got, err := svc.PasswordGet(context.Background(), &pb.PasswordGetRequest{Id: "db-prod"})
	require.NoError(t, err)
	assert.Equal(t, "root", got.Entry.Username)
}

// TestServicePasswordUpdate_RenameReturnsNewID is the regression for the
// update that answered with the ID it was asked about: a rename or a move
// re-keys the entry, and the old ID no longer resolves.
func TestServicePasswordUpdate_RenameReturnsNewID(t *testing.T) {
	svc := newPasswordGRPCService(t)
	added, err := svc.PasswordAdd(context.Background(), &pb.PasswordAddRequest{Name: "db-prod", Password: "hunter2"})
	require.NoError(t, err)

	newName, newFolder := "db-primary", "ops"
	resp, err := svc.PasswordUpdate(context.Background(), &pb.PasswordUpdateRequest{Id: added.Id, Name: &newName, FolderPath: &newFolder})
	require.NoError(t, err)
	assert.Equal(t, staticpw.GenerateID(newName, newFolder), resp.Id)
	assert.NotEqual(t, added.Id, resp.Id)

	got, err := svc.PasswordGet(context.Background(), &pb.PasswordGetRequest{Id: resp.Id})
	require.NoError(t, err)
	assert.Equal(t, newName, got.Entry.Name)
	_, err = svc.PasswordGet(context.Background(), &pb.PasswordGetRequest{Id: added.Id})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestServicePasswordUpdate_NotFound(t *testing.T) {
	svc := newPasswordGRPCService(t)
	newUsername := "root"
	_, err := svc.PasswordUpdate(context.Background(), &pb.PasswordUpdateRequest{Id: "missing", Username: &newUsername})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestServicePasswordUpdate_InvalidExpiresAt(t *testing.T) {
	svc := newPasswordGRPCService(t)
	_, err := svc.PasswordAdd(context.Background(), &pb.PasswordAddRequest{Name: "db-prod", Password: "hunter2"})
	require.NoError(t, err)

	bad := "not-a-timestamp"
	_, err = svc.PasswordUpdate(context.Background(), &pb.PasswordUpdateRequest{Id: "db-prod", ExpiresAt: &bad})
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestServicePasswordDelete_Success(t *testing.T) {
	svc := newPasswordGRPCService(t)
	_, err := svc.PasswordAdd(context.Background(), &pb.PasswordAddRequest{Name: "db-prod", Password: "hunter2"})
	require.NoError(t, err)

	resp, err := svc.PasswordDelete(context.Background(), &pb.PasswordDeleteRequest{Id: "db-prod"})
	require.NoError(t, err)
	assert.True(t, resp.Success)

	_, err = svc.PasswordGet(context.Background(), &pb.PasswordGetRequest{Id: "db-prod"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestServicePasswordDelete_NotFound(t *testing.T) {
	svc := newPasswordGRPCService(t)
	_, err := svc.PasswordDelete(context.Background(), &pb.PasswordDeleteRequest{Id: "missing"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestServicePasswordGenerate_Success(t *testing.T) {
	svc := newPasswordGRPCService(t)
	resp, err := svc.PasswordGenerate(context.Background(), &pb.PasswordGenerateRequest{
		Length: 16, Upper: true, Lower: true, Digits: true, Symbols: true,
	})
	require.NoError(t, err)
	assert.Len(t, resp.Password, 16)
	assert.Equal(t, int32(16), resp.Length)
}

func TestServicePasswordGenerate_InvalidLength(t *testing.T) {
	svc := newPasswordGRPCService(t)
	_, err := svc.PasswordGenerate(context.Background(), &pb.PasswordGenerateRequest{Length: 2})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServicePasswordStoreStatus_Success(t *testing.T) {
	svc := newPasswordGRPCService(t)
	_, err := svc.PasswordAdd(context.Background(), &pb.PasswordAddRequest{Name: "db-prod", Password: "hunter2"})
	require.NoError(t, err)

	resp, err := svc.PasswordStoreStatus(context.Background(), &pb.PasswordStoreStatusRequest{})
	require.NoError(t, err)
	assert.Equal(t, "direct", resp.AccessMode)
	assert.False(t, resp.IsLocked)
	assert.Equal(t, int32(1), resp.PasswordCount)
}

func TestServicePasswordStoreLock_OperationNotSupportedOnSystemStore(t *testing.T) {
	svc := newPasswordGRPCService(t)
	// The system-level store has no session, so lock/unlock report
	// Unimplemented (xkms.ErrOperationNotSupported) rather than succeeding
	// silently or panicking.
	_, err := svc.PasswordStoreLock(context.Background(), &pb.PasswordStoreLockRequest{})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}

func TestServicePasswordStoreUnlock_OperationNotSupportedOnSystemStore(t *testing.T) {
	svc := newPasswordGRPCService(t)
	_, err := svc.PasswordStoreUnlock(context.Background(), &pb.PasswordStoreUnlockRequest{
		Credential: &pb.PasswordVaultCredential{Factor: "passphrase", Passphrase: "correct horse battery"},
	})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}

func TestServicePasswordStoreSetAccessMode_InvalidMode(t *testing.T) {
	svc := newPasswordGRPCService(t)
	_, err := svc.PasswordStoreSetAccessMode(context.Background(), &pb.PasswordStoreSetAccessModeRequest{Mode: "bogus"})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestServicePasswordStoreSetAccessMode_UnsupportedOnSystemStore(t *testing.T) {
	svc := newPasswordGRPCService(t)
	// The system store enforces no access-control strategy of its own
	// (PasswordAccessMode returns ""), so any well-formed mode differs from
	// the effective one and is reported as unsupported rather than applied.
	_, err := svc.PasswordStoreSetAccessMode(context.Background(), &pb.PasswordStoreSetAccessModeRequest{Mode: string(staticpw.AccessSessionBased)})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}

// --- mapBootstrapError / mapSealStoreError pure-function coverage ---
//
// Neither mapper had any direct test: mapSealStoreError was only exercised
// indirectly through apierrors_parity_test.go's classified-sentinel sweep
// (never with nil or an unclassified error), and mapBootstrapError had no
// test at all.

func TestMapBootstrapError_NilIsNil(t *testing.T) {
	assert.NoError(t, mapBootstrapError(nil))
}

func TestMapBootstrapError_NotEnabled(t *testing.T) {
	err := mapBootstrapError(xkms.ErrBootstrapListenerNotEnabled)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestMapBootstrapError_UnclassifiedFallsBackToInternal(t *testing.T) {
	err := mapBootstrapError(errors.New("listener: socket closed"))
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestMapSealStoreError_NilIsNil(t *testing.T) {
	assert.NoError(t, mapSealStoreError(nil))
}

func TestMapSealStoreError_UnclassifiedFallsBackToInternal(t *testing.T) {
	err := mapSealStoreError(errors.New("seal store: unexpected EOF"))
	assert.Equal(t, codes.Internal, status.Code(err))
}

// The TenantPasswordStoreManager branch of PasswordStoreUnlock,
// PasswordStoreLock, PasswordStoreStatus and PasswordStoreSetAccessMode,
// through the gRPC handlers. This mirrors pkg/xkms's
// setupServiceWithPasswordManager fixture one layer up. The personal-vault
// RPCs have their own tests in service_password_vault_test.go.

// newTenantPasswordGRPCService wires an XKMSService with a
// TenantPasswordStoreManager backed by a registered, unsealed tenant barrier,
// and returns the gRPC Service in front of it together with a context scoped
// to a user of that tenant.
func newTenantPasswordGRPCService(t *testing.T) (*Service, context.Context) {
	t.Helper()
	ctx := context.Background()

	sysBackend := storage.NewMemory()
	sysBarrier, err := seal.NewBarrier(
		discardLogger(),
		sysBackend,
		seal.BarrierConfig{
			RootKeyPath:     "core/seal",
			PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase},
		},
		seal.NewSoftwareStrategy(),
	)
	require.NoError(t, err)

	sysCreds, err := seal.CredentialsFor([]byte("system-password"))
	require.NoError(t, err)
	defer sysCreds.Secret.Destroy()
	require.NoError(t, sysBarrier.Initialize(ctx, sysCreds))

	registry, err := seal.NewBarrierRegistry(sysBarrier)
	require.NoError(t, err)

	_, err = registry.RegisterTenant(vaultTenant)
	require.NoError(t, err)
	tenantCreds, err := seal.CredentialsFor([]byte("tenant-password"))
	require.NoError(t, err)
	defer tenantCreds.Secret.Destroy()
	require.NoError(t, registry.InitializeTenant(ctx, vaultTenant, tenantCreds))

	systemStore := staticpw.NewStore(storage.NewMemory())
	manager, err := staticpw.NewTenantPasswordStoreManager(registry, systemStore, staticpw.WithPasskeyRelyingParty("kms.example.com"))
	require.NoError(t, err)

	xkmsSvc := &xkms.XKMSService{}
	xkmsSvc.SetPasswordStore(systemStore)
	xkmsSvc.SetPasswordStoreManager(manager)

	return NewService(nil, nil, xkmsSvc), vaultUserCtx("test-user")
}

func TestServicePasswordStoreUnlock_TenantSuccess(t *testing.T) {
	svc, ctx := newTenantPasswordGRPCService(t)
	enrollPasskey(t, svc, ctx, testPasskey("test-user"))
	_, err := svc.PasswordStoreLock(ctx, &pb.PasswordStoreLockRequest{})
	require.NoError(t, err)

	resp, err := svc.PasswordStoreUnlock(ctx, &pb.PasswordStoreUnlockRequest{Credential: testPasskey("test-user")})
	require.NoError(t, err)
	assert.False(t, resp.IsLocked)
}

func TestServicePasswordStoreUnlock_WrongCredential(t *testing.T) {
	svc, ctx := newTenantPasswordGRPCService(t)
	enrollPasskey(t, svc, ctx, testPasskey("test-user"))
	_, err := svc.PasswordStoreLock(ctx, &pb.PasswordStoreLockRequest{})
	require.NoError(t, err)

	wrong := testPasskey("test-user")
	wrong.Secret = make([]byte, 32)
	_, err = svc.PasswordStoreUnlock(ctx, &pb.PasswordStoreUnlockRequest{Credential: wrong})
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestServicePasswordStoreLock_TenantSuccess(t *testing.T) {
	svc, ctx := newTenantPasswordGRPCService(t)
	// The first enrollment opens the session.
	enrollPasskey(t, svc, ctx, testPasskey("test-user"))

	resp, err := svc.PasswordStoreLock(ctx, &pb.PasswordStoreLockRequest{})
	require.NoError(t, err)
	assert.True(t, resp.IsLocked)
}

func TestServicePasswordStoreStatus_TenantScoped(t *testing.T) {
	svc, ctx := newTenantPasswordGRPCService(t)
	resp, err := svc.PasswordStoreStatus(ctx, &pb.PasswordStoreStatusRequest{})
	require.NoError(t, err)
	assert.Equal(t, "tenant", resp.AccessMode)
	assert.True(t, resp.IsLocked)
}

func TestServicePasswordStoreSetAccessMode_TenantAlreadyEffective(t *testing.T) {
	svc, ctx := newTenantPasswordGRPCService(t)
	// A tenant store is always session based (staticpw.AccessSessionBased is
	// the only reachable tenant mode), so requesting it is idempotent.
	resp, err := svc.PasswordStoreSetAccessMode(ctx, &pb.PasswordStoreSetAccessModeRequest{Mode: string(staticpw.AccessSessionBased)})
	require.NoError(t, err)
	assert.Equal(t, string(staticpw.AccessSessionBased), resp.Mode)
}

func TestServicePasswordStoreSetAccessMode_TenantUnsupportedMode(t *testing.T) {
	svc, ctx := newTenantPasswordGRPCService(t)
	_, err := svc.PasswordStoreSetAccessMode(ctx, &pb.PasswordStoreSetAccessModeRequest{Mode: string(staticpw.AccessPINPerOperation)})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}

func TestServicePasswordGenerate_CharsetPassesThrough(t *testing.T) {
	svc := newPasswordGRPCService(t)
	resp, err := svc.PasswordGenerate(context.Background(), &pb.PasswordGenerateRequest{Length: 32, Charset: "0123456789"})
	require.NoError(t, err)
	require.Len(t, resp.Password, 32)
	for _, r := range resp.Password {
		assert.True(t, r >= '0' && r <= '9', "%q is outside the requested charset", r)
	}
}

func TestServicePasswordGenerate_InvalidCharset(t *testing.T) {
	svc := newPasswordGRPCService(t)
	_, err := svc.PasswordGenerate(context.Background(), &pb.PasswordGenerateRequest{Length: 16, Charset: "a", Upper: true})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}
