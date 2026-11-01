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
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/kdftest"
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
	xkmsSvc.SetPasswordStore(newTestPasswordStore(t))
	return NewService(nil, nil, xkmsSvc)
}

// newTestPasswordStore returns a system password store over an in-memory DAO
// factory.
func newTestPasswordStore(t *testing.T) *staticpw.DAOStore {
	t.Helper()
	store, err := staticpw.NewStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	return store
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

// --- mapBootstrapError / mapSealStoreError pure-function coverage ---
//
// Neither mapper had any direct test: mapSealStoreError was only exercised
// indirectly through apierrors_parity_test.go's classified-sentinel sweep
// (never with nil or an unclassified error), and mapBootstrapError had no
// test at all.

func TestMapBootstrapError_NilIsNil(t *testing.T) {
	assert.NoError(t, mapBootstrapError(nil))
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
// TenantPasswordStoreManager over in-memory tenant stores, and returns the
// gRPC Service in front of it together with a context scoped to a user of
// vaultTenant.
func newTenantPasswordGRPCService(t *testing.T) (*Service, context.Context) {
	t.Helper()

	systemStore := newTestPasswordStore(t)
	manager, err := staticpw.NewTenantPasswordStoreManager(testutil.NewTenantStores(), systemStore, staticpw.WithPasskeyRelyingParty("kms.example.com"), staticpw.WithPassphraseKDFParams(kdftest.CheapPassphraseParams))
	require.NoError(t, err)

	xkmsSvc := &xkms.XKMSService{}
	xkmsSvc.SetPasswordStore(systemStore)
	xkmsSvc.SetPasswordStoreManager(manager)

	return NewService(nil, nil, xkmsSvc), vaultUserCtx("test-user")
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

func TestServicePasswordGenerate_InvalidCharset(t *testing.T) {
	svc := newPasswordGRPCService(t)
	_, err := svc.PasswordGenerate(context.Background(), &pb.PasswordGenerateRequest{Length: 16, Charset: "a", Upper: true})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}
