//go:build codec_json

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

package admin

import (
	"context"
	"log/slog"
	"testing"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	acmeobjstore "github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	xkmsstorage "github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newNilQRDBTenantService creates a TenantAwareAdminService with nil qrdbService
// to exercise the ErrRBACNotAvailable code paths.
func newNilQRDBTenantService(t *testing.T) *TenantAwareAdminService {
	t.Helper()
	kv, err := kvadapter.New(xkmsstorage.NewMemory())
	require.NoError(t, err)
	factory, err := acmeobjstore.NewTenantAwareFactoryFromKVStore(kv)
	require.NoError(t, err)
	return mustTenantAwareAdminService(t, nil, factory, nil, slog.Default(), "1.0.0")
}

// ==========================================================================
// TenantAwareAdminService — BarrierSvc accessors
// ==========================================================================

func TestTenantAwareAdminService_BarrierSvc_GetterSetter(t *testing.T) {
	svc := newNilQRDBTenantService(t)
	assert.Nil(t, svc.BarrierSvc())

	stub := NewBarrierService(BarrierModeEmbedded, nil, slog.Default())
	svc.SetBarrierService(stub)
	assert.Equal(t, stub, svc.BarrierSvc())
}

// ==========================================================================
// TenantAwareAdminService — role management (nil qrdbService path)
// ==========================================================================

func TestTenantAwareAdminService_CreateTenantRole_NilQRDB(t *testing.T) {
	svc := newNilQRDBTenantService(t)
	ctx := context.Background()

	_, err := svc.CreateTenantRole(ctx, "", &db.CreateRoleRequest{Name: "admin"})
	assert.ErrorIs(t, err, ErrInvalidTenantID)

	_, err = svc.CreateTenantRole(ctx, "t1", &db.CreateRoleRequest{Name: "admin"})
	assert.ErrorIs(t, err, ErrRBACNotAvailable)
}

func TestTenantAwareAdminService_GetTenantRole_NilQRDB(t *testing.T) {
	svc := newNilQRDBTenantService(t)
	ctx := context.Background()

	_, err := svc.GetTenantRole(ctx, "", "role-1")
	assert.ErrorIs(t, err, ErrInvalidTenantID)

	_, err = svc.GetTenantRole(ctx, "t1", "role-1")
	assert.ErrorIs(t, err, ErrRBACNotAvailable)
}

func TestTenantAwareAdminService_UpdateTenantRole_NilQRDB(t *testing.T) {
	svc := newNilQRDBTenantService(t)
	ctx := context.Background()

	_, err := svc.UpdateTenantRole(ctx, "", &db.UpdateRoleRequest{ID: "role-1"})
	assert.ErrorIs(t, err, ErrInvalidTenantID)

	_, err = svc.UpdateTenantRole(ctx, "t1", &db.UpdateRoleRequest{ID: "role-1"})
	assert.ErrorIs(t, err, ErrRBACNotAvailable)
}

func TestTenantAwareAdminService_DeleteTenantRole_NilQRDB(t *testing.T) {
	svc := newNilQRDBTenantService(t)
	ctx := context.Background()

	err := svc.DeleteTenantRole(ctx, "", "role-1")
	assert.ErrorIs(t, err, ErrInvalidTenantID)

	err = svc.DeleteTenantRole(ctx, "t1", "role-1")
	assert.ErrorIs(t, err, ErrRBACNotAvailable)
}

func TestTenantAwareAdminService_ListTenantRoles_NilQRDB(t *testing.T) {
	svc := newNilQRDBTenantService(t)
	ctx := context.Background()

	_, err := svc.ListTenantRoles(ctx, "", &db.ListRolesRequest{})
	assert.ErrorIs(t, err, ErrInvalidTenantID)

	_, err = svc.ListTenantRoles(ctx, "t1", &db.ListRolesRequest{})
	assert.ErrorIs(t, err, ErrRBACNotAvailable)
}

// ==========================================================================
// TenantAwareAdminService — user management (nil qrdbService path)
// ==========================================================================

func TestTenantAwareAdminService_CreateTenantUser_NilQRDB(t *testing.T) {
	svc := newNilQRDBTenantService(t)
	ctx := context.Background()

	_, err := svc.CreateTenantUser(ctx, "", &db.CreateUserRequest{Username: "alice"})
	assert.ErrorIs(t, err, ErrInvalidTenantID)

	_, err = svc.CreateTenantUser(ctx, "t1", &db.CreateUserRequest{Username: "alice"})
	assert.ErrorIs(t, err, ErrRBACNotAvailable)
}

func TestTenantAwareAdminService_GetTenantUser_NilQRDB(t *testing.T) {
	svc := newNilQRDBTenantService(t)
	ctx := context.Background()

	_, err := svc.GetTenantUser(ctx, "", "1")
	assert.ErrorIs(t, err, ErrInvalidTenantID)

	_, err = svc.GetTenantUser(ctx, "t1", "1")
	assert.ErrorIs(t, err, ErrRBACNotAvailable)
}

func TestTenantAwareAdminService_UpdateTenantUser_NilQRDB(t *testing.T) {
	svc := newNilQRDBTenantService(t)
	ctx := context.Background()

	_, err := svc.UpdateTenantUser(ctx, "", &db.UpdateUserRequest{ID: 1})
	assert.ErrorIs(t, err, ErrInvalidTenantID)

	_, err = svc.UpdateTenantUser(ctx, "t1", &db.UpdateUserRequest{ID: 1})
	assert.ErrorIs(t, err, ErrRBACNotAvailable)
}

func TestTenantAwareAdminService_DeleteTenantUser_NilQRDB(t *testing.T) {
	svc := newNilQRDBTenantService(t)
	ctx := context.Background()

	err := svc.DeleteTenantUser(ctx, "", "1")
	assert.ErrorIs(t, err, ErrInvalidTenantID)

	err = svc.DeleteTenantUser(ctx, "t1", "1")
	assert.ErrorIs(t, err, ErrRBACNotAvailable)
}

func TestTenantAwareAdminService_ListTenantUsers_NilQRDB(t *testing.T) {
	svc := newNilQRDBTenantService(t)
	ctx := context.Background()

	_, err := svc.ListTenantUsers(ctx, "", &db.ListUsersRequest{})
	assert.ErrorIs(t, err, ErrInvalidTenantID)

	_, err = svc.ListTenantUsers(ctx, "t1", &db.ListUsersRequest{})
	assert.ErrorIs(t, err, ErrRBACNotAvailable)
}

// ==========================================================================
// parseUserID
// ==========================================================================

func TestParseUserID_Valid(t *testing.T) {
	id, err := parseUserID("42")
	require.NoError(t, err)
	assert.Equal(t, uint64(42), id)
}

func TestParseUserID_Invalid(t *testing.T) {
	_, err := parseUserID("not-a-number")
	require.Error(t, err)
}

func TestParseUserID_Negative(t *testing.T) {
	_, err := parseUserID("-1")
	require.Error(t, err)
}
