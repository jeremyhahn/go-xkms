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

package auth

import (
	"context"
	"errors"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeQRDBUserClient is a narrow in-memory stand-in for qrdbtransport.UserClient
// exercising only the paths QRDBUserStore depends on: cert-thumbprint lookup
// and a paginated existence probe. Every other method returns a typed "not
// implemented" error so an accidental call surfaces immediately in a test
// failure rather than silently succeeding.
type fakeQRDBUserClient struct {
	byThumbprint map[string]*qrdbtransport.User
	getErr       error

	listResp *qrdbtransport.ListUsersResponse
	listErr  error
	// lastListReq captures the request passed to ListUsers so tests can
	// assert HasAnyUsers requests a minimal single-row page.
	lastListReq *qrdbtransport.ListUsersRequest
}

func newFakeQRDBUserClient() *fakeQRDBUserClient {
	return &fakeQRDBUserClient{byThumbprint: make(map[string]*qrdbtransport.User)}
}

func (f *fakeQRDBUserClient) CreateUser(ctx context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
	return nil, errors.New("not implemented in fake")
}

func (f *fakeQRDBUserClient) GetUser(ctx context.Context, id uint64) (*qrdbtransport.User, error) {
	return nil, errors.New("not implemented in fake")
}

func (f *fakeQRDBUserClient) GetUserByUsername(ctx context.Context, tenantID, username string) (*qrdbtransport.User, error) {
	return nil, errors.New("not implemented in fake")
}

func (f *fakeQRDBUserClient) GetUserByEmail(ctx context.Context, tenantID, email string) (*qrdbtransport.User, error) {
	return nil, errors.New("not implemented in fake")
}

func (f *fakeQRDBUserClient) GetUserByCertThumbprint(ctx context.Context, thumbprint string) (*qrdbtransport.User, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	u, ok := f.byThumbprint[thumbprint]
	if !ok {
		return nil, errors.New("user not found")
	}
	return u, nil
}

func (f *fakeQRDBUserClient) AddCertBinding(ctx context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error) {
	return nil, errors.New("not implemented in fake")
}

func (f *fakeQRDBUserClient) UpdateUser(ctx context.Context, req *qrdbtransport.UpdateUserRequest) (*qrdbtransport.User, error) {
	return nil, errors.New("not implemented in fake")
}

func (f *fakeQRDBUserClient) DeleteUser(ctx context.Context, id uint64) error {
	return errors.New("not implemented in fake")
}

func (f *fakeQRDBUserClient) ListUsers(ctx context.Context, req *qrdbtransport.ListUsersRequest) (*qrdbtransport.ListUsersResponse, error) {
	f.lastListReq = req
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listResp, nil
}

func (f *fakeQRDBUserClient) EnableUser(ctx context.Context, id uint64) error {
	return errors.New("not implemented in fake")
}

func (f *fakeQRDBUserClient) DisableUser(ctx context.Context, id uint64) error {
	return errors.New("not implemented in fake")
}

// fakeQRDBRoleClient is a narrow in-memory stand-in for qrdbtransport.RoleClient
// exercising only GetRole, the single method QRDBUserStore calls.
type fakeQRDBRoleClient struct {
	byID map[string]*qrdbtransport.Role
	err  error
}

func newFakeQRDBRoleClient() *fakeQRDBRoleClient {
	return &fakeQRDBRoleClient{byID: make(map[string]*qrdbtransport.Role)}
}

func (f *fakeQRDBRoleClient) CreateRole(ctx context.Context, req *qrdbtransport.CreateRoleRequest) (*qrdbtransport.Role, error) {
	return nil, errors.New("not implemented in fake")
}

func (f *fakeQRDBRoleClient) GetRole(ctx context.Context, id string) (*qrdbtransport.Role, error) {
	if f.err != nil {
		return nil, f.err
	}
	r, ok := f.byID[id]
	if !ok {
		return nil, errors.New("role not found")
	}
	return r, nil
}

func (f *fakeQRDBRoleClient) GetRoleByName(ctx context.Context, req *qrdbtransport.GetRoleByNameRequest) (*qrdbtransport.Role, error) {
	return nil, errors.New("not implemented in fake")
}

func (f *fakeQRDBRoleClient) UpdateRole(ctx context.Context, req *qrdbtransport.UpdateRoleRequest) (*qrdbtransport.Role, error) {
	return nil, errors.New("not implemented in fake")
}

func (f *fakeQRDBRoleClient) DeleteRole(ctx context.Context, id string) error {
	return errors.New("not implemented in fake")
}

func (f *fakeQRDBRoleClient) ListRoles(ctx context.Context, req *qrdbtransport.ListRolesRequest) (*qrdbtransport.ListRolesResponse, error) {
	return nil, errors.New("not implemented in fake")
}

func (f *fakeQRDBRoleClient) AssignRole(ctx context.Context, userID uint64, roleID string) error {
	return errors.New("not implemented in fake")
}

func (f *fakeQRDBRoleClient) UnassignRole(ctx context.Context, userID uint64, roleID string) error {
	return errors.New("not implemented in fake")
}

func (f *fakeQRDBRoleClient) ListPermissions(ctx context.Context) (*qrdbtransport.ListPermissionsResponse, error) {
	return nil, errors.New("not implemented in fake")
}

func (f *fakeQRDBRoleClient) ResolvePermissions(ctx context.Context, req *qrdbtransport.ResolvePermissionsRequest) (*qrdbtransport.ResolvePermissionsResponse, error) {
	return nil, errors.New("not implemented in fake")
}

func TestNewQRDBUserStore(t *testing.T) {
	users := newFakeQRDBUserClient()
	roles := newFakeQRDBRoleClient()
	store := NewQRDBUserStore(users, roles)
	require.NotNil(t, store)
	assert.Same(t, users, store.users)
	assert.Same(t, roles, store.roles)
}

func TestQRDBUserStore_GetByCertFingerprint_Success(t *testing.T) {
	users := newFakeQRDBUserClient()
	users.byThumbprint["thumb-1"] = &qrdbtransport.User{
		Username: "alice",
		TenantID: "tenant-a",
		RoleIDs:  []string{"role-1"},
		Enabled:  true,
	}
	roles := newFakeQRDBRoleClient()
	roles.byID["role-1"] = &qrdbtransport.Role{ID: "role-1", Name: "admin"}

	store := NewQRDBUserStore(users, roles)
	u, err := store.GetByCertFingerprint(context.Background(), "thumb-1")
	require.NoError(t, err)
	assert.Equal(t, "alice", u.Username)
	assert.Equal(t, "admin", u.Role)
	assert.Equal(t, "tenant-a", u.TenantID)
	assert.True(t, u.Enabled)
}

func TestQRDBUserStore_GetByCertFingerprint_UserNotFound(t *testing.T) {
	users := newFakeQRDBUserClient()
	roles := newFakeQRDBRoleClient()
	store := NewQRDBUserStore(users, roles)

	_, err := store.GetByCertFingerprint(context.Background(), "missing-thumb")
	require.Error(t, err)
}

func TestQRDBUserStore_GetByCertFingerprint_NoRoleIDs(t *testing.T) {
	users := newFakeQRDBUserClient()
	users.byThumbprint["thumb-2"] = &qrdbtransport.User{
		Username: "bob",
		TenantID: "tenant-b",
		RoleIDs:  nil,
		Enabled:  true,
	}
	roles := newFakeQRDBRoleClient()
	store := NewQRDBUserStore(users, roles)

	u, err := store.GetByCertFingerprint(context.Background(), "thumb-2")
	require.NoError(t, err)
	assert.Equal(t, "bob", u.Username)
	assert.Empty(t, u.Role, "role should be empty when the user carries no role ids")
}

// TestQRDBUserStore_GetByCertFingerprint_RoleResolutionFails proves that a
// failed role lookup degrades the resolved role to empty rather than failing
// the cert-bound lookup outright, matching the documented behavior: a valid
// cert binding still authenticates even if the role name cannot be resolved.
func TestQRDBUserStore_GetByCertFingerprint_RoleResolutionFails(t *testing.T) {
	users := newFakeQRDBUserClient()
	users.byThumbprint["thumb-3"] = &qrdbtransport.User{
		Username: "carol",
		TenantID: "tenant-c",
		RoleIDs:  []string{"role-missing"},
		Enabled:  false,
	}
	roles := newFakeQRDBRoleClient()
	roles.err = errors.New("role service unavailable")
	store := NewQRDBUserStore(users, roles)

	u, err := store.GetByCertFingerprint(context.Background(), "thumb-3")
	require.NoError(t, err)
	assert.Equal(t, "carol", u.Username)
	assert.Empty(t, u.Role)
	assert.False(t, u.Enabled)
}
