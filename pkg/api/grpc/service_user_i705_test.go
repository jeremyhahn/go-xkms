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

package grpc

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/invitetest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// This file covers service_user.go (go-xkms #705, batch A): every RPC there
// shipped without a test. grpcFakeUserClient/grpcFakeRoleClient exercise the
// gRPC handlers end to end through a real *xkms.XKMSService, the same pattern
// service_pkcs11state_cad_test.go and service_custodian_share_tenant_test.go
// already use for their servicer-backed handlers.

// grpcFakeUserClient is an in-memory qrdbtransport.UserClient covering only
// the operations the xkms user servicer calls; the rest satisfy the interface
// with an explicit "not used" error so an accidental new call fails loudly.
type grpcFakeUserClient struct {
	byUsername map[string]*qrdbtransport.User
	byID       map[uint64]*qrdbtransport.User
	nextID     uint64
}

var _ qrdbtransport.UserClient = (*grpcFakeUserClient)(nil)

func newGRPCFakeUserClient() *grpcFakeUserClient {
	return &grpcFakeUserClient{
		byUsername: map[string]*qrdbtransport.User{},
		byID:       map[uint64]*qrdbtransport.User{},
	}
}

func (f *grpcFakeUserClient) CreateUser(_ context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
	if _, exists := f.byUsername[req.Username]; exists {
		return nil, &qrdbtransport.UserExistsError{Username: req.Username}
	}
	f.nextID++
	lifecycle := qrdbsdk.LifecycleActive
	if req.Pending || req.Lifecycle == string(qrdbsdk.LifecyclePending) {
		lifecycle = qrdbsdk.LifecyclePending
	}
	u := &qrdbtransport.User{
		ID: f.nextID, Username: req.Username, Email: req.Email, Name: req.Name,
		TenantID: req.TenantID, RoleIDs: req.RoleIDs, Lifecycle: string(lifecycle),
	}
	f.byUsername[req.Username] = u
	f.byID[u.ID] = u
	return u, nil
}

func (f *grpcFakeUserClient) GetUser(_ context.Context, id uint64) (*qrdbtransport.User, error) {
	if u, ok := f.byID[id]; ok {
		return u, nil
	}
	return nil, &qrdbtransport.UserNotFoundError{ID: id}
}

func (f *grpcFakeUserClient) GetUserByUsername(_ context.Context, tenantID, username string) (*qrdbtransport.User, error) {
	if u, ok := f.byUsername[username]; ok {
		return u, nil
	}
	return nil, &qrdbtransport.UserNotFoundError{Lookup: qrdbtransport.UserLookupKey(tenantID, username)}
}

func (f *grpcFakeUserClient) GetUserByEmail(context.Context, string, string) (*qrdbtransport.User, error) {
	return nil, errors.New("not used")
}

func (f *grpcFakeUserClient) GetUserByCertThumbprint(context.Context, string) (*qrdbtransport.User, error) {
	return nil, errors.New("not used")
}

func (f *grpcFakeUserClient) AddCertBinding(_ context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error) {
	u, ok := f.byID[userID]
	if !ok {
		return nil, &qrdbtransport.UserNotFoundError{ID: userID}
	}
	return u, nil
}

func (f *grpcFakeUserClient) RemoveCertBinding(context.Context, uint64, string) (*qrdbtransport.User, error) {
	return nil, errors.New("not used")
}

func (f *grpcFakeUserClient) UpdateUser(context.Context, *qrdbtransport.UpdateUserRequest) (*qrdbtransport.User, error) {
	return nil, errors.New("not used")
}

func (f *grpcFakeUserClient) DeleteUser(_ context.Context, id uint64) error {
	u, ok := f.byID[id]
	if !ok {
		return &qrdbtransport.UserNotFoundError{ID: id}
	}
	delete(f.byUsername, u.Username)
	delete(f.byID, id)
	return nil
}

func (f *grpcFakeUserClient) ListUsers(context.Context, *qrdbtransport.ListUsersRequest) (*qrdbtransport.ListUsersResponse, error) {
	users := make([]*qrdbtransport.User, 0, len(f.byID))
	for _, u := range f.byID {
		users = append(users, u)
	}
	return &qrdbtransport.ListUsersResponse{Users: users, Total: len(users)}, nil
}

func (f *grpcFakeUserClient) EnableUser(_ context.Context, id uint64) error {
	u, ok := f.byID[id]
	if !ok {
		return &qrdbtransport.UserNotFoundError{ID: id}
	}
	u.Lifecycle = string(qrdbsdk.LifecycleActive)
	return nil
}

func (f *grpcFakeUserClient) DisableUser(_ context.Context, id uint64) error {
	u, ok := f.byID[id]
	if !ok {
		return &qrdbtransport.UserNotFoundError{ID: id}
	}
	u.Lifecycle = "disabled"
	return nil
}

// grpcFakeRoleClient is an in-memory qrdbtransport.RoleClient covering only
// ListRoles, the one method the xkms user servicer calls to resolve a role
// name to an id.
type grpcFakeRoleClient struct {
	roles []*qrdbtransport.Role
}

var _ qrdbtransport.RoleClient = (*grpcFakeRoleClient)(nil)

func (f *grpcFakeRoleClient) CreateRole(context.Context, *qrdbtransport.CreateRoleRequest) (*qrdbtransport.Role, error) {
	return nil, errors.New("not used")
}
func (f *grpcFakeRoleClient) GetRole(_ context.Context, id string) (*qrdbtransport.Role, error) {
	for _, r := range f.roles {
		if r.ID == id {
			return r, nil
		}
	}
	return nil, errors.New("role not found")
}
func (f *grpcFakeRoleClient) GetRoleByName(context.Context, *qrdbtransport.GetRoleByNameRequest) (*qrdbtransport.Role, error) {
	return nil, errors.New("not used")
}
func (f *grpcFakeRoleClient) UpdateRole(context.Context, *qrdbtransport.UpdateRoleRequest) (*qrdbtransport.Role, error) {
	return nil, errors.New("not used")
}
func (f *grpcFakeRoleClient) DeleteRole(context.Context, string) error {
	return errors.New("not used")
}
func (f *grpcFakeRoleClient) ListRoles(context.Context, *qrdbtransport.ListRolesRequest) (*qrdbtransport.ListRolesResponse, error) {
	return &qrdbtransport.ListRolesResponse{Roles: f.roles}, nil
}
func (f *grpcFakeRoleClient) AssignRole(context.Context, uint64, string) error {
	return errors.New("not used")
}
func (f *grpcFakeRoleClient) UnassignRole(context.Context, uint64, string) error {
	return errors.New("not used")
}
func (f *grpcFakeRoleClient) ListPermissions(context.Context) (*qrdbtransport.ListPermissionsResponse, error) {
	return nil, errors.New("not used")
}
func (f *grpcFakeRoleClient) ResolvePermissions(context.Context, *qrdbtransport.ResolvePermissionsRequest) (*qrdbtransport.ResolvePermissionsResponse, error) {
	return nil, errors.New("not used")
}
func (f *grpcFakeRoleClient) ReconcileBuiltInRoles(context.Context, *qrdbtransport.ReconcileRolesRequest) (*qrdbtransport.ReconcileRolesResponse, error) {
	return nil, errors.New("not used")
}

// newUserGRPCService wires a fresh XKMSService with in-memory user/role
// clients and returns the gRPC Service in front of it.
// grpcSingleStoreResolver resolves every tenant to the same backing
// KVStore — enough for a unit test's invite store, which does not exercise
// per-tenant routing or barrier isolation.
type grpcSingleStoreResolver struct{ store qrdbsdk.KVStore }

func (r grpcSingleStoreResolver) Resolve(context.Context, string) (qrdbsdk.KVStore, error) {
	return r.store, nil
}

func newUserGRPCService(t *testing.T) (*Service, *grpcFakeUserClient) {
	t.Helper()
	users := newGRPCFakeUserClient()
	roles := &grpcFakeRoleClient{roles: []*qrdbtransport.Role{{
		ID:   qrdbsdk.SystemRoleID("", qrdbsdk.RoleNameOperator),
		Name: qrdbsdk.RoleNameOperator,
	}}}
	xkmsSvc := &xkms.XKMSService{}
	xkmsSvc.SetUserClients(users, roles)
	// CreateUser mints an invitation for every account created with an
	// email login key (go-xkms#1294 part B); wire the real qrdb invite
	// store over an in-memory KV store so that path is reachable here.
	inviteStore, err := invitetest.New(grpcSingleStoreResolver{store: qrdbsdk.NewMemoryKVStore()})
	require.NoError(t, err)
	xkmsSvc.SetInviteStore(inviteStore)
	return NewService(nil, nil, xkmsSvc), users
}

// --- CreateUser ---

func TestServiceCreateUser_Success(t *testing.T) {
	svc, _ := newUserGRPCService(t)
	resp, err := svc.CreateUser(context.Background(), &pb.CreateUserRequest{
		Username: "alice", Email: "alice@example.com", Role: "operator", DisplayName: "Alice",
	})
	require.NoError(t, err)
	assert.Equal(t, "alice", resp.User.Username)
	assert.Equal(t, "alice@example.com", resp.User.Email)
	// An email-login-key account is created PENDING, not active: it holds no
	// credential yet and activates only through invite redemption
	// (go-xkms#1294 part B). CreateUser mints the one-time activation
	// invitation in the same call.
	assert.False(t, resp.User.Enabled)
	require.NotNil(t, resp.Invite)
	assert.NotEmpty(t, resp.Invite.Token)
}

func TestServiceCreateUser_MissingUsername(t *testing.T) {
	svc, _ := newUserGRPCService(t)
	_, err := svc.CreateUser(context.Background(), &pb.CreateUserRequest{Email: "a@example.com"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServiceCreateUser_MissingEmailIsInvalidArgumentNotInternal(t *testing.T) {
	// Pins createUserErrorCode's classification end to end: a missing login
	// key is malformed client input, not a server failure.
	svc, _ := newUserGRPCService(t)
	_, err := svc.CreateUser(context.Background(), &pb.CreateUserRequest{Username: "bob"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServiceCreateUser_Unavailable(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.CreateUser(context.Background(), &pb.CreateUserRequest{Username: "x", Email: "x@example.com"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// --- ListUsers ---

func TestServiceListUsers_Success(t *testing.T) {
	svc, _ := newUserGRPCService(t)
	_, err := svc.CreateUser(context.Background(), &pb.CreateUserRequest{Username: "alice", Email: "a@example.com"})
	require.NoError(t, err)

	resp, err := svc.ListUsers(context.Background(), &pb.ListUsersRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Users, 1)
	assert.Equal(t, "alice", resp.Users[0].Username)
}

func TestServiceListUsers_Unavailable(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.ListUsers(context.Background(), &pb.ListUsersRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// --- GetUser ---

func TestServiceGetUser_Success(t *testing.T) {
	svc, _ := newUserGRPCService(t)
	_, err := svc.CreateUser(context.Background(), &pb.CreateUserRequest{Username: "alice", Email: "a@example.com"})
	require.NoError(t, err)

	resp, err := svc.GetUser(context.Background(), &pb.GetUserRequest{Username: "alice"})
	require.NoError(t, err)
	assert.Equal(t, "alice", resp.User.Username)
}

func TestServiceGetUser_MissingUsername(t *testing.T) {
	svc, _ := newUserGRPCService(t)
	_, err := svc.GetUser(context.Background(), &pb.GetUserRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServiceGetUser_NotFound(t *testing.T) {
	svc, _ := newUserGRPCService(t)
	_, err := svc.GetUser(context.Background(), &pb.GetUserRequest{Username: "ghost"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestServiceGetUser_Unavailable(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.GetUser(context.Background(), &pb.GetUserRequest{Username: "alice"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// --- DeleteUser ---

func TestServiceDeleteUser_Success(t *testing.T) {
	svc, users := newUserGRPCService(t)
	_, err := svc.CreateUser(context.Background(), &pb.CreateUserRequest{Username: "alice", Email: "a@example.com"})
	require.NoError(t, err)

	resp, err := svc.DeleteUser(context.Background(), &pb.DeleteUserRequest{Username: "alice"})
	require.NoError(t, err)
	assert.True(t, resp.Deleted)
	assert.Empty(t, users.byUsername)
}

func TestServiceDeleteUser_MissingUsername(t *testing.T) {
	svc, _ := newUserGRPCService(t)
	_, err := svc.DeleteUser(context.Background(), &pb.DeleteUserRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServiceDeleteUser_Unavailable(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.DeleteUser(context.Background(), &pb.DeleteUserRequest{Username: "alice"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// --- EnableUser / DisableUser (setUserEnabled) ---

func TestServiceEnableUser_Success(t *testing.T) {
	svc, _ := newUserGRPCService(t)
	_, err := svc.CreateUser(context.Background(), &pb.CreateUserRequest{Username: "alice", Email: "a@example.com"})
	require.NoError(t, err)
	_, err = svc.DisableUser(context.Background(), &pb.DisableUserRequest{Username: "alice"})
	require.NoError(t, err)

	resp, err := svc.EnableUser(context.Background(), &pb.EnableUserRequest{Username: "alice"})
	require.NoError(t, err)
	assert.True(t, resp.User.Enabled)
}

func TestServiceDisableUser_Success(t *testing.T) {
	svc, _ := newUserGRPCService(t)
	_, err := svc.CreateUser(context.Background(), &pb.CreateUserRequest{Username: "alice", Email: "a@example.com"})
	require.NoError(t, err)

	resp, err := svc.DisableUser(context.Background(), &pb.DisableUserRequest{Username: "alice"})
	require.NoError(t, err)
	assert.False(t, resp.User.Enabled)
}

func TestServiceSetUserEnabled_MissingUsername(t *testing.T) {
	svc, _ := newUserGRPCService(t)
	_, err := svc.EnableUser(context.Background(), &pb.EnableUserRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServiceSetUserEnabled_Unavailable(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.EnableUser(context.Background(), &pb.EnableUserRequest{Username: "alice"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestServiceSetUserEnabled_UnknownUser(t *testing.T) {
	svc, _ := newUserGRPCService(t)
	_, err := svc.EnableUser(context.Background(), &pb.EnableUserRequest{Username: "ghost"})
	assert.Equal(t, codes.Internal, status.Code(err))
}

// --- BindUserCert ---

func TestServiceBindUserCert_Success(t *testing.T) {
	svc, _ := newUserGRPCService(t)
	_, err := svc.CreateUser(context.Background(), &pb.CreateUserRequest{Username: "alice", Email: "a@example.com"})
	require.NoError(t, err)

	resp, err := svc.BindUserCert(context.Background(), &pb.BindUserCertRequest{
		Username: "alice", Thumbprint: "abc123", NotAfterUnix: 999999,
	})
	require.NoError(t, err)
	assert.Equal(t, "alice", resp.User.Username)
}

func TestServiceBindUserCert_MissingUsername(t *testing.T) {
	svc, _ := newUserGRPCService(t)
	_, err := svc.BindUserCert(context.Background(), &pb.BindUserCertRequest{Thumbprint: "abc"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServiceBindUserCert_MissingThumbprint(t *testing.T) {
	svc, _ := newUserGRPCService(t)
	_, err := svc.BindUserCert(context.Background(), &pb.BindUserCertRequest{Username: "alice"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServiceBindUserCert_Unavailable(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.BindUserCert(context.Background(), &pb.BindUserCertRequest{Username: "alice", Thumbprint: "abc"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// --- ListUserCredentials ---

func TestServiceListUserCredentials_Success(t *testing.T) {
	svc, _ := newUserGRPCService(t)
	_, err := svc.CreateUser(context.Background(), &pb.CreateUserRequest{Username: "alice", Email: "a@example.com"})
	require.NoError(t, err)

	resp, err := svc.ListUserCredentials(context.Background(), &pb.ListUserCredentialsRequest{Username: "alice"})
	require.NoError(t, err)
	assert.Empty(t, resp.Credentials)
}

func TestServiceListUserCredentials_MissingUsername(t *testing.T) {
	svc, _ := newUserGRPCService(t)
	_, err := svc.ListUserCredentials(context.Background(), &pb.ListUserCredentialsRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServiceListUserCredentials_NotFound(t *testing.T) {
	svc, _ := newUserGRPCService(t)
	_, err := svc.ListUserCredentials(context.Background(), &pb.ListUserCredentialsRequest{Username: "ghost"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestServiceListUserCredentials_Unavailable(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.ListUserCredentials(context.Background(), &pb.ListUserCredentialsRequest{Username: "alice"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}
