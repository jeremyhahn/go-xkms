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

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/invitetest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// ============================================================================
// In-memory qrdb UserClient / RoleClient mocks for the mcp package. Mirrors
// pkg/api/rest/user_handlers_test.go's restMockUserClient/restMockRoleClient
// exactly: the user handlers reach the qrdb user/role clients exclusively
// through XKMSService, so only the methods the servicer actually invokes
// carry programmable behavior; the rest report a sentinel "unused" error.
// ============================================================================

var errMCPMockUnused = errors.New("mcp mock: method not used")

type mcpMockUserClient struct {
	createUser        func(ctx context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error)
	getUserByUsername func(ctx context.Context, tenantID, username string) (*qrdbtransport.User, error)
	listUsers         func(ctx context.Context, req *qrdbtransport.ListUsersRequest) (*qrdbtransport.ListUsersResponse, error)
	deleteUser        func(ctx context.Context, id uint64) error
	enableUser        func(ctx context.Context, id uint64) error
	disableUser       func(ctx context.Context, id uint64) error
	addCertBinding    func(ctx context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error)
}

var _ qrdbtransport.UserClient = (*mcpMockUserClient)(nil)

func (m *mcpMockUserClient) CreateUser(ctx context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
	return m.createUser(ctx, req)
}

func (m *mcpMockUserClient) GetUser(ctx context.Context, id uint64) (*qrdbtransport.User, error) {
	return nil, errMCPMockUnused
}

func (m *mcpMockUserClient) GetUserByUsername(ctx context.Context, tenantID, username string) (*qrdbtransport.User, error) {
	return m.getUserByUsername(ctx, tenantID, username)
}

func (m *mcpMockUserClient) GetUserByEmail(ctx context.Context, tenantID, email string) (*qrdbtransport.User, error) {
	return nil, &qrdbtransport.UserNotFoundError{Lookup: qrdbtransport.UserLookupKey(tenantID, email)}
}

func (m *mcpMockUserClient) GetUserByCertThumbprint(ctx context.Context, thumbprint string) (*qrdbtransport.User, error) {
	return nil, errMCPMockUnused
}

func (m *mcpMockUserClient) AddCertBinding(ctx context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error) {
	return m.addCertBinding(ctx, userID, thumbprint, notAfterUnix)
}

func (m *mcpMockUserClient) RemoveCertBinding(ctx context.Context, userID uint64, thumbprint string) (*qrdbtransport.User, error) {
	return nil, errMCPMockUnused
}

func (m *mcpMockUserClient) UpdateUser(ctx context.Context, req *qrdbtransport.UpdateUserRequest) (*qrdbtransport.User, error) {
	return nil, errMCPMockUnused
}

func (m *mcpMockUserClient) DeleteUser(ctx context.Context, id uint64) error {
	return m.deleteUser(ctx, id)
}

func (m *mcpMockUserClient) ListUsers(ctx context.Context, req *qrdbtransport.ListUsersRequest) (*qrdbtransport.ListUsersResponse, error) {
	return m.listUsers(ctx, req)
}

func (m *mcpMockUserClient) EnableUser(ctx context.Context, id uint64) error {
	return m.enableUser(ctx, id)
}

func (m *mcpMockUserClient) DisableUser(ctx context.Context, id uint64) error {
	return m.disableUser(ctx, id)
}

// mcpMockRoleClient satisfies qrdbtransport.RoleClient with every method
// reporting "unused" except ListRoles, which the role-name resolution path
// calls when a request names a role; tests that leave Role empty never reach
// it, so an empty result is a safe default.
type mcpMockRoleClient struct{}

var _ qrdbtransport.RoleClient = (*mcpMockRoleClient)(nil)

func (m *mcpMockRoleClient) CreateRole(ctx context.Context, req *qrdbtransport.CreateRoleRequest) (*qrdbtransport.Role, error) {
	return nil, errMCPMockUnused
}
func (m *mcpMockRoleClient) GetRole(ctx context.Context, id string) (*qrdbtransport.Role, error) {
	return nil, errMCPMockUnused
}
func (m *mcpMockRoleClient) GetRoleByName(ctx context.Context, req *qrdbtransport.GetRoleByNameRequest) (*qrdbtransport.Role, error) {
	return nil, errMCPMockUnused
}
func (m *mcpMockRoleClient) ResolvePermissions(ctx context.Context, req *qrdbtransport.ResolvePermissionsRequest) (*qrdbtransport.ResolvePermissionsResponse, error) {
	return nil, errMCPMockUnused
}
func (m *mcpMockRoleClient) UpdateRole(ctx context.Context, req *qrdbtransport.UpdateRoleRequest) (*qrdbtransport.Role, error) {
	return nil, errMCPMockUnused
}
func (m *mcpMockRoleClient) DeleteRole(ctx context.Context, id string) error {
	return errMCPMockUnused
}
func (m *mcpMockRoleClient) ListRoles(ctx context.Context, req *qrdbtransport.ListRolesRequest) (*qrdbtransport.ListRolesResponse, error) {
	return &qrdbtransport.ListRolesResponse{}, nil
}
func (m *mcpMockRoleClient) AssignRole(ctx context.Context, userID uint64, roleID string) error {
	return errMCPMockUnused
}
func (m *mcpMockRoleClient) UnassignRole(ctx context.Context, userID uint64, roleID string) error {
	return errMCPMockUnused
}
func (m *mcpMockRoleClient) ListPermissions(ctx context.Context) (*qrdbtransport.ListPermissionsResponse, error) {
	return nil, errMCPMockUnused
}
func (m *mcpMockRoleClient) ReconcileBuiltInRoles(ctx context.Context, req *qrdbtransport.ReconcileRolesRequest) (*qrdbtransport.ReconcileRolesResponse, error) {
	return nil, errMCPMockUnused
}

// newUserTestServer builds a real *Server (createTestServer) and, when users
// is non-nil, wires it into the server's XKMSService alongside a role client.
// This exercises the same real dispatch core (handler + XKMSService) that
// InvokeMethod uses in production; only the qrdb user/role boundary is
// mocked, which is unavoidable without an embedded qrdb node. A nil users
// client leaves the user subsystem unconfigured so the ErrNotConfigured
// paths are reachable.
// mcpSingleStoreResolver resolves every tenant to the same backing
// KVStore — enough for a unit test's invite store, which does not exercise
// per-tenant routing or barrier isolation.
type mcpSingleStoreResolver struct{ store qrdbsdk.KVStore }

func (r mcpSingleStoreResolver) Resolve(context.Context, string) (qrdbsdk.KVStore, error) {
	return r.store, nil
}

func newUserTestServer(t *testing.T, users qrdbtransport.UserClient) *Server {
	t.Helper()
	server := createTestServer(t)
	if users != nil {
		server.xkmsService.SetUserClients(users, &mcpMockRoleClient{})
	}
	// CreateUser mints an invitation for every account created with an
	// email login key (go-xkms#1294 part B); wire the real qrdb invite
	// store over an in-memory KV store so that path is reachable here.
	inviteStore, err := invitetest.New(mcpSingleStoreResolver{store: qrdbsdk.NewMemoryKVStore()})
	require.NoError(t, err)
	server.xkmsService.SetInviteStore(inviteStore)
	return server
}

// rpcRequest builds a JSONRPCRequest carrying params marshaled to JSON,
// matching the shape InvokeMethod and the handlers receive on the wire.
func rpcRequest(method string, params interface{}) *JSONRPCRequest {
	data, err := json.Marshal(params)
	if err != nil {
		panic(err)
	}
	return &JSONRPCRequest{JSONRPC: "2.0", Method: method, Params: data, ID: 1}
}

// --- user.create ---

func TestHandleCreateUser(t *testing.T) {
	t.Run("creates a user successfully", func(t *testing.T) {
		users := &mcpMockUserClient{
			createUser: func(_ context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
				assert.Equal(t, "alice", req.Username)
				assert.Equal(t, "alice@example.com", req.Email)
				return &qrdbtransport.User{ID: 1, Username: "alice", Email: "alice@example.com", Lifecycle: string(qrdbsdk.LifecycleActive)}, nil
			},
		}
		server := newUserTestServer(t, users)

		req := rpcRequest("user.create", &transport.CreateUserRequest{Username: "alice", Email: "alice@example.com"})
		result, err := server.handleCreateUser(context.Background(), req)
		require.NoError(t, err)

		resp, ok := result.(*transport.GetUserResponse)
		require.True(t, ok)
		assert.Equal(t, "alice", resp.User.Username)
		assert.True(t, resp.User.Enabled)
	})

	t.Run("rejects invalid params JSON", func(t *testing.T) {
		server := newUserTestServer(t, &mcpMockUserClient{})
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "user.create", Params: json.RawMessage(`not-json`), ID: 1}

		_, err := server.handleCreateUser(context.Background(), req)
		require.Error(t, err)
	})

	t.Run("fails when user subsystem not configured", func(t *testing.T) {
		server := newUserTestServer(t, nil)
		req := rpcRequest("user.create", &transport.CreateUserRequest{Username: "alice", Email: "alice@example.com"})

		_, err := server.handleCreateUser(context.Background(), req)
		require.Error(t, err)
	})
}

// --- user.list ---

func TestHandleListUsers(t *testing.T) {
	t.Run("lists users successfully", func(t *testing.T) {
		users := &mcpMockUserClient{
			listUsers: func(_ context.Context, _ *qrdbtransport.ListUsersRequest) (*qrdbtransport.ListUsersResponse, error) {
				return &qrdbtransport.ListUsersResponse{Users: []*qrdbtransport.User{
					{ID: 1, Username: "alice", Lifecycle: string(qrdbsdk.LifecycleActive)},
					{ID: 2, Username: "bob", Lifecycle: string(qrdbsdk.LifecycleDisabled)},
				}}, nil
			},
		}
		server := newUserTestServer(t, users)

		result, err := server.handleListUsers(context.Background(), rpcRequest("user.list", nil))
		require.NoError(t, err)

		resp, ok := result.(*transport.ListUsersResponse)
		require.True(t, ok)
		require.Len(t, resp.Users, 2)
		assert.Equal(t, "alice", resp.Users[0].Username)
	})

	t.Run("propagates the service error", func(t *testing.T) {
		users := &mcpMockUserClient{
			listUsers: func(_ context.Context, _ *qrdbtransport.ListUsersRequest) (*qrdbtransport.ListUsersResponse, error) {
				return nil, errors.New("backend down")
			},
		}
		server := newUserTestServer(t, users)

		_, err := server.handleListUsers(context.Background(), rpcRequest("user.list", nil))
		require.Error(t, err)
	})
}

// --- user.get ---

func TestHandleGetUser(t *testing.T) {
	t.Run("retrieves a user successfully", func(t *testing.T) {
		users := &mcpMockUserClient{
			getUserByUsername: func(_ context.Context, _, username string) (*qrdbtransport.User, error) {
				assert.Equal(t, "alice", username)
				return &qrdbtransport.User{ID: 1, Username: "alice", Lifecycle: string(qrdbsdk.LifecycleActive)}, nil
			},
		}
		server := newUserTestServer(t, users)

		result, err := server.handleGetUser(context.Background(), rpcRequest("user.get", UserUsernameParams{Username: "alice"}))
		require.NoError(t, err)

		resp, ok := result.(*transport.GetUserResponse)
		require.True(t, ok)
		assert.Equal(t, "alice", resp.User.Username)
	})

	t.Run("requires a username", func(t *testing.T) {
		server := newUserTestServer(t, &mcpMockUserClient{})

		_, err := server.handleGetUser(context.Background(), rpcRequest("user.get", UserUsernameParams{}))
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUsernameRequired)
	})

	t.Run("rejects invalid params JSON", func(t *testing.T) {
		server := newUserTestServer(t, &mcpMockUserClient{})
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "user.get", Params: json.RawMessage(`not-json`), ID: 1}

		_, err := server.handleGetUser(context.Background(), req)
		require.Error(t, err)
	})
}

// --- user.delete ---

func TestHandleDeleteUser(t *testing.T) {
	t.Run("deletes a user successfully", func(t *testing.T) {
		var deletedID uint64
		users := &mcpMockUserClient{
			getUserByUsername: func(_ context.Context, _, username string) (*qrdbtransport.User, error) {
				return &qrdbtransport.User{ID: 7, Username: username}, nil
			},
			deleteUser: func(_ context.Context, id uint64) error {
				deletedID = id
				return nil
			},
		}
		server := newUserTestServer(t, users)

		result, err := server.handleDeleteUser(context.Background(), rpcRequest("user.delete", UserUsernameParams{Username: "alice"}))
		require.NoError(t, err)
		assert.Equal(t, uint64(7), deletedID)

		res, ok := result.(UserDeleteResult)
		require.True(t, ok)
		assert.Equal(t, "alice", res.Username)
		assert.Equal(t, "deleted", res.Status)
	})

	t.Run("requires a username", func(t *testing.T) {
		server := newUserTestServer(t, &mcpMockUserClient{})

		_, err := server.handleDeleteUser(context.Background(), rpcRequest("user.delete", UserUsernameParams{}))
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUsernameRequired)
	})
}

// --- user.enable / user.disable ---

func TestHandleEnableUser(t *testing.T) {
	t.Run("enables a user and reads it back", func(t *testing.T) {
		enabled := false
		users := &mcpMockUserClient{
			getUserByUsername: func(_ context.Context, _, username string) (*qrdbtransport.User, error) {
				return &qrdbtransport.User{ID: 1, Username: username, Lifecycle: lifecycleOf(enabled)}, nil
			},
			enableUser: func(_ context.Context, id uint64) error {
				enabled = true
				return nil
			},
		}
		server := newUserTestServer(t, users)

		result, err := server.handleEnableUser(context.Background(), rpcRequest("user.enable", UserUsernameParams{Username: "alice"}))
		require.NoError(t, err)

		resp, ok := result.(*transport.GetUserResponse)
		require.True(t, ok)
		assert.True(t, resp.User.Enabled)
	})

	t.Run("propagates the enable failure", func(t *testing.T) {
		users := &mcpMockUserClient{
			getUserByUsername: func(_ context.Context, _, username string) (*qrdbtransport.User, error) {
				return &qrdbtransport.User{ID: 1, Username: username}, nil
			},
			enableUser: func(_ context.Context, id uint64) error {
				return errors.New("qrdb unavailable")
			},
		}
		server := newUserTestServer(t, users)

		_, err := server.handleEnableUser(context.Background(), rpcRequest("user.enable", UserUsernameParams{Username: "alice"}))
		require.Error(t, err)
	})
}

func TestHandleDisableUser(t *testing.T) {
	t.Run("disables a user and reads it back", func(t *testing.T) {
		enabled := true
		users := &mcpMockUserClient{
			getUserByUsername: func(_ context.Context, _, username string) (*qrdbtransport.User, error) {
				return &qrdbtransport.User{ID: 1, Username: username, Lifecycle: lifecycleOf(enabled)}, nil
			},
			disableUser: func(_ context.Context, id uint64) error {
				enabled = false
				return nil
			},
		}
		server := newUserTestServer(t, users)

		result, err := server.handleDisableUser(context.Background(), rpcRequest("user.disable", UserUsernameParams{Username: "alice"}))
		require.NoError(t, err)

		resp, ok := result.(*transport.GetUserResponse)
		require.True(t, ok)
		assert.False(t, resp.User.Enabled)
	})

	t.Run("requires a username", func(t *testing.T) {
		server := newUserTestServer(t, &mcpMockUserClient{})

		_, err := server.handleDisableUser(context.Background(), rpcRequest("user.disable", UserUsernameParams{}))
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUsernameRequired)
	})
}

// --- user.bindCert ---

func TestHandleBindUserCert(t *testing.T) {
	t.Run("binds a certificate successfully", func(t *testing.T) {
		var boundThumbprint string
		var boundNotAfter int64
		users := &mcpMockUserClient{
			getUserByUsername: func(_ context.Context, _, username string) (*qrdbtransport.User, error) {
				return &qrdbtransport.User{ID: 1, Username: username}, nil
			},
			addCertBinding: func(_ context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error) {
				boundThumbprint, boundNotAfter = thumbprint, notAfterUnix
				return &qrdbtransport.User{ID: userID}, nil
			},
		}
		server := newUserTestServer(t, users)

		params := UserBindCertParams{Username: "alice", Thumbprint: "abcd", NotAfterUnix: 1234567890}
		result, err := server.handleBindUserCert(context.Background(), rpcRequest("user.bindCert", params))
		require.NoError(t, err)
		assert.Equal(t, "abcd", boundThumbprint)
		assert.EqualValues(t, 1234567890, boundNotAfter)

		res, ok := result.(UserBindCertResult)
		require.True(t, ok)
		assert.Equal(t, "alice", res.Username)
		assert.Equal(t, "bound", res.Status)
	})

	t.Run("requires a username", func(t *testing.T) {
		server := newUserTestServer(t, &mcpMockUserClient{})

		_, err := server.handleBindUserCert(context.Background(), rpcRequest("user.bindCert", UserBindCertParams{Thumbprint: "abcd"}))
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUsernameRequired)
	})
}

// --- user.listCredentials ---

func TestHandleListUserCredentials(t *testing.T) {
	t.Run("lists credentials for an existing user", func(t *testing.T) {
		users := &mcpMockUserClient{
			getUserByUsername: func(_ context.Context, _, username string) (*qrdbtransport.User, error) {
				return &qrdbtransport.User{ID: 1, Username: username}, nil
			},
		}
		server := newUserTestServer(t, users)

		result, err := server.handleListUserCredentials(context.Background(), rpcRequest("user.listCredentials", UserUsernameParams{Username: "alice"}))
		require.NoError(t, err)

		res, ok := result.(UserListCredentialsResult)
		require.True(t, ok)
		assert.Empty(t, res.Credentials)
	})

	t.Run("propagates an unknown user", func(t *testing.T) {
		users := &mcpMockUserClient{
			getUserByUsername: func(_ context.Context, tenantID, username string) (*qrdbtransport.User, error) {
				return nil, &qrdbtransport.UserNotFoundError{Lookup: qrdbtransport.UserLookupKey(tenantID, username)}
			},
		}
		server := newUserTestServer(t, users)

		_, err := server.handleListUserCredentials(context.Background(), rpcRequest("user.listCredentials", UserUsernameParams{Username: "ghost"}))
		require.Error(t, err)
	})

	t.Run("requires a username", func(t *testing.T) {
		server := newUserTestServer(t, &mcpMockUserClient{})

		_, err := server.handleListUserCredentials(context.Background(), rpcRequest("user.listCredentials", UserUsernameParams{}))
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUsernameRequired)
	})
}

// --- InvokeMethod, real dispatch core (handler + authz + tenant gating) ---

func TestInvokeMethod_UserCreate_RealDispatchCore(t *testing.T) {
	users := &mcpMockUserClient{
		createUser: func(_ context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
			return &qrdbtransport.User{ID: 1, Username: req.Username, Email: req.Email, Lifecycle: string(qrdbsdk.LifecycleActive)}, nil
		},
	}
	server := newUserTestServer(t, users)

	paramsJSON, err := json.Marshal(&transport.CreateUserRequest{Username: "alice", Email: "alice@example.com"})
	require.NoError(t, err)

	result, err := server.InvokeMethod(context.Background(), "user.create", paramsJSON)
	require.NoError(t, err)

	resp, ok := result.(*transport.GetUserResponse)
	require.True(t, ok)
	assert.Equal(t, "alice", resp.User.Username)
}

func TestInvokeMethod_UnknownUserMethod(t *testing.T) {
	server := newUserTestServer(t, &mcpMockUserClient{})

	_, err := server.InvokeMethod(context.Background(), "user.doesNotExist", nil)
	require.Error(t, err)
	var unknown *UnknownMethodError
	require.ErrorAs(t, err, &unknown)
}

// lifecycleOf maps a test's enabled flag to qrdb's account lifecycle, the only
// account state since qrdb v0.20.
func lifecycleOf(enabled bool) string {
	if enabled {
		return string(qrdbsdk.LifecycleActive)
	}
	return string(qrdbsdk.LifecycleDisabled)
}

// --- mapUserError ---

// TestMapUserError_NotFoundAndInvalidParams pins go-xkms#814: a
// *qrdbsdk.UserNotFoundError (bare, or reached through pkg/xkms's
// *ErrUserOperation wrapper the way GetUser/DeleteUser/ListUserCredentials
// actually return it) classifies onto sdkssh.JSONRPCCodeNotFound, matching
// go-qrdb's own gRPC/QUIC/MCP-wire classification of the identical type
// ("lower layers win"); ErrUsernameRequired and xkms.ErrEmailRequired --
// the caller's own mistake -- classify onto ErrCodeInvalidParams, the same
// code decodeParams uses for a decode failure.
func TestMapUserError_NotFoundAndInvalidParams(t *testing.T) {
	notFound := &qrdbsdk.UserNotFoundError{Lookup: "u:ghost"}

	tests := []struct {
		name     string
		err      error
		wantCode int
	}{
		{"bare UserNotFoundError", notFound, sdkssh.JSONRPCCodeNotFound},
		{"UserNotFoundError wrapped by ErrUserOperation", &xkms.ErrUserOperation{Operation: "get user", Err: notFound}, sdkssh.JSONRPCCodeNotFound},
		{"ErrUsernameRequired", ErrUsernameRequired, ErrCodeInvalidParams},
		{"xkms.ErrEmailRequired", xkms.ErrEmailRequired, ErrCodeInvalidParams},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mapUserError(tt.err)
			var keyErr *KeyOpError
			require.ErrorAs(t, err, &keyErr)
			assert.Equal(t, tt.wantCode, keyErr.Code)
			// The original error must still be reachable through errors.Is,
			// so a caller like TestHandleGetUser's "requires a username"
			// subtest can keep asserting ErrorIs(err, ErrUsernameRequired).
			assert.ErrorIs(t, err, tt.err)
		})
	}
}

// TestMapUserError_UnclassifiedErrorIsInternal proves mapUserError's floor:
// an error matching none of its known cases still becomes a classified
// *KeyOpError instead of reaching the caller bare, and reports
// ErrCodeInternalError.
func TestMapUserError_UnclassifiedErrorIsInternal(t *testing.T) {
	err := mapUserError(errors.New("qrdb unavailable"))

	var keyErr *KeyOpError
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, ErrCodeInternalError, keyErr.Code)
}

// TestMapUserError_Nil proves mapUserError passes a nil error through
// unchanged.
func TestMapUserError_Nil(t *testing.T) {
	assert.NoError(t, mapUserError(nil))
}
