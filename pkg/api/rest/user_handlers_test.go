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

package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// ============================================================================
// In-memory qrdb UserClient / RoleClient mocks for the rest package.
//
// The user HTTP handlers reach the qrdb user/role clients exclusively through
// the XKMSService singleton. These mocks let the handlers run entirely
// in-memory: only the methods the user servicer actually invokes carry
// programmable behavior; the rest satisfy the interface with a sentinel error.
// ============================================================================

var errRestMockUnused = errors.New("rest mock: method not used")

type restMockUserClient struct {
	createUser        func(ctx context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error)
	getUserByUsername func(ctx context.Context, tenantID, username string) (*qrdbtransport.User, error)
	getUserByEmail    func(ctx context.Context, tenantID, email string) (*qrdbtransport.User, error)
	listUsers         func(ctx context.Context, req *qrdbtransport.ListUsersRequest) (*qrdbtransport.ListUsersResponse, error)
	deleteUser        func(ctx context.Context, id uint64) error
	enableUser        func(ctx context.Context, id uint64) error
	disableUser       func(ctx context.Context, id uint64) error
	addCertBinding    func(ctx context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error)
}

var _ qrdbtransport.UserClient = (*restMockUserClient)(nil)

func (m *restMockUserClient) CreateUser(ctx context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
	return m.createUser(ctx, req)
}

func (m *restMockUserClient) GetUser(ctx context.Context, id uint64) (*qrdbtransport.User, error) {
	return nil, errRestMockUnused
}

func (m *restMockUserClient) GetUserByUsername(ctx context.Context, tenantID, username string) (*qrdbtransport.User, error) {
	return m.getUserByUsername(ctx, tenantID, username)
}

func (m *restMockUserClient) GetUserByEmail(ctx context.Context, tenantID, email string) (*qrdbtransport.User, error) {
	if m.getUserByEmail != nil {
		return m.getUserByEmail(ctx, tenantID, email)
	}
	return nil, &qrdbtransport.UserNotFoundError{Lookup: qrdbtransport.UserLookupKey(tenantID, email)}
}

func (m *restMockUserClient) GetUserByCertThumbprint(ctx context.Context, thumbprint string) (*qrdbtransport.User, error) {
	return nil, errRestMockUnused
}

func (m *restMockUserClient) AddCertBinding(ctx context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error) {
	return m.addCertBinding(ctx, userID, thumbprint, notAfterUnix)
}

func (m *restMockUserClient) RemoveCertBinding(ctx context.Context, userID uint64, thumbprint string) (*qrdbtransport.User, error) {
	return nil, errRestMockUnused
}

func (m *restMockUserClient) UpdateUser(ctx context.Context, req *qrdbtransport.UpdateUserRequest) (*qrdbtransport.User, error) {
	return nil, errRestMockUnused
}

func (m *restMockUserClient) DeleteUser(ctx context.Context, id uint64) error {
	return m.deleteUser(ctx, id)
}

func (m *restMockUserClient) ListUsers(ctx context.Context, req *qrdbtransport.ListUsersRequest) (*qrdbtransport.ListUsersResponse, error) {
	return m.listUsers(ctx, req)
}

func (m *restMockUserClient) EnableUser(ctx context.Context, id uint64) error {
	return m.enableUser(ctx, id)
}

func (m *restMockUserClient) DisableUser(ctx context.Context, id uint64) error {
	return m.disableUser(ctx, id)
}

type restMockRoleClient struct {
	getRole   func(ctx context.Context, id string) (*qrdbtransport.Role, error)
	listRoles func(ctx context.Context, req *qrdbtransport.ListRolesRequest) (*qrdbtransport.ListRolesResponse, error)
}

var _ qrdbtransport.RoleClient = (*restMockRoleClient)(nil)

func (m *restMockRoleClient) CreateRole(ctx context.Context, req *qrdbtransport.CreateRoleRequest) (*qrdbtransport.Role, error) {
	return nil, errRestMockUnused
}

func (m *restMockRoleClient) GetRole(ctx context.Context, id string) (*qrdbtransport.Role, error) {
	if m.getRole == nil {
		return nil, errRestMockUnused
	}
	return m.getRole(ctx, id)
}

func (m *restMockRoleClient) GetRoleByName(ctx context.Context, req *qrdbtransport.GetRoleByNameRequest) (*qrdbtransport.Role, error) {
	return nil, errRestMockUnused
}

func (m *restMockRoleClient) ResolvePermissions(ctx context.Context, req *qrdbtransport.ResolvePermissionsRequest) (*qrdbtransport.ResolvePermissionsResponse, error) {
	return nil, errRestMockUnused
}

func (m *restMockRoleClient) UpdateRole(ctx context.Context, req *qrdbtransport.UpdateRoleRequest) (*qrdbtransport.Role, error) {
	return nil, errRestMockUnused
}

func (m *restMockRoleClient) DeleteRole(ctx context.Context, id string) error {
	return errRestMockUnused
}

func (m *restMockRoleClient) ListRoles(ctx context.Context, req *qrdbtransport.ListRolesRequest) (*qrdbtransport.ListRolesResponse, error) {
	if m.listRoles == nil {
		return &qrdbtransport.ListRolesResponse{}, nil
	}
	return m.listRoles(ctx, req)
}

func (m *restMockRoleClient) AssignRole(ctx context.Context, userID uint64, roleID string) error {
	return errRestMockUnused
}

func (m *restMockRoleClient) UnassignRole(ctx context.Context, userID uint64, roleID string) error {
	return errRestMockUnused
}

func (m *restMockRoleClient) ListPermissions(ctx context.Context) (*qrdbtransport.ListPermissionsResponse, error) {
	return nil, errRestMockUnused
}

// ReconcileBuiltInRoles is not exercised by the user handlers under test, so
// this mock reports the verb as unused exactly as its other unexercised methods
// do. The real convergence lives in pkg/qrdbrole.
func (m *restMockRoleClient) ReconcileBuiltInRoles(ctx context.Context, req *qrdbtransport.ReconcileRolesRequest) (*qrdbtransport.ReconcileRolesResponse, error) {
	return nil, errRestMockUnused
}

// setupUserHandlerTest initializes the XKMSService singleton, wires the
// provided user/role mocks (when non-nil), mounts the user routes on a chi
// router, and returns the router. Passing nil clients leaves the service's
// user subsystem unconfigured so the ErrNotConfigured paths are reachable.
func setupUserHandlerTest(t *testing.T, users qrdbtransport.UserClient, roles qrdbtransport.RoleClient) *chi.Mux {
	t.Helper()

	xkms.Reset()
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"mem": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "mem",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)
	if users != nil || roles != nil {
		svc.SetUserClients(users, roles)
	}
	t.Cleanup(func() { xkms.Reset() })

	s := &Server{xkmsService: svc}
	r := chi.NewRouter()
	r.Route("/users", func(r chi.Router) {
		r.Post("/", s.handleCreateUser)
		r.Get("/", s.handleListUsers)
		r.Get("/{username}", s.handleGetUser)
		r.Put("/{username}", s.handleUpdateUser)
		r.Delete("/{username}", s.handleDeleteUser)
		r.Post("/{username}/cert-bindings", s.handleBindUserCert)
		r.Get("/{username}/credentials", s.handleListUserCredentials)
	})
	return r
}

func boolPtr(b bool) *bool { return &b }

// ============================================================================
// handleListUsers
// ============================================================================

func TestHandleListUsers_Success(t *testing.T) {
	users := &restMockUserClient{
		listUsers: func(_ context.Context, _ *qrdbtransport.ListUsersRequest) (*qrdbtransport.ListUsersResponse, error) {
			return &qrdbtransport.ListUsersResponse{Users: []*qrdbtransport.User{
				{ID: 1, Username: "alice", Lifecycle: string(qrdbsdk.LifecycleActive)},
				{ID: 2, Username: "bob", Lifecycle: string(qrdbsdk.LifecycleDisabled)},
			}}, nil
		},
	}
	r := setupUserHandlerTest(t, users, &restMockRoleClient{})

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/users/", nil))

	require.Equal(t, http.StatusOK, rr.Code)
	var resp struct {
		Users []map[string]any `json:"users"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Len(t, resp.Users, 2)
	assert.Equal(t, "alice", resp.Users[0]["username"])
}

func TestHandleListUsers_ServiceError(t *testing.T) {
	users := &restMockUserClient{
		listUsers: func(_ context.Context, _ *qrdbtransport.ListUsersRequest) (*qrdbtransport.ListUsersResponse, error) {
			return nil, errors.New("backend down")
		},
	}
	r := setupUserHandlerTest(t, users, &restMockRoleClient{})

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/users/", nil))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestHandleListUsers_NotConfigured(t *testing.T) {
	// No user clients wired => svc.users is nil => ErrNotConfigured => 500.
	r := setupUserHandlerTest(t, nil, nil)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/users/", nil))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestHandleListUsers_ServiceNotInitialized(t *testing.T) {
	// The singleton is reset (never initialized) => xkms.Get() fails => 503.
	xkms.Reset()
	t.Cleanup(func() { xkms.Reset() })

	s := &Server{}
	rr := httptest.NewRecorder()
	s.handleListUsers(rr, httptest.NewRequest(http.MethodGet, "/users/", nil))

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

// ============================================================================
// handleListUserCredentials
// ============================================================================

func TestHandleListUserCredentials_Success(t *testing.T) {
	users := &restMockUserClient{
		getUserByUsername: func(_ context.Context, _, username string) (*qrdbtransport.User, error) {
			return &qrdbtransport.User{ID: 7, Username: username, Lifecycle: string(qrdbsdk.LifecycleActive)}, nil
		},
	}
	r := setupUserHandlerTest(t, users, &restMockRoleClient{})

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/users/alice/credentials", nil))

	require.Equal(t, http.StatusOK, rr.Code)
	var resp struct {
		Credentials []userCredentialItem `json:"credentials"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Empty(t, resp.Credentials)
}

func TestHandleListUserCredentials_UserNotFound(t *testing.T) {
	users := &restMockUserClient{
		getUserByUsername: func(_ context.Context, _, _ string) (*qrdbtransport.User, error) {
			return nil, errors.New("no such user")
		},
	}
	r := setupUserHandlerTest(t, users, &restMockRoleClient{})

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/users/ghost/credentials", nil))

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleListUserCredentials_ServiceNotInitialized(t *testing.T) {
	xkms.Reset()
	t.Cleanup(func() { xkms.Reset() })

	s := &Server{}
	rr := httptest.NewRecorder()
	s.handleListUserCredentials(rr, httptest.NewRequest(http.MethodGet, "/users/x/credentials", nil))

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

// ============================================================================
// handleUpdateUser
// ============================================================================

func TestHandleUpdateUser_Enable(t *testing.T) {
	enabled := false
	users := &restMockUserClient{
		getUserByUsername: func(_ context.Context, _, username string) (*qrdbtransport.User, error) {
			return &qrdbtransport.User{ID: 3, Username: username, Lifecycle: lifecycleOf(enabled)}, nil
		},
		enableUser: func(_ context.Context, _ uint64) error {
			enabled = true
			return nil
		},
	}
	r := setupUserHandlerTest(t, users, &restMockRoleClient{})

	body, _ := json.Marshal(updateUserBody{Enabled: boolPtr(true)})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/users/alice", bytes.NewReader(body)))

	require.Equal(t, http.StatusOK, rr.Code)
	assert.True(t, enabled)
	var info map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &info))
	assert.Equal(t, "alice", info["username"])
}

func TestHandleUpdateUser_Disable(t *testing.T) {
	users := &restMockUserClient{
		getUserByUsername: func(_ context.Context, _, username string) (*qrdbtransport.User, error) {
			return &qrdbtransport.User{ID: 4, Username: username, Lifecycle: string(qrdbsdk.LifecycleDisabled)}, nil
		},
		disableUser: func(_ context.Context, _ uint64) error { return nil },
	}
	r := setupUserHandlerTest(t, users, &restMockRoleClient{})

	body, _ := json.Marshal(updateUserBody{Enabled: boolPtr(false)})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/users/bob", bytes.NewReader(body)))

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleUpdateUser_BadJSON(t *testing.T) {
	r := setupUserHandlerTest(t, &restMockUserClient{}, &restMockRoleClient{})

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/users/alice", bytes.NewBufferString("{not json")))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleUpdateUser_MissingEnabledField(t *testing.T) {
	r := setupUserHandlerTest(t, &restMockUserClient{}, &restMockRoleClient{})

	rr := httptest.NewRecorder()
	// Valid JSON but no "enabled" key => body.Enabled stays nil => 400.
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/users/alice", bytes.NewBufferString("{}")))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleUpdateUser_EnableError(t *testing.T) {
	users := &restMockUserClient{
		getUserByUsername: func(_ context.Context, _, username string) (*qrdbtransport.User, error) {
			return &qrdbtransport.User{ID: 5, Username: username}, nil
		},
		enableUser: func(_ context.Context, _ uint64) error { return errors.New("enable failed") },
	}
	r := setupUserHandlerTest(t, users, &restMockRoleClient{})

	body, _ := json.Marshal(updateUserBody{Enabled: boolPtr(true)})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/users/alice", bytes.NewReader(body)))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestHandleUpdateUser_GetAfterUpdateError(t *testing.T) {
	// Enable succeeds, but the follow-up GetUser fails => 500.
	calls := 0
	users := &restMockUserClient{
		getUserByUsername: func(_ context.Context, _, username string) (*qrdbtransport.User, error) {
			calls++
			if calls >= 2 {
				return nil, errors.New("vanished")
			}
			return &qrdbtransport.User{ID: 6, Username: username}, nil
		},
		enableUser: func(_ context.Context, _ uint64) error { return nil },
	}
	r := setupUserHandlerTest(t, users, &restMockRoleClient{})

	body, _ := json.Marshal(updateUserBody{Enabled: boolPtr(true)})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/users/alice", bytes.NewReader(body)))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestHandleUpdateUser_ServiceNotInitialized(t *testing.T) {
	xkms.Reset()
	t.Cleanup(func() { xkms.Reset() })

	s := &Server{}
	body, _ := json.Marshal(updateUserBody{Enabled: boolPtr(true)})
	rr := httptest.NewRecorder()
	s.handleUpdateUser(rr, httptest.NewRequest(http.MethodPut, "/users/x", bytes.NewReader(body)))

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

// ============================================================================
// handleCreateUser / handleGetUser / handleDeleteUser / handleBindUserCert
// (already partly covered elsewhere; these add the success + error branches
// reachable purely through the singleton.)
// ============================================================================

func TestHandleCreateUser_Success(t *testing.T) {
	users := &restMockUserClient{
		createUser: func(_ context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
			// Echo the persisted fields, as the real store does.
			return &qrdbtransport.User{
				ID: 1, Username: req.Username, Email: req.Email, Name: req.Name, Lifecycle: string(qrdbsdk.LifecycleActive),
			}, nil
		},
	}
	r := setupUserHandlerTest(t, users, &restMockRoleClient{})

	body, _ := json.Marshal(createUserBody{Username: "carol", Email: "carol@example.com", DisplayName: "Carol"})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/users/", bytes.NewReader(body)))

	require.Equal(t, http.StatusCreated, rr.Code)
	var info map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &info))
	assert.Equal(t, "carol", info["username"])
	assert.Equal(t, "Carol", info["display_name"])
}

func TestHandleCreateUser_BadJSON(t *testing.T) {
	r := setupUserHandlerTest(t, &restMockUserClient{}, &restMockRoleClient{})

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/users/", bytes.NewBufferString("nope")))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleCreateUser_ServiceError(t *testing.T) {
	users := &restMockUserClient{
		createUser: func(_ context.Context, _ *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
			return nil, errors.New("duplicate")
		},
	}
	r := setupUserHandlerTest(t, users, &restMockRoleClient{})

	// A valid request that the SERVICE rejects. Without the email it would stop
	// at the client-input guard and return 400, so this test would no longer
	// reach the 500 path it exists to cover.
	body, _ := json.Marshal(createUserBody{Username: "carol", Email: "carol@example.com"})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/users/", bytes.NewReader(body)))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestHandleGetUser_Success(t *testing.T) {
	users := &restMockUserClient{
		getUserByUsername: func(_ context.Context, _, username string) (*qrdbtransport.User, error) {
			return &qrdbtransport.User{ID: 9, Username: username, Lifecycle: string(qrdbsdk.LifecycleActive)}, nil
		},
	}
	r := setupUserHandlerTest(t, users, &restMockRoleClient{})

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/users/dave", nil))

	require.Equal(t, http.StatusOK, rr.Code)
	var info map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &info))
	assert.Equal(t, "dave", info["username"])
}

func TestHandleGetUser_NotFound(t *testing.T) {
	users := &restMockUserClient{
		getUserByUsername: func(_ context.Context, _, _ string) (*qrdbtransport.User, error) {
			return nil, errors.New("missing")
		},
	}
	r := setupUserHandlerTest(t, users, &restMockRoleClient{})

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/users/ghost", nil))

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleDeleteUser_Success(t *testing.T) {
	users := &restMockUserClient{
		getUserByUsername: func(_ context.Context, _, username string) (*qrdbtransport.User, error) {
			return &qrdbtransport.User{ID: 11, Username: username}, nil
		},
		deleteUser: func(_ context.Context, _ uint64) error { return nil },
	}
	r := setupUserHandlerTest(t, users, &restMockRoleClient{})

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/users/dave", nil))

	require.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "deleted", resp["status"])
}

func TestHandleDeleteUser_Error(t *testing.T) {
	users := &restMockUserClient{
		getUserByUsername: func(_ context.Context, _, _ string) (*qrdbtransport.User, error) {
			return nil, errors.New("nope")
		},
	}
	r := setupUserHandlerTest(t, users, &restMockRoleClient{})

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/users/ghost", nil))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestHandleBindUserCert_Success(t *testing.T) {
	users := &restMockUserClient{
		getUserByUsername: func(_ context.Context, _, username string) (*qrdbtransport.User, error) {
			return &qrdbtransport.User{ID: 13, Username: username}, nil
		},
		addCertBinding: func(_ context.Context, _ uint64, _ string, _ int64) (*qrdbtransport.User, error) {
			return &qrdbtransport.User{ID: 13}, nil
		},
	}
	r := setupUserHandlerTest(t, users, &restMockRoleClient{})

	body, _ := json.Marshal(bindUserCertBody{Thumbprint: "abc123", NotAfterUnix: 9999999999})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/users/dave/cert-bindings", bytes.NewReader(body)))

	require.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "bound", resp["status"])
}

func TestHandleBindUserCert_BadJSON(t *testing.T) {
	r := setupUserHandlerTest(t, &restMockUserClient{}, &restMockRoleClient{})

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/users/dave/cert-bindings", bytes.NewBufferString("x")))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleBindUserCert_Error(t *testing.T) {
	users := &restMockUserClient{
		getUserByUsername: func(_ context.Context, _, _ string) (*qrdbtransport.User, error) {
			return nil, errors.New("nope")
		},
	}
	r := setupUserHandlerTest(t, users, &restMockRoleClient{})

	body, _ := json.Marshal(bindUserCertBody{Thumbprint: "abc"})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/users/ghost/cert-bindings", bytes.NewReader(body)))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// The REST surface must refuse a create with no canonical login key, and must
// do so as a client error rather than a 500.
//
// Email is REQUIRED (go-qrdb #190): xkms resolves logins and WebAuthn
// enrollment through it, so a user created without one is provisioned and
// unreachable. Before this the field did not exist on the request at all.
func TestHandleCreateUser_EmailRequired(t *testing.T) {
	called := false
	users := &restMockUserClient{
		createUser: func(_ context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
			called = true
			return &qrdbtransport.User{ID: 1, Username: req.Username}, nil
		},
	}
	r := setupUserHandlerTest(t, users, &restMockRoleClient{})

	body, _ := json.Marshal(createUserBody{Username: "carol", DisplayName: "Carol"})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/users/", bytes.NewReader(body)))

	// Assert the EXACT status, not merely "not created". The first version of
	// this test checked only != 201 while its comment claimed a client error —
	// so it passed against the 500 the handler was actually returning. A test
	// that names a property must assert that property.
	assert.Equal(t, http.StatusBadRequest, rr.Code,
		"a missing login key is malformed client input, not a server fault")
	assert.False(t, called, "the store must not be reached")
}

// The email supplied over HTTP must actually reach the store — asserting on the
// response would pass even when the field is dropped in the handler.
func TestHandleCreateUser_EmailReachesTheStore(t *testing.T) {
	var got *qrdbtransport.CreateUserRequest
	users := &restMockUserClient{
		createUser: func(_ context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
			got = req
			return &qrdbtransport.User{ID: 1, Username: req.Username, Email: req.Email, Name: req.Name, Lifecycle: string(qrdbsdk.LifecycleActive)}, nil
		},
	}
	r := setupUserHandlerTest(t, users, &restMockRoleClient{})

	body, _ := json.Marshal(createUserBody{Username: "dan", Email: "dan@example.com", DisplayName: "Dan"})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/users/", bytes.NewReader(body)))

	require.Equal(t, http.StatusCreated, rr.Code)
	require.NotNil(t, got)
	assert.Equal(t, "dan@example.com", got.Email)
	assert.Equal(t, "Dan", got.Name)
}

// lifecycleOf maps a test's enabled flag to qrdb's account lifecycle, the only
// account state since qrdb v0.20.
func lifecycleOf(enabled bool) string {
	if enabled {
		return string(qrdbsdk.LifecycleActive)
	}
	return string(qrdbsdk.LifecycleDisabled)
}
