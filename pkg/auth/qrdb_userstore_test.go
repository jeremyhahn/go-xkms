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
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
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

func (f *fakeQRDBUserClient) RemoveCertBinding(ctx context.Context, userID uint64, thumbprint string) (*qrdbtransport.User, error) {
	return nil, errors.New("not implemented in fake")
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

func TestNewQRDBUserStore(t *testing.T) {
	users := newFakeQRDBUserClient()
	store := NewQRDBUserStore(users)
	require.NotNil(t, store)
	assert.Same(t, users, store.users)
}

// TestQRDBUserStore_GetByCertFingerprint_Success proves the store carries
// every assigned role as the qrdb role ID the user record holds -- go-qrdb's
// authorizer resolves permissions by role ID, never by name (go-xkms#1069).
func TestQRDBUserStore_GetByCertFingerprint_Success(t *testing.T) {
	users := newFakeQRDBUserClient()
	users.byThumbprint["thumb-1"] = &qrdbtransport.User{
		Username:    "alice",
		Email:       "alice@example.com",
		TenantID:    "tenant-a",
		RoleIDs:     []string{"role-id-admin", "role-id-owner"},
		Lifecycle:   string(qrdbsdk.LifecycleActive),
		AuthMethods: []string{"mtls", "webauthn"},
	}

	store := NewQRDBUserStore(users)
	u, err := store.GetByCertFingerprint(context.Background(), "thumb-1")
	require.NoError(t, err)
	assert.Equal(t, "alice", u.Username)
	assert.Equal(t, "alice@example.com", u.Email, "the canonical login key must be projected")
	assert.Equal(t, []string{"role-id-admin", "role-id-owner"}, u.Roles,
		"every role ID must be carried verbatim, none dropped or renamed")
	assert.Equal(t, "tenant-a", u.TenantID)
	assert.True(t, u.Enabled)
	assert.Equal(t, []string{"mtls", "webauthn"}, u.AuthMethods, "the permitted-method policy must be projected")
}

// TestQRDBUserStore_GetByCertFingerprint_RolesAreACopy proves the projected
// roles do not alias the user record's slice, so a caller mutating the
// identity cannot rewrite the store's answer.
func TestQRDBUserStore_GetByCertFingerprint_RolesAreACopy(t *testing.T) {
	users := newFakeQRDBUserClient()
	record := &qrdbtransport.User{
		Username:  "dave",
		TenantID:  "system",
		RoleIDs:   []string{"role-id-admin"},
		Lifecycle: string(qrdbsdk.LifecycleActive),
	}
	users.byThumbprint["thumb-4"] = record

	u, err := NewQRDBUserStore(users).GetByCertFingerprint(context.Background(), "thumb-4")
	require.NoError(t, err)
	u.Roles[0] = "tampered"
	assert.Equal(t, "role-id-admin", record.RoleIDs[0])
}

func TestQRDBUserStore_GetByCertFingerprint_UserNotFound(t *testing.T) {
	store := NewQRDBUserStore(newFakeQRDBUserClient())

	_, err := store.GetByCertFingerprint(context.Background(), "missing-thumb")
	require.Error(t, err)
}

func TestQRDBUserStore_GetByCertFingerprint_NoRoleIDs(t *testing.T) {
	users := newFakeQRDBUserClient()
	users.byThumbprint["thumb-2"] = &qrdbtransport.User{
		Username:  "bob",
		TenantID:  "tenant-b",
		RoleIDs:   nil,
		Lifecycle: string(qrdbsdk.LifecycleActive),
	}
	store := NewQRDBUserStore(users)

	u, err := store.GetByCertFingerprint(context.Background(), "thumb-2")
	require.NoError(t, err)
	assert.Equal(t, "bob", u.Username)
	assert.Empty(t, u.Roles, "roles should be empty when the user carries no role ids")
}

// TestQRDBUserStore_GetByCertFingerprint_NoEmailLoginKey proves a user
// created without an email login key projects an empty Email — the
// documented "absent" state for bootstrap and service accounts — rather than
// a value derived from the username.
func TestQRDBUserStore_GetByCertFingerprint_NoEmailLoginKey(t *testing.T) {
	users := newFakeQRDBUserClient()
	users.byThumbprint["thumb-svc"] = &qrdbtransport.User{
		Username:  "svc-backup",
		TenantID:  "system",
		Lifecycle: string(qrdbsdk.LifecycleActive),
	}
	store := NewQRDBUserStore(users)

	u, err := store.GetByCertFingerprint(context.Background(), "thumb-svc")
	require.NoError(t, err)
	assert.Equal(t, "svc-backup", u.Username)
	assert.Empty(t, u.Email, "no login key must project as empty, never fabricated")
}

// TestQRDBUserStore_GetByCertFingerprint_DisabledUser proves a user whose
// lifecycle is not active projects Enabled=false, so the authenticator
// refuses it.
func TestQRDBUserStore_GetByCertFingerprint_DisabledUser(t *testing.T) {
	users := newFakeQRDBUserClient()
	users.byThumbprint["thumb-3"] = &qrdbtransport.User{
		Username:  "carol",
		TenantID:  "tenant-c",
		RoleIDs:   []string{"role-id-user"},
		Lifecycle: string(qrdbsdk.LifecycleDisabled),
	}
	store := NewQRDBUserStore(users)

	u, err := store.GetByCertFingerprint(context.Background(), "thumb-3")
	require.NoError(t, err)
	assert.Equal(t, "carol", u.Username)
	assert.False(t, u.Enabled)
}
