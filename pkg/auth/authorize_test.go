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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRBACClient is a narrow in-memory stand-in for qrdbtransport.RBACClient.
// It records the last Authorize call so tests can assert the Authorizer
// projects the xkms Identity and target tenant correctly, and it returns a
// pre-programmed decision.
type fakeRBACClient struct {
	err error

	lastIdentity *qrdbtransport.Identity
	lastResource string
	lastAction   string
	lastTenant   string
}

func (f *fakeRBACClient) Authorize(ctx context.Context, identity *qrdbtransport.Identity, resource, action string) error {
	f.lastIdentity = identity
	f.lastResource = resource
	f.lastAction = action
	f.lastTenant, _ = qrdbsdk.TenantFromContext(ctx)
	return f.err
}

func (f *fakeRBACClient) ListPermissions(ctx context.Context, identity *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, errors.New("not implemented in fake")
}

func TestNewAuthorizer_NilRBAC_Disabled(t *testing.T) {
	a := NewAuthorizer(nil)
	require.NotNil(t, a)
	assert.False(t, a.Enabled())
}

func TestNewAuthorizer_Enabled(t *testing.T) {
	a := NewAuthorizer(&fakeRBACClient{})
	assert.True(t, a.Enabled())
}

// TestAuthorizer_Enabled_NilReceiver proves Enabled tolerates a nil
// *Authorizer (the documented "no Authorizer configured" shape) without
// panicking.
func TestAuthorizer_Enabled_NilReceiver(t *testing.T) {
	var a *Authorizer
	assert.False(t, a.Enabled())
}

// TestAuthorizer_Authorize_Disabled_AllowsAll proves that a disabled
// Authorizer (nil RBAC client) allows every request, including one with a
// nil identity, preserving legacy "RBAC disabled => allow all" behavior.
func TestAuthorizer_Authorize_Disabled_AllowsAll(t *testing.T) {
	a := NewAuthorizer(nil)
	err := a.Authorize(context.Background(), nil, "key", "read")
	assert.NoError(t, err)
}

func TestAuthorizer_Authorize_NilIdentity(t *testing.T) {
	a := NewAuthorizer(&fakeRBACClient{})
	err := a.Authorize(context.Background(), nil, "key", "read")
	assert.ErrorIs(t, err, ErrUnauthenticated)
}

func TestAuthorizer_Authorize_Allowed(t *testing.T) {
	fake := &fakeRBACClient{}
	a := NewAuthorizer(fake)
	identity := &Identity{
		Subject:  "alice",
		TenantID: "tenant-a",
		Roles:    []string{"admin"},
		Metadata: map[string]string{"k": "v"},
	}

	err := a.Authorize(context.Background(), identity, "key", "read")
	require.NoError(t, err)
	require.NotNil(t, fake.lastIdentity)
	assert.Equal(t, "alice", fake.lastIdentity.Subject)
	assert.Equal(t, "tenant-a", fake.lastIdentity.TenantID)
	assert.Equal(t, []string{"admin"}, fake.lastIdentity.Roles)
	assert.Equal(t, "v", fake.lastIdentity.Metadata["k"])
	assert.Equal(t, "key", fake.lastResource)
	assert.Equal(t, "read", fake.lastAction)
	assert.Equal(t, "tenant-a", fake.lastTenant)
}

// TestAuthorizer_Authorize_EmptyTenantDefaultsToSystem proves an identity
// with an unset TenantID is normalized to the system tenant both on the
// projected qrdb identity and on the request-scoped tenant context, matching
// IsCrossTenant's treatment of an unset tenant as the privileged platform
// scope.
func TestAuthorizer_Authorize_EmptyTenantDefaultsToSystem(t *testing.T) {
	fake := &fakeRBACClient{}
	a := NewAuthorizer(fake)
	identity := &Identity{Subject: "root"}

	err := a.Authorize(context.Background(), identity, "tenant", "create")
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.SystemTenantID, fake.lastIdentity.TenantID)
	assert.Equal(t, qrdbsdk.SystemTenantID, fake.lastTenant)
}

func TestAuthorizer_Authorize_Denied(t *testing.T) {
	denyErr := errors.New("permission denied")
	fake := &fakeRBACClient{err: denyErr}
	a := NewAuthorizer(fake)
	identity := &Identity{Subject: "mallory", TenantID: "tenant-a"}

	err := a.Authorize(context.Background(), identity, "key", "delete")
	assert.ErrorIs(t, err, denyErr)
}
