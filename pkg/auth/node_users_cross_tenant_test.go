// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"errors"
	"testing"

	qrdbtenant "github.com/jeremyhahn/go-qrdb/pkg/tenant"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/require"
)

const (
	crossTenantA = "tenant-a"
	crossTenantB = "tenant-b"
	crossEmail   = "alice@shared.example"
)

// crossTenantUsers mimics go-qrdb's routing user service over two tenants
// that each hold a user "alice" with the same email. Every lookup acts on
// tenant.EffectiveTenant, so it only sees the records of the tenant bound on
// ctx; "bob" exists in tenant B only.
type crossTenantUsers struct {
	qrdbsdk.UserServicer
}

var crossTenantRecords = map[string][]qrdbsdk.User{
	crossTenantA: {
		{ID: 11, Username: "alice", Email: crossEmail, TenantID: crossTenantA, Lifecycle: qrdbsdk.LifecycleActive},
	},
	crossTenantB: {
		{ID: 21, Username: "alice", Email: crossEmail, TenantID: crossTenantB, Lifecycle: qrdbsdk.LifecycleActive},
		{ID: 22, Username: "bob", Email: "bob@b.example", TenantID: crossTenantB, Lifecycle: qrdbsdk.LifecycleActive},
	},
}

var errCrossTenantNotFound = errors.New("user not found")

func (crossTenantUsers) find(ctx context.Context, requested string, match func(qrdbsdk.User) bool) (*qrdbsdk.User, error) {
	eff, err := qrdbtenant.EffectiveTenant(ctx, requested, "get user")
	if err != nil {
		return nil, err
	}
	for _, u := range crossTenantRecords[eff] {
		if match(u) {
			u := u
			return &u, nil
		}
	}
	return nil, errCrossTenantNotFound
}

func (r crossTenantUsers) GetUser(ctx context.Context, id uint64) (*qrdbsdk.User, error) {
	return r.find(ctx, "", func(u qrdbsdk.User) bool { return u.ID == id })
}

func (r crossTenantUsers) GetUserByUsername(ctx context.Context, tenantID, username string) (*qrdbsdk.User, error) {
	return r.find(ctx, tenantID, func(u qrdbsdk.User) bool { return u.Username == username })
}

func (r crossTenantUsers) GetUserByEmail(ctx context.Context, tenantID, email string) (*qrdbsdk.User, error) {
	return r.find(ctx, tenantID, func(u qrdbsdk.User) bool { return u.Email == email })
}

type crossTenantSource struct{}

func (crossTenantSource) UserService() qrdbsdk.UserServicer { return crossTenantUsers{} }

// TestNodeUserClient_CrossTenantSameUsernameAndEmail is issue #2335 (Tenant
// Agent follow-up of #2296): with the same username and email in two
// tenants, a lookup for one tenant never returns the other tenant's record,
// and a name present only in tenant B is not found from tenant A.
func TestNodeUserClient_CrossTenantSameUsernameAndEmail(t *testing.T) {
	c := NewNodeUserClient(crossTenantSource{})
	ctx := context.Background()

	for _, tc := range []struct {
		tenant string
		id     uint64
	}{{crossTenantA, 11}, {crossTenantB, 21}} {
		u, err := c.GetUserByUsername(ctx, tc.tenant, "alice")
		require.NoError(t, err, tc.tenant)
		require.Equal(t, tc.tenant, u.TenantID)
		require.Equal(t, tc.id, u.ID)

		u, err = c.GetUserByEmail(ctx, tc.tenant, crossEmail)
		require.NoError(t, err, tc.tenant)
		require.Equal(t, tc.tenant, u.TenantID)
		require.Equal(t, tc.id, u.ID)
	}

	_, err := c.GetUserByUsername(ctx, crossTenantA, "bob")
	require.Error(t, err, "a username present only in tenant B must not resolve from tenant A")
	_, err = c.GetUserByEmail(ctx, crossTenantA, "bob@b.example")
	require.Error(t, err, "an email present only in tenant B must not resolve from tenant A")

	u, err := c.GetUserByUsername(ctx, crossTenantB, "bob")
	require.NoError(t, err)
	require.Equal(t, crossTenantB, u.TenantID)
}

// TestNodeUserClient_CrossTenantBoundContextWins checks that a by-id lookup
// bound to tenant A never returns tenant B's user, and that a lookup naming
// tenant B from a tenant A context yields B's own record or an error, never
// tenant A's "alice".
func TestNodeUserClient_CrossTenantBoundContextWins(t *testing.T) {
	c := NewNodeUserClient(crossTenantSource{})
	ctxA := qrdbtenant.WithTenantID(context.Background(), crossTenantA)

	u, err := c.GetUser(ctxA, 11)
	require.NoError(t, err)
	require.Equal(t, crossTenantA, u.TenantID)

	_, err = c.GetUser(ctxA, 21)
	require.Error(t, err, "tenant B's user id must not resolve from a tenant A context")

	u, err = c.GetUserByUsername(ctxA, crossTenantB, "alice")
	if err == nil {
		require.Equal(t, crossTenantB, u.TenantID,
			"a lookup naming tenant B must never return tenant A's record either")
	}
	u, err = c.GetUserByEmail(ctxA, crossTenantB, crossEmail)
	if err == nil {
		require.Equal(t, crossTenantB, u.TenantID)
	}
}
