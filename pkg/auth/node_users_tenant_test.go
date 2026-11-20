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

const tenantTestTenant = "acme"

// routingUsers mimics go-qrdb's routing user service: a lookup acts on
// tenant.EffectiveTenant, which defaults an unbound context to the system
// tenant and refuses a different requested tenant.
type routingUsers struct {
	qrdbsdk.UserServicer
}

func (routingUsers) lookup(ctx context.Context, requested string) (*qrdbsdk.User, error) {
	eff, err := qrdbtenant.EffectiveTenant(ctx, requested, "get user")
	if err != nil {
		return nil, err
	}
	if eff != tenantTestTenant {
		return nil, errors.New("user not found")
	}
	return &qrdbsdk.User{ID: 7, Username: "alice", Email: "alice@acme.example", TenantID: eff, Lifecycle: qrdbsdk.LifecycleActive}, nil
}

// GetUser acts, like go-qrdb's routing user service, on the tenant bound on
// ctx: an unbound (anonymous) context resolves in the system tenant.
func (r routingUsers) GetUser(ctx context.Context, id uint64) (*qrdbsdk.User, error) {
	if id != 7 {
		return nil, errors.New("user not found")
	}
	return r.lookup(ctx, "")
}

func (r routingUsers) GetUserByUsername(ctx context.Context, tenantID, _ string) (*qrdbsdk.User, error) {
	return r.lookup(ctx, tenantID)
}

func (r routingUsers) GetUserByEmail(ctx context.Context, tenantID, _ string) (*qrdbsdk.User, error) {
	return r.lookup(ctx, tenantID)
}

type routingSource struct{}

func (routingSource) UserService() qrdbsdk.UserServicer { return routingUsers{} }

// TestNodeUserClient_NonSystemTenantLookups is PR #2296's Codex P1: the
// public routes' context is anonymous, so the adapter must bind the
// server-validated tenant before the node call, or a non-system tenant's
// PIV refresh and WebAuthn lookups are refused or routed to system.
func TestNodeUserClient_NonSystemTenantLookups(t *testing.T) {
	c := NewNodeUserClient(routingSource{})
	ctx := context.Background()

	u, err := c.GetUserByUsername(ctx, tenantTestTenant, "alice")
	require.NoError(t, err)
	require.Equal(t, tenantTestTenant, u.TenantID)

	u, err = c.GetUserByEmail(ctx, tenantTestTenant, "alice@acme.example")
	require.NoError(t, err)
	require.Equal(t, tenantTestTenant, u.TenantID)
}

// TestQRDBUserResolver_NonSystemUserHandleRefresh refreshes a passkey
// session of a non-system tenant: the anonymous refresh route must bind the
// validated token's tenant before the by-id lookup (Codex 5989079760).
func TestQRDBUserResolver_NonSystemUserHandleRefresh(t *testing.T) {
	resolver := NewQRDBUserResolver(NewNodeUserClient(routingSource{}))

	fresh, err := resolver.ResolveUser(context.Background(), &Identity{
		Subject:  webAuthnHandleSubject(7),
		TenantID: tenantTestTenant,
		Metadata: map[string]string{SubjectKindMetadataKey: SubjectKindUserHandle},
	})
	require.NoError(t, err)
	require.Equal(t, tenantTestTenant, fresh.TenantID)
}
