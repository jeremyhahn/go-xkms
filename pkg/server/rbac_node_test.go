package server

import (
	"context"
	"errors"
	"slices"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// scopeDecider grants what the identity carries in ScopePermissions.
type scopeDecider struct{ seen *auth.Identity }

func (d *scopeDecider) Authorize(_ context.Context, identity *auth.Identity, resource, action string) error {
	d.seen = identity
	if slices.Contains(identity.ScopePermissions, resource+":"+action) {
		return nil
	}
	return &qrdbsdk.PermissionDeniedError{}
}

// refusingRBAC is an SDK RBAC client that refuses every decision.
type refusingRBAC struct{}

func (refusingRBAC) Authorize(context.Context, *qrdbtransport.Identity, string, string) error {
	return errors.New("projection refuses")
}

func (refusingRBAC) ListPermissions(context.Context, *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, nil
}

func (refusingRBAC) ListOwnPermissions(context.Context) ([]qrdbtransport.PermissionInfo, error) {
	return nil, nil
}

func TestNodeAuthorizer_DecidesOnScopePermissions(t *testing.T) {
	d := &scopeDecider{}
	a := newNodeAuthorizer(refusingRBAC{}, d)
	require.True(t, a.Enabled())

	delegated := &auth.Identity{
		Subject:          "qrdb-service:onboarder",
		ScopePermissions: []string{string(qrdbsdk.PermissionUsersInvite)},
	}
	other := &auth.Identity{Subject: "root", TenantID: qrdbsdk.SystemTenantID}
	ctx := auth.WithIdentity(context.Background(), other)
	require.NoError(t, a.Authorize(ctx, delegated, "users", "invite"))
	require.Equal(t, "qrdb-service:onboarder", d.seen.Subject)
	require.Equal(t, qrdbsdk.SystemTenantID, d.seen.TenantID, "an unset tenant defaults to system")
	require.Empty(t, delegated.TenantID, "the caller's identity is not mutated")

	var denied *qrdbsdk.PermissionDeniedError
	require.True(t, errors.As(a.Authorize(ctx, delegated, "users", "delete"), &denied))
	require.ErrorIs(t, a.Authorize(ctx, nil, "users", "invite"), auth.ErrUnauthenticated)
}

func TestNodeAuthorizer_Posture(t *testing.T) {
	ctx := context.Background()
	id := &auth.Identity{Subject: "operator", TenantID: qrdbsdk.SystemTenantID}

	off := newNodeAuthorizer(nil, &scopeDecider{})
	require.False(t, off.Enabled())
	require.NoError(t, off.Authorize(ctx, id, "users", "delete"))

	rbacOnly := newNodeAuthorizer(refusingRBAC{}, nil)
	require.True(t, rbacOnly.Enabled())
	require.Error(t, rbacOnly.Authorize(ctx, id, "users", "invite"))
}
