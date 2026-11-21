package auth

import (
	"context"
	"errors"
	"slices"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/require"
)

// scopeDecider stands in for the node's own authorizer: it grants exactly
// the permissions the identity carries in ScopePermissions, the field a
// trusted issuance path (token scp claim, service principal) fills.
type scopeDecider struct{ seen *Identity }

func (d *scopeDecider) Authorize(_ context.Context, identity *Identity, resource, action string) error {
	d.seen = identity
	if slices.Contains(identity.ScopePermissions, resource+":"+action) {
		return nil
	}
	return &qrdbsdk.PermissionDeniedError{}
}

// TestNodeAuthorizer_DecidesOnScopePermissions is SPEC row
// authz-device-onboarding for a delegated caller: a principal granted
// users:invite only through ScopePermissions is allowed, because the
// decision is made by the node's authorizer on the original trusted
// identity, not on the Subject/TenantID/Roles projection the SDK RBAC
// client takes. The RBAC client here refuses everything, so an allow can
// only come from the node's decision.
func TestNodeAuthorizer_DecidesOnScopePermissions(t *testing.T) {
	d := &scopeDecider{}
	a := NewNodeAuthorizer(&fakeRBACClient{err: errors.New("projection refuses")}, d)
	require.True(t, a.Enabled())

	delegated := &Identity{
		Subject:          "qrdb-service:onboarder",
		ScopePermissions: []string{string(qrdbsdk.PermissionUsersInvite)},
	}
	ctx := context.Background()
	require.NoError(t, a.Authorize(ctx, delegated, "users", "invite"))
	require.Equal(t, []string{string(qrdbsdk.PermissionUsersInvite)}, d.seen.ScopePermissions)
	require.Equal(t, qrdbsdk.SystemTenantID, d.seen.TenantID, "an unset tenant defaults to system")
	require.Empty(t, delegated.TenantID, "the caller's identity is not mutated")

	var denied *qrdbsdk.PermissionDeniedError
	require.True(t, errors.As(a.Authorize(ctx, delegated, "users", "delete"), &denied))
	require.ErrorIs(t, a.Authorize(ctx, nil, "users", "invite"), ErrUnauthenticated)
}

// TestNodeAuthorizer_Posture: without an RBAC client authorization is off,
// as NewAuthorizer(nil); without a node authorizer the RBAC client decides,
// as NewAuthorizer(rbac).
func TestNodeAuthorizer_Posture(t *testing.T) {
	ctx := context.Background()
	id := &Identity{Subject: "operator", TenantID: qrdbsdk.SystemTenantID}

	off := NewNodeAuthorizer(nil, &scopeDecider{})
	require.False(t, off.Enabled())
	require.NoError(t, off.Authorize(ctx, id, "users", "delete"))

	rbacErr := errors.New("rbac refuses")
	rbacOnly := NewNodeAuthorizer(&fakeRBACClient{err: rbacErr}, nil)
	require.True(t, rbacOnly.Enabled())
	require.Error(t, rbacOnly.Authorize(ctx, id, "users", "invite"))
}
