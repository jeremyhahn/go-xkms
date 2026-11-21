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

package token

import (
	"context"
	"errors"
	"testing"

	qrdbtenant "github.com/jeremyhahn/go-qrdb/pkg/tenant"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// rbacServiceBind models Node.ServiceContext on an RBAC-enforcing node: it
// swaps the identity for the system service principal but keeps an explicit
// tenant binding, so a call bound to any tenant other than the system one
// is refused ("identity not in target tenant").
func rbacServiceBind(ctx context.Context) (context.Context, error) {
	if tid := qrdbtenant.FromContext(ctx); tid != "" && tid != qrdbsdk.SystemTenantID {
		return nil, errors.New("identity not in target tenant")
	}
	return ctx, nil
}

// TestQRDBRefreshStore_RevokeBySubjectFromNonSystemRequest: the public
// login paths save refresh sessions in system storage, and a DisableUser on
// a non-system request (its context bound to the user's tenant) must still
// revoke them, so re-enabling the account cannot revive the old refresh
// token.
func TestQRDBRefreshStore_RevokeBySubjectFromNonSystemRequest(t *testing.T) {
	store, err := NewQRDBRefreshStore(newGuardedMemoryKV(), WithCallContext(rbacServiceBind))
	require.NoError(t, err)
	issuer := newIssuerWithStore(t, store)

	// Public login: no tenant binding on the request.
	pair, err := issuer.Mint(context.Background(), testIdentity())
	require.NoError(t, err)

	// DisableUser on a non-system request.
	tenantCtx := qrdbtenant.WithTenantID(context.Background(), "acme")
	require.NoError(t, issuer.RevokeBySubject(tenantCtx, testIdentity().TenantID, testIdentity().Subject))

	// After re-enable, the old refresh token stays refused.
	_, err = issuer.Refresh(context.Background(), pair.RefreshToken)
	var revokedErr *RefreshRevokedError
	require.ErrorAs(t, err, &revokedErr)
}

// TestQRDBRefreshStore_RevokeBySubjectIsTenantScoped is PR #2296's Codex
// round-5 P1: every tenant's refresh bookkeeping shares the system store and
// usernames are tenant-scoped, so disabling alice in tenant A must leave
// alice in tenant B and alice in the system tenant signed in.
func TestQRDBRefreshStore_RevokeBySubjectIsTenantScoped(t *testing.T) {
	store, err := NewQRDBRefreshStore(newGuardedMemoryKV(), WithCallContext(rbacServiceBind))
	require.NoError(t, err)
	issuer := newIssuerWithStore(t, store)

	alice := func(tenantID string) *auth.Identity {
		return &auth.Identity{Subject: "alice", TenantID: tenantID, Metadata: map[string]string{"username": "alice"}}
	}
	pairA, err := issuer.Mint(context.Background(), alice("tenant-a"))
	require.NoError(t, err)
	pairB, err := issuer.Mint(context.Background(), alice("tenant-b"))
	require.NoError(t, err)
	pairSys, err := issuer.Mint(context.Background(), alice(qrdbsdk.SystemTenantID))
	require.NoError(t, err)

	tenantCtx := qrdbtenant.WithTenantID(context.Background(), "tenant-a")
	require.NoError(t, issuer.RevokeBySubject(tenantCtx, "tenant-a", "alice"))

	_, err = issuer.Refresh(context.Background(), pairA.RefreshToken)
	var revokedErr *RefreshRevokedError
	require.ErrorAs(t, err, &revokedErr, "tenant A alice is revoked")

	_, err = issuer.Refresh(context.Background(), pairB.RefreshToken)
	require.NoError(t, err, "tenant B alice stays signed in")
	_, err = issuer.Refresh(context.Background(), pairSys.RefreshToken)
	require.NoError(t, err, "system-tenant alice stays signed in")
}

// TestRecordOwnedBy_LegacyRecordIsSystemTenant: a record saved before Record
// carried a tenant belongs to the system tenant only.
func TestRecordOwnedBy_LegacyRecordIsSystemTenant(t *testing.T) {
	legacy := &Record{Subject: "alice"}
	require.True(t, legacy.ownedBy(qrdbsdk.SystemTenantID, "alice"))
	require.True(t, legacy.ownedBy("", "alice"))
	require.False(t, legacy.ownedBy("tenant-a", "alice"))
	require.False(t, legacy.ownedBy(qrdbsdk.SystemTenantID, "bob"))

	scoped := &Record{Subject: "alice", TenantID: "tenant-a"}
	require.True(t, scoped.ownedBy("tenant-a", "alice"))
	require.False(t, scoped.ownedBy("tenant-b", "alice"))
	require.False(t, scoped.ownedBy("", "alice"))
}
