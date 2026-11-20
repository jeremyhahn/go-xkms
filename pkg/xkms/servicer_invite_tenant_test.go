// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package xkms

import (
	"context"
	"testing"

	qrdbtenant "github.com/jeremyhahn/go-qrdb/pkg/tenant"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/require"

	xkmstransport "github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestGetInvite_NonSystemTenantBindsInviteTenant is PR #2296's Codex P1:
// the invite routes are anonymous, so the node user service would route a
// by-ID user read to the system tenant. Once the invite record is found in
// its tenant, the read runs bound to that tenant.
func TestGetInvite_NonSystemTenantBindsInviteTenant(t *testing.T) {
	const tenantID = "acme"
	f := newInviteFixture(t)
	f.users.getUser = func(ctx context.Context, id uint64) (*qrdbtransport.User, error) {
		if got := qrdbtenant.CallerTenant(ctx); got != tenantID || id != inviteFixtureQRDBUserID {
			return nil, &qrdbtransport.UserNotFoundError{ID: id}
		}
		return &qrdbtransport.User{ID: id, Email: inviteFixtureEmail, Name: "Invitee", TenantID: tenantID}, nil
	}

	info, err := f.svc.createInvite(context.Background(), tenantID, inviteFixtureQRDBUserID, f.inviteTTL)
	require.NoError(t, err)

	meta, err := f.svc.GetInvite(context.Background(), &xkmstransport.GetInviteRequest{TenantID: tenantID, Token: info.Token})
	require.NoError(t, err)
	require.Equal(t, inviteFixtureEmail, meta.Email)
}
