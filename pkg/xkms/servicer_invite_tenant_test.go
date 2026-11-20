// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package xkms

import (
	"context"
	"testing"

	qrdbtenant "github.com/jeremyhahn/go-qrdb/pkg/tenant"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
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

// inviteCallerTenant is the tenant a go-qrdb routing user service acts on:
// the one bound on ctx, else system.
func inviteCallerTenant(ctx context.Context) string {
	if id, ok := qrdbtenant.IDFromContext(ctx); ok && id != "" {
		return id
	}
	return "system"
}

// TestInviteRegistration_NonSystemTenant enrols a FIDO2 credential through a
// non-system tenant's invite (Codex 5989079760): the ceremony must resolve
// the invite's own account in the invite's validated tenant, not re-resolve
// the email in the WebAuthn store's configured (system) scope.
func TestInviteRegistration_OutsideRPTenantRefused(t *testing.T) {
	// Ruling 1029 (B): the relying party serves one tenant (the fixture's
	// WebAuthn stores are scoped to webauthntest.TenantID, "system"). An
	// account invited into another tenant could enrol a passkey it can never
	// sign in with, so enrolment is refused with a typed error and leaves
	// the account pending with no credential.
	const tenant = "acme"
	f := newInviteFixtureIn(t, tenant)
	token := f.mintInvite(t)

	_, err := f.beginRegistration(tenant, token)
	require.ErrorIs(t, err, ErrInviteTenantNotServed)

	_, err = f.finishRegistration(tenant, token, "no-session", `{}`)
	require.ErrorIs(t, err, ErrInviteTenantNotServed)

	u, err := f.users.GetUser(qrdbtenant.WithTenantID(context.Background(), tenant), inviteFixtureQRDBUserID)
	require.NoError(t, err)
	require.Equal(t, string(qrdbsdk.LifecyclePending), u.Lifecycle, "a refused enrolment activates nothing")

	// The invitation was not redeemed: it still resolves.
	_, err = f.svc.GetInvite(context.Background(), &xkmstransport.GetInviteRequest{TenantID: tenant, Token: token})
	require.NoError(t, err)
}
