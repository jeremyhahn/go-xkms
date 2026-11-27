// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestInviteRedemption_CrossTenantSameEmail is issue #2335: two tenants on
// one RBAC node each invite an account with the same username and email. An
// invitation issued in tenant A resolves only in tenant A, never through
// tenant B, and redeeming it activates only tenant A's account: tenant B's
// same-named account stays pending and its own invitation stays usable.
func TestInviteRedemption_CrossTenantSameEmail(t *testing.T) {
	const (
		tenantA = "acme-invite-a"
		tenantB = "acme-invite-b"
		email   = "alice-invite@example.com"
	)
	s := tenantCeremonyNode(t, tenantA)
	ctx := context.Background()
	_, err := s.xkmsService.CreateTenant(ctx, &transport.CreateTenantRequest{ID: tenantB, Name: "Tenant " + tenantB})
	require.NoError(t, err)
	s.xkmsService.SetWebAuthn(crossTenantCeremonyService(t, s, tenantA))

	invite := func(tenantID string) (string, uint64) {
		adminRole, err := s.qrdbNode.Services().Role.GetRoleByName(
			qrdbsdk.ContextWithTenant(ctx, tenantID), tenantID, qrdbsdk.RoleNameAdmin)
		require.NoError(t, err)
		adminCtx := qrdbsdk.ContextWithTenant(auth.WithIdentity(ctx, &auth.Identity{
			Subject: "admin@" + tenantID, TenantID: tenantID, Roles: []string{adminRole.ID},
		}), tenantID)
		created, err := s.xkmsService.CreateUser(adminCtx, &transport.CreateUserRequest{
			Username: email, Email: email, DisplayName: "Alice", TenantID: tenantID,
		})
		require.NoError(t, err, "invite alice in %s", tenantID)
		require.NotNil(t, created.Invite)
		users := auth.NewNodeUserClient(s.nodeUserSource())
		u, err := users.GetUserByEmail(ctx, tenantID, email)
		require.NoError(t, err)
		require.Equal(t, tenantID, u.TenantID)
		return created.Invite.Token, u.ID
	}
	tokenA, _ := invite(tenantA)
	tokenB, _ := invite(tenantB)

	// Each invitation resolves in its own tenant only.
	meta, err := s.xkmsService.GetInvite(ctx, &transport.GetInviteRequest{TenantID: tenantA, Token: tokenA})
	require.NoError(t, err)
	require.Equal(t, email, meta.Email)
	_, err = s.xkmsService.GetInvite(ctx, &transport.GetInviteRequest{TenantID: tenantB, Token: tokenA})
	require.Error(t, err, "tenant A's invitation must not resolve through tenant B")
	_, err = s.xkmsService.GetInvite(ctx, &transport.GetInviteRequest{TenantID: tenantA, Token: tokenB})
	require.Error(t, err, "tenant B's invitation must not resolve through tenant A")
	_, err = s.xkmsService.BeginInviteRegistration(ctx, &transport.BeginInviteRegistrationRequest{TenantID: tenantA, Token: tokenB})
	require.Error(t, err, "tenant B's invitation must not begin an enrolment in tenant A")

	// Redeem tenant A's invitation.
	begin, err := s.xkmsService.BeginInviteRegistration(ctx, &transport.BeginInviteRegistrationRequest{TenantID: tenantA, Token: tokenA})
	require.NoError(t, err)
	var creation protocol.CredentialCreation
	require.NoError(t, json.Unmarshal([]byte(begin.OptionsJSON), &creation))
	raw, err := json.Marshal(creation.Response)
	require.NoError(t, err)
	attOpts, err := virtualwebauthn.ParseAttestationOptions(string(raw))
	require.NoError(t, err)
	rp := virtualwebauthn.RelyingParty{Name: "Test", ID: "localhost", Origin: "https://localhost"}
	attestation := virtualwebauthn.CreateAttestationResponse(rp, virtualwebauthn.NewAuthenticator(),
		virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2), *attOpts)
	_, err = s.xkmsService.FinishInviteRegistration(ctx, &transport.FinishInviteRegistrationRequest{
		TenantID: tenantA, Token: tokenA, SessionID: begin.SessionID, AttestationJSON: attestation,
	})
	require.NoError(t, err, "redeem tenant A's invitation")

	users := auth.NewNodeUserClient(s.nodeUserSource())
	aliceA, err := users.GetUserByEmail(ctx, tenantA, email)
	require.NoError(t, err)
	require.Equal(t, tenantA, aliceA.TenantID)
	require.EqualValues(t, qrdbsdk.LifecycleActive, aliceA.Lifecycle, "tenant A's alice is activated")

	aliceB, err := users.GetUserByEmail(ctx, tenantB, email)
	require.NoError(t, err)
	require.Equal(t, tenantB, aliceB.TenantID)
	require.NotEqualValues(t, qrdbsdk.LifecycleActive, aliceB.Lifecycle,
		"redeeming tenant A's invitation must not activate tenant B's alice")

	_, err = s.xkmsService.GetInvite(ctx, &transport.GetInviteRequest{TenantID: tenantA, Token: tokenA})
	require.ErrorIs(t, err, xkms.ErrInviteUnusable, "tenant A's invitation is spent")
	meta, err = s.xkmsService.GetInvite(ctx, &transport.GetInviteRequest{TenantID: tenantB, Token: tokenB})
	require.NoError(t, err, "tenant B's invitation stays usable")
	require.Equal(t, email, meta.Email)
}
