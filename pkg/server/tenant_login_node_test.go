// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// publicKeyOptions returns the inner "publicKey" member of a WebAuthn
// options document (CredentialCreation / CredentialAssertion), which is
// what virtualwebauthn parses.
func publicKeyOptions(t *testing.T, optionsJSON string) string {
	t.Helper()
	var wrapped map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(optionsJSON), &wrapped))
	inner, ok := wrapped["publicKey"]
	require.True(t, ok, "options carry a publicKey member: %s", optionsJSON)
	return string(inner)
}

// tenantLoginNode is a running embedded RBAC node with tenants tenant-b and
// tenant-c and a pending tenant-b user "bea" holding an invitation.
type tenantLoginNode struct {
	server      *Server
	svc         *xkms.XKMSService
	inviteToken string
}

const tenantLoginEmail = "bea@example.com"

// newTenantLoginNode starts the embedded node of the go-xkms#2319
// acceptance tests and mints the tenant-b invitation.
func newTenantLoginNode(t *testing.T) *tenantLoginNode {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)

	cfg := qrdbBarrierConfig(t)
	cfg.Barrier = config.BarrierConfig{Enabled: true, Strategy: "none"}
	cfg.Auth.EnableRBAC = true
	cfg.WebAuthn = &config.WebAuthnConfig{
		Enabled:       true,
		RPID:          "localhost",
		RPDisplayName: "Test",
		RPOrigins:     []string{"https://localhost"},
	}

	server, err := New(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Shutdown() })
	require.True(t, server.nodeSealEnabled, "node-seal flip must engage so tenant lookups are real")

	svc := server.XKMSService()
	require.NotNil(t, svc)

	// Tenant and user creation need a system administrator under RBAC.
	ctx := context.Background()
	adminCtx := qrdbsdk.ContextWithTenant(qrdbsdk.WithIdentity(ctx, &qrdbsdk.Identity{
		Subject:  "e2e-operator",
		TenantID: qrdbsdk.SystemTenantID,
		Roles:    []string{qrdbsdk.SystemRoleID(qrdbsdk.SystemTenantID, qrdbsdk.RoleNameAdmin)},
	}), qrdbsdk.SystemTenantID)
	for _, id := range []string{"tenant-b", "tenant-c"} {
		_, err := svc.CreateTenant(adminCtx, &transport.CreateTenantRequest{ID: id, Name: id})
		require.NoError(t, err, "CreateTenant %s", id)
	}

	// A system caller may not create users inside another tenant, so the
	// invitation is minted by tenant-b's own administrator.
	tenantAdminCtx := qrdbsdk.ContextWithTenant(qrdbsdk.WithIdentity(ctx, &qrdbsdk.Identity{
		Subject:  "tenant-b-operator",
		TenantID: "tenant-b",
		Roles:    []string{qrdbsdk.SystemRoleID("tenant-b", qrdbsdk.RoleNameAdmin)},
	}), "tenant-b")
	created, err := svc.CreateUser(tenantAdminCtx, &transport.CreateUserRequest{
		Username:    "bea",
		Email:       tenantLoginEmail,
		DisplayName: "Bea",
		TenantID:    "tenant-b",
	})
	require.NoError(t, err)
	require.NotNil(t, created.Invite, "a tenant user is created pending with an invitation")
	return &tenantLoginNode{server: server, svc: svc, inviteToken: created.Invite.Token}
}

// TestTenantLogin_EmbeddedNodeCeremonyLookups pins the ceremony identity
// (Codex round 2 on #2387): the unauthenticated invite verbs read the
// tenant-b account on an RBAC node, while an admin verb on the same plain
// context stays refused, so the ceremony identity never reaches it.
func TestTenantLogin_EmbeddedNodeCeremonyLookups(t *testing.T) {
	node := newTenantLoginNode(t)
	ctx := context.Background()

	invite, err := node.svc.GetInvite(ctx, &transport.GetInviteRequest{TenantID: "tenant-b", Token: node.inviteToken})
	require.NoError(t, err)
	require.Equal(t, tenantLoginEmail, invite.Email)

	begin, err := node.svc.BeginInviteRegistration(ctx, &transport.BeginInviteRegistrationRequest{
		TenantID: "tenant-b",
		Token:    node.inviteToken,
	})
	require.NoError(t, err)
	require.NotEmpty(t, begin.SessionID)

	_, err = node.svc.GetUser(ctx, "bea")
	require.Error(t, err, "an admin verb on an unauthenticated context must stay refused")
}

// TestTenantLogin_EmbeddedNodeInvitation is the go-xkms#2319 acceptance test
// over a real embedded qrdb node with RBAC on: a tenant-b invitation enrols
// through tenant-b's relying party, an email login naming tenant-b (as
// xkmsctl and xkey send it) mints a tenant-b token, and the same login
// naming another tenant gets decoy options whose finish fails.
func TestTenantLogin_EmbeddedNodeInvitation(t *testing.T) {
	node := newTenantLoginNode(t)
	server, svc, inviteToken := node.server, node.svc, node.inviteToken
	const email = tenantLoginEmail
	// The login and invite verbs are unauthenticated and run on a plain context.
	ctx := context.Background()

	rp := virtualwebauthn.RelyingParty{Name: "Test", ID: "localhost", Origin: "https://localhost"}
	authn := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	// Enrol through the invitation verbs, naming tenant-b.
	begin, err := svc.BeginInviteRegistration(ctx, &transport.BeginInviteRegistrationRequest{
		TenantID: "tenant-b",
		Token:    inviteToken,
	})
	require.NoError(t, err)
	attOpts, err := virtualwebauthn.ParseAttestationOptions(publicKeyOptions(t, begin.OptionsJSON))
	require.NoError(t, err)
	attestation := virtualwebauthn.CreateAttestationResponse(rp, authn, cred, *attOpts)
	finished, err := svc.FinishInviteRegistration(ctx, &transport.FinishInviteRegistrationRequest{
		TenantID:        "tenant-b",
		Token:           inviteToken,
		SessionID:       begin.SessionID,
		AttestationJSON: attestation,
	})
	require.NoError(t, err)
	require.NotZero(t, finished.UserID)
	authn.AddCredential(cred)
	authn.Options.UserHandle = []byte(attOpts.UserID)

	login := func(tenantID string) (*transport.FinishAuthenticationResponse, error) {
		t.Helper()
		b, err := svc.BeginAuthentication(ctx, &transport.BeginAuthenticationRequest{Email: email, TenantID: tenantID})
		require.NoError(t, err, "begin naming %q answers with options, never an error", tenantID)
		asOpts, err := virtualwebauthn.ParseAssertionOptions(publicKeyOptions(t, b.OptionsJSON))
		require.NoError(t, err)
		assertion := virtualwebauthn.CreateAssertionResponse(rp, authn, cred, *asOpts)
		return svc.FinishAuthentication(ctx, &transport.FinishAuthenticationRequest{
			SessionID:     b.SessionID,
			Email:         email,
			AssertionJSON: assertion,
			TenantID:      tenantID,
		})
	}

	// (a) The login naming tenant-b mints a tenant-b token. Token is the
	// bare access JWT the relying party's token adapter mints.
	ok, err := login("tenant-b")
	require.NoError(t, err)
	require.True(t, ok.Success)
	require.NotEmpty(t, ok.Token)

	issuer := server.tokenIssuer
	require.NotNil(t, issuer)
	jwtAuth, err := auth.NewJWTAuthenticator(&auth.JWTConfig{
		PublicKey:  issuer.PublicKey(),
		Issuer:     issuer.IssuerName(),
		Audience:   issuer.Audience(),
		HeaderName: "Authorization",
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+ok.Token)
	id, err := jwtAuth.AuthenticateHTTP(req)
	require.NoError(t, err)
	require.Equal(t, "tenant-b", id.TenantID)

	// (b) The same login naming another tenant, or the system tenant, gets
	// decoy options and a finish that fails like a wrong assertion.
	for _, other := range []string{"tenant-c", "system"} {
		resp, err := login(other)
		require.Error(t, err, "login naming %q must be refused", other)
		if resp != nil {
			require.False(t, resp.Success)
			require.Empty(t, strings.TrimSpace(resp.Token))
		}
	}
}
