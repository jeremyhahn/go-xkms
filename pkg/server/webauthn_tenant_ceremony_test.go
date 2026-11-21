// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// tenantCeremonyNode builds xkmsd over an embedded go-qrdb node that
// enforces authentication with enable_rbac on and WebAuthn enabled, and
// creates tenantID on it.
func tenantCeremonyNode(t *testing.T, tenantID string) *Server {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)

	openRegistration := true
	cfg := qrdbBarrierConfig(t)
	cfg.Barrier = config.BarrierConfig{Enabled: true, Strategy: "none"}
	cfg.Auth.EnableRBAC = true
	cfg.TLS.ServerCN = "localhost"
	cfg.WebAuthn = &config.WebAuthnConfig{
		Enabled:                 true,
		RPID:                    "localhost",
		RPDisplayName:           "Test",
		RPOrigins:               []string{"https://localhost"},
		AllowPublicRegistration: &openRegistration,
	}

	s, err := New(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Shutdown() })
	require.NotNil(t, s.qrdbNode, "the wiring under test is the embedded node")
	require.NotNil(t, s.webauthnService, "WebAuthn must be built on the node")

	_, err = s.xkmsService.CreateTenant(context.Background(), &transport.CreateTenantRequest{
		ID: tenantID, Name: "Tenant " + tenantID,
	})
	require.NoError(t, err)
	return s
}

// TestWebAuthnCeremony_NonSystemTenantOverRBACNode is the Codex P1 on #2296
// over a real authenticating node: a WebAuthn service whose user store is
// scoped to a non-system tenant registers a passkey and signs in with it.
// The production datastore runs the credential DAO as the system service
// principal and keeps an explicit tenant binding, so with RBAC on a tenant
// binding that leaks into the credential store is refused before the
// ceremony begins.
func TestWebAuthnCeremony_NonSystemTenantOverRBACNode(t *testing.T) {
	const tenantID = "acme-ceremony"
	s := tenantCeremonyNode(t, tenantID)

	ds := s.datastore.Load()
	require.NotNil(t, ds)
	svc, err := rest.BuildWebAuthnService(rest.WebAuthnServiceParams{
		Config:      s.webauthnConfig,
		QRDBClient:  ds.Client(),
		NodeUsers:   s.nodeUserSource(),
		DAOFactory:  ds.DAOFactory(),
		TenantID:    tenantID,
		TokenIssuer: s.tokenIssuer,
		Logger:      s.logger,
		AuditLogger: s.auditLogger,
	})
	require.NoError(t, err)

	rp := virtualwebauthn.RelyingParty{Name: "Test", ID: "localhost", Origin: "https://localhost"}
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	ctx := context.Background()
	const email = "tenant-passkey@example.com"

	creation, sessionID, err := svc.BeginRegistration(ctx, email, "Tenant Passkey")
	require.NoError(t, err, "begin registration in a non-system tenant")
	raw, err := json.Marshal(creation.Response)
	require.NoError(t, err)
	attOpts, err := virtualwebauthn.ParseAttestationOptions(string(raw))
	require.NoError(t, err)
	attestation := virtualwebauthn.CreateAttestationResponse(rp, virtualwebauthn.NewAuthenticator(), credential, *attOpts)
	parsedAtt, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(attestation))
	require.NoError(t, err)
	_, _, err = svc.FinishRegistration(ctx, sessionID, parsedAtt)
	require.NoError(t, err, "finish registration in a non-system tenant")

	assertion, sessionID, err := svc.BeginLoginForEmail(ctx, email)
	require.NoError(t, err, "begin login in a non-system tenant")
	raw, err = json.Marshal(assertion.Response)
	require.NoError(t, err)
	asOpts, err := virtualwebauthn.ParseAssertionOptions(string(raw))
	require.NoError(t, err)
	authenticator := virtualwebauthn.NewAuthenticator()
	authenticator.AddCredential(credential)
	resp := virtualwebauthn.CreateAssertionResponse(rp, authenticator, credential, *asOpts)
	parsedAs, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(resp))
	require.NoError(t, err)
	pair, _, err := svc.FinishLoginPair(ctx, sessionID, nil, parsedAs)
	require.NoError(t, err, "finish login in a non-system tenant")
	require.NotEmpty(t, pair.AccessToken)
}

// TestInviteRedemption_RPTenantOverRBACNode drives a full invitation
// enrolment (create, begin, finish) for an account in the relying party's
// own non-system tenant over an embedded node with enable_rbac on. The user
// operations run in the invite's tenant; the invitation itself lives in
// system storage, so its redemption must not carry the invite's tenant
// binding (Codex P1 on #2296, ruling 1029 B).
func TestInviteRedemption_RPTenantOverRBACNode(t *testing.T) {
	const tenantID = "acme-invite"
	s := tenantCeremonyNode(t, tenantID)

	ds := s.datastore.Load()
	require.NotNil(t, ds)
	svc, err := rest.BuildWebAuthnService(rest.WebAuthnServiceParams{
		Config:      s.webauthnConfig,
		QRDBClient:  ds.Client(),
		NodeUsers:   s.nodeUserSource(),
		DAOFactory:  ds.DAOFactory(),
		TenantID:    tenantID,
		TokenIssuer: s.tokenIssuer,
		Logger:      s.logger,
		AuditLogger: s.auditLogger,
	})
	require.NoError(t, err)
	s.xkmsService.SetWebAuthn(svc)

	// The administrator creates the account (an authenticated call); the
	// enrolment that follows is the invitee's, on the public routes.
	adminRole, err := s.qrdbNode.Services().Role.GetRoleByName(
		qrdbsdk.ContextWithTenant(context.Background(), tenantID), tenantID, qrdbsdk.RoleNameAdmin)
	require.NoError(t, err)
	adminCtx := qrdbsdk.ContextWithTenant(auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "admin@" + tenantID, TenantID: tenantID, Roles: []string{adminRole.ID},
	}), tenantID)
	ctx := context.Background()
	created, err := s.xkmsService.CreateUser(adminCtx, &transport.CreateUserRequest{
		Username: "invitee@example.com", Email: "invitee@example.com",
		DisplayName: "Invitee", TenantID: tenantID,
	})
	require.NoError(t, err, "create the invited account")
	require.NotNil(t, created.Invite)
	token := created.Invite.Token

	begin, err := s.xkmsService.BeginInviteRegistration(ctx, &transport.BeginInviteRegistrationRequest{TenantID: tenantID, Token: token})
	require.NoError(t, err, "begin invite enrolment")
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
		TenantID: tenantID, Token: token, SessionID: begin.SessionID, AttestationJSON: attestation,
	})
	require.NoError(t, err, "finish invite enrolment, redeeming the invitation")

	_, err = s.xkmsService.GetInvite(ctx, &transport.GetInviteRequest{TenantID: tenantID, Token: token})
	require.ErrorIs(t, err, xkms.ErrInviteUnusable, "the invitation is spent")
}
