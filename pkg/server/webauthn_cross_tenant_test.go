// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	qrdbtenant "github.com/jeremyhahn/go-qrdb/pkg/tenant"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	xkmswebauthn "github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// crossTenantCeremonyService builds the tenant-scoped WebAuthn service as
// xkmsd does for tenantID on node s.
func crossTenantCeremonyService(t *testing.T, s *Server, tenantID string) *xkmswebauthn.Service {
	t.Helper()
	ds := s.datastore.Load()
	require.NotNil(t, ds)
	svc, err := rest.BuildWebAuthnService(rest.WebAuthnServiceParams{
		Config:      s.webauthnConfig,
		QRDBClient:  ds.Client(),
		NodeUsers:   s.nodeUserSource(),
		DAOFactory:  ds.DAOFactory(),
		TenantID:    tenantID,
		CallContext: s.qrdbNode.ServiceContext,
		TokenIssuer: s.tokenIssuer,
		Logger:      s.logger,
		AuditLogger: s.auditLogger,
	})
	require.NoError(t, err)
	return svc
}

// crossTenantAssert runs a login for email on svc and answers it with
// credential; it returns the FinishLoginPair result.
func crossTenantAssert(t *testing.T, svc *xkmswebauthn.Service, rp virtualwebauthn.RelyingParty, credential virtualwebauthn.Credential, email string) (*xkmswebauthn.TokenPair, xkmswebauthn.User, error) {
	t.Helper()
	ctx := context.Background()
	assertion, sessionID, err := svc.BeginLoginForEmail(ctx, email)
	if err != nil {
		return nil, nil, err
	}
	raw, err := json.Marshal(assertion.Response)
	require.NoError(t, err)
	asOpts, err := virtualwebauthn.ParseAssertionOptions(string(raw))
	require.NoError(t, err)
	authenticator := virtualwebauthn.NewAuthenticator()
	authenticator.AddCredential(credential)
	resp := virtualwebauthn.CreateAssertionResponse(rp, authenticator, credential, *asOpts)
	parsedAs, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(resp))
	require.NoError(t, err)
	return svc.FinishLoginPair(ctx, sessionID, nil, parsedAs)
}

// TestWebAuthnCeremony_CrossTenantSameUsernameAndEmail is issue #2335: two
// tenants on one RBAC node each hold an account "alice" with the same
// username and email. A passkey registered in tenant A binds only tenant A's
// account, a login in tenant A resolves tenant A's account, and A's
// credential never authenticates tenant B's "alice".
func TestWebAuthnCeremony_CrossTenantSameUsernameAndEmail(t *testing.T) {
	const (
		tenantA = "acme-cross-a"
		tenantB = "acme-cross-b"
		email   = "alice-cross@example.com"
	)
	s := tenantCeremonyNode(t, tenantA)
	ctx := context.Background()
	_, err := s.xkmsService.CreateTenant(ctx, &transport.CreateTenantRequest{ID: tenantB, Name: "Tenant " + tenantB})
	require.NoError(t, err)

	svcA := crossTenantCeremonyService(t, s, tenantA)
	svcB := crossTenantCeremonyService(t, s, tenantB)
	users := auth.NewNodeUserClient(s.nodeUserSource())

	create := func(tenantID string) *qrdbtransport.User {
		u, err := users.CreateUser(ctx, &qrdbtransport.CreateUserRequest{
			TenantID: tenantID, Username: email, Email: email, Name: "Alice", Pending: true,
		})
		require.NoError(t, err, "create alice in %s", tenantID)
		require.Equal(t, tenantID, u.TenantID)
		return u
	}
	aliceA := create(tenantA)
	aliceB := create(tenantB)

	rp := virtualwebauthn.RelyingParty{Name: "Test", ID: "localhost", Origin: "https://localhost"}
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	handleA := xkmswebauthn.HandleFromUserID(aliceA.ID)

	creation, sessionID, err := svcA.BeginInviteRegistration(ctx, handleA)
	require.NoError(t, err)
	raw, err := json.Marshal(creation.Response)
	require.NoError(t, err)
	attOpts, err := virtualwebauthn.ParseAttestationOptions(string(raw))
	require.NoError(t, err)
	attestation := virtualwebauthn.CreateAttestationResponse(rp, virtualwebauthn.NewAuthenticator(), credential, *attOpts)
	parsedAtt, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(attestation))
	require.NoError(t, err)
	_, err = svcA.FinishInviteRegistration(ctx, sessionID, handleA, parsedAtt)
	require.NoError(t, err)

	for _, u := range []*qrdbtransport.User{aliceA, aliceB} {
		_, err = users.UpdateUser(qrdbtenant.WithTenantID(ctx, u.TenantID), &qrdbtransport.UpdateUserRequest{ID: u.ID, Lifecycle: string(qrdbsdk.LifecycleActive)})
		require.NoError(t, err, "activate alice in %s", u.TenantID)
	}

	// The registration bound only tenant A's account: tenant B's alice
	// holds no credential.
	gotB, err := users.GetUserByUsername(ctx, tenantB, email)
	require.NoError(t, err)
	require.Equal(t, aliceB.ID, gotB.ID)
	require.Equal(t, tenantB, gotB.TenantID)

	// A login in tenant A resolves tenant A's alice.
	pair, user, err := crossTenantAssert(t, svcA, rp, credential, email)
	require.NoError(t, err, "login in tenant A")
	require.NotEmpty(t, pair.AccessToken)
	require.True(t, bytes.Equal(handleA, user.WebAuthnID()), "tenant A's login must resolve tenant A's account")

	// Tenant A's credential never authenticates tenant B's alice.
	pairB, userB, err := crossTenantAssert(t, svcB, rp, credential, email)
	require.Error(t, err, "tenant A's passkey must not authenticate tenant B's alice")
	require.Nil(t, pairB)
	require.Nil(t, userB)
}
