// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package grpc

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	waprotocol "github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/webauthntest"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

const (
	grpcLoginSystemTenant = "system"
	grpcLoginTenantB      = "tenant-b"
	grpcLoginEmail        = "member@example.com"
)

// tenantTokenGenerator mints a token naming the tenant of the relying party
// that issued it, so a test can tell which tenant signed the account in.
type tenantTokenGenerator struct{ tenant string }

func (g tenantTokenGenerator) GenerateToken(_ context.Context, _ webauthn.User) (string, error) {
	return "tenant=" + g.tenant, nil
}

type grpcTenantLoginFixture struct {
	svc           *Service
	authenticator *webauthn.MockAuthenticator
	user          webauthn.User
}

// newGRPCTenantLoginFixture builds the gRPC service over an XKMSService whose
// passkey ceremonies route through a TenantRouter (go-xkms#2319), and enrols
// one account in tenant B only.
func newGRPCTenantLoginFixture(t *testing.T) *grpcTenantLoginFixture {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"mem": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "mem",
	}))
	xsvc, err := xkms.Get()
	require.NoError(t, err)

	open := true
	cfg := &webauthn.Config{
		RPID:                    "example.com",
		RPDisplayName:           "Example",
		RPOrigins:               []string{standingOrigin},
		AllowPublicRegistration: &open,
	}
	newRP := func(tenant string) (*webauthn.Service, error) {
		stores := webauthntest.NewStores(t)
		return webauthn.NewService(webauthn.ServiceParams{
			TenantID:        tenant,
			Config:          cfg,
			UserStore:       stores.Users,
			SessionStore:    webauthn.NewMemorySessionStore(),
			CredentialStore: stores.Credentials,
			JWTGenerator:    tenantTokenGenerator{tenant: tenant},
		})
	}
	system, err := newRP(grpcLoginSystemTenant)
	require.NoError(t, err)
	router, err := webauthn.NewTenantRouter(webauthn.TenantRouterParams{
		SystemTenant: grpcLoginSystemTenant,
		System:       system,
		TenantExists: func(_ context.Context, tenantID string) (bool, error) {
			return tenantID == grpcLoginTenantB, nil
		},
		Build: newRP,
	})
	require.NoError(t, err)
	xsvc.SetWebAuthn(system)
	xsvc.SetWebAuthnTenants(router)

	ctx := context.Background()
	tenantB, err := router.For(ctx, grpcLoginTenantB)
	require.NoError(t, err)
	options, sessionID, err := tenantB.BeginRegistration(ctx, grpcLoginEmail, grpcLoginEmail)
	require.NoError(t, err)
	user, err := tenantB.GetUserByEmail(ctx, grpcLoginEmail)
	require.NoError(t, err)
	authenticator, err := webauthn.NewMockAuthenticator("example.com")
	require.NoError(t, err)
	attestation, err := authenticator.CreateAttestationObject(options.Response.Challenge, user.WebAuthnID(), standingOrigin)
	require.NoError(t, err)
	attestationJSON, err := json.Marshal(attestation.Raw)
	require.NoError(t, err)
	parsed, err := waprotocol.ParseCredentialCreationResponseBody(strings.NewReader(string(attestationJSON)))
	require.NoError(t, err)
	_, _, err = tenantB.FinishRegistration(ctx, sessionID, parsed)
	require.NoError(t, err)

	return &grpcTenantLoginFixture{svc: NewService(nil, nil, xsvc), authenticator: authenticator, user: user}
}

// login runs the gRPC ceremony for the fixture's account under tenant,
// signing with signer.
func (f *grpcTenantLoginFixture) login(t *testing.T, tenant string, signer *webauthn.MockAuthenticator) (*pb.FinishAuthenticationResponse, error) {
	t.Helper()
	ctx := context.Background()
	begin, err := f.svc.BeginAuthentication(ctx, &pb.BeginAuthenticationRequest{Email: grpcLoginEmail, TenantId: tenant})
	require.NoError(t, err)
	var options waprotocol.CredentialAssertion
	require.NoError(t, json.Unmarshal([]byte(begin.OptionsJson), &options))
	assertion, err := signer.CreateAssertionResponse(options.Response.Challenge, f.user.WebAuthnID(), standingOrigin)
	require.NoError(t, err)
	assertionJSON, err := json.Marshal(assertion.Raw)
	require.NoError(t, err)
	return f.svc.FinishAuthentication(ctx, &pb.FinishAuthenticationRequest{
		SessionId:     begin.SessionId,
		Email:         grpcLoginEmail,
		AssertionJson: string(assertionJSON),
		TenantId:      tenant,
	})
}

// TestGRPCLogin_TenantIDSignsInToThatTenant proves the gRPC wire carries the
// explicit login tenant (go-xkms#2319): a tenant-B account signs in with
// tenant_id tenant-b and its token is minted by tenant B.
func TestGRPCLogin_TenantIDSignsInToThatTenant(t *testing.T) {
	f := newGRPCTenantLoginFixture(t)

	resp, err := f.login(t, grpcLoginTenantB, f.authenticator)
	require.NoError(t, err)
	assert.True(t, resp.GetSuccess())
	assert.Equal(t, "tenant="+grpcLoginTenantB, resp.GetToken())
}

// TestGRPCLogin_OtherTenantFailsLikeAWrongAssertion proves the same account
// under the system tenant fails exactly as a wrong assertion does in its own
// tenant, so the login does not reveal that the account exists elsewhere.
func TestGRPCLogin_OtherTenantFailsLikeAWrongAssertion(t *testing.T) {
	f := newGRPCTenantLoginFixture(t)

	forger, err := webauthn.NewMockAuthenticator("example.com")
	require.NoError(t, err)
	_, wrongErr := f.login(t, grpcLoginTenantB, forger)
	require.Error(t, wrongErr)

	_, crossErr := f.login(t, grpcLoginSystemTenant, f.authenticator)
	require.Error(t, crossErr)

	assert.Equal(t, codes.Unauthenticated, status.Code(wrongErr))
	assert.Equal(t, status.Code(wrongErr), status.Code(crossErr))
	assert.Equal(t, status.Convert(wrongErr).Message(), status.Convert(crossErr).Message())
}
