// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package xkms

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/require"

	xkmstransport "github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// assertWith signs the request options of a login ceremony with credential
// held by authenticator and parses the result as the server would.
func (f *inviteFixture) assertWith(t *testing.T, assertion *protocol.CredentialAssertion, authenticator virtualwebauthn.Authenticator, credential virtualwebauthn.Credential) *protocol.ParsedCredentialAssertionData {
	t.Helper()
	raw, err := json.Marshal(assertion.Response)
	require.NoError(t, err)
	opts, err := virtualwebauthn.ParseAssertionOptions(string(raw))
	require.NoError(t, err)
	authenticator.AddCredential(credential)
	resp := virtualwebauthn.CreateAssertionResponse(f.rp, authenticator, credential, *opts)
	parsed, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(resp))
	require.NoError(t, err)
	return parsed
}

// TestLogin_NonSystemTenantAccount is ruling 1019 on #2296: an account
// enrolled through an invite in tenant B signs in by email, by user handle
// and discoverably, and every minted token carries tenant B. The login
// routes carry no tenant, so the account's tenant must come from its
// credential or user handle, not from the configured system tenant.
func TestLogin_NonSystemTenantAccount(t *testing.T) {
	const tenant = "acme"
	f := newInviteFixtureIn(t, tenant)
	token := f.mintInvite(t)

	begin, err := f.beginRegistration(tenant, token)
	require.NoError(t, err)
	credential := newInviteEC2Credential(t)
	attestation := f.attestInvite(t, begin.OptionsJSON, credential)
	_, err = f.finishRegistration(tenant, token, begin.SessionID, attestation)
	require.NoError(t, err)

	ctx := context.Background()
	handle := webauthn.HandleFromUserID(inviteFixtureQRDBUserID)
	wantToken := "tenant=" + tenant

	t.Run("email", func(t *testing.T) {
		beginAuth, err := f.svc.BeginAuthentication(ctx, &xkmstransport.BeginAuthenticationRequest{Email: inviteFixtureEmail})
		require.NoError(t, err)
		var assertion protocol.CredentialAssertion
		require.NoError(t, json.Unmarshal([]byte(beginAuth.OptionsJSON), &assertion))
		require.NotEmpty(t, assertion.Response.AllowedCredentials, "email login must find the tenant-B account's passkey")
		raw, err := json.Marshal(assertion.Response)
		require.NoError(t, err)
		opts, err := virtualwebauthn.ParseAssertionOptions(string(raw))
		require.NoError(t, err)
		authenticator := virtualwebauthn.NewAuthenticator()
		authenticator.AddCredential(credential)
		resp := virtualwebauthn.CreateAssertionResponse(f.rp, authenticator, credential, *opts)
		finish, err := f.svc.FinishAuthentication(ctx, &xkmstransport.FinishAuthenticationRequest{
			SessionID: beginAuth.SessionID, Email: inviteFixtureEmail, AssertionJSON: resp,
		})
		require.NoError(t, err)
		require.True(t, finish.Success)
		require.Equal(t, wantToken, finish.Token)
	})

	t.Run("handle", func(t *testing.T) {
		assertion, sessionID, err := f.svc.webauthnService.BeginLoginForHandle(ctx, handle)
		require.NoError(t, err)
		parsed := f.assertWith(t, assertion, virtualwebauthn.NewAuthenticator(), credential)
		tok, _, err := f.svc.webauthnService.FinishLogin(ctx, sessionID, handle, parsed)
		require.NoError(t, err)
		require.Equal(t, wantToken, tok)
	})

	t.Run("discoverable", func(t *testing.T) {
		assertion, sessionID, err := f.svc.webauthnService.BeginLogin(ctx, nil)
		require.NoError(t, err)
		authenticator := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: handle})
		parsed := f.assertWith(t, assertion, authenticator, credential)
		tok, _, err := f.svc.webauthnService.FinishLogin(ctx, sessionID, nil, parsed)
		require.NoError(t, err)
		require.Equal(t, wantToken, tok)
	})
}
