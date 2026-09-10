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

//go:build integration && fido2

package fido2

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	waprotocol "github.com/go-webauthn/webauthn/protocol"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/fido2"
	"github.com/stretchr/testify/require"
)

// runAuthenticationCeremony drives the full WebAuthn authentication (login)
// ceremony against the real server-side XKMSService using the supplied FIDO2
// handler. It assumes a credential for username has already been registered on
// the SAME authenticator (same virtual device / same physical key), because the
// authenticator must hold the credential's private key to produce a valid
// assertion signature.
//
// Flow (symmetric to runRegistrationCeremony):
//  1. svcXKMS.BeginAuthentication -> opaque session ID + CredentialAssertion JSON.
//  2. Parse the options JSON to recover challenge, RPID, and the allow-list of
//     credential IDs the server registered for the user.
//  3. handler.AuthenticateWebAuthn drives the CTAP2 authenticator to emit a real
//     assertion over that exact challenge/origin/RP, signed with the credential's
//     private key.
//  4. svcXKMS.FinishAuthentication verifies the assertion signature server-side
//     and issues a JWT on success.
//  5. Assert success + a non-empty token.
func runAuthenticationCeremony(t *testing.T, surface *ceremonySurface, handler *fido2.FIDO2Handler, username string) {
	t.Helper()

	ctx := context.Background()

	// Step 1: Begin authentication through the XKMSService transport surface.
	beginResp, err := surface.xkmsSvc.BeginAuthentication(ctx, &transport.BeginAuthenticationRequest{
		Email: username,
	})
	require.NoError(t, err, "BeginAuthentication")
	require.NotEmpty(t, beginResp.SessionID, "session ID")
	require.NotEmpty(t, beginResp.OptionsJSON, "options JSON")

	// Step 2: Parse the options JSON (a CredentialAssertion) to recover the
	// challenge, relying-party ID, and the allow-list of registered credentials.
	var options waprotocol.CredentialAssertion
	require.NoError(t, json.Unmarshal([]byte(beginResp.OptionsJSON), &options), "parse CredentialAssertion options")

	challenge := []byte(options.Response.Challenge)
	require.NotEmpty(t, challenge, "server challenge")

	rpID := options.Response.RelyingPartyID
	require.Equal(t, surface.rpID, rpID, "RPID from options must match configured RP")

	// Origin MUST match the service's configured RPOrigins. The service is
	// configured with origin "https://" + rpID, so derive it identically here.
	origin := "https://" + rpID

	// The server supplies the allow-list of credential IDs registered for the
	// user; the authenticator selects the matching credential to sign with.
	allowList := make([][]byte, 0, len(options.Response.AllowedCredentials))
	for _, cred := range options.Response.AllowedCredentials {
		allowList = append(allowList, cred.CredentialID)
	}
	require.NotEmpty(t, allowList, "server must return at least one allowed credential")

	// Step 3: Drive the REAL CTAP2 authenticator to produce an assertion over the
	// server-issued challenge, signed with the registered credential's private key.
	t.Logf("Driving authenticator authentication for user %q (rpID=%q origin=%q, %d allowed credentials)",
		username, rpID, origin, len(allowList))
	assertion, err := handler.AuthenticateWebAuthn(fido2.WebAuthnAuthenticationOptions{
		Challenge:               challenge,
		Origin:                  origin,
		RPID:                    rpID,
		AllowCredentialIDs:      allowList,
		RequireUserVerification: false,
		Timeout:                 30 * time.Second,
	})
	require.NoError(t, err, "AuthenticateWebAuthn (authenticator assertion)")
	require.NotEmpty(t, assertion.CredentialID, "asserted credential ID")
	require.NotEmpty(t, assertion.PublicKeyCredentialJSON, "PublicKeyCredential JSON")

	// Step 4: Finish authentication. This is the load-bearing assertion: the
	// server re-parses the PublicKeyCredential, verifies the assertion signature
	// over the clientDataHash + authenticatorData against the registered public
	// key, checks RP/origin/challenge, and issues a JWT. Any signature, allow-list,
	// or RP/origin mismatch fails here.
	finishResp, err := surface.xkmsSvc.FinishAuthentication(ctx, &transport.FinishAuthenticationRequest{
		SessionID:     beginResp.SessionID,
		Email:         username,
		AssertionJSON: string(assertion.PublicKeyCredentialJSON),
	})
	require.NoError(t, err, "FinishAuthentication (server-side assertion verification)")
	require.True(t, finishResp.Success, "authentication reported success")
	require.NotEmpty(t, finishResp.Token, "JWT token issued on success")

	t.Logf("Authentication ceremony succeeded: token issued for %q", username)
}

// TestFIDO2Authentication_VirtualAuthenticator_EndToEnd proves the full WebAuthn
// authentication (login) flow works end-to-end against the REAL server-side
// XKMSService ceremony, driven by xkey's in-process virtual CTAP2 authenticator.
//
// It first registers a credential (so the server has a public key to verify
// against), then authenticates with that SAME authenticator. The virtual device
// persists the credential's private key in-memory, so the same handler must be
// reused across both ceremonies for the assertion signature to verify.
//
// This is the canonical CI proof that a real authenticator's assertion is
// accepted (signature-verified) by the server, and that a JWT is issued. No
// hardware, no browser.
func TestFIDO2Authentication_VirtualAuthenticator_EndToEnd(t *testing.T) {
	cfg := LoadFIDO2TestConfig()

	// One virtual authenticator instance, reused across register + authenticate.
	handler := cfg.CreateVirtualHandler(t)
	require.NotNil(t, handler, "virtual FIDO2 handler")
	defer CleanupCredential(t, handler)

	surface := newCeremonySurface(t)
	username := GenerateUniqueUsername("fido2-auth")

	// Register a credential first so the server has a public key to challenge.
	runRegistrationCeremony(t, surface, handler, username)

	// Authenticate with the SAME authenticator; the private key lives in the
	// virtual device, so the assertion signature verifies against the registered
	// public key.
	runAuthenticationCeremony(t, surface, handler, username)
}
