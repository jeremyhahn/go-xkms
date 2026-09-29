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

package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	waprotocol "github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	pkgwebauthn "github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

const finishUniformOrigin = "https://localhost"

// enrollSDKAccount registers a real passkey for email directly against wa
// (bypassing the HTTP layer, like the browser fixtures do) and returns the
// authenticator holding it plus the account's WebAuthn user ID.
func enrollSDKAccount(t *testing.T, wa *pkgwebauthn.Service, email string) (*pkgwebauthn.MockAuthenticator, []byte) {
	t.Helper()
	ctx := context.Background()

	options, sessionID, err := wa.BeginRegistration(ctx, email, email)
	require.NoError(t, err)
	user, err := wa.GetUserByEmail(ctx, email)
	require.NoError(t, err)

	authenticator, err := pkgwebauthn.NewMockAuthenticator("localhost")
	require.NoError(t, err)
	attestation, err := authenticator.CreateAttestationObject(options.Response.Challenge, user.WebAuthnID(), finishUniformOrigin)
	require.NoError(t, err)
	raw, err := json.Marshal(attestation.Raw)
	require.NoError(t, err)
	parsed, err := waprotocol.ParseCredentialCreationResponseBody(bytes.NewReader(raw))
	require.NoError(t, err)
	_, _, err = wa.FinishRegistration(ctx, sessionID, parsed)
	require.NoError(t, err)

	return authenticator, user.WebAuthnID()
}

// sdkFinishAuthentication posts the SDK authentication/finish request and
// returns the recorded response.
func sdkFinishAuthentication(t *testing.T, r http.Handler, req transport.FinishAuthenticationRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/webauthn/sdk/authentication/finish", bytes.NewReader(body)))
	return rr
}

// TestHandleSDKFinishAuthentication_DecoyAndWrongAssertionUniformResponse is
// go-xkms#1310: a finish against a decoy account (an email that names no
// account) and a finish with a wrong assertion against a real, registered
// account must be byte-identical on the wire -- same status, same body --
// over the SDK REST transport, matching the browser route.
func TestHandleSDKFinishAuthentication_DecoyAndWrongAssertionUniformResponse(t *testing.T) {
	wa := newTestWebAuthnService(t)
	r := setupFIDO2HandlerTest(t, wa)
	const email = "member@example.com"
	_, userID := enrollSDKAccount(t, wa, email)

	// Real account, wrong assertion: an authenticator that never enrolled a
	// credential for this account signs the real ceremony's challenge.
	beginRR := sdkFinishBegin(t, r, email)
	var realOptions waprotocol.CredentialAssertion
	require.NoError(t, json.Unmarshal([]byte(beginRR.OptionsJSON), &realOptions))
	forger, err := pkgwebauthn.NewMockAuthenticator("localhost")
	require.NoError(t, err)
	forgedAssertion, err := forger.CreateAssertionResponse(realOptions.Response.Challenge, userID, finishUniformOrigin)
	require.NoError(t, err)
	forgedJSON, err := json.Marshal(forgedAssertion.Raw)
	require.NoError(t, err)
	wrongRR := sdkFinishAuthentication(t, r, transport.FinishAuthenticationRequest{
		SessionID:     beginRR.SessionID,
		Email:         email,
		AssertionJSON: string(forgedJSON),
	})
	require.True(t, wrongRR.Code >= http.StatusBadRequest, "body: %s", wrongRR.Body.String())

	// Decoy account: an email that names no account.
	decoyBeginRR := sdkFinishBegin(t, r, "nobody@example.com")
	var decoyOptions waprotocol.CredentialAssertion
	require.NoError(t, json.Unmarshal([]byte(decoyBeginRR.OptionsJSON), &decoyOptions))
	decoyAssertion, err := forger.CreateAssertionResponse(decoyOptions.Response.Challenge, userID, finishUniformOrigin)
	require.NoError(t, err)
	decoyJSON, err := json.Marshal(decoyAssertion.Raw)
	require.NoError(t, err)
	decoyRR := sdkFinishAuthentication(t, r, transport.FinishAuthenticationRequest{
		SessionID:     decoyBeginRR.SessionID,
		Email:         "nobody@example.com",
		AssertionJSON: string(decoyJSON),
	})
	require.True(t, decoyRR.Code >= http.StatusBadRequest, "body: %s", decoyRR.Body.String())

	assert.Equal(t, http.StatusUnauthorized, wrongRR.Code)
	assert.Equal(t, wrongRR.Code, decoyRR.Code)
	assert.JSONEq(t, wrongRR.Body.String(), decoyRR.Body.String())
}

// sdkFinishBegin posts the SDK authentication/begin request for email and
// decodes the response.
func sdkFinishBegin(t *testing.T, r http.Handler, email string) transport.BeginAuthenticationResponse {
	t.Helper()
	body, err := json.Marshal(transport.BeginAuthenticationRequest{Email: email})
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/webauthn/sdk/authentication/begin", bytes.NewReader(body)))
	require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())
	var resp transport.BeginAuthenticationResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	return resp
}

// TestHandleSDKFinishAuthentication_MissingSessionDistinctFromUniformFailure
// proves a missing session keeps its own, distinct 400 response rather than
// being folded into the uniform 401 verification-failure response
// go-xkms#1310 requires for every other login-finish failure.
func TestHandleSDKFinishAuthentication_MissingSessionDistinctFromUniformFailure(t *testing.T) {
	wa := newTestWebAuthnService(t)
	r := setupFIDO2HandlerTest(t, wa)
	const email = "member2@example.com"
	authenticator, userID := enrollSDKAccount(t, wa, email)

	beginRR := sdkFinishBegin(t, r, email)
	var options waprotocol.CredentialAssertion
	require.NoError(t, json.Unmarshal([]byte(beginRR.OptionsJSON), &options))
	assertion, err := authenticator.CreateAssertionResponse(options.Response.Challenge, userID, finishUniformOrigin)
	require.NoError(t, err)
	assertionJSON, err := json.Marshal(assertion.Raw)
	require.NoError(t, err)

	rr := sdkFinishAuthentication(t, r, transport.FinishAuthenticationRequest{
		SessionID:     "session-that-was-never-issued",
		Email:         email,
		AssertionJSON: string(assertionJSON),
	})

	require.Equal(t, http.StatusBadRequest, rr.Code, "body: %s", rr.Body.String())
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.NotEqual(t, "verification failed", errResp.Message)
}
