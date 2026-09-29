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

package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgwebauthn "github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

const standingOrigin = "https://example.com"

// enrollBrowserAccount enrols a real passkey for email through the service
// and returns the authenticator holding it.
func (f *securityFixture) enrollBrowserAccount(t *testing.T, email string) (*pkgwebauthn.MockAuthenticator, pkgwebauthn.User) {
	t.Helper()
	ctx := context.Background()
	options, sessionID, err := f.h.service.BeginRegistration(ctx, email, email)
	require.NoError(t, err)
	user, err := f.users.GetByEmail(ctx, email)
	require.NoError(t, err)

	authenticator, err := pkgwebauthn.NewMockAuthenticator("example.com")
	require.NoError(t, err)
	attestation, err := authenticator.CreateAttestationObject(options.Response.Challenge, user.WebAuthnID(), standingOrigin)
	require.NoError(t, err)
	raw, err := json.Marshal(attestation.Raw)
	require.NoError(t, err)
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(raw))
	require.NoError(t, err)
	_, _, err = f.h.service.FinishRegistration(ctx, sessionID, parsed)
	require.NoError(t, err)
	return authenticator, user
}

// setStanding rewrites the standing of the account email names.
func (f *securityFixture) setStanding(t *testing.T, email string, state qrdbsdk.Lifecycle, methods []string) {
	t.Helper()
	user, err := f.users.GetByEmail(context.Background(), email)
	require.NoError(t, err)
	du, ok := user.(*pkgwebauthn.DefaultUser)
	require.True(t, ok)
	du.SetLifecycle(state)
	du.SetAuthMethods(methods)
}

// beginBrowserLogin runs POST /login/begin for email.
func (f *securityFixture) beginBrowserLogin(t *testing.T, email string) (string, protocol.CredentialAssertion) {
	t.Helper()
	rec := post(f.h.BeginLogin, "/login/begin", `{"email":"`+email+`"}`, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var options protocol.CredentialAssertion
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&options))
	return rec.Header().Get(HeaderSessionID), options
}

// finishBrowserLogin runs POST /login/finish with authenticator's assertion.
func (f *securityFixture) finishBrowserLogin(t *testing.T, sessionID string, options protocol.CredentialAssertion, authenticator *pkgwebauthn.MockAuthenticator, user pkgwebauthn.User) *httptest.ResponseRecorder {
	t.Helper()
	assertion, err := authenticator.CreateAssertionResponse(options.Response.Challenge, user.WebAuthnID(), standingOrigin)
	require.NoError(t, err)
	body, err := json.Marshal(assertion.Raw)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/login/finish", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderSessionID, sessionID)
	rec := httptest.NewRecorder()
	f.h.FinishLogin(rec, req)
	return rec
}

// TestFinishLogin_BrowserRefusesAccountNotInGoodStanding is go-xkms#1298 on
// the browser route: a valid passkey for a suspended, disabled or locked
// account, or one whose policy withdraws WebAuthn, is answered with the same
// 401 verification_failed as a wrong assertion — both when the account was
// already out of standing at begin and when it left standing mid-ceremony.
func TestFinishLogin_BrowserRefusesAccountNotInGoodStanding(t *testing.T) {
	cases := map[string]struct {
		state   qrdbsdk.Lifecycle
		methods []string
	}{
		"suspended":          {state: qrdbsdk.LifecycleSuspended},
		"disabled":           {state: qrdbsdk.LifecycleDisabled},
		"locked":             {state: qrdbsdk.LifecycleLocked},
		"webauthn withdrawn": {state: qrdbsdk.LifecycleActive, methods: []string{"mtls"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSecurityFixture(t, true)
			const email = "member@example.com"
			authenticator, user := f.enrollBrowserAccount(t, email)

			midSession, midOptions := f.beginBrowserLogin(t, email)
			f.setStanding(t, email, tc.state, tc.methods)
			assertVerificationFailed(t, f.finishBrowserLogin(t, midSession, midOptions, authenticator, user))

			sessionID, options := f.beginBrowserLogin(t, email)
			assertVerificationFailed(t, f.finishBrowserLogin(t, sessionID, options, authenticator, user))
		})
	}
}

func assertVerificationFailed(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	resp := decodeError(t, rec)
	assert.Equal(t, ErrorCodeVerificationFailed, resp.Error)
	assert.Equal(t, "verification failed", resp.Message)
}

// TestFinishLogin_BrowserActiveAccountLogsIn is the control.
func TestFinishLogin_BrowserActiveAccountLogsIn(t *testing.T) {
	f := newSecurityFixture(t, true)
	const email = "member@example.com"
	authenticator, user := f.enrollBrowserAccount(t, email)
	f.setStanding(t, email, qrdbsdk.LifecycleActive, []string{"mtls", "webauthn"})

	sessionID, options := f.beginBrowserLogin(t, email)
	rec := f.finishBrowserLogin(t, sessionID, options, authenticator, user)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp AuthResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotEmpty(t, resp.Token)
}

// TestBeginLogin_DisabledAccountIndistinguishableFromUnknown: begin answers a
// disabled account exactly as it answers an email that names no account.
func TestBeginLogin_DisabledAccountIndistinguishableFromUnknown(t *testing.T) {
	f := newSecurityFixture(t, true)
	const email = "member@example.com"
	f.enrollBrowserAccount(t, email)
	f.setStanding(t, email, qrdbsdk.LifecycleDisabled, nil)

	disabled := post(f.h.BeginLogin, "/login/begin", `{"email":"member@example.com"}`, nil)
	unknown := post(f.h.BeginLogin, "/login/begin", `{"email":"unknown@example.com"}`, nil)

	require.Equal(t, http.StatusOK, disabled.Code)
	assert.Equal(t, unknown.Code, disabled.Code)
	assert.Equal(t, headerNames(unknown.Header()), headerNames(disabled.Header()))

	var disabledBody, unknownBody map[string]map[string]any
	require.NoError(t, json.NewDecoder(disabled.Body).Decode(&disabledBody))
	require.NoError(t, json.NewDecoder(unknown.Body).Decode(&unknownBody))
	assert.Equal(t, fieldNames(unknownBody["publicKey"]), fieldNames(disabledBody["publicKey"]))
}

// TestBeginRegistration_InactiveZeroCredentialAccountRefused: the public
// route answers a non-active provisioned account with the same 403 as every
// other refused enrolment.
func TestBeginRegistration_InactiveZeroCredentialAccountRefused(t *testing.T) {
	f := newSecurityFixture(t, false)
	const email = "provisioned@example.com"
	_, err := f.users.Create(context.Background(), email, email)
	require.NoError(t, err)
	f.setStanding(t, email, qrdbsdk.LifecycleSuspended, nil)

	inactive := post(f.h.BeginRegistration, "/register/begin", `{"email":"provisioned@example.com"}`, nil)
	unknown := post(f.h.BeginRegistration, "/register/begin", `{"email":"unknown@example.com"}`, nil)

	require.Equal(t, http.StatusForbidden, inactive.Code)
	assert.Equal(t, unknown.Code, inactive.Code)
	assert.Equal(t, decodeError(t, unknown), decodeError(t, inactive))
}
