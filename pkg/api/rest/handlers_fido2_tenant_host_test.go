package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	webauthnhttp "github.com/jeremyhahn/go-xkms/pkg/webauthn/http"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// sdkLoginAuthenticator is one passkey a test asserts with.
type sdkLoginAuthenticator struct {
	authn virtualwebauthn.Authenticator
	cred  virtualwebauthn.Credential
}

// enrolSystemAccount registers tenantLoginEmail in the system tenant with its
// own passkey, so a login that wrongly reaches the system RP succeeds.
func enrolSystemAccount(t *testing.T, f *tenantLoginFixture) sdkLoginAuthenticator {
	t.Helper()
	ctx := context.Background()
	a := sdkLoginAuthenticator{
		authn: virtualwebauthn.NewAuthenticator(),
		cred:  virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2),
	}
	svc := f.router.System()
	opts, sessionID, err := svc.BeginRegistration(ctx, tenantLoginEmail, "Sys")
	require.NoError(t, err)
	raw, err := json.Marshal(opts.Response)
	require.NoError(t, err)
	attOpts, err := virtualwebauthn.ParseAttestationOptions(string(raw))
	require.NoError(t, err)
	att := virtualwebauthn.CreateAttestationResponse(f.rp, a.authn, a.cred, *attOpts)
	parsed, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(att))
	require.NoError(t, err)
	_, _, err = svc.FinishRegistration(ctx, sessionID, parsed)
	require.NoError(t, err)
	a.authn.AddCredential(a.cred)
	user, err := svc.GetUserByEmail(ctx, tenantLoginEmail)
	require.NoError(t, err)
	a.authn.Options.UserHandle = user.WebAuthnID()
	return a
}

// sdkLogin drives /webauthn/sdk/authentication/begin and /finish on host,
// naming bodyTenant in both bodies and headerTenant in X-Tenant-Id.
func sdkLogin(t *testing.T, mux *chi.Mux, host, bodyTenant, headerTenant string, a sdkLoginAuthenticator) *httptest.ResponseRecorder {
	t.Helper()
	post := func(path string, body any) *httptest.ResponseRecorder {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
		req.Host = host
		req.Header.Set("Content-Type", "application/json")
		if headerTenant != "" {
			req.Header.Set(webauthnhttp.HeaderTenantID, headerTenant)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	rec := post("/webauthn/sdk/authentication/begin", transport.BeginAuthenticationRequest{
		Email: tenantLoginEmail, TenantID: bodyTenant,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var begin transport.BeginAuthenticationResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &begin))
	var assertion protocol.CredentialAssertion
	require.NoError(t, json.Unmarshal([]byte(begin.OptionsJSON), &assertion))
	raw, err := json.Marshal(assertion.Response)
	require.NoError(t, err)
	asOpts, err := virtualwebauthn.ParseAssertionOptions(string(raw))
	require.NoError(t, err)

	rp := virtualwebauthn.RelyingParty{Name: "xkms test", ID: "example.com", Origin: "https://" + host}
	as := virtualwebauthn.CreateAssertionResponse(rp, a.authn, a.cred, *asOpts)
	return post("/webauthn/sdk/authentication/finish", transport.FinishAuthenticationRequest{
		SessionID: begin.SessionID, Email: tenantLoginEmail, AssertionJSON: as, TenantID: bodyTenant,
	})
}

// TestSDKLogin_HostRule pins Codex round 2 on #2387: the SDK REST login
// lane applies the tenant host rule of pkg/webauthn/http (docs/SPEC.md:129).
func TestSDKLogin_HostRule(t *testing.T) {
	f := newTenantLoginFixture(t)
	sys := enrolSystemAccount(t, f)
	mux := setupFIDO2HandlerTest(t, f.router.System())
	svc, err := xkms.Get()
	require.NoError(t, err)
	svc.SetWebAuthnTenants(f.router)

	tenantB := sdkLoginAuthenticator{authn: f.authn, cred: f.cred}

	// Control: on the unmapped host the system account signs in, so a decoy
	// below comes from the host rule and not from a broken system login.
	rec := sdkLogin(t, mux, "example.com", "system", "", sys)
	require.Equal(t, http.StatusOK, rec.Code, "control: system login on the system host: %s", rec.Body.String())

	t.Run("host selects tenant", func(t *testing.T) {
		rec := sdkLogin(t, mux, tenantLoginHostB, "", "", tenantB)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var resp transport.FinishAuthenticationResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		id := authenticateMinted(t, f.issuer, resp.Token)
		require.Equal(t, tenantLoginTenantB, id.TenantID)
	})

	decoyed := func(t *testing.T, rec *httptest.ResponseRecorder) {
		t.Helper()
		require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
		var body ErrorResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		require.Equal(t, webauthnhttp.ErrorCodeVerificationFailed, body.Error)
	}
	t.Run("body tenant mismatch is decoyed", func(t *testing.T) {
		decoyed(t, sdkLogin(t, mux, tenantLoginHostB, "system", "", sys))
	})
	t.Run("header tenant mismatch is decoyed", func(t *testing.T) {
		decoyed(t, sdkLogin(t, mux, tenantLoginHostB, "", "system", sys))
	})
}
