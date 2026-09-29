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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	pkgwebauthn "github.com/jeremyhahn/go-xkms/pkg/webauthn"
	webauthnhttp "github.com/jeremyhahn/go-xkms/pkg/webauthn/http"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// newTestWebAuthnService builds a fully in-memory WebAuthn relying-party
// service using the package's memory stores. This lets the SDK FIDO2 handlers
// exercise real ceremony logic (BeginRegistration success) without hardware or
// a browser.
func newTestWebAuthnService(t *testing.T) *pkgwebauthn.Service {
	t.Helper()
	allowRegistration := true
	svc, err := pkgwebauthn.NewService(pkgwebauthn.ServiceParams{
		Config: &pkgwebauthn.Config{
			RPID:                    "localhost",
			RPDisplayName:           "xkms test",
			RPOrigins:               []string{"https://localhost"},
			AllowPublicRegistration: &allowRegistration,
		},
		UserStore:       pkgwebauthn.NewMemoryUserStore(),
		SessionStore:    pkgwebauthn.NewMemorySessionStore(),
		CredentialStore: pkgwebauthn.NewMemoryCredentialStore(),
	})
	require.NoError(t, err)
	return svc
}

// setupFIDO2HandlerTest initializes the singleton, optionally wires a real
// WebAuthn service, mounts the four SDK FIDO2 routes, and returns the router.
func setupFIDO2HandlerTest(t *testing.T, wa *pkgwebauthn.Service) *chi.Mux {
	t.Helper()

	xkms.Reset()
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"mem": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "mem",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)
	if wa != nil {
		svc.SetWebAuthn(wa)
	}
	t.Cleanup(func() { xkms.Reset() })

	s := &Server{xkmsService: svc}
	r := chi.NewRouter()
	r.Route("/webauthn/sdk", func(r chi.Router) {
		r.Post("/registration/begin", s.handleSDKBeginRegistration)
		r.Post("/registration/finish", s.handleSDKFinishRegistration)
		r.Post("/authentication/begin", s.handleSDKBeginAuthentication)
		r.Post("/authentication/finish", s.handleSDKFinishAuthentication)
	})
	return r
}

// ============================================================================
// handleSDKBeginRegistration
// ============================================================================

// TestHandleSDKBeginRegistration_UsernameKeyNotRecognized verifies the SDK
// route reads the login key from "email" only: a body that carries the
// address solely under the removed "username" wire key never resolves an
// account by that address, proving the alias was deleted outright rather
// than kept as a silent fallback (owner rule 2026-09-22, PR 2).
func TestHandleSDKBeginRegistration_UsernameKeyNotRecognized(t *testing.T) {
	r := setupFIDO2HandlerTest(t, newTestWebAuthnService(t))

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/webauthn/sdk/registration/begin",
		bytes.NewReader([]byte(`{"username":"alice@example.com","display_name":"Alice"}`))))

	require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())
	assert.NotContains(t, rr.Body.String(), "alice@example.com",
		"the removed \"username\" key must not be read as the login key")
}

func TestHandleSDKBeginRegistration_Success(t *testing.T) {
	r := setupFIDO2HandlerTest(t, newTestWebAuthnService(t))

	body, _ := json.Marshal(transport.BeginRegistrationRequest{Email: "alice@example.com", DisplayName: "Alice"})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/webauthn/sdk/registration/begin", bytes.NewReader(body)))

	require.Equal(t, http.StatusOK, rr.Code)
	var resp transport.BeginRegistrationResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.SessionID)
	assert.Contains(t, resp.OptionsJSON, "publicKey")
}

// TestHandleSDKBeginRegistration_RegistrationClosed pins the SDK route's wire
// contract for the go-xkms#184 default: a relying party that never decided
// allow_public_registration refuses an unknown email with the documented 403,
// not a fall-through 500, matching the browser route and docs/webauthn/api.md.
func TestHandleSDKBeginRegistration_RegistrationClosed(t *testing.T) {
	closedRP, err := pkgwebauthn.NewService(pkgwebauthn.ServiceParams{
		Config: &pkgwebauthn.Config{
			RPID:          "localhost",
			RPDisplayName: "xkms test",
			RPOrigins:     []string{"https://localhost"},
			// AllowPublicRegistration deliberately unset: the default is closed.
		},
		UserStore:       pkgwebauthn.NewMemoryUserStore(),
		SessionStore:    pkgwebauthn.NewMemorySessionStore(),
		CredentialStore: pkgwebauthn.NewMemoryCredentialStore(),
	})
	require.NoError(t, err)

	r := setupFIDO2HandlerTest(t, closedRP)

	body, _ := json.Marshal(transport.BeginRegistrationRequest{Email: "stranger@example.com", DisplayName: "Stranger"})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/webauthn/sdk/registration/begin", bytes.NewReader(body)))

	require.Equal(t, http.StatusForbidden, rr.Code, "body: %s", rr.Body.String())
	var errResp ErrorResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &errResp))
	assert.Equal(t, "registration_refused", errResp.Error,
		"the machine-readable code must match the browser route's documented contract")
	assert.Equal(t, pkgwebauthn.ErrRegistrationRefused.Error(), errResp.Message)
}

func TestHandleSDKBeginRegistration_BadJSON(t *testing.T) {
	r := setupFIDO2HandlerTest(t, newTestWebAuthnService(t))

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/webauthn/sdk/registration/begin", bytes.NewBufferString("{bad")))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleSDKBeginRegistration_NotConfigured(t *testing.T) {
	// Singleton initialized but no WebAuthn service wired => ErrNotConfigured => 500.
	r := setupFIDO2HandlerTest(t, nil)

	body, _ := json.Marshal(transport.BeginRegistrationRequest{Email: "alice@example.com"})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/webauthn/sdk/registration/begin", bytes.NewReader(body)))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestHandleSDKBeginRegistration_ServiceNotInitialized(t *testing.T) {
	xkms.Reset()
	t.Cleanup(func() { xkms.Reset() })

	s := &Server{}
	body, _ := json.Marshal(transport.BeginRegistrationRequest{Email: "a@b.c"})
	rr := httptest.NewRecorder()
	s.handleSDKBeginRegistration(rr, httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)))

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

// ============================================================================
// handleSDKFinishRegistration
// ============================================================================

func TestHandleSDKFinishRegistration_BadJSON(t *testing.T) {
	r := setupFIDO2HandlerTest(t, newTestWebAuthnService(t))

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/webauthn/sdk/registration/finish", bytes.NewBufferString("{bad")))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleSDKFinishRegistration_ParseError(t *testing.T) {
	// Valid request JSON, but the embedded attestation is not parseable =>
	// the service returns a ceremony error => handler maps to 400.
	r := setupFIDO2HandlerTest(t, newTestWebAuthnService(t))

	body, _ := json.Marshal(transport.FinishRegistrationRequest{
		SessionID:       "nonexistent",
		AttestationJSON: `{"not":"a-real-attestation"}`,
	})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/webauthn/sdk/registration/finish", bytes.NewReader(body)))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleSDKFinishRegistration_NotConfigured(t *testing.T) {
	r := setupFIDO2HandlerTest(t, nil)

	body, _ := json.Marshal(transport.FinishRegistrationRequest{SessionID: "s", AttestationJSON: "{}"})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/webauthn/sdk/registration/finish", bytes.NewReader(body)))

	// ErrNotConfigured is returned before parsing => the handler still maps the
	// service error to 400 (FinishRegistration uses StatusBadRequest for errors).
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleSDKFinishRegistration_ServiceNotInitialized(t *testing.T) {
	xkms.Reset()
	t.Cleanup(func() { xkms.Reset() })

	s := &Server{}
	body, _ := json.Marshal(transport.FinishRegistrationRequest{SessionID: "s"})
	rr := httptest.NewRecorder()
	s.handleSDKFinishRegistration(rr, httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)))

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

// ============================================================================
// handleSDKBeginAuthentication
// ============================================================================

func TestHandleSDKBeginAuthentication_BadJSON(t *testing.T) {
	r := setupFIDO2HandlerTest(t, newTestWebAuthnService(t))

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/webauthn/sdk/authentication/begin", bytes.NewBufferString("{bad")))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleSDKBeginAuthentication_UnknownUser(t *testing.T) {
	// Real service, but the user was never registered: answered with decoy
	// options, exactly like a known account, so the SDK route does not
	// reveal whether the account exists (go-xkms#1296).
	r := setupFIDO2HandlerTest(t, newTestWebAuthnService(t))

	body, _ := json.Marshal(transport.BeginAuthenticationRequest{Email: "nobody@example.com"})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/webauthn/sdk/authentication/begin", bytes.NewReader(body)))

	require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())
	var resp transport.BeginAuthenticationResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.SessionID)
	assert.Contains(t, resp.OptionsJSON, "allowCredentials")
}

// TestHandleSDKBeginAuthentication_UsernameKeyNotRecognized verifies the SDK
// route reads the login key from "email" only: a body that carries the
// address solely under the removed "username" wire key resolves an empty
// login key, not the address, and so is refused as the same malformed
// request an empty Email always produces (owner rule 2026-09-22, PR 2).
func TestHandleSDKBeginAuthentication_UsernameKeyNotRecognized(t *testing.T) {
	r := setupFIDO2HandlerTest(t, newTestWebAuthnService(t))

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/webauthn/sdk/authentication/begin",
		bytes.NewReader([]byte(`{"username":"alice@example.com"}`))))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestHandleSDKBeginAuthentication_NotConfigured(t *testing.T) {
	r := setupFIDO2HandlerTest(t, nil)

	body, _ := json.Marshal(transport.BeginAuthenticationRequest{Email: "x@y.z"})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/webauthn/sdk/authentication/begin", bytes.NewReader(body)))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestHandleSDKBeginAuthentication_ServiceNotInitialized(t *testing.T) {
	xkms.Reset()
	t.Cleanup(func() { xkms.Reset() })

	s := &Server{}
	body, _ := json.Marshal(transport.BeginAuthenticationRequest{Email: "x@y.z"})
	rr := httptest.NewRecorder()
	s.handleSDKBeginAuthentication(rr, httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)))

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

// ============================================================================
// handleSDKFinishAuthentication
// ============================================================================

func TestHandleSDKFinishAuthentication_BadJSON(t *testing.T) {
	r := setupFIDO2HandlerTest(t, newTestWebAuthnService(t))

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/webauthn/sdk/authentication/finish", bytes.NewBufferString("{bad")))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestHandleSDKFinishAuthentication_ParseError is go-xkms#1310: a malformed
// assertion is a login-finish failure like any other, so it gets the same
// fixed 401 verification_failed response as a wrong-but-well-formed
// assertion, not a distinct 400 that would set it apart from that case.
func TestHandleSDKFinishAuthentication_ParseError(t *testing.T) {
	r := setupFIDO2HandlerTest(t, newTestWebAuthnService(t))

	body, _ := json.Marshal(transport.FinishAuthenticationRequest{
		SessionID:     "s",
		Email:         "alice@example.com",
		AssertionJSON: `{"not":"an-assertion"}`,
	})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/webauthn/sdk/authentication/finish", bytes.NewReader(body)))

	require.Equal(t, http.StatusUnauthorized, rr.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Equal(t, webauthnhttp.ErrorCodeVerificationFailed, errResp.Error)
	assert.Equal(t, "verification failed", errResp.Message)
}

func TestHandleSDKFinishAuthentication_NotConfigured(t *testing.T) {
	r := setupFIDO2HandlerTest(t, nil)

	body, _ := json.Marshal(transport.FinishAuthenticationRequest{SessionID: "s", Email: "x@y.z", AssertionJSON: "{}"})
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/webauthn/sdk/authentication/finish", bytes.NewReader(body)))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleSDKFinishAuthentication_ServiceNotInitialized(t *testing.T) {
	xkms.Reset()
	t.Cleanup(func() { xkms.Reset() })

	s := &Server{}
	body, _ := json.Marshal(transport.FinishAuthenticationRequest{SessionID: "s"})
	rr := httptest.NewRecorder()
	s.handleSDKFinishAuthentication(rr, httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)))

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

// TestHandleSDKBeginRegistration_SessionStoreFull pins the SDK route's answer
// when the relying party holds its maximum number of unfinished ceremonies:
// 503 with the browser route's session_limit code, not a 500.
func TestHandleSDKBeginRegistration_SessionStoreFull(t *testing.T) {
	allowRegistration := true
	rp, err := pkgwebauthn.NewService(pkgwebauthn.ServiceParams{
		Config: &pkgwebauthn.Config{
			RPID:                    "localhost",
			RPDisplayName:           "xkms test",
			RPOrigins:               []string{"https://localhost"},
			AllowPublicRegistration: &allowRegistration,
		},
		UserStore:       pkgwebauthn.NewMemoryUserStore(),
		SessionStore:    pkgwebauthn.NewMemorySessionStore(pkgwebauthn.WithMaxSessions(1)),
		CredentialStore: pkgwebauthn.NewMemoryCredentialStore(),
	})
	require.NoError(t, err)
	r := setupFIDO2HandlerTest(t, rp)

	begin := func(email string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(transport.BeginRegistrationRequest{Email: email})
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/webauthn/sdk/registration/begin", bytes.NewReader(body)))
		return rr
	}

	require.Equal(t, http.StatusOK, begin("alice@example.com").Code)
	rr := begin("bob@example.com")
	require.Equal(t, http.StatusServiceUnavailable, rr.Code, "body: %s", rr.Body.String())
	var errResp ErrorResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &errResp))
	assert.Equal(t, "session_limit", errResp.Error)
}
