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

// This file exercises the single WebAuthn ceremony driver end to end against
// a real relying party in both of its shapes: the browser-shaped
// pkg/webauthn/http routes (HTTPRelyingParty) and the SDK transport routes
// (TransportRelyingParty), both served by a real pkg/api/rest.Server backed
// by real pkg/webauthn ceremony logic — no double stands in for the RP.
package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	xkmstransport "github.com/jeremyhahn/go-xkms/pkg/api/transport"
	restclient "github.com/jeremyhahn/go-xkms/pkg/api/transport/rest"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/webauthntest"
	pkgwebauthn "github.com/jeremyhahn/go-xkms/pkg/webauthn"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// e2eServer wires a real rest.Server, exposing both the browser-shaped
// pkg/webauthn/http routes and the SDK transport routes on the same
// pkgwebauthn.Service instance, over an httptest.Server.
type e2eServer struct {
	httpServer *httptest.Server
}

// newE2EServer boots a real REST server with WebAuthn enabled against wa. A
// nil wa builds the default open-registration service.
func newE2EServer(t *testing.T, wa *pkgwebauthn.Service, waConfig *pkgwebauthn.Config) *e2eServer {
	t.Helper()

	xkms.Reset()
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"mem": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "mem",
	}))
	xkmsSvc, err := xkms.Get()
	require.NoError(t, err)
	xkmsSvc.SetWebAuthn(wa)
	t.Cleanup(xkms.Reset)

	srv, err := rest.NewServer(&rest.Config{
		Authenticator:   auth.NewNoOpAuthenticator(),
		Backends:        map[string]xkms.Backend{"mem": xkmsmocks.NewMockKeyStore()},
		XKMSService:     xkmsSvc,
		WebAuthnConfig:  waConfig,
		WebAuthnService: wa,
	})
	require.NoError(t, err)

	httpServer := httptest.NewServer(srv.Handler())
	t.Cleanup(httpServer.Close)

	return &e2eServer{httpServer: httpServer}
}

// openRegistrationService builds a real pkgwebauthn.Service with public
// registration enabled, the shape every "happy path" e2e test needs.
func openRegistrationService(t *testing.T) (*pkgwebauthn.Service, *pkgwebauthn.Config) {
	t.Helper()
	allow := true
	cfg := &pkgwebauthn.Config{
		RPID:                    "localhost",
		RPDisplayName:           "xkms e2e",
		RPOrigins:               []string{"https://localhost"},
		AllowPublicRegistration: &allow,
	}
	stores := webauthntest.NewStores(t)
	svc, err := pkgwebauthn.NewService(pkgwebauthn.ServiceParams{
		Config:          cfg,
		UserStore:       stores.Users,
		SessionStore:    pkgwebauthn.NewMemorySessionStore(),
		CredentialStore: stores.Credentials,
	})
	require.NoError(t, err)
	return svc, cfg
}

// closedRegistrationService builds a real pkgwebauthn.Service with public
// registration left at its closed default, for the RP-rejection test.
func closedRegistrationService(t *testing.T) (*pkgwebauthn.Service, *pkgwebauthn.Config) {
	t.Helper()
	cfg := &pkgwebauthn.Config{
		RPID:          "localhost",
		RPDisplayName: "xkms e2e",
		RPOrigins:     []string{"https://localhost"},
	}
	stores := webauthntest.NewStores(t)
	svc, err := pkgwebauthn.NewService(pkgwebauthn.ServiceParams{
		Config:          cfg,
		UserStore:       stores.Users,
		SessionStore:    pkgwebauthn.NewMemorySessionStore(),
		CredentialStore: stores.Credentials,
	})
	require.NoError(t, err)
	return svc, cfg
}

// --- HTTPRelyingParty (browser routes) ---

// TestE2E_HTTPRelyingParty_RegisterAndLogin drives a full registration then
// login ceremony through Client, using the default HTTPRelyingParty against
// a real pkg/webauthn/http-served RP and SoftwareAdapter as the
// authenticator.
func TestE2E_HTTPRelyingParty_RegisterAndLogin(t *testing.T) {
	wa, cfg := openRegistrationService(t)
	srv := newE2EServer(t, wa, cfg)

	c, err := NewClient(&Config{
		ServerURL:            srv.httpServer.URL,
		AuthenticatorAdapter: NewSoftwareAdapter(),
		Origin:               "https://localhost",
	})
	require.NoError(t, err)

	regResult, err := c.Register(context.Background(), &RegistrationRequest{
		Username:    "alice@example.com",
		DisplayName: "Alice",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, regResult.UserID)
	assert.NotEmpty(t, regResult.JWT)

	loginResult, err := c.Login(context.Background(), &AuthenticationRequest{
		Username: "alice@example.com",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, loginResult.JWT)
	assert.Equal(t, regResult.UserID, loginResult.UserID)
}

// TestE2E_HTTPRelyingParty_Register_RPRejection proves a relying party
// rejection (registration closed) reaches Client.Register as an error.
func TestE2E_HTTPRelyingParty_Register_RPRejection(t *testing.T) {
	wa, cfg := closedRegistrationService(t)
	srv := newE2EServer(t, wa, cfg)

	c, err := NewClient(&Config{
		ServerURL:            srv.httpServer.URL,
		AuthenticatorAdapter: NewSoftwareAdapter(),
	})
	require.NoError(t, err)

	_, err = c.Register(context.Background(), &RegistrationRequest{Username: "nobody@example.com"})
	require.Error(t, err)
}

// TestE2E_HTTPRelyingParty_Register_AuthenticatorFailure proves an
// authenticator failure surfaces as ErrCTAPOperationFailed and never reaches
// FinishRegistration.
func TestE2E_HTTPRelyingParty_Register_AuthenticatorFailure(t *testing.T) {
	wa, cfg := openRegistrationService(t)
	srv := newE2EServer(t, wa, cfg)

	c, err := NewClient(&Config{
		ServerURL:            srv.httpServer.URL,
		AuthenticatorAdapter: &failingAdapter{},
	})
	require.NoError(t, err)

	_, err = c.Register(context.Background(), &RegistrationRequest{Username: "bob@example.com"})
	require.ErrorIs(t, err, ErrCTAPOperationFailed)
}

// TestE2E_HTTPRelyingParty_Login_ChallengeMismatch proves the real RP's
// challenge verification rejects an assertion bound to the wrong challenge,
// and that rejection reaches Client.Login as an error rather than a
// successful login.
func TestE2E_HTTPRelyingParty_Login_ChallengeMismatch(t *testing.T) {
	wa, cfg := openRegistrationService(t)
	srv := newE2EServer(t, wa, cfg)

	software := NewSoftwareAdapter()

	registerClient, err := NewClient(&Config{
		ServerURL:            srv.httpServer.URL,
		AuthenticatorAdapter: software,
		Origin:               "https://localhost",
	})
	require.NoError(t, err)
	_, err = registerClient.Register(context.Background(), &RegistrationRequest{Username: "carol@example.com"})
	require.NoError(t, err)

	loginClient, err := NewClient(&Config{
		ServerURL:            srv.httpServer.URL,
		AuthenticatorAdapter: &challengeMismatchAdapter{inner: software},
		Origin:               "https://localhost",
	})
	require.NoError(t, err)

	_, err = loginClient.Login(context.Background(), &AuthenticationRequest{Username: "carol@example.com"})
	require.Error(t, err)
}

// --- TransportRelyingParty (SDK routes) ---

// TestE2E_TransportRelyingParty_RegisterAndLogin drives a full registration
// then login ceremony using TransportRelyingParty over a real
// pkg/api/transport/rest connection to the SDK ceremony routes, against the
// same real RP and SoftwareAdapter.
func TestE2E_TransportRelyingParty_RegisterAndLogin(t *testing.T) {
	wa, cfg := openRegistrationService(t)
	srv := newE2EServer(t, wa, cfg)

	tr := connectTransportClient(t, srv.httpServer.URL)
	rp, err := NewTransportRelyingParty(tr)
	require.NoError(t, err)

	c, err := NewClient(&Config{
		RelyingParty:         rp,
		AuthenticatorAdapter: NewSoftwareAdapter(),
		Origin:               "https://localhost",
	})
	require.NoError(t, err)

	regResult, err := c.Register(context.Background(), &RegistrationRequest{
		Username:    "dave@example.com",
		DisplayName: "Dave",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, regResult.CredentialID)

	loginResult, err := c.Login(context.Background(), &AuthenticationRequest{Username: "dave@example.com"})
	require.NoError(t, err)
	assert.NotEmpty(t, loginResult.JWT)
}

// TestE2E_TransportRelyingParty_Register_RPRejection is the SDK-route
// counterpart of TestE2E_HTTPRelyingParty_Register_RPRejection.
func TestE2E_TransportRelyingParty_Register_RPRejection(t *testing.T) {
	wa, cfg := closedRegistrationService(t)
	srv := newE2EServer(t, wa, cfg)

	tr := connectTransportClient(t, srv.httpServer.URL)
	rp, err := NewTransportRelyingParty(tr)
	require.NoError(t, err)

	c, err := NewClient(&Config{
		RelyingParty:         rp,
		Origin:               "https://localhost",
		AuthenticatorAdapter: NewSoftwareAdapter(),
	})
	require.NoError(t, err)

	_, err = c.Register(context.Background(), &RegistrationRequest{Username: "nobody@example.com"})
	require.Error(t, err)
}

// TestE2E_TransportRelyingParty_Login_AuthenticatorFailure is the SDK-route
// counterpart of the authenticator-failure path.
func TestE2E_TransportRelyingParty_Login_AuthenticatorFailure(t *testing.T) {
	wa, cfg := openRegistrationService(t)
	srv := newE2EServer(t, wa, cfg)

	software := NewSoftwareAdapter()
	tr := connectTransportClient(t, srv.httpServer.URL)
	rp, err := NewTransportRelyingParty(tr)
	require.NoError(t, err)

	registerClient, err := NewClient(&Config{RelyingParty: rp, Origin: "https://localhost", AuthenticatorAdapter: software})
	require.NoError(t, err)
	_, err = registerClient.Register(context.Background(), &RegistrationRequest{Username: "erin@example.com"})
	require.NoError(t, err)

	loginClient, err := NewClient(&Config{RelyingParty: rp, Origin: "https://localhost", AuthenticatorAdapter: &failingAdapter{}})
	require.NoError(t, err)

	_, err = loginClient.Login(context.Background(), &AuthenticationRequest{Username: "erin@example.com"})
	require.ErrorIs(t, err, ErrCTAPOperationFailed)
}

// connectTransportClient connects a real pkg/api/transport/rest.Transport to
// the given server URL, satisfying TransportClient.
func connectTransportClient(t *testing.T, serverURL string) *restclient.Transport {
	t.Helper()

	// A plaintext loopback httptest server: the opt-out's one use (ruling 152).
	tr, err := restclient.NewWithConfig(&xkmstransport.Config{Address: serverURL, AllowInsecureTransport: true})
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	t.Cleanup(func() { _ = tr.Close() })

	return tr
}

// --- Authenticator doubles used only by the e2e error-path tests ---

// failingAdapter is an AuthenticatorAdapter whose authenticator is present
// but fails every ceremony call, distinguishing "unavailable"
// (ErrAuthenticatorNotFound) from "available but refuses"
// (ErrCTAPOperationFailed).
type failingAdapter struct{}

func (a *failingAdapter) Available() bool { return true }

func (a *failingAdapter) MakeCredential(context.Context, *CeremonyOptions) ([]byte, error) {
	return nil, errAdapterFailure
}

func (a *failingAdapter) GetAssertion(context.Context, *CeremonyOptions) ([]byte, error) {
	return nil, errAdapterFailure
}

// challengeMismatchAdapter wraps a working adapter and corrupts the
// clientDataJSON challenge in its assertion response, proving the real RP's
// challenge verification — not just Client's plumbing — rejects a
// mismatched ceremony.
type challengeMismatchAdapter struct {
	inner AuthenticatorAdapter
}

func (a *challengeMismatchAdapter) Available() bool { return a.inner.Available() }

func (a *challengeMismatchAdapter) MakeCredential(ctx context.Context, opts *CeremonyOptions) ([]byte, error) {
	return a.inner.MakeCredential(ctx, opts)
}

func (a *challengeMismatchAdapter) GetAssertion(ctx context.Context, opts *CeremonyOptions) ([]byte, error) {
	raw, err := a.inner.GetAssertion(ctx, opts)
	if err != nil {
		return nil, err
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	resp, ok := doc["response"].(map[string]interface{})
	if !ok {
		return nil, &errAdapterFailureType{}
	}
	// clientDataJSON base64url-decodes to {"type":...,"challenge":...,"origin":...};
	// swap in a base64url document with a challenge that cannot match the
	// session the RP is verifying against.
	corrupted := `{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://localhost"}`
	resp["clientDataJSON"] = base64.RawURLEncoding.EncodeToString([]byte(corrupted))
	doc["response"] = resp

	return json.Marshal(doc)
}

var errAdapterFailure = &errAdapterFailureType{}

// errAdapterFailureType is a typed error for the e2e authenticator doubles.
type errAdapterFailureType struct{}

func (*errAdapterFailureType) Error() string {
	return "webauthn/client: e2e test authenticator failure"
}
