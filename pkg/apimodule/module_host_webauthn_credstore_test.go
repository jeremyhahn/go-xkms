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

package apimodule

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// countingCredentialStore delegates every call to the wrapped store and
// counts the credentials that passed through Save -- the observable a
// composer's write-through decorator (an identity-plane auth factor, an
// audit record) hangs off in production.
type countingCredentialStore struct {
	webauthn.CredentialStore

	mu    sync.Mutex
	saved []string
}

// Save delegates first and records only a successful write.
func (c *countingCredentialStore) Save(ctx context.Context, cred *webauthn.Credential) error {
	if err := c.CredentialStore.Save(ctx, cred); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.saved = append(c.saved, string(cred.ID))
	return nil
}

// count returns how many credentials were saved through the decorator.
func (c *countingCredentialStore) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.saved)
}

// selfBuiltModuleRoutes composes the module the way a host does (service
// resolver + qrdb client + WebAuthn config, no WithRESTServer) and returns
// its registered routes by method+pattern.
func selfBuiltModuleRoutes(t *testing.T, opts ...Option) map[string]http.HandlerFunc {
	t.Helper()

	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "test",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	client, _, err := testutil.NewQRDBFakeClient()
	require.NoError(t, err)

	allow := true
	base := []Option{
		WithQRDBClient(func() *qrdbsdk.Client { return client }),
		WithWebAuthnConfig(&config.WebAuthnConfig{
			RPID:                    "example.com",
			RPOrigins:               []string{"https://example.com"},
			AllowPublicRegistration: &allow,
		}),
	}
	m, err := NewModule(func() *xkms.XKMSService { return svc }, append(base, opts...)...)
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)

	routes := make(map[string]http.HandlerFunc, len(*recs))
	for _, rec := range *recs {
		routes[rec.method+" "+rec.pattern] = rec.handler
	}
	return routes
}

// registerThroughSDKLane drives the SDK registration ceremony
// (POST /api/v1/webauthn/sdk/registration/{begin,finish}) -- the exact route
// pair the xkey CLI uses -- against the module's self-built surface, and
// returns the credential id the server reported enrolling.
func registerThroughSDKLane(t *testing.T, routes map[string]http.HandlerFunc, email string) string {
	t.Helper()

	begin := routes["POST /api/v1/webauthn/sdk/registration/begin"]
	finish := routes["POST /api/v1/webauthn/sdk/registration/finish"]
	require.NotNil(t, begin, "the SDK registration lane must be registered")
	require.NotNil(t, finish, "the SDK registration lane must be registered")

	beginBody, err := json.Marshal(transport.BeginRegistrationRequest{Username: email, DisplayName: email})
	require.NoError(t, err)
	beginReq := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/sdk/registration/begin", bytes.NewReader(beginBody))
	beginReq.Header.Set("Content-Type", "application/json")
	beginRec := httptest.NewRecorder()
	begin(beginRec, beginReq)
	require.Equal(t, http.StatusOK, beginRec.Code, "body: %s", beginRec.Body.String())

	var beginResp transport.BeginRegistrationResponse
	require.NoError(t, json.Unmarshal(beginRec.Body.Bytes(), &beginResp))
	require.NotEmpty(t, beginResp.SessionID)

	var options protocol.CredentialCreation
	require.NoError(t, json.Unmarshal([]byte(beginResp.OptionsJSON), &options))

	// The ceremony options carry the user handle as a base64url string on
	// the wire; the authenticator signs over the raw bytes.
	encodedUserID, ok := options.Response.User.ID.(string)
	require.True(t, ok, "the ceremony options must carry a base64url user handle, got %T", options.Response.User.ID)
	userID, err := base64.RawURLEncoding.DecodeString(encodedUserID)
	require.NoError(t, err)

	authenticator, err := webauthn.NewMockAuthenticator("example.com")
	require.NoError(t, err)
	attestation, err := authenticator.CreateAttestationObject(
		options.Response.Challenge,
		userID,
		"https://example.com",
	)
	require.NoError(t, err)
	attestationJSON, err := json.Marshal(attestation.Raw)
	require.NoError(t, err)

	finishBody, err := json.Marshal(transport.FinishRegistrationRequest{
		SessionID:       beginResp.SessionID,
		AttestationJSON: string(attestationJSON),
	})
	require.NoError(t, err)
	finishReq := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/sdk/registration/finish", bytes.NewReader(finishBody))
	finishReq.Header.Set("Content-Type", "application/json")
	finishRec := httptest.NewRecorder()
	finish(finishRec, finishReq)
	require.Equal(t, http.StatusOK, finishRec.Code, "body: %s", finishRec.Body.String())

	var finishResp transport.FinishRegistrationResponse
	require.NoError(t, json.Unmarshal(finishRec.Body.Bytes(), &finishResp))
	require.True(t, finishResp.Success)
	return finishResp.CredentialID
}

// TestModule_WebAuthnCredentialStoreDecorator_SeesSDKLaneRegistration is the
// go-xkms#350 regression at the composition boundary: a credential enrolled
// through the module's OWN SDK registration lane (what `xkey auth register`
// posts to) must pass through the host-supplied credential-store decorator.
// Before the seam existed the module's relying party wrote straight to the
// qrdb store, so the composer's registration side effects — on a composed
// node, the qrdb auth factor its unified login ceremony resolves — were
// never created for that surface.
func TestModule_WebAuthnCredentialStoreDecorator_SeesSDKLaneRegistration(t *testing.T) {
	var recorder *countingCredentialStore

	routes := selfBuiltModuleRoutes(t, WithWebAuthnCredentialStoreDecorator(
		func(inner webauthn.CredentialStore) webauthn.CredentialStore {
			require.NotNil(t, inner, "the decorator receives the qrdb-backed store")
			recorder = &countingCredentialStore{CredentialStore: inner}
			return recorder
		}))

	credID := registerThroughSDKLane(t, routes, "alice@example.com")
	assert.NotEmpty(t, credID)

	require.NotNil(t, recorder, "the module must apply the host's decorator when it self-builds the surface")
	assert.Equal(t, 1, recorder.count(),
		"a registration served by the module's own SDK lane must pass through the host's decorator")
}

// TestModule_WebAuthnCredentialStoreDecorator_UnsetLeavesCeremonyIntact pins
// the default: with no decorator configured the module's SDK registration
// lane behaves exactly as before — the ceremony completes against the
// qrdb-backed store the module derives for itself.
func TestModule_WebAuthnCredentialStoreDecorator_UnsetLeavesCeremonyIntact(t *testing.T) {
	routes := selfBuiltModuleRoutes(t)

	credID := registerThroughSDKLane(t, routes, "bob@example.com")
	assert.NotEmpty(t, credID, "registration completes with no decorator configured")
}

// TestModule_WebAuthnCredentialStoreDecorator_NilStoreFailsClosed proves a
// decorator that returns no store cannot yield a half-built surface: the
// WebAuthn relying party is not constructed at all, so the ceremony routes
// answer "not configured" instead of serving a relying party that cannot
// persist a passkey. That is the same disposition every other WebAuthn
// construction failure gets on the self-built surface (NewHostServer logs it
// and leaves the WebAuthn family unmounted); the rest of the surface —
// keys, certs, seal — still serves.
func TestModule_WebAuthnCredentialStoreDecorator_NilStoreFailsClosed(t *testing.T) {
	routes := selfBuiltModuleRoutes(t, WithWebAuthnCredentialStoreDecorator(
		func(webauthn.CredentialStore) webauthn.CredentialStore { return nil }))

	begin := routes["POST /api/v1/webauthn/sdk/registration/begin"]
	require.NotNil(t, begin, "routes are still registered so the failure is reported, not silently 404")

	body, err := json.Marshal(transport.BeginRegistrationRequest{Username: "carol@example.com"})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/sdk/registration/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	begin(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code,
		"a ceremony must not be served by a relying party built on a nil store; body: %s", w.Body.String())
	assert.NotContains(t, w.Body.String(), "session_id",
		"no ceremony session may be issued when the relying party was never built")
}
