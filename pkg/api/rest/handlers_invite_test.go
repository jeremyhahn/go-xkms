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
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	xkmstransport "github.com/jeremyhahn/go-xkms/pkg/api/transport"
	xkmswebauthn "github.com/jeremyhahn/go-xkms/pkg/webauthn"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// inviteHandlerFixture wires an XKMSService with a real invite store and a
// mock user client seeded with a single PENDING account, and mounts the
// invite routes on a chi router.
type inviteHandlerFixture struct {
	router      *chi.Mux
	inviteStore *qrdbsdk.TenantInviteStore
	userID      uint64
}

// token mints a fresh single-use token for the fixture's seeded account, so
// each test that consumes one (finish, activate) can mint its own.
func (f *inviteHandlerFixture) token(t *testing.T) string {
	t.Helper()
	tok, _, err := f.inviteStore.Create(context.Background(), "1", "", time.Hour)
	require.NoError(t, err)
	return tok
}

func setupInviteHandlerTest(t *testing.T) *inviteHandlerFixture {
	t.Helper()

	xkms.Reset()
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"mem": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "mem",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)
	t.Cleanup(func() { xkms.Reset() })

	const userID = uint64(1)
	const email = "invitee@example.com"
	qrdbUser := &qrdbtransport.User{ID: userID, Username: email, Email: email, Name: "Invitee", Lifecycle: string(qrdbsdk.LifecyclePending)}
	users := &restMockUserClient{
		getUser: func(_ context.Context, id uint64) (*qrdbtransport.User, error) {
			if id != userID {
				return nil, &qrdbtransport.UserNotFoundError{ID: id}
			}
			return qrdbUser, nil
		},
	}
	svc.SetUserClients(users, &restMockRoleClient{})

	inviteStore, err := qrdbsdk.NewTenantInviteStore(restSingleStoreResolver{store: qrdbsdk.NewMemoryKVStore()})
	require.NoError(t, err)
	svc.SetInviteStore(inviteStore)

	// A real WebAuthn service, over an in-memory user store seeded to agree
	// with the mock qrdb user client above (the two are logically the same
	// store in production; see pkg/xkms/servicer_invite_test.go's fixture
	// for why they are decoupled in tests).
	waUsers := xkmswebauthn.NewMemoryUserStore()
	waUser := xkmswebauthn.NewDefaultUser(xkmswebauthn.HandleFromUserID(userID), email, "Invitee")
	waUser.SetLifecycle(qrdbsdk.LifecyclePending)
	require.NoError(t, waUsers.Save(context.Background(), waUser))
	waSvc, err := xkmswebauthn.NewService(xkmswebauthn.ServiceParams{
		Config: &xkmswebauthn.Config{
			RPID: "example.com", RPDisplayName: "xkms test",
			RPOrigins: []string{"https://example.com"},
		},
		UserStore:       waUsers,
		SessionStore:    xkmswebauthn.NewMemorySessionStore(),
		CredentialStore: xkmswebauthn.NewMemoryCredentialStore(),
	})
	require.NoError(t, err)
	svc.SetWebAuthn(waSvc)

	s := &Server{xkmsService: svc}
	r := chi.NewRouter()
	r.Route("/invites", func(r chi.Router) {
		r.Get("/{tenant_id}/{token}", s.handleGetInvite)
		r.Post("/{tenant_id}/{token}/fido2/begin", s.handleInviteBeginFIDO2)
		r.Post("/{tenant_id}/{token}/fido2/finish", s.handleInviteFinishFIDO2)
		r.Post("/{tenant_id}/{token}/piv/activate", s.handleInviteActivatePIV)
	})

	return &inviteHandlerFixture{router: r, inviteStore: inviteStore, userID: userID}
}

func TestHandleGetInvite_Success(t *testing.T) {
	f := setupInviteHandlerTest(t)
	tok := f.token(t)

	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/invites/system/"+tok, nil))
	require.Equal(t, http.StatusOK, rr.Code)

	var meta xkmstransport.GetInviteResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &meta))
	assert.Equal(t, "invitee@example.com", meta.Email)
	assert.Equal(t, "Invitee", meta.DisplayName)
	assert.Contains(t, meta.Methods, "webauthn")
	assert.Contains(t, meta.Methods, "piv")
}

func TestHandleGetInvite_UnknownToken(t *testing.T) {
	f := setupInviteHandlerTest(t)

	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/invites/system/does-not-exist", nil))
	require.Equal(t, http.StatusNotFound, rr.Code)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, ErrorCodeInviteUnusable, resp.Error)
}

// TestHandleGetInvite_RedeemedTokenIsIndistinguishableFromUnknown is
// go-xkms#1294 part B's opacity requirement: a spent token answers exactly
// like a fabricated one.
func TestHandleGetInvite_RedeemedTokenIsIndistinguishableFromUnknown(t *testing.T) {
	f := setupInviteHandlerTest(t)
	tok := f.token(t)
	_, err := f.inviteStore.Redeem(context.Background(), "", tok)
	require.NoError(t, err)

	redeemedRR := httptest.NewRecorder()
	f.router.ServeHTTP(redeemedRR, httptest.NewRequest(http.MethodGet, "/invites/system/"+tok, nil))
	unknownRR := httptest.NewRecorder()
	f.router.ServeHTTP(unknownRR, httptest.NewRequest(http.MethodGet, "/invites/system/never-existed", nil))

	assert.Equal(t, unknownRR.Code, redeemedRR.Code)
	assert.Equal(t, unknownRR.Body.String(), redeemedRR.Body.String())
}

func TestHandleGetInvite_NotConfigured(t *testing.T) {
	xkms.Reset()
	t.Cleanup(func() { xkms.Reset() })
	s := &Server{}
	r := chi.NewRouter()
	r.Get("/invites/{tenant_id}/{token}", s.handleGetInvite)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/invites/system/tok", nil))
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestHandleInviteBeginFIDO2_UnusableToken(t *testing.T) {
	f := setupInviteHandlerTest(t)

	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/invites/system/does-not-exist/fido2/begin", nil))
	require.Equal(t, http.StatusNotFound, rr.Code)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, ErrorCodeInviteUnusable, resp.Error)
}

// TestHandleInviteBeginFIDO2_Success proves the full path from a minted
// token to a returned WebAuthn ceremony for the pending account it names.
func TestHandleInviteBeginFIDO2_Success(t *testing.T) {
	f := setupInviteHandlerTest(t)
	tok := f.token(t)

	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/invites/system/"+tok+"/fido2/begin", nil))
	require.Equal(t, http.StatusOK, rr.Code)

	var resp struct {
		SessionID   string `json:"session_id"`
		OptionsJSON string `json:"options_json"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.SessionID)
	assert.Contains(t, resp.OptionsJSON, "invitee@example.com")
}

// TestHandleInviteBeginFIDO2_NoWebAuthnConfigured proves the handler answers
// a wiring gap (no WebAuthn subsystem) with a scrubbed 503, not a 200 or a
// leaked internal error, even for an otherwise-valid token.
func TestHandleInviteBeginFIDO2_NoWebAuthnConfigured(t *testing.T) {
	xkms.Reset()
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"mem": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "mem",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)
	t.Cleanup(func() { xkms.Reset() })
	svc.SetUserClients(&restMockUserClient{}, &restMockRoleClient{})
	inviteStore, err := qrdbsdk.NewTenantInviteStore(restSingleStoreResolver{store: qrdbsdk.NewMemoryKVStore()})
	require.NoError(t, err)
	svc.SetInviteStore(inviteStore)
	tok, _, err := inviteStore.Create(context.Background(), "1", "", time.Hour)
	require.NoError(t, err)

	s := &Server{xkmsService: svc}
	r := chi.NewRouter()
	r.Post("/invites/{tenant_id}/{token}/fido2/begin", s.handleInviteBeginFIDO2)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/invites/system/"+tok+"/fido2/begin", nil))
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestHandleInviteFinishFIDO2_MissingFields(t *testing.T) {
	f := setupInviteHandlerTest(t)
	tok := f.token(t)

	rr := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{})
	f.router.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/invites/system/"+tok+"/fido2/finish", bytes.NewReader(body)))
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleInviteActivatePIV_MissingCertPEM(t *testing.T) {
	f := setupInviteHandlerTest(t)
	tok := f.token(t)

	rr := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{})
	f.router.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/invites/system/"+tok+"/piv/activate", bytes.NewReader(body)))
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestHandleInviteActivatePIV_NotConfigured proves the handler answers a
// wiring gap (no CA configured) with a scrubbed 503, for an otherwise
// well-formed request against a valid token: the handler's own cert_pem
// presence check passes, and it is the service's CA check that refuses.
func TestHandleInviteActivatePIV_NotConfigured(t *testing.T) {
	f := setupInviteHandlerTest(t)
	tok := f.token(t)

	rr := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"cert_pem": "not-empty"})
	f.router.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/invites/system/"+tok+"/piv/activate", bytes.NewReader(body)))
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}
