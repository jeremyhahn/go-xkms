// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package apimodule

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/barriertest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// nodeHostedModule composes the module's own REST host (no WithRESTServer)
// over an embedded go-qrdb node that enforces authentication, the way a
// host that embeds a node wires it, and mounts its routes on a router.
func nodeHostedModule(t *testing.T, opts ...Option) (*Module, *xkms.XKMSService, http.Handler) {
	t.Helper()

	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "test",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	node := barriertest.NewPrincipalNode(t)
	allow := true
	base := []Option{
		WithQRDBClient(func() *qrdbsdk.Client { return node.Client() }),
		WithServiceContext(node.ServiceContext),
		WithWebAuthnConfig(&config.WebAuthnConfig{
			RPID:                    "example.com",
			RPOrigins:               []string{"https://example.com"},
			AllowPublicRegistration: &allow,
		}),
		WithNodeUsers(node),
	}
	m, err := NewModule(func() *xkms.XKMSService { return svc }, append(base, opts...)...)
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)
	router := chi.NewRouter()
	for _, rec := range *recs {
		router.Method(rec.method, rec.pattern, rec.handler)
	}
	return m, svc, router
}

func serveJSON(t *testing.T, h http.Handler, method, path string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	raw := []byte("{}")
	if payload != nil {
		var err error
		raw, err = json.Marshal(payload)
		require.NoError(t, err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// TestModuleHost_NodeUsers_WebAuthnBeginOverAuthNode is ruling 973 on the
// apimodule host path: without WithNodeUsers the ceremony's user lookup ran
// through the node client with the anonymous request context and answered
// 500 "qrdb/auth: unauthenticated".
func TestModuleHost_NodeUsers_WebAuthnBeginOverAuthNode(t *testing.T) {
	_, _, h := nodeHostedModule(t)

	w := serveJSON(t, h, http.MethodPost, "/api/v1/webauthn/registration/begin", map[string]string{
		"email":        "passkey-user@example.com",
		"display_name": "Passkey User",
	})
	require.Equal(t, http.StatusOK, w.Code, "registration/begin: %s", w.Body.String())
}

// TestModuleHost_NodeUsers_FreshInviteRedeemsOverAuthNode is ruling 973 on
// the apimodule host path: without WithNodeUsers a fresh invite's user read
// ran with the anonymous request context and the invite answered 404.
func TestModuleHost_NodeUsers_FreshInviteRedeemsOverAuthNode(t *testing.T) {
	m, svc, h := nodeHostedModule(t)

	// The first request builds the host (and composes its stores).
	w := serveJSON(t, h, http.MethodGet, "/api/v1/invites/"+qrdbsdk.SystemTenantID+"/not-a-token", nil)
	require.NotEqual(t, http.StatusInternalServerError, w.Code, w.Body.String())
	stores := m.HostStores()
	require.NotNil(t, stores, "the module host composes its stores on first use")
	require.NotNil(t, stores.Invite, "invite store: %v", stores.Disabled)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	users := auth.NewNodeUserClient(m.nodeUsers)
	user, err := users.CreateUser(ctx, &qrdbtransport.CreateUserRequest{
		Username:             "invitee",
		Email:                "invitee@example.com",
		Name:                 "Invitee",
		WithoutEmailLoginKey: true,
	})
	require.NoError(t, err)
	token, _, err := stores.Invite.Create(ctx, strconv.FormatUint(user.ID, 10), qrdbsdk.SystemTenantID, time.Hour)
	require.NoError(t, err)
	require.NotNil(t, svc)

	w = serveJSON(t, h, http.MethodGet, "/api/v1/invites/"+qrdbsdk.SystemTenantID+"/"+token, nil)
	require.Equal(t, http.StatusOK, w.Code, "fresh invite lookup: %s", w.Body.String())

	w = serveJSON(t, h, http.MethodPost, "/api/v1/invites/"+qrdbsdk.SystemTenantID+"/"+token+"/fido2/begin", nil)
	require.Equal(t, http.StatusOK, w.Code, "fresh invite fido2/begin: %s", w.Body.String())
}
