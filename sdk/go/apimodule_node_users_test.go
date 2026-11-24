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

package xkms

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbserver "github.com/jeremyhahn/go-qrdb/sdk/go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/barriertest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/hostdeps"
	pkgxkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// countingNodeUsers is a node user source over a real node that counts how
// often the module consults it.
type countingNodeUsers struct {
	inner ServiceModuleNodeUserSource
	calls atomic.Int32
}

func (c *countingNodeUsers) UserService() qrdbsdk.UserServicer {
	c.calls.Add(1)
	return c.inner.UserService()
}

// registrationBegin builds a self-hosted module over an authentication-
// enforcing node with the given extra options and posts a WebAuthn
// registration begin to it.
func registrationBegin(t *testing.T, extra func(node ServiceModuleNodeUserSource) []ServiceModuleOption) *httptest.ResponseRecorder {
	t.Helper()
	svc := hostdeps.NewService(t)
	node := barriertest.NewPrincipalNode(t)
	opts := extra(node)
	allow := true
	base := []ServiceModuleOption{
		WithServiceModuleQRDBClient(func() *qrdbsdk.Client { return node.Client() }),
		WithServiceModuleServiceContext(node.ServiceContext),
		WithServiceModuleWebAuthn(&config.WebAuthnConfig{
			RPID:                    "example.com",
			RPOrigins:               []string{"https://example.com"},
			AllowPublicRegistration: &allow,
		}),
	}
	module, err := NewServiceModule(func() *pkgxkms.XKMSService { return svc }, append(base, opts...)...)
	require.NoError(t, err)

	mux := chi.NewRouter()
	gate := func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
	module.RegisterHTTP(qrdbserver.NewModuleHTTPRegistrar(mux,
		func(method, pattern string, _ qrdbsdk.Permission, _ http.HandlerFunc) {
			mux.MethodFunc(method, pattern, gate)
		},
		func(method, pattern string, h http.HandlerFunc) { mux.MethodFunc(method, pattern, h) },
		func(method, pattern string, h http.HandlerFunc) { mux.MethodFunc(method, pattern, h) }))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/registration/begin",
		bytes.NewReader([]byte(`{"email":"passkey-user@example.com","display_name":"Passkey User"}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

// TestWithServiceModuleNodeUsers_WiresNodeUserSource proves a host building
// on the SDK can hand the embedded node's user service to the module, so the
// public WebAuthn routes resolve users through it. Anonymous registration of
// a nonexistent account is refused (403): the user is created through the
// authorized client and the xkms service principal holds no users:create
// grant; accounts are provisioned by an
// administrator and enrolled by invitation.
func TestWithServiceModuleNodeUsers_WiresNodeUserSource(t *testing.T) {
	users := &countingNodeUsers{}
	w := registrationBegin(t, func(node ServiceModuleNodeUserSource) []ServiceModuleOption {
		users.inner = node
		return []ServiceModuleOption{WithServiceModuleNodeUsers(users)}
	})
	require.Equal(t, http.StatusForbidden, w.Code, "registration/begin: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "registration_refused")
	assert.Positive(t, users.calls.Load(), "the module must resolve users through the wired source")
}

// TestWithServiceModuleNodeUsers_UnsetLeavesNone is the negative case: a
// module built without the option never consults the source.
func TestWithServiceModuleNodeUsers_UnsetLeavesNone(t *testing.T) {
	users := &countingNodeUsers{}
	registrationBegin(t, func(node ServiceModuleNodeUserSource) []ServiceModuleOption {
		users.inner = node
		return nil
	})
	assert.Zero(t, users.calls.Load())
}
