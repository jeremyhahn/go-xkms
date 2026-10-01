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
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/compose"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/hostdeps"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/vaulttest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// hostAdmin is the system-tenant operator the host's unified server would
// have authenticated; the platform-scoped features refuse anyone else.
var hostAdmin = &auth.Identity{Subject: "admin", TenantID: qrdbsdk.SystemTenantID, Roles: []string{"admin"}}

// hostSOPIN and hostUserPIN are provisioned on the host's PIN backend; the
// user PIN opens a tenant Password Manager session.
const (
	hostSOPIN   = "so-pin-123456"
	hostUserPIN = "user-pin-654321"
)

// tenantUser is a user of the host tenant "acme", whose Password Manager
// entries live behind acme's own barrier.
var tenantUser = &auth.Identity{Subject: "alice", TenantID: "acme", Roles: []string{"user"}}

// hostMount is the module mounted the way an embedding host mounts it: no
// WithRESTServer, so the module self-builds its surface from host inputs.
type hostMount struct {
	module   *Module
	routes   *[]captured
	svc      *xkms.XKMSService
	registry *seal.BarrierRegistry
}

// mountLikeHost builds the module over a software-backed XKMSService and a
// qrdb client, adds opts, and registers its HTTP surface.
func mountLikeHost(t *testing.T, client *qrdbsdk.Client, opts ...Option) *hostMount {
	t.Helper()
	svc := hostdeps.NewService(t)
	registry := hostdeps.NewBarrierRegistry(t)
	all := append([]Option{WithQRDBClient(func() *qrdbsdk.Client { return client })}, opts...)
	m, err := NewModule(func() *xkms.XKMSService { return svc }, all...)
	require.NoError(t, err)
	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)
	return &hostMount{module: m, routes: recs, svc: svc, registry: registry}
}

// fullHostOptions supplies every dependency the host composition accepts.
func (h *hostMount) fullHostOptions(t *testing.T) []Option {
	return []Option{
		WithBarrierRegistry(func() *qrdbsdk.BarrierRegistry { return h.registry.Inner() }),
		WithPINBackend(hostdeps.NewPINBackend(t, hostSOPIN, hostUserPIN)),
		WithPlatformSealer("passphrase", hostdeps.NewSealer(t)),
		WithCA(hostdeps.NewCAConfig("Host Mount Root")),
		WithPasswordVaultRelyingParty(vaulttest.RelyingParty),
	}
}

// newFullHostMount mounts the module with every host dependency supplied.
func newFullHostMount(t *testing.T, extra ...Option) *hostMount {
	t.Helper()
	client, _, err := testutil.NewQRDBFakeClient()
	require.NoError(t, err)
	return newFullHostMountWithClient(t, client, extra...)
}

func newFullHostMountWithClient(t *testing.T, client *qrdbsdk.Client, extra ...Option) *hostMount {
	t.Helper()
	// The registry must exist before the options that resolve it, so the
	// mount is built in two steps sharing one service and registry.
	svc := hostdeps.NewService(t)
	h := &hostMount{svc: svc, registry: hostdeps.NewBarrierRegistry(t)}
	hostdeps.RegisterTenant(t, h.registry, tenantUser.TenantID)
	opts := append([]Option{WithQRDBClient(func() *qrdbsdk.Client { return client })}, h.fullHostOptions(t)...)
	opts = append(opts, extra...)
	m, err := NewModule(func() *xkms.XKMSService { return svc }, opts...)
	require.NoError(t, err)
	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)
	h.module, h.routes = m, recs
	return h
}

// call invokes the registered route method+pattern at path as hostAdmin,
// with chi URL parameters, the way the host's unified server dispatches it.
func (h *hostMount) call(t *testing.T, method, pattern, path string, params map[string]string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return h.callAs(t, hostAdmin, method, pattern, path, params, body)
}

// callAs is call with an explicit caller.
func (h *hostMount) callAs(t *testing.T, id *auth.Identity, method, pattern, path string, params map[string]string, body any) *httptest.ResponseRecorder {
	t.Helper()
	handler := findRoute(t, h.routes, method, pattern)
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = auth.WithIdentity(ctx, id)
	w := httptest.NewRecorder()
	handler(w, req.WithContext(ctx))
	return w
}

// registered reports whether method+pattern was registered.
func (h *hostMount) registered(method, pattern string) bool {
	for _, rec := range *h.routes {
		if rec.method == method && rec.pattern == pattern {
			return true
		}
	}
	return false
}

// TestModule_HostMount_EveryStoreAnswers is the host-mode acceptance test:
// mounted the way go-quicbaas mounts it, with the host's qrdb client,
// barrier registry, a platform sealer and a CA configuration, the Password
// Manager, SSH, CA and platform store routes all serve real requests instead
// of 404/501, and the gRPC surface sees the same composition. The TPM policy
// routes answer 503 here: the host's service has no TPM2 backend.
func TestModule_HostMount_EveryStoreAnswers(t *testing.T) {
	h := newFullHostMount(t)

	t.Run("passwords", func(t *testing.T) {
		// The caller's personal vault is initialized by enrolling a passkey,
		// which returns the recovery code and opens the session ...
		passkey := vaulttest.Passkey(tenantUser.Subject)
		w := h.callAs(t, tenantUser, http.MethodPost, "/api/v1/password-vault/factors", "/api/v1/password-vault/factors", nil, passkey)
		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
		var enrolled transport.PasswordVaultEnrollResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &enrolled))
		assert.NotEmpty(t, enrolled.RecoveryCode)

		// ... and, once locked, reopens with that passkey ...
		w = h.callAs(t, tenantUser, http.MethodPost, "/api/v1/password-vault/lock", "/api/v1/password-vault/lock", nil, nil)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		w = h.callAs(t, tenantUser, http.MethodPost, "/api/v1/password-vault/unlock", "/api/v1/password-vault/unlock", nil, passkey)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		// ... and the entry is routed to the tenant's store behind its own
		// barrier (WithBarrierRegistry), not to a process-wide store.
		w = h.callAs(t, tenantUser, http.MethodPost, "/api/v1/passwords/", "/api/v1/passwords/", nil,
			rest.PasswordAddRequest{Name: "gitea", Username: "agent", Password: "s3cret-Passw0rd!"})
		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

		w = h.callAs(t, tenantUser, http.MethodGet, "/api/v1/passwords/", "/api/v1/passwords/", nil, nil)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var list rest.PasswordListResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
		require.Equal(t, 1, list.Total)
		assert.Equal(t, "gitea", list.Passwords[0].Name)
	})

	t.Run("ssh", func(t *testing.T) {
		w := h.call(t, http.MethodGet, "/xkms/v1/ssh/keys", "/xkms/v1/ssh/keys", nil, nil)
		assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	})

	t.Run("ca", func(t *testing.T) {
		w := h.call(t, http.MethodGet, "/api/v1/ca/certificate", "/api/v1/ca/certificate", nil, nil)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), "Host Mount Root")
	})

	t.Run("platform store", func(t *testing.T) {
		params := map[string]string{"name": "db-pin"}
		secret := base64.StdEncoding.EncodeToString([]byte("1234"))
		w := h.call(t, http.MethodPut, "/api/v1/platform/secrets/{name}", "/api/v1/platform/secrets/db-pin",
			params, rest.SealStorePutRequest{Secret: secret})
		require.Less(t, w.Code, 300, w.Body.String())

		w = h.call(t, http.MethodGet, "/api/v1/platform/secrets/{name}", "/api/v1/platform/secrets/db-pin", params, nil)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var got rest.SealStoreGetResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
		assert.Equal(t, secret, got.Secret)
	})

	t.Run("tpm policies need a TPM2 backend", func(t *testing.T) {
		w := h.call(t, http.MethodGet, "/api/v1/tpm/policies", "/api/v1/tpm/policies", nil, nil)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
	})

	t.Run("credentials", func(t *testing.T) {
		w := h.call(t, http.MethodGet, "/api/v1/credentials/strategy", "/api/v1/credentials/strategy", nil, nil)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), "manual")
	})

	t.Run("grpc sees the same composition", func(t *testing.T) {
		client := startBufconnModule(t, h.module)
		resp, err := client.GetCACertificate(context.Background(), &pb.GetCACertificateRequest{})
		require.NoError(t, err)
		assert.Contains(t, resp.Subject, "Host Mount Root")
	})

	// The host's service has no TPM2 backend (the simulator tests in
	// pkg/compose cover that composition), and the fake qrdb transport
	// carries no coordination (leases), which the OIDC credential service
	// needs (pkg/compose covers it over a real node). Those two are off,
	// each with its typed reason; every other feature is on.
	stores := h.module.HostStores()
	require.NotNil(t, stores)
	missing := map[compose.Feature]string{}
	for _, reason := range stores.Disabled {
		var disabled *compose.FeatureDisabledError
		require.ErrorAs(t, reason, &disabled)
		missing[disabled.Feature] = disabled.Missing
	}
	assert.Equal(t, map[compose.Feature]string{
		compose.FeatureTPMPolicies:     "TPM2 backend",
		compose.FeatureOIDCCredentials: "qrdb coordination",
	}, missing)
}

// TestModule_HostMount_MissingDependenciesAreTypedAndOff proves a host that
// supplies only its qrdb client gets the storage-only features, and every
// feature it did not supply a dependency for is off with a typed reason and
// answers "not configured" or "not enabled" — never a silent 404.
func TestModule_HostMount_MissingDependenciesAreTypedAndOff(t *testing.T) {
	client, _, err := testutil.NewQRDBFakeClient()
	require.NoError(t, err)
	h := mountLikeHost(t, client)

	// First use composes: the Password Manager and SSH need only storage.
	w := h.call(t, http.MethodGet, "/xkms/v1/ssh/keys", "/xkms/v1/ssh/keys", nil, nil)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())

	stores := h.module.HostStores()
	require.NotNil(t, stores)
	missing := map[compose.Feature]string{}
	for _, reason := range stores.Disabled {
		var disabled *compose.FeatureDisabledError
		require.ErrorAs(t, reason, &disabled)
		missing[disabled.Feature] = disabled.Missing
	}
	assert.Equal(t, map[compose.Feature]string{
		compose.FeatureTenantPasswords: "barrier registry",
		compose.FeaturePIN:             "PIN backend",
		compose.FeaturePlatformStore:   "platform sealer",
		compose.FeatureCA:              "CA configuration",
		compose.FeatureTPMPolicies:     "TPM2 backend",
		compose.FeatureOIDCCredentials: "barrier registry",
	}, missing)

	w = h.call(t, http.MethodGet, "/api/v1/ca/certificate", "/api/v1/ca/certificate", nil, nil)
	assert.Equal(t, http.StatusNotImplemented, w.Code, "no CA is composed, so the CA subsystem is absent")

	w = h.call(t, http.MethodGet, "/api/v1/platform/status", "/api/v1/platform/status", nil, nil)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())

	w = h.call(t, http.MethodGet, "/api/v1/tpm/policies", "/api/v1/tpm/policies", nil, nil)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
}

// TestModule_HostMount_NoQRDBClientLeavesStoresOff proves the store-backed
// features have no storage without the host's qrdb client and say so.
func TestModule_HostMount_NoQRDBClientLeavesStoresOff(t *testing.T) {
	svc := hostdeps.NewService(t)
	m, err := NewModule(func() *xkms.XKMSService { return svc })
	require.NoError(t, err)
	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)
	h := &hostMount{module: m, routes: recs, svc: svc}

	w := h.call(t, http.MethodGet, "/api/v1/passwords/", "/api/v1/passwords/", nil, nil)
	assert.Equal(t, http.StatusNotImplemented, w.Code)

	var reasons []string
	for _, reason := range m.HostStores().Disabled {
		reasons = append(reasons, reason.Error())
	}
	assert.Contains(t, strings.Join(reasons, "\n"), "compose: passwords is off: no storage was supplied")
}

// TestModule_BarrierRoutes_OffByDefault proves a host that did not opt in
// keeps the barrier route families: the module registers none of them, so
// the host can own those paths.
func TestModule_BarrierRoutes_OffByDefault(t *testing.T) {
	h := newFullHostMount(t)
	for _, spec := range rest.Routes() {
		if rest.IsBarrierRoute(spec) {
			assert.False(t, h.registered(spec.Method, spec.Pattern), "%s %s must not be mounted", spec.Method, spec.Pattern)
		}
	}
	assert.True(t, h.registered(http.MethodGet, "/api/v1/passwords/"), "non-barrier routes still mount")

	// The host's barrier registry still backs the per-tenant Password
	// Manager; it is simply not served.
	h.call(t, http.MethodGet, "/xkms/v1/ssh/keys", "/xkms/v1/ssh/keys", nil, nil)
	stores := h.module.HostStores()
	assert.NotNil(t, stores.PasswordManager)
	assert.Nil(t, stores.Barrier)
}

// custodyTransport is the fake qrdb transport plus the custody capability a
// real node transport carries, so the host's client can hand the module its
// custodian and share clients. Only the capability matters here; no custody
// call is made.
type custodyTransport struct {
	*testutil.QRDBFakeTransport
	qrdbtransport.CustodianGroupClient
	qrdbtransport.ShareClient
}

// TestModule_BarrierRoutes_ServeTheHostBarrier proves WithBarrierRoutes
// mounts the barrier families and serves them over the host's own qrdb
// barrier: the status reflects the host's initialized, unsealed barrier.
func TestModule_BarrierRoutes_ServeTheHostBarrier(t *testing.T) {
	client, err := qrdbsdk.NewClient(&custodyTransport{QRDBFakeTransport: testutil.NewQRDBFakeTransport()})
	require.NoError(t, err)
	h := newFullHostMountWithClient(t, client, WithBarrierRoutes())

	for _, spec := range rest.Routes() {
		if rest.IsBarrierRoute(spec) {
			assert.True(t, h.registered(spec.Method, spec.Pattern), "%s %s must be mounted", spec.Method, spec.Pattern)
		}
	}

	w := h.call(t, http.MethodGet, "/api/v1/barrier/status", "/api/v1/barrier/status", nil, nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"sealed":false`)

	stores := h.module.HostStores()
	assert.Same(t, h.registry.SystemBarrier(), stores.Barrier)
	assert.NotNil(t, stores.Custodians)
	assert.NotNil(t, stores.Shares)
}

// TestModule_BarrierRoutes_WithoutRegistryIsTypedOff proves opting in
// without supplying the barrier leaves the barrier off with a typed reason.
func TestModule_BarrierRoutes_WithoutRegistryIsTypedOff(t *testing.T) {
	client, err := qrdbsdk.NewClient(&custodyTransport{QRDBFakeTransport: testutil.NewQRDBFakeTransport()})
	require.NoError(t, err)
	h := mountLikeHost(t, client, WithBarrierRoutes())

	w := h.call(t, http.MethodGet, "/api/v1/barrier/status", "/api/v1/barrier/status", nil, nil)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())

	var disabled *compose.FeatureDisabledError
	found := false
	for _, reason := range h.module.HostStores().Disabled {
		if assert.ErrorAs(t, reason, &disabled) && disabled.Feature == compose.FeatureBarrier {
			found = true
			assert.Equal(t, "barrier registry", disabled.Missing)
		}
	}
	assert.True(t, found, "the barrier's absence must be recorded")
}
