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

package rest

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/keypolicy"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// newKeyManagementRESTFixture extends the key version fixture with the key
// policy store, the backend and safety routes, an ECDSA key "signer" and an
// AES-256-GCM key "aead".
func newKeyManagementRESTFixture(t *testing.T) *keyVersionRESTFixture {
	t.Helper()
	f := newKeyVersionRESTFixture(t)
	store, err := keypolicy.NewStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	f.svc.SetKeyPolicyStore(store)

	server := &Server{handlers: f.handlers()}
	for _, spec := range Routes() {
		if strings.HasPrefix(spec.Pattern, "/api/v1/backend/") || strings.HasPrefix(spec.Pattern, "/api/v1/safety/") {
			f.router.Method(spec.Method, spec.Pattern, spec.Handler(server))
		}
	}
	f.generate("signer", "ecdsa")
	f.generate("aead", "aes-256-gcm")
	return f
}

// handlers returns a handler context over the fixture's service.
func (f *keyVersionRESTFixture) handlers() *HandlerContext {
	h := NewHandlerContext("1.0.0")
	h.SetXKMSService(f.svc)
	return h
}

// TestKeyManagementREST_ClientMeetsServer drives every key management RPC
// through the wire client against the server's routes and the real service.
func TestKeyManagementREST_ClientMeetsServer(t *testing.T) {
	f := newKeyManagementRESTFixture(t)
	ctx := context.Background()
	c := wire.KeyManagementClient{Do: f.do}
	signer := &transport.KeyManagementRequest{Backend: "software", KeyID: "signer"}
	aead := &transport.KeyManagementRequest{Backend: "software", KeyID: "aead"}

	pub, err := c.GetPublicKey(ctx, &transport.GetPublicKeyRequest{Backend: "software", KeyID: "signer", Version: 1})
	require.NoError(t, err)
	_, err = x509.ParsePKIXPublicKey(pub.PublicKey)
	require.NoError(t, err)

	status, err := c.UpdateKeyStatus(ctx, &transport.UpdateKeyStatusRequest{Backend: "software", KeyID: "signer", Status: transport.KeyStatusDisabled})
	require.NoError(t, err)
	assert.Equal(t, transport.KeyStatusDisabled, status.Status)

	_, err = c.UpdateKeyMetadata(ctx, &transport.UpdateKeyMetadataRequest{Backend: "software", KeyID: "signer", Name: "Signer", Tags: map[string]string{"env": "prod"}})
	require.NoError(t, err)
	meta, err := c.GetKeyMetadata(ctx, signer)
	require.NoError(t, err)
	assert.Equal(t, "Signer", meta.Metadata.Name)
	assert.Equal(t, transport.KeyStatusDisabled, meta.Metadata.Status)

	set, err := c.SetKeyPolicy(ctx, &transport.SetKeyPolicyRequest{Backend: "software", KeyID: "signer", Policy: &transport.KeyPolicy{MaxUsageCount: 5}})
	require.NoError(t, err)
	assert.Equal(t, uint64(1), set.PolicyVersion)
	policy, err := c.GetKeyPolicy(ctx, signer)
	require.NoError(t, err)
	require.NotNil(t, policy.Policy)
	_, err = c.DeleteKeyPolicy(ctx, signer)
	require.NoError(t, err)

	rotation, err := c.SetKeyRotationPolicy(ctx, &transport.SetKeyRotationPolicyRequest{Backend: "software", KeyID: "signer", Policy: &transport.RotationPolicy{Enabled: true, IntervalSeconds: 60}})
	require.NoError(t, err)
	require.NotNil(t, rotation.Policy)
	got, err := c.GetKeyRotationPolicy(ctx, signer)
	require.NoError(t, err)
	require.NotNil(t, got.Policy)
	_, err = c.DeleteKeyRotationPolicy(ctx, signer)
	require.NoError(t, err)

	_, err = c.SetKeySafety(ctx, &transport.SetKeySafetyRequest{Backend: "software", KeyID: "aead", MaxOperations: 100})
	require.NoError(t, err)
	report, err := c.SafetyReport(ctx, &transport.SafetyReportRequest{Format: "json"})
	require.NoError(t, err)
	assert.Len(t, report.AllItems, 1)
	_, err = c.SafetyCheck(ctx, &transport.SafetyCheckRequest{})
	require.NoError(t, err)
	_, err = c.ClearKeySafety(ctx, aead)
	require.NoError(t, err)

	backend := &transport.BackendRequest{Backend: "software"}
	algorithms, err := c.GetSupportedAlgorithms(ctx, backend)
	require.NoError(t, err)
	assert.Contains(t, algorithms.Algorithms, transport.KeyAlgorithmAES256GCM)
	backendStatus, err := c.BackendStatus(ctx, backend)
	require.NoError(t, err)
	assert.NotEmpty(t, backendStatus.Status)
	// BackendTest exercises the default sealing key; the first Seal creates it.
	_, err = f.svc.Seal(ctx, &transport.SealRequest{Backend: "software", Data: []byte("first seal")})
	require.NoError(t, err)
	trip, err := c.BackendTest(ctx, backend)
	require.NoError(t, err)
	assert.True(t, trip.Success, trip.Message)

	revoked, err := c.RevokeKey(ctx, &transport.RevokeKeyRequest{Backend: "software", KeyID: "signer", Reason: "retired"})
	require.NoError(t, err)
	assert.Equal(t, transport.KeyStatusCompromised, revoked.Status)
}

// TestKeyManagementREST_MapsErrors proves the refusals reach the caller as
// the HTTP status their class promises.
func TestKeyManagementREST_MapsErrors(t *testing.T) {
	f := newKeyManagementRESTFixture(t)
	tests := []struct {
		name, method, path, body string
		status                   int
	}{
		{"symmetric public key", http.MethodGet, "/api/v1/keys/aead/public-key?backend=software", "", http.StatusBadRequest},
		{"public key version not a number", http.MethodGet, "/api/v1/keys/signer/public-key?backend=software&version=x", "", http.StatusBadRequest},
		{"missing key", http.MethodGet, "/api/v1/keys/ghost/metadata?backend=software", "", http.StatusNotFound},
		{"require mfa", http.MethodPut, "/api/v1/keys/signer/policy", `{"backend":"software","policy":{"require_mfa":true}}`, http.StatusNotImplemented},
		{"auto rotate", http.MethodPut, "/api/v1/keys/signer/rotation-policy", `{"backend":"software","policy":{"auto_rotate":true}}`, http.StatusNotImplemented},
		{"gcm limit", http.MethodPut, "/api/v1/keys/aead/safety", `{"backend":"software","max_operations":4294967297}`, http.StatusBadRequest},
		{"report format", http.MethodGet, "/api/v1/safety/report?format=xml", "", http.StatusBadRequest},
		{"malformed body", http.MethodPost, "/api/v1/keys/signer/status", `{`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := f.serve(tt.method, tt.path, tt.body)
			assert.Equal(t, tt.status, w.Code, w.Body.String())
		})
	}

	w := f.serve(http.MethodPost, "/api/v1/keys/signer/revoke", `{"backend":"software"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = f.serve(http.MethodPost, "/api/v1/keys/signer/status", `{"backend":"software","status":"enabled"}`)
	assert.Equal(t, http.StatusConflict, w.Code, "a revoked key stays revoked: %s", w.Body.String())

	f.svc.SetKeyPolicyStore(nil)
	w = f.serve(http.MethodPut, "/api/v1/keys/aead/safety", `{"backend":"software","max_operations":10}`)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
}

// TestKeyManagementREST_NoService proves every key management handler
// answers 503 before the service is set.
func TestKeyManagementREST_NoService(t *testing.T) {
	h := NewHandlerContext("1.0.0")
	r := chi.NewRouter()
	r.Get("/api/v1/keys/{id}/public-key", h.GetPublicKeyHandler)
	r.Get("/api/v1/keys/{id}/policy", h.GetKeyPolicyHandler)
	r.Put("/api/v1/keys/{id}/safety", h.SetKeySafetyHandler)
	r.Get("/api/v1/backend/status", h.BackendStatusHandler)
	r.Post("/api/v1/backend/test", h.BackendTestHandler)
	r.Get("/api/v1/safety/report", h.SafetyReportHandler)
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/api/v1/keys/k/public-key", nil),
		httptest.NewRequest(http.MethodGet, "/api/v1/keys/k/policy", nil),
		httptest.NewRequest(http.MethodPut, "/api/v1/keys/k/safety", strings.NewReader(`{"max_operations":1}`)),
		httptest.NewRequest(http.MethodGet, "/api/v1/backend/status", nil),
		httptest.NewRequest(http.MethodPost, "/api/v1/backend/test", strings.NewReader(`{}`)),
		httptest.NewRequest(http.MethodGet, "/api/v1/safety/report", nil),
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code, req.URL.Path)
	}
}
