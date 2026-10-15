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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// serveTrustRoots sends method path with body as a caller of tenant through
// every trust-root route of the route table, over svc.
func serveTrustRoots(t *testing.T, svc *xkms.XKMSService, tenant, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	server := &Server{trustRootHandlers: NewTrustRootHandlers(svc)}
	r := chi.NewRouter()
	identity := &auth.Identity{Subject: "admin@" + tenant, TenantID: tenant, Roles: []string{"admin"}}
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(auth.WithIdentity(req.Context(), identity)))
		})
	})
	for _, spec := range Routes() {
		if spec.Resource == auth.ResourceTrustRoots {
			r.Method(spec.Method, spec.Pattern, spec.Handler(server))
		}
	}
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(method, path, reader))
	return w
}

// newTrustRootRESTService returns a service over an in-memory trust-root
// store.
func newTrustRootRESTService(t *testing.T) *xkms.XKMSService {
	t.Helper()
	store, err := truststore.NewDAOStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	svc := &xkms.XKMSService{}
	svc.SetTrustRootStore(store)
	return svc
}

// trustRootImportBody returns an import request body carrying a fresh
// self-signed CA certificate classified as purpose.
func trustRootImportBody(t *testing.T, purpose string) string {
	t.Helper()
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)
	body, err := json.Marshal(transport.TrustRootImportRequest{PEM: string(ca.CertPEM), Purpose: purpose})
	require.NoError(t, err)
	return string(body)
}

// TestTrustRootREST_ServesTheStore proves the routes import, list, get,
// quarantine and remove a root through the store.
func TestTrustRootREST_ServesTheStore(t *testing.T) {
	svc := newTrustRootRESTService(t)
	sys := qrdbsdk.SystemTenantID

	w := serveTrustRoots(t, svc, sys, http.MethodPost, "/api/v1/trust-roots", trustRootImportBody(t, string(truststore.PurposeUserCA)))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var imported transport.TrustRootImportResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &imported))
	assert.Equal(t, 1, imported.Added)

	w = serveTrustRoots(t, svc, sys, http.MethodGet, "/api/v1/trust-roots?purpose=user-ca", "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var list transport.TrustRootListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	require.Len(t, list.Roots, 1)
	fp := list.Roots[0].Fingerprint

	w = serveTrustRoots(t, svc, sys, http.MethodGet, "/api/v1/trust-roots/"+fp, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var root transport.TrustRoot
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &root))
	assert.Contains(t, root.PEM, "BEGIN CERTIFICATE")

	w = serveTrustRoots(t, svc, sys, http.MethodPost, "/api/v1/trust-roots/"+fp+"/quarantine", "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &root))
	assert.Equal(t, string(truststore.PurposeSynced), root.Purpose)

	w = serveTrustRoots(t, svc, sys, http.MethodDelete, "/api/v1/trust-roots/"+fp, "")
	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	w = serveTrustRoots(t, svc, sys, http.MethodGet, "/api/v1/trust-roots/"+fp, "")
	assert.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}

// TestTrustRootREST_MapsErrors proves each refusal reaches the wire with the
// status its class maps to.
func TestTrustRootREST_MapsErrors(t *testing.T) {
	svc := newTrustRootRESTService(t)
	sys := qrdbsdk.SystemTenantID
	absent := strings.Repeat("0", 64) // well-formed SHA-256, never imported
	tests := []struct {
		name, tenant, method, path, body string
		status                           int
	}{
		{"tenant caller", "acme", http.MethodGet, "/api/v1/trust-roots", "", http.StatusNotFound},
		{"tenant remove", "acme", http.MethodDelete, "/api/v1/trust-roots/00", "", http.StatusNotFound},
		{"unknown root", sys, http.MethodGet, "/api/v1/trust-roots/" + absent, "", http.StatusNotFound},
		{"unknown quarantine", sys, http.MethodPost, "/api/v1/trust-roots/" + absent + "/quarantine", "", http.StatusNotFound},
		{"malformed fingerprint", sys, http.MethodGet, "/api/v1/trust-roots/00", "", http.StatusBadRequest},
		{"invalid purpose filter", sys, http.MethodGet, "/api/v1/trust-roots?purpose=bogus", "", http.StatusBadRequest},
		{"invalid import purpose", sys, http.MethodPost, "/api/v1/trust-roots", trustRootImportBody(t, "bogus"), http.StatusBadRequest},
		{"malformed import", sys, http.MethodPost, "/api/v1/trust-roots", "{", http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := serveTrustRoots(t, svc, tt.tenant, tt.method, tt.path, tt.body)
			assert.Equal(t, tt.status, w.Code, w.Body.String())
		})
	}
}

// TestTrustRootREST_NotConfigured proves an unwired store answers 503.
func TestTrustRootREST_NotConfigured(t *testing.T) {
	w := serveTrustRoots(t, &xkms.XKMSService{}, qrdbsdk.SystemTenantID, http.MethodGet, "/api/v1/trust-roots", "")
	assert.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
}
