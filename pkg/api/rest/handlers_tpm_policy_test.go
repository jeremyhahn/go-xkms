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
	"encoding/json"
	"errors"
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
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmpolicytest"
	tpmpolicy "github.com/jeremyhahn/go-xkms/pkg/tpm2/policy"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// tpmPolicyRESTFixture mounts the TPM policy routes, as Routes() registers
// them, over an XKMSService whose policy service has no TPM.
type tpmPolicyRESTFixture struct {
	t        *testing.T
	policies *tpmpolicy.Service
	registry *tpmpolicy.Registry
	svc      *xkms.XKMSService
}

func newTPMPolicyRESTFixture(t *testing.T) *tpmPolicyRESTFixture {
	t.Helper()
	policies, registry := tpmpolicytest.NewOffline(t)
	svc := &xkms.XKMSService{}
	svc.SetTPMPolicyService(policies)
	return &tpmPolicyRESTFixture{t: t, policies: policies, registry: registry, svc: svc}
}

// serve sends method path with body as a caller of tenant through every TPM
// policy route of the route table.
func (f *tpmPolicyRESTFixture) serve(tenant, method, path, body string) *httptest.ResponseRecorder {
	f.t.Helper()
	server := &Server{tpmPolicyHandlers: NewTPMPolicyHandlers(f.svc)}
	r := chi.NewRouter()
	identity := &auth.Identity{Subject: "admin@" + tenant, TenantID: tenant, Roles: []string{"admin"}}
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(auth.WithIdentity(req.Context(), identity)))
		})
	})
	for _, spec := range Routes() {
		if spec.Resource == auth.ResourceTPMPolicy || strings.Contains(spec.Pattern, "/tpm") {
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

// TestTPMPolicyREST_ServesTheCallersTenant proves the routes reach the
// policy service in the caller's tenant.
func TestTPMPolicyREST_ServesTheCallersTenant(t *testing.T) {
	f := newTPMPolicyRESTFixture(t)
	require.NoError(t, f.policies.Assign(context.Background(), "acme", tpmpolicy.ObjectKey, "signer", "", []byte{0x0F}))

	w := f.serve("acme", http.MethodGet, "/api/v1/tpm/policies", "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var list transport.TPMPolicyListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	assert.Empty(t, list.Policies)

	w = f.serve("acme", http.MethodGet, "/api/v1/keys/signer/tpm-policy", "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var obj transport.TPMObjectPolicyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &obj))
	assert.Equal(t, "key/signer", obj.ObjectID)
	assert.Equal(t, "0f", obj.AuthPolicy)

	w = f.serve("acme", http.MethodGet, "/api/v1/tpm/policies/platform/objects", "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var objects transport.TPMPolicyObjectsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &objects))
	assert.Equal(t, []string{"key/signer"}, objects.Objects)

	sys := qrdbsdk.SystemTenantID
	w = f.serve(sys, http.MethodPut, "/api/v1/tenants/globex/tpm", `{"mode":"none"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = f.serve(sys, http.MethodGet, "/api/v1/tenants/globex/tpm", "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"mode":"none"`)

	w = f.serve(sys, http.MethodGet, "/api/v1/tenants/globex/tpm/vtpm", "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"running":false`)
}

// TestTPMPolicyREST_MapsErrors proves each refusal reaches the wire with the
// status its class maps to.
func TestTPMPolicyREST_MapsErrors(t *testing.T) {
	f := newTPMPolicyRESTFixture(t)
	require.NoError(t, f.registry.PutScope(context.Background(), &tpmpolicy.Scope{Tenant: "initech", Mode: tpmpolicy.ModeNone}))
	sys := qrdbsdk.SystemTenantID

	tests := []struct {
		name, tenant, method, path, body string
		status                           int
	}{
		{"unknown object", "acme", http.MethodGet, "/api/v1/keys/missing/tpm-policy", "", http.StatusNotFound},
		{"invalid kind", "acme", http.MethodGet, "/api/v1/keys/signer/tpm-policy?kind=blob", "", http.StatusBadRequest},
		{"malformed create", "acme", http.MethodPost, "/api/v1/tpm/policies", "{", http.StatusBadRequest},
		{"invalid bank", "acme", http.MethodPost, "/api/v1/tpm/policies", `{"name":"boot","branches":[{"conditions":[{"type":"pcr","bank":"md5","pcrs":[7]}]}]}`, http.StatusBadRequest},
		{"no branches", "acme", http.MethodPost, "/api/v1/tpm/policies", `{"name":"boot"}`, http.StatusBadRequest},
		{"supplied values", "acme", http.MethodPost, "/api/v1/tpm/policies", `{"name":"boot","branches":[{"conditions":[{"type":"pcr","bank":"sha256","pcrs":[7],"pcr_values":{"7":"00"}}]}]}`, http.StatusBadRequest},
		{"reserved name", "acme", http.MethodPost, "/api/v1/tpm/policies", `{"name":"platform","branches":[{"conditions":[{"type":"pcr","bank":"sha256","pcrs":[7]}]}]}`, http.StatusBadRequest},
		{"another tenant", "acme", http.MethodGet, "/api/v1/tpm/policies?tenant_id=globex", "", http.StatusNotFound},
		{"mode none refuses delete", "initech", http.MethodDelete, "/api/v1/tpm/policies/boot", "", http.StatusConflict},
		{"mode none refuses update", "initech", http.MethodPost, "/api/v1/tpm/policies/boot/update", "", http.StatusConflict},
		{"mode none refuses rotate", "initech", http.MethodPost, "/api/v1/tpm/authority/rotate", "", http.StatusConflict},
		{"malformed action body", "acme", http.MethodPost, "/api/v1/tpm/policies/boot/verify", "{", http.StatusBadRequest},
		{"malformed auto-unseal", "acme", http.MethodPost, "/api/v1/tpm/policies/boot/auto-unseal", "", http.StatusBadRequest},
		{"malformed description", "acme", http.MethodPost, "/api/v1/tpm/policies/boot/description", "", http.StatusBadRequest},
		{"description too long", "acme", http.MethodPost, "/api/v1/tpm/policies/boot/description", `{"description":"` + strings.Repeat("d", 4097) + `"}`, http.StatusBadRequest},
		{"tenant mode is system scope", "acme", http.MethodGet, "/api/v1/tenants/acme/tpm", "", http.StatusNotFound},
		{"malformed mode", sys, http.MethodPut, "/api/v1/tenants/acme/tpm", "{", http.StatusBadRequest},
		{"invalid mode", sys, http.MethodPut, "/api/v1/tenants/acme/tpm", `{"mode":"cloud"}`, http.StatusBadRequest},
		{"vtpm unavailable", sys, http.MethodPost, "/api/v1/tenants/acme/tpm/vtpm/start", "", http.StatusConflict},
		{"vtpm stop unavailable", sys, http.MethodPost, "/api/v1/tenants/acme/tpm/vtpm/stop", "", http.StatusConflict},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := f.serve(tt.tenant, tt.method, tt.path, tt.body)
			assert.Equal(t, tt.status, w.Code, w.Body.String())
		})
	}
}

// TestWriteTPMPolicyError_WithholdsAnUnclassifiedError proves an error the
// classification does not know is a 500 whose text is withheld.
func TestWriteTPMPolicyError_WithholdsAnUnclassifiedError(t *testing.T) {
	w := httptest.NewRecorder()
	writeTPMPolicyError(w, errors.New("secret internal detail"))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), "secret internal detail")

	w = httptest.NewRecorder()
	writeTPMPolicyError(w, &tpmpolicy.PolicyInUseError{Policy: "boot", Objects: []string{"key/a"}})
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "key/a")
}

// TestDecodeOptionalJSON proves an empty body leaves the target unchanged
// and a malformed one is an error.
func TestDecodeOptionalJSON(t *testing.T) {
	var req transport.TPMPolicyRequest
	require.NoError(t, decodeOptionalJSON(httptest.NewRequest(http.MethodPost, "/", http.NoBody), &req))
	assert.Empty(t, req.TenantID)

	require.NoError(t, decodeOptionalJSON(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"tenant_id":"acme"}`)), &req))
	assert.Equal(t, "acme", req.TenantID)

	assert.Error(t, decodeOptionalJSON(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{")), &req))
}
