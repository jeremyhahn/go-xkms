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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/oidccredentialtest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/oidccredentialtest/offline"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// oidcCredentialRESTFixture mounts the OIDC credential routes, as Routes()
// registers them, over an XKMSService whose credential service holds the
// barriers of tenants acme and globex.
type oidcCredentialRESTFixture struct {
	t   *testing.T
	svc *xkms.XKMSService
}

func newOIDCCredentialRESTFixture(t *testing.T) *oidcCredentialRESTFixture {
	t.Helper()
	svc := &xkms.XKMSService{}
	svc.SetOIDCCredentialService(offline.NewService(t, "acme", "globex"))
	return &oidcCredentialRESTFixture{t: t, svc: svc}
}

// serve sends method path with body as subject@tenant through every OIDC
// credential route of the route table.
func (f *oidcCredentialRESTFixture) serve(tenant, subject, method, path, body string) *httptest.ResponseRecorder {
	f.t.Helper()
	server := &Server{oidcCredentialHandlers: NewOIDCCredentialHandlers(f.svc)}
	r := chi.NewRouter()
	identity := &auth.Identity{Subject: subject, TenantID: tenant, Roles: []string{"admin"}}
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(auth.WithIdentity(req.Context(), identity)))
		})
	})
	for _, spec := range Routes() {
		if spec.Resource == auth.ResourceOIDCCredentials {
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

// createBody returns the JSON body of a create request.
func createBody(t *testing.T, scope, name string, tokens *transport.OIDCCredentialTokens) string {
	t.Helper()
	raw, err := json.Marshal(transport.OIDCCredentialCreateRequest{
		OIDCCredentialRef: transport.OIDCCredentialRef{Scope: scope, Name: name},
		Config:            oidccredentialtest.Config(),
		Tokens:            tokens,
	})
	require.NoError(t, err)
	return string(raw)
}

// TestOIDCCredentialREST_Lifecycle proves the routes reach the credential
// service in the caller's tenant: a credential is created, listed, read,
// re-imported, serves its access token uncached, and is deleted.
func TestOIDCCredentialREST_Lifecycle(t *testing.T) {
	f := newOIDCCredentialRESTFixture(t)

	w := f.serve("acme", "alice", http.MethodPost, "/api/v1/oidc/credentials", createBody(t, "tenant", "ci", oidccredentialtest.Tokens("at-0")))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var created transport.OIDCCredential
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	assert.Equal(t, "acme", created.TenantID)
	assert.Equal(t, transport.OIDCCredentialStatusActive, created.Status)
	assert.NotContains(t, w.Body.String(), "at-0", "the public view carries no token")

	w = f.serve("acme", "alice", http.MethodGet, "/api/v1/oidc/credentials", "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var list transport.OIDCCredentialListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	require.Len(t, list.Credentials, 1)
	assert.Equal(t, "ci", list.Credentials[0].Name)

	w = f.serve("acme", "alice", http.MethodGet, "/api/v1/oidc/credentials/tenant/ci", "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = f.serve("acme", "alice", http.MethodPost, "/api/v1/oidc/credentials/tenant/ci/import", `{"tokens":{"access_token":"at-1"}}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = f.serve("acme", "bob", http.MethodPost, "/api/v1/oidc/credentials/tenant/ci/token", "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	var tok transport.OIDCAccessToken
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tok))
	assert.Equal(t, "at-1", tok.AccessToken, "a tenant credential serves every user of the tenant")

	w = f.serve("acme", "alice", http.MethodDelete, "/api/v1/oidc/credentials/tenant/ci", "")
	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	w = f.serve("acme", "alice", http.MethodGet, "/api/v1/oidc/credentials/tenant/ci", "")
	assert.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}

// TestOIDCCredentialREST_PersonalCredential proves the path's scope and the
// owner query parameter reach the service: a personal credential serves its
// owner and is refused to another user of the tenant.
func TestOIDCCredentialREST_PersonalCredential(t *testing.T) {
	f := newOIDCCredentialRESTFixture(t)
	w := f.serve("acme", "alice", http.MethodPost, "/api/v1/oidc/credentials", createBody(t, "user", "mine", oidccredentialtest.Tokens("at-alice")))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	w = f.serve("acme", "alice", http.MethodPost, "/api/v1/oidc/credentials/user/mine/token", "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "at-alice")

	w = f.serve("acme", "bob", http.MethodPost, "/api/v1/oidc/credentials/user/mine/token?owner=alice", "")
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}

// TestOIDCCredentialREST_MapsErrors proves each refusal reaches the wire
// with the status apierrors.OIDCCredentialClassOf's class maps to.
func TestOIDCCredentialREST_MapsErrors(t *testing.T) {
	f := newOIDCCredentialRESTFixture(t)
	require.Equal(t, http.StatusCreated, f.serve("acme", "alice", http.MethodPost, "/api/v1/oidc/credentials", createBody(t, "tenant", "ci", oidccredentialtest.Tokens("at"))).Code)
	require.Equal(t, http.StatusCreated, f.serve("acme", "alice", http.MethodPost, "/api/v1/oidc/credentials", createBody(t, "tenant", "pending", nil)).Code)

	tests := []struct {
		name, method, path, body string
		status                   int
	}{
		{"malformed create", http.MethodPost, "/api/v1/oidc/credentials", "{", http.StatusBadRequest},
		{"no issuer", http.MethodPost, "/api/v1/oidc/credentials", `{"scope":"tenant","name":"x","config":{}}`, http.StatusBadRequest},
		{"invalid scope", http.MethodGet, "/api/v1/oidc/credentials/galaxy/ci", "", http.StatusBadRequest},
		{"duplicate", http.MethodPost, "/api/v1/oidc/credentials", createBody(t, "tenant", "ci", nil), http.StatusConflict},
		{"unknown credential", http.MethodGet, "/api/v1/oidc/credentials/tenant/missing", "", http.StatusNotFound},
		{"unknown delete", http.MethodDelete, "/api/v1/oidc/credentials/tenant/missing", "", http.StatusNotFound},
		{"malformed import", http.MethodPost, "/api/v1/oidc/credentials/tenant/ci/import", "{", http.StatusBadRequest},
		{"empty import", http.MethodPost, "/api/v1/oidc/credentials/tenant/ci/import", `{"tokens":{}}`, http.StatusBadRequest},
		{"another tenant", http.MethodGet, "/api/v1/oidc/credentials?tenant_id=globex", "", http.StatusForbidden},
		{"no login", http.MethodPost, "/api/v1/oidc/credentials/tenant/pending/token", "", http.StatusConflict},
		{"not refreshable", http.MethodPost, "/api/v1/oidc/credentials/tenant/ci/refresh", "", http.StatusConflict},
		{"device login without endpoints", http.MethodPost, "/api/v1/oidc/credentials/tenant/ci/device", "", http.StatusBadRequest},
		{"no device login", http.MethodPost, "/api/v1/oidc/credentials/tenant/ci/device/poll", "", http.StatusConflict},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := f.serve("acme", "alice", tt.method, tt.path, tt.body)
			assert.Equal(t, tt.status, w.Code, w.Body.String())
		})
	}
}

// TestOIDCCredentialREST_WithoutTheService proves every route answers 503
// on a server whose XKMSService composes no credential service.
func TestOIDCCredentialREST_WithoutTheService(t *testing.T) {
	f := &oidcCredentialRESTFixture{t: t, svc: &xkms.XKMSService{}}
	for _, spec := range Routes() {
		if spec.Resource != auth.ResourceOIDCCredentials {
			continue
		}
		t.Run(spec.Method+" "+spec.Pattern, func(t *testing.T) {
			path := strings.NewReplacer("{scope}", "tenant", "{name}", "ci").Replace(spec.Pattern)
			body := ""
			if spec.Method == http.MethodPost {
				body = `{"scope":"tenant","name":"ci","tokens":{"access_token":"at"}}`
			}
			w := f.serve("acme", "alice", spec.Method, path, body)
			assert.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
		})
	}
}

// TestRespondOIDCCredential_WithholdsAnUnclassifiedError proves an error
// the OIDC credential classification does not know is a 500 whose text is
// withheld.
func TestRespondOIDCCredential_WithholdsAnUnclassifiedError(t *testing.T) {
	w := httptest.NewRecorder()
	respondOIDCCredential[*transport.OIDCCredential](w, nil, errors.New("secret internal detail"), http.StatusOK)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), "secret internal detail")
}
