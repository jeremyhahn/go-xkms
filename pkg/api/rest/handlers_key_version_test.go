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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// keyVersionRESTFixture mounts every /api/v1/keys route, as Routes()
// registers them, over a real XKMSService: one software backend and an
// in-memory key-version store.
type keyVersionRESTFixture struct {
	t      *testing.T
	svc    *xkms.XKMSService
	router *chi.Mux
	tenant string
}

func newKeyVersionRESTFixture(t *testing.T) *keyVersionRESTFixture {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	be, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	require.NoError(t, err)
	ks, err := xkms.New(&xkms.BackendConfig{Backend: be, CertStorage: storage.New()})
	require.NoError(t, err)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{Backends: map[string]xkms.Backend{"software": ks}, DefaultBackend: "software"}))
	svc, err := xkms.Get()
	require.NoError(t, err)
	wireKeyVersionStore(t)

	f := &keyVersionRESTFixture{t: t, svc: svc, router: chi.NewRouter()}
	handlers := NewHandlerContext("1.0.0")
	handlers.SetXKMSService(svc)
	server := &Server{handlers: handlers}
	f.router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if f.tenant == "" {
				next.ServeHTTP(w, req)
				return
			}
			identity := &auth.Identity{Subject: "admin@" + f.tenant, TenantID: f.tenant, Roles: []string{"admin"}}
			next.ServeHTTP(w, req.WithContext(auth.WithIdentity(req.Context(), identity)))
		})
	})
	for _, spec := range Routes() {
		if spec.Resource == auth.ResourceKeys && strings.HasPrefix(spec.Pattern, "/api/v1/keys") {
			f.router.Method(spec.Method, spec.Pattern, spec.Handler(server))
		}
	}
	return f
}

// serve sends method path with body and returns the response.
func (f *keyVersionRESTFixture) serve(method, path, body string) *httptest.ResponseRecorder {
	f.t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, httptest.NewRequest(method, path, reader))
	return w
}

// do is a wire.Requester over the fixture's router: the client-side route
// table meets the server-side one.
func (f *keyVersionRESTFixture) do(_ context.Context, method, path string, body any) ([]byte, error) {
	var payload string
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		payload = string(raw)
	}
	w := f.serve(method, path, payload)
	if w.Code/100 != 2 {
		return nil, fmt.Errorf("%s %s: %d %s", method, path, w.Code, w.Body.String())
	}
	return w.Body.Bytes(), nil
}

// generate creates an ECDSA key over the REST route.
func (f *keyVersionRESTFixture) generate(keyID, algorithm string) {
	f.t.Helper()
	body := fmt.Sprintf(`{"key_id":%q,"backend":"software","key_type":"signing","algorithm":%q}`, keyID, algorithm)
	w := f.serve(http.MethodPost, "/api/v1/keys", body)
	require.Equal(f.t, http.StatusCreated, w.Code, w.Body.String())
}

// rotate rotates keyID over the REST route and returns the new version.
func (f *keyVersionRESTFixture) rotate(keyID string) uint32 {
	f.t.Helper()
	w := f.serve(http.MethodPost, "/api/v1/keys/"+keyID+"/rotate?backend=software", "")
	require.Equal(f.t, http.StatusOK, w.Code, w.Body.String())
	var resp RotateKeyResponse
	require.NoError(f.t, json.Unmarshal(w.Body.Bytes(), &resp))
	return resp.KeyVersion
}

// TestKeyVersionREST_ClientMeetsServer drives every key-version method of
// wire.KeyVersionClient -- the client the REST and QUIC transports use --
// against the server's own routes and handlers.
func TestKeyVersionREST_ClientMeetsServer(t *testing.T) {
	f := newKeyVersionRESTFixture(t)
	ctx := context.Background()
	c := wire.KeyVersionClient{Do: f.do}
	f.generate("k", "ecdsa")
	assert.Equal(t, uint32(2), f.rotate("k"))

	listed, err := c.ListKeyVersions(ctx, &transport.ListKeyVersionsRequest{Backend: "software", KeyID: "k"})
	require.NoError(t, err)
	assert.Equal(t, uint32(2), listed.CurrentVersion)
	require.Len(t, listed.Versions, 2)

	state, err := c.DisableKeyVersion(ctx, &transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 1})
	require.NoError(t, err)
	assert.Equal(t, transport.KeyVersionDisabled, state.State)
	state, err = c.EnableKeyVersion(ctx, &transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 1})
	require.NoError(t, err)
	assert.Equal(t, transport.KeyVersionEnabled, state.State)

	all, err := c.DisableAllKeyVersions(ctx, &transport.AllKeyVersionsRequest{Backend: "software", KeyID: "k"})
	require.NoError(t, err)
	assert.Equal(t, []uint32{1}, all.Versions)
	all, err = c.EnableAllKeyVersions(ctx, &transport.AllKeyVersionsRequest{Backend: "software", KeyID: "k"})
	require.NoError(t, err)
	assert.Equal(t, []uint32{1}, all.Versions)

	state, err = c.RetireKeyVersion(ctx, &transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 1})
	require.NoError(t, err)
	assert.Equal(t, transport.KeyVersionRetired, state.State)

	scope, err := c.RotateScopeKeys(ctx, &transport.RotateScopeKeysRequest{})
	require.NoError(t, err)
	require.Len(t, scope.Results, 1)
	assert.Equal(t, uint32(3), scope.Results[0].KeyVersion)
}

// TestKeyVersionREST_CryptoCarriesKeyVersion proves the sign, verify,
// encrypt and decrypt routes carry key_version both ways, and the listing
// and lookup report the current version.
func TestKeyVersionREST_CryptoCarriesKeyVersion(t *testing.T) {
	f := newKeyVersionRESTFixture(t)
	f.generate("k", "ecdsa")

	w := f.serve(http.MethodPost, "/api/v1/keys/k/sign?backend=software", `{"data":"ZGF0YQ=="}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var signed SignResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &signed))
	assert.Equal(t, uint32(1), signed.KeyVersion)

	f.rotate("k")
	sig, err := json.Marshal(signed.Signature)
	require.NoError(t, err)
	w = f.serve(http.MethodPost, "/api/v1/keys/k/verify?backend=software", `{"data":"ZGF0YQ==","signature":`+string(sig)+`}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var verified VerifyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &verified))
	assert.True(t, verified.Valid)
	assert.Equal(t, uint32(1), verified.KeyVersion)

	w = f.serve(http.MethodPost, "/api/v1/keys/k/verify?backend=software", `{"data":"ZGF0YQ==","signature":`+string(sig)+`,"key_version":2}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &verified))
	assert.False(t, verified.Valid, "the v1 signature is not version 2's")

	w = f.serve(http.MethodGet, "/api/v1/keys?backend=software", "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var list ListKeysResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	require.Len(t, list.Keys, 1, "a version is never listed on its own")
	assert.Equal(t, uint32(2), list.Keys[0].KeyVersion)

	w = f.serve(http.MethodGet, "/api/v1/keys/k?backend=software", "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"key_version":2`)

	f.generate("aes", "aes-256-gcm")
	w = f.serve(http.MethodPost, "/api/v1/keys/aes/encrypt?backend=software", `{"plaintext":"MDEyMzQ1Njc4OWFiY2RlZg==","mode":"cbc-pad"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var enc EncryptResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &enc))
	assert.Equal(t, uint32(1), enc.KeyVersion)
	f.rotate("aes")

	decBody := func(version string) string {
		ct, err := json.Marshal(enc.Ciphertext)
		require.NoError(t, err)
		iv, err := json.Marshal(enc.IV)
		require.NoError(t, err)
		return `{"ciphertext":` + string(ct) + `,"iv":` + string(iv) + `,"mode":"cbc-pad"` + version + `}`
	}
	w = f.serve(http.MethodPost, "/api/v1/keys/aes/decrypt?backend=software", decBody(""))
	assert.Equal(t, http.StatusBadRequest, w.Code, "CBC with two enabled versions needs key_version")
	assert.Contains(t, w.Body.String(), "key_version is required")

	w = f.serve(http.MethodPost, "/api/v1/keys/aes/decrypt?backend=software", decBody(`,"key_version":1`))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var dec DecryptResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &dec))
	assert.True(t, bytes.Equal([]byte("0123456789abcdef"), dec.Plaintext))
	assert.Equal(t, uint32(1), dec.KeyVersion)
}

// TestKeyVersionREST_MapsErrors proves each refusal reaches the wire with the
// status its class maps to.
func TestKeyVersionREST_MapsErrors(t *testing.T) {
	f := newKeyVersionRESTFixture(t)
	f.generate("k", "ecdsa")
	f.rotate("k")

	tests := []struct {
		name, method, path, body string
		status                   int
	}{
		{"disable current", http.MethodPost, "/api/v1/keys/k/versions/2/disable?backend=software", "", http.StatusConflict},
		{"retire current", http.MethodPost, "/api/v1/keys/k/versions/2/retire?backend=software", "", http.StatusConflict},
		{"unknown version", http.MethodPost, "/api/v1/keys/k/versions/9/enable?backend=software", "", http.StatusNotFound},
		{"version zero", http.MethodPost, "/api/v1/keys/k/versions/0/enable?backend=software", "", http.StatusBadRequest},
		{"version not a number", http.MethodPost, "/api/v1/keys/k/versions/two/enable?backend=software", "", http.StatusBadRequest},
		{"missing backend", http.MethodGet, "/api/v1/keys/k/versions", "", http.StatusBadRequest},
		{"missing key", http.MethodGet, "/api/v1/keys/ghost/versions?backend=software", "", http.StatusNotFound},
		{"version name", http.MethodGet, "/api/v1/keys/k--v2/versions?backend=software", "", http.StatusBadRequest},
		{"reserved key ID", http.MethodPost, "/api/v1/keys", `{"key_id":"x--v2","backend":"software","key_type":"signing","algorithm":"ecdsa"}`, http.StatusBadRequest},
		{"malformed rotate-all body", http.MethodPost, "/api/v1/keys/rotate-all", `{`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := f.serve(tt.method, tt.path, tt.body)
			assert.Equal(t, tt.status, w.Code, w.Body.String())
		})
	}

	f.tenant = "acme"
	w := f.serve(http.MethodPost, "/api/v1/keys/rotate-all", `{"tenant_id":"globex"}`)
	assert.Equal(t, http.StatusNotFound, w.Code, "a tenant cannot rotate another tenant: %s", w.Body.String())

	f.tenant = ""
	f.svc.SetKeyVersionStore(nil)
	w = f.serve(http.MethodPost, "/api/v1/keys/k/versions/1/disable?backend=software", "")
	assert.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
}

// TestKeyVersionREST_NoService proves the routes answer 503, not a panic,
// when no service is wired.
func TestKeyVersionREST_NoService(t *testing.T) {
	h := NewHandlerContext("1.0.0")
	r := chi.NewRouter()
	r.Get("/api/v1/keys/{id}/versions", h.ListKeyVersionsHandler)
	r.Post("/api/v1/keys/rotate-all", h.RotateScopeKeysHandler)
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/api/v1/keys/k/versions?backend=software", nil),
		httptest.NewRequest(http.MethodPost, "/api/v1/keys/rotate-all", nil),
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code, req.URL.Path)
	}
}
