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
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// errSigningKeyStatus is a non-2xx answer of the signing-key routes.
type errSigningKeyStatus struct{ code int }

func (e *errSigningKeyStatus) Error() string { return "status " + strconv.Itoa(e.code) }

// signingKeyRouter serves the signing-key routes of the route table over svc
// as a caller of tenant acme.
func signingKeyRouter(svc transport.SigningKeyServicer) http.Handler {
	server := &Server{signingKeyHandlers: NewSigningKeyHandlers(svc)}
	r := chi.NewRouter()
	identity := &auth.Identity{Subject: "release-manager", TenantID: "acme", Roles: []string{"admin"}}
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(auth.WithIdentity(req.Context(), identity)))
		})
	})
	for _, spec := range Routes() {
		if spec.Resource == auth.ResourceAttestationSigningKeys {
			r.Method(spec.Method, spec.Pattern, spec.Handler(server))
		}
	}
	return r
}

// signingKeyClient returns the wire client over router, failing a non-2xx
// answer with its status.
func signingKeyClient(t *testing.T, router http.Handler) wire.SigningKeyClient {
	return wire.SigningKeyClient{Do: func(_ context.Context, method, path string, body any) ([]byte, error) {
		var reader io.Reader
		if body != nil {
			raw, err := json.Marshal(body)
			require.NoError(t, err)
			reader = bytes.NewReader(raw)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(method, path, reader))
		if w.Code >= 300 {
			return nil, &errSigningKeyStatus{code: w.Code}
		}
		return w.Body.Bytes(), nil
	}}
}

// signingKeyXKMS returns a service with a Verifier wired.
func signingKeyXKMS(t *testing.T) *xkms.XKMSService {
	t.Helper()
	store, err := appraisal.NewStore(appraisal.StoreConfig{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)
	appraiser, err := appraisal.NewAppraiser(store)
	require.NoError(t, err)
	svc := &xkms.XKMSService{}
	svc.SetAttestationAppraiser(appraiser)
	return svc
}

// TestSigningKeyREST_BindResolveRemove proves the wire client and the routes
// round-trip a binding, the repository's slash surviving the query
// parameter.
func TestSigningKeyREST_BindResolveRemove(t *testing.T) {
	c := signingKeyClient(t, signingKeyRouter(signingKeyXKMS(t)))
	ctx := context.Background()

	resolved, err := c.ResolveSigningKey(ctx, &transport.ResolveSigningKeyRequest{Repository: "acme/app"})
	require.NoError(t, err)
	assert.True(t, resolved.Default)

	bound, err := c.SetSigningKeyBinding(ctx, &transport.SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: "app-release"})
	require.NoError(t, err)
	assert.Equal(t, "acme/app", bound.Repository)

	got, err := c.GetSigningKeyBinding(ctx, &transport.GetSigningKeyBindingRequest{Repository: "acme/app"})
	require.NoError(t, err)
	assert.Equal(t, "app-release", got.KeyID)

	list, err := c.ListSigningKeyBindings(ctx)
	require.NoError(t, err)
	require.Len(t, list.Bindings, 1)

	resolved, err = c.ResolveSigningKey(ctx, &transport.ResolveSigningKeyRequest{Repository: "acme/app"})
	require.NoError(t, err)
	assert.Equal(t, "app-release", resolved.KeyID)

	require.NoError(t, c.DeleteSigningKeyBinding(ctx, &transport.DeleteSigningKeyBindingRequest{Repository: "acme/app"}))
	_, err = c.GetSigningKeyBinding(ctx, &transport.GetSigningKeyBindingRequest{Repository: "acme/app"})
	assert.Equal(t, &errSigningKeyStatus{code: http.StatusNotFound}, err)
}

// TestSigningKeyREST_MapsErrors proves the routes answer a malformed body or
// repository with 400, an unbound repository's removal with 404, and every
// route of a server with no Verifier with 503.
func TestSigningKeyREST_MapsErrors(t *testing.T) {
	router := signingKeyRouter(signingKeyXKMS(t))
	serve := func(method, path, body string) int {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
		return w.Code
	}
	assert.Equal(t, http.StatusBadRequest, serve(http.MethodPut, wire.SigningKeysPath, "{"))
	assert.Equal(t, http.StatusBadRequest, serve(http.MethodPut, wire.SigningKeysPath, `{"repository":"acme/app","key_id":"a/b"}`))
	assert.Equal(t, http.StatusBadRequest, serve(http.MethodGet, wire.SigningKeyResolvePath+"?repository=Acme", ""))
	assert.Equal(t, http.StatusNotFound, serve(http.MethodDelete, wire.SigningKeyBindingPath+"?repository=acme/app", ""))

	c := signingKeyClient(t, signingKeyRouter(&xkms.XKMSService{}))
	ctx := context.Background()
	unavailable := &errSigningKeyStatus{code: http.StatusServiceUnavailable}
	_, err := c.SetSigningKeyBinding(ctx, &transport.SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: "k"})
	assert.Equal(t, unavailable, err)
	_, err = c.GetSigningKeyBinding(ctx, &transport.GetSigningKeyBindingRequest{Repository: "acme/app"})
	assert.Equal(t, unavailable, err)
	_, err = c.ListSigningKeyBindings(ctx)
	assert.Equal(t, unavailable, err)
	assert.Equal(t, unavailable, c.DeleteSigningKeyBinding(ctx, &transport.DeleteSigningKeyBindingRequest{Repository: "acme/app"}))
	_, err = c.ResolveSigningKey(ctx, &transport.ResolveSigningKeyRequest{Repository: "acme/app"})
	assert.Equal(t, unavailable, err)
}

// TestSigningKeyWire_NilRequests proves the wire client refuses a nil
// request before it sends anything.
func TestSigningKeyWire_NilRequests(t *testing.T) {
	c := wire.SigningKeyClient{}
	ctx := context.Background()
	_, err := c.SetSigningKeyBinding(ctx, nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)
	_, err = c.GetSigningKeyBinding(ctx, nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)
	assert.ErrorIs(t, c.DeleteSigningKeyBinding(ctx, nil), wire.ErrNilRequest)
	_, err = c.ResolveSigningKey(ctx, nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)
}
