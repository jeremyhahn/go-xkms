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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/continuous"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

type restVerdictSource struct{}

func (restVerdictSource) Collect(context.Context, string, string, []byte) (*appraisal.AppraiseQuoteRequest, error) {
	return &appraisal.AppraiseQuoteRequest{}, nil
}

type restVerdictAppraiser struct{}

func (restVerdictAppraiser) AppraiseQuote(context.Context, string, *appraisal.AppraiseQuoteRequest) (*appraisal.AttestationResult, error) {
	return &appraisal.AttestationResult{Verified: true}, nil
}

// verdictXKMS returns a service with a verdict store and, when withEngine,
// an engine that verifies every device.
func verdictXKMS(t *testing.T, withEngine bool) *xkms.XKMSService {
	t.Helper()
	store, err := continuous.NewStore(continuous.StoreConfig{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)
	var engine *continuous.Engine
	if withEngine {
		now := time.Unix(1_700_000_000, 0)
		engine, err = continuous.NewEngine(continuous.Config{
			Store:     store,
			Source:    restVerdictSource{},
			Appraiser: restVerdictAppraiser{},
			Now: func() time.Time {
				now = now.Add(time.Second)
				return now
			},
		})
		require.NoError(t, err)
	}
	svc := &xkms.XKMSService{}
	svc.SetContinuousAttestation(engine, store)
	return svc
}

func verdictRouter(svc *xkms.XKMSService) http.Handler {
	server := &Server{verdictHandlers: NewAttestationVerdictHandlers(svc)}
	r := chi.NewRouter()
	identity := &auth.Identity{Subject: "operator", TenantID: "acme", Roles: []string{"admin"}}
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(auth.WithIdentity(req.Context(), identity)))
		})
	})
	for _, spec := range Routes() {
		if spec.Resource == auth.ResourceAttestationVerdicts {
			r.Method(spec.Method, spec.Pattern, spec.Handler(server))
		}
	}
	return r
}

func serveVerdict(router http.Handler, method, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
	return w
}

func TestAttestationVerdictREST_ReattestLatestList(t *testing.T) {
	router := verdictRouter(verdictXKMS(t, true))

	w := serveVerdict(router, http.MethodGet, "/api/v1/attestation/verdicts/latest?device=dev-1", "")
	assert.Equal(t, http.StatusNotFound, w.Code)

	for range 2 {
		w = serveVerdict(router, http.MethodPost, "/api/v1/attestation/verdicts", `{"device_id":"dev-1"}`)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	}
	var reattested transport.AttestationVerdict
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &reattested))
	assert.True(t, reattested.Verified)
	assert.Equal(t, "dev-1", reattested.DeviceID)

	w = serveVerdict(router, http.MethodGet, "/api/v1/attestation/verdicts/latest?device=dev-1", "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var latest transport.AttestationVerdict
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &latest))
	assert.True(t, latest.At.Equal(reattested.At))

	w = serveVerdict(router, http.MethodGet, "/api/v1/attestation/verdicts?device=dev-1", "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var list transport.ListAttestationVerdictsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	assert.Len(t, list.Verdicts, 2)
}

func TestAttestationVerdictREST_MapsErrors(t *testing.T) {
	router := verdictRouter(verdictXKMS(t, true))
	assert.Equal(t, http.StatusBadRequest, serveVerdict(router, http.MethodPost, "/api/v1/attestation/verdicts", "{").Code)
	assert.Equal(t, http.StatusBadRequest, serveVerdict(router, http.MethodPost, "/api/v1/attestation/verdicts", `{}`).Code)
	assert.Equal(t, http.StatusBadRequest, serveVerdict(router, http.MethodGet, "/api/v1/attestation/verdicts", "").Code)
	assert.Equal(t, http.StatusBadRequest, serveVerdict(router, http.MethodGet, "/api/v1/attestation/verdicts/latest?device=a/b", "").Code)

	unconfigured := verdictRouter(&xkms.XKMSService{})
	assert.Equal(t, http.StatusServiceUnavailable, serveVerdict(unconfigured, http.MethodGet, "/api/v1/attestation/verdicts?device=dev-1", "").Code)
	assert.Equal(t, http.StatusServiceUnavailable, serveVerdict(unconfigured, http.MethodGet, "/api/v1/attestation/verdicts/latest?device=dev-1", "").Code)

	storeOnly := verdictRouter(verdictXKMS(t, false))
	assert.Equal(t, http.StatusServiceUnavailable, serveVerdict(storeOnly, http.MethodPost, "/api/v1/attestation/verdicts", `{"device_id":"dev-1"}`).Code)
	assert.Equal(t, http.StatusOK, serveVerdict(storeOnly, http.MethodGet, "/api/v1/attestation/verdicts?device=dev-1", "").Code)
}

func TestAttestationVerdictREST_RoutePermissions(t *testing.T) {
	want := map[string]string{
		"GET /api/v1/attestation/verdicts":        auth.ActionList,
		"GET /api/v1/attestation/verdicts/latest": auth.ActionGet,
		"POST /api/v1/attestation/verdicts":       auth.ActionCreate,
	}
	got := map[string]string{}
	for _, spec := range Routes() {
		if spec.Resource == auth.ResourceAttestationVerdicts {
			got[spec.Method+" "+spec.Pattern] = spec.Action
		}
	}
	assert.Equal(t, want, got)
}
