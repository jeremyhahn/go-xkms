//go:build codec_json

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

package admin

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/gorilla/mux"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/require"
)

// This file extends #822's router/spec parity test with response-body
// validation: for a representative success and error on every admin
// operation, it asserts the exact bytes the handler wrote satisfy
// admin-api.yaml's declared schema for that status code. #822 only checked
// that a (method, path) pair exists on both sides; it said nothing about
// whether the documented response shape is the one the handler actually
// produces, which is what issue #823 found wrong (a SuccessResponse
// envelope no handler ever writes).
//
// admin-api.yaml is loaded from its single source location —
// pkg/acme/api/swagger/openapi/admin-api.yaml, the file go:embed's into
// pkg/acme/api/swagger and GET /openapi/admin-api.yaml serves unmodified —
// rather than through that package's OpenAPISpecHandler, because
// pkg/acme/api/swagger imports pkg/acme/admin (for AuthHandler and
// PermissionGate), so the reverse import here would cycle. Reading the same
// file by path carries no drift risk: after #823 removed the duplicate
// api/openapi/ tree, this is the only copy on disk.

// specAdminAPIURL is the base URL every response-validation request is
// built against. admin-api.yaml declares two servers; matching one exactly
// (scheme + host) is what lets the OpenAPI router's gorilla/mux resolve a
// route at all (routers/gorillamux matches on server host and scheme, not
// only path).
const specAdminAPIURL = "https://localhost:8443"

// loadAdminAPISpecRouter parses admin-api.yaml and returns both the parsed
// document and an OpenAPI-aware router over it, used to look up which
// response schema a given (method, path, status) triple must satisfy.
func loadAdminAPISpecRouter(t *testing.T) (*openapi3.T, routers.Router) {
	t.Helper()

	data, err := os.ReadFile("../api/swagger/openapi/admin-api.yaml")
	require.NoError(t, err)

	doc, err := openapi3.NewLoader().LoadFromData(data)
	require.NoError(t, err)
	require.NoError(t, doc.Validate(context.Background()))

	router, err := gorillamux.NewRouter(doc)
	require.NoError(t, err)

	return doc, router
}

// newSpecRequest builds the *http.Request used purely to resolve an
// admin-api.yaml route (method + path, against specAdminAPIURL). It is
// deliberately never the same *http.Request passed to the handler under
// test: handlers read gorilla/mux vars set via mux.SetURLVars, which this
// request never carries.
func newSpecRequest(t *testing.T, method, path string) *http.Request {
	t.Helper()
	return httptest.NewRequest(method, specAdminAPIURL+path, nil)
}

// requireResponseMatchesSpec asserts the literal bytes rec captured for a
// request against path satisfy admin-api.yaml's declared response schema
// for rec.Code. IncludeResponseStatus is set so an undocumented status code
// fails the assertion instead of silently passing — the same fail-loud
// posture #822's router/path parity check uses.
func requireResponseMatchesSpec(t *testing.T, router routers.Router, method, path string, rec *httptest.ResponseRecorder) {
	t.Helper()

	specReq := newSpecRequest(t, method, path)
	route, pathParams, err := router.FindRoute(specReq)
	require.NoErrorf(t, err, "%s %s: not resolvable against admin-api.yaml", method, path)

	respInput := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request:    specReq,
			PathParams: pathParams,
			Route:      route,
		},
		Status:  rec.Code,
		Header:  rec.Header(),
		Options: &openapi3filter.Options{IncludeResponseStatus: true},
	}
	respInput.SetBodyBytes(rec.Body.Bytes())

	err = openapi3filter.ValidateResponse(context.Background(), respInput)
	require.NoErrorf(t, err, "%s %s -> %d: response does not match admin-api.yaml\nbody: %s",
		method, path, rec.Code, rec.Body.String())
}

// --- Certificates, Accounts, Orders, Status, Stats (pkg/acme/admin.Handlers) ---

func TestOpenAPIResponses_Certificates(t *testing.T) {
	_, router := loadAdminAPISpecRouter(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	cert := &CertificateInfo{
		SerialNumber: "1A2B3C4D5E6F",
		Subject:      "CN=api.example.com",
		Issuer:       "CN=ACME Corp Issuing CA",
		Status:       "valid",
	}

	t.Run("list_success", func(t *testing.T) {
		h := NewHandlers(&mockService{
			listCertificatesFunc: func(context.Context, ListCertificatesRequest) ([]*CertificateInfo, *Pagination, error) {
				return []*CertificateInfo{cert}, &Pagination{Page: 1, PerPage: 20, Total: 1}, nil
			},
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/admin/certificates", nil)
		w := httptest.NewRecorder()
		h.ListCertificates(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/admin/certificates", w)
	})

	t.Run("get_not_found", func(t *testing.T) {
		h := NewHandlers(&mockService{
			getCertificateFunc: func(context.Context, string) (*CertificateInfo, error) {
				return nil, ErrCertificateNotFound
			},
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/admin/certificates/deadbeef", nil)
		req = mux.SetURLVars(req, map[string]string{"serial": "deadbeef"})
		w := httptest.NewRecorder()
		h.GetCertificate(w, req)
		require.Equal(t, http.StatusNotFound, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/admin/certificates/deadbeef", w)
	})

	t.Run("get_success", func(t *testing.T) {
		h := NewHandlers(&mockService{
			getCertificateFunc: func(context.Context, string) (*CertificateInfo, error) {
				return cert, nil
			},
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/admin/certificates/1A2B3C4D5E6F", nil)
		req = mux.SetURLVars(req, map[string]string{"serial": "1A2B3C4D5E6F"})
		w := httptest.NewRecorder()
		h.GetCertificate(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/admin/certificates/1A2B3C4D5E6F", w)
	})

	t.Run("revoke_success", func(t *testing.T) {
		h := NewHandlers(&mockService{}, logger)
		req := httptest.NewRequest(http.MethodPost, "/admin/certificates/1A2B3C4D5E6F/revoke",
			bytes.NewBufferString(`{"reason":"keyCompromise"}`))
		req = mux.SetURLVars(req, map[string]string{"serial": "1A2B3C4D5E6F"})
		w := httptest.NewRecorder()
		h.RevokeCertificate(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPost, "/admin/certificates/1A2B3C4D5E6F/revoke", w)
	})

	t.Run("revoke_bad_request", func(t *testing.T) {
		h := NewHandlers(&mockService{}, logger)
		req := httptest.NewRequest(http.MethodPost, "/admin/certificates/1A2B3C4D5E6F/revoke",
			bytes.NewBufferString("not json"))
		req = mux.SetURLVars(req, map[string]string{"serial": "1A2B3C4D5E6F"})
		w := httptest.NewRecorder()
		h.RevokeCertificate(w, req)
		require.Equal(t, http.StatusBadRequest, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPost, "/admin/certificates/1A2B3C4D5E6F/revoke", w)
	})

	t.Run("expiring_success", func(t *testing.T) {
		h := NewHandlers(&mockService{
			listExpiringCertificatesFunc: func(context.Context, int, int, int) ([]*CertificateInfo, *Pagination, error) {
				return []*CertificateInfo{cert}, &Pagination{Page: 1, PerPage: 20, Total: 1}, nil
			},
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/admin/certificates/expiring", nil)
		w := httptest.NewRecorder()
		h.ListExpiringCertificates(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/admin/certificates/expiring", w)
	})
}

func TestOpenAPIResponses_Accounts(t *testing.T) {
	_, router := loadAdminAPISpecRouter(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	account := &AccountInfo{ID: 12345, Status: "valid", OrdersURL: "https://ca.example.com/acme/account/12345/orders"}

	t.Run("list_success", func(t *testing.T) {
		h := NewHandlers(&mockService{
			listAccountsFunc: func(context.Context, ListAccountsRequest) ([]*AccountInfo, *Pagination, error) {
				return []*AccountInfo{account}, &Pagination{Page: 1, PerPage: 20, Total: 1}, nil
			},
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/admin/accounts", nil)
		w := httptest.NewRecorder()
		h.ListAccounts(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/admin/accounts", w)
	})

	t.Run("get_success", func(t *testing.T) {
		h := NewHandlers(&mockService{
			getAccountFunc: func(context.Context, uint64) (*AccountInfo, error) { return account, nil },
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/admin/accounts/12345", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "12345"})
		w := httptest.NewRecorder()
		h.GetAccount(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/admin/accounts/12345", w)
	})

	t.Run("get_not_found", func(t *testing.T) {
		h := NewHandlers(&mockService{
			getAccountFunc: func(context.Context, uint64) (*AccountInfo, error) { return nil, ErrAccountNotFound },
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/admin/accounts/99999", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "99999"})
		w := httptest.NewRecorder()
		h.GetAccount(w, req)
		require.Equal(t, http.StatusNotFound, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/admin/accounts/99999", w)
	})

	t.Run("disable_success", func(t *testing.T) {
		h := NewHandlers(&mockService{}, logger)
		req := httptest.NewRequest(http.MethodDelete, "/admin/accounts/12345", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "12345"})
		w := httptest.NewRecorder()
		h.DisableAccount(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodDelete, "/admin/accounts/12345", w)
	})
}

func TestOpenAPIResponses_Orders(t *testing.T) {
	_, router := loadAdminAPISpecRouter(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	order := &OrderInfo{ID: 67890, AccountID: 12345, Status: "valid", Identifiers: []string{"api.example.com"}}

	t.Run("list_success", func(t *testing.T) {
		h := NewHandlers(&mockService{
			listOrdersFunc: func(context.Context, ListOrdersRequest) ([]*OrderInfo, *Pagination, error) {
				return []*OrderInfo{order}, &Pagination{Page: 1, PerPage: 20, Total: 1}, nil
			},
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/admin/orders", nil)
		w := httptest.NewRecorder()
		h.ListOrders(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/admin/orders", w)
	})

	t.Run("get_success", func(t *testing.T) {
		h := NewHandlers(&mockService{
			getOrderFunc: func(context.Context, uint64, uint64) (*OrderInfo, error) { return order, nil },
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/admin/orders/67890?account_id=12345", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "67890"})
		w := httptest.NewRecorder()
		h.GetOrder(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/admin/orders/67890", w)
	})

	t.Run("get_bad_request_missing_account_id", func(t *testing.T) {
		h := NewHandlers(&mockService{}, logger)
		req := httptest.NewRequest(http.MethodGet, "/admin/orders/67890", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "67890"})
		w := httptest.NewRecorder()
		h.GetOrder(w, req)
		require.Equal(t, http.StatusBadRequest, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/admin/orders/67890", w)
	})
}

func TestOpenAPIResponses_StatusStats(t *testing.T) {
	_, router := loadAdminAPISpecRouter(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("status_success", func(t *testing.T) {
		h := NewHandlers(&mockService{
			getStatusFunc: func(context.Context) (*CAStatus, error) {
				return &CAStatus{Identity: "go-xkms", Initialized: true, Version: "1.0.0",
					KeyAlgorithm: "ECDSA-P384", SignatureAlgo: "SHA384-ECDSA", RootCA: "CN=Trusted Root CA",
					Keys: []KeyInfo{{Algorithm: "ECDSA", SignatureAlgorithm: "ECDSAWithSHA384", Store: "software", Curve: "P-384", Default: true}}}, nil
			},
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
		w := httptest.NewRecorder()
		h.GetStatus(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/admin/status", w)
	})

	t.Run("stats_success", func(t *testing.T) {
		h := NewHandlers(&mockService{
			getStatsFunc: func(context.Context) (*CAStats, error) { return &CAStats{TotalCertificates: 10}, nil },
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
		w := httptest.NewRecorder()
		h.GetStats(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/admin/stats", w)
	})
}

func TestOpenAPIResponses_Audit(t *testing.T) {
	_, router := loadAdminAPISpecRouter(t)

	t.Run("list_success", func(t *testing.T) {
		h := newAuditBackedHandlers(t, auditTestEvent(0, "certificate.issued", "admin:test@example.com", "success"))
		req := httptest.NewRequest(http.MethodGet, "/admin/audit", nil)
		w := httptest.NewRecorder()
		h.ListAuditLogs(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/admin/audit", w)
	})

	t.Run("not_implemented", func(t *testing.T) {
		h := NewHandlers(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
		req := httptest.NewRequest(http.MethodGet, "/admin/audit", nil)
		w := httptest.NewRecorder()
		h.ListAuditLogs(w, req)
		require.Equal(t, http.StatusNotImplemented, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/admin/audit", w)
	})
}

func TestOpenAPIResponses_Algorithms(t *testing.T) {
	_, router := loadAdminAPISpecRouter(t)

	h := NewHandlers(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), WithAlgorithmDiscoverer(func() *AlgorithmsResponse {
		return &AlgorithmsResponse{
			Signing:          []AlgorithmInfo{{Algorithm: "ECDSA", Curves: []string{"P-256"}, Backends: []string{"software"}}},
			KeyEncapsulation: []AlgorithmInfo{},
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "/admin/algorithms", nil)
	w := httptest.NewRecorder()
	h.GetAlgorithms(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	requireResponseMatchesSpec(t, router, http.MethodGet, "/admin/algorithms", w)
}

// --- Tenants, Tenant CA, EAB, Roles, Users (pkg/acme/admin.TenantHandlers) ---

func TestOpenAPIResponses_Tenants(t *testing.T) {
	_, router := loadAdminAPISpecRouter(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tenant := &TenantInfo{ID: "acme-corp", Name: "ACME Corporation", Status: "active"}

	t.Run("list_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			listTenantsFunc: func(context.Context, ListTenantsRequest) ([]*TenantInfo, *Pagination, error) {
				return []*TenantInfo{tenant}, &Pagination{Page: 1, PerPage: 20, Total: 1}, nil
			},
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
		w := httptest.NewRecorder()
		h.ListTenants(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/api/v1/tenants", w)
	})

	t.Run("create_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			createTenantFunc: func(context.Context, CreateTenantRequest) (*TenantInfo, error) { return tenant, nil },
		}, logger)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants",
			bytes.NewBufferString(`{"id":"acme-corp","name":"ACME Corporation"}`))
		w := httptest.NewRecorder()
		h.CreateTenant(w, req)
		require.Equal(t, http.StatusCreated, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPost, "/api/v1/tenants", w)
	})

	t.Run("create_conflict", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			createTenantFunc: func(context.Context, CreateTenantRequest) (*TenantInfo, error) {
				return nil, ErrTenantAlreadyExists
			},
		}, logger)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants",
			bytes.NewBufferString(`{"id":"acme-corp","name":"ACME Corporation"}`))
		w := httptest.NewRecorder()
		h.CreateTenant(w, req)
		require.Equal(t, http.StatusConflict, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPost, "/api/v1/tenants", w)
	})

	t.Run("get_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			getTenantFunc: func(context.Context, string) (*TenantInfo, error) { return tenant, nil },
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/acme-corp", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp"})
		req = addUserToRequest(req, createAdminUser("acme-corp"))
		w := httptest.NewRecorder()
		h.GetTenant(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/api/v1/tenants/acme-corp", w)
	})

	t.Run("get_not_found", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			getTenantFunc: func(context.Context, string) (*TenantInfo, error) { return nil, ErrTenantNotFound },
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/missing", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "missing"})
		req = addUserToRequest(req, createAdminUser("missing"))
		w := httptest.NewRecorder()
		h.GetTenant(w, req)
		require.Equal(t, http.StatusNotFound, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/api/v1/tenants/missing", w)
	})

	t.Run("update_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			updateTenantFunc: func(context.Context, string, UpdateTenantRequest) (*TenantInfo, error) { return tenant, nil },
		}, logger)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/acme-corp", bytes.NewBufferString(`{"name":"ACME Corp"}`))
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp"})
		req = addUserToRequest(req, createAdminUser("acme-corp"))
		w := httptest.NewRecorder()
		h.UpdateTenant(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPut, "/api/v1/tenants/acme-corp", w)
	})

	t.Run("delete_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			deleteTenantFunc: func(context.Context, string) error { return nil },
		}, logger)
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/acme-corp", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp"})
		w := httptest.NewRecorder()
		h.DeleteTenant(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodDelete, "/api/v1/tenants/acme-corp", w)
	})

	t.Run("status_update_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			updateTenantStatusFunc: func(context.Context, string, string) error { return nil },
		}, logger)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/acme-corp/status", bytes.NewBufferString(`{"status":"suspended"}`))
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp"})
		w := httptest.NewRecorder()
		h.UpdateTenantStatus(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPut, "/api/v1/tenants/acme-corp/status", w)
	})
}

func TestOpenAPIResponses_TenantCA(t *testing.T) {
	_, router := loadAdminAPISpecRouter(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	user := createAdminUser("acme-corp")

	rootCA := &TenantRootCAInfo{CommonName: "ACME Corp Root CA", KeyAlgorithm: "ECDSA-P384", Status: "active"}
	intCA := &TenantIntCAInfo{ID: "int-ca-001", CommonName: "ACME Corp Issuing CA", ParentType: "tenant", KeyAlgorithm: "ECDSA-P256", Status: "active"}
	caStatus := &TenantCAStatusInfo{TenantID: "acme-corp", RootCA: rootCA, ActiveCACount: 1, CanIssueCerts: true}

	t.Run("create_root_ca_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			createTenantRootCAFunc: func(context.Context, string, CreateTenantRootCARequest) (*TenantRootCAInfo, error) {
				return rootCA, nil
			},
		}, logger)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/acme-corp/root-ca",
			bytes.NewBufferString(`{"common_name":"ACME Corp Root CA","key_algorithm":"ECDSA-P384","validity_years":20}`))
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp"})
		req = addUserToRequest(req, user)
		w := httptest.NewRecorder()
		h.CreateTenantRootCA(w, req)
		require.Equal(t, http.StatusCreated, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPost, "/api/v1/tenants/acme-corp/root-ca", w)
	})

	t.Run("list_intermediate_cas_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			listTenantIntermediateCAsFunc: func(context.Context, string) ([]*TenantIntCAInfo, error) {
				return []*TenantIntCAInfo{intCA}, nil
			},
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/acme-corp/intermediate-cas", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp"})
		req = addUserToRequest(req, user)
		w := httptest.NewRecorder()
		h.ListTenantIntermediateCAs(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/api/v1/tenants/acme-corp/intermediate-cas", w)
	})

	t.Run("create_intermediate_ca_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			createTenantIntermediateCAFunc: func(context.Context, string, CreateTenantIntermediateCARequest) (*TenantIntCAInfo, error) {
				return intCA, nil
			},
		}, logger)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/acme-corp/intermediate-cas",
			bytes.NewBufferString(`{"common_name":"ACME Corp Issuing CA","parent_type":"tenant","key_algorithm":"ECDSA-P256","validity_years":10}`))
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp"})
		req = addUserToRequest(req, user)
		w := httptest.NewRecorder()
		h.CreateTenantIntermediateCA(w, req)
		require.Equal(t, http.StatusCreated, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPost, "/api/v1/tenants/acme-corp/intermediate-cas", w)
	})

	t.Run("get_intermediate_ca_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			getTenantIntermediateCAFunc: func(context.Context, string, string) (*TenantIntCAInfo, error) { return intCA, nil },
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/acme-corp/intermediate-cas/int-ca-001", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp", "caid": "int-ca-001"})
		req = addUserToRequest(req, user)
		w := httptest.NewRecorder()
		h.GetTenantIntermediateCA(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/api/v1/tenants/acme-corp/intermediate-cas/int-ca-001", w)
	})

	t.Run("get_intermediate_ca_not_found", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			getTenantIntermediateCAFunc: func(context.Context, string, string) (*TenantIntCAInfo, error) {
				return nil, ErrTenantCANotConfigured
			},
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/acme-corp/intermediate-cas/missing", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp", "caid": "missing"})
		req = addUserToRequest(req, user)
		w := httptest.NewRecorder()
		h.GetTenantIntermediateCA(w, req)
		require.Equal(t, http.StatusNotFound, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/api/v1/tenants/acme-corp/intermediate-cas/missing", w)
	})

	t.Run("update_intermediate_ca_status_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			updateTenantIntermediateCAStatusFunc: func(context.Context, string, string, string) error { return nil },
		}, logger)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/acme-corp/intermediate-cas/int-ca-001/status",
			bytes.NewBufferString(`{"status":"revoked"}`))
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp", "caid": "int-ca-001"})
		req = addUserToRequest(req, user)
		w := httptest.NewRecorder()
		h.UpdateTenantIntermediateCAStatus(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPut, "/api/v1/tenants/acme-corp/intermediate-cas/int-ca-001/status", w)
	})

	t.Run("set_default_intermediate_ca_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			setTenantDefaultIntermediateCAFunc: func(context.Context, string, string) error { return nil },
		}, logger)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/acme-corp/default-intermediate-ca",
			bytes.NewBufferString(`{"intermediate_ca_id":"int-ca-001"}`))
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp"})
		req = addUserToRequest(req, user)
		w := httptest.NewRecorder()
		h.SetTenantDefaultIntermediateCA(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPut, "/api/v1/tenants/acme-corp/default-intermediate-ca", w)
	})

	t.Run("ca_status_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			getTenantCAStatusFunc: func(context.Context, string) (*TenantCAStatusInfo, error) { return caStatus, nil },
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/acme-corp/ca-status", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp"})
		req = addUserToRequest(req, user)
		w := httptest.NewRecorder()
		h.GetTenantCAStatus(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/api/v1/tenants/acme-corp/ca-status", w)
	})
}

func TestOpenAPIResponses_EAB(t *testing.T) {
	_, router := loadAdminAPISpecRouter(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	user := createAdminUser("acme-corp")

	eab := &EABInfo{ID: "eab-abc123", TenantID: "acme-corp", Status: "pending", Purpose: "account-binding"}
	createResp := &CreateEABResponse{ID: "eab-abc123", MACKey: "ZOMGTlZrZW5YbGZ", Algorithm: "HS256"}

	t.Run("create_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			createTenantEABFunc: func(context.Context, string, CreateEABRequest) (*CreateEABResponse, error) { return createResp, nil },
		}, logger)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/acme-corp/eab",
			bytes.NewBufferString(`{"purpose":"account-binding"}`))
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp"})
		req = addUserToRequest(req, user)
		w := httptest.NewRecorder()
		h.CreateTenantEAB(w, req)
		require.Equal(t, http.StatusCreated, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPost, "/api/v1/tenants/acme-corp/eab", w)
	})

	t.Run("get_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			getTenantEABFunc: func(context.Context, string, string) (*EABInfo, error) { return eab, nil },
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/acme-corp/eab/eab-abc123", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp", "kid": "eab-abc123"})
		req = addUserToRequest(req, user)
		w := httptest.NewRecorder()
		h.GetTenantEAB(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/api/v1/tenants/acme-corp/eab/eab-abc123", w)
	})

	t.Run("get_not_found", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			getTenantEABFunc: func(context.Context, string, string) (*EABInfo, error) { return nil, ErrEABNotFound },
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/acme-corp/eab/missing", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp", "kid": "missing"})
		req = addUserToRequest(req, user)
		w := httptest.NewRecorder()
		h.GetTenantEAB(w, req)
		require.Equal(t, http.StatusNotFound, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/api/v1/tenants/acme-corp/eab/missing", w)
	})

	t.Run("delete_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			deleteTenantEABFunc: func(context.Context, string, string) error { return nil },
		}, logger)
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/acme-corp/eab/eab-abc123", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp", "kid": "eab-abc123"})
		req = addUserToRequest(req, user)
		w := httptest.NewRecorder()
		h.DeleteTenantEAB(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodDelete, "/api/v1/tenants/acme-corp/eab/eab-abc123", w)
	})

	t.Run("list_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			listTenantEABsFunc: func(context.Context, string, ListEABRequest) ([]*EABInfo, *Pagination, error) {
				return []*EABInfo{eab}, &Pagination{Page: 1, PerPage: 20, Total: 1}, nil
			},
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/acme-corp/eab", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp"})
		req = addUserToRequest(req, user)
		w := httptest.NewRecorder()
		h.ListTenantEABs(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/api/v1/tenants/acme-corp/eab", w)
	})
}

func TestOpenAPIResponses_Roles(t *testing.T) {
	_, router := loadAdminAPISpecRouter(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	role := &db.Role{ID: "role-1", TenantID: "acme-corp", Name: "endorser", Permissions: []string{"acme_eab:create"},
		CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z"}

	t.Run("create_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			createTenantRoleFunc: func(context.Context, string, *db.CreateRoleRequest) (*db.Role, error) { return role, nil },
		}, logger)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/acme-corp/roles",
			bytes.NewBufferString(`{"name":"endorser","permissions":["acme_eab:create"]}`))
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp"})
		w := httptest.NewRecorder()
		h.CreateTenantRole(w, req)
		require.Equal(t, http.StatusCreated, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPost, "/api/v1/tenants/acme-corp/roles", w)
	})

	t.Run("create_error", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			createTenantRoleFunc: func(context.Context, string, *db.CreateRoleRequest) (*db.Role, error) {
				return nil, errors.New("qrdb: role already exists")
			},
		}, logger)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/acme-corp/roles",
			bytes.NewBufferString(`{"name":"endorser","permissions":["acme_eab:create"]}`))
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp"})
		w := httptest.NewRecorder()
		h.CreateTenantRole(w, req)
		require.Equal(t, http.StatusInternalServerError, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPost, "/api/v1/tenants/acme-corp/roles", w)
	})

	t.Run("get_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			getTenantRoleFunc: func(context.Context, string, string) (*db.Role, error) { return role, nil },
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/acme-corp/roles/role-1", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp", "roleID": "role-1"})
		w := httptest.NewRecorder()
		h.GetTenantRole(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/api/v1/tenants/acme-corp/roles/role-1", w)
	})

	t.Run("get_not_found", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			getTenantRoleFunc: func(context.Context, string, string) (*db.Role, error) {
				return nil, errors.New("qrdb: role not found")
			},
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/acme-corp/roles/missing", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp", "roleID": "missing"})
		w := httptest.NewRecorder()
		h.GetTenantRole(w, req)
		require.Equal(t, http.StatusNotFound, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/api/v1/tenants/acme-corp/roles/missing", w)
	})

	t.Run("update_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			updateTenantRoleFunc: func(context.Context, string, *db.UpdateRoleRequest) (*db.Role, error) { return role, nil },
		}, logger)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/acme-corp/roles/role-1",
			bytes.NewBufferString(`{"permissions":["acme_eab:create","acme_eab:list"]}`))
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp", "roleID": "role-1"})
		w := httptest.NewRecorder()
		h.UpdateTenantRole(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPut, "/api/v1/tenants/acme-corp/roles/role-1", w)
	})

	t.Run("delete_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			deleteTenantRoleFunc: func(context.Context, string, string) error { return nil },
		}, logger)
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/acme-corp/roles/role-1", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp", "roleID": "role-1"})
		w := httptest.NewRecorder()
		h.DeleteTenantRole(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodDelete, "/api/v1/tenants/acme-corp/roles/role-1", w)
	})

	t.Run("list_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			listTenantRolesFunc: func(context.Context, string, *db.ListRolesRequest) (*db.ListRolesResponse, error) {
				return &db.ListRolesResponse{Roles: []*db.Role{role}, Total: 1}, nil
			},
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/acme-corp/roles", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp"})
		w := httptest.NewRecorder()
		h.ListTenantRoles(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/api/v1/tenants/acme-corp/roles", w)
	})
}

func TestOpenAPIResponses_Users(t *testing.T) {
	_, router := loadAdminAPISpecRouter(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	user := &db.User{ID: 123456789012345, Username: "jdoe", Email: "jdoe@example.com", TenantID: "acme-corp", Lifecycle: string(qrdbsdk.LifecycleActive),
		CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z"}

	t.Run("create_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			createTenantUserFunc: func(context.Context, string, *db.CreateUserRequest) (*db.User, error) { return user, nil },
		}, logger)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/acme-corp/users",
			bytes.NewBufferString(`{"username":"jdoe","email":"jdoe@example.com"}`))
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp"})
		w := httptest.NewRecorder()
		h.CreateTenantUser(w, req)
		require.Equal(t, http.StatusCreated, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPost, "/api/v1/tenants/acme-corp/users", w)
	})

	t.Run("create_error", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			createTenantUserFunc: func(context.Context, string, *db.CreateUserRequest) (*db.User, error) {
				return nil, errors.New("qrdb: user already exists")
			},
		}, logger)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/acme-corp/users",
			bytes.NewBufferString(`{"username":"jdoe","email":"jdoe@example.com"}`))
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp"})
		w := httptest.NewRecorder()
		h.CreateTenantUser(w, req)
		require.Equal(t, http.StatusInternalServerError, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPost, "/api/v1/tenants/acme-corp/users", w)
	})

	t.Run("get_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			getTenantUserFunc: func(context.Context, string, string) (*db.User, error) { return user, nil },
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/acme-corp/users/123456789012345", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp", "userID": "123456789012345"})
		w := httptest.NewRecorder()
		h.GetTenantUser(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/api/v1/tenants/acme-corp/users/123456789012345", w)
	})

	t.Run("get_not_found", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			getTenantUserFunc: func(context.Context, string, string) (*db.User, error) {
				return nil, errors.New("qrdb: user not found")
			},
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/acme-corp/users/999", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp", "userID": "999"})
		w := httptest.NewRecorder()
		h.GetTenantUser(w, req)
		require.Equal(t, http.StatusNotFound, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/api/v1/tenants/acme-corp/users/999", w)
	})

	t.Run("update_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			updateTenantUserFunc: func(context.Context, string, *db.UpdateUserRequest) (*db.User, error) { return user, nil },
		}, logger)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/acme-corp/users/123456789012345",
			bytes.NewBufferString(`{"name":"Jane Doe"}`))
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp", "userID": "123456789012345"})
		w := httptest.NewRecorder()
		h.UpdateTenantUser(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPut, "/api/v1/tenants/acme-corp/users/123456789012345", w)
	})

	t.Run("delete_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			deleteTenantUserFunc: func(context.Context, string, string) error { return nil },
		}, logger)
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/acme-corp/users/123456789012345", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp", "userID": "123456789012345"})
		w := httptest.NewRecorder()
		h.DeleteTenantUser(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodDelete, "/api/v1/tenants/acme-corp/users/123456789012345", w)
	})

	t.Run("list_success", func(t *testing.T) {
		h := NewTenantHandlers(&mockTenantService{
			listTenantUsersFunc: func(context.Context, string, *db.ListUsersRequest) (*db.ListUsersResponse, error) {
				return &db.ListUsersResponse{Users: []*db.User{user}, Total: 1}, nil
			},
		}, logger)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/acme-corp/users", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "acme-corp"})
		w := httptest.NewRecorder()
		h.ListTenantUsers(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/api/v1/tenants/acme-corp/users", w)
	})
}

// --- Barrier (pkg/acme/admin.BarrierHandlers) ---

func TestOpenAPIResponses_Barrier(t *testing.T) {
	_, router := loadAdminAPISpecRouter(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("status_success", func(t *testing.T) {
		h := NewBarrierHandlers(newStubBarrierService(), logger)
		req := httptest.NewRequest(http.MethodGet, "/admin/barrier/status", nil)
		w := httptest.NewRecorder()
		h.handleBarrierStatus(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/admin/barrier/status", w)
	})

	t.Run("initialize_success", func(t *testing.T) {
		h := NewBarrierHandlers(newStubBarrierService(), logger)
		req := httptest.NewRequest(http.MethodPost, "/admin/barrier/initialize", bytes.NewBufferString(`{"secret":"correct horse battery staple"}`))
		w := httptest.NewRecorder()
		h.handleBarrierInitialize(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPost, "/admin/barrier/initialize", w)
	})

	t.Run("initialize_bad_request", func(t *testing.T) {
		h := NewBarrierHandlers(newStubBarrierService(), logger)
		req := httptest.NewRequest(http.MethodPost, "/admin/barrier/initialize", bytes.NewBufferString(`{"secret":""}`))
		w := httptest.NewRecorder()
		h.handleBarrierInitialize(w, req)
		require.Equal(t, http.StatusBadRequest, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPost, "/admin/barrier/initialize", w)
	})

	t.Run("initialize_conflict", func(t *testing.T) {
		stub := newStubBarrierService()
		stub.initErr = &BarrierNotEnabledError{Operation: "initialize"}
		h := NewBarrierHandlers(stub, logger)
		req := httptest.NewRequest(http.MethodPost, "/admin/barrier/initialize", bytes.NewBufferString(`{"secret":"x"}`))
		w := httptest.NewRecorder()
		h.handleBarrierInitialize(w, req)
		require.Equal(t, http.StatusConflict, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPost, "/admin/barrier/initialize", w)
	})

	t.Run("seal_success", func(t *testing.T) {
		h := NewBarrierHandlers(newStubBarrierService(), logger)
		req := httptest.NewRequest(http.MethodPost, "/admin/barrier/seal", nil)
		w := httptest.NewRecorder()
		h.handleBarrierSeal(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPost, "/admin/barrier/seal", w)
	})

	t.Run("unseal_success", func(t *testing.T) {
		h := NewBarrierHandlers(newStubBarrierService(), logger)
		req := httptest.NewRequest(http.MethodPost, "/admin/barrier/unseal", bytes.NewBufferString(`{"secret":"correct horse battery staple"}`))
		w := httptest.NewRecorder()
		h.handleBarrierUnseal(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPost, "/admin/barrier/unseal", w)
	})

	t.Run("shamir_initialize_success", func(t *testing.T) {
		h := NewBarrierHandlers(newStubBarrierService(), logger)
		req := httptest.NewRequest(http.MethodPost, "/admin/barrier/shamir/initialize",
			bytes.NewBufferString(`{"secret":"x","threshold":2,"total_shares":3}`))
		w := httptest.NewRecorder()
		h.handleBarrierShamirInitialize(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPost, "/admin/barrier/shamir/initialize", w)
	})

	t.Run("shamir_unseal_share_success", func(t *testing.T) {
		h := NewBarrierHandlers(newStubBarrierService(), logger)
		req := httptest.NewRequest(http.MethodPost, "/admin/barrier/shamir/unseal-share", bytes.NewBufferString(`{"share":"share-1"}`))
		w := httptest.NewRecorder()
		h.handleBarrierShamirUnsealShare(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPost, "/admin/barrier/shamir/unseal-share", w)
	})

	t.Run("rekey_success", func(t *testing.T) {
		h := NewBarrierHandlers(newStubBarrierService(), logger)
		req := httptest.NewRequest(http.MethodPost, "/admin/barrier/rekey", bytes.NewBufferString(`{"threshold":2,"total":3}`))
		w := httptest.NewRecorder()
		h.handleBarrierRekey(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPost, "/admin/barrier/rekey", w)
	})

	t.Run("recovery_generate_success", func(t *testing.T) {
		h := NewBarrierHandlers(newStubBarrierService(), logger)
		req := httptest.NewRequest(http.MethodPost, "/admin/barrier/recovery/generate", bytes.NewBufferString(`{"threshold":2,"total":3}`))
		w := httptest.NewRecorder()
		h.handleBarrierRecoveryGenerate(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPost, "/admin/barrier/recovery/generate", w)
	})

	t.Run("recovery_recover_success", func(t *testing.T) {
		h := NewBarrierHandlers(newStubBarrierService(), logger)
		req := httptest.NewRequest(http.MethodPost, "/admin/barrier/recovery/recover", bytes.NewBufferString(`{"keys":["k1","k2"]}`))
		w := httptest.NewRecorder()
		h.handleBarrierRecoveryRecover(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPost, "/admin/barrier/recovery/recover", w)
	})

	t.Run("recovery_status_success", func(t *testing.T) {
		h := NewBarrierHandlers(newStubBarrierService(), logger)
		req := httptest.NewRequest(http.MethodGet, "/admin/barrier/recovery/status", nil)
		w := httptest.NewRecorder()
		h.handleBarrierRecoveryStatus(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodGet, "/admin/barrier/recovery/status", w)
	})

	t.Run("root_token_success", func(t *testing.T) {
		h := NewBarrierHandlers(newStubBarrierService(), logger)
		req := httptest.NewRequest(http.MethodPost, "/admin/barrier/root-token", bytes.NewBufferString(`{"shares":["s1","s2"]}`))
		w := httptest.NewRecorder()
		h.handleBarrierRootToken(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		requireResponseMatchesSpec(t, router, http.MethodPost, "/admin/barrier/root-token", w)
	})
}
