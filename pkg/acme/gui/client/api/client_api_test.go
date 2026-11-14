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

// Tests live in the same package so that unexported handler methods and the
// handlers struct fields are directly accessible.

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	svc "github.com/jeremyhahn/go-xkms/pkg/acme/client/service"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/workflow"
)

// =============================================================================
// Fake workflow
// =============================================================================

// fakeWorkflow satisfies workflow.Workflow with configurable per-method funcs.
type fakeWorkflow struct {
	registerFunc func(ctx context.Context, req *workflow.RegisterRequest) (*workflow.RegisterResponse, error)
	revokeFunc   func(ctx context.Context, req *workflow.RevokeRequest) error
}

func (f *fakeWorkflow) Register(ctx context.Context, req *workflow.RegisterRequest) (*workflow.RegisterResponse, error) {
	if f.registerFunc != nil {
		return f.registerFunc(ctx, req)
	}
	return &workflow.RegisterResponse{
		AccountURL: "https://ca.example.com/acme/acct/1",
		Status:     "valid",
		Contact:    []string{"mailto:test@example.com"},
	}, nil
}

func (f *fakeWorkflow) RequestCertificate(ctx context.Context, req *workflow.CertificateRequest) (*workflow.CertificateResponse, error) {
	return nil, errors.New("not implemented in fake")
}

func (f *fakeWorkflow) RevokeCertificate(ctx context.Context, req *workflow.RevokeRequest) error {
	if f.revokeFunc != nil {
		return f.revokeFunc(ctx, req)
	}
	return nil
}

// =============================================================================
// Helpers
// =============================================================================

// makeConfig returns a minimal *svc.Config with optional accounts and certs.
func makeConfig(accounts map[string]*svc.AccountConfig, certs map[string]*svc.CertificateSpec) *svc.Config {
	cfg := svc.DefaultConfig()
	if accounts != nil {
		cfg.Accounts = accounts
	}
	if certs != nil {
		cfg.Certificates = certs
	}
	return cfg
}

// makeSvcFromConfig builds a *svc.Service from the given config.
func makeSvcFromConfig(cfg *svc.Config) *svc.Service {
	s, _ := svc.NewService(cfg, slog.Default())
	return s
}

// newHandlersFor is the central helper: build a handlers struct with a real
// service backed by the given config fixtures.
func newHandlersFor(wf workflow.Workflow, accounts map[string]*svc.AccountConfig, certs map[string]*svc.CertificateSpec) *handlers {
	cfg := makeConfig(accounts, certs)
	return &handlers{
		wf:      wf,
		service: makeSvcFromConfig(cfg),
		logger:  slog.Default(),
	}
}

// routerFor builds a full gorilla/mux router for the given test fixture.
func routerFor(wf workflow.Workflow, accounts map[string]*svc.AccountConfig, certs map[string]*svc.CertificateSpec) http.Handler {
	h := newHandlersFor(wf, accounts, certs)
	return NewRouter(wf, h.service, h.logger)
}

// emptyRouter returns a router with no accounts or certs and no workflow.
func emptyRouter() http.Handler { return routerFor(nil, nil, nil) }

// jsonBody encodes v and returns a request body reader.
func jsonBody(t *testing.T, v interface{}) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return bytes.NewReader(b)
}

// doRequest performs a request against the given handler and returns the recorder.
func doRequest(handler http.Handler, method, path string, body *bytes.Reader) *httptest.ResponseRecorder {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, body)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// =============================================================================
// Error type tests
// =============================================================================

func TestErrInvalidRequestBody_Error(t *testing.T) {
	e := &ErrInvalidRequestBody{Detail: "unexpected EOF"}
	if !strings.Contains(e.Error(), "unexpected EOF") {
		t.Errorf("expected detail in message: %q", e.Error())
	}
}

func TestErrServiceCall_Error(t *testing.T) {
	e := &ErrServiceCall{Operation: "add account", Detail: "conflict"}
	msg := e.Error()
	if !strings.Contains(msg, "add account") || !strings.Contains(msg, "conflict") {
		t.Errorf("expected op+detail in message: %q", msg)
	}
}

func TestErrMissingField_Error(t *testing.T) {
	e := &ErrMissingField{Field: "name"}
	if !strings.Contains(e.Error(), "name") {
		t.Errorf("expected field in message: %q", e.Error())
	}
}

// =============================================================================
// writeJSON / writeError
// =============================================================================

func TestWriteJSON_SetsContentTypeAndStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusCreated, map[string]string{"k": "v"})
	if rec.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %q", ct)
	}
	var resp apiResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data == nil {
		t.Error("expected non-nil Data")
	}
}

func TestWriteError_SetsErrorField(t *testing.T) {
	rec := httptest.NewRecorder()
	writeError(rec, http.StatusBadRequest, "bad input")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
	var resp apiResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error == "" {
		t.Error("expected non-empty Error field")
	}
}

// failingResponseWriter is an http.ResponseWriter whose Write always fails,
// simulating a client that disconnects mid-response so json.Encoder.Encode
// cannot finish writing the body.
type failingResponseWriter struct {
	header http.Header
}

func (w *failingResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *failingResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("simulated write failure")
}

func (w *failingResponseWriter) WriteHeader(int) {}

// TestWriteJSON_LogsEncodeFailure verifies that a failure to write the
// response body — which can no longer be reported to the client because
// headers are already sent — is logged rather than silently dropped.
func TestWriteJSON_LogsEncodeFailure(t *testing.T) {
	var logBuf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, nil)))
	defer slog.SetDefault(prev)

	writeJSON(&failingResponseWriter{}, http.StatusOK, map[string]string{"k": "v"})

	if !strings.Contains(logBuf.String(), "failed to write JSON response") {
		t.Errorf("expected write failure to be logged, got: %s", logBuf.String())
	}
}

// TestWriteError_LogsEncodeFailure is TestWriteJSON_LogsEncodeFailure for
// the error-response encoder.
func TestWriteError_LogsEncodeFailure(t *testing.T) {
	var logBuf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, nil)))
	defer slog.SetDefault(prev)

	writeError(&failingResponseWriter{}, http.StatusBadRequest, "bad input")

	if !strings.Contains(logBuf.String(), "failed to write JSON error response") {
		t.Errorf("expected write failure to be logged, got: %s", logBuf.String())
	}
}

// =============================================================================
// register (POST /api/v1/account/register)
// =============================================================================

func TestRegister_ViaWorkflow_Success(t *testing.T) {
	router := routerFor(&fakeWorkflow{}, nil, nil)
	rec := doRequest(router, http.MethodPost, "/api/v1/account/register",
		jsonBody(t, map[string]string{"email": "user@example.com"}))
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRegister_ViaWorkflow_Error(t *testing.T) {
	wf := &fakeWorkflow{
		registerFunc: func(_ context.Context, _ *workflow.RegisterRequest) (*workflow.RegisterResponse, error) {
			return nil, errors.New("ACME error")
		},
	}
	rec := doRequest(routerFor(wf, nil, nil), http.MethodPost, "/api/v1/account/register",
		jsonBody(t, map[string]string{"email": "user@example.com"}))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestRegister_NoWorkflow_ReturnsBadRequest(t *testing.T) {
	rec := doRequest(emptyRouter(), http.MethodPost, "/api/v1/account/register",
		jsonBody(t, map[string]string{"email": "user@example.com"}))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when no workflow, got %d", rec.Code)
	}
}

func TestRegister_InvalidJSON(t *testing.T) {
	rec := doRequest(emptyRouter(), http.MethodPost, "/api/v1/account/register",
		bytes.NewReader([]byte("not-json")))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

// =============================================================================
// addAccount (POST /api/v1/accounts)
// =============================================================================

func TestAddAccount_Success(t *testing.T) {
	body := map[string]interface{}{
		"name":      "new-acct",
		"email":     "user@example.com",
		"directory": "https://ca.example.com/directory",
		"key":       map[string]string{"algorithm": "ECDSA", "store": "software"},
	}
	rec := doRequest(emptyRouter(), http.MethodPost, "/api/v1/accounts", jsonBody(t, body))
	if rec.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAddAccount_Duplicate(t *testing.T) {
	accounts := map[string]*svc.AccountConfig{
		"dup": {
			DirectoryURL: "https://ca.example.com",
			Email:        "a@b.com",
			Key:          &svc.KeyConfig{Algorithm: "ECDSA", Store: "software"},
		},
	}
	body := map[string]interface{}{
		"name":      "dup",
		"email":     "x@y.com",
		"directory": "https://ca.example.com",
		"key":       map[string]string{"algorithm": "ECDSA", "store": "software"},
	}
	rec := doRequest(routerFor(nil, accounts, nil), http.MethodPost, "/api/v1/accounts", jsonBody(t, body))
	if rec.Code != http.StatusConflict {
		t.Errorf("expected 409 for duplicate, got %d", rec.Code)
	}
}

func TestAddAccount_MissingName(t *testing.T) {
	body := map[string]string{"email": "a@b.com", "directory": "https://ca"}
	rec := doRequest(emptyRouter(), http.MethodPost, "/api/v1/accounts", jsonBody(t, body))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestAddAccount_MissingDirectory(t *testing.T) {
	body := map[string]string{"name": "x", "email": "a@b.com"}
	rec := doRequest(emptyRouter(), http.MethodPost, "/api/v1/accounts", jsonBody(t, body))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestAddAccount_MissingEmail(t *testing.T) {
	body := map[string]string{"name": "x", "directory": "https://ca"}
	rec := doRequest(emptyRouter(), http.MethodPost, "/api/v1/accounts", jsonBody(t, body))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestAddAccount_InvalidJSON(t *testing.T) {
	rec := doRequest(emptyRouter(), http.MethodPost, "/api/v1/accounts",
		bytes.NewReader([]byte("{bad")))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

// =============================================================================
// getAccount (GET /api/v1/accounts/{name})
// =============================================================================

func TestGetAccount_Success(t *testing.T) {
	accounts := map[string]*svc.AccountConfig{
		"myacct": {DirectoryURL: "https://ca.example.com", Email: "a@b.com"},
	}
	rec := doRequest(routerFor(nil, accounts, nil), http.MethodGet, "/api/v1/accounts/myacct", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGetAccount_NotFound(t *testing.T) {
	rec := doRequest(emptyRouter(), http.MethodGet, "/api/v1/accounts/nonexistent", nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

// =============================================================================
// removeAccount (DELETE /api/v1/accounts/{name})
// =============================================================================

func TestRemoveAccount_Success(t *testing.T) {
	accounts := map[string]*svc.AccountConfig{
		"todel": {
			DirectoryURL: "https://ca.example.com",
			Email:        "a@b.com",
			Key:          &svc.KeyConfig{Algorithm: "ECDSA", Store: "software"},
		},
	}
	rec := doRequest(routerFor(nil, accounts, nil), http.MethodDelete, "/api/v1/accounts/todel", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRemoveAccount_NotFound(t *testing.T) {
	rec := doRequest(emptyRouter(), http.MethodDelete, "/api/v1/accounts/nope", nil)
	if rec.Code != http.StatusConflict {
		t.Errorf("expected 409 for not-found removal, got %d", rec.Code)
	}
}

// =============================================================================
// requestCert (POST /api/v1/certificate/request) — direct handler invocation
// =============================================================================

func TestRequestCert_MissingName(t *testing.T) {
	h := newHandlersFor(nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]string{}))
	req.Header.Set("Content-Type", "application/json")
	h.requestCert(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing name, got %d", rec.Code)
	}
}

func TestRequestCert_InvalidJSON(t *testing.T) {
	h := newHandlersFor(nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("not-json")))
	req.Header.Set("Content-Type", "application/json")
	h.requestCert(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestRequestCert_CertSpecNotFound(t *testing.T) {
	h := newHandlersFor(nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]string{"name": "missing"}))
	req.Header.Set("Content-Type", "application/json")
	h.requestCert(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for missing spec, got %d", rec.Code)
	}
}

// =============================================================================
// renewCert (POST /api/v1/certificate/renew)
// =============================================================================

func TestRenewCert_MissingName(t *testing.T) {
	h := newHandlersFor(nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]string{}))
	req.Header.Set("Content-Type", "application/json")
	h.renewCert(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing name, got %d", rec.Code)
	}
}

func TestRenewCert_InvalidJSON(t *testing.T) {
	h := newHandlersFor(nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("bad")))
	req.Header.Set("Content-Type", "application/json")
	h.renewCert(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestRenewCert_SpecNotFound(t *testing.T) {
	h := newHandlersFor(nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]string{"name": "nonexistent"}))
	req.Header.Set("Content-Type", "application/json")
	h.renewCert(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for unknown cert, got %d", rec.Code)
	}
}

// =============================================================================
// revokeCert
// =============================================================================

func TestRevokeCert_ViaWorkflow_Success(t *testing.T) {
	wf := &fakeWorkflow{}
	rec := doRequest(routerFor(wf, nil, nil), http.MethodPost, "/api/v1/certificate/revoke",
		jsonBody(t, map[string]interface{}{
			"certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
			"reason":      0,
		}))
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRevokeCert_ViaWorkflow_Error(t *testing.T) {
	wf := &fakeWorkflow{
		revokeFunc: func(_ context.Context, _ *workflow.RevokeRequest) error {
			return errors.New("revocation failed")
		},
	}
	rec := doRequest(routerFor(wf, nil, nil), http.MethodPost, "/api/v1/certificate/revoke",
		jsonBody(t, map[string]interface{}{
			"certificate": "-----BEGIN CERTIFICATE-----",
			"reason":      0,
		}))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestRevokeCert_ViaService_MissingName(t *testing.T) {
	// No workflow, empty certificate field → revokeViaService, missing name.
	rec := doRequest(emptyRouter(), http.MethodPost, "/api/v1/certificate/revoke",
		jsonBody(t, map[string]interface{}{"reason": 0}))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing name, got %d", rec.Code)
	}
}

func TestRevokeCert_ViaService_SpecNotFound(t *testing.T) {
	rec := doRequest(emptyRouter(), http.MethodPost, "/api/v1/certificate/revoke",
		jsonBody(t, map[string]interface{}{"name": "web", "reason": 0}))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for not-found cert, got %d", rec.Code)
	}
}

func TestRevokeCert_InvalidJSON(t *testing.T) {
	h := newHandlersFor(nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("bad")))
	req.Header.Set("Content-Type", "application/json")
	h.revokeCert(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

// =============================================================================
// listCertificates
// =============================================================================

func TestListCertificates_WithFilter(t *testing.T) {
	certs := map[string]*svc.CertificateSpec{
		"web": {Account: "acc1", Subject: svc.SubjectConfig{CN: "web.example.com"}},
		"api": {Account: "acc2", Subject: svc.SubjectConfig{CN: "api.example.com"}},
	}
	rec := doRequest(routerFor(nil, nil, certs), http.MethodGet, "/api/v1/certificates?account=acc1", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

// =============================================================================
// getCertificate
// =============================================================================

func TestGetCertificate_FallsBackToSpec(t *testing.T) {
	certs := map[string]*svc.CertificateSpec{
		"web": {Account: "acc", Subject: svc.SubjectConfig{CN: "web.example.com"}},
	}
	// Show will fail (not yet managed), handler falls back to spec.
	rec := doRequest(routerFor(nil, nil, certs), http.MethodGet, "/api/v1/certificates/web", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 via spec fallback, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGetCertificate_NotFound(t *testing.T) {
	rec := doRequest(emptyRouter(), http.MethodGet, "/api/v1/certificates/nonexistent", nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

// =============================================================================
// deployCertificate
// =============================================================================

func TestDeployCertificate_NotInConfig(t *testing.T) {
	rec := doRequest(emptyRouter(), http.MethodPost, "/api/v1/certificates/nonexistent/deploy", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

// =============================================================================
// device handlers — error paths. Success-path (200) coverage lives in
// device_handlers_simulator_test.go, gated by the tpm_simulator build tag:
// a real device enrollment/attestation needs the in-process TPM 2.0
// simulator, which is only compiled in under that tag.
// =============================================================================

func TestDeviceEnroll_MissingName(t *testing.T) {
	rec := doRequest(emptyRouter(), http.MethodPost, "/api/v1/device/enroll", jsonBody(t, map[string]string{}))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing name, got %d", rec.Code)
	}
}

func TestDeviceEnroll_InvalidJSON(t *testing.T) {
	rec := doRequest(emptyRouter(), http.MethodPost, "/api/v1/device/enroll", bytes.NewReader([]byte("not-json")))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestDeviceEnroll_UnknownDevice(t *testing.T) {
	rec := doRequest(emptyRouter(), http.MethodPost, "/api/v1/device/enroll",
		jsonBody(t, map[string]string{"name": "missing"}))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for unknown device, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDeviceAttest_MissingName(t *testing.T) {
	rec := doRequest(emptyRouter(), http.MethodPost, "/api/v1/device/attest", jsonBody(t, map[string]string{}))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing name, got %d", rec.Code)
	}
}

func TestDeviceAttest_InvalidJSON(t *testing.T) {
	rec := doRequest(emptyRouter(), http.MethodPost, "/api/v1/device/attest", bytes.NewReader([]byte("not-json")))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestDeviceAttest_UnknownDevice(t *testing.T) {
	rec := doRequest(emptyRouter(), http.MethodPost, "/api/v1/device/attest",
		jsonBody(t, map[string]string{"name": "missing"}))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for unknown device, got %d: %s", rec.Code, rec.Body.String())
	}
}

// =============================================================================
// single-config / single-renewal-policy endpoints: removed outright
// =============================================================================

// TestSingleConfigEndpoints_Removed pins the removal of the single-account
// /api/v1/config and /api/v1/renewal/{status,config} endpoints. The service
// is multi-account (Accounts/Certificates); these handlers used to paper
// over that with a made-up "default" account/certificate key. The real
// per-account settings live at /api/v1/accounts[/​{name}], and per-certificate
// renewal policy (auto/days-before) is part of the CertificateSpec returned
// by /api/v1/certificates[/​{name}] — there is no global config or renewal
// policy left to expose.
func TestSingleConfigEndpoints_Removed(t *testing.T) {
	router := emptyRouter()
	for _, tt := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/config"},
		{http.MethodPut, "/api/v1/config"},
		{http.MethodGet, "/api/v1/renewal/status"},
		{http.MethodGet, "/api/v1/renewal/config"},
		{http.MethodPut, "/api/v1/renewal/config"},
	} {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			rec := doRequest(router, tt.method, tt.path, nil)
			if rec.Code != http.StatusNotFound {
				t.Errorf("expected 404 (route removed), got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}
