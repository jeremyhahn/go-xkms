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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/acme/api"
)

// tlsMinVersionTLS13 mirrors the floor NewAdapter installs; naming it makes
// the assertion below read as a policy check rather than a magic number.
const tlsMinVersionTLS13 = tls.VersionTLS13

// testCertKeyPEM generates a self-signed P-256 certificate and its private key
// in PEM form, for exercising the adapter's TLS file-loading branches without
// checking key material into the repository.
func testCertKeyPEM(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "acme-admin-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// writeTempFile writes contents into dir/name and returns the full path.
func writeTempFile(t *testing.T, dir, name string, contents []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
	return path
}

// capturedRequest records what the adapter actually put on the wire so the
// tests can assert on the HTTP method, path, query string, and JSON body —
// the parts of the contract the server depends on.
type capturedRequest struct {
	Method string
	Path   string
	Query  url.Values
	Body   []byte
	Auth   string
}

// newCapturingServer starts an httptest server that records the incoming
// request and replies with status and body. body may be a string (written
// verbatim, so malformed payloads can be exercised) or any JSON-marshalable
// value.
func newCapturingServer(t *testing.T, status int, body any) (*httptest.Server, *capturedRequest) {
	t.Helper()
	captured := &capturedRequest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading request body: %v", err)
		}
		captured.Method = r.Method
		captured.Path = r.URL.Path
		captured.Query = r.URL.Query()
		captured.Body = raw
		captured.Auth = r.Header.Get("Authorization")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		switch v := body.(type) {
		case nil:
		case string:
			_, _ = w.Write([]byte(v))
		default:
			_ = json.NewEncoder(w).Encode(v)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, captured
}

// newAdapterFor builds an adapter pointed at srv with a fixed bearer token.
func newAdapterFor(t *testing.T, srv *httptest.Server) *Adapter {
	t.Helper()
	a, err := NewAdapter(&api.AdapterConfig{BaseURL: srv.URL, AuthToken: "test-token"})
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

// problemJSON is a well-formed RFC 7807 problem document as the ACME admin
// server emits it.
const problemJSON = `{"type":"urn:trusted-ca:error:not-found","title":"Not Found","detail":"tenant does not exist","status":404}`

// assertProblemSurfaced checks that an RFC 7807 body reaches the caller with
// its title, detail, and status intact. Losing any of the three leaves an
// operator with an opaque "request failed" and no way to act.
func assertProblemSurfaced(t *testing.T, err error, wantStatus string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error for a problem-detail response, got nil")
	}
	msg := err.Error()
	for _, want := range []string{"Not Found", "tenant does not exist", wantStatus} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not carry %q from the problem document", msg, want)
		}
	}
}

// TestUpdateTenantStatus covers the tenant status transition: the PUT target,
// the request body the server parses, and both error shapes.
func TestUpdateTenantStatus(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv, got := newCapturingServer(t, http.StatusNoContent, nil)
		a := newAdapterFor(t, srv)

		if err := a.UpdateTenantStatus(context.Background(), "tenant-1", "suspended"); err != nil {
			t.Fatalf("UpdateTenantStatus: %v", err)
		}
		if got.Method != http.MethodPut {
			t.Errorf("method = %s, want PUT", got.Method)
		}
		if got.Path != "/api/v1/tenants/tenant-1/status" {
			t.Errorf("path = %s, want /api/v1/tenants/tenant-1/status", got.Path)
		}
		if got.Auth != "Bearer test-token" {
			t.Errorf("Authorization = %q, want the bearer token", got.Auth)
		}
		var body admin.UpdateTenantStatusRequest
		if err := json.Unmarshal(got.Body, &body); err != nil {
			t.Fatalf("request body is not the expected JSON: %v (%s)", err, got.Body)
		}
		if body.Status != "suspended" {
			t.Errorf("body status = %q, want suspended", body.Status)
		}
	})

	t.Run("problem detail", func(t *testing.T) {
		srv, _ := newCapturingServer(t, http.StatusNotFound, problemJSON)
		a := newAdapterFor(t, srv)
		assertProblemSurfaced(t, a.UpdateTenantStatus(context.Background(), "ghost", "active"), "404")
	})

	t.Run("non-problem error body", func(t *testing.T) {
		srv, _ := newCapturingServer(t, http.StatusInternalServerError, "upstream exploded")
		a := newAdapterFor(t, srv)
		err := a.UpdateTenantStatus(context.Background(), "tenant-1", "active")
		if err == nil {
			t.Fatal("expected an error for a 500 response")
		}
		// A body that is not a problem document must still reach the operator.
		if !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "upstream exploded") {
			t.Errorf("error %q loses the status or the raw body", err)
		}
	})
}

// TestCreateTenantRootCA covers the root-CA creation call, including that the
// request body round-trips every field the CA service needs (a dropped
// validity or algorithm silently produces the wrong CA).
func TestCreateTenantRootCA(t *testing.T) {
	want := &admin.TenantRootCAInfo{
		CommonName:   "Tenant Alpha Root",
		SerialNumber: "0A0B0C",
		KeyAlgorithm: "ECDSA",
		Status:       "active",
	}

	t.Run("success", func(t *testing.T) {
		srv, got := newCapturingServer(t, http.StatusCreated, want)
		a := newAdapterFor(t, srv)

		req := &admin.CreateTenantRootCARequest{
			CommonName:    "Tenant Alpha Root",
			KeyAlgorithm:  "ECDSA",
			ValidityYears: 10,
		}
		info, err := a.CreateTenantRootCA(context.Background(), "tenant-1", req)
		if err != nil {
			t.Fatalf("CreateTenantRootCA: %v", err)
		}
		if got.Method != http.MethodPost || got.Path != "/api/v1/tenants/tenant-1/root-ca" {
			t.Errorf("request = %s %s, want POST /api/v1/tenants/tenant-1/root-ca", got.Method, got.Path)
		}
		var sent admin.CreateTenantRootCARequest
		if err := json.Unmarshal(got.Body, &sent); err != nil {
			t.Fatalf("request body: %v", err)
		}
		if sent != *req {
			t.Errorf("server received %+v, want %+v", sent, *req)
		}
		if info.CommonName != want.CommonName || info.SerialNumber != want.SerialNumber || info.Status != want.Status {
			t.Errorf("decoded %+v, want %+v", info, want)
		}
	})

	t.Run("problem detail", func(t *testing.T) {
		srv, _ := newCapturingServer(t, http.StatusConflict, problemJSON)
		a := newAdapterFor(t, srv)
		info, err := a.CreateTenantRootCA(context.Background(), "tenant-1", &admin.CreateTenantRootCARequest{})
		assertProblemSurfaced(t, err, "409")
		if info != nil {
			t.Errorf("returned a CA alongside an error: %+v", info)
		}
	})

	t.Run("malformed success body", func(t *testing.T) {
		srv, _ := newCapturingServer(t, http.StatusOK, `{"common_name": `)
		a := newAdapterFor(t, srv)
		if _, err := a.CreateTenantRootCA(context.Background(), "tenant-1", &admin.CreateTenantRootCARequest{}); err == nil {
			t.Fatal("a truncated JSON body was accepted")
		}
	})
}

// TestGetTenantCAStatus covers the CA status read, including the nested
// intermediate list — a decode regression there would silently report a
// tenant as unable to issue certificates.
func TestGetTenantCAStatus(t *testing.T) {
	want := &admin.TenantCAStatusInfo{
		TenantID:                "tenant-1",
		RootCA:                  &admin.TenantRootCAInfo{CommonName: "Root", Status: "active"},
		IntermediateCAs:         []*admin.TenantIntCAInfo{{ID: "int-1", CommonName: "Int", Status: "active"}},
		DefaultIntermediateCAID: "int-1",
		ActiveCACount:           2,
		CanIssueCerts:           true,
	}

	t.Run("success", func(t *testing.T) {
		srv, got := newCapturingServer(t, http.StatusOK, want)
		a := newAdapterFor(t, srv)

		status, err := a.GetTenantCAStatus(context.Background(), "tenant-1")
		if err != nil {
			t.Fatalf("GetTenantCAStatus: %v", err)
		}
		if got.Method != http.MethodGet || got.Path != "/api/v1/tenants/tenant-1/ca-status" {
			t.Errorf("request = %s %s, want GET /api/v1/tenants/tenant-1/ca-status", got.Method, got.Path)
		}
		if len(got.Body) != 0 {
			t.Errorf("a GET must not carry a body, got %q", got.Body)
		}
		if status.TenantID != "tenant-1" || !status.CanIssueCerts || status.ActiveCACount != 2 {
			t.Errorf("decoded %+v, want %+v", status, want)
		}
		if status.RootCA == nil || status.RootCA.CommonName != "Root" {
			t.Errorf("root CA not decoded: %+v", status.RootCA)
		}
		if len(status.IntermediateCAs) != 1 || status.IntermediateCAs[0].ID != "int-1" {
			t.Errorf("intermediate CAs not decoded: %+v", status.IntermediateCAs)
		}
		if status.DefaultIntermediateCAID != "int-1" {
			t.Errorf("default intermediate = %q, want int-1", status.DefaultIntermediateCAID)
		}
	})

	t.Run("problem detail", func(t *testing.T) {
		srv, _ := newCapturingServer(t, http.StatusNotFound, problemJSON)
		a := newAdapterFor(t, srv)
		status, err := a.GetTenantCAStatus(context.Background(), "ghost")
		assertProblemSurfaced(t, err, "404")
		if status != nil {
			t.Errorf("returned a status alongside an error: %+v", status)
		}
	})
}

// TestTenantIntermediateCAOperations covers create / list / get / update-status
// for intermediate CAs, which share a path prefix and are easy to cross-wire.
func TestTenantIntermediateCAOperations(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		want := &admin.TenantIntCAInfo{ID: "int-1", CommonName: "Int CA", ParentType: "tenant", Status: "active"}
		srv, got := newCapturingServer(t, http.StatusCreated, want)
		a := newAdapterFor(t, srv)

		req := &admin.CreateTenantIntermediateCARequest{
			CommonName:    "Int CA",
			ParentType:    "tenant",
			Purpose:       "server-auth",
			KeyAlgorithm:  "ECDSA",
			ValidityYears: 5,
			SetAsDefault:  true,
		}
		info, err := a.CreateTenantIntermediateCA(context.Background(), "tenant-1", req)
		if err != nil {
			t.Fatalf("CreateTenantIntermediateCA: %v", err)
		}
		if got.Method != http.MethodPost || got.Path != "/api/v1/tenants/tenant-1/intermediate-cas" {
			t.Errorf("request = %s %s", got.Method, got.Path)
		}
		var sent admin.CreateTenantIntermediateCARequest
		if err := json.Unmarshal(got.Body, &sent); err != nil {
			t.Fatalf("request body: %v", err)
		}
		if sent != *req {
			t.Errorf("server received %+v, want %+v", sent, *req)
		}
		if info.ID != "int-1" || info.ParentType != "tenant" {
			t.Errorf("decoded %+v, want %+v", info, want)
		}
	})

	t.Run("create problem detail", func(t *testing.T) {
		srv, _ := newCapturingServer(t, http.StatusUnprocessableEntity, problemJSON)
		a := newAdapterFor(t, srv)
		info, err := a.CreateTenantIntermediateCA(context.Background(), "t", &admin.CreateTenantIntermediateCARequest{})
		assertProblemSurfaced(t, err, "422")
		if info != nil {
			t.Errorf("returned a CA alongside an error: %+v", info)
		}
	})

	t.Run("list", func(t *testing.T) {
		want := []*admin.TenantIntCAInfo{
			{ID: "int-1", CommonName: "A", Status: "active"},
			{ID: "int-2", CommonName: "B", Status: "revoked"},
		}
		srv, got := newCapturingServer(t, http.StatusOK, want)
		a := newAdapterFor(t, srv)

		cas, err := a.ListTenantIntermediateCAs(context.Background(), "tenant-1")
		if err != nil {
			t.Fatalf("ListTenantIntermediateCAs: %v", err)
		}
		if got.Method != http.MethodGet || got.Path != "/api/v1/tenants/tenant-1/intermediate-cas" {
			t.Errorf("request = %s %s", got.Method, got.Path)
		}
		if len(cas) != 2 || cas[0].ID != "int-1" || cas[1].Status != "revoked" {
			t.Errorf("decoded %+v, want %+v", cas, want)
		}
	})

	t.Run("list empty body yields no CAs and no error", func(t *testing.T) {
		// The adapter treats an empty 200 body as "nothing to decode"; callers
		// must see an empty list rather than a spurious decode failure.
		srv, _ := newCapturingServer(t, http.StatusOK, nil)
		a := newAdapterFor(t, srv)
		cas, err := a.ListTenantIntermediateCAs(context.Background(), "tenant-1")
		if err != nil {
			t.Fatalf("empty body produced an error: %v", err)
		}
		if len(cas) != 0 {
			t.Errorf("expected no CAs, got %+v", cas)
		}
	})

	t.Run("list problem detail", func(t *testing.T) {
		srv, _ := newCapturingServer(t, http.StatusForbidden, problemJSON)
		a := newAdapterFor(t, srv)
		cas, err := a.ListTenantIntermediateCAs(context.Background(), "tenant-1")
		assertProblemSurfaced(t, err, "403")
		if cas != nil {
			t.Errorf("returned CAs alongside an error: %+v", cas)
		}
	})

	t.Run("get", func(t *testing.T) {
		want := &admin.TenantIntCAInfo{ID: "int-7", CommonName: "Seven", Status: "active"}
		srv, got := newCapturingServer(t, http.StatusOK, want)
		a := newAdapterFor(t, srv)

		info, err := a.GetTenantIntermediateCA(context.Background(), "tenant-1", "int-7")
		if err != nil {
			t.Fatalf("GetTenantIntermediateCA: %v", err)
		}
		if got.Path != "/api/v1/tenants/tenant-1/intermediate-cas/int-7" {
			t.Errorf("path = %s, want the CA ID appended", got.Path)
		}
		if info.ID != "int-7" {
			t.Errorf("decoded %+v, want %+v", info, want)
		}
	})

	t.Run("get problem detail", func(t *testing.T) {
		srv, _ := newCapturingServer(t, http.StatusNotFound, problemJSON)
		a := newAdapterFor(t, srv)
		info, err := a.GetTenantIntermediateCA(context.Background(), "tenant-1", "ghost")
		assertProblemSurfaced(t, err, "404")
		if info != nil {
			t.Errorf("returned a CA alongside an error: %+v", info)
		}
	})

	t.Run("update status", func(t *testing.T) {
		srv, got := newCapturingServer(t, http.StatusOK, nil)
		a := newAdapterFor(t, srv)

		if err := a.UpdateTenantIntermediateCAStatus(context.Background(), "tenant-1", "int-7", "revoked"); err != nil {
			t.Fatalf("UpdateTenantIntermediateCAStatus: %v", err)
		}
		if got.Method != http.MethodPut {
			t.Errorf("method = %s, want PUT", got.Method)
		}
		if got.Path != "/api/v1/tenants/tenant-1/intermediate-cas/int-7" {
			t.Errorf("path = %s", got.Path)
		}
		var body admin.UpdateIntermediateCAStatusRequest
		if err := json.Unmarshal(got.Body, &body); err != nil {
			t.Fatalf("request body: %v", err)
		}
		if body.Status != "revoked" {
			t.Errorf("body status = %q, want revoked", body.Status)
		}
	})

	t.Run("update status problem detail", func(t *testing.T) {
		srv, _ := newCapturingServer(t, http.StatusNotFound, problemJSON)
		a := newAdapterFor(t, srv)
		assertProblemSurfaced(t, a.UpdateTenantIntermediateCAStatus(context.Background(), "t", "ghost", "revoked"), "404")
	})
}

// TestListOrders covers the paginated order listing and, critically, that the
// account and status filters reach the server. A dropped filter would show an
// admin every tenant's orders instead of the ones they asked for.
func TestListOrders(t *testing.T) {
	page := map[string]any{
		"items": []*admin.OrderInfo{
			{ID: 1, AccountID: 42, Status: "valid", Identifiers: []string{"a.example.com"}},
			{ID: 2, AccountID: 42, Status: "pending"},
		},
		"total":    2,
		"page":     3,
		"per_page": 25,
	}

	t.Run("filters are forwarded", func(t *testing.T) {
		srv, got := newCapturingServer(t, http.StatusOK, page)
		a := newAdapterFor(t, srv)

		orders, pagination, err := a.ListOrders(context.Background(), &admin.ListOrdersRequest{
			Page: 3, PerPage: 25, AccountID: 42, Status: "valid",
		})
		if err != nil {
			t.Fatalf("ListOrders: %v", err)
		}
		if got.Path != "/admin/orders" {
			t.Errorf("path = %s, want /admin/orders", got.Path)
		}
		for key, want := range map[string]string{
			"page": "3", "per_page": "25", "account_id": "42", "status": "valid",
		} {
			if got.Query.Get(key) != want {
				t.Errorf("query %s = %q, want %q (filter dropped)", key, got.Query.Get(key), want)
			}
		}
		if len(orders) != 2 || orders[0].ID != 1 || orders[1].Status != "pending" {
			t.Errorf("decoded orders %+v", orders)
		}
		if orders[0].AccountID != 42 || len(orders[0].Identifiers) != 1 {
			t.Errorf("order fields not decoded: %+v", orders[0])
		}
		if pagination == nil || pagination.Page != 3 || pagination.PerPage != 25 || pagination.Total != 2 {
			t.Errorf("pagination = %+v, want page 3 / per_page 25 / total 2", pagination)
		}
	})

	t.Run("optional filters are omitted when unset", func(t *testing.T) {
		srv, got := newCapturingServer(t, http.StatusOK, page)
		a := newAdapterFor(t, srv)

		if _, _, err := a.ListOrders(context.Background(), &admin.ListOrdersRequest{Page: 1, PerPage: 10}); err != nil {
			t.Fatalf("ListOrders: %v", err)
		}
		if _, ok := got.Query["account_id"]; ok {
			t.Error("account_id was sent even though the request left it zero")
		}
		if _, ok := got.Query["status"]; ok {
			t.Error("status was sent even though the request left it empty")
		}
	})

	t.Run("problem detail", func(t *testing.T) {
		srv, _ := newCapturingServer(t, http.StatusInternalServerError, problemJSON)
		a := newAdapterFor(t, srv)
		orders, pagination, err := a.ListOrders(context.Background(), &admin.ListOrdersRequest{Page: 1, PerPage: 10})
		assertProblemSurfaced(t, err, "500")
		if orders != nil || pagination != nil {
			t.Errorf("returned data alongside an error: %+v / %+v", orders, pagination)
		}
	})

	t.Run("malformed pagination envelope", func(t *testing.T) {
		srv, _ := newCapturingServer(t, http.StatusOK, `{"items": [`)
		a := newAdapterFor(t, srv)
		if _, _, err := a.ListOrders(context.Background(), &admin.ListOrdersRequest{Page: 1, PerPage: 10}); err == nil {
			t.Fatal("a truncated pagination envelope was accepted")
		}
	})

	t.Run("items of the wrong shape", func(t *testing.T) {
		// A well-formed envelope whose items are not orders must fail loudly
		// rather than yielding a slice of zero-valued orders.
		srv, _ := newCapturingServer(t, http.StatusOK, `{"items":["not-an-order"],"total":1,"page":1,"per_page":10}`)
		a := newAdapterFor(t, srv)
		if _, _, err := a.ListOrders(context.Background(), &admin.ListOrdersRequest{Page: 1, PerPage: 10}); err == nil {
			t.Fatal("items of the wrong shape were accepted")
		}
	})

	t.Run("empty body yields no orders and no pagination", func(t *testing.T) {
		srv, _ := newCapturingServer(t, http.StatusOK, nil)
		a := newAdapterFor(t, srv)
		orders, pagination, err := a.ListOrders(context.Background(), &admin.ListOrdersRequest{Page: 1, PerPage: 10})
		if err != nil {
			t.Fatalf("empty body produced an error: %v", err)
		}
		if len(orders) != 0 {
			t.Errorf("expected no orders, got %+v", orders)
		}
		if pagination != nil {
			t.Errorf("expected nil pagination for an empty body, got %+v", pagination)
		}
	})
}

// TestGetOrder_SendsAccountID is a regression test for a shipped bug: the
// admin handler (pkg/acme/admin/handlers.go GetOrder) parses account_id from
// the query string and rejects the request with 400 "Account ID is required"
// when it is missing. The REST adapter built the path without that parameter,
// so every admin GetOrder call over REST failed. The account scope is also a
// security control — it prevents an order lookup from crossing accounts — so
// the parameter must always be present, including when it is zero.
func TestGetOrder_SendsAccountID(t *testing.T) {
	want := &admin.OrderInfo{ID: 7, AccountID: 42, Status: "valid", Identifiers: []string{"a.example.com"}}

	t.Run("success", func(t *testing.T) {
		srv, got := newCapturingServer(t, http.StatusOK, want)
		a := newAdapterFor(t, srv)

		order, err := a.GetOrder(context.Background(), 7, 42)
		if err != nil {
			t.Fatalf("GetOrder: %v", err)
		}
		if got.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", got.Method)
		}
		if got.Path != "/admin/orders/7" {
			t.Errorf("path = %s, want /admin/orders/7", got.Path)
		}
		if got.Query.Get("account_id") != "42" {
			t.Fatalf("account_id = %q, want 42; the admin handler rejects the request without it", got.Query.Get("account_id"))
		}
		if order.ID != 7 || order.AccountID != 42 || order.Status != "valid" {
			t.Errorf("decoded %+v, want %+v", order, want)
		}
	})

	t.Run("zero account is still sent explicitly", func(t *testing.T) {
		srv, got := newCapturingServer(t, http.StatusOK, want)
		a := newAdapterFor(t, srv)

		if _, err := a.GetOrder(context.Background(), 7, 0); err != nil {
			t.Fatalf("GetOrder: %v", err)
		}
		if got.Query.Get("account_id") != "0" {
			t.Errorf("account_id = %q, want an explicit 0 so the server reports the scope error rather than a parse error", got.Query.Get("account_id"))
		}
	})

	t.Run("problem detail", func(t *testing.T) {
		srv, _ := newCapturingServer(t, http.StatusNotFound, problemJSON)
		a := newAdapterFor(t, srv)
		order, err := a.GetOrder(context.Background(), 99, 42)
		assertProblemSurfaced(t, err, "404")
		if order != nil {
			t.Errorf("returned an order alongside an error: %+v", order)
		}
	})

	t.Run("malformed body", func(t *testing.T) {
		srv, _ := newCapturingServer(t, http.StatusOK, `{"id": "not-a-number"}`)
		a := newAdapterFor(t, srv)
		if _, err := a.GetOrder(context.Background(), 7, 42); err == nil {
			t.Fatal("a body whose id is the wrong JSON type was accepted")
		}
	})
}

// TestDoRequest_UnreachableServer verifies transport failures surface as
// errors on every call shape (typed result, list result, and no result)
// instead of yielding a zero value the caller would treat as real data.
func TestDoRequest_UnreachableServer(t *testing.T) {
	srv, _ := newCapturingServer(t, http.StatusOK, nil)
	base := srv.URL
	srv.Close() // nothing is listening now

	a, err := NewAdapter(&api.AdapterConfig{BaseURL: base})
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	ctx := context.Background()

	if _, err := a.GetOrder(ctx, 1, 1); err == nil {
		t.Error("GetOrder succeeded against a closed server")
	}
	if _, _, err := a.ListOrders(ctx, &admin.ListOrdersRequest{Page: 1, PerPage: 10}); err == nil {
		t.Error("ListOrders succeeded against a closed server")
	}
	if err := a.UpdateTenantStatus(ctx, "t", "active"); err == nil {
		t.Error("UpdateTenantStatus succeeded against a closed server")
	}
	if _, err := a.GetTenantCAStatus(ctx, "t"); err == nil {
		t.Error("GetTenantCAStatus succeeded against a closed server")
	}
	if _, err := a.CreateTenantRootCA(ctx, "t", &admin.CreateTenantRootCARequest{}); err == nil {
		t.Error("CreateTenantRootCA succeeded against a closed server")
	}
	if _, err := a.CreateTenantIntermediateCA(ctx, "t", &admin.CreateTenantIntermediateCARequest{}); err == nil {
		t.Error("CreateTenantIntermediateCA succeeded against a closed server")
	}
	if _, err := a.ListTenantIntermediateCAs(ctx, "t"); err == nil {
		t.Error("ListTenantIntermediateCAs succeeded against a closed server")
	}
	if _, err := a.GetTenantIntermediateCA(ctx, "t", "c"); err == nil {
		t.Error("GetTenantIntermediateCA succeeded against a closed server")
	}
	if err := a.UpdateTenantIntermediateCAStatus(ctx, "t", "c", "revoked"); err == nil {
		t.Error("UpdateTenantIntermediateCAStatus succeeded against a closed server")
	}
}

// TestNewAdapter_LoadsClientCertificateAndCAPool covers the TLS branches of
// the constructor with real PEM files, which the existing tests only exercise
// via nonexistent paths. It also pins the TLS 1.3 floor: silently accepting an
// older protocol version would weaken every admin connection.
func TestNewAdapter_LoadsClientCertificateAndCAPool(t *testing.T) {
	certPEM, keyPEM := testCertKeyPEM(t)
	dir := t.TempDir()
	certFile := writeTempFile(t, dir, "cert.pem", certPEM)
	keyFile := writeTempFile(t, dir, "key.pem", keyPEM)
	caFile := writeTempFile(t, dir, "ca.pem", certPEM)

	a, err := NewAdapter(&api.AdapterConfig{
		BaseURL: "https://acme.example.com",
		TLSConfig: &api.TLSConfig{
			CertFile: certFile,
			KeyFile:  keyFile,
			CAFile:   caFile,
		},
	})
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	transport, ok := a.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", a.httpClient.Transport)
	}
	tlsCfg := transport.TLSClientConfig
	if tlsCfg == nil {
		t.Fatal("TLS config was not installed on the transport")
	}
	if tlsCfg.MinVersion != tlsMinVersionTLS13 {
		t.Errorf("MinVersion = %#x, want TLS 1.3 (%#x)", tlsCfg.MinVersion, tlsMinVersionTLS13)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("client certificates = %d, want 1", len(tlsCfg.Certificates))
	}
	if tlsCfg.RootCAs == nil {
		t.Error("CA pool was not populated from CAFile")
	}
	if tlsCfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify is set; admin connections must verify the server")
	}
}
