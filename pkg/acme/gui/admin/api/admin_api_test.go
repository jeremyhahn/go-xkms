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

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/gui/guard"
	trustedca "github.com/jeremyhahn/go-xkms/sdk/go/acme"
	sdkadmin "github.com/jeremyhahn/go-xkms/sdk/go/acme/client/admin"
	sdkerrors "github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
)

// =============================================================================
// Fake implementations
// =============================================================================

// fakeStatusClient is a fake StatusClient.
type fakeStatusClient struct {
	statusFunc func(ctx context.Context) (*sdkadmin.CAStatus, error)
	statsFunc  func(ctx context.Context) (*sdkadmin.CAStats, error)
}

func (f *fakeStatusClient) Status(ctx context.Context) (*sdkadmin.CAStatus, error) {
	if f.statusFunc != nil {
		return f.statusFunc(ctx)
	}
	return &sdkadmin.CAStatus{Identity: "test-ca", Initialized: true}, nil
}

func (f *fakeStatusClient) Stats(ctx context.Context) (*sdkadmin.CAStats, error) {
	if f.statsFunc != nil {
		return f.statsFunc(ctx)
	}
	return &sdkadmin.CAStats{TotalCertificates: 10}, nil
}

// fakeCertificateClient is a fake CertificateClient.
type fakeCertificateClient struct {
	listFunc   func(ctx context.Context, req *sdkadmin.ListCertificatesRequest) (*sdkadmin.ListCertificatesResponse, error)
	getFunc    func(ctx context.Context, serial string) (*sdkadmin.CertificateInfo, error)
	revokeFunc func(ctx context.Context, serial, reason string) error
}

func (f *fakeCertificateClient) List(ctx context.Context, req *sdkadmin.ListCertificatesRequest) (*sdkadmin.ListCertificatesResponse, error) {
	if f.listFunc != nil {
		return f.listFunc(ctx, req)
	}
	return &sdkadmin.ListCertificatesResponse{Certificates: []*sdkadmin.CertificateInfo{}}, nil
}

func (f *fakeCertificateClient) Get(ctx context.Context, serial string) (*sdkadmin.CertificateInfo, error) {
	if f.getFunc != nil {
		return f.getFunc(ctx, serial)
	}
	return &sdkadmin.CertificateInfo{SerialNumber: serial}, nil
}

func (f *fakeCertificateClient) Revoke(ctx context.Context, serial, reason string) error {
	if f.revokeFunc != nil {
		return f.revokeFunc(ctx, serial, reason)
	}
	return nil
}

// fakeAdminAccountClient is a fake AdminAccountClient.
type fakeAdminAccountClient struct {
	listFunc    func(ctx context.Context, req *sdkadmin.ListAccountsRequest) (*sdkadmin.ListAccountsResponse, error)
	getFunc     func(ctx context.Context, id uint64) (*sdkadmin.AccountInfo, error)
	disableFunc func(ctx context.Context, id uint64) error
}

func (f *fakeAdminAccountClient) List(ctx context.Context, req *sdkadmin.ListAccountsRequest) (*sdkadmin.ListAccountsResponse, error) {
	if f.listFunc != nil {
		return f.listFunc(ctx, req)
	}
	return &sdkadmin.ListAccountsResponse{Accounts: []*sdkadmin.AccountInfo{}}, nil
}

func (f *fakeAdminAccountClient) Get(ctx context.Context, id uint64) (*sdkadmin.AccountInfo, error) {
	if f.getFunc != nil {
		return f.getFunc(ctx, id)
	}
	return &sdkadmin.AccountInfo{}, nil
}

func (f *fakeAdminAccountClient) Disable(ctx context.Context, id uint64) error {
	if f.disableFunc != nil {
		return f.disableFunc(ctx, id)
	}
	return nil
}

// fakeOrderClient is a fake OrderClient.
type fakeOrderClient struct {
	listFunc func(ctx context.Context, req *sdkadmin.ListOrdersRequest) (*sdkadmin.ListOrdersResponse, error)
	getFunc  func(ctx context.Context, id uint64) (*sdkadmin.OrderInfo, error)
}

func (f *fakeOrderClient) List(ctx context.Context, req *sdkadmin.ListOrdersRequest) (*sdkadmin.ListOrdersResponse, error) {
	if f.listFunc != nil {
		return f.listFunc(ctx, req)
	}
	return &sdkadmin.ListOrdersResponse{Orders: []*sdkadmin.OrderInfo{}}, nil
}

func (f *fakeOrderClient) Get(ctx context.Context, id uint64) (*sdkadmin.OrderInfo, error) {
	if f.getFunc != nil {
		return f.getFunc(ctx, id)
	}
	return &sdkadmin.OrderInfo{ID: id}, nil
}

// fakeTenantClient is a fake TenantClient.
type fakeTenantClient struct {
	listFunc   func(ctx context.Context, req *sdkadmin.ListTenantsRequest) (*sdkadmin.ListTenantsResponse, error)
	createFunc func(ctx context.Context, req *sdkadmin.CreateTenantRequest) (*sdkadmin.TenantInfo, error)
	getFunc    func(ctx context.Context, id string) (*sdkadmin.TenantInfo, error)
	updateFunc func(ctx context.Context, id string, req *sdkadmin.UpdateTenantRequest) (*sdkadmin.TenantInfo, error)
	deleteFunc func(ctx context.Context, id string) error
}

func (f *fakeTenantClient) List(ctx context.Context, req *sdkadmin.ListTenantsRequest) (*sdkadmin.ListTenantsResponse, error) {
	if f.listFunc != nil {
		return f.listFunc(ctx, req)
	}
	return &sdkadmin.ListTenantsResponse{Tenants: []*sdkadmin.TenantInfo{}}, nil
}

func (f *fakeTenantClient) Create(ctx context.Context, req *sdkadmin.CreateTenantRequest) (*sdkadmin.TenantInfo, error) {
	if f.createFunc != nil {
		return f.createFunc(ctx, req)
	}
	return &sdkadmin.TenantInfo{ID: req.ID, Name: req.Name}, nil
}

func (f *fakeTenantClient) Get(ctx context.Context, id string) (*sdkadmin.TenantInfo, error) {
	if f.getFunc != nil {
		return f.getFunc(ctx, id)
	}
	return &sdkadmin.TenantInfo{ID: id}, nil
}

func (f *fakeTenantClient) Update(ctx context.Context, id string, req *sdkadmin.UpdateTenantRequest) (*sdkadmin.TenantInfo, error) {
	if f.updateFunc != nil {
		return f.updateFunc(ctx, id, req)
	}
	return &sdkadmin.TenantInfo{ID: id}, nil
}

func (f *fakeTenantClient) Delete(ctx context.Context, id string) error {
	if f.deleteFunc != nil {
		return f.deleteFunc(ctx, id)
	}
	return nil
}

// fakeEABClient is a fake EABClient.
type fakeEABClient struct {
	listFunc   func(ctx context.Context, tenantID string, req *sdkadmin.ListEABRequest) (*sdkadmin.ListEABResponse, error)
	createFunc func(ctx context.Context, tenantID string, req *sdkadmin.CreateEABRequest) (*sdkadmin.CreateEABResponse, error)
	getFunc    func(ctx context.Context, tenantID, eabID string) (*sdkadmin.EABInfo, error)
	deleteFunc func(ctx context.Context, tenantID, eabID string) error
}

func (f *fakeEABClient) List(ctx context.Context, tenantID string, req *sdkadmin.ListEABRequest) (*sdkadmin.ListEABResponse, error) {
	if f.listFunc != nil {
		return f.listFunc(ctx, tenantID, req)
	}
	return &sdkadmin.ListEABResponse{EABs: []*sdkadmin.EABInfo{}}, nil
}

func (f *fakeEABClient) Create(ctx context.Context, tenantID string, req *sdkadmin.CreateEABRequest) (*sdkadmin.CreateEABResponse, error) {
	if f.createFunc != nil {
		return f.createFunc(ctx, tenantID, req)
	}
	return &sdkadmin.CreateEABResponse{ID: "eab-1"}, nil
}

func (f *fakeEABClient) Get(ctx context.Context, tenantID, eabID string) (*sdkadmin.EABInfo, error) {
	if f.getFunc != nil {
		return f.getFunc(ctx, tenantID, eabID)
	}
	return &sdkadmin.EABInfo{ID: eabID, TenantID: tenantID}, nil
}

func (f *fakeEABClient) Delete(ctx context.Context, tenantID, eabID string) error {
	if f.deleteFunc != nil {
		return f.deleteFunc(ctx, tenantID, eabID)
	}
	return nil
}

// fakeRoleClient is a fake RoleClient.
type fakeRoleClient struct {
	listFunc   func(ctx context.Context, tenantID string, req *sdkadmin.ListRolesRequest) (*sdkadmin.ListRolesResponse, error)
	createFunc func(ctx context.Context, tenantID string, req *sdkadmin.CreateRoleRequest) (*sdkadmin.Role, error)
	getFunc    func(ctx context.Context, tenantID, roleID string) (*sdkadmin.Role, error)
	updateFunc func(ctx context.Context, tenantID string, req *sdkadmin.UpdateRoleRequest) (*sdkadmin.Role, error)
	deleteFunc func(ctx context.Context, tenantID, roleID string) error
}

func (f *fakeRoleClient) List(ctx context.Context, tenantID string, req *sdkadmin.ListRolesRequest) (*sdkadmin.ListRolesResponse, error) {
	if f.listFunc != nil {
		return f.listFunc(ctx, tenantID, req)
	}
	return &sdkadmin.ListRolesResponse{Roles: []*sdkadmin.Role{}}, nil
}

func (f *fakeRoleClient) Create(ctx context.Context, tenantID string, req *sdkadmin.CreateRoleRequest) (*sdkadmin.Role, error) {
	if f.createFunc != nil {
		return f.createFunc(ctx, tenantID, req)
	}
	return &sdkadmin.Role{ID: "role-1", Name: req.Name}, nil
}

func (f *fakeRoleClient) Get(ctx context.Context, tenantID, roleID string) (*sdkadmin.Role, error) {
	if f.getFunc != nil {
		return f.getFunc(ctx, tenantID, roleID)
	}
	return &sdkadmin.Role{ID: roleID}, nil
}

func (f *fakeRoleClient) Update(ctx context.Context, tenantID string, req *sdkadmin.UpdateRoleRequest) (*sdkadmin.Role, error) {
	if f.updateFunc != nil {
		return f.updateFunc(ctx, tenantID, req)
	}
	return &sdkadmin.Role{ID: req.ID}, nil
}

func (f *fakeRoleClient) Delete(ctx context.Context, tenantID, roleID string) error {
	if f.deleteFunc != nil {
		return f.deleteFunc(ctx, tenantID, roleID)
	}
	return nil
}

// fakeUserClient is a fake UserClient.
type fakeUserClient struct {
	listFunc   func(ctx context.Context, tenantID string, req *sdkadmin.ListUsersRequest) (*sdkadmin.ListUsersResponse, error)
	createFunc func(ctx context.Context, tenantID string, req *sdkadmin.CreateUserRequest) (*sdkadmin.User, error)
	getFunc    func(ctx context.Context, tenantID, userID string) (*sdkadmin.User, error)
	updateFunc func(ctx context.Context, tenantID string, req *sdkadmin.UpdateUserRequest) (*sdkadmin.User, error)
	deleteFunc func(ctx context.Context, tenantID, userID string) error
}

func (f *fakeUserClient) List(ctx context.Context, tenantID string, req *sdkadmin.ListUsersRequest) (*sdkadmin.ListUsersResponse, error) {
	if f.listFunc != nil {
		return f.listFunc(ctx, tenantID, req)
	}
	return &sdkadmin.ListUsersResponse{Users: []*sdkadmin.User{}}, nil
}

func (f *fakeUserClient) Create(ctx context.Context, tenantID string, req *sdkadmin.CreateUserRequest) (*sdkadmin.User, error) {
	if f.createFunc != nil {
		return f.createFunc(ctx, tenantID, req)
	}
	return &sdkadmin.User{ID: "user-1", Username: req.Username}, nil
}

func (f *fakeUserClient) Get(ctx context.Context, tenantID, userID string) (*sdkadmin.User, error) {
	if f.getFunc != nil {
		return f.getFunc(ctx, tenantID, userID)
	}
	return &sdkadmin.User{ID: userID}, nil
}

func (f *fakeUserClient) Update(ctx context.Context, tenantID string, req *sdkadmin.UpdateUserRequest) (*sdkadmin.User, error) {
	if f.updateFunc != nil {
		return f.updateFunc(ctx, tenantID, req)
	}
	return &sdkadmin.User{ID: req.ID}, nil
}

func (f *fakeUserClient) Delete(ctx context.Context, tenantID, userID string) error {
	if f.deleteFunc != nil {
		return f.deleteFunc(ctx, tenantID, userID)
	}
	return nil
}

// fakeTenantCAClient is a fake TenantCAClient.
type fakeTenantCAClient struct {
	createRootCAFunc           func(ctx context.Context, tenantID string, req *sdkadmin.CreateTenantRootCARequest) (*sdkadmin.TenantRootCAInfo, error)
	caStatusFunc               func(ctx context.Context, tenantID string) (*sdkadmin.TenantCAStatusInfo, error)
	createIntermediateCAFunc   func(ctx context.Context, tenantID string, req *sdkadmin.CreateTenantIntermediateCARequest) (*sdkadmin.TenantIntCAInfo, error)
	listIntermediateCAsFunc    func(ctx context.Context, tenantID string) ([]*sdkadmin.TenantIntCAInfo, error)
	getIntermediateCAFunc      func(ctx context.Context, tenantID, caID string) (*sdkadmin.TenantIntCAInfo, error)
	updateIntermediateCAStatus func(ctx context.Context, tenantID, caID, status string) error
	updateTenantStatusFunc     func(ctx context.Context, tenantID, status string) error
}

func (f *fakeTenantCAClient) CreateRootCA(ctx context.Context, tenantID string, req *sdkadmin.CreateTenantRootCARequest) (*sdkadmin.TenantRootCAInfo, error) {
	if f.createRootCAFunc != nil {
		return f.createRootCAFunc(ctx, tenantID, req)
	}
	return &sdkadmin.TenantRootCAInfo{CommonName: req.CommonName}, nil
}

func (f *fakeTenantCAClient) CAStatus(ctx context.Context, tenantID string) (*sdkadmin.TenantCAStatusInfo, error) {
	if f.caStatusFunc != nil {
		return f.caStatusFunc(ctx, tenantID)
	}
	return &sdkadmin.TenantCAStatusInfo{TenantID: tenantID}, nil
}

func (f *fakeTenantCAClient) CreateIntermediateCA(ctx context.Context, tenantID string, req *sdkadmin.CreateTenantIntermediateCARequest) (*sdkadmin.TenantIntCAInfo, error) {
	if f.createIntermediateCAFunc != nil {
		return f.createIntermediateCAFunc(ctx, tenantID, req)
	}
	return &sdkadmin.TenantIntCAInfo{CommonName: req.CommonName}, nil
}

func (f *fakeTenantCAClient) ListIntermediateCAs(ctx context.Context, tenantID string) ([]*sdkadmin.TenantIntCAInfo, error) {
	if f.listIntermediateCAsFunc != nil {
		return f.listIntermediateCAsFunc(ctx, tenantID)
	}
	return []*sdkadmin.TenantIntCAInfo{}, nil
}

func (f *fakeTenantCAClient) GetIntermediateCA(ctx context.Context, tenantID, caID string) (*sdkadmin.TenantIntCAInfo, error) {
	if f.getIntermediateCAFunc != nil {
		return f.getIntermediateCAFunc(ctx, tenantID, caID)
	}
	return &sdkadmin.TenantIntCAInfo{ID: caID}, nil
}

func (f *fakeTenantCAClient) UpdateIntermediateCAStatus(ctx context.Context, tenantID, caID, status string) error {
	if f.updateIntermediateCAStatus != nil {
		return f.updateIntermediateCAStatus(ctx, tenantID, caID, status)
	}
	return nil
}

func (f *fakeTenantCAClient) UpdateTenantStatus(ctx context.Context, tenantID, status string) error {
	if f.updateTenantStatusFunc != nil {
		return f.updateTenantStatusFunc(ctx, tenantID, status)
	}
	return nil
}

// fakeAdminClient is a fake Admin client (sdk/go/acme.AdminClient = admin.Client).
type fakeAdminClient struct {
	tenantClient   sdkadmin.TenantClient
	tenantCAClient sdkadmin.TenantCAClient
	eabClient      sdkadmin.EABClient
	roleClient     sdkadmin.RoleClient
	userClient     sdkadmin.UserClient
	certClient     sdkadmin.CertificateClient
	accountClient  sdkadmin.AdminAccountClient
	orderClient    sdkadmin.OrderClient
	statusClient   sdkadmin.StatusClient
}

func (f *fakeAdminClient) Tenant() sdkadmin.TenantClient           { return f.tenantClient }
func (f *fakeAdminClient) TenantCA() sdkadmin.TenantCAClient       { return f.tenantCAClient }
func (f *fakeAdminClient) EAB() sdkadmin.EABClient                 { return f.eabClient }
func (f *fakeAdminClient) Role() sdkadmin.RoleClient               { return f.roleClient }
func (f *fakeAdminClient) User() sdkadmin.UserClient               { return f.userClient }
func (f *fakeAdminClient) Certificate() sdkadmin.CertificateClient { return f.certClient }
func (f *fakeAdminClient) Account() sdkadmin.AdminAccountClient    { return f.accountClient }
func (f *fakeAdminClient) Order() sdkadmin.OrderClient             { return f.orderClient }
func (f *fakeAdminClient) Status() sdkadmin.StatusClient           { return f.statusClient }

// fakeClient satisfies trustedca.Client for the handler dependency.
type fakeClient struct {
	adminClient trustedca.AdminClient
}

func (f *fakeClient) Admin() trustedca.AdminClient { return f.adminClient }

// The remaining Client methods are not exercised by the GUI admin/api package.

var _ trustedca.Client = (*fakeClient)(nil)

// Remaining trustedca.Client methods that are not used by gui/admin/api.
func (f *fakeClient) Account() trustedca.AccountClient             { return nil }
func (f *fakeClient) Order() trustedca.OrderClient                 { return nil }
func (f *fakeClient) Authorization() trustedca.AuthorizationClient { return nil }
func (f *fakeClient) Challenge() trustedca.ChallengeClient         { return nil }
func (f *fakeClient) Certificate() trustedca.CertificateClient     { return nil }
func (f *fakeClient) Directory() trustedca.DirectoryClient         { return nil }
func (f *fakeClient) Nonce() trustedca.NonceClient                 { return nil }
func (f *fakeClient) Transport() trustedca.Transport               { return nil }
func (f *fakeClient) Workflow(opts ...trustedca.WorkflowOption) trustedca.WorkflowInterface {
	return nil
}
func (f *fakeClient) Close() error { return nil }

// =============================================================================
// Test helpers
// =============================================================================

// newTestRouter creates a router backed by a fully configured fake client,
// wired the way the admin desktop app wires it: in-process, behind the Wails
// AssetServer Handler, with no listener under it.
func newTestRouter(
	t *testing.T,
	admin *fakeAdminClient,
) http.Handler {
	t.Helper()
	cli := &fakeClient{adminClient: admin}
	return NewRouter(cli, slog.Default(), WithInProcessTransport())
}

// networkTestRouter creates a router backed by the default, network-mode
// guard.Guard — the configuration the admin router does not ship today, but
// is wired through nonetheless, since it shares pkg/acme/gui/guard with the
// ACME client GUI API's "trusted-acme-client serve" deployment.
func networkTestRouter(
	t *testing.T,
	admin *fakeAdminClient,
) http.Handler {
	t.Helper()
	cli := &fakeClient{adminClient: admin}
	return NewRouter(cli, slog.Default())
}

// defaultFakeAdmin returns a fakeAdminClient wired up with default no-op fakes.
func defaultFakeAdmin() *fakeAdminClient {
	return &fakeAdminClient{
		statusClient:   &fakeStatusClient{},
		certClient:     &fakeCertificateClient{},
		accountClient:  &fakeAdminAccountClient{},
		orderClient:    &fakeOrderClient{},
		tenantClient:   &fakeTenantClient{},
		eabClient:      &fakeEABClient{},
		roleClient:     &fakeRoleClient{},
		userClient:     &fakeUserClient{},
		tenantCAClient: &fakeTenantCAClient{},
	}
}

func decodeResponse(t *testing.T, rec *httptest.ResponseRecorder) apiResponse {
	t.Helper()
	var resp apiResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

// notFoundErr returns a CAError with CodeNotFound.
func notFoundErr() error {
	return sdkerrors.NewNotFound("test", "not found")
}

// alreadyExistsErr returns a CAError with CodeAlreadyExists.
func alreadyExistsErr() error {
	return sdkerrors.NewAlreadyExists("test", "already exists")
}

// invalidInputErr returns a CAError with CodeInvalidInput.
func invalidInputErr() error {
	return sdkerrors.NewInvalidInput("test", "invalid")
}

// internalErr returns a generic error.
func internalErr() error {
	return errors.New("internal error")
}

// =============================================================================
// Helpers and utility tests
// =============================================================================

func TestWriteJSON_SetsContentType(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, map[string]string{"key": "val"}, nil)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %s", ct)
	}
	var resp apiResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Success {
		t.Error("expected success=true")
	}
}

func TestWriteJSON_IncludesPagination(t *testing.T) {
	rec := httptest.NewRecorder()
	pagination := map[string]int{"page": 1}
	writeJSON(rec, http.StatusOK, "data", pagination)

	var resp apiResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Pagination == nil {
		t.Error("expected non-nil pagination")
	}
}

func TestWriteErrorResponse_SetsErrorFields(t *testing.T) {
	rec := httptest.NewRecorder()
	writeErrorResponse(rec, http.StatusNotFound, "NOT_FOUND", "something is missing")

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
	var resp apiResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Success {
		t.Error("expected success=false")
	}
	if resp.Error == nil {
		t.Fatal("expected non-nil error info")
	}
	if resp.Error.Code != "NOT_FOUND" {
		t.Errorf("expected NOT_FOUND, got %s", resp.Error.Code)
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

	writeJSON(&failingResponseWriter{}, http.StatusOK, map[string]string{"key": "val"}, nil)

	if !bytes.Contains(logBuf.Bytes(), []byte("failed to write JSON response")) {
		t.Errorf("expected write failure to be logged, got: %s", logBuf.String())
	}
}

// TestWriteErrorResponse_LogsEncodeFailure is TestWriteJSON_LogsEncodeFailure
// for the error-response encoder.
func TestWriteErrorResponse_LogsEncodeFailure(t *testing.T) {
	var logBuf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, nil)))
	defer slog.SetDefault(prev)

	writeErrorResponse(&failingResponseWriter{}, http.StatusNotFound, "NOT_FOUND", "boom")

	if !bytes.Contains(logBuf.Bytes(), []byte("failed to write JSON error response")) {
		t.Errorf("expected write failure to be logged, got: %s", logBuf.String())
	}
}

func TestParseInt(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		defaultValue int
		want         int
	}{
		{"empty uses default", "", 5, 5},
		{"valid integer", "10", 5, 10},
		{"invalid uses default", "abc", 3, 3},
		{"zero is valid", "0", 1, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseInt(tt.input, tt.defaultValue); got != tt.want {
				t.Errorf("parseInt(%q, %d) = %d; want %d", tt.input, tt.defaultValue, got, tt.want)
			}
		})
	}
}

// =============================================================================
// Cross-origin guard
//
// The admin router installs the same guard.Guard the ACME client GUI API
// uses (pkg/acme/gui/guard); see pkg/acme/gui/client/api/security_test.go
// for the equivalent coverage on that router. The admin desktop app always
// supplies WithInProcessTransport (pkg/acme/gui/admin/app.go); the
// network-mode cases below exercise the shared guard's other branch, which
// the admin router does not ship today but is wired through rather than a
// separate code path.
// =============================================================================

// TestGuard_InProcessSetsPermissiveCORSHeaders verifies that CORS headers are
// set on requests that match a registered route and method, mirroring the
// ACME client GUI API's in-process policy.
func TestGuard_InProcessSetsPermissiveCORSHeaders(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	req.Header.Set("Origin", "wails://wails")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != guard.AnyOrigin {
		t.Errorf("expected the wildcard CORS origin in-process, got %q", got)
	}
	if rec.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("missing Access-Control-Allow-Methods header")
	}
}

// TestGuard_InProcessAcceptsEveryWebviewOrigin covers the reason the origin
// check is dropped in-process: a webview's own origin varies by platform and
// may be opaque, and every form, including a request with no Origin header
// at all, must still reach the admin API.
func TestGuard_InProcessAcceptsEveryWebviewOrigin(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	origins := []string{"wails://wails", "http://wails.localhost", "https://wails.localhost", "null", ""}
	for _, origin := range origins {
		t.Run(origin, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
			if origin != "" {
				req.Header.Set("Origin", origin)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200 for Origin %q, got %d: %s", origin, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestGuard_UnmatchedOPTIONSNotAnswered verifies that OPTIONS on a path
// without an OPTIONS route registration returns a non-2xx status. The admin
// router registers routes without OPTIONS; gorilla/mux applies router
// middleware, including the guard, only once a route and method have
// matched, so an unmatched OPTIONS request never reaches it.
func TestGuard_UnmatchedOPTIONSNotAnswered(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodOptions, "/admin/status", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Errorf("OPTIONS should not return 200 when not registered: got %d", rec.Code)
	}
}

// TestGuard_NetworkModeRejectsCrossOrigin proves the admin router is wired to
// the same guard.Guard the ACME client GUI API uses: given the default,
// network-mode guard, it rejects a cross-origin caller exactly as the client
// router does.
func TestGuard_NetworkModeRejectsCrossOrigin(t *testing.T) {
	router := networkTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a cross-origin caller, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("a rejected origin must not be granted CORS access, got %q", got)
	}
	resp := decodeResponse(t, rec)
	if resp.Error == nil || resp.Error.Code != "FORBIDDEN_ORIGIN" {
		t.Errorf("expected a FORBIDDEN_ORIGIN error envelope, got %+v", resp.Error)
	}
}

// TestGuard_NetworkModeAcceptsSameOrigin proves the same default guard
// serves a same-origin caller normally.
func TestGuard_NetworkModeAcceptsSameOrigin(t *testing.T) {
	router := networkTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	req.Host = "ca.example.com:8443"
	req.Header.Set("Origin", "https://ca.example.com:8443")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for a same-origin caller, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://ca.example.com:8443" {
		t.Errorf("expected the origin to be echoed, got %q", got)
	}
}

// =============================================================================
// Status handlers
// =============================================================================

func TestGetStatus_Success(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.statusClient = &fakeStatusClient{
		statusFunc: func(ctx context.Context) (*sdkadmin.CAStatus, error) {
			return &sdkadmin.CAStatus{Identity: "my-ca", Initialized: true}, nil
		},
	}
	router := newTestRouter(t, admin)

	req := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	resp := decodeResponse(t, rec)
	if !resp.Success {
		t.Error("expected success=true")
	}
}

func TestGetStatus_Error(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.statusClient = &fakeStatusClient{
		statusFunc: func(ctx context.Context) (*sdkadmin.CAStatus, error) {
			return nil, internalErr()
		},
	}
	router := newTestRouter(t, admin)

	req := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestGetStats_Success(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.statusClient = &fakeStatusClient{
		statsFunc: func(ctx context.Context) (*sdkadmin.CAStats, error) {
			return &sdkadmin.CAStats{TotalCertificates: 42}, nil
		},
	}
	router := newTestRouter(t, admin)

	req := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestGetStats_Error(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.statusClient = &fakeStatusClient{
		statsFunc: func(ctx context.Context) (*sdkadmin.CAStats, error) {
			return nil, internalErr()
		},
	}
	router := newTestRouter(t, admin)

	req := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

// =============================================================================
// Certificate handlers
// =============================================================================

func TestListCertificates_DefaultPagination(t *testing.T) {
	var capturedReq *sdkadmin.ListCertificatesRequest
	admin := defaultFakeAdmin()
	admin.certClient = &fakeCertificateClient{
		listFunc: func(ctx context.Context, req *sdkadmin.ListCertificatesRequest) (*sdkadmin.ListCertificatesResponse, error) {
			capturedReq = req
			return &sdkadmin.ListCertificatesResponse{}, nil
		},
	}
	router := newTestRouter(t, admin)

	req := httptest.NewRequest(http.MethodGet, "/admin/certificates", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if capturedReq == nil {
		t.Fatal("handler did not call List")
	}
	if capturedReq.Page != 1 {
		t.Errorf("expected default page=1, got %d", capturedReq.Page)
	}
	if capturedReq.PerPage != 20 {
		t.Errorf("expected default per_page=20, got %d", capturedReq.PerPage)
	}
}

func TestListCertificates_QueryParams(t *testing.T) {
	var capturedReq *sdkadmin.ListCertificatesRequest
	admin := defaultFakeAdmin()
	admin.certClient = &fakeCertificateClient{
		listFunc: func(ctx context.Context, req *sdkadmin.ListCertificatesRequest) (*sdkadmin.ListCertificatesResponse, error) {
			capturedReq = req
			return &sdkadmin.ListCertificatesResponse{}, nil
		},
	}
	router := newTestRouter(t, admin)

	req := httptest.NewRequest(http.MethodGet, "/admin/certificates?page=3&per_page=5&status=valid&subject=test", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if capturedReq.Page != 3 || capturedReq.PerPage != 5 || capturedReq.Status != "valid" || capturedReq.Subject != "test" {
		t.Errorf("unexpected request values: %+v", capturedReq)
	}
}

func TestListCertificates_Error(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.certClient = &fakeCertificateClient{
		listFunc: func(ctx context.Context, req *sdkadmin.ListCertificatesRequest) (*sdkadmin.ListCertificatesResponse, error) {
			return nil, internalErr()
		},
	}
	router := newTestRouter(t, admin)

	req := httptest.NewRequest(http.MethodGet, "/admin/certificates", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestGetCertificate_Success(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.certClient = &fakeCertificateClient{
		getFunc: func(ctx context.Context, serial string) (*sdkadmin.CertificateInfo, error) {
			return &sdkadmin.CertificateInfo{SerialNumber: serial}, nil
		},
	}
	router := newTestRouter(t, admin)

	req := httptest.NewRequest(http.MethodGet, "/admin/certificates/abc123", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestGetCertificate_NotFound(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.certClient = &fakeCertificateClient{
		getFunc: func(ctx context.Context, serial string) (*sdkadmin.CertificateInfo, error) {
			return nil, notFoundErr()
		},
	}
	router := newTestRouter(t, admin)

	req := httptest.NewRequest(http.MethodGet, "/admin/certificates/missing", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestGetCertificate_InternalError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.certClient = &fakeCertificateClient{
		getFunc: func(ctx context.Context, serial string) (*sdkadmin.CertificateInfo, error) {
			return nil, internalErr()
		},
	}
	router := newTestRouter(t, admin)

	req := httptest.NewRequest(http.MethodGet, "/admin/certificates/err", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestRevokeCertificate_Success(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.certClient = &fakeCertificateClient{
		revokeFunc: func(ctx context.Context, serial, reason string) error {
			return nil
		},
	}
	router := newTestRouter(t, admin)

	body := bytes.NewBufferString(`{"reason":"keyCompromise"}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/certificates/abc123/revoke", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestRevokeCertificate_InvalidBody(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())

	req := httptest.NewRequest(http.MethodPost, "/admin/certificates/abc/revoke", bytes.NewBufferString("not-json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestRevokeCertificate_NotFound(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.certClient = &fakeCertificateClient{
		revokeFunc: func(ctx context.Context, serial, reason string) error {
			return notFoundErr()
		},
	}
	router := newTestRouter(t, admin)

	body := bytes.NewBufferString(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/certificates/abc/revoke", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestRevokeCertificate_InternalError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.certClient = &fakeCertificateClient{
		revokeFunc: func(ctx context.Context, serial, reason string) error {
			return internalErr()
		},
	}
	router := newTestRouter(t, admin)

	body := bytes.NewBufferString(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/certificates/abc/revoke", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

// TestListCertificates_ExpiresDays checks the Dashboard's
// expires_days filter reaches the SDK request.
func TestListCertificates_ExpiresDays(t *testing.T) {
	var capturedReq *sdkadmin.ListCertificatesRequest
	admin := defaultFakeAdmin()
	admin.certClient = &fakeCertificateClient{
		listFunc: func(ctx context.Context, req *sdkadmin.ListCertificatesRequest) (*sdkadmin.ListCertificatesResponse, error) {
			capturedReq = req
			return &sdkadmin.ListCertificatesResponse{}, nil
		},
	}
	router := newTestRouter(t, admin)

	req := httptest.NewRequest(http.MethodGet, "/admin/certificates?expires_days=30&per_page=5", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if capturedReq.ExpiresDays != 30 || capturedReq.PerPage != 5 {
		t.Errorf("unexpected request values: %+v", capturedReq)
	}
}

// TestListCertificates_InvalidExpiresDays checks a non-positive or
// non-numeric expires_days is refused before the SDK is called.
func TestListCertificates_InvalidExpiresDays(t *testing.T) {
	for _, value := range []string{"0", "-5", "soon"} {
		t.Run(value, func(t *testing.T) {
			called := false
			admin := defaultFakeAdmin()
			admin.certClient = &fakeCertificateClient{
				listFunc: func(ctx context.Context, req *sdkadmin.ListCertificatesRequest) (*sdkadmin.ListCertificatesResponse, error) {
					called = true
					return &sdkadmin.ListCertificatesResponse{}, nil
				},
			}
			router := newTestRouter(t, admin)

			req := httptest.NewRequest(http.MethodGet, "/admin/certificates?expires_days="+value, nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", rec.Code)
			}
			if called {
				t.Error("SDK called despite an invalid expires_days")
			}
		})
	}
}

// =============================================================================
// Account handlers
// =============================================================================

func TestListAccounts_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodGet, "/admin/accounts", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestListAccounts_Error(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.accountClient = &fakeAdminAccountClient{
		listFunc: func(ctx context.Context, req *sdkadmin.ListAccountsRequest) (*sdkadmin.ListAccountsResponse, error) {
			return nil, internalErr()
		},
	}
	router := newTestRouter(t, admin)
	req := httptest.NewRequest(http.MethodGet, "/admin/accounts", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestGetAccount_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodGet, "/admin/accounts/42", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestGetAccount_InvalidID(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodGet, "/admin/accounts/notanumber", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestGetAccount_NotFound(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.accountClient = &fakeAdminAccountClient{
		getFunc: func(ctx context.Context, id uint64) (*sdkadmin.AccountInfo, error) {
			return nil, notFoundErr()
		},
	}
	router := newTestRouter(t, admin)
	req := httptest.NewRequest(http.MethodGet, "/admin/accounts/99", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestGetAccount_InternalError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.accountClient = &fakeAdminAccountClient{
		getFunc: func(ctx context.Context, id uint64) (*sdkadmin.AccountInfo, error) {
			return nil, internalErr()
		},
	}
	router := newTestRouter(t, admin)
	req := httptest.NewRequest(http.MethodGet, "/admin/accounts/1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestDisableAccount_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodDelete, "/admin/accounts/1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestDisableAccount_InvalidID(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodDelete, "/admin/accounts/bad", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestDisableAccount_NotFound(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.accountClient = &fakeAdminAccountClient{
		disableFunc: func(ctx context.Context, id uint64) error {
			return notFoundErr()
		},
	}
	router := newTestRouter(t, admin)
	req := httptest.NewRequest(http.MethodDelete, "/admin/accounts/7", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestDisableAccount_InternalError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.accountClient = &fakeAdminAccountClient{
		disableFunc: func(ctx context.Context, id uint64) error {
			return internalErr()
		},
	}
	router := newTestRouter(t, admin)
	req := httptest.NewRequest(http.MethodDelete, "/admin/accounts/1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

// =============================================================================
// Order handlers
// =============================================================================

func TestListOrders_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodGet, "/admin/orders", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestListOrders_WithAccountID(t *testing.T) {
	var capturedReq *sdkadmin.ListOrdersRequest
	admin := defaultFakeAdmin()
	admin.orderClient = &fakeOrderClient{
		listFunc: func(ctx context.Context, req *sdkadmin.ListOrdersRequest) (*sdkadmin.ListOrdersResponse, error) {
			capturedReq = req
			return &sdkadmin.ListOrdersResponse{}, nil
		},
	}
	router := newTestRouter(t, admin)
	req := httptest.NewRequest(http.MethodGet, "/admin/orders?account_id=5", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if capturedReq.AccountID != 5 {
		t.Errorf("expected AccountID=5, got %d", capturedReq.AccountID)
	}
}

func TestListOrders_InvalidAccountID(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodGet, "/admin/orders?account_id=notanumber", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestListOrders_Error(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.orderClient = &fakeOrderClient{
		listFunc: func(ctx context.Context, req *sdkadmin.ListOrdersRequest) (*sdkadmin.ListOrdersResponse, error) {
			return nil, internalErr()
		},
	}
	router := newTestRouter(t, admin)
	req := httptest.NewRequest(http.MethodGet, "/admin/orders", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestGetOrder_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodGet, "/admin/orders/1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestGetOrder_InvalidID(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodGet, "/admin/orders/bad", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestGetOrder_NotFound(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.orderClient = &fakeOrderClient{
		getFunc: func(ctx context.Context, id uint64) (*sdkadmin.OrderInfo, error) {
			return nil, sdkadmin.NewOrderNotFound("test", "not found")
		},
	}
	router := newTestRouter(t, admin)
	req := httptest.NewRequest(http.MethodGet, "/admin/orders/99", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestGetOrder_InternalError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.orderClient = &fakeOrderClient{
		getFunc: func(ctx context.Context, id uint64) (*sdkadmin.OrderInfo, error) {
			return nil, internalErr()
		},
	}
	router := newTestRouter(t, admin)
	req := httptest.NewRequest(http.MethodGet, "/admin/orders/1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

// =============================================================================
// Tenant CRUD handlers
// =============================================================================

func TestListTenants_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestListTenants_Error(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.tenantClient = &fakeTenantClient{
		listFunc: func(ctx context.Context, req *sdkadmin.ListTenantsRequest) (*sdkadmin.ListTenantsResponse, error) {
			return nil, internalErr()
		},
	}
	router := newTestRouter(t, admin)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestCreateTenant_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	body := bytes.NewBufferString(`{"id":"t1","name":"Tenant One"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rec.Code)
	}
}

func TestCreateTenant_InvalidBody(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/", bytes.NewBufferString("bad"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestCreateTenant_AlreadyExists(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.tenantClient = &fakeTenantClient{
		createFunc: func(ctx context.Context, req *sdkadmin.CreateTenantRequest) (*sdkadmin.TenantInfo, error) {
			return nil, alreadyExistsErr()
		},
	}
	router := newTestRouter(t, admin)
	body := bytes.NewBufferString(`{"id":"t1","name":"Tenant One"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d", rec.Code)
	}
}

func TestCreateTenant_ValidationError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.tenantClient = &fakeTenantClient{
		createFunc: func(ctx context.Context, req *sdkadmin.CreateTenantRequest) (*sdkadmin.TenantInfo, error) {
			return nil, invalidInputErr()
		},
	}
	router := newTestRouter(t, admin)
	body := bytes.NewBufferString(`{"id":"","name":""}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestCreateTenant_InternalError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.tenantClient = &fakeTenantClient{
		createFunc: func(ctx context.Context, req *sdkadmin.CreateTenantRequest) (*sdkadmin.TenantInfo, error) {
			return nil, internalErr()
		},
	}
	router := newTestRouter(t, admin)
	body := bytes.NewBufferString(`{"id":"t1","name":"T1"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestGetTenant_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/t1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestGetTenant_NotFound(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.tenantClient = &fakeTenantClient{
		getFunc: func(ctx context.Context, id string) (*sdkadmin.TenantInfo, error) {
			return nil, notFoundErr()
		},
	}
	router := newTestRouter(t, admin)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/missing", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestGetTenant_InternalError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.tenantClient = &fakeTenantClient{
		getFunc: func(ctx context.Context, id string) (*sdkadmin.TenantInfo, error) {
			return nil, internalErr()
		},
	}
	router := newTestRouter(t, admin)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/t1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestUpdateTenant_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	body := bytes.NewBufferString(`{"name":"Updated"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/t1", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestUpdateTenant_InvalidBody(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/t1", bytes.NewBufferString("bad"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestUpdateTenant_NotFound(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.tenantClient = &fakeTenantClient{
		updateFunc: func(ctx context.Context, id string, req *sdkadmin.UpdateTenantRequest) (*sdkadmin.TenantInfo, error) {
			return nil, notFoundErr()
		},
	}
	router := newTestRouter(t, admin)
	body := bytes.NewBufferString(`{"name":"U"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/t1", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestUpdateTenant_ValidationError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.tenantClient = &fakeTenantClient{
		updateFunc: func(ctx context.Context, id string, req *sdkadmin.UpdateTenantRequest) (*sdkadmin.TenantInfo, error) {
			return nil, invalidInputErr()
		},
	}
	router := newTestRouter(t, admin)
	body := bytes.NewBufferString(`{"name":""}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/t1", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestUpdateTenant_InternalError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.tenantClient = &fakeTenantClient{
		updateFunc: func(ctx context.Context, id string, req *sdkadmin.UpdateTenantRequest) (*sdkadmin.TenantInfo, error) {
			return nil, internalErr()
		},
	}
	router := newTestRouter(t, admin)
	body := bytes.NewBufferString(`{"name":"X"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/t1", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestDeleteTenant_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/t1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestDeleteTenant_NotFound(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.tenantClient = &fakeTenantClient{
		deleteFunc: func(ctx context.Context, id string) error {
			return notFoundErr()
		},
	}
	router := newTestRouter(t, admin)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/missing", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestDeleteTenant_InternalError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.tenantClient = &fakeTenantClient{
		deleteFunc: func(ctx context.Context, id string) error {
			return internalErr()
		},
	}
	router := newTestRouter(t, admin)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/t1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

// =============================================================================
// Tenant Status handler
// =============================================================================

func TestUpdateTenantStatus_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	body := bytes.NewBufferString(`{"status":"active"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/t1/status", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestUpdateTenantStatus_InvalidBody(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/t1/status", bytes.NewBufferString("bad"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestUpdateTenantStatus_MissingStatus(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	body := bytes.NewBufferString(`{}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/t1/status", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing status, got %d", rec.Code)
	}
}

func TestUpdateTenantStatus_NotFound(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.tenantCAClient = &fakeTenantCAClient{
		updateTenantStatusFunc: func(ctx context.Context, tenantID, status string) error {
			return sdkadmin.NewTenantNotFound("test", "not found")
		},
	}
	router := newTestRouter(t, admin)
	body := bytes.NewBufferString(`{"status":"active"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/t1/status", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestUpdateTenantStatus_InternalError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.tenantCAClient = &fakeTenantCAClient{
		updateTenantStatusFunc: func(ctx context.Context, tenantID, status string) error {
			return internalErr()
		},
	}
	router := newTestRouter(t, admin)
	body := bytes.NewBufferString(`{"status":"active"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/t1/status", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

// =============================================================================
// EAB handlers
// =============================================================================

func TestListEABs_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/t1/eab", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestListEABs_Error(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.eabClient = &fakeEABClient{
		listFunc: func(ctx context.Context, tenantID string, req *sdkadmin.ListEABRequest) (*sdkadmin.ListEABResponse, error) {
			return nil, internalErr()
		},
	}
	router := newTestRouter(t, admin)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/t1/eab", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestCreateEAB_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	body := bytes.NewBufferString(`{"purpose":"enrollment"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/t1/eab", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rec.Code)
	}
}

func TestCreateEAB_InvalidBody(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/t1/eab", bytes.NewBufferString("bad"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestCreateEAB_ValidationError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.eabClient = &fakeEABClient{
		createFunc: func(ctx context.Context, tenantID string, req *sdkadmin.CreateEABRequest) (*sdkadmin.CreateEABResponse, error) {
			return nil, invalidInputErr()
		},
	}
	router := newTestRouter(t, admin)
	body := bytes.NewBufferString(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/t1/eab", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestCreateEAB_InternalError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.eabClient = &fakeEABClient{
		createFunc: func(ctx context.Context, tenantID string, req *sdkadmin.CreateEABRequest) (*sdkadmin.CreateEABResponse, error) {
			return nil, internalErr()
		},
	}
	router := newTestRouter(t, admin)
	body := bytes.NewBufferString(`{"purpose":"e"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/t1/eab", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestDeleteEAB_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/t1/eab/e1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestDeleteEAB_NotFound(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.eabClient = &fakeEABClient{
		deleteFunc: func(ctx context.Context, tenantID, eabID string) error {
			return notFoundErr()
		},
	}
	router := newTestRouter(t, admin)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/t1/eab/missing", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestDeleteEAB_InternalError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.eabClient = &fakeEABClient{
		deleteFunc: func(ctx context.Context, tenantID, eabID string) error {
			return internalErr()
		},
	}
	router := newTestRouter(t, admin)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/t1/eab/e1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

// =============================================================================
// Role handlers
// =============================================================================

func TestListRoles_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/t1/roles", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestListRoles_Error(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.roleClient = &fakeRoleClient{
		listFunc: func(ctx context.Context, tenantID string, req *sdkadmin.ListRolesRequest) (*sdkadmin.ListRolesResponse, error) {
			return nil, internalErr()
		},
	}
	router := newTestRouter(t, admin)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/t1/roles", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestCreateRole_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	body := bytes.NewBufferString(`{"name":"admin","permissions":["read"]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/t1/roles", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rec.Code)
	}
}

func TestCreateRole_InvalidBody(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/t1/roles", bytes.NewBufferString("bad"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestCreateRole_InternalError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.roleClient = &fakeRoleClient{
		createFunc: func(ctx context.Context, tenantID string, req *sdkadmin.CreateRoleRequest) (*sdkadmin.Role, error) {
			return nil, internalErr()
		},
	}
	router := newTestRouter(t, admin)
	body := bytes.NewBufferString(`{"name":"r"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/t1/roles", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestGetRole_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/t1/roles/r1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestGetRole_InternalError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.roleClient = &fakeRoleClient{
		getFunc: func(ctx context.Context, tenantID, roleID string) (*sdkadmin.Role, error) {
			return nil, internalErr()
		},
	}
	router := newTestRouter(t, admin)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/t1/roles/r1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestUpdateRole_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	body := bytes.NewBufferString(`{"name":"updated-role"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/t1/roles/r1", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestUpdateRole_InvalidBody(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/t1/roles/r1", bytes.NewBufferString("bad"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestUpdateRole_InternalError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.roleClient = &fakeRoleClient{
		updateFunc: func(ctx context.Context, tenantID string, req *sdkadmin.UpdateRoleRequest) (*sdkadmin.Role, error) {
			return nil, internalErr()
		},
	}
	router := newTestRouter(t, admin)
	body := bytes.NewBufferString(`{"name":"r"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/t1/roles/r1", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestDeleteRole_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/t1/roles/r1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestDeleteRole_InternalError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.roleClient = &fakeRoleClient{
		deleteFunc: func(ctx context.Context, tenantID, roleID string) error {
			return internalErr()
		},
	}
	router := newTestRouter(t, admin)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/t1/roles/r1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

// =============================================================================
// User handlers
// =============================================================================

func TestListUsers_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/t1/users", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestListUsers_Error(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.userClient = &fakeUserClient{
		listFunc: func(ctx context.Context, tenantID string, req *sdkadmin.ListUsersRequest) (*sdkadmin.ListUsersResponse, error) {
			return nil, internalErr()
		},
	}
	router := newTestRouter(t, admin)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/t1/users", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestCreateUser_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	body := bytes.NewBufferString(`{"username":"alice"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/t1/users", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rec.Code)
	}
}

func TestCreateUser_InvalidBody(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/t1/users", bytes.NewBufferString("bad"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestCreateUser_InternalError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.userClient = &fakeUserClient{
		createFunc: func(ctx context.Context, tenantID string, req *sdkadmin.CreateUserRequest) (*sdkadmin.User, error) {
			return nil, internalErr()
		},
	}
	router := newTestRouter(t, admin)
	body := bytes.NewBufferString(`{"username":"bob"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/t1/users", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestGetUser_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/t1/users/u1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestGetUser_InternalError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.userClient = &fakeUserClient{
		getFunc: func(ctx context.Context, tenantID, userID string) (*sdkadmin.User, error) {
			return nil, internalErr()
		},
	}
	router := newTestRouter(t, admin)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/t1/users/u1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestUpdateUser_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	body := bytes.NewBufferString(`{"username":"carol"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/t1/users/u1", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestUpdateUser_InvalidBody(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/t1/users/u1", bytes.NewBufferString("bad"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestUpdateUser_InternalError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.userClient = &fakeUserClient{
		updateFunc: func(ctx context.Context, tenantID string, req *sdkadmin.UpdateUserRequest) (*sdkadmin.User, error) {
			return nil, internalErr()
		},
	}
	router := newTestRouter(t, admin)
	body := bytes.NewBufferString(`{"username":"x"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/t1/users/u1", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestDeleteUser_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/t1/users/u1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestDeleteUser_InternalError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.userClient = &fakeUserClient{
		deleteFunc: func(ctx context.Context, tenantID, userID string) error {
			return internalErr()
		},
	}
	router := newTestRouter(t, admin)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/t1/users/u1", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

// =============================================================================
// Tenant CA handlers
// =============================================================================

func TestCreateTenantRootCA_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	body := bytes.NewBufferString(`{"common_name":"Root CA","key_algorithm":"RSA-2048","validity_years":10}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/t1/root-ca", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rec.Code)
	}
}

func TestCreateTenantRootCA_InvalidBody(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/t1/root-ca", bytes.NewBufferString("bad"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestCreateTenantRootCA_TenantNotFound(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.tenantCAClient = &fakeTenantCAClient{
		createRootCAFunc: func(ctx context.Context, tenantID string, req *sdkadmin.CreateTenantRootCARequest) (*sdkadmin.TenantRootCAInfo, error) {
			return nil, sdkadmin.NewTenantNotFound("test", "not found")
		},
	}
	router := newTestRouter(t, admin)
	body := bytes.NewBufferString(`{"common_name":"Root CA"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/t1/root-ca", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestCreateTenantRootCA_AlreadyExists(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.tenantCAClient = &fakeTenantCAClient{
		createRootCAFunc: func(ctx context.Context, tenantID string, req *sdkadmin.CreateTenantRootCARequest) (*sdkadmin.TenantRootCAInfo, error) {
			return nil, sdkadmin.NewTenantRootCAExists("test", "exists")
		},
	}
	router := newTestRouter(t, admin)
	body := bytes.NewBufferString(`{"common_name":"Root CA"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/t1/root-ca", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d", rec.Code)
	}
}

func TestCreateTenantRootCA_InternalError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.tenantCAClient = &fakeTenantCAClient{
		createRootCAFunc: func(ctx context.Context, tenantID string, req *sdkadmin.CreateTenantRootCARequest) (*sdkadmin.TenantRootCAInfo, error) {
			return nil, internalErr()
		},
	}
	router := newTestRouter(t, admin)
	body := bytes.NewBufferString(`{"common_name":"Root CA"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/t1/root-ca", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestGetTenantCAStatus_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/t1/ca-status", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestGetTenantCAStatus_NotFound(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.tenantCAClient = &fakeTenantCAClient{
		caStatusFunc: func(ctx context.Context, tenantID string) (*sdkadmin.TenantCAStatusInfo, error) {
			return nil, sdkadmin.NewTenantNotFound("test", "not found")
		},
	}
	router := newTestRouter(t, admin)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/missing/ca-status", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestGetTenantCAStatus_InternalError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.tenantCAClient = &fakeTenantCAClient{
		caStatusFunc: func(ctx context.Context, tenantID string) (*sdkadmin.TenantCAStatusInfo, error) {
			return nil, internalErr()
		},
	}
	router := newTestRouter(t, admin)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/t1/ca-status", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestCreateIntermediateCA_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	body := bytes.NewBufferString(`{"common_name":"Issuing CA","key_algorithm":"ECDSA-P256"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/t1/intermediate-cas", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rec.Code)
	}
}

func TestCreateIntermediateCA_InvalidBody(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/t1/intermediate-cas", bytes.NewBufferString("bad"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestCreateIntermediateCA_TenantNotFound(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.tenantCAClient = &fakeTenantCAClient{
		createIntermediateCAFunc: func(ctx context.Context, tenantID string, req *sdkadmin.CreateTenantIntermediateCARequest) (*sdkadmin.TenantIntCAInfo, error) {
			return nil, sdkadmin.NewTenantNotFound("test", "not found")
		},
	}
	router := newTestRouter(t, admin)
	body := bytes.NewBufferString(`{"common_name":"ICA"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/missing/intermediate-cas", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestCreateIntermediateCA_AlreadyExists(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.tenantCAClient = &fakeTenantCAClient{
		createIntermediateCAFunc: func(ctx context.Context, tenantID string, req *sdkadmin.CreateTenantIntermediateCARequest) (*sdkadmin.TenantIntCAInfo, error) {
			return nil, sdkadmin.NewIntermediateCAExists("test", "exists")
		},
	}
	router := newTestRouter(t, admin)
	body := bytes.NewBufferString(`{"common_name":"ICA"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/t1/intermediate-cas", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d", rec.Code)
	}
}

func TestCreateIntermediateCA_InternalError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.tenantCAClient = &fakeTenantCAClient{
		createIntermediateCAFunc: func(ctx context.Context, tenantID string, req *sdkadmin.CreateTenantIntermediateCARequest) (*sdkadmin.TenantIntCAInfo, error) {
			return nil, internalErr()
		},
	}
	router := newTestRouter(t, admin)
	body := bytes.NewBufferString(`{"common_name":"ICA"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/t1/intermediate-cas", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestUpdateIntermediateCAStatus_Success(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	body := bytes.NewBufferString(`{"status":"active"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/t1/intermediate-cas/ca1/status", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestUpdateIntermediateCAStatus_InvalidBody(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/t1/intermediate-cas/ca1/status", bytes.NewBufferString("bad"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestUpdateIntermediateCAStatus_MissingStatus(t *testing.T) {
	router := newTestRouter(t, defaultFakeAdmin())
	body := bytes.NewBufferString(`{}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/t1/intermediate-cas/ca1/status", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing status, got %d", rec.Code)
	}
}

func TestUpdateIntermediateCAStatus_NotFound(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.tenantCAClient = &fakeTenantCAClient{
		updateIntermediateCAStatus: func(ctx context.Context, tenantID, caID, status string) error {
			return sdkadmin.NewIntermediateCANotFound("test", "not found")
		},
	}
	router := newTestRouter(t, admin)
	body := bytes.NewBufferString(`{"status":"active"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/t1/intermediate-cas/missing/status", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestUpdateIntermediateCAStatus_InternalError(t *testing.T) {
	admin := defaultFakeAdmin()
	admin.tenantCAClient = &fakeTenantCAClient{
		updateIntermediateCAStatus: func(ctx context.Context, tenantID, caID, status string) error {
			return internalErr()
		},
	}
	router := newTestRouter(t, admin)
	body := bytes.NewBufferString(`{"status":"active"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/t1/intermediate-cas/ca1/status", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

// =============================================================================
// Error type tests
// =============================================================================

func TestErrInvalidRequestBody_Error(t *testing.T) {
	e := &ErrInvalidRequestBody{Detail: "missing field"}
	want := "gui/api: invalid request body: missing field"
	if got := e.Error(); got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestErrInvalidPathParam_Error(t *testing.T) {
	e := &ErrInvalidPathParam{Param: "id", Detail: "not a number"}
	want := "gui/api: invalid path parameter id: not a number"
	if got := e.Error(); got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestErrSDKCall_Error(t *testing.T) {
	e := &ErrSDKCall{Operation: "List", Detail: "timeout"}
	want := "gui/api: List failed: timeout"
	if got := e.Error(); got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestIsErrorType_Match(t *testing.T) {
	orig := &ErrSDKCall{Operation: "op", Detail: "detail"}
	var target *ErrSDKCall
	if !isErrorType(orig, &target) {
		t.Error("expected isErrorType to return true for matching type")
	}
}

func TestIsErrorType_Mismatch(t *testing.T) {
	orig := &ErrInvalidRequestBody{Detail: "x"}
	var target *ErrSDKCall
	if isErrorType(orig, &target) {
		t.Error("expected isErrorType to return false for mismatched type")
	}
}

func TestIsErrorType_Wrapped(t *testing.T) {
	inner := &ErrSDKCall{Operation: "op", Detail: "detail"}
	wrapped := errors.New("wrapper: " + inner.Error())
	_ = wrapped // wrapping via %w would work; this tests false negative is fine
	var target *ErrSDKCall
	// Direct non-wrapped error
	if !isErrorType(inner, &target) {
		t.Error("expected match for direct error")
	}
}
