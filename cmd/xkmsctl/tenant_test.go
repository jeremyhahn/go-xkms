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

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// mockTenantClient is a mock client for testing tenant operations.
type mockTenantClient struct {
	mockBackendsClient
	createTenantResp *transport.CreateTenantResponse
	createTenantErr  error
	getTenantResp    *transport.GetTenantResponse
	getTenantErr     error
	listTenantsResp  *transport.ListTenantsResponse
	listTenantsErr   error
	deleteTenantErr  error
	connectErr       error
	closeCalled      bool

	// Captured requests for assertion.
	gotCreateReq           *transport.CreateTenantRequest
	updateEntitlementsResp *transport.UpdateTenantEntitlementsResponse
	updateEntitlementsErr  error
	updateQuotasResp       *transport.UpdateTenantQuotasResponse
	updateQuotasErr        error
}

func (m *mockTenantClient) Connect(ctx context.Context) error {
	return m.connectErr
}

func (m *mockTenantClient) Close() error {
	m.closeCalled = true
	return nil
}

func (m *mockTenantClient) CreateTenant(ctx context.Context, req *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	m.gotCreateReq = req
	return m.createTenantResp, m.createTenantErr
}

func (m *mockTenantClient) GetTenant(ctx context.Context, tenantID string) (*transport.GetTenantResponse, error) {
	return m.getTenantResp, m.getTenantErr
}

func (m *mockTenantClient) ListTenants(ctx context.Context) (*transport.ListTenantsResponse, error) {
	return m.listTenantsResp, m.listTenantsErr
}

func (m *mockTenantClient) DeleteTenant(ctx context.Context, tenantID string) error {
	return m.deleteTenantErr
}

func (m *mockTenantClient) UpdateTenantEntitlements(_ context.Context, _ *transport.UpdateTenantEntitlementsRequest) (*transport.UpdateTenantEntitlementsResponse, error) {
	return m.updateEntitlementsResp, m.updateEntitlementsErr
}

func (m *mockTenantClient) UpdateTenantQuotas(_ context.Context, _ *transport.UpdateTenantQuotasRequest) (*transport.UpdateTenantQuotasResponse, error) {
	return m.updateQuotasResp, m.updateQuotasErr
}

func (m *mockTenantClient) BootstrapListenerKeys(ctx context.Context) (*transport.BootstrapListenerKeysResponse, error) {
	return nil, nil
}

// --- New isolation / strategy flag plumbing ---

func TestTenantCreate_ForwardsIsolationAndAutoUnseal(t *testing.T) {
	mock := &mockTenantClient{
		createTenantResp: &transport.CreateTenantResponse{Tenant: transport.TenantInfo{ID: "acme", Name: "Acme"}},
	}
	cfg := &Config{
		OutputFormat:  "text",
		ClientFactory: func(c *Config) (client.Client, error) { return mock, nil },
	}
	tenantCreate(cfg, NewPrinter("text", new(bytes.Buffer)), "acme", "Acme", "volume", true)

	if mock.gotCreateReq == nil {
		t.Fatal("CreateTenant was not called")
	}
	if string(mock.gotCreateReq.IsolationType) != "volume" {
		t.Errorf("IsolationType = %q, want %q", mock.gotCreateReq.IsolationType, "volume")
	}
	if !mock.gotCreateReq.BarrierAutoUnseal {
		t.Error("BarrierAutoUnseal = false, want true")
	}
}

// --- Command existence and properties ---

// --- tenantCreate ---

func TestTenantCreate_ClientError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockTenantClient{
		connectErr: errors.New("connection refused"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}

	tenantCreate(cfg, printer, "acme", "Acme Corporation", "", false)
	// Should not panic; handleError is called internally
}

func TestTenantCreate_APIError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockTenantClient{
		createTenantErr: errors.New("tenant already exists"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}

	tenantCreate(cfg, printer, "acme", "Acme Corporation", "", false)
	// handleError is called, no panic
}

// --- tenantList ---

// --- tenantShow ---

func TestTenantShow_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockTenantClient{
		getTenantErr: errors.New("tenant not found"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}

	tenantShow(cfg, printer, "nonexistent")
	// handleError is called, no panic
}

// --- tenantDelete ---

func TestTenantDelete_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockTenantClient{
		deleteTenantErr: errors.New("permission denied"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}

	tenantDelete(cfg, printer, "acme")
	// handleError is called, no panic
}

// --- tenantBarrierInit ---

// --- tenantBarrierUnseal ---

// --- tenantBarrierStatus ---

// --- Output helpers: printTenantInfo ---

func TestPrintTenantInfo_JSON(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	tenant := &transport.TenantInfo{
		ID:        "acme",
		Name:      "Acme Corporation",
		CreatedAt: now,
		UpdatedAt: now,
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	printTenantInfo(printer, tenant, "Tenant Created")

	output := buf.String()
	if !strings.Contains(output, `"id"`) {
		t.Error("JSON output should contain 'id' field")
	}
	if !strings.Contains(output, `"acme"`) {
		t.Error("JSON output should contain the tenant ID value")
	}
	if !strings.Contains(output, `"Acme Corporation"`) {
		t.Error("JSON output should contain the tenant name")
	}
	if !strings.Contains(output, `"created_at"`) {
		t.Error("JSON output should contain 'created_at' field")
	}
	if !strings.Contains(output, `"updated_at"`) {
		t.Error("JSON output should contain 'updated_at' field")
	}
}

func TestPrintTenantInfo_Text(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	tenant := &transport.TenantInfo{
		ID:        "acme",
		Name:      "Acme Corporation",
		CreatedAt: now,
		UpdatedAt: now,
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	printTenantInfo(printer, tenant, "Tenant Details")

	output := buf.String()
	if !strings.Contains(output, "Tenant Details:") {
		t.Error("text output should contain the header")
	}
	if !strings.Contains(output, "ID:      acme") {
		t.Error("text output should contain formatted ID")
	}
	if !strings.Contains(output, "Name:    Acme Corporation") {
		t.Error("text output should contain formatted name")
	}
	if !strings.Contains(output, "Created:") {
		t.Error("text output should contain Created line")
	}
	if !strings.Contains(output, "Updated:") {
		t.Error("text output should contain Updated line")
	}
}

func TestPrintTenantInfo_Table(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	tenant := &transport.TenantInfo{
		ID:        "acme",
		Name:      "Acme Corporation",
		CreatedAt: now,
		UpdatedAt: now,
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("table", buf)

	printTenantInfo(printer, tenant, "Tenant Info")

	output := buf.String()
	// Table format uses the same code path as text for printTenantInfo
	if !strings.Contains(output, "Tenant Info:") {
		t.Error("table output should contain the header")
	}
	if !strings.Contains(output, "acme") {
		t.Error("table output should contain tenant ID")
	}
}

// --- Output helpers: printTenantList ---

func TestPrintTenantList_JSON(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	tenants := []transport.TenantInfo{
		{ID: "acme", Name: "Acme Corporation", CreatedAt: now, UpdatedAt: now},
		{ID: "globex", Name: "Globex Corp", CreatedAt: now, UpdatedAt: now},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	printTenantList(printer, tenants)

	output := buf.String()
	if !strings.Contains(output, `"tenants"`) {
		t.Error("JSON output should contain 'tenants' key")
	}
	if !strings.Contains(output, `"total"`) {
		t.Error("JSON output should contain 'total' key")
	}
	if !strings.Contains(output, `"acme"`) {
		t.Error("JSON output should contain tenant ID 'acme'")
	}
	if !strings.Contains(output, `"globex"`) {
		t.Error("JSON output should contain tenant ID 'globex'")
	}
}

func TestPrintTenantList_Table(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	tenants := []transport.TenantInfo{
		{ID: "acme", Name: "Acme Corporation", CreatedAt: now, UpdatedAt: now},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("table", buf)

	printTenantList(printer, tenants)

	output := buf.String()
	if !strings.Contains(output, "ID") {
		t.Error("table output should contain column header 'ID'")
	}
	if !strings.Contains(output, "NAME") {
		t.Error("table output should contain column header 'NAME'")
	}
	if !strings.Contains(output, "CREATED") {
		t.Error("table output should contain column header 'CREATED'")
	}
	if !strings.Contains(output, "acme") {
		t.Error("table output should contain tenant ID")
	}
	if !strings.Contains(output, "Total: 1 tenant(s)") {
		t.Error("table output should contain total count")
	}
}

func TestPrintTenantList_Table_Empty(t *testing.T) {
	buf := new(bytes.Buffer)
	printer := NewPrinter("table", buf)

	printTenantList(printer, []transport.TenantInfo{})

	output := buf.String()
	if !strings.Contains(output, "No tenants found") {
		t.Errorf("table output for empty list should contain 'No tenants found', got: %s", output)
	}
}

func TestPrintTenantList_Text(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	tenants := []transport.TenantInfo{
		{ID: "acme", Name: "Acme Corporation", CreatedAt: now, UpdatedAt: now},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	printTenantList(printer, tenants)

	output := buf.String()
	if !strings.Contains(output, "Tenants:") {
		t.Error("text output should contain 'Tenants:' header")
	}
	if !strings.Contains(output, "Acme Corporation (acme)") {
		t.Error("text output should contain 'Name (ID)' format")
	}
}

func TestPrintTenantList_Text_Empty(t *testing.T) {
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	printTenantList(printer, []transport.TenantInfo{})

	output := buf.String()
	if !strings.Contains(output, "No tenants found") {
		t.Errorf("text output for empty list should contain 'No tenants found', got: %s", output)
	}
}

// --- Output helpers: printTenantBarrierStatus ---

// --- createTenantClient ---

// --- Additional coverage for format variations ---

func TestTenantCreate_JSONFormat(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	mock := &mockTenantClient{
		createTenantResp: &transport.CreateTenantResponse{
			Tenant: transport.TenantInfo{
				ID:        "test-tenant",
				Name:      "Test Tenant",
				CreatedAt: now,
				UpdatedAt: now,
			},
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		OutputFormat: "json",
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}

	tenantCreate(cfg, printer, "test-tenant", "Test Tenant", "", false)

	output := buf.String()
	if !strings.Contains(output, `"id"`) {
		t.Error("JSON output should contain 'id' field")
	}
	if !strings.Contains(output, `"test-tenant"`) {
		t.Error("JSON output should contain tenant ID")
	}
}

func TestTenantList_TableFormat(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	mock := &mockTenantClient{
		listTenantsResp: &transport.ListTenantsResponse{
			Tenants: []transport.TenantInfo{
				{ID: "acme", Name: "Acme Corporation", CreatedAt: now, UpdatedAt: now},
			},
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("table", buf)

	cfg := &Config{
		OutputFormat: "table",
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}

	tenantList(cfg, printer)

	output := buf.String()
	if !strings.Contains(output, "ID") {
		t.Error("table output should contain column headers")
	}
	if !strings.Contains(output, "Total:") {
		t.Error("table output should contain total count")
	}
}

func TestTenantDelete_JSONFormat(t *testing.T) {
	mock := &mockTenantClient{}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		OutputFormat: "json",
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}

	tenantDelete(cfg, printer, "acme")

	output := buf.String()
	if !strings.Contains(output, "success") {
		t.Error("JSON output should contain 'success' status")
	}
	if !strings.Contains(output, "acme") {
		t.Error("JSON output should contain tenant ID")
	}
}

// --- Verify Close is called on success paths ---

func TestTenantCreate_CloseIsCalled(t *testing.T) {
	now := time.Now()
	mock := &mockTenantClient{
		createTenantResp: &transport.CreateTenantResponse{
			Tenant: transport.TenantInfo{
				ID:        "acme",
				Name:      "Acme",
				CreatedAt: now,
				UpdatedAt: now,
			},
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}

	tenantCreate(cfg, printer, "acme", "Acme", "", false)

	if !mock.closeCalled {
		t.Error("client.Close() should be called via deferred cleanup")
	}
}

func TestTenantList_CloseIsCalled(t *testing.T) {
	mock := &mockTenantClient{
		listTenantsResp: &transport.ListTenantsResponse{
			Tenants: []transport.TenantInfo{},
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}

	tenantList(cfg, printer)

	if !mock.closeCalled {
		t.Error("client.Close() should be called via deferred cleanup")
	}
}
