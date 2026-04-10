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
	"encoding/base64"
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
	createTenantResp  *transport.CreateTenantResponse
	createTenantErr   error
	getTenantResp     *transport.GetTenantResponse
	getTenantErr      error
	listTenantsResp   *transport.ListTenantsResponse
	listTenantsErr    error
	deleteTenantErr   error
	barrierInitErr    error
	barrierUnsealErr  error
	barrierStatusResp *transport.BarrierStatusResponse
	barrierStatusErr  error
	connectErr        error
	closeCalled       bool
}

func (m *mockTenantClient) Connect(ctx context.Context) error {
	return m.connectErr
}

func (m *mockTenantClient) Close() error {
	m.closeCalled = true
	return nil
}

func (m *mockTenantClient) CreateTenant(ctx context.Context, req *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
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

func (m *mockTenantClient) TenantBarrierInit(ctx context.Context, req *transport.TenantBarrierInitRequest) error {
	return m.barrierInitErr
}

func (m *mockTenantClient) TenantBarrierUnseal(ctx context.Context, req *transport.TenantBarrierUnsealRequest) error {
	return m.barrierUnsealErr
}

func (m *mockTenantClient) BarrierStatus(ctx context.Context) (*transport.BarrierStatusResponse, error) {
	return m.barrierStatusResp, m.barrierStatusErr
}

// --- Command existence and properties ---

func TestTenantCmd_Exists(t *testing.T) {
	if tenantCmd == nil {
		t.Fatal("tenantCmd should not be nil")
	}
}

func TestTenantCmd_Properties(t *testing.T) {
	if tenantCmd.Use != "tenant" {
		t.Errorf("tenantCmd.Use = %q, want %q", tenantCmd.Use, "tenant")
	}
	if tenantCmd.Short == "" {
		t.Error("tenantCmd.Short should not be empty")
	}
}

func TestTenantCmd_Subcommands(t *testing.T) {
	subcommands := tenantCmd.Commands()

	expected := map[string]bool{
		"create":         false,
		"list":           false,
		"show":           false,
		"delete":         false,
		"barrier-init":   false,
		"barrier-unseal": false,
		"barrier-status": false,
	}

	for _, cmd := range subcommands {
		name := cmd.Name()
		if _, ok := expected[name]; ok {
			expected[name] = true
		}
	}

	for name, found := range expected {
		if !found {
			t.Errorf("expected subcommand %q not found", name)
		}
	}

	if len(expected) != 7 {
		t.Errorf("expected 7 subcommands, got %d", len(expected))
	}
}

// --- tenantCreate ---

func TestTenantCreate_Success(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	mock := &mockTenantClient{
		createTenantResp: &transport.CreateTenantResponse{
			Tenant: transport.TenantInfo{
				ID:        "acme",
				Name:      "Acme Corporation",
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

	tenantCreate(cfg, printer, "acme", "Acme Corporation")

	output := buf.String()
	if !strings.Contains(output, "Acme Corporation") {
		t.Error("output should contain tenant name")
	}
	if !strings.Contains(output, "acme") {
		t.Error("output should contain tenant ID")
	}
	if !strings.Contains(output, "Tenant Created") {
		t.Error("output should contain header 'Tenant Created'")
	}
}

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

	tenantCreate(cfg, printer, "acme", "Acme Corporation")
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

	tenantCreate(cfg, printer, "acme", "Acme Corporation")
	// handleError is called, no panic
}

// --- tenantList ---

func TestTenantList_Success(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	mock := &mockTenantClient{
		listTenantsResp: &transport.ListTenantsResponse{
			Tenants: []transport.TenantInfo{
				{ID: "acme", Name: "Acme Corporation", CreatedAt: now, UpdatedAt: now},
				{ID: "globex", Name: "Globex Corp", CreatedAt: now, UpdatedAt: now},
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

	tenantList(cfg, printer)

	output := buf.String()
	if !strings.Contains(output, "Acme Corporation") {
		t.Error("output should contain 'Acme Corporation'")
	}
	if !strings.Contains(output, "Globex Corp") {
		t.Error("output should contain 'Globex Corp'")
	}
}

func TestTenantList_Empty(t *testing.T) {
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

	output := buf.String()
	if !strings.Contains(output, "No tenants found") {
		t.Errorf("expected 'No tenants found', got: %s", output)
	}
}

func TestTenantList_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockTenantClient{
		listTenantsErr: errors.New("internal server error"),
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
	// handleError is called, no panic
}

// --- tenantShow ---

func TestTenantShow_Success(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	mock := &mockTenantClient{
		getTenantResp: &transport.GetTenantResponse{
			Tenant: transport.TenantInfo{
				ID:        "acme",
				Name:      "Acme Corporation",
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

	tenantShow(cfg, printer, "acme")

	output := buf.String()
	if !strings.Contains(output, "acme") {
		t.Error("output should contain tenant ID 'acme'")
	}
	if !strings.Contains(output, "Acme Corporation") {
		t.Error("output should contain tenant name")
	}
	if !strings.Contains(output, "Tenant Details") {
		t.Error("output should contain header 'Tenant Details'")
	}
}

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

func TestTenantDelete_Success(t *testing.T) {
	mock := &mockTenantClient{}

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}

	tenantDelete(cfg, printer, "acme")

	output := buf.String()
	if !strings.Contains(output, "acme") {
		t.Error("output should contain the deleted tenant ID")
	}
	if !strings.Contains(output, "deleted") {
		t.Error("output should indicate the tenant was deleted")
	}
}

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

func TestTenantBarrierInit_Success(t *testing.T) {
	mock := &mockTenantClient{}

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}

	tenantBarrierInit(cfg, printer, "acme", 3, 5)

	output := buf.String()
	if !strings.Contains(output, "acme") {
		t.Error("output should contain the tenant ID")
	}
	if !strings.Contains(output, "Barrier initialized") {
		t.Error("output should indicate barrier was initialized")
	}
}

func TestTenantBarrierInit_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockTenantClient{
		barrierInitErr: errors.New("barrier already initialized"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}

	tenantBarrierInit(cfg, printer, "acme", 3, 5)
	// handleError is called, no panic
}

// --- tenantBarrierUnseal ---

func TestTenantBarrierUnseal_Success(t *testing.T) {
	mock := &mockTenantClient{}

	validShare := base64.StdEncoding.EncodeToString([]byte("test-share-bytes"))

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}

	tenantBarrierUnseal(cfg, printer, "acme", validShare)

	output := buf.String()
	if !strings.Contains(output, "acme") {
		t.Error("output should contain the tenant ID")
	}
	if !strings.Contains(output, "Barrier unsealed") {
		t.Error("output should indicate barrier was unsealed")
	}
}

func TestTenantBarrierUnseal_InvalidBase64(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockTenantClient{}

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}

	tenantBarrierUnseal(cfg, printer, "acme", "!!!not-valid-base64!!!")
	// handleError is called due to base64 decode failure, no panic
}

func TestTenantBarrierUnseal_EmptyShare(t *testing.T) {
	mock := &mockTenantClient{}

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}

	// Empty share string should skip base64 decoding
	tenantBarrierUnseal(cfg, printer, "acme", "")

	output := buf.String()
	if !strings.Contains(output, "Barrier unsealed") {
		t.Error("output should indicate barrier was unsealed even with empty share")
	}
}

func TestTenantBarrierUnseal_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockTenantClient{
		barrierUnsealErr: errors.New("insufficient shares"),
	}

	validShare := base64.StdEncoding.EncodeToString([]byte("share-data"))

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}

	tenantBarrierUnseal(cfg, printer, "acme", validShare)
	// handleError is called, no panic
}

// --- tenantBarrierStatus ---

func TestTenantBarrierStatus_Success(t *testing.T) {
	mock := &mockTenantClient{
		barrierStatusResp: &transport.BarrierStatusResponse{
			Sealed:         false,
			Strategy:       "shamir",
			HardwareBacked: true,
			InitializedAt:  "2025-01-15T10:30:00Z",
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

	tenantBarrierStatus(cfg, printer, "acme")

	output := buf.String()
	if !strings.Contains(output, "acme") {
		t.Error("output should contain the tenant ID")
	}
	if !strings.Contains(output, "unsealed") {
		t.Error("output should indicate barrier is unsealed")
	}
	if !strings.Contains(output, "shamir") {
		t.Error("output should contain the strategy")
	}
	if !strings.Contains(output, "true") {
		t.Error("output should indicate hardware backed status")
	}
	if !strings.Contains(output, "2025-01-15T10:30:00Z") {
		t.Error("output should contain the initialized_at timestamp")
	}
}

func TestTenantBarrierStatus_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockTenantClient{
		barrierStatusErr: errors.New("not found"),
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}

	tenantBarrierStatus(cfg, printer, "acme")
	// handleError is called, no panic
}

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

func TestPrintTenantBarrierStatus_JSON(t *testing.T) {
	resp := &transport.BarrierStatusResponse{
		Sealed:         true,
		Strategy:       "shamir",
		HardwareBacked: false,
		InitializedAt:  "2025-01-15T10:30:00Z",
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	printTenantBarrierStatus(printer, "acme", resp)

	output := buf.String()
	if !strings.Contains(output, `"tenant_id"`) {
		t.Error("JSON output should contain 'tenant_id'")
	}
	if !strings.Contains(output, `"acme"`) {
		t.Error("JSON output should contain tenant ID value")
	}
	if !strings.Contains(output, `"sealed"`) {
		t.Error("JSON output should contain 'sealed' field")
	}
	if !strings.Contains(output, `"strategy"`) {
		t.Error("JSON output should contain 'strategy' field")
	}
	if !strings.Contains(output, `"hardware_backed"`) {
		t.Error("JSON output should contain 'hardware_backed' field")
	}
	if !strings.Contains(output, `"initialized_at"`) {
		t.Error("JSON output should contain 'initialized_at' when set")
	}
}

func TestPrintTenantBarrierStatus_JSON_NoInitializedAt(t *testing.T) {
	resp := &transport.BarrierStatusResponse{
		Sealed:         false,
		Strategy:       "aes-gcm",
		HardwareBacked: true,
		InitializedAt:  "",
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	printTenantBarrierStatus(printer, "globex", resp)

	output := buf.String()
	if strings.Contains(output, `"initialized_at"`) {
		t.Error("JSON output should NOT contain 'initialized_at' when empty")
	}
}

func TestPrintTenantBarrierStatus_Text_Sealed(t *testing.T) {
	resp := &transport.BarrierStatusResponse{
		Sealed:         true,
		Strategy:       "shamir",
		HardwareBacked: false,
		InitializedAt:  "2025-01-15T10:30:00Z",
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	printTenantBarrierStatus(printer, "acme", resp)

	output := buf.String()
	if !strings.Contains(output, "Tenant Barrier Status:") {
		t.Error("text output should contain header")
	}
	if !strings.Contains(output, "Tenant:          acme") {
		t.Error("text output should contain tenant ID")
	}
	if !strings.Contains(output, "State:           sealed") {
		t.Error("text output should show 'sealed' state")
	}
	if !strings.Contains(output, "Strategy:        shamir") {
		t.Error("text output should contain strategy")
	}
	if !strings.Contains(output, "Hardware Backed: false") {
		t.Error("text output should contain hardware backed status")
	}
	if !strings.Contains(output, "Initialized At:") {
		t.Error("text output should contain initialized_at when set")
	}
}

func TestPrintTenantBarrierStatus_Text_Unsealed(t *testing.T) {
	resp := &transport.BarrierStatusResponse{
		Sealed:         false,
		Strategy:       "aes-gcm",
		HardwareBacked: true,
		InitializedAt:  "",
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	printTenantBarrierStatus(printer, "globex", resp)

	output := buf.String()
	if !strings.Contains(output, "State:           unsealed") {
		t.Error("text output should show 'unsealed' state")
	}
	if !strings.Contains(output, "Hardware Backed: true") {
		t.Error("text output should show hardware backed as true")
	}
	if strings.Contains(output, "Initialized At:") {
		t.Error("text output should NOT contain 'Initialized At' when empty")
	}
}

func TestPrintTenantBarrierStatus_Table(t *testing.T) {
	resp := &transport.BarrierStatusResponse{
		Sealed:         true,
		Strategy:       "shamir",
		HardwareBacked: true,
		InitializedAt:  "2025-06-01T00:00:00Z",
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("table", buf)

	printTenantBarrierStatus(printer, "acme", resp)

	output := buf.String()
	// Table format uses the same code path as text for printTenantBarrierStatus
	if !strings.Contains(output, "Tenant Barrier Status:") {
		t.Error("table output should contain header")
	}
	if !strings.Contains(output, "sealed") {
		t.Error("table output should contain seal state")
	}
}

// --- createTenantClient ---

func TestCreateTenantClient_Success(t *testing.T) {
	mock := &mockTenantClient{}

	cfg := &Config{
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}

	cl, cleanup, err := createTenantClient(cfg)
	if err != nil {
		t.Fatalf("createTenantClient returned unexpected error: %v", err)
	}
	if cl == nil {
		t.Fatal("createTenantClient returned nil client")
	}
	if cleanup == nil {
		t.Fatal("createTenantClient returned nil cleanup function")
	}

	cleanup()
	if !mock.closeCalled {
		t.Error("cleanup function should call client.Close()")
	}
}

func TestCreateTenantClient_FactoryError(t *testing.T) {
	cfg := &Config{
		ClientFactory: func(c *Config) (client.Client, error) {
			return nil, errors.New("factory failure")
		},
	}

	cl, cleanup, err := createTenantClient(cfg)
	if err == nil {
		t.Fatal("createTenantClient should return an error when factory fails")
	}
	if cl != nil {
		t.Error("client should be nil on error")
	}
	if cleanup != nil {
		t.Error("cleanup should be nil on error")
	}
	if !strings.Contains(err.Error(), "failed to create client") {
		t.Errorf("error should mention 'failed to create client', got: %v", err)
	}
}

func TestCreateTenantClient_ConnectError(t *testing.T) {
	mock := &mockTenantClient{
		connectErr: errors.New("connection refused"),
	}

	cfg := &Config{
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}

	cl, cleanup, err := createTenantClient(cfg)
	if err == nil {
		t.Fatal("createTenantClient should return an error when Connect fails")
	}
	if cl != nil {
		t.Error("client should be nil on connect error")
	}
	if cleanup != nil {
		t.Error("cleanup should be nil on connect error")
	}
	if !strings.Contains(err.Error(), "failed to connect") {
		t.Errorf("error should mention 'failed to connect', got: %v", err)
	}
	if !mock.closeCalled {
		t.Error("Close should be called when Connect fails")
	}
}

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

	tenantCreate(cfg, printer, "test-tenant", "Test Tenant")

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

func TestTenantBarrierInit_JSONFormat(t *testing.T) {
	mock := &mockTenantClient{}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		OutputFormat: "json",
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}

	tenantBarrierInit(cfg, printer, "acme", 2, 3)

	output := buf.String()
	if !strings.Contains(output, "success") {
		t.Error("JSON output should contain 'success' status")
	}
	if !strings.Contains(output, "acme") {
		t.Error("JSON output should contain tenant ID")
	}
}

func TestTenantBarrierUnseal_JSONFormat(t *testing.T) {
	mock := &mockTenantClient{}

	validShare := base64.StdEncoding.EncodeToString([]byte("my-share"))

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	cfg := &Config{
		OutputFormat: "json",
		ClientFactory: func(c *Config) (client.Client, error) {
			return mock, nil
		},
	}

	tenantBarrierUnseal(cfg, printer, "acme", validShare)

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

	tenantCreate(cfg, printer, "acme", "Acme")

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

func TestTenantBarrierStatus_CloseIsCalled(t *testing.T) {
	mock := &mockTenantClient{
		barrierStatusResp: &transport.BarrierStatusResponse{
			Sealed:   false,
			Strategy: "static",
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

	tenantBarrierStatus(cfg, printer, "acme")

	if !mock.closeCalled {
		t.Error("client.Close() should be called via deferred cleanup")
	}
}
