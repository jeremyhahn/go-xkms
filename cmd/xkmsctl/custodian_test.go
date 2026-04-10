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

// mockCustodianClient is a mock client for testing custodian operations.
type mockCustodianClient struct {
	mockBackendsClient

	connectErr  error
	closeErr    error
	closeCalled bool

	createGroupResp *transport.CreateCustodianGroupResponse
	createGroupErr  error

	getGroupResp *transport.GetCustodianGroupResponse
	getGroupErr  error

	listGroupsResp *transport.ListCustodianGroupsResponse
	listGroupsErr  error

	deleteGroupErr error

	addMemberResp *transport.AddCustodianMemberResponse
	addMemberErr  error

	removeMemberErr error

	distributeResp *transport.DistributeSharesResponse
	distributeErr  error
}

func (m *mockCustodianClient) Connect(ctx context.Context) error {
	return m.connectErr
}

func (m *mockCustodianClient) Close() error {
	m.closeCalled = true
	return m.closeErr
}

func (m *mockCustodianClient) CreateCustodianGroup(ctx context.Context, req *transport.CreateCustodianGroupRequest) (*transport.CreateCustodianGroupResponse, error) {
	return m.createGroupResp, m.createGroupErr
}

func (m *mockCustodianClient) GetCustodianGroup(ctx context.Context, groupID string) (*transport.GetCustodianGroupResponse, error) {
	return m.getGroupResp, m.getGroupErr
}

func (m *mockCustodianClient) ListCustodianGroups(ctx context.Context) (*transport.ListCustodianGroupsResponse, error) {
	return m.listGroupsResp, m.listGroupsErr
}

func (m *mockCustodianClient) DeleteCustodianGroup(ctx context.Context, groupID string) error {
	return m.deleteGroupErr
}

func (m *mockCustodianClient) AddCustodianMember(ctx context.Context, req *transport.AddCustodianMemberRequest) (*transport.AddCustodianMemberResponse, error) {
	return m.addMemberResp, m.addMemberErr
}

func (m *mockCustodianClient) RemoveCustodianMember(ctx context.Context, req *transport.RemoveCustodianMemberRequest) error {
	return m.removeMemberErr
}

func (m *mockCustodianClient) DistributeShares(ctx context.Context, req *transport.DistributeSharesRequest) (*transport.DistributeSharesResponse, error) {
	return m.distributeResp, m.distributeErr
}

// ShareService stub implementations
func (m *mockCustodianClient) SubmitShare(ctx context.Context, req *transport.SubmitShareRequest) (*transport.SubmitShareResponse, error) {
	return nil, nil
}

func (m *mockCustodianClient) ListShares(ctx context.Context) (*transport.ListSharesResponse, error) {
	return nil, nil
}

func (m *mockCustodianClient) GetShareCollectionStatus(ctx context.Context, groupID string) (*transport.ShareCollectionStatus, error) {
	return nil, nil
}

// TenantService stub implementations
func (m *mockCustodianClient) CreateTenant(ctx context.Context, req *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	return nil, nil
}

func (m *mockCustodianClient) GetTenant(ctx context.Context, tenantID string) (*transport.GetTenantResponse, error) {
	return nil, nil
}

func (m *mockCustodianClient) ListTenants(ctx context.Context) (*transport.ListTenantsResponse, error) {
	return nil, nil
}

func (m *mockCustodianClient) DeleteTenant(ctx context.Context, tenantID string) error {
	return nil
}

func (m *mockCustodianClient) TenantBarrierInit(ctx context.Context, req *transport.TenantBarrierInitRequest) error {
	return nil
}

func (m *mockCustodianClient) TenantBarrierUnseal(ctx context.Context, req *transport.TenantBarrierUnsealRequest) error {
	return nil
}

// newTestCustodianConfig creates a Config wired to the given mock client.
func newTestCustodianConfig(mock *mockCustodianClient) *Config {
	return &Config{
		OutputFormat: "text",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mock, nil
		},
	}
}

// testFixtureTime returns a deterministic time for test fixtures.
func testFixtureTime() time.Time {
	return time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC)
}

// testFixtureGroup returns a CustodianGroupInfo for test fixtures.
func testFixtureGroup() transport.CustodianGroupInfo {
	return transport.CustodianGroupInfo{
		ID:        "grp-001",
		TenantID:  "tenant-acme",
		Name:      "Ops Team",
		Purpose:   "production barrier",
		Threshold: 3,
		Total:     5,
		Members: []transport.CustodianMemberInfo{
			{
				ShareIndex: 1,
				UserID:     "user-001",
				Username:   "alice",
				AssignedAt: testFixtureTime(),
				Method:     "encrypted",
			},
			{
				ShareIndex: 2,
				UserID:     "user-002",
				Username:   "bob",
				AssignedAt: testFixtureTime(),
				Method:     "manual",
			},
		},
		CreatedAt: testFixtureTime(),
		UpdatedAt: testFixtureTime(),
	}
}

// --- Command existence and properties ---

func TestCustodianCmd_Exists(t *testing.T) {
	if custodianCmd == nil {
		t.Fatal("custodianCmd should not be nil")
	}
}

func TestCustodianCmd_Properties(t *testing.T) {
	if custodianCmd.Use != "custodian" {
		t.Errorf("custodianCmd.Use = %q, want %q", custodianCmd.Use, "custodian")
	}
	if custodianCmd.Short == "" {
		t.Error("custodianCmd.Short should not be empty")
	}
}

func TestCustodianCmd_Subcommands(t *testing.T) {
	subcommands := custodianCmd.Commands()

	expected := map[string]bool{
		"create":        false,
		"list":          false,
		"show":          false,
		"delete":        false,
		"add-member":    false,
		"remove-member": false,
		"distribute":    false,
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

	if len(subcommands) != 7 {
		t.Errorf("expected 7 subcommands, got %d", len(subcommands))
	}
}

// --- createCustodianClient ---

func TestCreateCustodianClient_Success(t *testing.T) {
	mock := &mockCustodianClient{}
	cfg := newTestCustodianConfig(mock)

	cl, cleanup, err := createCustodianClient(cfg)
	if err != nil {
		t.Fatalf("createCustodianClient returned unexpected error: %v", err)
	}
	if cl == nil {
		t.Fatal("createCustodianClient returned nil client")
	}
	if cleanup == nil {
		t.Fatal("createCustodianClient returned nil cleanup")
	}

	cleanup()
	if !mock.closeCalled {
		t.Error("cleanup should call client.Close()")
	}
}

func TestCreateCustodianClient_FactoryError(t *testing.T) {
	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return nil, errors.New("factory failure")
		},
	}

	cl, cleanup, err := createCustodianClient(cfg)
	if err == nil {
		t.Fatal("createCustodianClient should return error on factory failure")
	}
	if cl != nil {
		t.Error("client should be nil on error")
	}
	if cleanup != nil {
		t.Error("cleanup should be nil on error")
	}
	if !strings.Contains(err.Error(), "failed to create client") {
		t.Errorf("error should wrap 'failed to create client', got: %v", err)
	}
}

func TestCreateCustodianClient_ConnectError(t *testing.T) {
	mock := &mockCustodianClient{
		connectErr: errors.New("connect refused"),
	}
	cfg := newTestCustodianConfig(mock)

	cl, cleanup, err := createCustodianClient(cfg)
	if err == nil {
		t.Fatal("createCustodianClient should return error on connect failure")
	}
	if cl != nil {
		t.Error("client should be nil on error")
	}
	if cleanup != nil {
		t.Error("cleanup should be nil on error")
	}
	if !strings.Contains(err.Error(), "failed to connect") {
		t.Errorf("error should wrap 'failed to connect', got: %v", err)
	}
	// Verify Close was called for cleanup on connect failure
	if !mock.closeCalled {
		t.Error("Close should be called when Connect fails")
	}
}

// --- custodianCreate ---

func TestCustodianCreate_Success(t *testing.T) {
	group := testFixtureGroup()
	mock := &mockCustodianClient{
		createGroupResp: &transport.CreateCustodianGroupResponse{
			Group: group,
		},
	}

	buf := new(bytes.Buffer)
	cfg := newTestCustodianConfig(mock)
	printer := NewPrinter("text", buf)

	custodianCreate(cfg, printer, "grp-001", "tenant-acme", "Ops Team", "production barrier", 3, 5)

	output := buf.String()
	if !strings.Contains(output, "Ops Team") {
		t.Error("output should contain group name")
	}
	if !strings.Contains(output, "grp-001") {
		t.Error("output should contain group ID")
	}
	if !strings.Contains(output, "3 of 5") {
		t.Error("output should contain threshold/total")
	}
}

func TestCustodianCreate_ClientError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	cfg := &Config{
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return nil, errors.New("client creation failed")
		},
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	custodianCreate(cfg, printer, "", "", "name", "purpose", 2, 3)
	// Should not panic
}

func TestCustodianCreate_APIError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockCustodianClient{
		createGroupErr: errors.New("server error"),
	}

	buf := new(bytes.Buffer)
	cfg := newTestCustodianConfig(mock)
	printer := NewPrinter("text", buf)

	custodianCreate(cfg, printer, "", "", "name", "purpose", 2, 3)
	// Should not panic; handleError is called
}

// --- custodianList ---

func TestCustodianList_Success(t *testing.T) {
	groups := []transport.CustodianGroupInfo{
		testFixtureGroup(),
		{
			ID:        "grp-002",
			Name:      "DR Group",
			Purpose:   "disaster recovery",
			Threshold: 2,
			Total:     3,
			CreatedAt: testFixtureTime(),
		},
	}
	mock := &mockCustodianClient{
		listGroupsResp: &transport.ListCustodianGroupsResponse{
			Groups: groups,
		},
	}

	buf := new(bytes.Buffer)
	cfg := newTestCustodianConfig(mock)
	printer := NewPrinter("table", buf)

	custodianList(cfg, printer)

	output := buf.String()
	if !strings.Contains(output, "Ops Team") {
		t.Error("output should contain first group name")
	}
	if !strings.Contains(output, "DR Group") {
		t.Error("output should contain second group name")
	}
	if !strings.Contains(output, "Total: 2 group(s)") {
		t.Error("output should contain total count")
	}
}

func TestCustodianList_Empty(t *testing.T) {
	mock := &mockCustodianClient{
		listGroupsResp: &transport.ListCustodianGroupsResponse{
			Groups: []transport.CustodianGroupInfo{},
		},
	}

	buf := new(bytes.Buffer)
	cfg := newTestCustodianConfig(mock)
	printer := NewPrinter("table", buf)

	custodianList(cfg, printer)

	output := buf.String()
	if !strings.Contains(output, "No custodian groups found") {
		t.Error("output should contain 'No custodian groups found' for empty list")
	}
}

func TestCustodianList_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockCustodianClient{
		listGroupsErr: errors.New("list failed"),
	}

	buf := new(bytes.Buffer)
	cfg := newTestCustodianConfig(mock)
	printer := NewPrinter("text", buf)

	custodianList(cfg, printer)
	// Should not panic
}

// --- custodianShow ---

func TestCustodianShow_Success(t *testing.T) {
	group := testFixtureGroup()
	mock := &mockCustodianClient{
		getGroupResp: &transport.GetCustodianGroupResponse{
			Group: group,
		},
	}

	buf := new(bytes.Buffer)
	cfg := newTestCustodianConfig(mock)
	printer := NewPrinter("text", buf)

	custodianShow(cfg, printer, "grp-001")

	output := buf.String()
	if !strings.Contains(output, "grp-001") {
		t.Error("output should contain group ID")
	}
	if !strings.Contains(output, "Ops Team") {
		t.Error("output should contain group name")
	}
	if !strings.Contains(output, "alice") {
		t.Error("output should contain member username")
	}
	if !strings.Contains(output, "bob") {
		t.Error("output should contain second member username")
	}
	if !strings.Contains(output, "Members (2)") {
		t.Error("output should contain member count")
	}
}

func TestCustodianShow_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockCustodianClient{
		getGroupErr: errors.New("not found"),
	}

	buf := new(bytes.Buffer)
	cfg := newTestCustodianConfig(mock)
	printer := NewPrinter("text", buf)

	custodianShow(cfg, printer, "nonexistent")
	// Should not panic
}

// --- custodianDelete ---

func TestCustodianDelete_Success(t *testing.T) {
	mock := &mockCustodianClient{}

	buf := new(bytes.Buffer)
	cfg := newTestCustodianConfig(mock)
	printer := NewPrinter("text", buf)

	custodianDelete(cfg, printer, "grp-001")

	output := buf.String()
	if !strings.Contains(output, "grp-001") {
		t.Error("output should contain the deleted group ID")
	}
	if !strings.Contains(output, "deleted") {
		t.Error("output should contain 'deleted'")
	}
}

func TestCustodianDelete_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockCustodianClient{
		deleteGroupErr: errors.New("delete failed"),
	}

	buf := new(bytes.Buffer)
	cfg := newTestCustodianConfig(mock)
	printer := NewPrinter("text", buf)

	custodianDelete(cfg, printer, "grp-001")
	// Should not panic
}

// --- custodianAddMember ---

func TestCustodianAddMember_Success(t *testing.T) {
	mock := &mockCustodianClient{
		addMemberResp: &transport.AddCustodianMemberResponse{
			Member: transport.CustodianMemberInfo{
				ShareIndex: 3,
				UserID:     "user-003",
				Username:   "charlie",
				AssignedAt: testFixtureTime(),
				Method:     "encrypted",
			},
		},
	}

	buf := new(bytes.Buffer)
	cfg := newTestCustodianConfig(mock)
	printer := NewPrinter("text", buf)

	custodianAddMember(cfg, printer, "grp-001", "user-003", "charlie", "encrypted")

	output := buf.String()
	if !strings.Contains(output, "user-003") {
		t.Error("output should contain user ID")
	}
	if !strings.Contains(output, "charlie") {
		t.Error("output should contain username")
	}
	if !strings.Contains(output, "encrypted") {
		t.Error("output should contain method")
	}
}

func TestCustodianAddMember_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockCustodianClient{
		addMemberErr: errors.New("group full"),
	}

	buf := new(bytes.Buffer)
	cfg := newTestCustodianConfig(mock)
	printer := NewPrinter("text", buf)

	custodianAddMember(cfg, printer, "grp-001", "user-003", "charlie", "encrypted")
	// Should not panic
}

// --- custodianRemoveMember ---

func TestCustodianRemoveMember_Success(t *testing.T) {
	mock := &mockCustodianClient{}

	buf := new(bytes.Buffer)
	cfg := newTestCustodianConfig(mock)
	printer := NewPrinter("text", buf)

	custodianRemoveMember(cfg, printer, "grp-001", "user-003")

	output := buf.String()
	if !strings.Contains(output, "user-003") {
		t.Error("output should contain removed user ID")
	}
	if !strings.Contains(output, "grp-001") {
		t.Error("output should contain group ID")
	}
	if !strings.Contains(output, "removed") {
		t.Errorf("output should contain 'removed', got: %s", output)
	}
}

func TestCustodianRemoveMember_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockCustodianClient{
		removeMemberErr: errors.New("member not found"),
	}

	buf := new(bytes.Buffer)
	cfg := newTestCustodianConfig(mock)
	printer := NewPrinter("text", buf)

	custodianRemoveMember(cfg, printer, "grp-001", "user-999")
	// Should not panic
}

// --- custodianDistribute ---

func TestCustodianDistribute_Success(t *testing.T) {
	mock := &mockCustodianClient{
		distributeResp: &transport.DistributeSharesResponse{
			Distributed: 5,
		},
	}

	buf := new(bytes.Buffer)
	cfg := newTestCustodianConfig(mock)
	printer := NewPrinter("text", buf)

	custodianDistribute(cfg, printer, "grp-001")

	output := buf.String()
	if !strings.Contains(output, "grp-001") {
		t.Error("output should contain group ID")
	}
	if !strings.Contains(output, "5 share(s)") {
		t.Error("output should contain distributed count")
	}
	if !strings.Contains(output, "successfully") {
		t.Error("output should contain success message")
	}
}

func TestCustodianDistribute_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockCustodianClient{
		distributeErr: errors.New("barrier sealed"),
	}

	buf := new(bytes.Buffer)
	cfg := newTestCustodianConfig(mock)
	printer := NewPrinter("text", buf)

	custodianDistribute(cfg, printer, "grp-001")
	// Should not panic
}

// --- printCustodianGroup ---

func TestPrintCustodianGroup_JSON(t *testing.T) {
	group := testFixtureGroup()
	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	printCustodianGroup(printer, &group)

	output := buf.String()
	if !strings.Contains(output, `"id"`) {
		t.Error("JSON output should contain 'id' field")
	}
	if !strings.Contains(output, `"grp-001"`) {
		t.Error("JSON output should contain group ID value")
	}
	if !strings.Contains(output, `"name"`) {
		t.Error("JSON output should contain 'name' field")
	}
	if !strings.Contains(output, `"Ops Team"`) {
		t.Error("JSON output should contain group name value")
	}
	if !strings.Contains(output, `"threshold"`) {
		t.Error("JSON output should contain 'threshold' field")
	}
}

func TestPrintCustodianGroup_Text(t *testing.T) {
	group := testFixtureGroup()
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	printCustodianGroup(printer, &group)

	output := buf.String()
	if !strings.Contains(output, "Custodian Group Created:") {
		t.Error("text output should contain header")
	}
	if !strings.Contains(output, "grp-001") {
		t.Error("text output should contain ID")
	}
	if !strings.Contains(output, "Ops Team") {
		t.Error("text output should contain name")
	}
	if !strings.Contains(output, "3 of 5") {
		t.Error("text output should contain threshold")
	}
	if !strings.Contains(output, "tenant-acme") {
		t.Error("text output should contain tenant ID when present")
	}
}

func TestPrintCustodianGroup_TextNoTenant(t *testing.T) {
	group := testFixtureGroup()
	group.TenantID = ""
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	printCustodianGroup(printer, &group)

	output := buf.String()
	if strings.Contains(output, "Tenant:") {
		t.Error("text output should not contain Tenant line when TenantID is empty")
	}
}

// --- printCustodianGroupList ---

func TestPrintCustodianGroupList_JSON(t *testing.T) {
	groups := []transport.CustodianGroupInfo{testFixtureGroup()}
	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	printCustodianGroupList(printer, groups)

	output := buf.String()
	if !strings.Contains(output, `"groups"`) {
		t.Error("JSON output should contain 'groups' field")
	}
	if !strings.Contains(output, `"total"`) {
		t.Error("JSON output should contain 'total' field")
	}
	if !strings.Contains(output, `"Ops Team"`) {
		t.Error("JSON output should contain group name")
	}
}

func TestPrintCustodianGroupList_Table(t *testing.T) {
	groups := []transport.CustodianGroupInfo{
		testFixtureGroup(),
		{
			ID:        "grp-002",
			Name:      "DR Group",
			Threshold: 2,
			Total:     3,
			CreatedAt: testFixtureTime(),
		},
	}
	buf := new(bytes.Buffer)
	printer := NewPrinter("table", buf)

	printCustodianGroupList(printer, groups)

	output := buf.String()
	if !strings.Contains(output, "ID") {
		t.Error("table output should contain header row")
	}
	if !strings.Contains(output, "NAME") {
		t.Error("table output should contain NAME header")
	}
	if !strings.Contains(output, "Ops Team") {
		t.Error("table output should contain first group name")
	}
	if !strings.Contains(output, "DR Group") {
		t.Error("table output should contain second group name")
	}
	if !strings.Contains(output, "Total: 2 group(s)") {
		t.Error("table output should contain total count")
	}
}

func TestPrintCustodianGroupList_TableEmpty(t *testing.T) {
	buf := new(bytes.Buffer)
	printer := NewPrinter("table", buf)

	printCustodianGroupList(printer, []transport.CustodianGroupInfo{})

	output := buf.String()
	if !strings.Contains(output, "No custodian groups found") {
		t.Error("empty table output should show 'No custodian groups found'")
	}
}

func TestPrintCustodianGroupList_TextEmpty(t *testing.T) {
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	printCustodianGroupList(printer, []transport.CustodianGroupInfo{})

	output := buf.String()
	if !strings.Contains(output, "No custodian groups found") {
		t.Error("empty text output should show 'No custodian groups found'")
	}
}

func TestPrintCustodianGroupList_Text(t *testing.T) {
	groups := []transport.CustodianGroupInfo{testFixtureGroup()}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	printCustodianGroupList(printer, groups)

	output := buf.String()
	if !strings.Contains(output, "Custodian Groups:") {
		t.Error("text output should contain header")
	}
	if !strings.Contains(output, "Ops Team") {
		t.Error("text output should contain group name")
	}
	if !strings.Contains(output, "grp-001") {
		t.Error("text output should contain group ID")
	}
}

// --- printCustodianGroupDetail ---

func TestPrintCustodianGroupDetail_JSON(t *testing.T) {
	group := testFixtureGroup()
	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	printCustodianGroupDetail(printer, &group)

	output := buf.String()
	if !strings.Contains(output, `"id"`) {
		t.Error("JSON output should contain 'id' field")
	}
	if !strings.Contains(output, `"members"`) {
		t.Error("JSON output should contain 'members' field")
	}
	if !strings.Contains(output, `"alice"`) {
		t.Error("JSON output should contain member username")
	}
}

func TestPrintCustodianGroupDetail_Text(t *testing.T) {
	group := testFixtureGroup()
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	printCustodianGroupDetail(printer, &group)

	output := buf.String()
	if !strings.Contains(output, "Custodian Group Details:") {
		t.Error("text output should contain header")
	}
	if !strings.Contains(output, "grp-001") {
		t.Error("text output should contain ID")
	}
	if !strings.Contains(output, "tenant-acme") {
		t.Error("text output should contain tenant ID")
	}
	if !strings.Contains(output, "Members (2):") {
		t.Error("text output should show member count")
	}
	if !strings.Contains(output, "alice (user-001)") {
		t.Error("text output should contain member label with username and user ID")
	}
	if !strings.Contains(output, "bob (user-002)") {
		t.Error("text output should contain second member label")
	}
	if !strings.Contains(output, "Share Index: 1") {
		t.Error("text output should contain share index")
	}
	if !strings.Contains(output, "Method:      encrypted") {
		t.Error("text output should contain method")
	}
}

func TestPrintCustodianGroupDetail_TextNoMembers(t *testing.T) {
	group := transport.CustodianGroupInfo{
		ID:        "grp-empty",
		Name:      "Empty Group",
		Threshold: 2,
		Total:     3,
		CreatedAt: testFixtureTime(),
		UpdatedAt: testFixtureTime(),
	}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	printCustodianGroupDetail(printer, &group)

	output := buf.String()
	if !strings.Contains(output, "Members: none") {
		t.Error("text output should show 'Members: none' when no members")
	}
}

func TestPrintCustodianGroupDetail_TextNoTenant(t *testing.T) {
	group := testFixtureGroup()
	group.TenantID = ""
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	printCustodianGroupDetail(printer, &group)

	output := buf.String()
	if strings.Contains(output, "Tenant:") {
		t.Error("text output should not contain Tenant line when empty")
	}
}

func TestPrintCustodianGroupDetail_TextMemberWithReceivedAt(t *testing.T) {
	received := testFixtureTime().Add(time.Hour)
	group := transport.CustodianGroupInfo{
		ID:        "grp-received",
		Name:      "Received Group",
		Threshold: 1,
		Total:     1,
		Members: []transport.CustodianMemberInfo{
			{
				ShareIndex: 1,
				UserID:     "user-100",
				Username:   "dave",
				AssignedAt: testFixtureTime(),
				ReceivedAt: &received,
				Method:     "manual",
			},
		},
		CreatedAt: testFixtureTime(),
		UpdatedAt: testFixtureTime(),
	}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	printCustodianGroupDetail(printer, &group)

	output := buf.String()
	if !strings.Contains(output, "Received:") {
		t.Error("text output should contain 'Received:' when ReceivedAt is set")
	}
}

func TestPrintCustodianGroupDetail_TextMemberWithoutUsername(t *testing.T) {
	group := transport.CustodianGroupInfo{
		ID:        "grp-noname",
		Name:      "No Username Group",
		Threshold: 1,
		Total:     1,
		Members: []transport.CustodianMemberInfo{
			{
				ShareIndex: 1,
				UserID:     "user-anon",
				Username:   "",
				AssignedAt: testFixtureTime(),
				Method:     "encrypted",
			},
		},
		CreatedAt: testFixtureTime(),
		UpdatedAt: testFixtureTime(),
	}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	printCustodianGroupDetail(printer, &group)

	output := buf.String()
	// When username is empty, label is just the UserID
	if !strings.Contains(output, "1. user-anon") {
		t.Errorf("text output should use UserID as label when username is empty, got: %s", output)
	}
}

// --- printCustodianMember ---

func TestPrintCustodianMember_JSON(t *testing.T) {
	member := &transport.CustodianMemberInfo{
		ShareIndex: 1,
		UserID:     "user-001",
		Username:   "alice",
		AssignedAt: testFixtureTime(),
		Method:     "encrypted",
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	printCustodianMember(printer, member)

	output := buf.String()
	if !strings.Contains(output, `"user_id"`) {
		t.Error("JSON output should contain 'user_id' field")
	}
	if !strings.Contains(output, `"alice"`) {
		t.Error("JSON output should contain username")
	}
	if !strings.Contains(output, `"share_index"`) {
		t.Error("JSON output should contain 'share_index' field")
	}
}

func TestPrintCustodianMember_Text(t *testing.T) {
	member := &transport.CustodianMemberInfo{
		ShareIndex: 3,
		UserID:     "user-003",
		Username:   "charlie",
		AssignedAt: testFixtureTime(),
		Method:     "encrypted",
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	printCustodianMember(printer, member)

	output := buf.String()
	if !strings.Contains(output, "Member Added:") {
		t.Error("text output should contain header")
	}
	if !strings.Contains(output, "user-003") {
		t.Error("text output should contain user ID")
	}
	if !strings.Contains(output, "charlie") {
		t.Error("text output should contain username")
	}
	if !strings.Contains(output, "Share Index: 3") {
		t.Error("text output should contain share index")
	}
	if !strings.Contains(output, "encrypted") {
		t.Error("text output should contain method")
	}
}

func TestPrintCustodianMember_TextNoUsername(t *testing.T) {
	member := &transport.CustodianMemberInfo{
		ShareIndex: 1,
		UserID:     "user-anon",
		AssignedAt: testFixtureTime(),
		Method:     "manual",
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	printCustodianMember(printer, member)

	output := buf.String()
	if strings.Contains(output, "Username:") {
		t.Error("text output should not contain Username line when empty")
	}
}

// --- printDistributeResult ---

func TestPrintDistributeResult_JSON(t *testing.T) {
	resp := &transport.DistributeSharesResponse{
		Distributed: 5,
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	printDistributeResult(printer, "grp-001", resp)

	output := buf.String()
	if !strings.Contains(output, `"group_id"`) {
		t.Error("JSON output should contain 'group_id' field")
	}
	if !strings.Contains(output, `"grp-001"`) {
		t.Error("JSON output should contain group ID value")
	}
	if !strings.Contains(output, `"distributed"`) {
		t.Error("JSON output should contain 'distributed' field")
	}
	if !strings.Contains(output, "5") {
		t.Error("JSON output should contain distributed count")
	}
}

func TestPrintDistributeResult_Text(t *testing.T) {
	resp := &transport.DistributeSharesResponse{
		Distributed: 3,
	}

	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	printDistributeResult(printer, "grp-002", resp)

	output := buf.String()
	if !strings.Contains(output, "Shares distributed successfully") {
		t.Error("text output should contain success message")
	}
	if !strings.Contains(output, "grp-002") {
		t.Error("text output should contain group ID")
	}
	if !strings.Contains(output, "3 share(s)") {
		t.Error("text output should contain distributed count")
	}
}

// --- All-formats tests for output consistency ---

func TestCustodianCreate_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			group := testFixtureGroup()
			mock := &mockCustodianClient{
				createGroupResp: &transport.CreateCustodianGroupResponse{
					Group: group,
				},
			}

			buf := new(bytes.Buffer)
			cfg := newTestCustodianConfig(mock)
			printer := NewPrinter(format, buf)

			custodianCreate(cfg, printer, "grp-001", "", "Ops Team", "purpose", 3, 5)

			if buf.Len() == 0 {
				t.Errorf("custodianCreate with %s format should produce output", format)
			}
		})
	}
}

func TestCustodianList_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mock := &mockCustodianClient{
				listGroupsResp: &transport.ListCustodianGroupsResponse{
					Groups: []transport.CustodianGroupInfo{testFixtureGroup()},
				},
			}

			buf := new(bytes.Buffer)
			cfg := newTestCustodianConfig(mock)
			printer := NewPrinter(format, buf)

			custodianList(cfg, printer)

			if buf.Len() == 0 {
				t.Errorf("custodianList with %s format should produce output", format)
			}
		})
	}
}

func TestCustodianShow_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mock := &mockCustodianClient{
				getGroupResp: &transport.GetCustodianGroupResponse{
					Group: testFixtureGroup(),
				},
			}

			buf := new(bytes.Buffer)
			cfg := newTestCustodianConfig(mock)
			printer := NewPrinter(format, buf)

			custodianShow(cfg, printer, "grp-001")

			if buf.Len() == 0 {
				t.Errorf("custodianShow with %s format should produce output", format)
			}
		})
	}
}

func TestCustodianDelete_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mock := &mockCustodianClient{}

			buf := new(bytes.Buffer)
			cfg := newTestCustodianConfig(mock)
			printer := NewPrinter(format, buf)

			custodianDelete(cfg, printer, "grp-001")

			if buf.Len() == 0 {
				t.Errorf("custodianDelete with %s format should produce output", format)
			}
		})
	}
}

func TestCustodianDistribute_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			mock := &mockCustodianClient{
				distributeResp: &transport.DistributeSharesResponse{
					Distributed: 5,
				},
			}

			buf := new(bytes.Buffer)
			cfg := newTestCustodianConfig(mock)
			printer := NewPrinter(format, buf)

			custodianDistribute(cfg, printer, "grp-001")

			if buf.Len() == 0 {
				t.Errorf("custodianDistribute with %s format should produce output", format)
			}
		})
	}
}

// --- Client lifecycle tests ---

func TestCustodianCreate_ClosesClient(t *testing.T) {
	mock := &mockCustodianClient{
		createGroupResp: &transport.CreateCustodianGroupResponse{
			Group: testFixtureGroup(),
		},
	}

	buf := new(bytes.Buffer)
	cfg := newTestCustodianConfig(mock)
	printer := NewPrinter("text", buf)

	custodianCreate(cfg, printer, "grp-001", "", "name", "purpose", 3, 5)

	if !mock.closeCalled {
		t.Error("custodianCreate should call client.Close() via cleanup")
	}
}

func TestCustodianList_ClosesClient(t *testing.T) {
	mock := &mockCustodianClient{
		listGroupsResp: &transport.ListCustodianGroupsResponse{
			Groups: []transport.CustodianGroupInfo{},
		},
	}

	buf := new(bytes.Buffer)
	cfg := newTestCustodianConfig(mock)
	printer := NewPrinter("text", buf)

	custodianList(cfg, printer)

	if !mock.closeCalled {
		t.Error("custodianList should call client.Close() via cleanup")
	}
}
