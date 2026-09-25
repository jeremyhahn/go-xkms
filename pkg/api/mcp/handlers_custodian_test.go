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

// handlers_custodian_test.go covers the MCP custodian group methods:
// dispatch registration, the not-configured path taken when no go-qrdb
// custodian client is composed, and the success path against a fake
// CustodianGroupClient.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// fakeCustodianClient is an in-memory qrdbtransport.CustodianGroupClient for
// exercising the custodian handlers' success and error paths without a real
// go-qrdb node.
type fakeCustodianClient struct {
	groups map[string]*qrdbtransport.CustodianGroupInfo
	err    error
}

func newFakeCustodianClient() *fakeCustodianClient {
	return &fakeCustodianClient{groups: make(map[string]*qrdbtransport.CustodianGroupInfo)}
}

func (f *fakeCustodianClient) CreateCustodianGroup(_ context.Context, req *qrdbtransport.CreateCustodianGroupRequest) (*qrdbtransport.CreateCustodianGroupResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	g := &qrdbtransport.CustodianGroupInfo{
		ID: req.ID, TenantID: req.TenantID, Name: req.Name, Purpose: req.Purpose,
		Threshold: req.Threshold, Total: req.Total,
	}
	f.groups[req.ID] = g
	return &qrdbtransport.CreateCustodianGroupResponse{Group: *g}, nil
}

func (f *fakeCustodianClient) GetCustodianGroup(_ context.Context, groupID string) (*qrdbtransport.GetCustodianGroupResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	g, ok := f.groups[groupID]
	if !ok {
		return nil, qrdbsdk.ErrCeremonyGroupNotFound
	}
	return &qrdbtransport.GetCustodianGroupResponse{Group: *g}, nil
}

func (f *fakeCustodianClient) ListCustodianGroups(_ context.Context) (*qrdbtransport.ListCustodianGroupsResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	groups := make([]qrdbtransport.CustodianGroupInfo, 0, len(f.groups))
	for _, g := range f.groups {
		groups = append(groups, *g)
	}
	return &qrdbtransport.ListCustodianGroupsResponse{Groups: groups}, nil
}

func (f *fakeCustodianClient) DeleteCustodianGroup(_ context.Context, groupID string) error {
	if f.err != nil {
		return f.err
	}
	if _, ok := f.groups[groupID]; !ok {
		return qrdbsdk.ErrCeremonyGroupNotFound
	}
	delete(f.groups, groupID)
	return nil
}

func (f *fakeCustodianClient) AddCustodianMember(_ context.Context, req *qrdbtransport.AddCustodianMemberRequest) (*qrdbtransport.AddCustodianMemberResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	g, ok := f.groups[req.GroupID]
	if !ok {
		return nil, qrdbsdk.ErrCeremonyGroupNotFound
	}
	m := qrdbtransport.CustodianMemberInfo{UserID: req.UserID, Username: req.Username, Method: req.Method}
	g.Members = append(g.Members, m)
	return &qrdbtransport.AddCustodianMemberResponse{Member: m}, nil
}

func (f *fakeCustodianClient) RemoveCustodianMember(_ context.Context, req *qrdbtransport.RemoveCustodianMemberRequest) error {
	if f.err != nil {
		return f.err
	}
	if _, ok := f.groups[req.GroupID]; !ok {
		return qrdbsdk.ErrCeremonyGroupNotFound
	}
	return nil
}

func (f *fakeCustodianClient) DistributeShares(_ context.Context, req *qrdbtransport.DistributeSharesRequest) (*qrdbtransport.DistributeSharesResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	g, ok := f.groups[req.GroupID]
	if !ok {
		return nil, qrdbsdk.ErrCeremonyGroupNotFound
	}
	return &qrdbtransport.DistributeSharesResponse{Distributed: len(g.Members)}, nil
}

// newCustodianServer returns an MCP server backed by the standard test XKMS
// service, optionally composed with a custodian group client.
func newCustodianServer(t *testing.T, client qrdbtransport.CustodianGroupClient) *Server {
	t.Helper()

	svc := setupTestXKMS(t)
	t.Cleanup(cleanupXKMS)
	if client != nil {
		svc.SetCustodianClient(client)
	}

	server, err := NewServer(&Config{
		XKMSService:   svc,
		Authenticator: auth.NewNoOpAuthenticator(),
	})
	require.NoError(t, err)
	return server
}

func custodianRequest(t *testing.T, method string, params interface{}) *JSONRPCRequest {
	t.Helper()

	raw, err := json.Marshal(params)
	require.NoError(t, err)

	return &JSONRPCRequest{JSONRPC: "2.0", Method: method, Params: raw, ID: 1}
}

// TestCustodianMethods_Dispatchable proves every custodian method is
// reachable through the dispatch table and carries a permission mapping.
func TestCustodianMethods_Dispatchable(t *testing.T) {
	for _, method := range []string{
		"xkms.createCustodianGroup", "xkms.getCustodianGroup", "xkms.listCustodianGroups",
		"xkms.deleteCustodianGroup", "xkms.addCustodianMember", "xkms.removeCustodianMember",
		"xkms.distributeShares",
	} {
		_, ok := rpcMethodHandlers[method]
		assert.True(t, ok, "method %q must be dispatchable", method)
		_, mapped := methodPermissions[method]
		assert.True(t, mapped, "method %q must carry a permission mapping", method)
	}
}

func TestHandleCreateCustodianGroup_Success(t *testing.T) {
	server := newCustodianServer(t, newFakeCustodianClient())

	result, err := server.handleCreateCustodianGroup(context.Background(),
		custodianRequest(t, "xkms.createCustodianGroup", transport.CreateCustodianGroupRequest{
			ID: "g1", Name: "ops", Threshold: 2, Total: 3,
		}))

	require.NoError(t, err)
	resp, ok := result.(*transport.CreateCustodianGroupResponse)
	require.True(t, ok, "result must be *transport.CreateCustodianGroupResponse, got %T", result)
	assert.Equal(t, "g1", resp.Group.ID)
	assert.Equal(t, 2, resp.Group.Threshold)
}

func TestHandleCreateCustodianGroup_NotConfigured(t *testing.T) {
	server := newCustodianServer(t, nil)

	_, err := server.handleCreateCustodianGroup(context.Background(),
		custodianRequest(t, "xkms.createCustodianGroup", transport.CreateCustodianGroupRequest{
			ID: "g1", Name: "ops", Threshold: 2, Total: 3,
		}))

	require.Error(t, err, "a service with no custodian client must report failure, not panic")
}

func TestHandleCreateCustodianGroup_InvalidParams(t *testing.T) {
	server := newCustodianServer(t, newFakeCustodianClient())

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.createCustodianGroup", Params: json.RawMessage(`{`), ID: 1}
	_, err := server.handleCreateCustodianGroup(context.Background(), req)

	require.Error(t, err)
	var keyOpErr *KeyOpError
	require.True(t, errors.As(err, &keyOpErr), "decode failure must be a *KeyOpError")
	assert.Equal(t, ErrCodeInvalidParams, keyOpErr.Code)
}

func TestHandleGetCustodianGroup_Success(t *testing.T) {
	client := newFakeCustodianClient()
	client.groups["g1"] = &qrdbtransport.CustodianGroupInfo{ID: "g1", Name: "ops", Threshold: 2, Total: 3}
	server := newCustodianServer(t, client)

	result, err := server.handleGetCustodianGroup(context.Background(),
		custodianRequest(t, "xkms.getCustodianGroup", CustodianGroupIDParams{GroupID: "g1"}))

	require.NoError(t, err)
	resp, ok := result.(*transport.GetCustodianGroupResponse)
	require.True(t, ok, "result must be *transport.GetCustodianGroupResponse, got %T", result)
	assert.Equal(t, "ops", resp.Group.Name)
}

func TestHandleGetCustodianGroup_NotFound(t *testing.T) {
	server := newCustodianServer(t, newFakeCustodianClient())

	_, err := server.handleGetCustodianGroup(context.Background(),
		custodianRequest(t, "xkms.getCustodianGroup", CustodianGroupIDParams{GroupID: "missing"}))

	require.Error(t, err)
	assert.True(t, errors.Is(err, qrdbsdk.ErrCeremonyGroupNotFound))
}

func TestHandleGetCustodianGroup_RequiresGroupID(t *testing.T) {
	server := newCustodianServer(t, newFakeCustodianClient())

	_, err := server.handleGetCustodianGroup(context.Background(),
		custodianRequest(t, "xkms.getCustodianGroup", CustodianGroupIDParams{}))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "group_id")
}

func TestHandleListCustodianGroups_Success(t *testing.T) {
	client := newFakeCustodianClient()
	client.groups["g1"] = &qrdbtransport.CustodianGroupInfo{ID: "g1"}
	client.groups["g2"] = &qrdbtransport.CustodianGroupInfo{ID: "g2"}
	server := newCustodianServer(t, client)

	result, err := server.handleListCustodianGroups(context.Background(),
		custodianRequest(t, "xkms.listCustodianGroups", struct{}{}))

	require.NoError(t, err)
	resp, ok := result.(*transport.ListCustodianGroupsResponse)
	require.True(t, ok, "result must be *transport.ListCustodianGroupsResponse, got %T", result)
	assert.Len(t, resp.Groups, 2)
}

func TestHandleListCustodianGroups_NotConfigured(t *testing.T) {
	server := newCustodianServer(t, nil)

	_, err := server.handleListCustodianGroups(context.Background(),
		custodianRequest(t, "xkms.listCustodianGroups", struct{}{}))

	require.Error(t, err)
}

func TestHandleDeleteCustodianGroup_Success(t *testing.T) {
	client := newFakeCustodianClient()
	client.groups["g1"] = &qrdbtransport.CustodianGroupInfo{ID: "g1"}
	server := newCustodianServer(t, client)

	result, err := server.handleDeleteCustodianGroup(context.Background(),
		custodianRequest(t, "xkms.deleteCustodianGroup", CustodianGroupIDParams{GroupID: "g1"}))

	require.NoError(t, err)
	assert.Equal(t, custodianSuccess, result)
	_, stillThere := client.groups["g1"]
	assert.False(t, stillThere)
}

func TestHandleDeleteCustodianGroup_NotFound(t *testing.T) {
	server := newCustodianServer(t, newFakeCustodianClient())

	_, err := server.handleDeleteCustodianGroup(context.Background(),
		custodianRequest(t, "xkms.deleteCustodianGroup", CustodianGroupIDParams{GroupID: "missing"}))

	require.Error(t, err)
	assert.True(t, errors.Is(err, qrdbsdk.ErrCeremonyGroupNotFound))
}

func TestHandleAddCustodianMember_Success(t *testing.T) {
	client := newFakeCustodianClient()
	client.groups["g1"] = &qrdbtransport.CustodianGroupInfo{ID: "g1"}
	server := newCustodianServer(t, client)

	result, err := server.handleAddCustodianMember(context.Background(),
		custodianRequest(t, "xkms.addCustodianMember", transport.AddCustodianMemberRequest{
			GroupID: "g1", UserID: "u1", Username: "alice",
		}))

	require.NoError(t, err)
	resp, ok := result.(*transport.AddCustodianMemberResponse)
	require.True(t, ok, "result must be *transport.AddCustodianMemberResponse, got %T", result)
	assert.Equal(t, "u1", resp.Member.UserID)
}

func TestHandleAddCustodianMember_GroupNotFound(t *testing.T) {
	server := newCustodianServer(t, newFakeCustodianClient())

	_, err := server.handleAddCustodianMember(context.Background(),
		custodianRequest(t, "xkms.addCustodianMember", transport.AddCustodianMemberRequest{
			GroupID: "missing", UserID: "u1",
		}))

	require.Error(t, err)
	assert.True(t, errors.Is(err, qrdbsdk.ErrCeremonyGroupNotFound))
}

func TestHandleRemoveCustodianMember_Success(t *testing.T) {
	client := newFakeCustodianClient()
	client.groups["g1"] = &qrdbtransport.CustodianGroupInfo{ID: "g1"}
	server := newCustodianServer(t, client)

	result, err := server.handleRemoveCustodianMember(context.Background(),
		custodianRequest(t, "xkms.removeCustodianMember", transport.RemoveCustodianMemberRequest{
			GroupID: "g1", UserID: "u1",
		}))

	require.NoError(t, err)
	assert.Equal(t, custodianSuccess, result)
}

func TestHandleRemoveCustodianMember_GroupNotFound(t *testing.T) {
	server := newCustodianServer(t, newFakeCustodianClient())

	_, err := server.handleRemoveCustodianMember(context.Background(),
		custodianRequest(t, "xkms.removeCustodianMember", transport.RemoveCustodianMemberRequest{
			GroupID: "missing", UserID: "u1",
		}))

	require.Error(t, err)
	assert.True(t, errors.Is(err, qrdbsdk.ErrCeremonyGroupNotFound))
}

func TestHandleDistributeShares_Success(t *testing.T) {
	client := newFakeCustodianClient()
	client.groups["g1"] = &qrdbtransport.CustodianGroupInfo{
		ID:      "g1",
		Members: []qrdbtransport.CustodianMemberInfo{{UserID: "u1"}, {UserID: "u2"}},
	}
	server := newCustodianServer(t, client)

	result, err := server.handleDistributeShares(context.Background(),
		custodianRequest(t, "xkms.distributeShares", transport.DistributeSharesRequest{GroupID: "g1"}))

	require.NoError(t, err)
	resp, ok := result.(*transport.DistributeSharesResponse)
	require.True(t, ok, "result must be *transport.DistributeSharesResponse, got %T", result)
	assert.Equal(t, 2, resp.Distributed)
}

func TestHandleDistributeShares_GroupNotFound(t *testing.T) {
	server := newCustodianServer(t, newFakeCustodianClient())

	_, err := server.handleDistributeShares(context.Background(),
		custodianRequest(t, "xkms.distributeShares", transport.DistributeSharesRequest{GroupID: "missing"}))

	require.Error(t, err)
	assert.True(t, errors.Is(err, qrdbsdk.ErrCeremonyGroupNotFound))
}
