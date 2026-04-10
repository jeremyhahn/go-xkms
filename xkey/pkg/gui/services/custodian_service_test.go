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

package services

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
)

// mockCustodianClient implements the CustodianGroupService methods
// and embeds transport.Client to satisfy the full interface.
type mockCustodianClient struct {
	transport.Client // embed to satisfy interface; unused methods will panic
	groups           map[string]*transport.CustodianGroupInfo
	members          map[string][]transport.CustodianMemberInfo
	err              error
}

func newMockCustodianClient() *mockCustodianClient {
	return &mockCustodianClient{
		groups:  make(map[string]*transport.CustodianGroupInfo),
		members: make(map[string][]transport.CustodianMemberInfo),
	}
}

func (m *mockCustodianClient) CreateCustodianGroup(_ context.Context, req *transport.CreateCustodianGroupRequest) (*transport.CreateCustodianGroupResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	now := time.Now()
	group := transport.CustodianGroupInfo{
		ID:        "group-" + req.Name,
		Name:      req.Name,
		Purpose:   req.Purpose,
		Threshold: req.Threshold,
		Total:     req.Total,
		CreatedAt: now,
		UpdatedAt: now,
	}
	m.groups[group.ID] = &group
	return &transport.CreateCustodianGroupResponse{Group: group}, nil
}

func (m *mockCustodianClient) GetCustodianGroup(_ context.Context, groupID string) (*transport.GetCustodianGroupResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	g, ok := m.groups[groupID]
	if !ok {
		return nil, errors.New("group not found")
	}
	return &transport.GetCustodianGroupResponse{Group: *g}, nil
}

func (m *mockCustodianClient) ListCustodianGroups(_ context.Context) (*transport.ListCustodianGroupsResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	groups := make([]transport.CustodianGroupInfo, 0, len(m.groups))
	for _, g := range m.groups {
		groups = append(groups, *g)
	}
	return &transport.ListCustodianGroupsResponse{Groups: groups}, nil
}

func (m *mockCustodianClient) DeleteCustodianGroup(_ context.Context, groupID string) error {
	if m.err != nil {
		return m.err
	}
	if _, ok := m.groups[groupID]; !ok {
		return errors.New("group not found")
	}
	delete(m.groups, groupID)
	return nil
}

func (m *mockCustodianClient) AddCustodianMember(_ context.Context, req *transport.AddCustodianMemberRequest) (*transport.AddCustodianMemberResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	member := transport.CustodianMemberInfo{
		ShareIndex: len(m.members[req.GroupID]) + 1,
		UserID:     req.UserID,
		Username:   req.Username,
		AssignedAt: time.Now(),
		Method:     req.Method,
	}
	m.members[req.GroupID] = append(m.members[req.GroupID], member)
	return &transport.AddCustodianMemberResponse{Member: member}, nil
}

func (m *mockCustodianClient) RemoveCustodianMember(_ context.Context, req *transport.RemoveCustodianMemberRequest) error {
	if m.err != nil {
		return m.err
	}
	members := m.members[req.GroupID]
	for i, mem := range members {
		if mem.UserID == req.UserID {
			m.members[req.GroupID] = append(members[:i], members[i+1:]...)
			return nil
		}
	}
	return errors.New("member not found")
}

func (m *mockCustodianClient) DistributeShares(_ context.Context, req *transport.DistributeSharesRequest) (*transport.DistributeSharesResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	count := len(m.members[req.GroupID])
	return &transport.DistributeSharesResponse{Distributed: count}, nil
}

func setupCustodianService(t *testing.T) (*CustodianService, *mockCustodianClient) {
	t.Helper()
	svc := NewCustodianService()
	svc.SetContext(context.Background())

	mock := newMockCustodianClient()
	var client transport.Client = mock
	svc.SetClient(client)

	return svc, mock
}

// --- Constructor and lifecycle ---

func TestNewCustodianService(t *testing.T) {
	svc := NewCustodianService()
	require.NotNil(t, svc)
	assert.NotNil(t, svc.log)
}

func TestCustodianService_NoClient(t *testing.T) {
	svc := NewCustodianService()
	svc.SetContext(context.Background())

	_, err := svc.ListGroups()
	require.ErrorIs(t, err, ErrCustodianServiceNoClient)
}

// --- CreateGroup ---

func TestCustodianService_CreateGroup_Success(t *testing.T) {
	svc, _ := setupCustodianService(t)

	info, err := svc.CreateGroup("Admins", "barrier-unseal", 3, 5)
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, "Admins", info.Name)
	assert.Equal(t, "barrier-unseal", info.Purpose)
	assert.Equal(t, 3, info.Threshold)
	assert.Equal(t, 5, info.Total)
	assert.NotEmpty(t, info.CreatedAt)
}

func TestCustodianService_CreateGroup_EmptyName(t *testing.T) {
	svc, _ := setupCustodianService(t)

	_, err := svc.CreateGroup("", "barrier-unseal", 3, 5)
	require.ErrorIs(t, err, ErrCustodianGroupNameRequired)
}

func TestCustodianService_CreateGroup_InvalidThreshold(t *testing.T) {
	svc, _ := setupCustodianService(t)

	_, err := svc.CreateGroup("Admins", "barrier-unseal", 0, 5)
	require.ErrorIs(t, err, ErrCustodianInvalidThreshold)
}

func TestCustodianService_CreateGroup_InvalidTotal(t *testing.T) {
	svc, _ := setupCustodianService(t)

	_, err := svc.CreateGroup("Admins", "barrier-unseal", 5, 3)
	require.ErrorIs(t, err, ErrCustodianInvalidTotal)
}

func TestCustodianService_CreateGroup_ServerError(t *testing.T) {
	svc, mock := setupCustodianService(t)
	mock.err = errors.New("server unavailable")

	_, err := svc.CreateGroup("Admins", "barrier-unseal", 3, 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server unavailable")
}

func TestCustodianService_CreateGroup_NoClient(t *testing.T) {
	svc := NewCustodianService()
	svc.SetContext(context.Background())

	_, err := svc.CreateGroup("Admins", "barrier-unseal", 3, 5)
	require.ErrorIs(t, err, ErrCustodianServiceNoClient)
}

// --- GetGroup ---

func TestCustodianService_GetGroup_Success(t *testing.T) {
	svc, _ := setupCustodianService(t)

	created, err := svc.CreateGroup("Ops", "backup", 2, 3)
	require.NoError(t, err)

	info, err := svc.GetGroup(created.ID)
	require.NoError(t, err)
	assert.Equal(t, "Ops", info.Name)
}

func TestCustodianService_GetGroup_EmptyID(t *testing.T) {
	svc, _ := setupCustodianService(t)

	_, err := svc.GetGroup("")
	require.ErrorIs(t, err, ErrCustodianGroupIDRequired)
}

func TestCustodianService_GetGroup_NotFound(t *testing.T) {
	svc, _ := setupCustodianService(t)

	_, err := svc.GetGroup("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// --- ListGroups ---

func TestCustodianService_ListGroups_Empty(t *testing.T) {
	svc, _ := setupCustodianService(t)

	groups, err := svc.ListGroups()
	require.NoError(t, err)
	assert.Empty(t, groups)
}

func TestCustodianService_ListGroups_WithData(t *testing.T) {
	svc, _ := setupCustodianService(t)

	_, err := svc.CreateGroup("Group1", "unseal", 2, 3)
	require.NoError(t, err)
	_, err = svc.CreateGroup("Group2", "backup", 3, 5)
	require.NoError(t, err)

	groups, err := svc.ListGroups()
	require.NoError(t, err)
	assert.Len(t, groups, 2)
}

func TestCustodianService_ListGroups_ServerError(t *testing.T) {
	svc, mock := setupCustodianService(t)
	mock.err = errors.New("timeout")

	_, err := svc.ListGroups()
	require.Error(t, err)
}

// --- DeleteGroup ---

func TestCustodianService_DeleteGroup_Success(t *testing.T) {
	svc, _ := setupCustodianService(t)

	created, err := svc.CreateGroup("ToDelete", "temp", 1, 1)
	require.NoError(t, err)

	err = svc.DeleteGroup(created.ID)
	require.NoError(t, err)

	groups, err := svc.ListGroups()
	require.NoError(t, err)
	assert.Empty(t, groups)
}

func TestCustodianService_DeleteGroup_EmptyID(t *testing.T) {
	svc, _ := setupCustodianService(t)

	err := svc.DeleteGroup("")
	require.ErrorIs(t, err, ErrCustodianGroupIDRequired)
}

func TestCustodianService_DeleteGroup_NotFound(t *testing.T) {
	svc, _ := setupCustodianService(t)

	err := svc.DeleteGroup("nonexistent")
	require.Error(t, err)
}

// --- AddMember ---

func TestCustodianService_AddMember_Success(t *testing.T) {
	svc, _ := setupCustodianService(t)

	created, err := svc.CreateGroup("WithMembers", "unseal", 2, 3)
	require.NoError(t, err)

	member, err := svc.AddMember(created.ID, "user-1", "alice", "manual")
	require.NoError(t, err)
	require.NotNil(t, member)
	assert.Equal(t, "user-1", member.UserID)
	assert.Equal(t, "alice", member.Username)
	assert.Equal(t, "manual", member.Method)
	assert.NotEmpty(t, member.AssignedAt)
}

func TestCustodianService_AddMember_EmptyGroupID(t *testing.T) {
	svc, _ := setupCustodianService(t)

	_, err := svc.AddMember("", "user-1", "alice", "manual")
	require.ErrorIs(t, err, ErrCustodianGroupIDRequired)
}

func TestCustodianService_AddMember_EmptyUserID(t *testing.T) {
	svc, _ := setupCustodianService(t)

	_, err := svc.AddMember("group-1", "", "alice", "manual")
	require.ErrorIs(t, err, ErrCustodianUserIDRequired)
}

func TestCustodianService_AddMember_ServerError(t *testing.T) {
	svc, mock := setupCustodianService(t)
	mock.err = errors.New("permission denied")

	_, err := svc.AddMember("group-1", "user-1", "alice", "manual")
	require.Error(t, err)
}

// --- RemoveMember ---

func TestCustodianService_RemoveMember_Success(t *testing.T) {
	svc, _ := setupCustodianService(t)

	created, err := svc.CreateGroup("RemoveTest", "unseal", 2, 3)
	require.NoError(t, err)

	_, err = svc.AddMember(created.ID, "user-1", "alice", "manual")
	require.NoError(t, err)

	err = svc.RemoveMember(created.ID, "user-1")
	require.NoError(t, err)
}

func TestCustodianService_RemoveMember_EmptyGroupID(t *testing.T) {
	svc, _ := setupCustodianService(t)

	err := svc.RemoveMember("", "user-1")
	require.ErrorIs(t, err, ErrCustodianGroupIDRequired)
}

func TestCustodianService_RemoveMember_EmptyUserID(t *testing.T) {
	svc, _ := setupCustodianService(t)

	err := svc.RemoveMember("group-1", "")
	require.ErrorIs(t, err, ErrCustodianUserIDRequired)
}

func TestCustodianService_RemoveMember_NotFound(t *testing.T) {
	svc, _ := setupCustodianService(t)

	err := svc.RemoveMember("group-1", "nonexistent")
	require.Error(t, err)
}

// --- DistributeShares ---

func TestCustodianService_DistributeShares_Success(t *testing.T) {
	svc, _ := setupCustodianService(t)

	created, err := svc.CreateGroup("DistTest", "unseal", 2, 3)
	require.NoError(t, err)

	_, err = svc.AddMember(created.ID, "user-1", "alice", "manual")
	require.NoError(t, err)
	_, err = svc.AddMember(created.ID, "user-2", "bob", "manual")
	require.NoError(t, err)

	distributed, err := svc.DistributeShares(created.ID)
	require.NoError(t, err)
	assert.Equal(t, 2, distributed)
}

func TestCustodianService_DistributeShares_EmptyGroupID(t *testing.T) {
	svc, _ := setupCustodianService(t)

	_, err := svc.DistributeShares("")
	require.ErrorIs(t, err, ErrCustodianGroupIDRequired)
}

func TestCustodianService_DistributeShares_ServerError(t *testing.T) {
	svc, mock := setupCustodianService(t)
	mock.err = errors.New("not enough members")

	_, err := svc.DistributeShares("group-1")
	require.Error(t, err)
}

// --- Event emission ---

func TestCustodianService_EventEmission(t *testing.T) {
	svc, _ := setupCustodianService(t)

	var mu sync.Mutex
	var captured []events.Event
	svc.SetEventEmitter(func(e events.Event) {
		mu.Lock()
		defer mu.Unlock()
		captured = append(captured, e)
	})

	// Create triggers event.
	_, err := svc.CreateGroup("EventTest", "unseal", 2, 3)
	require.NoError(t, err)

	mu.Lock()
	require.Len(t, captured, 1)
	assert.Equal(t, events.EventCustodianGroupCreated, captured[0].Type)
	mu.Unlock()
}

func TestCustodianService_DeleteGroup_EventEmission(t *testing.T) {
	svc, _ := setupCustodianService(t)

	var mu sync.Mutex
	var captured []events.Event
	svc.SetEventEmitter(func(e events.Event) {
		mu.Lock()
		defer mu.Unlock()
		captured = append(captured, e)
	})

	created, err := svc.CreateGroup("DelEvent", "unseal", 1, 1)
	require.NoError(t, err)

	err = svc.DeleteGroup(created.ID)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, captured, 2) // create + delete
	assert.Equal(t, events.EventCustodianGroupDeleted, captured[1].Type)
}

// --- Conversion helpers ---

func TestTransportGroupToInfo(t *testing.T) {
	now := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
	received := time.Date(2025, 7, 2, 12, 0, 0, 0, time.UTC)

	group := &transport.CustodianGroupInfo{
		ID:        "group-42",
		TenantID:  "tenant-a",
		Name:      "Admins",
		Purpose:   "barrier-unseal",
		Threshold: 3,
		Total:     5,
		Members: []transport.CustodianMemberInfo{
			{
				ShareIndex: 1,
				UserID:     "user-1",
				Username:   "alice",
				AssignedAt: now,
				ReceivedAt: &received,
				Method:     "manual",
			},
			{
				ShareIndex: 2,
				UserID:     "user-2",
				Username:   "bob",
				AssignedAt: now,
				Method:     "push",
			},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	info := transportGroupToInfo(group)
	assert.Equal(t, "group-42", info.ID)
	assert.Equal(t, "tenant-a", info.TenantID)
	assert.Equal(t, "Admins", info.Name)
	assert.Equal(t, "barrier-unseal", info.Purpose)
	assert.Equal(t, 3, info.Threshold)
	assert.Equal(t, 5, info.Total)
	assert.Equal(t, "2025-07-01T12:00:00Z", info.CreatedAt)
	assert.Equal(t, "2025-07-01T12:00:00Z", info.UpdatedAt)
	require.Len(t, info.Members, 2)

	assert.Equal(t, "user-1", info.Members[0].UserID)
	assert.Equal(t, "alice", info.Members[0].Username)
	assert.Equal(t, "2025-07-02T12:00:00Z", info.Members[0].ReceivedAt)

	assert.Equal(t, "user-2", info.Members[1].UserID)
	assert.Equal(t, "", info.Members[1].ReceivedAt)
}

func TestTransportMemberToInfo(t *testing.T) {
	now := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
	member := &transport.CustodianMemberInfo{
		ShareIndex: 3,
		UserID:     "user-3",
		Username:   "charlie",
		AssignedAt: now,
		Method:     "api",
	}

	info := transportMemberToInfo(member)
	assert.Equal(t, 3, info.ShareIndex)
	assert.Equal(t, "user-3", info.UserID)
	assert.Equal(t, "charlie", info.Username)
	assert.Equal(t, "2025-07-01T12:00:00Z", info.AssignedAt)
	assert.Equal(t, "api", info.Method)
	assert.Empty(t, info.ReceivedAt)
}
