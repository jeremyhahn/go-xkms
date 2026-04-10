package xkms

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/custodian"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockCustodianStore implements custodian.CustodianGroupStore for testing.
type mockCustodianStore struct {
	groups map[string]*custodian.CustodianGroup
}

func newMockCustodianStore() *mockCustodianStore {
	return &mockCustodianStore{groups: make(map[string]*custodian.CustodianGroup)}
}

func (m *mockCustodianStore) Create(_ context.Context, group *custodian.CustodianGroup) error {
	if _, exists := m.groups[group.ID]; exists {
		return errors.New("group already exists")
	}
	m.groups[group.ID] = group
	return nil
}

func (m *mockCustodianStore) Get(_ context.Context, id string) (*custodian.CustodianGroup, error) {
	g, ok := m.groups[id]
	if !ok {
		return nil, errors.New("group not found")
	}
	return g, nil
}

func (m *mockCustodianStore) Update(_ context.Context, group *custodian.CustodianGroup) error {
	if _, exists := m.groups[group.ID]; !exists {
		return errors.New("group not found")
	}
	m.groups[group.ID] = group
	return nil
}

func (m *mockCustodianStore) Delete(_ context.Context, id string) error {
	if _, exists := m.groups[id]; !exists {
		return errors.New("group not found")
	}
	delete(m.groups, id)
	return nil
}

func (m *mockCustodianStore) List(_ context.Context) ([]*custodian.CustodianGroup, error) {
	result := make([]*custodian.CustodianGroup, 0, len(m.groups))
	for _, g := range m.groups {
		result = append(result, g)
	}
	return result, nil
}

func (m *mockCustodianStore) ListByTenant(_ context.Context, _ string) ([]*custodian.CustodianGroup, error) {
	return nil, nil
}

func (m *mockCustodianStore) ListByPurpose(_ context.Context, _ string) ([]*custodian.CustodianGroup, error) {
	return nil, nil
}

// --- ErrNotConfigured guards ---

func TestCreateCustodianGroup_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.CreateCustodianGroup(context.Background(), &transport.CreateCustodianGroupRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestGetCustodianGroup_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetCustodianGroup(context.Background(), "g1")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestListCustodianGroups_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ListCustodianGroups(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestDeleteCustodianGroup_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.DeleteCustodianGroup(context.Background(), "g1")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestAddCustodianMember_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.AddCustodianMember(context.Background(), &transport.AddCustodianMemberRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestRemoveCustodianMember_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.RemoveCustodianMember(context.Background(), &transport.RemoveCustodianMemberRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestDistributeShares_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.DistributeShares(context.Background(), &transport.DistributeSharesRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

// --- Nil request guards ---

func TestCreateCustodianGroup_NilRequest(t *testing.T) {
	svc := setupServiceWithCustodian(t)

	_, err := svc.CreateCustodianGroup(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestAddCustodianMember_NilRequest(t *testing.T) {
	svc := setupServiceWithCustodian(t)

	_, err := svc.AddCustodianMember(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestRemoveCustodianMember_NilRequest(t *testing.T) {
	svc := setupServiceWithCustodian(t)

	err := svc.RemoveCustodianMember(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestDistributeShares_NilRequest(t *testing.T) {
	svc := setupServiceWithCustodian(t)

	_, err := svc.DistributeShares(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

// --- Delegation tests ---

func setupServiceWithCustodian(t *testing.T) *XKMSService {
	t.Helper()
	svc, _, _ := setupServiceWithProviders(t)
	store := newMockCustodianStore()
	svcCust, err := custodian.NewService(store)
	require.NoError(t, err)
	svc.SetCustodianService(svcCust)
	return svc
}

func TestCreateCustodianGroup_Success(t *testing.T) {
	svc := setupServiceWithCustodian(t)

	resp, err := svc.CreateCustodianGroup(context.Background(), &transport.CreateCustodianGroupRequest{
		ID:        "grp-1",
		TenantID:  "tenant-1",
		Name:      "Barrier Custodians",
		Purpose:   "barrier",
		Threshold: 2,
		Total:     3,
	})
	require.NoError(t, err)
	assert.Equal(t, "grp-1", resp.Group.ID)
	assert.Equal(t, "Barrier Custodians", resp.Group.Name)
	assert.Equal(t, 2, resp.Group.Threshold)
	assert.Equal(t, 3, resp.Group.Total)
}

func TestGetCustodianGroup_Success(t *testing.T) {
	svc := setupServiceWithCustodian(t)
	ctx := context.Background()

	_, err := svc.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		ID: "grp-2", Name: "Test Group", Purpose: "barrier", Threshold: 2, Total: 3,
	})
	require.NoError(t, err)

	resp, err := svc.GetCustodianGroup(ctx, "grp-2")
	require.NoError(t, err)
	assert.Equal(t, "grp-2", resp.Group.ID)
}

func TestGetCustodianGroup_NotFound(t *testing.T) {
	svc := setupServiceWithCustodian(t)

	_, err := svc.GetCustodianGroup(context.Background(), "nonexistent")
	require.Error(t, err)
}

func TestListCustodianGroups_Success(t *testing.T) {
	svc := setupServiceWithCustodian(t)
	ctx := context.Background()

	_, err := svc.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		ID: "grp-a", Name: "Group A", Purpose: "barrier", Threshold: 2, Total: 3,
	})
	require.NoError(t, err)
	_, err = svc.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		ID: "grp-b", Name: "Group B", Purpose: "barrier", Threshold: 2, Total: 3,
	})
	require.NoError(t, err)

	resp, err := svc.ListCustodianGroups(ctx)
	require.NoError(t, err)
	assert.Len(t, resp.Groups, 2)
}

func TestDeleteCustodianGroup_Success(t *testing.T) {
	svc := setupServiceWithCustodian(t)
	ctx := context.Background()

	_, err := svc.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		ID: "del-grp", Name: "Delete Me", Purpose: "barrier", Threshold: 2, Total: 3,
	})
	require.NoError(t, err)

	err = svc.DeleteCustodianGroup(ctx, "del-grp")
	require.NoError(t, err)

	_, err = svc.GetCustodianGroup(ctx, "del-grp")
	require.Error(t, err)
}

func TestDeleteCustodianGroup_NotFound(t *testing.T) {
	svc := setupServiceWithCustodian(t)

	err := svc.DeleteCustodianGroup(context.Background(), "ghost")
	require.Error(t, err)
}

func TestAddCustodianMember_Success(t *testing.T) {
	svc := setupServiceWithCustodian(t)
	ctx := context.Background()

	_, err := svc.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		ID: "mem-grp", Name: "Members", Purpose: "barrier", Threshold: 2, Total: 3,
	})
	require.NoError(t, err)

	resp, err := svc.AddCustodianMember(ctx, &transport.AddCustodianMemberRequest{
		GroupID:  "mem-grp",
		UserID:   "user-1",
		Username: "alice",
		Method:   "manual",
	})
	require.NoError(t, err)
	assert.Equal(t, "user-1", resp.Member.UserID)
	assert.Equal(t, "alice", resp.Member.Username)
	assert.Equal(t, 1, resp.Member.ShareIndex)
}

func TestRemoveCustodianMember_Success(t *testing.T) {
	svc := setupServiceWithCustodian(t)
	ctx := context.Background()

	_, err := svc.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		ID: "rm-grp", Name: "Remove", Purpose: "barrier", Threshold: 2, Total: 3,
	})
	require.NoError(t, err)

	_, err = svc.AddCustodianMember(ctx, &transport.AddCustodianMemberRequest{
		GroupID: "rm-grp", UserID: "user-1", Username: "alice", Method: "manual",
	})
	require.NoError(t, err)

	err = svc.RemoveCustodianMember(ctx, &transport.RemoveCustodianMemberRequest{
		GroupID: "rm-grp",
		UserID:  "user-1",
	})
	require.NoError(t, err)

	// Verify member was removed
	resp, err := svc.GetCustodianGroup(ctx, "rm-grp")
	require.NoError(t, err)
	assert.Empty(t, resp.Group.Members)
}

func TestDistributeShares_Success(t *testing.T) {
	svc := setupServiceWithCustodian(t)
	ctx := context.Background()

	_, err := svc.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		ID: "dist-grp", Name: "Distribute", Purpose: "barrier", Threshold: 2, Total: 3,
	})
	require.NoError(t, err)

	_, err = svc.AddCustodianMember(ctx, &transport.AddCustodianMemberRequest{
		GroupID: "dist-grp", UserID: "u1", Username: "alice", Method: "manual",
	})
	require.NoError(t, err)
	_, err = svc.AddCustodianMember(ctx, &transport.AddCustodianMemberRequest{
		GroupID: "dist-grp", UserID: "u2", Username: "bob", Method: "manual",
	})
	require.NoError(t, err)

	resp, err := svc.DistributeShares(ctx, &transport.DistributeSharesRequest{
		GroupID: "dist-grp",
	})
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Distributed)
}

func TestListCustodianGroups_WithMembers(t *testing.T) {
	svc := setupServiceWithCustodian(t)
	ctx := context.Background()

	_, err := svc.CreateCustodianGroup(ctx, &transport.CreateCustodianGroupRequest{
		ID: "grp-with-members", Name: "Team", Purpose: "barrier", Threshold: 2, Total: 3,
	})
	require.NoError(t, err)

	_, err = svc.AddCustodianMember(ctx, &transport.AddCustodianMemberRequest{
		GroupID: "grp-with-members", UserID: "u1", Username: "alice", Method: "manual",
	})
	require.NoError(t, err)

	// List groups -- custodianGroupToInfo must iterate over members.
	resp, err := svc.ListCustodianGroups(ctx)
	require.NoError(t, err)
	require.Len(t, resp.Groups, 1)
	assert.Len(t, resp.Groups[0].Members, 1)
	assert.Equal(t, "alice", resp.Groups[0].Members[0].Username)
}
