package xkms

import (
	"context"
	"errors"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeCustodianClient is an in-memory implementation of
// qrdbtransport.CustodianGroupClient used to exercise the XKMSService
// pass-through servicer. It mirrors the semantics of the embedded go-qrdb
// node's custodian client, returning the same sentinel errors so the
// servicer's ErrNotConfigured / ErrNilRequest guards and the error
// propagation path can be verified in isolation.
type fakeCustodianClient struct {
	groups map[string]*qrdbtransport.CustodianGroupInfo
}

func newFakeCustodianClient() *fakeCustodianClient {
	return &fakeCustodianClient{groups: make(map[string]*qrdbtransport.CustodianGroupInfo)}
}

func (f *fakeCustodianClient) CreateCustodianGroup(_ context.Context, req *qrdbtransport.CreateCustodianGroupRequest) (*qrdbtransport.CreateCustodianGroupResponse, error) {
	if req.ID == "" {
		return nil, qrdbsdk.ErrCeremonyEmptyGroupID
	}
	if req.Name == "" {
		return nil, qrdbsdk.ErrCeremonyEmptyGroupName
	}
	if req.Total < 1 {
		return nil, qrdbsdk.ErrCeremonyInvalidTotal
	}
	if req.Threshold < 1 || req.Threshold > req.Total {
		return nil, qrdbsdk.ErrCeremonyInvalidThreshold
	}
	if _, exists := f.groups[req.ID]; exists {
		return nil, qrdbsdk.ErrCeremonyGroupAlreadyExists
	}
	now := time.Now().UTC()
	g := &qrdbtransport.CustodianGroupInfo{
		ID:        req.ID,
		TenantID:  req.TenantID,
		Name:      req.Name,
		Purpose:   req.Purpose,
		Threshold: req.Threshold,
		Total:     req.Total,
		Members:   []qrdbtransport.CustodianMemberInfo{},
		CreatedAt: now,
		UpdatedAt: now,
	}
	f.groups[req.ID] = g
	return &qrdbtransport.CreateCustodianGroupResponse{Group: *g}, nil
}

func (f *fakeCustodianClient) GetCustodianGroup(_ context.Context, groupID string) (*qrdbtransport.GetCustodianGroupResponse, error) {
	if groupID == "" {
		return nil, qrdbsdk.ErrCeremonyEmptyGroupID
	}
	g, ok := f.groups[groupID]
	if !ok {
		return nil, qrdbsdk.ErrCeremonyGroupNotFound
	}
	return &qrdbtransport.GetCustodianGroupResponse{Group: *g}, nil
}

func (f *fakeCustodianClient) ListCustodianGroups(_ context.Context) (*qrdbtransport.ListCustodianGroupsResponse, error) {
	groups := make([]qrdbtransport.CustodianGroupInfo, 0, len(f.groups))
	for _, g := range f.groups {
		groups = append(groups, *g)
	}
	return &qrdbtransport.ListCustodianGroupsResponse{Groups: groups}, nil
}

func (f *fakeCustodianClient) DeleteCustodianGroup(_ context.Context, groupID string) error {
	if groupID == "" {
		return qrdbsdk.ErrCeremonyEmptyGroupID
	}
	if _, ok := f.groups[groupID]; !ok {
		return qrdbsdk.ErrCeremonyGroupNotFound
	}
	delete(f.groups, groupID)
	return nil
}

func (f *fakeCustodianClient) AddCustodianMember(_ context.Context, req *qrdbtransport.AddCustodianMemberRequest) (*qrdbtransport.AddCustodianMemberResponse, error) {
	if req.GroupID == "" {
		return nil, qrdbsdk.ErrCeremonyEmptyGroupID
	}
	if req.UserID == "" {
		return nil, qrdbsdk.ErrCeremonyUserNotFound
	}
	g, ok := f.groups[req.GroupID]
	if !ok {
		return nil, qrdbsdk.ErrCeremonyGroupNotFound
	}
	if len(g.Members) >= g.Total {
		return nil, qrdbsdk.ErrCeremonyGroupFull
	}
	for _, m := range g.Members {
		if m.UserID == req.UserID {
			return nil, qrdbsdk.ErrCeremonyMemberAlreadyExists
		}
	}
	member := qrdbtransport.CustodianMemberInfo{
		ShareIndex: len(g.Members),
		UserID:     req.UserID,
		Username:   req.Username,
		AssignedAt: time.Now().UTC(),
		Method:     req.Method,
	}
	g.Members = append(g.Members, member)
	g.UpdatedAt = time.Now().UTC()
	return &qrdbtransport.AddCustodianMemberResponse{Member: member}, nil
}

func (f *fakeCustodianClient) RemoveCustodianMember(_ context.Context, req *qrdbtransport.RemoveCustodianMemberRequest) error {
	if req.GroupID == "" {
		return qrdbsdk.ErrCeremonyEmptyGroupID
	}
	g, ok := f.groups[req.GroupID]
	if !ok {
		return qrdbsdk.ErrCeremonyGroupNotFound
	}
	for i, m := range g.Members {
		if m.UserID == req.UserID {
			g.Members = append(g.Members[:i], g.Members[i+1:]...)
			g.UpdatedAt = time.Now().UTC()
			return nil
		}
	}
	return qrdbsdk.ErrCeremonyMemberNotFound
}

func (f *fakeCustodianClient) DistributeShares(_ context.Context, req *qrdbtransport.DistributeSharesRequest) (*qrdbtransport.DistributeSharesResponse, error) {
	if req.GroupID == "" {
		return nil, qrdbsdk.ErrCeremonyEmptyGroupID
	}
	g, ok := f.groups[req.GroupID]
	if !ok {
		return nil, qrdbsdk.ErrCeremonyGroupNotFound
	}
	if len(g.Members) == 0 {
		return nil, qrdbsdk.ErrCeremonyInsufficientMembers
	}
	return &qrdbtransport.DistributeSharesResponse{Distributed: len(g.Members)}, nil
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
	svc.SetCustodianClient(newFakeCustodianClient())
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
	assert.True(t, errors.Is(err, qrdbsdk.ErrCeremonyGroupNotFound))
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
	assert.True(t, errors.Is(err, qrdbsdk.ErrCeremonyGroupNotFound))
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
	assert.Equal(t, 0, resp.Member.ShareIndex)
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

	// List groups -- the pass-through must surface members from the node.
	resp, err := svc.ListCustodianGroups(ctx)
	require.NoError(t, err)
	require.Len(t, resp.Groups, 1)
	assert.Len(t, resp.Groups[0].Members, 1)
	assert.Equal(t, "alice", resp.Groups[0].Members[0].Username)
}
