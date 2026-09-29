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

package grpc

import (
	"context"
	"errors"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// grpcFakeCustodianClient is an in-memory qrdbtransport.CustodianGroupClient
// mirroring the embedded go-qrdb node's custodian semantics, used to exercise
// the gRPC custodian handlers without a real node.
type grpcFakeCustodianClient struct {
	groups map[string]*qrdbtransport.CustodianGroupInfo
}

func newGRPCFakeCustodianClient() *grpcFakeCustodianClient {
	return &grpcFakeCustodianClient{groups: make(map[string]*qrdbtransport.CustodianGroupInfo)}
}

func (f *grpcFakeCustodianClient) CreateCustodianGroup(_ context.Context, req *qrdbtransport.CreateCustodianGroupRequest) (*qrdbtransport.CreateCustodianGroupResponse, error) {
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
		ID: req.ID, TenantID: req.TenantID, Name: req.Name, Purpose: req.Purpose,
		Threshold: req.Threshold, Total: req.Total,
		Members: []qrdbtransport.CustodianMemberInfo{}, CreatedAt: now, UpdatedAt: now,
	}
	f.groups[req.ID] = g
	return &qrdbtransport.CreateCustodianGroupResponse{Group: *g}, nil
}

func (f *grpcFakeCustodianClient) GetCustodianGroup(_ context.Context, groupID string) (*qrdbtransport.GetCustodianGroupResponse, error) {
	if groupID == "" {
		return nil, qrdbsdk.ErrCeremonyEmptyGroupID
	}
	g, ok := f.groups[groupID]
	if !ok {
		return nil, qrdbsdk.ErrCeremonyGroupNotFound
	}
	return &qrdbtransport.GetCustodianGroupResponse{Group: *g}, nil
}

func (f *grpcFakeCustodianClient) ListCustodianGroups(_ context.Context) (*qrdbtransport.ListCustodianGroupsResponse, error) {
	groups := make([]qrdbtransport.CustodianGroupInfo, 0, len(f.groups))
	for _, g := range f.groups {
		groups = append(groups, *g)
	}
	return &qrdbtransport.ListCustodianGroupsResponse{Groups: groups}, nil
}

func (f *grpcFakeCustodianClient) DeleteCustodianGroup(_ context.Context, groupID string) error {
	if groupID == "" {
		return qrdbsdk.ErrCeremonyEmptyGroupID
	}
	if _, ok := f.groups[groupID]; !ok {
		return qrdbsdk.ErrCeremonyGroupNotFound
	}
	delete(f.groups, groupID)
	return nil
}

func (f *grpcFakeCustodianClient) AddCustodianMember(_ context.Context, req *qrdbtransport.AddCustodianMemberRequest) (*qrdbtransport.AddCustodianMemberResponse, error) {
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
		ShareIndex: len(g.Members), UserID: req.UserID, Username: req.Username,
		AssignedAt: time.Now().UTC(), Method: req.Method,
	}
	g.Members = append(g.Members, member)
	g.UpdatedAt = time.Now().UTC()
	return &qrdbtransport.AddCustodianMemberResponse{Member: member}, nil
}

func (f *grpcFakeCustodianClient) RemoveCustodianMember(_ context.Context, req *qrdbtransport.RemoveCustodianMemberRequest) error {
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

func (f *grpcFakeCustodianClient) DistributeShares(_ context.Context, req *qrdbtransport.DistributeSharesRequest) (*qrdbtransport.DistributeSharesResponse, error) {
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

// grpcFakeShareClient is an in-memory qrdbtransport.ShareClient mirroring the
// embedded go-qrdb node's share semantics, used to exercise the gRPC share
// handlers without a real node.
type grpcFakeShareClient struct {
	shares    []qrdbtransport.ShareInfo
	threshold int
	total     int
}

func newGRPCFakeShareClient() *grpcFakeShareClient {
	return &grpcFakeShareClient{}
}

func (f *grpcFakeShareClient) SubmitShare(_ context.Context, req *qrdbtransport.SubmitShareRequest) (*qrdbtransport.SubmitShareResponse, error) {
	f.shares = append(f.shares, qrdbtransport.ShareInfo{
		ServerURL:  req.ServerURL,
		GroupID:    req.GroupID,
		GroupName:  req.GroupName,
		ShareIndex: req.ShareIndex,
		ShareData:  req.ShareData,
		Purpose:    req.Purpose,
		ReceivedAt: time.Now().UTC(),
		TenantID:   req.TenantID,
	})
	return &qrdbtransport.SubmitShareResponse{Accepted: true}, nil
}

func (f *grpcFakeShareClient) ListShares(_ context.Context) (*qrdbtransport.ListSharesResponse, error) {
	return &qrdbtransport.ListSharesResponse{Shares: f.shares}, nil
}

func (f *grpcFakeShareClient) GetShare(_ context.Context, serverURL, groupID string, shareIndex int) (*qrdbtransport.ShareInfo, error) {
	for i := range f.shares {
		s := f.shares[i]
		if s.ServerURL == serverURL && s.GroupID == groupID && s.ShareIndex == shareIndex {
			return &s, nil
		}
	}
	return nil, qrdbsdk.ErrCeremonyShareNotFound
}

func (f *grpcFakeShareClient) DeleteShare(_ context.Context, serverURL, groupID string, shareIndex int) error {
	for i := range f.shares {
		s := f.shares[i]
		if s.ServerURL == serverURL && s.GroupID == groupID && s.ShareIndex == shareIndex {
			f.shares = append(f.shares[:i], f.shares[i+1:]...)
			return nil
		}
	}
	return qrdbsdk.ErrCeremonyShareNotFound
}

func (f *grpcFakeShareClient) GetShareCollectionStatus(_ context.Context, groupID string) (*qrdbtransport.ShareCollectionStatus, error) {
	collected := 0
	for i := range f.shares {
		if f.shares[i].GroupID == groupID {
			collected++
		}
	}
	return &qrdbtransport.ShareCollectionStatus{
		GroupID:   groupID,
		Threshold: f.threshold,
		Total:     f.total,
		Collected: collected,
		Ready:     f.threshold > 0 && collected >= f.threshold,
	}, nil
}

// setupCustodianClient creates an in-memory custodian group client.
func setupCustodianClient(t *testing.T) *grpcFakeCustodianClient {
	t.Helper()
	return newGRPCFakeCustodianClient()
}

// setupShareClient creates an in-memory share client.
func setupShareClient(t *testing.T) *grpcFakeShareClient {
	t.Helper()
	return newGRPCFakeShareClient()
}

// setupBarrierRegistry creates an initialized barrier registry.
func setupBarrierRegistry(t *testing.T) *seal.BarrierRegistry {
	t.Helper()
	reg := testTenantRegistry(t)

	// The tenant barrier init/unseal RPCs delegate to the XKMSService servicer,
	// which requires a composed TenantService (there is no barrier-registry-only
	// fallback). Build a real go-qrdb TenantService over the SAME registry,
	// mirroring production wiring in pkg/server/server.go.
	tenantSvc, err := seal.NewHardwareTenantService(reg.SystemBarrier(), reg, discardLogger(), nil)
	require.NoError(t, err)

	setupXKMSForTest(t)
	svc, err := xkms.Get()
	require.NoError(t, err)
	svc.SetTenantService(tenantSvc)
	t.Cleanup(func() { xkms.Reset() })

	return reg
}

func TestSetCustodianClient_GetCustodianClient(t *testing.T) {
	old := GetCustodianClient()
	defer SetCustodianClient(old)

	t.Run("sets and gets custodian service", func(t *testing.T) {
		svc := setupCustodianClient(t)
		SetCustodianClient(svc)
		assert.Equal(t, svc, GetCustodianClient())
	})

	t.Run("returns nil when not set", func(t *testing.T) {
		SetCustodianClient(nil)
		assert.Nil(t, GetCustodianClient())
	})
}

func TestSetShareClient_GetShareClient(t *testing.T) {
	old := GetShareClient()
	defer SetShareClient(old)

	t.Run("sets and gets share client", func(t *testing.T) {
		sc := setupShareClient(t)
		SetShareClient(sc)
		assert.Equal(t, sc, GetShareClient())
	})

	t.Run("returns nil when not set", func(t *testing.T) {
		SetShareClient(nil)
		assert.Nil(t, GetShareClient())
	})
}

func TestSetBarrierRegistry_GetBarrierRegistry(t *testing.T) {
	old := GetBarrierRegistry()
	defer SetBarrierRegistry(old)

	t.Run("sets and gets barrier registry", func(t *testing.T) {
		reg := setupBarrierRegistry(t)
		SetBarrierRegistry(reg)
		assert.Equal(t, reg, GetBarrierRegistry())
	})

	t.Run("returns nil when not set", func(t *testing.T) {
		SetBarrierRegistry(nil)
		assert.Nil(t, GetBarrierRegistry())
	})
}

// --- Error mapping tests ---

func TestMapCustodianError(t *testing.T) {
	t.Run("nil error returns nil", func(t *testing.T) {
		assert.NoError(t, mapCustodianError(nil, "op"))
	})

	t.Run("known error maps to correct code", func(t *testing.T) {
		err := mapCustodianError(qrdbsdk.ErrCeremonyGroupNotFound, "get group")
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("unknown error maps to Internal", func(t *testing.T) {
		err := mapCustodianError(errors.New("unknown"), "op")
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})
}

func TestMapShareError(t *testing.T) {
	t.Run("nil error returns nil", func(t *testing.T) {
		assert.NoError(t, mapShareError(nil, "op"))
	})

	t.Run("known error maps to correct code", func(t *testing.T) {
		err := mapShareError(qrdbsdk.ErrCeremonyShareNotFound, "get share")
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("unknown error maps to Internal", func(t *testing.T) {
		err := mapShareError(errors.New("unknown"), "op")
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})
}

func TestMapTenantError(t *testing.T) {
	t.Run("nil error returns nil", func(t *testing.T) {
		assert.NoError(t, mapTenantError(nil, "op"))
	})

	t.Run("known error maps to correct code", func(t *testing.T) {
		err := mapTenantError(seal.ErrTenantNotFound, "get tenant")
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("unknown error maps to Internal", func(t *testing.T) {
		err := mapTenantError(errors.New("unknown"), "op")
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})
}

// --- Proto conversion tests ---

func TestCustodianGroupToProto(t *testing.T) {
	now := time.Now().UTC()
	group := &qrdbtransport.CustodianGroupInfo{
		ID:        "group-1",
		Name:      "Test Group",
		Purpose:   "barrier",
		Threshold: 2,
		Members: []qrdbtransport.CustodianMemberInfo{
			{UserID: "user-1", Username: "alice", Method: "manual"},
			{UserID: "user-2", Username: "bob", Method: "auto"},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	pb := custodianGroupToProto(group)
	assert.Equal(t, "group-1", pb.Id)
	assert.Equal(t, "Test Group", pb.Name)
	assert.Equal(t, "barrier", pb.Description)
	assert.Equal(t, int32(2), pb.Threshold)
	assert.Len(t, pb.Members, 2)
	assert.Equal(t, "user-1", pb.Members[0].UserId)
	assert.Equal(t, "alice", pb.Members[0].Name)
}

func TestCustodianMemberToProto(t *testing.T) {
	m := &qrdbtransport.CustodianMemberInfo{
		UserID:   "user-1",
		Username: "alice",
		Method:   "manual",
	}

	pb := custodianMemberToProto(m)
	assert.Equal(t, "user-1", pb.UserId)
	assert.Equal(t, "alice", pb.Name)
	assert.Equal(t, "manual", pb.Role)
}

func TestShareInfoToProto(t *testing.T) {
	now := time.Now().UTC()
	info := &qrdbtransport.ShareInfo{
		GroupID:    "group-1",
		ServerURL:  "https://server.example.com",
		GroupName:  "Test Group",
		ShareIndex: 1,
		Purpose:    "barrier",
		TenantID:   "tenant-1",
		ReceivedAt: now,
	}

	pb := shareInfoToProto(info)
	assert.Equal(t, "group-1", pb.GroupId)
	assert.Equal(t, "https://server.example.com", pb.ServerUrl)
	assert.Equal(t, "Test Group", pb.GroupName)
	assert.Equal(t, int32(1), pb.ShareIndex)
	assert.Equal(t, "barrier", pb.Purpose)
	assert.Equal(t, "tenant-1", pb.TenantId)
}

// --- Custodian Group Operations ---

func TestCreateCustodianGroup(t *testing.T) {
	svc := NewService(nil, nil, nil)

	t.Run("returns error when service not configured", func(t *testing.T) {
		old := GetCustodianClient()
		SetCustodianClient(nil)
		defer SetCustodianClient(old)

		_, err := svc.CreateCustodianGroup(context.Background(), &pb.CreateCustodianGroupRequest{
			Name: "test", Threshold: 2,
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error when name is empty", func(t *testing.T) {
		old := GetCustodianClient()
		SetCustodianClient(setupCustodianClient(t))
		defer SetCustodianClient(old)

		_, err := svc.CreateCustodianGroup(context.Background(), &pb.CreateCustodianGroupRequest{
			Name: "", Threshold: 2,
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when threshold is invalid", func(t *testing.T) {
		old := GetCustodianClient()
		SetCustodianClient(setupCustodianClient(t))
		defer SetCustodianClient(old)

		_, err := svc.CreateCustodianGroup(context.Background(), &pb.CreateCustodianGroupRequest{
			Name: "test", Threshold: 0,
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns mapped error when custodian service returns domain error", func(t *testing.T) {
		old := GetCustodianClient()
		SetCustodianClient(setupCustodianClient(t))
		defer SetCustodianClient(old)

		// The handler passes empty strings for id and tenantID, which fails
		// validation in the custodian service. This tests the error mapping path.
		_, err := svc.CreateCustodianGroup(context.Background(), &pb.CreateCustodianGroupRequest{
			Name:        "test-group",
			Description: "barrier",
			Threshold:   2,
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

func TestGetCustodianGroup(t *testing.T) {
	svc := NewService(nil, nil, nil)

	t.Run("returns error when service not configured", func(t *testing.T) {
		old := GetCustodianClient()
		SetCustodianClient(nil)
		defer SetCustodianClient(old)

		_, err := svc.GetCustodianGroup(context.Background(), &pb.GetCustodianGroupRequest{GroupId: "id"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error when group_id is empty", func(t *testing.T) {
		old := GetCustodianClient()
		SetCustodianClient(setupCustodianClient(t))
		defer SetCustodianClient(old)

		_, err := svc.GetCustodianGroup(context.Background(), &pb.GetCustodianGroupRequest{GroupId: ""})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when group not found", func(t *testing.T) {
		old := GetCustodianClient()
		SetCustodianClient(setupCustodianClient(t))
		defer SetCustodianClient(old)

		_, err := svc.GetCustodianGroup(context.Background(), &pb.GetCustodianGroupRequest{GroupId: "nonexistent"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("returns group on success", func(t *testing.T) {
		old := GetCustodianClient()
		cs := setupCustodianClient(t)
		SetCustodianClient(cs)
		defer SetCustodianClient(old)

		groupResp, err := cs.CreateCustodianGroup(context.Background(), &qrdbtransport.CreateCustodianGroupRequest{
			ID: "grp-1", TenantID: "tenant-1", Name: "test", Purpose: "barrier", Threshold: 2, Total: 2,
		})
		require.NoError(t, err)

		resp, err := svc.GetCustodianGroup(context.Background(), &pb.GetCustodianGroupRequest{GroupId: groupResp.Group.ID})
		require.NoError(t, err)
		assert.Equal(t, groupResp.Group.ID, resp.Group.Id)
	})
}

func TestListCustodianGroups(t *testing.T) {
	svc := NewService(nil, nil, nil)

	t.Run("returns error when service not configured", func(t *testing.T) {
		old := GetCustodianClient()
		SetCustodianClient(nil)
		defer SetCustodianClient(old)

		_, err := svc.ListCustodianGroups(context.Background(), &pb.ListCustodianGroupsRequest{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns empty list", func(t *testing.T) {
		old := GetCustodianClient()
		SetCustodianClient(setupCustodianClient(t))
		defer SetCustodianClient(old)

		resp, err := svc.ListCustodianGroups(context.Background(), &pb.ListCustodianGroupsRequest{})
		require.NoError(t, err)
		assert.Empty(t, resp.Groups)
	})

	t.Run("returns populated list", func(t *testing.T) {
		old := GetCustodianClient()
		cs := setupCustodianClient(t)
		SetCustodianClient(cs)
		defer SetCustodianClient(old)

		_, err := cs.CreateCustodianGroup(context.Background(), &qrdbtransport.CreateCustodianGroupRequest{
			ID: "grp-list-1", TenantID: "", Name: "g1", Purpose: "barrier", Threshold: 2, Total: 2,
		})
		require.NoError(t, err)

		resp, err := svc.ListCustodianGroups(context.Background(), &pb.ListCustodianGroupsRequest{})
		require.NoError(t, err)
		assert.Len(t, resp.Groups, 1)
	})
}

func TestDeleteCustodianGroup(t *testing.T) {
	svc := NewService(nil, nil, nil)

	t.Run("returns error when service not configured", func(t *testing.T) {
		old := GetCustodianClient()
		SetCustodianClient(nil)
		defer SetCustodianClient(old)

		_, err := svc.DeleteCustodianGroup(context.Background(), &pb.DeleteCustodianGroupRequest{GroupId: "id"})
		require.Error(t, err)
	})

	t.Run("returns error when group_id is empty", func(t *testing.T) {
		old := GetCustodianClient()
		SetCustodianClient(setupCustodianClient(t))
		defer SetCustodianClient(old)

		_, err := svc.DeleteCustodianGroup(context.Background(), &pb.DeleteCustodianGroupRequest{GroupId: ""})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("deletes group on success", func(t *testing.T) {
		old := GetCustodianClient()
		cs := setupCustodianClient(t)
		SetCustodianClient(cs)
		defer SetCustodianClient(old)

		groupResp, err := cs.CreateCustodianGroup(context.Background(), &qrdbtransport.CreateCustodianGroupRequest{
			ID: "grp-del-1", TenantID: "", Name: "test", Purpose: "barrier", Threshold: 2, Total: 2,
		})
		require.NoError(t, err)

		_, err = svc.DeleteCustodianGroup(context.Background(), &pb.DeleteCustodianGroupRequest{GroupId: groupResp.Group.ID})
		require.NoError(t, err)
	})
}

func TestAddCustodianMember(t *testing.T) {
	svc := NewService(nil, nil, nil)

	t.Run("returns error when service not configured", func(t *testing.T) {
		old := GetCustodianClient()
		SetCustodianClient(nil)
		defer SetCustodianClient(old)

		_, err := svc.AddCustodianMember(context.Background(), &pb.AddCustodianMemberRequest{
			GroupId: "g1", UserId: "u1",
		})
		require.Error(t, err)
	})

	t.Run("returns error when group_id is empty", func(t *testing.T) {
		old := GetCustodianClient()
		SetCustodianClient(setupCustodianClient(t))
		defer SetCustodianClient(old)

		_, err := svc.AddCustodianMember(context.Background(), &pb.AddCustodianMemberRequest{
			UserId: "u1",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when user_id is empty", func(t *testing.T) {
		old := GetCustodianClient()
		SetCustodianClient(setupCustodianClient(t))
		defer SetCustodianClient(old)

		_, err := svc.AddCustodianMember(context.Background(), &pb.AddCustodianMemberRequest{
			GroupId: "g1",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("adds member on success", func(t *testing.T) {
		old := GetCustodianClient()
		cs := setupCustodianClient(t)
		SetCustodianClient(cs)
		defer SetCustodianClient(old)

		groupResp, err := cs.CreateCustodianGroup(context.Background(), &qrdbtransport.CreateCustodianGroupRequest{
			ID: "grp-add-1", TenantID: "", Name: "test", Purpose: "barrier", Threshold: 2, Total: 2,
		})
		require.NoError(t, err)

		resp, err := svc.AddCustodianMember(context.Background(), &pb.AddCustodianMemberRequest{
			GroupId: groupResp.Group.ID, UserId: "user-1", Name: "alice",
		})
		require.NoError(t, err)
		assert.Equal(t, "user-1", resp.Member.UserId)
		assert.Equal(t, "alice", resp.Member.Name)
		assert.Equal(t, defaultCustodianMethod, resp.Member.Role)
	})
}

func TestRemoveCustodianMember(t *testing.T) {
	svc := NewService(nil, nil, nil)

	t.Run("returns error when service not configured", func(t *testing.T) {
		old := GetCustodianClient()
		SetCustodianClient(nil)
		defer SetCustodianClient(old)

		_, err := svc.RemoveCustodianMember(context.Background(), &pb.RemoveCustodianMemberRequest{
			GroupId: "g1", UserId: "u1",
		})
		require.Error(t, err)
	})

	t.Run("returns error when group_id is empty", func(t *testing.T) {
		old := GetCustodianClient()
		SetCustodianClient(setupCustodianClient(t))
		defer SetCustodianClient(old)

		_, err := svc.RemoveCustodianMember(context.Background(), &pb.RemoveCustodianMemberRequest{
			UserId: "u1",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when user_id is empty", func(t *testing.T) {
		old := GetCustodianClient()
		SetCustodianClient(setupCustodianClient(t))
		defer SetCustodianClient(old)

		_, err := svc.RemoveCustodianMember(context.Background(), &pb.RemoveCustodianMemberRequest{
			GroupId: "g1",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("removes member on success", func(t *testing.T) {
		old := GetCustodianClient()
		cs := setupCustodianClient(t)
		SetCustodianClient(cs)
		defer SetCustodianClient(old)

		groupResp, err := cs.CreateCustodianGroup(context.Background(), &qrdbtransport.CreateCustodianGroupRequest{
			ID: "grp-rem-1", TenantID: "", Name: "test", Purpose: "barrier", Threshold: 2, Total: 2,
		})
		require.NoError(t, err)
		_, err = cs.AddCustodianMember(context.Background(), &qrdbtransport.AddCustodianMemberRequest{
			GroupID: groupResp.Group.ID, UserID: "user-1", Username: "alice", Method: "manual",
		})
		require.NoError(t, err)

		_, err = svc.RemoveCustodianMember(context.Background(), &pb.RemoveCustodianMemberRequest{
			GroupId: groupResp.Group.ID, UserId: "user-1",
		})
		require.NoError(t, err)
	})
}

func TestDistributeShares(t *testing.T) {
	svc := NewService(nil, nil, nil)

	t.Run("returns error when service not configured", func(t *testing.T) {
		old := GetCustodianClient()
		SetCustodianClient(nil)
		defer SetCustodianClient(old)

		_, err := svc.DistributeShares(context.Background(), &pb.DistributeSharesRequest{GroupId: "g1"})
		require.Error(t, err)
	})

	t.Run("returns error when group_id is empty", func(t *testing.T) {
		old := GetCustodianClient()
		SetCustodianClient(setupCustodianClient(t))
		defer SetCustodianClient(old)

		_, err := svc.DistributeShares(context.Background(), &pb.DistributeSharesRequest{GroupId: ""})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

// --- Share Operations ---

func TestSubmitShare(t *testing.T) {
	svc := NewService(nil, nil, nil)

	t.Run("returns error when share client not configured", func(t *testing.T) {
		old := GetShareClient()
		SetShareClient(nil)
		defer SetShareClient(old)

		_, err := svc.SubmitShare(context.Background(), &pb.SubmitShareRequest{
			GroupId: "g1", ShareData: "data", ServerUrl: "https://example.com",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error when group_id is empty", func(t *testing.T) {
		old := GetShareClient()
		SetShareClient(setupShareClient(t))
		defer SetShareClient(old)

		_, err := svc.SubmitShare(context.Background(), &pb.SubmitShareRequest{
			ShareData: "data", ServerUrl: "https://example.com",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when share_data is empty", func(t *testing.T) {
		old := GetShareClient()
		SetShareClient(setupShareClient(t))
		defer SetShareClient(old)

		_, err := svc.SubmitShare(context.Background(), &pb.SubmitShareRequest{
			GroupId: "g1", ServerUrl: "https://example.com",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when server_url is empty", func(t *testing.T) {
		old := GetShareClient()
		SetShareClient(setupShareClient(t))
		defer SetShareClient(old)

		_, err := svc.SubmitShare(context.Background(), &pb.SubmitShareRequest{
			GroupId: "g1", ShareData: "data",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("submits share on success", func(t *testing.T) {
		old := GetShareClient()
		SetShareClient(setupShareClient(t))
		defer SetShareClient(old)

		resp, err := svc.SubmitShare(context.Background(), &pb.SubmitShareRequest{
			GroupId:    "g1",
			ShareData:  "secret-share",
			ServerUrl:  "https://example.com",
			GroupName:  "group-1",
			ShareIndex: 0,
			Purpose:    "barrier",
			TenantId:   "tenant-1",
		})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.Id)
		assert.Equal(t, "share submitted successfully", resp.Message)
	})
}

func TestListShares(t *testing.T) {
	svc := NewService(nil, nil, nil)

	t.Run("returns error when share client not configured", func(t *testing.T) {
		old := GetShareClient()
		SetShareClient(nil)
		defer SetShareClient(old)

		_, err := svc.ListShares(context.Background(), &pb.ListSharesRequest{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns empty list", func(t *testing.T) {
		old := GetShareClient()
		SetShareClient(setupShareClient(t))
		defer SetShareClient(old)

		resp, err := svc.ListShares(context.Background(), &pb.ListSharesRequest{})
		require.NoError(t, err)
		assert.Empty(t, resp.Shares)
	})

	t.Run("returns shares after submit", func(t *testing.T) {
		old := GetShareClient()
		sc := setupShareClient(t)
		SetShareClient(sc)
		defer SetShareClient(old)

		_, err := sc.SubmitShare(context.Background(), &qrdbtransport.SubmitShareRequest{
			ServerURL: "https://example.com",
			GroupID:   "g1",
			GroupName: "group-1",
			ShareData: []byte("share-data"),
		})
		require.NoError(t, err)

		resp, err := svc.ListShares(context.Background(), &pb.ListSharesRequest{})
		require.NoError(t, err)
		assert.Len(t, resp.Shares, 1)
	})
}

func TestGetShareCollectionStatus(t *testing.T) {
	svc := NewService(nil, nil, nil)

	t.Run("returns error when share client not configured", func(t *testing.T) {
		old := GetShareClient()
		SetShareClient(nil)
		defer SetShareClient(old)

		_, err := svc.GetShareCollectionStatus(context.Background(), &pb.GetShareCollectionStatusRequest{GroupId: "g1"})
		require.Error(t, err)
	})

	t.Run("returns error when group_id is empty", func(t *testing.T) {
		old := GetShareClient()
		SetShareClient(setupShareClient(t))
		defer SetShareClient(old)

		_, err := svc.GetShareCollectionStatus(context.Background(), &pb.GetShareCollectionStatusRequest{GroupId: ""})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns status with zero collected", func(t *testing.T) {
		old := GetShareClient()
		SetShareClient(setupShareClient(t))
		defer SetShareClient(old)

		resp, err := svc.GetShareCollectionStatus(context.Background(), &pb.GetShareCollectionStatusRequest{GroupId: "g1"})
		require.NoError(t, err)
		assert.Equal(t, "g1", resp.GroupId)
		assert.Equal(t, int32(0), resp.Collected)
	})

	t.Run("returns status with collected count and threshold from client", func(t *testing.T) {
		old := GetShareClient()
		sc := setupShareClient(t)
		sc.threshold = 2
		sc.total = 2
		SetShareClient(sc)
		defer SetShareClient(old)

		// Add shares for this group.
		for i := 0; i < 2; i++ {
			_, err := sc.SubmitShare(context.Background(), &qrdbtransport.SubmitShareRequest{
				ServerURL:  "https://example.com",
				GroupID:    "grp-share-1",
				GroupName:  "test",
				ShareIndex: i,
				ShareData:  []byte("share-data"),
			})
			require.NoError(t, err)
		}

		resp, err := svc.GetShareCollectionStatus(context.Background(), &pb.GetShareCollectionStatusRequest{GroupId: "grp-share-1"})
		require.NoError(t, err)
		assert.Equal(t, int32(2), resp.Collected)
		assert.Equal(t, int32(2), resp.Required)
		assert.True(t, resp.Complete)
	})
}

// --- Tenant Operations ---

func TestCreateTenant(t *testing.T) {
	svc := NewService(nil, nil, nil)

	t.Run("returns error when registry not configured", func(t *testing.T) {
		old := GetBarrierRegistry()
		SetBarrierRegistry(nil)
		defer SetBarrierRegistry(old)

		_, err := svc.CreateTenant(context.Background(), &pb.CreateTenantRequest{Id: "t1", Name: "Tenant 1"})
		require.Error(t, err)
	})

	t.Run("returns error when id is empty", func(t *testing.T) {
		old := GetBarrierRegistry()
		SetBarrierRegistry(setupBarrierRegistry(t))
		defer SetBarrierRegistry(old)

		_, err := svc.CreateTenant(context.Background(), &pb.CreateTenantRequest{Name: "Tenant 1"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when name is empty", func(t *testing.T) {
		old := GetBarrierRegistry()
		SetBarrierRegistry(setupBarrierRegistry(t))
		defer SetBarrierRegistry(old)

		_, err := svc.CreateTenant(context.Background(), &pb.CreateTenantRequest{Id: "t1"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("creates tenant on success", func(t *testing.T) {
		old := GetBarrierRegistry()
		SetBarrierRegistry(setupBarrierRegistry(t))
		defer SetBarrierRegistry(old)

		resp, err := svc.CreateTenant(context.Background(), &pb.CreateTenantRequest{
			Id:          "tenant-1",
			Name:        "Tenant 1",
			Description: "Test tenant",
		})
		require.NoError(t, err)
		assert.Equal(t, "tenant-1", resp.Tenant.Id)
		assert.Equal(t, "Tenant 1", resp.Tenant.Name)
		assert.Equal(t, "Test tenant", resp.Tenant.Description)
	})
}

func TestGetTenant(t *testing.T) {
	t.Run("returns unavailable when xkms service not wired", func(t *testing.T) {
		svc := NewService(nil, nil, nil)
		_, err := svc.GetTenant(context.Background(), &pb.GetTenantRequest{TenantId: "t1"})
		require.Error(t, err)
		assert.Equal(t, codes.Unavailable, status.Code(err))
	})

	t.Run("returns error when tenant_id is empty", func(t *testing.T) {
		svc := NewService(nil, nil, newTenantServiceWiredXKMS(t))
		_, err := svc.GetTenant(context.Background(), &pb.GetTenantRequest{})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("returns not found when tenant does not exist", func(t *testing.T) {
		svc := NewService(nil, nil, newTenantServiceWiredXKMS(t))
		_, err := svc.GetTenant(context.Background(), &pb.GetTenantRequest{TenantId: "nonexistent"})
		require.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err))
	})

	t.Run("returns tenant on success", func(t *testing.T) {
		svc := NewService(nil, nil, newTenantServiceWiredXKMS(t))
		_, err := svc.CreateTenant(context.Background(), &pb.CreateTenantRequest{Id: "my-tenant", Name: "Mine"})
		require.NoError(t, err)

		resp, err := svc.GetTenant(context.Background(), &pb.GetTenantRequest{TenantId: "my-tenant"})
		require.NoError(t, err)
		assert.Equal(t, "my-tenant", resp.Tenant.Id)
	})
}

func TestListTenants(t *testing.T) {
	t.Run("returns unavailable when xkms service not wired", func(t *testing.T) {
		svc := NewService(nil, nil, nil)
		_, err := svc.ListTenants(context.Background(), &pb.ListTenantsRequest{})
		require.Error(t, err)
		assert.Equal(t, codes.Unavailable, status.Code(err))
	})

	t.Run("returns empty list", func(t *testing.T) {
		svc := NewService(nil, nil, newTenantServiceWiredXKMS(t))
		resp, err := svc.ListTenants(context.Background(), &pb.ListTenantsRequest{})
		require.NoError(t, err)
		assert.Empty(t, resp.Tenants)
	})

	t.Run("returns populated list", func(t *testing.T) {
		svc := NewService(nil, nil, newTenantServiceWiredXKMS(t))
		for _, id := range []string{"tenant-a", "tenant-b"} {
			_, err := svc.CreateTenant(context.Background(), &pb.CreateTenantRequest{Id: id, Name: id})
			require.NoError(t, err)
		}

		resp, err := svc.ListTenants(context.Background(), &pb.ListTenantsRequest{})
		require.NoError(t, err)
		assert.Len(t, resp.Tenants, 2)
	})
}

func TestDeleteTenant(t *testing.T) {
	t.Run("returns unavailable when xkms service not wired", func(t *testing.T) {
		svc := NewService(nil, nil, nil)
		_, err := svc.DeleteTenant(context.Background(), &pb.DeleteTenantRequest{TenantId: "t1"})
		require.Error(t, err)
		assert.Equal(t, codes.Unavailable, status.Code(err))
	})

	t.Run("returns error when tenant_id is empty", func(t *testing.T) {
		svc := NewService(nil, nil, newTenantServiceWiredXKMS(t))
		_, err := svc.DeleteTenant(context.Background(), &pb.DeleteTenantRequest{})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	// A successful delete is absent for the reason
	// pkg/api/rest/handlers_tenant_test.go records: go-qrdb's tenant teardown
	// needs a DatabaseLister / KeyspaceReclaimer this in-memory harness does
	// not compose. The servicer's delegation is pinned by
	// pkg/xkms's TestDeleteTenant_Delegates.
	t.Run("returns not found when tenant does not exist", func(t *testing.T) {
		svc := NewService(nil, nil, newTenantServiceWiredXKMS(t))
		_, err := svc.DeleteTenant(context.Background(), &pb.DeleteTenantRequest{TenantId: "nonexistent"})
		require.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err))
	})
}

func TestTenantBarrierInit(t *testing.T) {
	// Initialize xkms at function scope so the service can be wired for the
	// success path. The registry-nil subtest overrides barrierRegistry explicitly,
	// so it still exercises the registry guard before reaching xkmsService.
	reg := setupBarrierRegistry(t)
	SetBarrierRegistry(reg)
	t.Cleanup(func() { SetBarrierRegistry(nil) })
	xkmsSvc, err := xkms.Get()
	require.NoError(t, err)
	svc := NewService(nil, nil, xkmsSvc)

	t.Run("returns error when registry not configured", func(t *testing.T) {
		old := GetBarrierRegistry()
		SetBarrierRegistry(nil)
		defer SetBarrierRegistry(old)

		_, err := svc.TenantBarrierInit(context.Background(), &pb.TenantBarrierInitRequest{TenantId: "t1"})
		require.Error(t, err)
	})

	t.Run("returns error when tenant_id is empty", func(t *testing.T) {
		_, err := svc.TenantBarrierInit(context.Background(), &pb.TenantBarrierInitRequest{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when tenant not found", func(t *testing.T) {
		_, err := svc.TenantBarrierInit(context.Background(), &pb.TenantBarrierInitRequest{TenantId: "nonexistent"})
		require.Error(t, err)
	})

	// TestTenantBarrierInit/succeeds_for_existing_tenant is intentionally
	// absent here: a barrier-isolated tenant's TenantBarrierInit success path
	// requires go-qrdb's pooled per-tenant storage (WithVolumePool /
	// WithPerTenantRegistry), which needs real Pebble-backed pool
	// infrastructure this in-memory unit test suite deliberately does not
	// stand up. That success path is covered against a fake TenantServicer
	// in pkg/xkms/servicer_tenant_delegation_test.go
	// (TestTenantBarrierInit_DelegatesWithStrategy); this file covers the
	// gRPC-layer request validation and not-found guards above.
}

func TestTenantBarrierUnseal(t *testing.T) {
	// Initialize xkms at function scope so the service can be wired for the
	// success path. The registry-nil subtest overrides barrierRegistry explicitly,
	// so it still exercises the registry guard before reaching xkmsService.
	reg := setupBarrierRegistry(t)
	SetBarrierRegistry(reg)
	t.Cleanup(func() { SetBarrierRegistry(nil) })
	xkmsSvc, err := xkms.Get()
	require.NoError(t, err)
	svc := NewService(nil, nil, xkmsSvc)

	t.Run("returns error when registry not configured", func(t *testing.T) {
		old := GetBarrierRegistry()
		SetBarrierRegistry(nil)
		defer SetBarrierRegistry(old)

		_, err := svc.TenantBarrierUnseal(context.Background(), &pb.TenantBarrierUnsealRequest{TenantId: "t1"})
		require.Error(t, err)
	})

	t.Run("returns error when tenant_id is empty", func(t *testing.T) {
		_, err := svc.TenantBarrierUnseal(context.Background(), &pb.TenantBarrierUnsealRequest{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when tenant not found", func(t *testing.T) {
		_, err := svc.TenantBarrierUnseal(context.Background(), &pb.TenantBarrierUnsealRequest{TenantId: "nonexistent"})
		require.Error(t, err)
	})

	// TestTenantBarrierUnseal/succeeds_for_existing_tenant is intentionally
	// absent here for the same reason as TenantBarrierInit's: it requires
	// go-qrdb's pooled per-tenant storage. That success path (including the
	// idempotent already-unsealed short-circuit) is covered against a fake
	// TenantServicer in pkg/xkms/servicer_tenant_delegation_test.go
	// (TestTenantBarrierUnseal_DelegatesKeyAndShare).
}

// TestMapTenantError_Denials verifies that go-qrdb tenant entitlement /
// barrier-mode / quota denials map to precise gRPC codes instead of Internal.
func TestMapTenantError_Denials(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"entitlement denied", &qrdbsdk.EntitlementError{TenantID: "t1", Feature: "barrier_mode:shamir"}, codes.PermissionDenied},
		{"shared barrier immutable", qrdbsdk.ErrSharedBarrierImmutable, codes.FailedPrecondition},
		{"quota exceeded", qrdbsdk.NewQuotaExceededError("keys", "ns", "t1", 10, 10, 1), codes.ResourceExhausted},
		{"unknown error", errors.New("boom"), codes.Internal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapTenantError(tt.err, "op")
			if status.Code(got) != tt.want {
				t.Errorf("mapTenantError code = %v, want %v", status.Code(got), tt.want)
			}
		})
	}

	if mapTenantError(nil, "op") != nil {
		t.Error("mapTenantError(nil) must return nil")
	}
}
