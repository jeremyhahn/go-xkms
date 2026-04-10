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

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/custodian"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/sharestore"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// setupCustodianService creates a real custodian service backed by an in-memory store.
func setupCustodianService(t *testing.T) *custodian.Service {
	t.Helper()
	store := custodian.NewMemoryStore()
	svc, err := custodian.NewService(store)
	require.NoError(t, err)
	return svc
}

// setupShareStore creates an in-memory share store.
func setupShareStore(t *testing.T) sharestore.ShareStore {
	t.Helper()
	return sharestore.NewMemoryShareStore()
}

// setupBarrierRegistry creates an initialized barrier registry.
func setupBarrierRegistry(t *testing.T) *seal.BarrierRegistry {
	t.Helper()
	return testTenantRegistry(t)
}

func TestSetCustodianService_GetCustodianService(t *testing.T) {
	old := GetCustodianService()
	defer SetCustodianService(old)

	t.Run("sets and gets custodian service", func(t *testing.T) {
		svc := setupCustodianService(t)
		SetCustodianService(svc)
		assert.Equal(t, svc, GetCustodianService())
	})

	t.Run("returns nil when not set", func(t *testing.T) {
		SetCustodianService(nil)
		assert.Nil(t, GetCustodianService())
	})
}

func TestSetShareStore_GetShareStore(t *testing.T) {
	old := GetShareStore()
	defer SetShareStore(old)

	t.Run("sets and gets share store", func(t *testing.T) {
		ss := setupShareStore(t)
		SetShareStore(ss)
		assert.Equal(t, ss, GetShareStore())
	})

	t.Run("returns nil when not set", func(t *testing.T) {
		SetShareStore(nil)
		assert.Nil(t, GetShareStore())
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
		err := mapCustodianError(custodian.ErrGroupNotFound, "get group")
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
		err := mapShareError(sharestore.ErrShareNotFound, "get share")
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
	group := &custodian.CustodianGroup{
		ID:        "group-1",
		Name:      "Test Group",
		Purpose:   "barrier",
		Threshold: 2,
		Members: []custodian.CustodianMember{
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
	m := &custodian.CustodianMember{
		UserID:   "user-1",
		Username: "alice",
		Method:   "manual",
	}

	pb := custodianMemberToProto(m)
	assert.Equal(t, "user-1", pb.UserId)
	assert.Equal(t, "alice", pb.Name)
	assert.Equal(t, "manual", pb.Role)
}

func TestShareEntryToProto(t *testing.T) {
	now := time.Now().UTC()
	entry := &sharestore.ShareEntry{
		GroupID:    "group-1",
		ServerURL:  "https://server.example.com",
		GroupName:  "Test Group",
		ShareIndex: 1,
		Purpose:    "barrier",
		TenantID:   "tenant-1",
		ReceivedAt: now,
	}

	pb := shareEntryToProto(entry)
	assert.Equal(t, "group-1", pb.GroupId)
	assert.Equal(t, "https://server.example.com", pb.ServerUrl)
	assert.Equal(t, "Test Group", pb.GroupName)
	assert.Equal(t, int32(1), pb.ShareIndex)
	assert.Equal(t, "barrier", pb.Purpose)
	assert.Equal(t, "tenant-1", pb.TenantId)
}

// --- Custodian Group Operations ---

func TestCreateCustodianGroup(t *testing.T) {
	svc := NewService(nil, nil)

	t.Run("returns error when service not configured", func(t *testing.T) {
		old := GetCustodianService()
		SetCustodianService(nil)
		defer SetCustodianService(old)

		_, err := svc.CreateCustodianGroup(context.Background(), &pb.CreateCustodianGroupRequest{
			Name: "test", Threshold: 2,
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error when name is empty", func(t *testing.T) {
		old := GetCustodianService()
		SetCustodianService(setupCustodianService(t))
		defer SetCustodianService(old)

		_, err := svc.CreateCustodianGroup(context.Background(), &pb.CreateCustodianGroupRequest{
			Name: "", Threshold: 2,
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when threshold is invalid", func(t *testing.T) {
		old := GetCustodianService()
		SetCustodianService(setupCustodianService(t))
		defer SetCustodianService(old)

		_, err := svc.CreateCustodianGroup(context.Background(), &pb.CreateCustodianGroupRequest{
			Name: "test", Threshold: 0,
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns mapped error when custodian service returns domain error", func(t *testing.T) {
		old := GetCustodianService()
		SetCustodianService(setupCustodianService(t))
		defer SetCustodianService(old)

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
	svc := NewService(nil, nil)

	t.Run("returns error when service not configured", func(t *testing.T) {
		old := GetCustodianService()
		SetCustodianService(nil)
		defer SetCustodianService(old)

		_, err := svc.GetCustodianGroup(context.Background(), &pb.GetCustodianGroupRequest{GroupId: "id"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error when group_id is empty", func(t *testing.T) {
		old := GetCustodianService()
		SetCustodianService(setupCustodianService(t))
		defer SetCustodianService(old)

		_, err := svc.GetCustodianGroup(context.Background(), &pb.GetCustodianGroupRequest{GroupId: ""})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when group not found", func(t *testing.T) {
		old := GetCustodianService()
		SetCustodianService(setupCustodianService(t))
		defer SetCustodianService(old)

		_, err := svc.GetCustodianGroup(context.Background(), &pb.GetCustodianGroupRequest{GroupId: "nonexistent"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("returns group on success", func(t *testing.T) {
		old := GetCustodianService()
		cs := setupCustodianService(t)
		SetCustodianService(cs)
		defer SetCustodianService(old)

		group, err := cs.CreateGroup(context.Background(), "grp-1", "tenant-1", "test", "barrier", 2, 2)
		require.NoError(t, err)

		resp, err := svc.GetCustodianGroup(context.Background(), &pb.GetCustodianGroupRequest{GroupId: group.ID})
		require.NoError(t, err)
		assert.Equal(t, group.ID, resp.Group.Id)
	})
}

func TestListCustodianGroups(t *testing.T) {
	svc := NewService(nil, nil)

	t.Run("returns error when service not configured", func(t *testing.T) {
		old := GetCustodianService()
		SetCustodianService(nil)
		defer SetCustodianService(old)

		_, err := svc.ListCustodianGroups(context.Background(), &pb.ListCustodianGroupsRequest{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns empty list", func(t *testing.T) {
		old := GetCustodianService()
		SetCustodianService(setupCustodianService(t))
		defer SetCustodianService(old)

		resp, err := svc.ListCustodianGroups(context.Background(), &pb.ListCustodianGroupsRequest{})
		require.NoError(t, err)
		assert.Empty(t, resp.Groups)
	})

	t.Run("returns populated list", func(t *testing.T) {
		old := GetCustodianService()
		cs := setupCustodianService(t)
		SetCustodianService(cs)
		defer SetCustodianService(old)

		_, err := cs.CreateGroup(context.Background(), "grp-list-1", "", "g1", "barrier", 2, 2)
		require.NoError(t, err)

		resp, err := svc.ListCustodianGroups(context.Background(), &pb.ListCustodianGroupsRequest{})
		require.NoError(t, err)
		assert.Len(t, resp.Groups, 1)
	})
}

func TestDeleteCustodianGroup(t *testing.T) {
	svc := NewService(nil, nil)

	t.Run("returns error when service not configured", func(t *testing.T) {
		old := GetCustodianService()
		SetCustodianService(nil)
		defer SetCustodianService(old)

		_, err := svc.DeleteCustodianGroup(context.Background(), &pb.DeleteCustodianGroupRequest{GroupId: "id"})
		require.Error(t, err)
	})

	t.Run("returns error when group_id is empty", func(t *testing.T) {
		old := GetCustodianService()
		SetCustodianService(setupCustodianService(t))
		defer SetCustodianService(old)

		_, err := svc.DeleteCustodianGroup(context.Background(), &pb.DeleteCustodianGroupRequest{GroupId: ""})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("deletes group on success", func(t *testing.T) {
		old := GetCustodianService()
		cs := setupCustodianService(t)
		SetCustodianService(cs)
		defer SetCustodianService(old)

		group, err := cs.CreateGroup(context.Background(), "grp-del-1", "", "test", "barrier", 2, 2)
		require.NoError(t, err)

		_, err = svc.DeleteCustodianGroup(context.Background(), &pb.DeleteCustodianGroupRequest{GroupId: group.ID})
		require.NoError(t, err)
	})
}

func TestAddCustodianMember(t *testing.T) {
	svc := NewService(nil, nil)

	t.Run("returns error when service not configured", func(t *testing.T) {
		old := GetCustodianService()
		SetCustodianService(nil)
		defer SetCustodianService(old)

		_, err := svc.AddCustodianMember(context.Background(), &pb.AddCustodianMemberRequest{
			GroupId: "g1", UserId: "u1",
		})
		require.Error(t, err)
	})

	t.Run("returns error when group_id is empty", func(t *testing.T) {
		old := GetCustodianService()
		SetCustodianService(setupCustodianService(t))
		defer SetCustodianService(old)

		_, err := svc.AddCustodianMember(context.Background(), &pb.AddCustodianMemberRequest{
			UserId: "u1",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when user_id is empty", func(t *testing.T) {
		old := GetCustodianService()
		SetCustodianService(setupCustodianService(t))
		defer SetCustodianService(old)

		_, err := svc.AddCustodianMember(context.Background(), &pb.AddCustodianMemberRequest{
			GroupId: "g1",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("adds member on success", func(t *testing.T) {
		old := GetCustodianService()
		cs := setupCustodianService(t)
		SetCustodianService(cs)
		defer SetCustodianService(old)

		group, err := cs.CreateGroup(context.Background(), "grp-add-1", "", "test", "barrier", 2, 2)
		require.NoError(t, err)

		resp, err := svc.AddCustodianMember(context.Background(), &pb.AddCustodianMemberRequest{
			GroupId: group.ID, UserId: "user-1", Name: "alice",
		})
		require.NoError(t, err)
		assert.Equal(t, "user-1", resp.Member.UserId)
		assert.Equal(t, "alice", resp.Member.Name)
		assert.Equal(t, custodian.MethodManual, resp.Member.Role)
	})
}

func TestRemoveCustodianMember(t *testing.T) {
	svc := NewService(nil, nil)

	t.Run("returns error when service not configured", func(t *testing.T) {
		old := GetCustodianService()
		SetCustodianService(nil)
		defer SetCustodianService(old)

		_, err := svc.RemoveCustodianMember(context.Background(), &pb.RemoveCustodianMemberRequest{
			GroupId: "g1", UserId: "u1",
		})
		require.Error(t, err)
	})

	t.Run("returns error when group_id is empty", func(t *testing.T) {
		old := GetCustodianService()
		SetCustodianService(setupCustodianService(t))
		defer SetCustodianService(old)

		_, err := svc.RemoveCustodianMember(context.Background(), &pb.RemoveCustodianMemberRequest{
			UserId: "u1",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when user_id is empty", func(t *testing.T) {
		old := GetCustodianService()
		SetCustodianService(setupCustodianService(t))
		defer SetCustodianService(old)

		_, err := svc.RemoveCustodianMember(context.Background(), &pb.RemoveCustodianMemberRequest{
			GroupId: "g1",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("removes member on success", func(t *testing.T) {
		old := GetCustodianService()
		cs := setupCustodianService(t)
		SetCustodianService(cs)
		defer SetCustodianService(old)

		group, err := cs.CreateGroup(context.Background(), "grp-rem-1", "", "test", "barrier", 2, 2)
		require.NoError(t, err)
		_, err = cs.AddMember(context.Background(), group.ID, "user-1", "alice", "manual")
		require.NoError(t, err)

		_, err = svc.RemoveCustodianMember(context.Background(), &pb.RemoveCustodianMemberRequest{
			GroupId: group.ID, UserId: "user-1",
		})
		require.NoError(t, err)
	})
}

func TestDistributeShares(t *testing.T) {
	svc := NewService(nil, nil)

	t.Run("returns error when service not configured", func(t *testing.T) {
		old := GetCustodianService()
		SetCustodianService(nil)
		defer SetCustodianService(old)

		_, err := svc.DistributeShares(context.Background(), &pb.DistributeSharesRequest{GroupId: "g1"})
		require.Error(t, err)
	})

	t.Run("returns error when group_id is empty", func(t *testing.T) {
		old := GetCustodianService()
		SetCustodianService(setupCustodianService(t))
		defer SetCustodianService(old)

		_, err := svc.DistributeShares(context.Background(), &pb.DistributeSharesRequest{GroupId: ""})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

// --- Share Operations ---

func TestSubmitShare(t *testing.T) {
	svc := NewService(nil, nil)

	t.Run("returns error when share store not configured", func(t *testing.T) {
		old := GetShareStore()
		SetShareStore(nil)
		defer SetShareStore(old)

		_, err := svc.SubmitShare(context.Background(), &pb.SubmitShareRequest{
			GroupId: "g1", ShareData: "data", ServerUrl: "https://example.com",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error when group_id is empty", func(t *testing.T) {
		old := GetShareStore()
		SetShareStore(setupShareStore(t))
		defer SetShareStore(old)

		_, err := svc.SubmitShare(context.Background(), &pb.SubmitShareRequest{
			ShareData: "data", ServerUrl: "https://example.com",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when share_data is empty", func(t *testing.T) {
		old := GetShareStore()
		SetShareStore(setupShareStore(t))
		defer SetShareStore(old)

		_, err := svc.SubmitShare(context.Background(), &pb.SubmitShareRequest{
			GroupId: "g1", ServerUrl: "https://example.com",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when server_url is empty", func(t *testing.T) {
		old := GetShareStore()
		SetShareStore(setupShareStore(t))
		defer SetShareStore(old)

		_, err := svc.SubmitShare(context.Background(), &pb.SubmitShareRequest{
			GroupId: "g1", ShareData: "data",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("submits share on success", func(t *testing.T) {
		old := GetShareStore()
		SetShareStore(setupShareStore(t))
		defer SetShareStore(old)

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
	svc := NewService(nil, nil)

	t.Run("returns error when share store not configured", func(t *testing.T) {
		old := GetShareStore()
		SetShareStore(nil)
		defer SetShareStore(old)

		_, err := svc.ListShares(context.Background(), &pb.ListSharesRequest{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns empty list", func(t *testing.T) {
		old := GetShareStore()
		SetShareStore(setupShareStore(t))
		defer SetShareStore(old)

		resp, err := svc.ListShares(context.Background(), &pb.ListSharesRequest{})
		require.NoError(t, err)
		assert.Empty(t, resp.Shares)
	})

	t.Run("returns shares after submit", func(t *testing.T) {
		old := GetShareStore()
		ss := setupShareStore(t)
		SetShareStore(ss)
		defer SetShareStore(old)

		err := ss.Save(context.Background(), &sharestore.ShareEntry{
			ServerURL:  "https://example.com",
			GroupID:    "g1",
			GroupName:  "group-1",
			ShareData:  []byte("share-data"),
			ReceivedAt: time.Now().UTC(),
		})
		require.NoError(t, err)

		resp, err := svc.ListShares(context.Background(), &pb.ListSharesRequest{})
		require.NoError(t, err)
		assert.Len(t, resp.Shares, 1)
	})
}

func TestGetShareCollectionStatus(t *testing.T) {
	svc := NewService(nil, nil)

	t.Run("returns error when share store not configured", func(t *testing.T) {
		old := GetShareStore()
		SetShareStore(nil)
		defer SetShareStore(old)

		_, err := svc.GetShareCollectionStatus(context.Background(), &pb.GetShareCollectionStatusRequest{GroupId: "g1"})
		require.Error(t, err)
	})

	t.Run("returns error when group_id is empty", func(t *testing.T) {
		old := GetShareStore()
		SetShareStore(setupShareStore(t))
		defer SetShareStore(old)

		_, err := svc.GetShareCollectionStatus(context.Background(), &pb.GetShareCollectionStatusRequest{GroupId: ""})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns status with zero collected", func(t *testing.T) {
		old := GetShareStore()
		SetShareStore(setupShareStore(t))
		defer SetShareStore(old)

		resp, err := svc.GetShareCollectionStatus(context.Background(), &pb.GetShareCollectionStatusRequest{GroupId: "g1"})
		require.NoError(t, err)
		assert.Equal(t, "g1", resp.GroupId)
		assert.Equal(t, int32(0), resp.Collected)
	})

	t.Run("returns status with collected count and threshold from custodian", func(t *testing.T) {
		oldSS := GetShareStore()
		oldCS := GetCustodianService()
		ss := setupShareStore(t)
		cs := setupCustodianService(t)
		SetShareStore(ss)
		SetCustodianService(cs)
		defer func() {
			SetShareStore(oldSS)
			SetCustodianService(oldCS)
		}()

		group, err := cs.CreateGroup(context.Background(), "grp-share-1", "", "test", "barrier", 2, 2)
		require.NoError(t, err)

		// Add shares for this group
		for i := 0; i < 2; i++ {
			err := ss.Save(context.Background(), &sharestore.ShareEntry{
				ServerURL:  "https://example.com",
				GroupID:    group.ID,
				GroupName:  "test",
				ShareIndex: i,
				ShareData:  []byte("share-data"),
				ReceivedAt: time.Now().UTC(),
			})
			require.NoError(t, err)
		}

		resp, err := svc.GetShareCollectionStatus(context.Background(), &pb.GetShareCollectionStatusRequest{GroupId: group.ID})
		require.NoError(t, err)
		assert.Equal(t, int32(2), resp.Collected)
		assert.Equal(t, int32(2), resp.Required)
		assert.True(t, resp.Complete)
	})
}

// --- Tenant Operations ---

func TestCreateTenant(t *testing.T) {
	svc := NewService(nil, nil)

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
	svc := NewService(nil, nil)

	t.Run("returns error when registry not configured", func(t *testing.T) {
		old := GetBarrierRegistry()
		SetBarrierRegistry(nil)
		defer SetBarrierRegistry(old)

		_, err := svc.GetTenant(context.Background(), &pb.GetTenantRequest{TenantId: "t1"})
		require.Error(t, err)
	})

	t.Run("returns error when tenant_id is empty", func(t *testing.T) {
		old := GetBarrierRegistry()
		SetBarrierRegistry(setupBarrierRegistry(t))
		defer SetBarrierRegistry(old)

		_, err := svc.GetTenant(context.Background(), &pb.GetTenantRequest{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when tenant not found", func(t *testing.T) {
		old := GetBarrierRegistry()
		SetBarrierRegistry(setupBarrierRegistry(t))
		defer SetBarrierRegistry(old)

		_, err := svc.GetTenant(context.Background(), &pb.GetTenantRequest{TenantId: "nonexistent"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("returns tenant on success", func(t *testing.T) {
		old := GetBarrierRegistry()
		reg := setupBarrierRegistry(t)
		SetBarrierRegistry(reg)
		defer SetBarrierRegistry(old)

		testTenantRegisteredTenant(t, reg, "my-tenant")

		resp, err := svc.GetTenant(context.Background(), &pb.GetTenantRequest{TenantId: "my-tenant"})
		require.NoError(t, err)
		assert.Equal(t, "my-tenant", resp.Tenant.Id)
	})
}

func TestListTenants(t *testing.T) {
	svc := NewService(nil, nil)

	t.Run("returns error when registry not configured", func(t *testing.T) {
		old := GetBarrierRegistry()
		SetBarrierRegistry(nil)
		defer SetBarrierRegistry(old)

		_, err := svc.ListTenants(context.Background(), &pb.ListTenantsRequest{})
		require.Error(t, err)
	})

	t.Run("returns empty list", func(t *testing.T) {
		old := GetBarrierRegistry()
		SetBarrierRegistry(setupBarrierRegistry(t))
		defer SetBarrierRegistry(old)

		resp, err := svc.ListTenants(context.Background(), &pb.ListTenantsRequest{})
		require.NoError(t, err)
		assert.Empty(t, resp.Tenants)
	})

	t.Run("returns populated list", func(t *testing.T) {
		old := GetBarrierRegistry()
		reg := setupBarrierRegistry(t)
		SetBarrierRegistry(reg)
		defer SetBarrierRegistry(old)

		testTenantRegisteredTenant(t, reg, "tenant-a")
		testTenantRegisteredTenant(t, reg, "tenant-b")

		resp, err := svc.ListTenants(context.Background(), &pb.ListTenantsRequest{})
		require.NoError(t, err)
		assert.Len(t, resp.Tenants, 2)
	})
}

func TestDeleteTenant(t *testing.T) {
	svc := NewService(nil, nil)

	t.Run("returns error when registry not configured", func(t *testing.T) {
		old := GetBarrierRegistry()
		SetBarrierRegistry(nil)
		defer SetBarrierRegistry(old)

		_, err := svc.DeleteTenant(context.Background(), &pb.DeleteTenantRequest{TenantId: "t1"})
		require.Error(t, err)
	})

	t.Run("returns error when tenant_id is empty", func(t *testing.T) {
		old := GetBarrierRegistry()
		SetBarrierRegistry(setupBarrierRegistry(t))
		defer SetBarrierRegistry(old)

		_, err := svc.DeleteTenant(context.Background(), &pb.DeleteTenantRequest{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("deletes tenant on success", func(t *testing.T) {
		old := GetBarrierRegistry()
		reg := setupBarrierRegistry(t)
		SetBarrierRegistry(reg)
		defer SetBarrierRegistry(old)

		testTenantRegisteredTenant(t, reg, "del-tenant")

		_, err := svc.DeleteTenant(context.Background(), &pb.DeleteTenantRequest{TenantId: "del-tenant"})
		require.NoError(t, err)
	})
}

func TestTenantBarrierInit(t *testing.T) {
	svc := NewService(nil, nil)

	t.Run("returns error when registry not configured", func(t *testing.T) {
		old := GetBarrierRegistry()
		SetBarrierRegistry(nil)
		defer SetBarrierRegistry(old)

		_, err := svc.TenantBarrierInit(context.Background(), &pb.TenantBarrierInitRequest{TenantId: "t1"})
		require.Error(t, err)
	})

	t.Run("returns error when tenant_id is empty", func(t *testing.T) {
		old := GetBarrierRegistry()
		SetBarrierRegistry(setupBarrierRegistry(t))
		defer SetBarrierRegistry(old)

		_, err := svc.TenantBarrierInit(context.Background(), &pb.TenantBarrierInitRequest{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when tenant not found", func(t *testing.T) {
		old := GetBarrierRegistry()
		SetBarrierRegistry(setupBarrierRegistry(t))
		defer SetBarrierRegistry(old)

		_, err := svc.TenantBarrierInit(context.Background(), &pb.TenantBarrierInitRequest{TenantId: "nonexistent"})
		require.Error(t, err)
	})

	t.Run("succeeds for existing tenant", func(t *testing.T) {
		old := GetBarrierRegistry()
		reg := setupBarrierRegistry(t)
		SetBarrierRegistry(reg)
		defer SetBarrierRegistry(old)

		testTenantRegisteredTenant(t, reg, "init-tenant")

		_, err := svc.TenantBarrierInit(context.Background(), &pb.TenantBarrierInitRequest{TenantId: "init-tenant"})
		require.NoError(t, err)
	})
}

func TestTenantBarrierUnseal(t *testing.T) {
	svc := NewService(nil, nil)

	t.Run("returns error when registry not configured", func(t *testing.T) {
		old := GetBarrierRegistry()
		SetBarrierRegistry(nil)
		defer SetBarrierRegistry(old)

		_, err := svc.TenantBarrierUnseal(context.Background(), &pb.TenantBarrierUnsealRequest{TenantId: "t1"})
		require.Error(t, err)
	})

	t.Run("returns error when tenant_id is empty", func(t *testing.T) {
		old := GetBarrierRegistry()
		SetBarrierRegistry(setupBarrierRegistry(t))
		defer SetBarrierRegistry(old)

		_, err := svc.TenantBarrierUnseal(context.Background(), &pb.TenantBarrierUnsealRequest{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns error when tenant not found", func(t *testing.T) {
		old := GetBarrierRegistry()
		SetBarrierRegistry(setupBarrierRegistry(t))
		defer SetBarrierRegistry(old)

		_, err := svc.TenantBarrierUnseal(context.Background(), &pb.TenantBarrierUnsealRequest{TenantId: "nonexistent"})
		require.Error(t, err)
	})

	t.Run("succeeds for existing tenant", func(t *testing.T) {
		old := GetBarrierRegistry()
		reg := setupBarrierRegistry(t)
		SetBarrierRegistry(reg)
		defer SetBarrierRegistry(old)

		testTenantRegisteredTenant(t, reg, "unseal-tenant")

		_, err := svc.TenantBarrierUnseal(context.Background(), &pb.TenantBarrierUnsealRequest{TenantId: "unseal-tenant"})
		require.NoError(t, err)
	})
}

// --- Barrier Registry helper with in-memory storage ---

func testBarrierRegistryWithTenant(t *testing.T) (*seal.BarrierRegistry, string) {
	t.Helper()
	base := storage.NewMemory()
	b, err := seal.NewBarrier(
		discardLogger(),
		base,
		seal.BarrierConfig{
			RootKeyPath:     "core/seal",
			PreferenceOrder: []seal.StrategyID{seal.StrategySoftware},
		},
		seal.NewSoftwareStrategy(),
	)
	require.NoError(t, err)

	ctx := context.Background()
	err = b.Initialize(ctx, seal.Credentials{Secret: "test-password"})
	require.NoError(t, err)

	reg, err := seal.NewBarrierRegistry(b)
	require.NoError(t, err)

	// Register tenant
	tenantID := "test-tenant"
	_, err = reg.RegisterTenant(tenantID)
	require.NoError(t, err)
	err = reg.InitializeTenant(ctx, tenantID, seal.Credentials{Secret: "tenant-pw"})
	require.NoError(t, err)

	return reg, tenantID
}
