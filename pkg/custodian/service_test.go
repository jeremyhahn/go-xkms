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

package custodian

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	store := NewMemoryStore()
	svc, err := NewService(store)
	require.NoError(t, err)
	return svc
}

func TestNewService(t *testing.T) {
	t.Run("creates service with valid store", func(t *testing.T) {
		store := NewMemoryStore()
		svc, err := NewService(store)
		require.NoError(t, err)
		assert.NotNil(t, svc)
	})

	t.Run("returns error with nil store", func(t *testing.T) {
		svc, err := NewService(nil)
		assert.ErrorIs(t, err, ErrNilStore)
		assert.Nil(t, svc)
	})
}

func TestService_CreateGroup(t *testing.T) {
	t.Run("creates valid group", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		group, err := svc.CreateGroup(ctx, "group-1", "tenant-1", "Barrier Group", PurposeBarrier, 2, 3)
		require.NoError(t, err)
		assert.Equal(t, "group-1", group.ID)
		assert.Equal(t, "tenant-1", group.TenantID)
		assert.Equal(t, "Barrier Group", group.Name)
		assert.Equal(t, PurposeBarrier, group.Purpose)
		assert.Equal(t, 2, group.Threshold)
		assert.Equal(t, 3, group.Total)
		assert.Empty(t, group.Members)
		assert.False(t, group.CreatedAt.IsZero())
		assert.False(t, group.UpdatedAt.IsZero())
	})

	t.Run("creates system-level group with empty tenant", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		group, err := svc.CreateGroup(ctx, "group-1", "", "System Group", PurposeBarrier, 2, 3)
		require.NoError(t, err)
		assert.Equal(t, "", group.TenantID)
	})

	t.Run("returns error for empty group ID", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		_, err := svc.CreateGroup(ctx, "", "tenant-1", "Test", PurposeBarrier, 2, 3)
		assert.ErrorIs(t, err, ErrEmptyGroupID)
	})

	t.Run("returns error for empty name", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		_, err := svc.CreateGroup(ctx, "group-1", "tenant-1", "", PurposeBarrier, 2, 3)
		assert.ErrorIs(t, err, ErrEmptyGroupName)
	})

	t.Run("returns error for empty purpose", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		_, err := svc.CreateGroup(ctx, "group-1", "tenant-1", "Test", "", 2, 3)
		assert.ErrorIs(t, err, ErrInvalidPurpose)
	})

	t.Run("returns error for invalid threshold", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		_, err := svc.CreateGroup(ctx, "group-1", "tenant-1", "Test", PurposeBarrier, 1, 3)
		assert.ErrorIs(t, err, ErrInvalidThreshold)
	})

	t.Run("returns error for total less than threshold", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		_, err := svc.CreateGroup(ctx, "group-1", "tenant-1", "Test", PurposeBarrier, 3, 2)
		assert.ErrorIs(t, err, ErrInvalidTotalShares)
	})

	t.Run("returns error for duplicate group ID", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		_, err := svc.CreateGroup(ctx, "group-1", "tenant-1", "Test", PurposeBarrier, 2, 3)
		require.NoError(t, err)

		_, err = svc.CreateGroup(ctx, "group-1", "tenant-1", "Test 2", PurposeBarrier, 2, 3)
		assert.ErrorIs(t, err, ErrGroupAlreadyExists)
	})
}

func TestService_GetGroup(t *testing.T) {
	t.Run("returns existing group", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		_, err := svc.CreateGroup(ctx, "group-1", "tenant-1", "Test", PurposeBarrier, 2, 3)
		require.NoError(t, err)

		group, err := svc.GetGroup(ctx, "group-1")
		require.NoError(t, err)
		assert.Equal(t, "group-1", group.ID)
	})

	t.Run("returns error for non-existing group", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		_, err := svc.GetGroup(ctx, "nonexistent")
		assert.ErrorIs(t, err, ErrGroupNotFound)
	})
}

func TestService_DeleteGroup(t *testing.T) {
	t.Run("deletes existing group", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		_, err := svc.CreateGroup(ctx, "group-1", "tenant-1", "Test", PurposeBarrier, 2, 3)
		require.NoError(t, err)

		err = svc.DeleteGroup(ctx, "group-1")
		require.NoError(t, err)

		_, err = svc.GetGroup(ctx, "group-1")
		assert.ErrorIs(t, err, ErrGroupNotFound)
	})

	t.Run("returns error for non-existing group", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		err := svc.DeleteGroup(ctx, "nonexistent")
		assert.ErrorIs(t, err, ErrGroupNotFound)
	})
}

func TestService_AddMember(t *testing.T) {
	t.Run("adds member successfully", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		_, err := svc.CreateGroup(ctx, "group-1", "", "Test", PurposeBarrier, 2, 3)
		require.NoError(t, err)

		member, err := svc.AddMember(ctx, "group-1", "user-1", "alice", MethodFIDO2)
		require.NoError(t, err)
		assert.Equal(t, 1, member.ShareIndex)
		assert.Equal(t, "user-1", member.UserID)
		assert.Equal(t, "alice", member.Username)
		assert.Equal(t, MethodFIDO2, member.Method)
		assert.False(t, member.AssignedAt.IsZero())
		assert.Nil(t, member.ReceivedAt)
	})

	t.Run("assigns sequential share indices", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		_, err := svc.CreateGroup(ctx, "group-1", "", "Test", PurposeBarrier, 2, 3)
		require.NoError(t, err)

		m1, err := svc.AddMember(ctx, "group-1", "user-1", "alice", MethodFIDO2)
		require.NoError(t, err)
		assert.Equal(t, 1, m1.ShareIndex)

		m2, err := svc.AddMember(ctx, "group-1", "user-2", "bob", MethodManual)
		require.NoError(t, err)
		assert.Equal(t, 2, m2.ShareIndex)
	})

	t.Run("returns error when group is full", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		_, err := svc.CreateGroup(ctx, "group-1", "", "Test", PurposeBarrier, 2, 2)
		require.NoError(t, err)

		_, err = svc.AddMember(ctx, "group-1", "user-1", "alice", MethodFIDO2)
		require.NoError(t, err)

		_, err = svc.AddMember(ctx, "group-1", "user-2", "bob", MethodFIDO2)
		require.NoError(t, err)

		_, err = svc.AddMember(ctx, "group-1", "user-3", "charlie", MethodFIDO2)
		assert.ErrorIs(t, err, ErrGroupFull)
	})

	t.Run("returns error for duplicate member", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		_, err := svc.CreateGroup(ctx, "group-1", "", "Test", PurposeBarrier, 2, 3)
		require.NoError(t, err)

		_, err = svc.AddMember(ctx, "group-1", "user-1", "alice", MethodFIDO2)
		require.NoError(t, err)

		_, err = svc.AddMember(ctx, "group-1", "user-1", "alice", MethodFIDO2)
		assert.ErrorIs(t, err, ErrMemberAlreadyExists)
	})

	t.Run("returns error for non-existing group", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		_, err := svc.AddMember(ctx, "nonexistent", "user-1", "alice", MethodFIDO2)
		assert.ErrorIs(t, err, ErrGroupNotFound)
	})

	t.Run("returns error for empty user ID", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		_, err := svc.CreateGroup(ctx, "group-1", "", "Test", PurposeBarrier, 2, 3)
		require.NoError(t, err)

		_, err = svc.AddMember(ctx, "group-1", "", "alice", MethodFIDO2)
		assert.ErrorIs(t, err, ErrEmptyUserID)
	})
}

func TestService_RemoveMember(t *testing.T) {
	t.Run("removes member successfully", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		_, err := svc.CreateGroup(ctx, "group-1", "", "Test", PurposeBarrier, 2, 3)
		require.NoError(t, err)

		_, err = svc.AddMember(ctx, "group-1", "user-1", "alice", MethodFIDO2)
		require.NoError(t, err)

		err = svc.RemoveMember(ctx, "group-1", "user-1")
		require.NoError(t, err)

		group, err := svc.GetGroup(ctx, "group-1")
		require.NoError(t, err)
		assert.Empty(t, group.Members)
	})

	t.Run("returns error for non-existing member", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		_, err := svc.CreateGroup(ctx, "group-1", "", "Test", PurposeBarrier, 2, 3)
		require.NoError(t, err)

		err = svc.RemoveMember(ctx, "group-1", "nonexistent")
		assert.ErrorIs(t, err, ErrMemberNotFound)
	})

	t.Run("returns error for non-existing group", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		err := svc.RemoveMember(ctx, "nonexistent", "user-1")
		assert.ErrorIs(t, err, ErrGroupNotFound)
	})

	t.Run("returns error for empty user ID", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		err := svc.RemoveMember(ctx, "group-1", "")
		assert.ErrorIs(t, err, ErrEmptyUserID)
	})
}

func TestService_MarkShareReceived(t *testing.T) {
	t.Run("marks share as received", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		_, err := svc.CreateGroup(ctx, "group-1", "", "Test", PurposeBarrier, 2, 3)
		require.NoError(t, err)

		_, err = svc.AddMember(ctx, "group-1", "user-1", "alice", MethodFIDO2)
		require.NoError(t, err)

		err = svc.MarkShareReceived(ctx, "group-1", "user-1")
		require.NoError(t, err)

		group, err := svc.GetGroup(ctx, "group-1")
		require.NoError(t, err)
		member := group.GetMember("user-1")
		require.NotNil(t, member)
		assert.True(t, member.HasReceived())
	})

	t.Run("returns error when already received", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		_, err := svc.CreateGroup(ctx, "group-1", "", "Test", PurposeBarrier, 2, 3)
		require.NoError(t, err)

		_, err = svc.AddMember(ctx, "group-1", "user-1", "alice", MethodFIDO2)
		require.NoError(t, err)

		err = svc.MarkShareReceived(ctx, "group-1", "user-1")
		require.NoError(t, err)

		err = svc.MarkShareReceived(ctx, "group-1", "user-1")
		assert.ErrorIs(t, err, ErrShareAlreadyReceived)
	})

	t.Run("returns error for non-existing member", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		_, err := svc.CreateGroup(ctx, "group-1", "", "Test", PurposeBarrier, 2, 3)
		require.NoError(t, err)

		err = svc.MarkShareReceived(ctx, "group-1", "nonexistent")
		assert.ErrorIs(t, err, ErrMemberNotFound)
	})

	t.Run("returns error for non-existing group", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		err := svc.MarkShareReceived(ctx, "nonexistent", "user-1")
		assert.ErrorIs(t, err, ErrGroupNotFound)
	})

	t.Run("returns error for empty user ID", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		err := svc.MarkShareReceived(ctx, "group-1", "")
		assert.ErrorIs(t, err, ErrEmptyUserID)
	})
}

func TestService_ListGroups(t *testing.T) {
	t.Run("returns all groups", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		_, err := svc.CreateGroup(ctx, "group-1", "", "Test 1", PurposeBarrier, 2, 3)
		require.NoError(t, err)
		_, err = svc.CreateGroup(ctx, "group-2", "", "Test 2", PurposeBackup, 2, 3)
		require.NoError(t, err)

		groups, err := svc.ListGroups(ctx)
		require.NoError(t, err)
		assert.Len(t, groups, 2)
	})

	t.Run("returns empty slice when no groups", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		groups, err := svc.ListGroups(ctx)
		require.NoError(t, err)
		assert.Empty(t, groups)
	})
}

func TestService_ListGroupsByTenant(t *testing.T) {
	t.Run("filters groups by tenant", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		_, err := svc.CreateGroup(ctx, "group-1", "tenant-a", "Test 1", PurposeBarrier, 2, 3)
		require.NoError(t, err)
		_, err = svc.CreateGroup(ctx, "group-2", "tenant-b", "Test 2", PurposeBarrier, 2, 3)
		require.NoError(t, err)
		_, err = svc.CreateGroup(ctx, "group-3", "tenant-a", "Test 3", PurposeBackup, 2, 3)
		require.NoError(t, err)

		groups, err := svc.ListGroupsByTenant(ctx, "tenant-a")
		require.NoError(t, err)
		assert.Len(t, groups, 2)
	})

	t.Run("returns empty for non-existing tenant", func(t *testing.T) {
		svc := newTestService(t)
		ctx := context.Background()

		groups, err := svc.ListGroupsByTenant(ctx, "nonexistent")
		require.NoError(t, err)
		assert.Empty(t, groups)
	})
}

func TestService_DistributeShares_Success(t *testing.T) {
	store := NewMemoryStore()
	svc, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	group, err := svc.CreateGroup(ctx, "grp-1", "", "Test Group", PurposeBarrier, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.AddMember(ctx, group.ID, "user-a", "alice", MethodFIDO2); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AddMember(ctx, group.ID, "user-b", "bob", MethodManual); err != nil {
		t.Fatal(err)
	}

	count, err := svc.DistributeShares(ctx, group.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 members, got %d", count)
	}
}

func TestService_DistributeShares_EmptyGroupID(t *testing.T) {
	store := NewMemoryStore()
	svc, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.DistributeShares(context.Background(), "")
	if err != ErrEmptyGroupID {
		t.Errorf("expected ErrEmptyGroupID, got %v", err)
	}
}

func TestService_DistributeShares_GroupNotFound(t *testing.T) {
	store := NewMemoryStore()
	svc, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.DistributeShares(context.Background(), "nonexistent")
	if err != ErrGroupNotFound {
		t.Errorf("expected ErrGroupNotFound, got %v", err)
	}
}

func TestService_DistributeShares_EmptyGroup(t *testing.T) {
	store := NewMemoryStore()
	svc, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	_, err = svc.CreateGroup(ctx, "grp-empty", "", "Empty Group", PurposeBarrier, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.DistributeShares(ctx, "grp-empty")
	if err != ErrGroupEmpty {
		t.Errorf("expected ErrGroupEmpty, got %v", err)
	}
}
