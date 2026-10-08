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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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
