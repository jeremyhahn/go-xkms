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

package unix

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// This file covers (go-xkms #705, batch A) the tenant entitlement/quota proto
// mapping helpers and ClaimShareComplete, none of which had a test.

func TestTenantEntitlementsToPB(t *testing.T) {
	e := transport.TenantEntitlements{
		AllowedIsolationModes:     []string{"dedicated", "shared"},
		AllowDedicatedRaft:        true,
		AllowVolumeStorage:        true,
		AllowSystemManagedBarrier: false,
	}
	out := tenantEntitlementsToPB(e)
	require.NotNil(t, out)
	assert.Equal(t, []string{"dedicated", "shared"}, out.GetAllowedIsolationModes())
	assert.True(t, out.GetAllowDedicatedRaft())
	assert.True(t, out.GetAllowVolumeStorage())
	assert.False(t, out.GetAllowSystemManagedBarrier())
}

func TestTenantQuotasToPB(t *testing.T) {
	q := transport.TenantQuotas{
		MaxDatabases: 1, MaxRaftGroups: 2, MaxReplicasPerGroup: 3, MaxTotalReplicas: 4,
		MaxCollections: 5, MaxKeys: 6, MaxStorageBytes: 7, MaxDatabaseSizeBytes: 8,
		MaxUsers: 9, MaxRoles: 10, MaxCertificates: 11, MaxBackups: 12,
		MaxVectorDims: 13, MaxTSMetrics: 14,
	}
	out := tenantQuotasToPB(q)
	require.NotNil(t, out)
	assert.Equal(t, int64(1), out.GetMaxDatabases())
	assert.Equal(t, int64(6), out.GetMaxKeys())
	assert.Equal(t, int64(9), out.GetMaxUsers())
	assert.Equal(t, int64(14), out.GetMaxTsMetrics())
}

func TestPbTenantInfoToTransport_WithQuotasAndEntitlements(t *testing.T) {
	ti := &pb.TenantInfo{
		Id: "t-1", Name: "test",
		Quotas:       &pb.TenantQuotas{MaxKeys: 100, MaxUsers: 5},
		Entitlements: &pb.TenantEntitlements{AllowDedicatedRaft: true, AllowedIsolationModes: []string{"dedicated"}},
	}
	out := pbTenantInfoToTransport(ti)
	require.NotNil(t, out.Quotas)
	assert.Equal(t, int64(100), out.Quotas.MaxKeys)
	assert.Equal(t, int64(5), out.Quotas.MaxUsers)
	require.NotNil(t, out.Entitlements)
	assert.True(t, out.Entitlements.AllowDedicatedRaft)
	assert.Equal(t, []string{"dedicated"}, out.Entitlements.AllowedIsolationModes)
}

// --- ClaimShareComplete: served over the HTTP-over-unix-socket bridge ---

func TestClaimShareComplete_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).ClaimShareComplete(context.Background(), &transport.ClaimShareCompleteRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestClaimShareComplete_Connected(t *testing.T) {
	tr, cleanup := newHTTPOnlyTransport(t)
	defer cleanup()
	resp, err := tr.ClaimShareComplete(context.Background(), &transport.ClaimShareCompleteRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestClaimShareComplete_ServerError(t *testing.T) {
	tr := &Transport{
		config: transport.DefaultConfig(),
		httpClient: &http.Client{
			Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				rec := httptest.NewRecorder()
				rec.WriteHeader(http.StatusInternalServerError)
				_, _ = rec.WriteString(`{"error":"share not claimable"}`)
				return rec.Result(), nil
			}),
		},
		connected: true,
	}
	_, err := tr.ClaimShareComplete(context.Background(), &transport.ClaimShareCompleteRequest{})
	require.Error(t, err, "a non-2xx status must surface as an error, not a zero-value success")
}
