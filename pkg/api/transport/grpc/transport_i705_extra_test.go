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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// This file covers (go-xkms #705, batch A): the leader-redirect wire contract
// (leaderAPIAddressFromError / notLeaderInterceptor), the tenant entitlement
// / quota proto mapping helpers, the ClaimShareComplete stub branches, and
// Connect's success path, none of which had a test.

// --- leaderAPIAddressFromError: the NOT_LEADER detection contract ---

func notLeaderStatus(t *testing.T, reason, addr string) error {
	t.Helper()
	st := status.New(codes.FailedPrecondition, "not leader")
	info := &errdetails.ErrorInfo{Reason: reason}
	if addr != "" {
		info.Metadata = map[string]string{leaderAPIAddressAnnotationKey: addr}
	}
	withDetails, err := st.WithDetails(info)
	require.NoError(t, err)
	return withDetails.Err()
}

func TestLeaderAPIAddressFromError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantAddr string
		wantOK   bool
	}{
		{"nil error", nil, "", false},
		{"non-status error", errors.New("boom"), "", false},
		{"wrong code", status.Error(codes.Internal, "internal"), "", false},
		{"failed precondition without details", status.Error(codes.FailedPrecondition, "no details"), "", false},
		{"wrong reason", notLeaderStatus(t, "SOME_OTHER_REASON", "10.0.0.1:9443"), "", false},
		{"not leader without address", notLeaderStatus(t, notLeaderReason, ""), "", false},
		{"not leader with address", notLeaderStatus(t, notLeaderReason, "10.0.0.1:9443"), "10.0.0.1:9443", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr, ok := leaderAPIAddressFromError(tc.err)
			assert.Equal(t, tc.wantAddr, addr)
			assert.Equal(t, tc.wantOK, ok)
		})
	}
}

// --- notLeaderInterceptor: the single-hop redirect-and-retry ---

func TestNotLeaderInterceptor_PassesThroughSuccess(t *testing.T) {
	tr := &Transport{credsOpt: grpc.WithTransportCredentials(insecure.NewCredentials())}
	calls := 0
	invoker := func(_ context.Context, _ string, _, _ interface{}, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
		calls++
		return nil
	}
	err := tr.notLeaderInterceptor(context.Background(), "/xkmsv1.KeystoreService/Health", nil, nil, nil, invoker)
	require.NoError(t, err)
	assert.Equal(t, 1, calls, "a successful call never redials")
}

func TestNotLeaderInterceptor_PassesThroughUnrelatedError(t *testing.T) {
	tr := &Transport{credsOpt: grpc.WithTransportCredentials(insecure.NewCredentials())}
	calls := 0
	wantErr := status.Error(codes.Unavailable, "down")
	invoker := func(_ context.Context, _ string, _, _ interface{}, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
		calls++
		return wantErr
	}
	err := tr.notLeaderInterceptor(context.Background(), "/xkmsv1.KeystoreService/Health", nil, nil, nil, invoker)
	assert.Equal(t, wantErr, err)
	assert.Equal(t, 1, calls, "an error that is not NOT_LEADER never redials")
}

func TestNotLeaderInterceptor_RedialsAndRetriesOnce(t *testing.T) {
	// A real listener so grpc.NewClient's target resolves; the interceptor
	// never actually needs to complete an RPC on it because the fake invoker
	// is what the test observes.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = lis.Close() }()

	tr := &Transport{credsOpt: grpc.WithTransportCredentials(insecure.NewCredentials())}

	var seenConns []*grpc.ClientConn
	first := true
	invoker := func(_ context.Context, _ string, _, _ interface{}, cc *grpc.ClientConn, _ ...grpc.CallOption) error {
		seenConns = append(seenConns, cc)
		if first {
			first = false
			return notLeaderStatus(t, notLeaderReason, lis.Addr().String())
		}
		return nil
	}

	err = tr.notLeaderInterceptor(context.Background(), "/xkmsv1.KeystoreService/GenerateKey", nil, nil, nil, invoker)
	require.NoError(t, err, "the retry against the leader succeeds")
	require.Len(t, seenConns, 2, "exactly one retry: the original call plus one redial")
	assert.Nil(t, seenConns[0], "the first invocation uses the caller's original connection unchanged")
	assert.NotNil(t, seenConns[1], "the retry runs against a freshly dialed leader connection")
}

func TestNotLeaderInterceptor_DialFailureReturnsOriginalError(t *testing.T) {
	tr := &Transport{credsOpt: grpc.WithTransportCredentials(insecure.NewCredentials())}
	original := notLeaderStatus(t, notLeaderReason, "\x7f:::not-a-valid-target")
	invoker := func(_ context.Context, _ string, _, _ interface{}, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
		return original
	}
	err := tr.notLeaderInterceptor(context.Background(), "/xkmsv1.KeystoreService/GenerateKey", nil, nil, nil, invoker)
	assert.Equal(t, original, err, "a redial that cannot even be dialed surfaces the original typed error")
}

// --- tenant_mapping: the wire DTO <-> proto round trip ---

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

// --- ClaimShareComplete: gRPC never implements this endpoint ---

func TestClaimShareComplete_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).ClaimShareComplete(context.Background(), &transport.ClaimShareCompleteRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestClaimShareComplete_NotSupportedWhenConnected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	tr.connected = true
	_, err := tr.ClaimShareComplete(context.Background(), &transport.ClaimShareCompleteRequest{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

// --- Connect: the success path, never exercised before this ---

func TestConnect_Success(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	pb.RegisterKeystoreServiceServer(srv, &mockKeystoreServer{})
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	cfg := transport.DefaultConfig()
	cfg.TLSEnabled = false
	cfg.Address = lis.Addr().String()

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.NoError(t, err)
	defer func() { _ = tr.Close() }()

	assert.NotNil(t, tr.Conn())
	assert.NotNil(t, tr.Client())
	resp, err := tr.Health(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "healthy", resp.Status)
}

func TestConnect_Success_DialFailure(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.TLSEnabled = false
	cfg.Address = "\x7f:::not-a-valid-target"

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConnectionFailed)
}
