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

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// grpcFakeClusterClient is a minimal xkms.ClusterClient double resolving the
// leader's API endpoint for the not-leader translation path.
type grpcFakeClusterClient struct {
	leaderEndpoint    string
	leaderEndpointErr error
}

func (f *grpcFakeClusterClient) LeaderEndpoint(context.Context, uint64, string) (string, error) {
	if f.leaderEndpointErr != nil {
		return "", f.leaderEndpointErr
	}
	return f.leaderEndpoint, nil
}

// setClusterClientForTest wires the fake cluster client into a fresh
// XKMSService so the not-leader translation can resolve leader endpoints.
func setClusterClientForTest(t *testing.T, c xkms.ClusterClient, shardID uint64) *xkms.XKMSService {
	t.Helper()
	svc := &xkms.XKMSService{}
	svc.SetClusterClient(c, shardID)
	return svc
}

func TestNotLeaderStatus_Translation(t *testing.T) {
	src := &qrdbtransport.NotLeaderError{ShardID: 7, LeaderID: 3, LeaderAddress: "10.0.0.3:63001"}
	err, ok := notLeaderStatus(context.Background(), nil, &errs.Wrapped{Msg: "write", Err: src})
	if !ok {
		t.Fatal("notLeaderStatus(NotLeaderError) ok = false, want true")
	}

	st, conv := status.FromError(err)
	if !conv {
		t.Fatal("returned error is not a gRPC status")
	}
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", st.Code())
	}

	info := notLeaderErrorInfo(t, st)
	if info.Reason != notLeaderReason {
		t.Fatalf("ErrorInfo.Reason = %q, want %q", info.Reason, notLeaderReason)
	}
	if info.Metadata["shard_id"] != "7" || info.Metadata["leader_id"] != "3" ||
		info.Metadata["leader_address"] != "10.0.0.3:63001" {
		t.Fatalf("ErrorInfo.Metadata = %v", info.Metadata)
	}
	if _, present := info.Metadata["leader_api_address"]; present {
		t.Fatalf("ErrorInfo.Metadata unexpectedly carries leader_api_address: %v", info.Metadata)
	}
}

func TestNotLeaderStatus_NoMatch(t *testing.T) {
	if err, ok := notLeaderStatus(context.Background(), nil, errors.New("boom")); ok || err != nil {
		t.Fatalf("notLeaderStatus(other) = (%v, %v), want (nil, false)", err, ok)
	}
}

// TestNotLeaderStatus_ResolvesAPIAddress covers the case the servicer's
// ClusterLeaderEndpoint successfully resolves the leader's dialable gRPC
// endpoint: the resolved address must be folded into the leader_api_address
// metadata key.
func TestNotLeaderStatus_ResolvesAPIAddress(t *testing.T) {
	reader := &grpcFakeClusterClient{
		leaderEndpoint: "10.0.0.3:9443",
	}
	xkmsSvc := setClusterClientForTest(t, reader, 7)

	src := &qrdbtransport.NotLeaderError{ShardID: 7, LeaderID: 3, LeaderAddress: "10.0.0.3:63001"}
	err, ok := notLeaderStatus(context.Background(), xkmsSvc, src)
	if !ok {
		t.Fatal("notLeaderStatus ok = false, want true")
	}

	st, _ := status.FromError(err)
	info := notLeaderErrorInfo(t, st)
	if info.Metadata["leader_api_address"] != "10.0.0.3:9443" {
		t.Fatalf("leader_api_address = %q, want %q", info.Metadata["leader_api_address"], "10.0.0.3:9443")
	}
}

// TestNotLeaderStatus_ResolutionFailureOmitsAPIAddress covers a
// ClusterLeaderEndpoint failure: it must not turn the not-leader condition
// into a harder failure, and leader_api_address must be omitted entirely
// rather than emitted empty.
func TestNotLeaderStatus_ResolutionFailureOmitsAPIAddress(t *testing.T) {
	reader := &grpcFakeClusterClient{
		leaderEndpointErr: errors.New("registry unreachable"),
	}
	xkmsSvc := setClusterClientForTest(t, reader, 7)

	src := &qrdbtransport.NotLeaderError{ShardID: 7, LeaderID: 3, LeaderAddress: "10.0.0.3:63001"}
	err, ok := notLeaderStatus(context.Background(), xkmsSvc, src)
	if !ok {
		t.Fatal("notLeaderStatus ok = false, want true")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", st.Code())
	}
	info := notLeaderErrorInfo(t, st)
	if _, present := info.Metadata["leader_api_address"]; present {
		t.Fatalf("ErrorInfo.Metadata unexpectedly carries leader_api_address after resolution failure: %v", info.Metadata)
	}
	if info.Metadata["leader_address"] != "10.0.0.3:63001" {
		t.Fatalf("leader_address = %q, want the Raft coordinates preserved", info.Metadata["leader_address"])
	}
}

func TestWrapWriteError_NotLeader(t *testing.T) {
	src := &qrdbtransport.NotLeaderError{ShardID: 1, LeaderID: 9, LeaderAddress: "n9:63001"}
	err := wrapWriteError(context.Background(), nil, &errs.Wrapped{Msg: "generate key", Err: src}, codes.Internal, "failed to generate key: %v", src)

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (not Internal)", st.Code())
	}
}

func TestWrapWriteError_Fallback(t *testing.T) {
	err := wrapWriteError(context.Background(), nil, errors.New("disk full"), codes.Internal, "failed to generate key: %v", "disk full")

	st, _ := status.FromError(err)
	if st.Code() != codes.Internal {
		t.Fatalf("code = %v, want Internal", st.Code())
	}
	if st.Message() != "failed to generate key: disk full" {
		t.Fatalf("message = %q", st.Message())
	}
}

// notLeaderErrorInfo extracts the ErrorInfo detail from a gRPC status,
// failing the test if it is absent.
func notLeaderErrorInfo(t *testing.T, st *status.Status) *errdetails.ErrorInfo {
	t.Helper()
	for _, d := range st.Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok {
			return ei
		}
	}
	t.Fatal("status missing ErrorInfo detail")
	return nil
}
