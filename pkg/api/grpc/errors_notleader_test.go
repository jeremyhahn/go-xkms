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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNotLeaderStatus_Translation(t *testing.T) {
	src := &qrdbtransport.NotLeaderError{ShardID: 7, LeaderID: 3, LeaderAddress: "10.0.0.3:63001"}
	err, ok := notLeaderStatus(&errs.Wrapped{Msg: "write", Err: src})
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

	var info *errdetails.ErrorInfo
	for _, d := range st.Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok {
			info = ei
		}
	}
	if info == nil {
		t.Fatal("status missing ErrorInfo detail")
	}
	if info.Reason != notLeaderReason {
		t.Fatalf("ErrorInfo.Reason = %q, want %q", info.Reason, notLeaderReason)
	}
	if info.Metadata["shard_id"] != "7" || info.Metadata["leader_id"] != "3" ||
		info.Metadata["leader_address"] != "10.0.0.3:63001" {
		t.Fatalf("ErrorInfo.Metadata = %v", info.Metadata)
	}
}

func TestNotLeaderStatus_NoMatch(t *testing.T) {
	if err, ok := notLeaderStatus(errors.New("boom")); ok || err != nil {
		t.Fatalf("notLeaderStatus(other) = (%v, %v), want (nil, false)", err, ok)
	}
}

func TestWrapWriteError_NotLeader(t *testing.T) {
	src := &qrdbtransport.NotLeaderError{ShardID: 1, LeaderID: 9, LeaderAddress: "n9:63001"}
	err := wrapWriteError(&errs.Wrapped{Msg: "generate key", Err: src}, codes.Internal, "failed to generate key: %v", src)

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (not Internal)", st.Code())
	}
}

func TestWrapWriteError_Fallback(t *testing.T) {
	err := wrapWriteError(errors.New("disk full"), codes.Internal, "failed to generate key: %v", "disk full")

	st, _ := status.FromError(err)
	if st.Code() != codes.Internal {
		t.Fatalf("code = %v, want Internal", st.Code())
	}
	if st.Message() != "failed to generate key: disk full" {
		t.Fatalf("message = %q", st.Message())
	}
}
