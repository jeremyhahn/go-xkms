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
	"fmt"
	"strconv"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// notLeaderReason is the ErrorInfo.Reason set on a not-leader gRPC status so
// clients can branch on it programmatically without parsing the message.
const notLeaderReason = "NOT_LEADER"

// notLeaderStatus converts an xkms.ErrNotLeader into a gRPC status error using
// codes.FailedPrecondition (the write cannot succeed on this node in its
// current, follower state) and attaches an ErrorInfo detail carrying the
// leader's coordinates. It returns (nil, false) when err is not a not-leader
// condition.
//
// TODO(cluster): transparent leader-forwarding needs a raft->API address map;
// until then the leader's Raft address is surfaced to the client as a hint.
func notLeaderStatus(err error) (error, bool) {
	nl, ok := xkms.AsNotLeader(err)
	if !ok {
		return nil, false
	}

	st := status.New(codes.FailedPrecondition, nl.Error())
	detail := &errdetails.ErrorInfo{
		Reason: notLeaderReason,
		Domain: "xkms.cluster",
		Metadata: map[string]string{
			"shard_id":       strconv.FormatUint(nl.ShardID, 10),
			"leader_id":      strconv.FormatUint(nl.LeaderID, 10),
			"leader_address": nl.LeaderAddress,
		},
	}
	if withDetails, derr := st.WithDetails(detail); derr == nil {
		st = withDetails
	}
	return st.Err(), true
}

// wrapWriteError translates an error returned from a write that touches the
// embedded qrdb client. A clustered not-leader condition becomes a
// FailedPrecondition status carrying the leader coordinates; every other error
// becomes a status with fallbackCode and the formatted message. Write handlers
// use this at the point they would otherwise restringify the servicer error,
// so the not-leader signal is preserved end to end (the error-handling
// interceptor also catches any raw not-leader error that slips through).
func wrapWriteError(err error, fallbackCode codes.Code, format string, args ...interface{}) error {
	if translated, ok := notLeaderStatus(err); ok {
		return translated
	}
	return status.Error(fallbackCode, fmt.Sprintf(format, args...))
}
