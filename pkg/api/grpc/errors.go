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
	"fmt"
	"strconv"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// ErrAuthenticatorRequired is returned by NewServer when ServerConfig carries no
// Authenticator. The constructor refuses to substitute a NoOp authenticator
// because doing so would silently disable authentication; a caller that really
// wants an unauthenticated server must pass auth.NewNoOpAuthenticator()
// explicitly.
var ErrAuthenticatorRequired = errors.New("grpc: authenticator is required")

// notLeaderReason is the ErrorInfo.Reason set on a not-leader gRPC status so
// clients can branch on it programmatically without parsing the message.
const notLeaderReason = "NOT_LEADER"

// notLeaderStatus converts an xkms.ErrNotLeader into a gRPC status error using
// codes.FailedPrecondition (the write cannot succeed on this node in its
// current, follower state) and attaches an ErrorInfo detail carrying the
// leader's coordinates. It returns (nil, false) when err is not a not-leader
// condition.
//
// AsNotLeader only ever returns the Raft-plane coordinates go-qrdb reports
// (ShardID/LeaderID/LeaderAddress); it never knows which API protocol carried
// the failed request, so it cannot fill in LeaderAPIAddress itself. This gRPC
// layer does know its own protocol, so when xkmsService is non-nil it resolves
// the leader's dialable gRPC endpoint here via XKMSService.ClusterLeaderEndpoint
// and folds it into the leader_api_address metadata key, emitted only when
// non-empty -- mirroring the QUIC transport's sendNotLeader so both layers
// degrade identically. Resolution failure is advisory: it is captured into a
// named resolveErr (never discarded with _) and the status falls back to the
// pre-advertisement redirect that carries only the Raft coordinates. A
// resolution failure must never turn a legitimate not-leader condition into a
// harder failure than the caller already has.
func notLeaderStatus(ctx context.Context, xkmsService *xkms.XKMSService, err error) (error, bool) {
	nl, ok := xkms.AsNotLeader(err)
	if !ok {
		return nil, false
	}

	leaderAPIAddress := nl.LeaderAPIAddress
	if leaderAPIAddress == "" && xkmsService != nil {
		addr, resolveErr := xkmsService.ClusterLeaderEndpoint(ctx, transport.APIProtocolGRPC)
		if resolveErr != nil {
			leaderAPIAddress = ""
		} else {
			leaderAPIAddress = addr
		}
	}

	metadata := map[string]string{
		"shard_id":       strconv.FormatUint(nl.ShardID, 10),
		"leader_id":      strconv.FormatUint(nl.LeaderID, 10),
		"leader_address": nl.LeaderAddress,
	}
	if leaderAPIAddress != "" {
		metadata["leader_api_address"] = leaderAPIAddress
	}

	st := status.New(codes.FailedPrecondition, nl.Error())
	detail := &errdetails.ErrorInfo{
		Reason:   notLeaderReason,
		Domain:   "xkms.cluster",
		Metadata: metadata,
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
// xkmsService is threaded through so a not-leader translation can resolve the
// leader's dialable gRPC endpoint; it may be nil, in which case the redirect
// carries only the Raft coordinates.
func wrapWriteError(ctx context.Context, xkmsService *xkms.XKMSService, err error, fallbackCode codes.Code, format string, args ...interface{}) error {
	if translated, ok := notLeaderStatus(ctx, xkmsService, err); ok {
		return translated
	}
	return status.Error(fallbackCode, fmt.Sprintf(format, args...))
}
