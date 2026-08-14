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

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// notLeaderReason mirrors pkg/api/grpc/errors.go's server-side notLeaderReason
// constant. It is redeclared here rather than imported so this client package
// does not need to depend on the server package; the two must stay in sync
// because they describe the same wire contract.
const notLeaderReason = "NOT_LEADER"

// leaderAPIAddressAnnotationKey is the ErrorInfo metadata key the gRPC server
// sets (pkg/api/grpc/errors.go's notLeaderStatus) to the leader's dialable
// gRPC endpoint, when it was able to resolve one.
const leaderAPIAddressAnnotationKey = "leader_api_address"

// leaderAPIAddressFromError inspects err for a gRPC FailedPrecondition status
// carrying an ErrorInfo{Reason: NOT_LEADER} detail, and reports the
// leader_api_address metadata value when the status carries one and it is
// non-empty. It returns ("", false) for every other error, including a
// NOT_LEADER status whose leader_api_address could not be resolved server
// side -- there is nowhere to redirect to in that case, so the caller must
// see the original typed error unchanged.
func leaderAPIAddressFromError(err error) (string, bool) {
	if err == nil {
		return "", false
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.FailedPrecondition {
		return "", false
	}
	for _, d := range st.Details() {
		info, ok := d.(*errdetails.ErrorInfo)
		if !ok || info.GetReason() != notLeaderReason {
			continue
		}
		addr := info.GetMetadata()[leaderAPIAddressAnnotationKey]
		if addr == "" {
			return "", false
		}
		return addr, true
	}
	return "", false
}

// notLeaderInterceptor implements the transparent leader redirect: it is
// installed on every unary call this Transport makes (see Connect), so any
// clustered write -- not just AddClusterReplica/RemoveClusterReplica -- gets
// the same behavior for free. When an RPC fails with a NOT_LEADER
// precondition carrying a resolvable leader_api_address, this dials that
// address EXACTLY ONCE, using the identical transport credentials this
// Transport was configured with (t.credsOpt -- the same TLS/mTLS material the
// original connection presents), and retries the RPC there.
//
// Dialing with the caller's own credentials, rather than forwarding the
// request server side, is deliberate: it means the caller re-presents its OWN
// identity to the leader, so the leader authenticates and authorizes the real
// caller and identity is never delegated through an intermediate hop. See
// pkg/api/quic's sendNotLeader for the server-side half of this reasoning,
// which applies identically here.
//
// The retry result -- success or a second NOT_LEADER -- is returned to the
// caller unchanged. There is exactly one hop, never a chain: the retry calls
// the terminal invoker directly against the freshly dialed leader connection
// rather than routing through that connection's own cc.Invoke, so this same
// interceptor (installed via grpc.WithChainUnaryInterceptor on every
// connection this Transport creates, including the temporary one) never runs
// again for the retry.
func (t *Transport) notLeaderInterceptor(
	ctx context.Context,
	method string,
	req, reply interface{},
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption,
) error {
	err := invoker(ctx, method, req, reply, cc, opts...)

	leaderAddr, ok := leaderAPIAddressFromError(err)
	if !ok {
		return err
	}

	leaderConn, dialErr := grpc.NewClient(leaderAddr, t.credsOpt)
	if dialErr != nil {
		// Dialing the leader is best-effort: if it fails, the caller still
		// sees the original typed not-leader error rather than a dial error
		// that obscures what actually happened.
		return err
	}
	defer func() {
		_ = leaderConn.Close()
	}()

	return invoker(ctx, method, req, reply, leaderConn, opts...)
}
