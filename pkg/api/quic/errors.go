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

package quic

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// NotLeaderResponse is the JSON body returned for a clustered not-leader
// condition. It mirrors the REST transport's response so clients see a single
// shape regardless of protocol. It carries the leader's Raft coordinates so the
// client can retry the write against the current leader, plus (when resolvable)
// the leader's dialable QUIC endpoint so the retry needs no out-of-band
// topology knowledge.
type NotLeaderResponse struct {
	Error         string `json:"error"`
	ShardID       uint64 `json:"shard_id"`
	LeaderID      uint64 `json:"leader_id"`
	LeaderAddress string `json:"leader_address,omitempty"`

	// LeaderAPIAddress is the address a client should dial to reach the leader
	// over QUIC. Omitted when it cannot be resolved (see sendNotLeader), in
	// which case the caller falls back to the Raft coordinates above.
	LeaderAPIAddress string `json:"leader_api_address,omitempty"`
}

// sendServiceError writes an error returned from the xkms service. A clustered
// not-leader condition is surfaced as 421 Misdirected Request with the leader
// coordinates (mirroring the REST transport); every other error falls back to
// the supplied status and message.
func (s *Server) sendServiceError(ctx context.Context, w http.ResponseWriter, err error, fallbackStatus int, message string) {
	if nl, ok := xkms.AsNotLeader(err); ok {
		s.sendNotLeader(ctx, w, nl)
		return
	}
	s.sendError(w, fallbackStatus, message)
}

// sendNotLeader writes a 421 Misdirected Request response for a clustered write
// that reached a follower. The leader's Raft address (when known) is echoed in
// the X-XKMS-Leader-Address header and the JSON body.
//
// AsNotLeader only ever returns the Raft-plane coordinates go-qrdb reports
// (ShardID/LeaderID/LeaderAddress); it never knows which API protocol carried
// the failed request, so it cannot fill in LeaderAPIAddress itself. This QUIC
// layer does know its own protocol, so it resolves the leader's dialable QUIC
// endpoint here via XKMSService.ClusterLeaderEndpoint and echoes it in both the
// X-XKMS-Leader-API-Address header and the JSON body -- never emitting the
// header when the address is empty. Resolution is best-effort: a lookup
// failure is captured into endpointErr (never discarded), logged, and the
// response degrades to the pre-advertisement redirect that carries only the
// Raft coordinates -- a resolution failure must never turn a legitimate
// not-leader condition into a hard failure.
//
// Design rationale for redirecting the CLIENT instead of forwarding the
// request server-side: a follower cannot re-present the caller's client
// certificate to the leader, because it does not hold the caller's private
// key. Forwarding server-side would therefore require either dialing the
// leader under the node's own identity plus an "acting for user X" assertion
// (an impersonation channel) or a full delegation/token-exchange protocol.
// Redirecting the client instead means the caller re-presents its OWN
// credentials to the leader, so the leader authenticates and authorizes the
// real caller and identity is never delegated. The client-side hop that
// follows this redirect lives in pkg/api/transport/quic/transport.go.
func (s *Server) sendNotLeader(ctx context.Context, w http.ResponseWriter, nl *xkms.ErrNotLeader) {
	leaderAPIAddress := nl.LeaderAPIAddress
	if leaderAPIAddress == "" && s.xkmsService != nil {
		addr, endpointErr := s.xkmsService.ClusterLeaderEndpoint(ctx, transport.APIProtocolQUIC)
		if endpointErr != nil {
			s.logger.Warn("failed to resolve QUIC leader endpoint",
				"error", endpointErr,
				"shard_id", nl.ShardID)
		} else {
			leaderAPIAddress = addr
		}
	}

	w.Header().Set("X-XKMS-Shard-ID", strconv.FormatUint(nl.ShardID, 10))
	if nl.LeaderID != 0 {
		w.Header().Set("X-XKMS-Leader-ID", strconv.FormatUint(nl.LeaderID, 10))
	}
	if nl.LeaderAddress != "" {
		w.Header().Set("X-XKMS-Leader-Address", nl.LeaderAddress)
	}
	if leaderAPIAddress != "" {
		w.Header().Set("X-XKMS-Leader-API-Address", leaderAPIAddress)
	}
	s.sendJSON(w, http.StatusMisdirectedRequest, NotLeaderResponse{
		Error:            nl.Error(),
		ShardID:          nl.ShardID,
		LeaderID:         nl.LeaderID,
		LeaderAddress:    nl.LeaderAddress,
		LeaderAPIAddress: leaderAPIAddress,
	})
}

// keyOpSentinelStatuses maps the service-layer sentinels raised by the key
// and crypto operations (AttestKey, DeriveKeyECDH, ExportKeyMaterial,
// WrapKeyByID, UnwrapKeyByID) onto HTTP status codes. It mirrors
// pkg/api/grpc/errors_keyops.go's keyOpSentinelCodes so both transports share
// the same capability-boundary semantics. It is an ordered slice rather than
// a map because a single error can satisfy errors.Is for more than one entry:
// xkms.ErrOperationWrap deliberately exposes both its sentinel and its cause.
// The first match wins, so the most specific sentinel is listed first.
var keyOpSentinelStatuses = []struct {
	sentinel error
	status   int
}{
	// A digest this service refuses (SHA-1 and the other collision-broken
	// names) or cannot resolve is a fault in the request, not in the server.
	// ResolveOAEPHash reports the weak-hash refusal as ErrOperationWrap rather
	// than ErrValidation, so without these two entries it fell through to the
	// catch-all and a caller that named a bad digest was told the server had
	// failed.
	{xkms.ErrWeakOAEPHash, http.StatusBadRequest},
	{xkms.ErrInvalidHashFunction, http.StatusBadRequest},
	{xkms.ErrOperationNotSupported, http.StatusNotImplemented},
	{xkms.ErrExportKeyMaterialFailed, http.StatusPreconditionFailed},
	{xkms.ErrBackendNotFound, http.StatusNotFound},
	{xkms.ErrKeyNotFound, http.StatusNotFound},
	{xkms.ErrNotInitialized, http.StatusServiceUnavailable},
}

// sendKeyOpError writes an error returned by a key/crypto servicer method as
// an HTTP response. A clustered not-leader condition is surfaced as 421
// (checked first, exactly like the gRPC sibling); role-lookup failures become
// 404; validation failures become 400 carrying the caller-facing detail;
// capability boundaries and missing objects map through
// keyOpSentinelStatuses; anything else is a 500.
func (s *Server) sendKeyOpError(ctx context.Context, w http.ResponseWriter, err error) {
	if nl, ok := xkms.AsNotLeader(err); ok {
		s.sendNotLeader(ctx, w, nl)
		return
	}

	var role *xkms.ErrRoleLookup
	if errors.As(err, &role) {
		s.sendError(w, http.StatusNotFound, role.Error())
		return
	}

	var validation *xkms.ErrValidation
	if errors.As(err, &validation) {
		s.sendError(w, http.StatusBadRequest, keyOpValidationMessage(validation))
		return
	}

	for _, entry := range keyOpSentinelStatuses {
		if errors.Is(err, entry.sentinel) {
			s.sendError(w, entry.status, err.Error())
			return
		}
	}

	s.sendError(w, http.StatusInternalServerError, err.Error())
}

// keyOpValidationMessage renders a service-layer validation error for the
// wire. The Detail carries the caller-facing message ("key_id is required");
// the sentinel is only used when a validation error carries no detail.
func keyOpValidationMessage(err *xkms.ErrValidation) string {
	if err.Detail != "" {
		return err.Detail
	}
	return err.Sentinel.Error()
}
