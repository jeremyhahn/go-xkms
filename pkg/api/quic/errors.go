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
	"net/http"
	"strconv"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// NotLeaderResponse is the JSON body returned for a clustered not-leader
// condition. It mirrors the REST transport's response so clients see a single
// shape regardless of protocol. It carries the leader's Raft coordinates so the
// client can retry the write against the current leader.
//
// TODO(cluster): transparent leader-forwarding needs a raft->API address map;
// until then the client retries using out-of-band knowledge of the topology.
type NotLeaderResponse struct {
	Error         string `json:"error"`
	ShardID       uint64 `json:"shard_id"`
	LeaderID      uint64 `json:"leader_id"`
	LeaderAddress string `json:"leader_address,omitempty"`
}

// sendServiceError writes an error returned from the xkms service. A clustered
// not-leader condition is surfaced as 421 Misdirected Request with the leader
// coordinates (mirroring the REST transport); every other error falls back to
// the supplied status and message.
func (s *Server) sendServiceError(w http.ResponseWriter, err error, fallbackStatus int, message string) {
	if nl, ok := xkms.AsNotLeader(err); ok {
		s.sendNotLeader(w, nl)
		return
	}
	s.sendError(w, fallbackStatus, message)
}

// sendNotLeader writes a 421 Misdirected Request response for a clustered write
// that reached a follower. The leader's Raft address (when known) is echoed in
// the X-XKMS-Leader-Address header and the JSON body.
func (s *Server) sendNotLeader(w http.ResponseWriter, nl *xkms.ErrNotLeader) {
	w.Header().Set("X-XKMS-Shard-ID", strconv.FormatUint(nl.ShardID, 10))
	if nl.LeaderID != 0 {
		w.Header().Set("X-XKMS-Leader-ID", strconv.FormatUint(nl.LeaderID, 10))
	}
	if nl.LeaderAddress != "" {
		w.Header().Set("X-XKMS-Leader-Address", nl.LeaderAddress)
	}
	s.sendJSON(w, http.StatusMisdirectedRequest, NotLeaderResponse{
		Error:         nl.Error(),
		ShardID:       nl.ShardID,
		LeaderID:      nl.LeaderID,
		LeaderAddress: nl.LeaderAddress,
	})
}
