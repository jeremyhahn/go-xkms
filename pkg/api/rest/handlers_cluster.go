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

package rest

import (
	"errors"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Cluster handler typed errors.
var (
	// ErrClusterNotConfigured is returned when the xkms service is not
	// available to answer cluster queries.
	ErrClusterNotConfigured = errors.New("rest: cluster service not configured")
)

// ClusterHandlers serves the read-only cluster REST endpoints. Cluster state is
// owned by the embedded go-qrdb node; the handlers delegate to the unified
// XKMSService servicer, which reads leadership and membership from the node's
// cluster client. The handlers hold no local state.
//
// Membership mutation (add/remove replica) is intentionally not served here: it
// requires a Raft replica-mutation API that is not yet surfaced through the
// xkms SDK.
type ClusterHandlers struct{}

// NewClusterHandlers creates a new ClusterHandlers.
func NewClusterHandlers() *ClusterHandlers {
	return &ClusterHandlers{}
}

// StatusHandler handles GET /api/v1/cluster/status requests.
// It returns the Raft leadership status for the configured shard. A standalone
// (non-clustered) node reports a single-node, non-clustered status.
func (h *ClusterHandlers) StatusHandler(w http.ResponseWriter, r *http.Request) {
	svc, err := xkms.Get()
	if err != nil {
		writeError(w, ErrClusterNotConfigured, http.StatusServiceUnavailable)
		return
	}

	status, err := svc.ClusterStatus(r.Context())
	if err != nil {
		writeError(w, ErrInternalError, http.StatusInternalServerError)
		return
	}

	writeJSON(w, transport.ClusterStatusResponse{
		Status: transport.ClusterStatusInfo{
			ShardID:   status.ShardID,
			LeaderID:  status.LeaderID,
			HasLeader: status.HasLeader,
			NodeID:    status.NodeID,
			Clustered: status.Clustered,
		},
	}, http.StatusOK)
}

// MembersHandler handles GET /api/v1/cluster/members requests.
// It returns the Raft replicas for the configured shard. A standalone node
// returns an empty membership set.
func (h *ClusterHandlers) MembersHandler(w http.ResponseWriter, r *http.Request) {
	svc, err := xkms.Get()
	if err != nil {
		writeError(w, ErrClusterNotConfigured, http.StatusServiceUnavailable)
		return
	}

	members, err := svc.ClusterMembers(r.Context())
	if err != nil {
		writeError(w, ErrInternalError, http.StatusInternalServerError)
		return
	}

	out := make([]transport.ClusterMemberInfo, len(members))
	for i, m := range members {
		out[i] = transport.ClusterMemberInfo{
			NodeID:   m.NodeID,
			Address:  m.Address,
			IsLeader: m.IsLeader,
		}
	}

	writeJSON(w, transport.ListClusterMembersResponse{Members: out}, http.StatusOK)
}
