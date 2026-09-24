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
	"log/slog"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// ErrClusterNotConfigured reports that no XKMS service is wired, which is a
// construction-order bug rather than a runtime condition (the service is
// always injected — see NewServer).
var ErrClusterNotConfigured = errors.New("rest: cluster service not configured")

// ClusterHandlers serves the Raft cluster status and membership REST
// endpoints. Cluster state is owned by the embedded go-qrdb node; the
// handlers delegate to the XKMSService servicer
// (pkg/xkms/servicer_cluster.go), never to qrdb directly.
//
// This is a read-only surface by design: StatusHandler and MembersHandler
// work on both a standalone and a clustered node, degrading to the
// standalone view rather than failing, so they are registered
// unconditionally. There is no membership-mutation handler — Raft
// membership changes go through go-qrdb's own control plane exclusively via
// `xkmsctl cluster add`/`remove` (docs/clustering/api.md, docs/web/parity.md
// "Cluster mutations"); a REST route that could only ever answer "not
// supported" would be a stub, which this codebase does not register.
type ClusterHandlers struct {
	xkmsService *xkms.XKMSService
}

// NewClusterHandlers creates a new ClusterHandlers with the provided XKMS
// service.
func NewClusterHandlers(svc *xkms.XKMSService) *ClusterHandlers {
	return &ClusterHandlers{xkmsService: svc}
}

// StatusHandler handles GET /cluster/status requests. Reports this node's
// Raft shard status; on a standalone node it reports clustered:false rather
// than failing.
func (h *ClusterHandlers) StatusHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrClusterNotConfigured, http.StatusServiceUnavailable)
		return
	}

	status, err := h.xkmsService.ClusterStatus(r.Context())
	if err != nil {
		handleClusterError(w, err)
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

// MembersHandler handles GET /cluster/members requests. Lists the shard's
// current Raft membership; on a standalone node it reports an empty list
// rather than failing.
func (h *ClusterHandlers) MembersHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrClusterNotConfigured, http.StatusServiceUnavailable)
		return
	}

	members, err := h.xkmsService.ClusterMembers(r.Context())
	if err != nil {
		handleClusterError(w, err)
		return
	}

	out := make([]transport.ClusterMemberInfo, len(members))
	for i, m := range members {
		out[i] = transport.ClusterMemberInfo{
			ReplicaID:    m.ReplicaID,
			Address:      m.Address,
			APIEndpoints: m.APIEndpoints,
			IsLeader:     m.IsLeader,
		}
	}
	writeJSON(w, transport.ListClusterMembersResponse{Members: out}, http.StatusOK)
}

// handleClusterError maps cluster domain errors (surfaced by the servicer's
// read-only pass-through to the embedded go-qrdb node's cluster client) to
// HTTP status codes and writes the error response.
func handleClusterError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, xkms.ErrNotConfigured):
		writeError(w, ErrClusterNotConfigured, http.StatusServiceUnavailable)
	default:
		// An unexpected error from the cluster subsystem must never be
		// silently collapsed into a bare 500 without a trace — log the
		// underlying cause for diagnosis.
		slog.Default().Error("cluster operation failed", "error", err)
		writeError(w, ErrInternalError, http.StatusInternalServerError)
	}
}
