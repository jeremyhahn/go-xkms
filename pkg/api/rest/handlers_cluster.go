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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Cluster handler typed errors.
var (
	// ErrClusterNotConfigured is returned when the xkms service is not
	// available to answer cluster queries.
	ErrClusterNotConfigured = errors.New("rest: cluster service not configured")
)

// ErrMalformedClusterRequest represents a failure to decode the JSON body of
// a cluster membership mutation request.
type ErrMalformedClusterRequest struct {
	Err error
}

// Error returns the error message.
func (e *ErrMalformedClusterRequest) Error() string {
	return fmt.Sprintf("rest: malformed cluster request body: %v", e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrMalformedClusterRequest) Unwrap() error { return e.Err }

// ErrInvalidReplicaIDParam represents a failure to parse the {replicaID} URL
// path parameter as an unsigned integer.
type ErrInvalidReplicaIDParam struct {
	Value string
	Err   error
}

// Error returns the error message.
func (e *ErrInvalidReplicaIDParam) Error() string {
	return fmt.Sprintf("rest: invalid replicaID path parameter %q: %v", e.Value, e.Err)
}

// Unwrap returns the underlying error.
func (e *ErrInvalidReplicaIDParam) Unwrap() error { return e.Err }

// ClusterHandlers serves the cluster REST endpoints: the read-only
// status/membership surface and the privileged membership-mutation surface
// (add/remove replica). Cluster state is owned by the embedded go-qrdb node;
// the handlers delegate to the unified XKMSService servicer, which reads
// leadership and membership from, and applies mutations through, the node's
// cluster client.
//
// Membership mutation is privileged: server.go gates AddReplicaHandler and
// RemoveReplicaHandler on the canonical qrdb admin:add_member /
// admin:remove_member permissions and fails closed (403) when RBAC is not
// wired, unlike the read routes which stay open on a standalone node.
type ClusterHandlers struct {
	xkmsService *xkms.XKMSService
}

// NewClusterHandlers creates a new ClusterHandlers with the provided XKMS service.
func NewClusterHandlers(svc *xkms.XKMSService) *ClusterHandlers {
	return &ClusterHandlers{xkmsService: svc}
}

// StatusHandler handles GET /api/v1/cluster/status requests.
// It returns the Raft leadership status for the configured shard. A standalone
// (non-clustered) node reports a single-node, non-clustered status.
func (h *ClusterHandlers) StatusHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrClusterNotConfigured, http.StatusServiceUnavailable)
		return
	}
	svc := h.xkmsService

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
	if h.xkmsService == nil {
		writeError(w, ErrClusterNotConfigured, http.StatusServiceUnavailable)
		return
	}
	svc := h.xkmsService

	members, err := svc.ClusterMembers(r.Context())
	if err != nil {
		writeError(w, ErrInternalError, http.StatusInternalServerError)
		return
	}

	out := make([]transport.ClusterMemberInfo, len(members))
	for i, m := range members {
		out[i] = transport.ClusterMemberInfo{
			NodeID:       m.NodeID,
			Address:      m.Address,
			APIEndpoints: m.APIEndpoints,
			IsLeader:     m.IsLeader,
		}
	}

	writeJSON(w, transport.ListClusterMembersResponse{Members: out}, http.StatusOK)
}

// AddReplicaHandler handles POST /api/v1/cluster/members requests. It adds a
// replica to the configured shard's Raft group. The underlying mutation is
// idempotent: adding a replica already present succeeds without changing the
// configuration.
func (h *ClusterHandlers) AddReplicaHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrClusterNotConfigured, http.StatusServiceUnavailable)
		return
	}
	svc := h.xkmsService

	var req transport.AddClusterReplicaRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, &ErrMalformedClusterRequest{Err: err}, http.StatusBadRequest)
		return
	}

	if err := svc.AddClusterReplica(r.Context(), req.ReplicaID, req.RaftAddress); err != nil {
		handleErrorWithCluster(w, r, err, svc)
		return
	}

	status, err := svc.ClusterStatus(r.Context())
	if err != nil {
		handleErrorWithCluster(w, r, err, svc)
		return
	}

	writeJSON(w, transport.ClusterReplicaResponse{
		ShardID:   status.ShardID,
		ReplicaID: req.ReplicaID,
	}, http.StatusOK)
}

// RemoveReplicaHandler handles DELETE /api/v1/cluster/members/{replicaID}
// requests. It removes a replica from the configured shard's Raft group. The
// underlying mutation is idempotent: removing a replica that is already
// absent succeeds.
func (h *ClusterHandlers) RemoveReplicaHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, ErrClusterNotConfigured, http.StatusServiceUnavailable)
		return
	}
	svc := h.xkmsService

	replicaIDParam := chi.URLParam(r, "replicaID")
	replicaID, err := strconv.ParseUint(replicaIDParam, 10, 64)
	if err != nil {
		writeError(w, &ErrInvalidReplicaIDParam{Value: replicaIDParam, Err: err}, http.StatusBadRequest)
		return
	}

	if err := svc.RemoveClusterReplica(r.Context(), replicaID); err != nil {
		handleErrorWithCluster(w, r, err, svc)
		return
	}

	status, err := svc.ClusterStatus(r.Context())
	if err != nil {
		handleErrorWithCluster(w, r, err, svc)
		return
	}

	writeJSON(w, transport.ClusterReplicaResponse{
		ShardID:   status.ShardID,
		ReplicaID: replicaID,
	}, http.StatusOK)
}

// denyClusterMutationHandler responds 403 Forbidden to a cluster membership
// mutation request. It is mounted in place of AddReplicaHandler /
// RemoveReplicaHandler only when the server has no RBAC middleware wired.
//
// Unlike the read-only status/members surface — which safely degrades to
// "always available" because the servicer reports single-node status on a
// standalone node — membership mutation reconfigures the Raft group and must
// never be reachable purely because an operator chose to run without RBAC.
// Failing closed here means a deployment that forgets to wire RBAC gets a
// loud, unambiguous 403 instead of a silently open cluster-reconfiguration
// endpoint.
func denyClusterMutationHandler(w http.ResponseWriter, r *http.Request) {
	writeErrorWithMessage(w, ErrForbidden,
		"cluster membership mutation requires RBAC to be enabled", http.StatusForbidden)
}
