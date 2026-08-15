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
	"log"
	"net/http"
	"strconv"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Common errors
var (
	ErrInvalidRequest      = errors.New("invalid request")
	ErrInvalidBackend      = errors.New("invalid backend")
	ErrInvalidKeyType      = errors.New("invalid key type")
	ErrMissingKeyID        = errors.New("missing key_id")
	ErrMissingBackend      = errors.New("missing backend parameter")
	ErrMissingData         = errors.New("missing data")
	ErrMissingCiphertext   = errors.New("missing ciphertext")
	ErrBackendNotFound     = errors.New("backend not found")
	ErrInternalError       = errors.New("internal server error")
	ErrUnauthorized        = errors.New("unauthorized")
	ErrForbidden           = errors.New("forbidden")
	ErrServiceUnavailable  = errors.New("service unavailable")
	ErrSealingNotSupported = errors.New("backend does not support sealing operations")

	// ErrAuthenticatorRequired is returned by NewServer when Config carries no
	// Authenticator. The constructor refuses to substitute a NoOp authenticator
	// because doing so would silently disable authentication; a caller that
	// really wants an unauthenticated server must pass
	// auth.NewNoOpAuthenticator() explicitly.
	ErrAuthenticatorRequired = errors.New("rest: authenticator is required")

	// ErrAuthorizerRequired is returned by NewServer when Config.EnableRBAC is
	// true but no usable RBACAuthorizer was supplied. The constructor refuses
	// to start a server that believes it enforces RBAC while every request
	// would in fact be allowed: enabling RBAC without a qrdb-backed authorizer
	// is a wiring bug, not a permissive deployment mode. Deployments that
	// really want an open gate leave EnableRBAC false.
	ErrAuthorizerRequired = errors.New("rest: authorizer is required when rbac is enabled")
)

// writeError writes an error response to the client.
func writeError(w http.ResponseWriter, err error, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	resp := ErrorResponse{
		Error: err.Error(),
		Code:  statusCode,
	}

	if encErr := json.NewEncoder(w).Encode(resp); encErr != nil {
		log.Printf("Failed to encode error response: %v", encErr)
	}
}

// writeErrorWithMessage writes an error response with a custom message.
func writeErrorWithMessage(w http.ResponseWriter, err error, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	resp := ErrorResponse{
		Error:   err.Error(),
		Message: message,
		Code:    statusCode,
	}

	if encErr := json.NewEncoder(w).Encode(resp); encErr != nil {
		log.Printf("Failed to encode error response: %v", encErr)
	}
}

// mapErrorToStatusCode maps errors to HTTP status codes.
func mapErrorToStatusCode(err error) int {
	// Tenant entitlement / barrier-mode / quota denials propagated from the
	// embedded go-qrdb TenantService. Map them to precise client-facing statuses
	// instead of a generic 500 so operators see the actual denial reason.
	var entErr *qrdbsdk.EntitlementError
	switch {
	case errors.As(err, &entErr):
		// Plan does not entitle the requested isolation mode / barrier mode /
		// feature.
		return http.StatusForbidden
	case errors.Is(err, qrdbsdk.ErrSharedBarrierImmutable):
		// A shared-barrier tenant's barrier mode cannot be changed in place.
		return http.StatusConflict
	case qrdbsdk.IsQuotaExceeded(err):
		// Resource quota for the tenant's plan is exhausted.
		return http.StatusTooManyRequests
	case errors.Is(err, storage.ErrNotFound),
		errors.Is(err, backend.ErrKeyNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrInvalidRequest),
		errors.Is(err, ErrInvalidBackend),
		errors.Is(err, ErrInvalidKeyType),
		errors.Is(err, ErrMissingKeyID),
		errors.Is(err, ErrMissingBackend),
		errors.Is(err, ErrMissingData),
		errors.Is(err, ErrMissingCiphertext),
		errors.Is(err, backend.ErrInvalidKeyType),
		errors.Is(err, backend.ErrInvalidKeyPartition),
		errors.Is(err, ErrSealingNotSupported):
		return http.StatusBadRequest
	case errors.Is(err, storage.ErrAlreadyExists):
		return http.StatusConflict
	case errors.Is(err, ErrServiceUnavailable):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// handleError is a convenience function that maps the error to a status code
// and writes the error response. A clustered not-leader condition is handled
// specially: it is surfaced as 421 Misdirected Request with the leader's Raft
// coordinates so the client can retry against the leader.
//
// This variant cannot enrich the redirect with the leader's dialable API
// address: resolving that requires calling back into the servicer
// (ClusterLeaderEndpoint), and most handleError call sites have no
// *xkms.XKMSService in scope. Call sites that do use handleErrorWithCluster
// instead.
func handleError(w http.ResponseWriter, err error) {
	if nl, ok := xkms.AsNotLeader(err); ok {
		writeNotLeader(w, nl)
		return
	}
	statusCode := mapErrorToStatusCode(err)
	writeError(w, err, statusCode)
}

// handleErrorWithCluster is the not-leader-aware variant of handleError for
// handlers that carry a *xkms.XKMSService reference. Where handleError can
// only surface the leader's bare Raft coordinates, this variant resolves the
// leader's dialable REST address via ClusterLeaderEndpoint (the servicer
// knows shard topology; only the transport knows it speaks REST) and adds it
// to the redirect, which is what lets a REST client retry transparently
// instead of needing out-of-band knowledge of the leader's API endpoint.
//
// Resolution failure is non-fatal: the resolved address is advisory, so a
// lookup error is logged and the response falls back to the pre-enrichment
// behavior (Raft coordinates only) rather than failing the whole request.
// Non-cluster errors fall back to the same mapping handleError uses, so a
// handler can call this unconditionally without special-casing the cluster
// case itself.
func handleErrorWithCluster(w http.ResponseWriter, r *http.Request, err error, svc *xkms.XKMSService) {
	if nl, ok := xkms.AsNotLeader(err); ok {
		if svc != nil {
			addr, resolveErr := svc.ClusterLeaderEndpoint(r.Context(), transport.APIProtocolREST)
			if resolveErr != nil {
				log.Printf("cluster: failed to resolve leader REST endpoint for shard %d: %v", nl.ShardID, resolveErr)
			} else {
				nl.LeaderAPIAddress = addr
			}
		}
		writeNotLeader(w, nl)
		return
	}
	statusCode := mapErrorToStatusCode(err)
	writeError(w, err, statusCode)
}

// NotLeaderResponse is the JSON body returned for a clustered not-leader
// condition. It carries the leader's Raft coordinates, and — when resolvable
// — the leader's dialable REST address, so the client can retry the write
// against the current leader without out-of-band knowledge of the topology.
type NotLeaderResponse struct {
	Error            string `json:"error"`
	ShardID          uint64 `json:"shard_id"`
	LeaderID         uint64 `json:"leader_id"`
	LeaderAddress    string `json:"leader_address,omitempty"`
	LeaderAPIAddress string `json:"leader_api_address,omitempty"`
}

// writeNotLeader writes a 421 Misdirected Request response for a clustered
// write that reached a follower. The leader's Raft address (when known) is
// echoed in the X-XKMS-Leader-Address header and the JSON body; the leader's
// dialable REST address (when resolved by the caller) is echoed in the
// X-XKMS-Leader-API-Address header and the JSON body. Neither header is ever
// emitted empty: an unresolved value is simply omitted, which callers treat
// as "unknown" rather than "empty string".
func writeNotLeader(w http.ResponseWriter, nl *xkms.ErrNotLeader) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-XKMS-Shard-ID", strconv.FormatUint(nl.ShardID, 10))
	if nl.LeaderID != 0 {
		w.Header().Set("X-XKMS-Leader-ID", strconv.FormatUint(nl.LeaderID, 10))
	}
	if nl.LeaderAddress != "" {
		w.Header().Set("X-XKMS-Leader-Address", nl.LeaderAddress)
	}
	if nl.LeaderAPIAddress != "" {
		w.Header().Set("X-XKMS-Leader-API-Address", nl.LeaderAPIAddress)
	}
	w.WriteHeader(http.StatusMisdirectedRequest)

	resp := NotLeaderResponse{
		Error:            nl.Error(),
		ShardID:          nl.ShardID,
		LeaderID:         nl.LeaderID,
		LeaderAddress:    nl.LeaderAddress,
		LeaderAPIAddress: nl.LeaderAPIAddress,
	}
	if encErr := json.NewEncoder(w).Encode(resp); encErr != nil {
		log.Printf("Failed to encode not-leader response: %v", encErr)
	}
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Failed to encode JSON response: %v", err)
		writeError(w, err, http.StatusInternalServerError)
	}
}
