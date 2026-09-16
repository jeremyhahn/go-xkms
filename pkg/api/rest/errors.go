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

	// ErrTokenIssuerBackendRequired is returned by BuildTokenIssuer when
	// TokenIssuerParams carries a nil signing Backend.
	ErrTokenIssuerBackendRequired = errors.New("rest: token issuer requires a non-nil signing backend")

	// ErrWebAuthnConfigRequired is returned by BuildWebAuthnService when
	// WebAuthnServiceParams carries a nil Config.
	ErrWebAuthnConfigRequired = errors.New("rest: webauthn service requires a non-nil config")

	// ErrWebAuthnQRDBClientRequired is returned by BuildWebAuthnService when
	// WebAuthnServiceParams carries a nil QRDBClient: the qrdb identity plane
	// is the only store BuildWebAuthnService knows how to wire.
	ErrWebAuthnQRDBClientRequired = errors.New("rest: webauthn service requires a non-nil qrdb client")

	// ErrWebAuthnCredentialStoreDecoratorNil is returned by
	// BuildWebAuthnService when a configured
	// WebAuthnServiceParams.CredentialStoreDecorator returns nil. A nil
	// credential store would leave the relying party unable to persist or
	// read back a passkey, so construction fails closed rather than
	// producing a service whose registrations silently vanish.
	ErrWebAuthnCredentialStoreDecoratorNil = errors.New("rest: webauthn credential store decorator returned a nil store")

	// ErrAuthenticatorChainEmpty is returned by BuildAuthenticator when
	// neither a token issuer nor a qrdb client was supplied: there is no
	// session vehicle a caller could authenticate with.
	ErrAuthenticatorChainEmpty = errors.New("rest: no session-vehicle input available (need a token issuer or a qrdb client)")
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
		errors.Is(err, backend.ErrAsymmetricKeyExportNotAllowed),
		errors.Is(err, ErrSealingNotSupported):
		return http.StatusBadRequest
	case errors.Is(err, storage.ErrAlreadyExists):
		return http.StatusConflict
	case errors.Is(err, ErrServiceUnavailable):
		return http.StatusServiceUnavailable
	// A backend that categorically cannot import or export -- the assertion
	// against backend.ImportBackend / backend.ExportBackend failed outright,
	// so no key or operation on this backend was ever going to succeed here
	// -- is a capability boundary, not a fault: 501, matching how
	// xkms.ErrOperationNotSupported is reported by mapKeyOpError for the same
	// reason on the crypto RPCs.
	case errors.Is(err, backend.ErrExportNotSupported),
		errors.Is(err, backend.ErrImportNotSupported):
		return http.StatusNotImplemented
	// A specific key that exists but was not created with Exportable=true is
	// a policy refusal on that key, not a missing backend capability: 403,
	// distinct from the 501 above.
	case errors.Is(err, backend.ErrKeyNotExportable):
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

// handleError is a convenience function that maps the error to a status code
// and writes the error response. A clustered not-leader condition is handled
// specially: it is surfaced as 421 Misdirected Request with the leader's Raft
// coordinates so the client can retry against the leader.
func handleError(w http.ResponseWriter, err error) {
	if nl, ok := xkms.AsNotLeader(err); ok {
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
