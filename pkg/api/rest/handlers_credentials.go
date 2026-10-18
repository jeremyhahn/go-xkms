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
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// credentialServicer is the slice of the XKMSService the credential
// management handlers need. The handlers never reach the credential service
// directly: submitted credentials are the platform's backend credentials, and
// the service's system-tenant check is what refuses a tenant-scoped caller
// (go-xkms#1226).
type credentialServicer interface {
	// SubmitCredential submits a base64-encoded credential value for the
	// named credential.
	SubmitCredential(ctx context.Context, req *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error)

	// GetCredentialStrategy reports the configured credential strategy and
	// whether automatic unsealing is available.
	GetCredentialStrategy(ctx context.Context) (*transport.CredentialStrategyResponse, error)

	// ListCredentials returns the names of the stored credentials. Values
	// are never returned.
	ListCredentials(ctx context.Context) ([]string, error)
}

// CredentialSubmitRequest is the request body for submitting a credential.
type CredentialSubmitRequest struct {
	Name  string `json:"name"`
	Value string `json:"value"` // base64-encoded
}

// CredentialSubmitResponse is the response for a successful credential submission.
type CredentialSubmitResponse struct {
	Status string `json:"status"`
}

// CredentialStrategyResponse is the response for the credential strategy endpoint.
type CredentialStrategyResponse struct {
	Strategy   string `json:"strategy"`
	AutoUnseal bool   `json:"auto_unseal"`
}

// CredentialListResponse is the response for the credential listing endpoint.
// It carries names only — a credential value has no read path out of the seal
// boundary, and this endpoint does not create one.
type CredentialListResponse struct {
	Names []string `json:"names"`
}

// Typed errors for credential handlers.
var (
	ErrMissingCredentialName  = errors.New("missing credential name")
	ErrMissingCredentialValue = errors.New("missing credential value")
)

// credentialErrorStatusMap maps credential errors to HTTP status codes for O(1) lookup.
var credentialErrorStatusMap = map[error]int{
	credentials.ErrEmptyCredentialName:        http.StatusBadRequest,
	credentials.ErrEmptyCredentialValue:       http.StatusBadRequest,
	credentials.ErrCredentialNotFound:         http.StatusNotFound,
	credentials.ErrCredentialAlreadySubmitted: http.StatusConflict,
	credentials.ErrInvalidStrategy:            http.StatusBadRequest,
	xkms.ErrInvalidEncoding:                   http.StatusBadRequest,
	xkms.ErrNotConfigured:                     http.StatusServiceUnavailable,
	// The platform-scope refusal (xkms.TenantBindingError) unwraps to
	// go-qrdb's unknown-tenant sentinel and answers as a genuine miss.
	qrdbsdk.ErrTenantMissing: http.StatusNotFound,
}

// CredentialHandlers provides HTTP handlers for the credential management API.
type CredentialHandlers struct {
	credService credentialServicer
	logger      *slog.Logger
}

// NewCredentialHandlers creates a new CredentialHandlers instance over the
// XKMSService's credential operations.
func NewCredentialHandlers(credService credentialServicer, logger *slog.Logger) *CredentialHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &CredentialHandlers{
		credService: credService,
		logger:      logger,
	}
}

// HandleSubmit handles credential submission for manual mode.
// POST /api/v1/credentials/submit
func (h *CredentialHandlers) HandleSubmit(w http.ResponseWriter, r *http.Request) {
	var req CredentialSubmitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		writeError(w, ErrMissingCredentialName, http.StatusBadRequest)
		return
	}
	if req.Value == "" {
		writeError(w, ErrMissingCredentialValue, http.StatusBadRequest)
		return
	}

	submitted, err := h.credService.SubmitCredential(r.Context(), &transport.CredentialSubmitRequest{Name: req.Name, Value: req.Value})
	if err != nil {
		h.logger.Warn("credential submission failed",
			slog.String("name", req.Name),
			slog.String("error", err.Error()))

		statusCode := mapCredentialError(err)
		writeError(w, err, statusCode)
		return
	}

	h.logger.Info("credential submitted",
		slog.String("name", req.Name))

	resp := CredentialSubmitResponse{
		Status: submitted.Status,
	}
	writeJSON(w, resp, http.StatusOK)
}

// HandleGetStrategy returns the configured credential strategy.
// GET /api/v1/credentials/strategy
func (h *CredentialHandlers) HandleGetStrategy(w http.ResponseWriter, r *http.Request) {
	strategy, err := h.credService.GetCredentialStrategy(r.Context())
	if err != nil {
		writeError(w, err, mapCredentialError(err))
		return
	}
	resp := CredentialStrategyResponse{
		Strategy:   strategy.Strategy,
		AutoUnseal: strategy.AutoUnseal,
	}
	writeJSON(w, resp, http.StatusOK)
}

// HandleList returns the names of the stored credentials.
// GET /api/v1/credentials
//
// Names only. An operator uses this to see which credentials the server has
// already been given — and therefore which are still outstanding before a
// backend can unseal — without any value crossing the seal boundary.
func (h *CredentialHandlers) HandleList(w http.ResponseWriter, r *http.Request) {
	names, err := h.credService.ListCredentials(r.Context())
	if err != nil {
		h.logger.Error("failed to list credentials", "error", err)
		writeError(w, err, mapCredentialError(err))
		return
	}

	// An empty store must serialize as [] rather than null so a client can
	// iterate the result without a nil check.
	if names == nil {
		names = []string{}
	}

	writeJSON(w, CredentialListResponse{Names: names}, http.StatusOK)
}

// mapCredentialError maps a credential error to the appropriate HTTP status code.
func mapCredentialError(err error) int {
	for sentinelErr, status := range credentialErrorStatusMap {
		if errors.Is(err, sentinelErr) {
			return status
		}
	}
	return http.StatusInternalServerError
}
