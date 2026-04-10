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
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/server/credentials"
)

// credentialServicer defines the operations required by the credential
// management handlers. This interface decouples the REST layer from the
// concrete credentials.Service implementation, allowing any type that
// satisfies these methods (including XKMSService) to be used.
type credentialServicer interface {
	// SubmitCredential submits a credential value for the named credential.
	SubmitCredential(ctx context.Context, name string, value []byte) error

	// Strategy returns the configured credential strategy name.
	Strategy() string

	// AutoUnsealAvailable reports whether automatic unsealing is available.
	AutoUnsealAvailable() bool
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
}

// CredentialHandlers provides HTTP handlers for the credential management API.
type CredentialHandlers struct {
	credService credentialServicer
	logger      *slog.Logger
}

// NewCredentialHandlers creates a new CredentialHandlers instance. The
// credService parameter accepts any type satisfying the credentialServicer
// interface, including *credentials.Service and *xkms.XKMSService.
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

	value, err := base64.StdEncoding.DecodeString(req.Value)
	if err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if err := h.credService.SubmitCredential(r.Context(), req.Name, value); err != nil {
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
		Status: "accepted",
	}
	writeJSON(w, resp, http.StatusOK)
}

// HandleGetStrategy returns the configured credential strategy.
// GET /api/v1/credentials/strategy
func (h *CredentialHandlers) HandleGetStrategy(w http.ResponseWriter, r *http.Request) {
	resp := CredentialStrategyResponse{
		Strategy:   h.credService.Strategy(),
		AutoUnseal: h.credService.AutoUnsealAvailable(),
	}
	writeJSON(w, resp, http.StatusOK)
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
