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
	"log/slog"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/bootstrap"
)

// BootstrapHandlers provides HTTP handlers for the bootstrap API.
type BootstrapHandlers struct {
	bootstrap *bootstrap.Service
	logger    *slog.Logger
}

// NewBootstrapHandlers creates a new BootstrapHandlers instance.
func NewBootstrapHandlers(bs *bootstrap.Service, logger *slog.Logger) *BootstrapHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &BootstrapHandlers{
		bootstrap: bs,
		logger:    logger,
	}
}

// BootstrapStatusAPIResponse is the response for the bootstrap status endpoint.
type BootstrapStatusAPIResponse struct {
	State   string `json:"state"`
	Message string `json:"message"`
}

// bootstrapErrorStatusMap maps bootstrap errors to HTTP status codes for O(1) lookup.
var bootstrapErrorStatusMap = map[error]int{
	bootstrap.ErrAlreadyInitialized: http.StatusConflict,
	bootstrap.ErrNotReady:           http.StatusServiceUnavailable,
	bootstrap.ErrInvalidToken:       http.StatusUnauthorized,
	bootstrap.ErrTokenExpired:       http.StatusGone,
	bootstrap.ErrTokenUsed:          http.StatusConflict,
	bootstrap.ErrNoToken:            http.StatusServiceUnavailable,
	bootstrap.ErrInvalidRequest:     http.StatusBadRequest,
	bootstrap.ErrUsernameTaken:      http.StatusConflict,
	bootstrap.ErrEmptyUsername:      http.StatusBadRequest,
	bootstrap.ErrEmptyToken:         http.StatusBadRequest,
	bootstrap.ErrEmptyAttestation:   http.StatusBadRequest,
	bootstrap.ErrInvalidInvitation:  http.StatusUnauthorized,
	bootstrap.ErrInvitationExpired:  http.StatusGone,
	bootstrap.ErrInvitationUsed:     http.StatusConflict,
	bootstrap.ErrCeremonyNotStarted: http.StatusServiceUnavailable,
	bootstrap.ErrCeremonyComplete:   http.StatusConflict,
}

// bootstrapStateMessages maps bootstrap states to human-readable messages for O(1) lookup.
var bootstrapStateMessages = map[string]string{
	bootstrap.StateUninitialized: "System requires initialization. Generate a setup token to begin.",
	bootstrap.StateReady:         "Setup token generated. System is ready for admin initialization.",
	bootstrap.StateCeremony:      "Threshold ceremony in progress. Waiting for additional admin registrations.",
	bootstrap.StateComplete:      "System is initialized and ready.",
}

// HandleGetStatus returns the current bootstrap status.
// GET /api/v1/bootstrap/status
func (h *BootstrapHandlers) HandleGetStatus(w http.ResponseWriter, r *http.Request) {
	state := h.bootstrap.State()

	message, ok := bootstrapStateMessages[state]
	if !ok {
		message = "Unknown state."
	}

	resp := BootstrapStatusAPIResponse{
		State:   state,
		Message: message,
	}

	writeJSON(w, resp, http.StatusOK)
}

// HandleInit handles atomic system initialization.
// POST /api/v1/init
func (h *BootstrapHandlers) HandleInit(w http.ResponseWriter, r *http.Request) {
	var req bootstrap.InitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	resp, err := h.bootstrap.Initialize(r.Context(), &req)
	if err != nil {
		h.logger.Warn("Bootstrap initialization failed",
			slog.String("error", err.Error()))

		statusCode := mapBootstrapError(err)
		writeError(w, err, statusCode)
		return
	}

	h.logger.Info("Bootstrap initialization succeeded",
		slog.String("username", resp.Username))

	writeJSON(w, resp, http.StatusOK)
}

// HandleThresholdInit handles threshold mode admin registration.
// POST /api/v1/init/threshold
func (h *BootstrapHandlers) HandleThresholdInit(w http.ResponseWriter, r *http.Request) {
	var req bootstrap.ThresholdInitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	// Determine which token to validate
	if req.SetupToken != "" {
		// First admin uses setup token -- delegate to regular init
		initReq := &bootstrap.InitRequest{
			SetupToken:       req.SetupToken,
			Username:         req.Username,
			DisplayName:      req.DisplayName,
			FIDO2Attestation: req.FIDO2Attestation,
		}

		resp, err := h.bootstrap.Initialize(r.Context(), initReq)
		if err != nil {
			h.logger.Warn("Bootstrap threshold initialization failed",
				slog.String("error", err.Error()))

			statusCode := mapBootstrapError(err)
			writeError(w, err, statusCode)
			return
		}

		writeJSON(w, resp, http.StatusOK)
		return
	}

	// Subsequent admins use invitation token
	if req.Invitation == "" {
		writeError(w, bootstrap.ErrEmptyToken, http.StatusBadRequest)
		return
	}

	// Validate invitation
	if err := h.bootstrap.ValidateInvitation(req.Invitation); err != nil {
		statusCode := mapBootstrapError(err)
		writeError(w, err, statusCode)
		return
	}

	// Note: In a real implementation, FIDO2 registration would happen here
	// via webauthn.Service. For now, we validate and consume the invitation.

	if err := h.bootstrap.ConsumeInvitation(req.Invitation); err != nil {
		statusCode := mapBootstrapError(err)
		writeError(w, err, statusCode)
		return
	}

	resp := &bootstrap.InitResponse{
		Username: req.Username,
	}

	writeJSON(w, resp, http.StatusOK)
}

// mapBootstrapError maps a bootstrap error to the appropriate HTTP status code.
func mapBootstrapError(err error) int {
	for sentinelErr, status := range bootstrapErrorStatusMap {
		if errors.Is(err, sentinelErr) {
			return status
		}
	}
	return http.StatusInternalServerError
}
