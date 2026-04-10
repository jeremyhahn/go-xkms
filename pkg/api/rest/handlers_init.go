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
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
)

// initServicer defines the operations required by the init ceremony handlers.
// This interface decouples the REST layer from the concrete CeremonyService
// implementation, allowing any type that satisfies these methods (including
// XKMSService) to be used.
type initServicer interface {
	// State returns the current ceremony state.
	State() initialize.CeremonyState

	// BeginClaimCert begins the certificate claim challenge-response flow
	// for the named officer.
	BeginClaimCert(ctx context.Context, username string) (*initialize.ChallengeResponse, error)

	// CompleteClaimCert verifies the officer's signature over the challenge
	// nonce and returns the officer certificate and CA certificate on success.
	CompleteClaimCert(ctx context.Context, username, nonceHex string, signature []byte) (*initialize.ClaimCertResult, error)

	// ClaimShare retrieves and returns the sealed Shamir share for the
	// named officer.
	ClaimShare(ctx context.Context, username string) ([]byte, error)
}

// InitStatusResponse is the response for the init ceremony status endpoint.
type InitStatusResponse struct {
	State string `json:"state"`
}

// ClaimCertBeginRequest is the request body for beginning a certificate claim.
type ClaimCertBeginRequest struct {
	Username string `json:"username"`
}

// ClaimCertBeginResponse is the response for a successful claim-cert begin.
type ClaimCertBeginResponse struct {
	Nonce     string    `json:"nonce"`
	Username  string    `json:"username"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ClaimCertCompleteRequest is the request body for completing a certificate claim.
type ClaimCertCompleteRequest struct {
	Username  string `json:"username"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"` // base64-encoded
}

// ClaimCertCompleteResponse is the response for a successful claim-cert complete.
type ClaimCertCompleteResponse struct {
	CertPEM   string `json:"cert_pem"`
	CACertPEM string `json:"ca_cert_pem"`
}

// ClaimShareRequest is the request body for claiming a Shamir share.
type ClaimShareRequest struct {
	Username string `json:"username"`
}

// ClaimShareResponse is the response for a successful share claim.
type ClaimShareResponse struct {
	Share json.RawMessage `json:"share"`
}

// Typed errors for init handlers.
var (
	ErrMissingUsername  = errors.New("missing username")
	ErrMissingNonce     = errors.New("missing nonce")
	ErrMissingSignature = errors.New("missing signature")
)

// initErrorStatusMap maps ceremony errors to HTTP status codes for O(1) lookup.
var initErrorStatusMap = map[error]int{
	initialize.ErrNotInEnrollingState:         http.StatusConflict,
	initialize.ErrPendingCertNotFound:         http.StatusNotFound,
	initialize.ErrCertAlreadyClaimed:          http.StatusConflict,
	initialize.ErrShareNotFound:               http.StatusNotFound,
	initialize.ErrShareAlreadyClaimed:         http.StatusConflict,
	initialize.ErrChallengeVerificationFailed: http.StatusUnauthorized,
	initialize.ErrAlreadyInitialized:          http.StatusConflict,
	initialize.ErrUserNotFound:                http.StatusNotFound,
	initialize.ErrChallengeNotFound:           http.StatusNotFound,
	initialize.ErrChallengeExpired:            http.StatusGone,
}

// InitHandlers provides HTTP handlers for the init ceremony API.
type InitHandlers struct {
	ceremony initServicer
	logger   *slog.Logger
}

// NewInitHandlers creates a new InitHandlers instance. The ceremony parameter
// accepts any type satisfying the initServicer interface, including
// *initialize.CeremonyService and *xkms.XKMSService.
func NewInitHandlers(ceremony initServicer, logger *slog.Logger) *InitHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &InitHandlers{
		ceremony: ceremony,
		logger:   logger,
	}
}

// HandleGetStatus returns the current init ceremony state.
// GET /api/v1/init/status
func (h *InitHandlers) HandleGetStatus(w http.ResponseWriter, r *http.Request) {
	state := h.ceremony.State()
	resp := InitStatusResponse{
		State: string(state),
	}
	writeJSON(w, resp, http.StatusOK)
}

// HandleClaimCertBegin begins the certificate claim process for an officer.
// POST /api/v1/init/claim-cert/begin
func (h *InitHandlers) HandleClaimCertBegin(w http.ResponseWriter, r *http.Request) {
	var req ClaimCertBeginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.Username == "" {
		writeError(w, ErrMissingUsername, http.StatusBadRequest)
		return
	}

	challenge, err := h.ceremony.BeginClaimCert(r.Context(), req.Username)
	if err != nil {
		h.logger.Warn("claim-cert begin failed",
			slog.String("username", req.Username),
			slog.String("error", err.Error()))

		statusCode := mapInitError(err)
		writeError(w, err, statusCode)
		return
	}

	resp := ClaimCertBeginResponse{
		Nonce:     hex.EncodeToString(challenge.Nonce),
		Username:  challenge.Username,
		ExpiresAt: challenge.ExpiresAt,
	}

	h.logger.Info("claim-cert begin succeeded",
		slog.String("username", req.Username))

	writeJSON(w, resp, http.StatusOK)
}

// HandleClaimCertComplete completes the certificate claim by verifying the
// officer's signature over the challenge nonce.
// POST /api/v1/init/claim-cert/complete
func (h *InitHandlers) HandleClaimCertComplete(w http.ResponseWriter, r *http.Request) {
	var req ClaimCertCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.Username == "" {
		writeError(w, ErrMissingUsername, http.StatusBadRequest)
		return
	}
	if req.Nonce == "" {
		writeError(w, ErrMissingNonce, http.StatusBadRequest)
		return
	}
	if req.Signature == "" {
		writeError(w, ErrMissingSignature, http.StatusBadRequest)
		return
	}

	signature, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	result, err := h.ceremony.CompleteClaimCert(r.Context(), req.Username, req.Nonce, signature)
	if err != nil {
		h.logger.Warn("claim-cert complete failed",
			slog.String("username", req.Username),
			slog.String("error", err.Error()))

		statusCode := mapInitError(err)
		writeError(w, err, statusCode)
		return
	}

	resp := ClaimCertCompleteResponse{
		CertPEM:   string(result.CertPEM),
		CACertPEM: string(result.CACertPEM),
	}

	h.logger.Info("claim-cert complete succeeded",
		slog.String("username", req.Username))

	writeJSON(w, resp, http.StatusOK)
}

// HandleClaimShare retrieves the Shamir share for the named officer.
// POST /api/v1/init/claim-share
func (h *InitHandlers) HandleClaimShare(w http.ResponseWriter, r *http.Request) {
	var req ClaimShareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.Username == "" {
		writeError(w, ErrMissingUsername, http.StatusBadRequest)
		return
	}

	shareJSON, err := h.ceremony.ClaimShare(r.Context(), req.Username)
	if err != nil {
		h.logger.Warn("claim-share failed",
			slog.String("username", req.Username),
			slog.String("error", err.Error()))

		statusCode := mapInitError(err)
		writeError(w, err, statusCode)
		return
	}

	resp := ClaimShareResponse{
		Share: json.RawMessage(shareJSON),
	}

	h.logger.Info("claim-share succeeded",
		slog.String("username", req.Username))

	writeJSON(w, resp, http.StatusOK)
}

// mapInitError maps an init ceremony error to the appropriate HTTP status code.
func mapInitError(err error) int {
	for sentinelErr, status := range initErrorStatusMap {
		if errors.Is(err, sentinelErr) {
			return status
		}
	}
	return http.StatusInternalServerError
}
