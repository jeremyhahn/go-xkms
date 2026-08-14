// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"strconv"

	"github.com/go-chi/chi/v5"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Auth-factor handler typed errors.
var (
	ErrAuthFactorNotConfigured = errors.New("rest: auth factor service not configured")
	ErrMissingAuthFactorUserID = errors.New("rest: missing or invalid user_id")
	ErrMissingAuthFactorID     = errors.New("rest: missing factor_id")
	ErrMissingAuthFactorType   = errors.New("rest: type is required")
	ErrMissingAuthFactorLookup = errors.New("rest: lookup_key is required")
	ErrMissingAuthFactorLabel  = errors.New("rest: label is required")
)

// authFactorServicer is the subset of the XKMS service the auth-factor
// handlers need. Keeping it an interface lets the handlers be driven directly
// in tests without standing up a qrdb node.
type authFactorServicer interface {
	AddAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorAddRequest) (*qrdbtransport.AuthFactorAddResponse, error)
	ListAuthFactors(ctx context.Context, req *qrdbtransport.AuthFactorListRequest) (*qrdbtransport.AuthFactorListResponse, error)
	GetAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorGetRequest) (*qrdbtransport.AuthFactorGetResponse, error)
	RemoveAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorRemoveRequest) (*qrdbtransport.AuthFactorRemoveResponse, error)
	RotateAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorRotateRequest) (*qrdbtransport.AuthFactorRotateResponse, error)
	RelabelAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorRelabelRequest) (*qrdbtransport.AuthFactorRelabelResponse, error)
	LoginAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorLoginRequest) (*qrdbtransport.AuthFactorLoginResponse, error)
}

// AuthFactorHandlers serves the user-side N-factor endpoints. Factor state is
// owned by the embedded go-qrdb node; these handlers delegate to the unified
// XKMSService servicer, which passes calls through.
type AuthFactorHandlers struct {
	svc    authFactorServicer
	logger *slog.Logger
}

// NewAuthFactorHandlers creates AuthFactorHandlers over the given servicer.
func NewAuthFactorHandlers(svc authFactorServicer, logger *slog.Logger) *AuthFactorHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &AuthFactorHandlers{svc: svc, logger: logger}
}

// ListHandler handles GET /factors?user_id=N.
func (h *AuthFactorHandlers) ListHandler(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseUint(r.URL.Query().Get("user_id"), 10, 64)
	if err != nil || userID == 0 {
		writeError(w, ErrMissingAuthFactorUserID, http.StatusBadRequest)
		return
	}

	resp, err := h.svc.ListAuthFactors(r.Context(), &qrdbtransport.AuthFactorListRequest{UserID: userID})
	if err != nil {
		h.writeAuthFactorError(w, err)
		return
	}

	writeJSON(w, resp, http.StatusOK)
}

// AddHandler handles POST /factors.
//
// The owning user comes from the request body. Enrolling a factor for another
// user is an administrative act, so what prevents it is the users:update
// permission the route carries — not the shape of the URL.
func (h *AuthFactorHandlers) AddHandler(w http.ResponseWriter, r *http.Request) {
	var req qrdbtransport.AuthFactorAddRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.UserID == 0 {
		writeError(w, ErrMissingAuthFactorUserID, http.StatusBadRequest)
		return
	}
	if req.Type == "" {
		writeError(w, ErrMissingAuthFactorType, http.StatusBadRequest)
		return
	}

	resp, err := h.svc.AddAuthFactor(r.Context(), &req)
	if err != nil {
		h.writeAuthFactorError(w, err)
		return
	}

	writeJSON(w, resp, http.StatusCreated)
}

// GetHandler handles GET /factors/{factorID}.
func (h *AuthFactorHandlers) GetHandler(w http.ResponseWriter, r *http.Request) {
	factorID := chi.URLParam(r, "factorID")
	if factorID == "" {
		writeError(w, ErrMissingAuthFactorID, http.StatusBadRequest)
		return
	}

	resp, err := h.svc.GetAuthFactor(r.Context(), &qrdbtransport.AuthFactorGetRequest{FactorID: factorID})
	if err != nil {
		h.writeAuthFactorError(w, err)
		return
	}

	writeJSON(w, resp, http.StatusOK)
}

// RemoveHandler handles DELETE /factors/{factorID}. The last-active-factor
// guard lives in qrdb; ?force=true asks it to stand down, which is the only
// way to remove a user's final factor.
func (h *AuthFactorHandlers) RemoveHandler(w http.ResponseWriter, r *http.Request) {
	factorID := chi.URLParam(r, "factorID")
	if factorID == "" {
		writeError(w, ErrMissingAuthFactorID, http.StatusBadRequest)
		return
	}

	force := r.URL.Query().Get("force") == "true"

	resp, err := h.svc.RemoveAuthFactor(r.Context(), &qrdbtransport.AuthFactorRemoveRequest{
		FactorID: factorID,
		Force:    force,
	})
	if err != nil {
		h.writeAuthFactorError(w, err)
		return
	}

	writeJSON(w, resp, http.StatusOK)
}

// RotateHandler handles POST /factors/{factorID}/rotate.
func (h *AuthFactorHandlers) RotateHandler(w http.ResponseWriter, r *http.Request) {
	factorID := chi.URLParam(r, "factorID")
	if factorID == "" {
		writeError(w, ErrMissingAuthFactorID, http.StatusBadRequest)
		return
	}

	var req qrdbtransport.AuthFactorRotateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	req.OldFactorID = factorID

	if req.NewFactor.Type == "" {
		writeError(w, ErrMissingAuthFactorType, http.StatusBadRequest)
		return
	}

	resp, err := h.svc.RotateAuthFactor(r.Context(), &req)
	if err != nil {
		h.writeAuthFactorError(w, err)
		return
	}

	writeJSON(w, resp, http.StatusOK)
}

// RelabelHandler handles PATCH /factors/{factorID}.
func (h *AuthFactorHandlers) RelabelHandler(w http.ResponseWriter, r *http.Request) {
	factorID := chi.URLParam(r, "factorID")
	if factorID == "" {
		writeError(w, ErrMissingAuthFactorID, http.StatusBadRequest)
		return
	}

	var req qrdbtransport.AuthFactorRelabelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	req.FactorID = factorID

	if req.Label == "" {
		writeError(w, ErrMissingAuthFactorLabel, http.StatusBadRequest)
		return
	}

	resp, err := h.svc.RelabelAuthFactor(r.Context(), &req)
	if err != nil {
		h.writeAuthFactorError(w, err)
		return
	}

	writeJSON(w, resp, http.StatusOK)
}

// LoginHandler handles POST /factors/login.
//
// This resolves a (type, lookup_key) pair to a principal and nothing more. It
// is NOT proof of possession: the hardware challenge — FIDO2 assertion, PIV
// signature, mTLS handshake — must be verified by the caller before this
// result is treated as an authenticated identity.
func (h *AuthFactorHandlers) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req qrdbtransport.AuthFactorLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.Type == "" {
		writeError(w, ErrMissingAuthFactorType, http.StatusBadRequest)
		return
	}
	if len(req.LookupKey) == 0 {
		writeError(w, ErrMissingAuthFactorLookup, http.StatusBadRequest)
		return
	}

	resp, err := h.svc.LoginAuthFactor(r.Context(), &req)
	if err != nil {
		h.writeAuthFactorError(w, err)
		return
	}

	writeJSON(w, resp, http.StatusOK)
}

// writeAuthFactorError maps auth-factor domain errors, surfaced by the go-qrdb
// node through the XKMSService servicer, onto HTTP status codes.
func (h *AuthFactorHandlers) writeAuthFactorError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, xkms.ErrNotConfigured):
		writeError(w, ErrAuthFactorNotConfigured, http.StatusServiceUnavailable)
	case errors.Is(err, xkms.ErrNilRequest):
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
	default:
		h.logger.Error("auth factor operation failed", "error", err)
		writeError(w, ErrInternalError, http.StatusInternalServerError)
	}
}
