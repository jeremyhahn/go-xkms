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
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

// Shamir barrier handler typed errors.
var (
	ErrMissingShare     = errors.New("rest: missing share")
	ErrMissingShares    = errors.New("rest: missing shares")
	ErrMissingThreshold = errors.New("rest: missing or invalid threshold")
	ErrMissingTotal     = errors.New("rest: missing or invalid total")
	ErrMissingKeys      = errors.New("rest: missing keys")
)

// --- Shamir barrier request/response types ---

// BarrierInitializeShamirRequest represents the request to initialize the barrier
// with Shamir secret sharing.
type BarrierInitializeShamirRequest struct {
	Secret string `json:"secret,omitempty"`
}

// BarrierUnsealShareRequest represents a request to submit a single share for
// quorum-based unsealing.
type BarrierUnsealShareRequest struct {
	Share string `json:"share"`
}

// BarrierUnsealSharesRequest represents a request to submit all shares at once
// for stateless batch unsealing.
type BarrierUnsealSharesRequest struct {
	Shares []string `json:"shares"`
}

// BarrierRekeyRequest represents a request to rekey the barrier with new
// Shamir parameters.
type BarrierRekeyRequest struct {
	Threshold int `json:"threshold"`
	Total     int `json:"total"`
}

// BarrierGenerateRecoveryKeysRequest represents a request to generate
// recovery keys.
type BarrierGenerateRecoveryKeysRequest struct {
	Threshold int `json:"threshold"`
	Total     int `json:"total"`
}

// BarrierRecoverWithKeysRequest represents a request to recover the barrier
// using recovery key shares.
type BarrierRecoverWithKeysRequest struct {
	Keys []string `json:"keys"`
}

// BarrierGenerateRootTokenRequest represents a request to generate a root token
// by proving knowledge of the master key through Shamir shares.
type BarrierGenerateRootTokenRequest struct {
	Shares []string `json:"shares"`
}

// --- Shamir barrier handlers ---

// BarrierInitializeShamirHandler handles POST /api/v1/barrier/initialize-shamir requests.
// Initializes the barrier using Shamir secret sharing. Returns the generated shares
// that must be distributed to key holders.
func (h *HandlerContext) BarrierInitializeShamirHandler(w http.ResponseWriter, r *http.Request) {
	if h.Barrier == nil {
		writeError(w, ErrBarrierNotConfigured, http.StatusServiceUnavailable)
		return
	}

	var req BarrierInitializeShamirRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	creds := seal.Credentials{Secret: req.Secret}
	result, err := h.Barrier.InitializeShamir(r.Context(), creds)
	if err != nil {
		handleBarrierError(w, err)
		return
	}

	writeJSON(w, result, http.StatusOK)
}

// BarrierUnsealShareHandler handles POST /api/v1/barrier/unseal-share requests.
// Submits a single Shamir share for stateful quorum-based unsealing.
// When enough shares have been submitted, the barrier unseals automatically.
func (h *HandlerContext) BarrierUnsealShareHandler(w http.ResponseWriter, r *http.Request) {
	if h.Barrier == nil {
		writeError(w, ErrBarrierNotConfigured, http.StatusServiceUnavailable)
		return
	}

	var req BarrierUnsealShareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.Share == "" {
		writeError(w, ErrMissingShare, http.StatusBadRequest)
		return
	}

	progress, err := h.Barrier.UnsealWithShare(r.Context(), req.Share)
	if err != nil {
		handleBarrierError(w, err)
		return
	}

	writeJSON(w, progress, http.StatusOK)
}

// BarrierUnsealSharesHandler handles POST /api/v1/barrier/unseal-shares requests.
// Performs stateless batch unsealing with all required shares provided at once.
func (h *HandlerContext) BarrierUnsealSharesHandler(w http.ResponseWriter, r *http.Request) {
	if h.Barrier == nil {
		writeError(w, ErrBarrierNotConfigured, http.StatusServiceUnavailable)
		return
	}

	var req BarrierUnsealSharesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if len(req.Shares) == 0 {
		writeError(w, ErrMissingShares, http.StatusBadRequest)
		return
	}

	if err := h.Barrier.UnsealWithShares(r.Context(), req.Shares); err != nil {
		handleBarrierError(w, err)
		return
	}

	writeJSON(w, &SuccessResponse{
		Success: true,
		Message: "barrier unsealed with shares",
	}, http.StatusOK)
}

// BarrierRekeyHandler handles POST /api/v1/barrier/rekey requests.
// Generates a new set of Shamir shares for the existing root key.
// The root key does not change; only the shares are rotated.
func (h *HandlerContext) BarrierRekeyHandler(w http.ResponseWriter, r *http.Request) {
	if h.Barrier == nil {
		writeError(w, ErrBarrierNotConfigured, http.StatusServiceUnavailable)
		return
	}

	var req BarrierRekeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.Threshold < 2 {
		writeError(w, ErrMissingThreshold, http.StatusBadRequest)
		return
	}

	if req.Total < req.Threshold {
		writeError(w, ErrMissingTotal, http.StatusBadRequest)
		return
	}

	result, err := h.Barrier.Rekey(r.Context(), req.Threshold, req.Total)
	if err != nil {
		handleBarrierError(w, err)
		return
	}

	writeJSON(w, result, http.StatusOK)
}

// BarrierGenerateRecoveryKeysHandler handles POST /api/v1/barrier/recovery-keys/generate requests.
// Generates an independent set of Shamir shares that can reconstruct the DEK.
// The shares are returned for offline storage and are not persisted.
func (h *HandlerContext) BarrierGenerateRecoveryKeysHandler(w http.ResponseWriter, r *http.Request) {
	if h.Barrier == nil {
		writeError(w, ErrBarrierNotConfigured, http.StatusServiceUnavailable)
		return
	}

	var req BarrierGenerateRecoveryKeysRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.Threshold < 2 {
		writeError(w, ErrMissingThreshold, http.StatusBadRequest)
		return
	}

	if req.Total < req.Threshold {
		writeError(w, ErrMissingTotal, http.StatusBadRequest)
		return
	}

	result, err := h.Barrier.GenerateRecoveryKeys(r.Context(), req.Threshold, req.Total)
	if err != nil {
		handleBarrierError(w, err)
		return
	}

	writeJSON(w, result, http.StatusOK)
}

// BarrierRecoverWithKeysHandler handles POST /api/v1/barrier/recovery-keys/recover requests.
// Reconstructs the DEK from recovery key shares and unseals the barrier.
func (h *HandlerContext) BarrierRecoverWithKeysHandler(w http.ResponseWriter, r *http.Request) {
	if h.Barrier == nil {
		writeError(w, ErrBarrierNotConfigured, http.StatusServiceUnavailable)
		return
	}

	var req BarrierRecoverWithKeysRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if len(req.Keys) == 0 {
		writeError(w, ErrMissingKeys, http.StatusBadRequest)
		return
	}

	if err := h.Barrier.RecoverWithKeys(r.Context(), req.Keys); err != nil {
		handleBarrierError(w, err)
		return
	}

	writeJSON(w, &SuccessResponse{
		Success: true,
		Message: "barrier recovered with keys",
	}, http.StatusOK)
}

// BarrierDeleteRecoveryKeysHandler handles DELETE /api/v1/barrier/recovery-keys requests.
// Removes recovery key metadata from storage.
func (h *HandlerContext) BarrierDeleteRecoveryKeysHandler(w http.ResponseWriter, r *http.Request) {
	if h.Barrier == nil {
		writeError(w, ErrBarrierNotConfigured, http.StatusServiceUnavailable)
		return
	}

	if err := h.Barrier.DeleteRecoveryKeys(r.Context()); err != nil {
		handleBarrierError(w, err)
		return
	}

	writeJSON(w, &SuccessResponse{
		Success: true,
		Message: "recovery keys deleted",
	}, http.StatusOK)
}

// BarrierGenerateRootTokenHandler handles POST /api/v1/barrier/root-token requests.
// Generates a one-time root token by proving knowledge of the master key
// through Shamir share reconstruction.
func (h *HandlerContext) BarrierGenerateRootTokenHandler(w http.ResponseWriter, r *http.Request) {
	if h.Barrier == nil {
		writeError(w, ErrBarrierNotConfigured, http.StatusServiceUnavailable)
		return
	}

	var req BarrierGenerateRootTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if len(req.Shares) == 0 {
		writeError(w, ErrMissingShares, http.StatusBadRequest)
		return
	}

	token, err := h.Barrier.GenerateRootToken(r.Context(), req.Shares)
	if err != nil {
		handleBarrierError(w, err)
		return
	}

	writeJSON(w, token, http.StatusOK)
}
