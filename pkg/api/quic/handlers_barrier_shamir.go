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

package quic

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

// --- Shamir request/response types ---

// BarrierInitializeShamirRequest represents the request to initialize the
// barrier with Shamir secret sharing.
type BarrierInitializeShamirRequest struct {
	Secret string `json:"secret,omitempty"`
}

// BarrierUnsealShareRequest represents the request to submit a single
// Shamir share for quorum-based unsealing.
type BarrierUnsealShareRequest struct {
	Share string `json:"share"`
}

// BarrierUnsealSharesRequest represents the request to submit multiple
// Shamir shares for batch unsealing.
type BarrierUnsealSharesRequest struct {
	Shares []string `json:"shares"`
}

// BarrierRekeyRequest represents the request to rekey the barrier with
// new Shamir parameters.
type BarrierRekeyRequest struct {
	Threshold int `json:"threshold"`
	Total     int `json:"total"`
}

// BarrierGenerateRecoveryKeysRequest represents the request to generate
// recovery keys for disaster recovery.
type BarrierGenerateRecoveryKeysRequest struct {
	Threshold int `json:"threshold"`
	Total     int `json:"total"`
}

// BarrierRecoverWithKeysRequest represents the request to recover the
// barrier using recovery key shares.
type BarrierRecoverWithKeysRequest struct {
	Keys []string `json:"keys"`
}

// BarrierGenerateRootTokenRequest represents the request to generate a
// root token by providing Shamir shares.
type BarrierGenerateRootTokenRequest struct {
	Shares []string `json:"shares"`
}

// BarrierShamirSharesResponse represents the response for Shamir share
// listing operations.
type BarrierShamirSharesResponse struct {
	Count     int `json:"count"`
	Threshold int `json:"threshold,omitempty"`
	Total     int `json:"total,omitempty"`
}

// --- Shamir barrier handlers ---

// handleBarrierInitializeShamir handles POST /api/v1/barrier/initialize-shamir requests.
// It initializes the barrier using Shamir secret sharing and returns the generated shares.
func (s *Server) handleBarrierInitializeShamir(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.barrier == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrBarrierNotConfigured.Error())
		return
	}

	if !s.authorize(w, r, "barrier", "use") {
		return
	}

	var req BarrierInitializeShamirRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	creds := seal.Credentials{Secret: req.Secret}
	result, err := s.barrier.InitializeShamir(r.Context(), creds)
	if err != nil {
		sendBarrierError(s, w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success":      true,
		"shares":       result.Shares,
		"threshold":    result.Threshold,
		"total_shares": result.TotalShares,
	})
}

// handleBarrierUnsealShare handles POST /api/v1/barrier/unseal-share requests.
// It submits a single Shamir share for stateful quorum-based unsealing.
func (s *Server) handleBarrierUnsealShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.barrier == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrBarrierNotConfigured.Error())
		return
	}

	if !s.authorize(w, r, "barrier", "use") {
		return
	}

	var req BarrierUnsealShareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.Share == "" {
		s.sendError(w, http.StatusBadRequest, "share is required")
		return
	}

	progress, err := s.barrier.UnsealWithShare(r.Context(), req.Share)
	if err != nil {
		sendBarrierError(s, w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"required":  progress.Required,
		"submitted": progress.Submitted,
		"complete":  progress.Complete,
	})
}

// handleBarrierUnsealShares handles POST /api/v1/barrier/unseal-shares requests.
// It submits all required Shamir shares at once for stateless batch unsealing.
func (s *Server) handleBarrierUnsealShares(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.barrier == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrBarrierNotConfigured.Error())
		return
	}

	if !s.authorize(w, r, "barrier", "use") {
		return
	}

	var req BarrierUnsealSharesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if len(req.Shares) == 0 {
		s.sendError(w, http.StatusBadRequest, "shares is required")
		return
	}

	if err := s.barrier.UnsealWithShares(r.Context(), req.Shares); err != nil {
		sendBarrierError(s, w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "barrier unsealed with shares",
	})
}

// handleBarrierRekey handles POST /api/v1/barrier/rekey requests.
// It generates new Shamir shares for the existing root key with updated parameters.
func (s *Server) handleBarrierRekey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.barrier == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrBarrierNotConfigured.Error())
		return
	}

	if !s.authorize(w, r, "barrier", "use") {
		return
	}

	var req BarrierRekeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.Threshold < 2 {
		s.sendError(w, http.StatusBadRequest, "threshold must be >= 2")
		return
	}

	if req.Total < req.Threshold {
		s.sendError(w, http.StatusBadRequest, "total must be >= threshold")
		return
	}

	result, err := s.barrier.Rekey(r.Context(), req.Threshold, req.Total)
	if err != nil {
		sendBarrierError(s, w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success":      true,
		"shares":       result.Shares,
		"threshold":    result.Threshold,
		"total_shares": result.TotalShares,
	})
}

// handleBarrierGenerateRootToken handles POST /api/v1/barrier/root-token requests.
// It generates a one-time root token by proving knowledge of the master key through shares.
func (s *Server) handleBarrierGenerateRootToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.barrier == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrBarrierNotConfigured.Error())
		return
	}

	if !s.authorize(w, r, "barrier", "use") {
		return
	}

	var req BarrierGenerateRootTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if len(req.Shares) == 0 {
		s.sendError(w, http.StatusBadRequest, "shares is required")
		return
	}

	token, err := s.barrier.GenerateRootToken(r.Context(), req.Shares)
	if err != nil {
		sendBarrierError(s, w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success":    true,
		"token":      token.Token,
		"created_at": token.CreatedAt,
	})
}

// handleBarrierShamirShares handles GET and DELETE /api/v1/barrier/shamir/shares requests.
// GET returns the share count and configuration. DELETE removes all shares.
func (s *Server) handleBarrierShamirShares(w http.ResponseWriter, r *http.Request) {
	if s.barrier == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrBarrierNotConfigured.Error())
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !s.authorize(w, r, "barrier", "read") {
			return
		}

		shamirStrat := s.barrier.ShamirStrategy()
		if shamirStrat == nil {
			s.sendError(w, http.StatusBadRequest, seal.ErrShamirNotConfigured.Error())
			return
		}

		count, err := shamirStrat.ShareCount(r.Context())
		if err != nil {
			sendBarrierError(s, w, err)
			return
		}

		s.sendJSON(w, http.StatusOK, BarrierShamirSharesResponse{
			Count:     count,
			Threshold: shamirStrat.Threshold(),
			Total:     shamirStrat.TotalShares(),
		})

	case http.MethodDelete:
		if !s.authorize(w, r, "barrier", "use") {
			return
		}

		shamirStrat := s.barrier.ShamirStrategy()
		if shamirStrat == nil {
			s.sendError(w, http.StatusBadRequest, seal.ErrShamirNotConfigured.Error())
			return
		}

		if err := shamirStrat.DeleteAllShares(r.Context()); err != nil {
			sendBarrierError(s, w, err)
			return
		}

		s.sendJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "all shares deleted",
		})

	default:
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleBarrierShamirDeleteShare handles DELETE /api/v1/barrier/shamir/shares/{index} requests.
// It removes a specific share by its 1-based index.
func (s *Server) handleBarrierShamirDeleteShare(w http.ResponseWriter, r *http.Request, path string) {
	if r.Method != http.MethodDelete {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.barrier == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrBarrierNotConfigured.Error())
		return
	}

	if !s.authorize(w, r, "barrier", "use") {
		return
	}

	// Parse share index from path suffix: "shamir/shares/{index}"
	indexStr := strings.TrimPrefix(path, "shamir/shares/")
	index, err := strconv.Atoi(indexStr)
	if err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid share index: "+indexStr)
		return
	}

	shamirStrat := s.barrier.ShamirStrategy()
	if shamirStrat == nil {
		s.sendError(w, http.StatusBadRequest, seal.ErrShamirNotConfigured.Error())
		return
	}

	if err := shamirStrat.DeleteShare(r.Context(), index); err != nil {
		sendBarrierError(s, w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "share deleted",
		"index":   index,
	})
}

// handleBarrierShamirVerify handles POST /api/v1/barrier/shamir/verify requests.
// It verifies the integrity and consistency of all stored Shamir shares.
func (s *Server) handleBarrierShamirVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.barrier == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrBarrierNotConfigured.Error())
		return
	}

	if !s.authorize(w, r, "barrier", "use") {
		return
	}

	shamirStrat := s.barrier.ShamirStrategy()
	if shamirStrat == nil {
		s.sendError(w, http.StatusBadRequest, seal.ErrShamirNotConfigured.Error())
		return
	}

	if err := shamirStrat.VerifyShares(r.Context()); err != nil {
		sendBarrierError(s, w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "all shares verified",
	})
}

// handleBarrierGenerateRecoveryKeys handles POST /api/v1/barrier/recovery-keys/generate requests.
// It generates an independent set of Shamir recovery key shares for disaster recovery.
func (s *Server) handleBarrierGenerateRecoveryKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.barrier == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrBarrierNotConfigured.Error())
		return
	}

	if !s.authorize(w, r, "barrier", "use") {
		return
	}

	var req BarrierGenerateRecoveryKeysRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.Threshold < 2 {
		s.sendError(w, http.StatusBadRequest, "threshold must be >= 2")
		return
	}

	if req.Total < req.Threshold {
		s.sendError(w, http.StatusBadRequest, "total must be >= threshold")
		return
	}

	result, err := s.barrier.GenerateRecoveryKeys(r.Context(), req.Threshold, req.Total)
	if err != nil {
		sendBarrierError(s, w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success":      true,
		"shares":       result.Shares,
		"threshold":    result.Threshold,
		"total_shares": result.TotalShares,
	})
}

// handleBarrierRecoverWithKeys handles POST /api/v1/barrier/recovery-keys/recover requests.
// It reconstructs the DEK from recovery key shares and unseals the barrier.
func (s *Server) handleBarrierRecoverWithKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.barrier == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrBarrierNotConfigured.Error())
		return
	}

	if !s.authorize(w, r, "barrier", "use") {
		return
	}

	var req BarrierRecoverWithKeysRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if len(req.Keys) == 0 {
		s.sendError(w, http.StatusBadRequest, "keys is required")
		return
	}

	if err := s.barrier.RecoverWithKeys(r.Context(), req.Keys); err != nil {
		sendBarrierError(s, w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "barrier recovered with recovery keys",
	})
}

// handleBarrierDeleteRecoveryKeys handles DELETE /api/v1/barrier/recovery-keys requests.
// It removes recovery key metadata from storage.
func (s *Server) handleBarrierDeleteRecoveryKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.barrier == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrBarrierNotConfigured.Error())
		return
	}

	if !s.authorize(w, r, "barrier", "use") {
		return
	}

	if err := s.barrier.DeleteRecoveryKeys(r.Context()); err != nil {
		sendBarrierError(s, w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "recovery keys deleted",
	})
}

// handleBarrierHasRecoveryKeys handles GET /api/v1/barrier/recovery-keys requests.
// It reports whether recovery key metadata exists in storage.
func (s *Server) handleBarrierHasRecoveryKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.barrier == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrBarrierNotConfigured.Error())
		return
	}

	if !s.authorize(w, r, "barrier", "read") {
		return
	}

	exists, err := s.barrier.HasRecoveryKeys(r.Context())
	if err != nil {
		sendBarrierError(s, w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"has_recovery_keys": exists,
	})
}

// handleBarrierRecoveryKeysDispatch handles /api/v1/barrier/recovery-keys requests,
// dispatching to the correct handler based on HTTP method (GET vs DELETE).
func (s *Server) handleBarrierRecoveryKeysDispatch(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleBarrierHasRecoveryKeys(w, r)
	case http.MethodDelete:
		s.handleBarrierDeleteRecoveryKeys(w, r)
	default:
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}
