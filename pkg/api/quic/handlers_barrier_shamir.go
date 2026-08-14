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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
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

	if !s.authorize(w, r, auth.ResourceSeal, auth.ActionInitializeShamir) {
		return
	}

	var req BarrierInitializeShamirRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	creds := seal.Credentials{Secret: []byte(req.Secret)}
	result, err := s.barrier.InitializeShamir(r.Context(), creds)
	if err != nil {
		sendBarrierError(s, w, err)
		return
	}

	// Share material is never returned: shares are sealed to enrolled
	// Security Officers via the CeremonyDistributor (qrdb share-free
	// contract). Only the threshold/total metadata is reported.
	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success":      true,
		"threshold":    result.Threshold,
		"total_shares": result.TotalShares,
		"share_count":  result.ShareCount,
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

	if !s.authorize(w, r, auth.ResourceBarrier, auth.ActionUnsealShare) {
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

	if !s.authorize(w, r, auth.ResourceSeal, auth.ActionUnseal) {
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

	if !s.authorize(w, r, auth.ResourceSeal, auth.ActionRekey) {
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

	// New shares are sealed to enrolled Security Officers and never
	// returned; only the threshold/total metadata is reported.
	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success":      true,
		"threshold":    result.Threshold,
		"total_shares": result.TotalShares,
		"share_count":  result.ShareCount,
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

	if !s.authorize(w, r, auth.ResourceSeal, auth.ActionRotateRootKey) {
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

	if !s.authorize(w, r, auth.ResourceSeal, auth.ActionGenerateRecovery) {
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

	// Recovery shares are sealed to enrolled recovery officers and never
	// returned; only the threshold/total metadata is reported.
	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success":      true,
		"threshold":    result.Threshold,
		"total_shares": result.TotalShares,
		"share_count":  result.ShareCount,
	})
}

// handleBarrierEnableEncryption handles POST /api/v1/barrier/enable-encryption
// requests. It migrates a previously-unencrypted barrier to a keyed strategy in
// place. The migration runs asynchronously; the response acknowledges the start
// and clients poll the barrier status endpoint for completion.
func (s *Server) handleBarrierEnableEncryption(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.xkmsService == nil {
		s.sendError(w, http.StatusServiceUnavailable, ErrBarrierNotConfigured.Error())
		return
	}

	if !s.authorize(w, r, auth.ResourceSeal, auth.ActionEnableEncryption) {
		return
	}

	var req transport.BarrierEnableEncryptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	resp, err := s.xkmsService.BarrierEnableEncryption(r.Context(), &req)
	if err != nil {
		sendBarrierError(s, w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, resp)
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

	if !s.authorize(w, r, auth.ResourceSeal, auth.ActionRecoverWithKeys) {
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

	if !s.authorize(w, r, auth.ResourceSeal, auth.ActionGenerateRecovery) {
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

	if !s.authorize(w, r, auth.ResourceSeal, auth.ActionStatus) {
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
