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

package admin

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// BarrierHandlers provides HTTP handlers for barrier management API endpoints.
type BarrierHandlers struct {
	service BarrierService
	logger  *slog.Logger
}

// NewBarrierHandlers creates a new barrier handlers instance.
func NewBarrierHandlers(service BarrierService, logger *slog.Logger) *BarrierHandlers {
	return &BarrierHandlers{
		service: service,
		logger:  logger,
	}
}

// RegisterRoutes registers all barrier API routes with the router.
//
// Each route declares the canonical go-qrdb seal:* / barrier:* grant it
// requires — the same vocabulary the QUIC and MCP barrier surfaces already
// enforce — so a seal grant means the same thing on every transport. The
// blanket "super-admin" gate this replaced conflated bootstrap, unseal, rekey,
// and root-token issuance into one role check.
func (h *BarrierHandlers) RegisterRoutes(router *mux.Router, authMiddleware AuthHandler, gate *PermissionGate) {
	barrierRouter := router.PathPrefix("/admin/barrier").Subrouter()
	if authMiddleware != nil {
		barrierRouter.Use(authMiddleware.Authenticate)
	}

	barrierRouter.Handle("/status",
		gate.Wrap(auth.ResourceSeal, auth.ActionStatus, h.handleBarrierStatus)).Methods("GET")
	barrierRouter.Handle("/initialize",
		gate.Wrap(auth.ResourceSeal, auth.ActionBootstrap, h.handleBarrierInitialize)).Methods("POST")
	barrierRouter.Handle("/seal",
		gate.Wrap(auth.ResourceSeal, auth.ActionSeal, h.handleBarrierSeal)).Methods("POST")
	barrierRouter.Handle("/unseal",
		gate.Wrap(auth.ResourceSeal, auth.ActionUnseal, h.handleBarrierUnseal)).Methods("POST")
	barrierRouter.Handle("/shamir/initialize",
		gate.Wrap(auth.ResourceSeal, auth.ActionInitializeShamir, h.handleBarrierShamirInitialize)).Methods("POST")
	barrierRouter.Handle("/shamir/unseal-share",
		gate.Wrap(auth.ResourceBarrier, auth.ActionUnsealShare, h.handleBarrierShamirUnsealShare)).Methods("POST")
	barrierRouter.Handle("/rekey",
		gate.Wrap(auth.ResourceSeal, auth.ActionRekey, h.handleBarrierRekey)).Methods("POST")
	barrierRouter.Handle("/recovery/generate",
		gate.Wrap(auth.ResourceSeal, auth.ActionGenerateRecovery, h.handleBarrierRecoveryGenerate)).Methods("POST")
	barrierRouter.Handle("/recovery/recover",
		gate.Wrap(auth.ResourceSeal, auth.ActionRecoverWithKeys, h.handleBarrierRecoveryRecover)).Methods("POST")
	barrierRouter.Handle("/recovery/status",
		gate.Wrap(auth.ResourceSeal, auth.ActionStatus, h.handleBarrierRecoveryStatus)).Methods("GET")
	barrierRouter.Handle("/root-token",
		gate.Wrap(auth.ResourceSeal, auth.ActionRotateRootKey, h.handleBarrierRootToken)).Methods("POST")
}

// handleBarrierStatus handles GET /admin/barrier/status.
func (h *BarrierHandlers) handleBarrierStatus(w http.ResponseWriter, r *http.Request) {
	status, err := h.service.Status(r.Context())
	if err != nil {
		h.logger.Error("failed to get barrier status", slog.String("error", err.Error()))
		writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Failed to get barrier status")
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// handleBarrierInitialize handles POST /admin/barrier/initialize.
func (h *BarrierHandlers) handleBarrierInitialize(w http.ResponseWriter, r *http.Request) {
	var req BarrierInitializeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body")
		return
	}
	if req.Secret == "" {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Secret is required")
		return
	}
	if err := h.service.Initialize(r.Context(), &req); err != nil {
		h.writeBarrierError(w, "initialize", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Barrier initialized successfully"})
}

// handleBarrierSeal handles POST /admin/barrier/seal.
func (h *BarrierHandlers) handleBarrierSeal(w http.ResponseWriter, r *http.Request) {
	if err := h.service.Seal(r.Context()); err != nil {
		h.writeBarrierError(w, "seal", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Barrier sealed successfully"})
}

// handleBarrierUnseal handles POST /admin/barrier/unseal.
func (h *BarrierHandlers) handleBarrierUnseal(w http.ResponseWriter, r *http.Request) {
	var req BarrierUnsealRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body")
		return
	}
	if req.Secret == "" {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Secret is required")
		return
	}
	if err := h.service.Unseal(r.Context(), &req); err != nil {
		h.writeBarrierError(w, "unseal", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Barrier unsealed successfully"})
}

// handleBarrierShamirInitialize handles POST /admin/barrier/shamir/initialize.
func (h *BarrierHandlers) handleBarrierShamirInitialize(w http.ResponseWriter, r *http.Request) {
	var req BarrierInitializeShamirRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body")
		return
	}
	if req.Secret == "" {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Secret is required")
		return
	}
	if req.Threshold < 1 {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Threshold must be at least 1")
		return
	}
	if req.TotalShares < req.Threshold {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Total shares must be >= threshold")
		return
	}
	resp, err := h.service.InitializeShamir(r.Context(), &req)
	if err != nil {
		h.writeBarrierError(w, "shamir-initialize", err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleBarrierShamirUnsealShare handles POST /admin/barrier/shamir/unseal-share.
func (h *BarrierHandlers) handleBarrierShamirUnsealShare(w http.ResponseWriter, r *http.Request) {
	var req BarrierUnsealShareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body")
		return
	}
	if req.Share == "" {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Share is required")
		return
	}
	resp, err := h.service.UnsealWithShare(r.Context(), &req)
	if err != nil {
		h.writeBarrierError(w, "shamir-unseal-share", err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleBarrierRekey handles POST /admin/barrier/rekey.
func (h *BarrierHandlers) handleBarrierRekey(w http.ResponseWriter, r *http.Request) {
	var req BarrierRekeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body")
		return
	}
	if req.Threshold < 1 {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Threshold must be at least 1")
		return
	}
	if req.Total < req.Threshold {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Total must be >= threshold")
		return
	}
	resp, err := h.service.Rekey(r.Context(), &req)
	if err != nil {
		h.writeBarrierError(w, "rekey", err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleBarrierRecoveryGenerate handles POST /admin/barrier/recovery/generate.
func (h *BarrierHandlers) handleBarrierRecoveryGenerate(w http.ResponseWriter, r *http.Request) {
	var req BarrierGenerateRecoveryKeysRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body")
		return
	}
	if req.Threshold < 1 {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Threshold must be at least 1")
		return
	}
	if req.Total < req.Threshold {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Total must be >= threshold")
		return
	}
	resp, err := h.service.GenerateRecoveryKeys(r.Context(), &req)
	if err != nil {
		h.writeBarrierError(w, "recovery-generate", err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleBarrierRecoveryRecover handles POST /admin/barrier/recovery/recover.
func (h *BarrierHandlers) handleBarrierRecoveryRecover(w http.ResponseWriter, r *http.Request) {
	var req BarrierRecoverWithKeysRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body")
		return
	}
	if len(req.Keys) == 0 {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "At least one recovery key is required")
		return
	}
	if err := h.service.RecoverWithKeys(r.Context(), &req); err != nil {
		h.writeBarrierError(w, "recovery-recover", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Barrier recovered successfully"})
}

// handleBarrierRecoveryStatus handles GET /admin/barrier/recovery/status.
func (h *BarrierHandlers) handleBarrierRecoveryStatus(w http.ResponseWriter, r *http.Request) {
	hasKeys, err := h.service.HasRecoveryKeys(r.Context())
	if err != nil {
		h.writeBarrierError(w, "recovery-status", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"has_recovery_keys": hasKeys})
}

// handleBarrierRootToken handles POST /admin/barrier/root-token.
func (h *BarrierHandlers) handleBarrierRootToken(w http.ResponseWriter, r *http.Request) {
	var req BarrierGenerateRootTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "Invalid request body")
		return
	}
	if len(req.Shares) == 0 {
		writeProblem(w, http.StatusBadRequest, "urn:trusted-ca:error:bad-request", "At least one share is required")
		return
	}
	resp, err := h.service.GenerateRootToken(r.Context(), &req)
	if err != nil {
		h.writeBarrierError(w, "root-token", err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// writeBarrierError maps barrier error types to appropriate HTTP responses.
func (h *BarrierHandlers) writeBarrierError(w http.ResponseWriter, operation string, err error) {
	var notEnabledErr *BarrierNotEnabledError
	if errors.As(err, &notEnabledErr) {
		writeProblem(w, http.StatusConflict, "urn:trusted-ca:error:barrier-not-enabled", notEnabledErr.Error())
		return
	}

	var remoteModeErr *BarrierRemoteModeError
	if errors.As(err, &remoteModeErr) {
		writeProblem(w, http.StatusConflict, "urn:trusted-ca:error:barrier-remote-mode", remoteModeErr.Error())
		return
	}

	var notInitErr *BarrierNotInitializedError
	if errors.As(err, &notInitErr) {
		writeProblem(w, http.StatusConflict, "urn:trusted-ca:error:barrier-not-initialized", notInitErr.Error())
		return
	}

	h.logger.Error("barrier operation failed",
		slog.String("operation", operation),
		slog.String("error", err.Error()))
	writeProblem(w, http.StatusInternalServerError, "urn:trusted-ca:error:internal", "Barrier operation failed")
}
