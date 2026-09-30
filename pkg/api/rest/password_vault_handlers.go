// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package rest

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// The personal-vault endpoints under /api/v1/passwords/vault. Every one acts
// on the caller's own vault -- the tenant and subject of the authenticated
// identity, which the servicer resolves -- so none names a user. Request and
// response bodies are the transport types; their byte fields (credential_id,
// prf_salt, secret) are base64 in JSON.

// VaultStatusHandler handles GET /api/v1/passwords/vault. It reports whether
// the caller's vault has a factor, whether the caller's session is open, and
// the enrolled factors -- a passkey's credential ID and PRF salt are what a
// client needs to evaluate hmac-secret before unlocking.
func (h *PasswordHandlers) VaultStatusHandler(w http.ResponseWriter, r *http.Request) {
	status, err := h.servicer.PasswordVaultStatus(r.Context())
	if err != nil {
		passwordWriteVaultError(w, err, "Failed to get vault status")
		return
	}
	writeJSON(w, status, http.StatusOK)
}

// VaultEnrollHandler handles POST /api/v1/passwords/vault/factors. The body is
// a transport.PasswordVaultCredential. The first enrollment initializes the
// vault, opens the session and returns the one-time recovery code; later
// enrollments need the caller's session open.
func (h *PasswordHandlers) VaultEnrollHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.PasswordVaultEnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		passwordWriteJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	defer clear(req.Secret)

	resp, err := h.servicer.PasswordVaultEnroll(r.Context(), &req)
	if err != nil {
		passwordWriteVaultError(w, err, "Failed to enroll vault factor")
		return
	}
	writeJSON(w, resp, http.StatusCreated)
}

// VaultRotateHandler handles PUT /api/v1/passwords/vault/factors/{id}. The body
// is a transport.PasswordVaultCredential of the same factor type as factor
// {id}; the old secret stops working. The caller's session must be open.
func (h *PasswordHandlers) VaultRotateHandler(w http.ResponseWriter, r *http.Request) {
	var cred transport.PasswordVaultCredential
	if err := json.NewDecoder(r.Body).Decode(&cred); err != nil {
		passwordWriteJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	defer clear(cred.Secret)

	resp, err := h.servicer.PasswordVaultRotate(r.Context(), &transport.PasswordVaultRotateRequest{
		FactorID:                chi.URLParam(r, "id"),
		PasswordVaultCredential: cred,
	})
	if err != nil {
		passwordWriteVaultError(w, err, "Failed to rotate vault factor")
		return
	}
	writeJSON(w, resp, http.StatusOK)
}

// VaultRemoveFactorHandler handles DELETE
// /api/v1/passwords/vault/factors/{id}. The caller's session must be open;
// the recovery code and the last passphrase or passkey cannot be removed.
func (h *PasswordHandlers) VaultRemoveFactorHandler(w http.ResponseWriter, r *http.Request) {
	err := h.servicer.PasswordVaultRemoveFactor(r.Context(), &transport.PasswordVaultRemoveFactorRequest{
		FactorID: chi.URLParam(r, "id"),
	})
	if err != nil {
		passwordWriteVaultError(w, err, "Failed to remove vault factor")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// VaultRecoverHandler handles POST /api/v1/passwords/vault/recover. The body
// is a transport.PasswordVaultRecoverRequest: the recovery code plus the new
// factor's credential. It enrolls the factor, opens the session and returns
// the replacement recovery code; the used code stops working.
func (h *PasswordHandlers) VaultRecoverHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.PasswordVaultRecoverRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		passwordWriteJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	defer clear(req.Secret)

	resp, err := h.servicer.PasswordVaultRecover(r.Context(), &req)
	if err != nil {
		passwordWriteVaultError(w, err, "Failed to recover vault")
		return
	}
	writeJSON(w, resp, http.StatusOK)
}
