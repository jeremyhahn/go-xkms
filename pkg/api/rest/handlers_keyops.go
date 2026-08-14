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

// This file implements the hardware-capability key operation handlers:
// AttestKeyHandler, DeriveKeyECDHHandler, ExportKeyMaterialHandler,
// WrapKeyByIDHandler, and UnwrapKeyByIDHandler. They are thin transport
// adapters: they decode the request, validate only what the route shape
// requires (path parameters and query strings the servicer never sees), and
// delegate to *xkms.XKMSService for every business decision. Field-level
// validation, backend/key resolution, and capability checks live in the
// service layer; see pkg/xkms/servicer_key.go and pkg/xkms/servicer_crypto.go.
// Errors returned by the servicer are mapped onto HTTP statuses by
// mapKeyOpError, which mirrors pkg/api/grpc/errors_keyops.go so both
// transports report the same capability boundaries.

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// ErrTenantIDNotAccepted is returned when a request body carries a tenant_id.
//
// The tenant an operation runs under is the authenticated caller's own, never
// a value the caller names: a key ID is only unique within a tenant, so a
// body-supplied tenant would let any caller address another tenant's keys.
// The field is refused rather than ignored, because a caller that believes it
// is acting on one tenant and is quietly served another has no way to tell.
var ErrTenantIDNotAccepted = errors.New("tenant_id is not accepted in the request body; the tenant is taken from the authenticated identity")

// tenantForRequest returns the tenant the operation must run under, which is
// the one carried by the authenticated identity. It refuses a request that
// supplied a tenant of its own, writing this transport's validation error and
// reporting false so the handler returns without delegating.
//
// This mirrors the gRPC transport, where the tenant has only ever come from
// callerTenantID and the wire format has no field for the caller to set.
func (h *HandlerContext) tenantForRequest(w http.ResponseWriter, r *http.Request, supplied string) (string, bool) {
	if supplied != "" {
		writeError(w, ErrTenantIDNotAccepted, http.StatusBadRequest)
		return "", false
	}
	return callerTenantID(r.Context()), true
}

// AttestKeyHandler handles POST /api/v1/attest requests. It generates a
// cryptographic attestation statement proving the requested key was created
// in hardware (TPM2, PKCS#11 HSM, etc.) and never left the secure boundary.
func (h *HandlerContext) AttestKeyHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, xkms.ErrNotInitialized, http.StatusServiceUnavailable)
		return
	}

	var req transport.AttestKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	tenantID, ok := h.tenantForRequest(w, r, req.TenantID)
	if !ok {
		return
	}
	req.TenantID = tenantID

	resp, err := h.xkmsService.AttestKey(r.Context(), &req)
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, resp, http.StatusOK)
}

// DeriveKeyECDHHandler handles POST /api/v1/keys/derive-ecdh requests. It
// performs ECDH key agreement against a peer public key and runs the
// resulting shared secret through a KDF to produce a derived symmetric key.
func (h *HandlerContext) DeriveKeyECDHHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, xkms.ErrNotInitialized, http.StatusServiceUnavailable)
		return
	}

	var req transport.DeriveKeyECDHRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	tenantID, ok := h.tenantForRequest(w, r, req.TenantID)
	if !ok {
		return
	}
	req.TenantID = tenantID

	resp, err := h.xkmsService.DeriveKeyECDH(r.Context(), &req)
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, resp, http.StatusOK)
}

// WrapKeyByIDHandler handles POST /api/v1/keys/wrap-by-id requests. It wraps
// a server-side target key with a server-side wrapping key, both identified
// by key ID and backend. This is the service-layer primitive behind PKCS#11
// C_WrapKey.
func (h *HandlerContext) WrapKeyByIDHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, xkms.ErrNotInitialized, http.StatusServiceUnavailable)
		return
	}

	var req transport.WrapKeyByIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	tenantID, ok := h.tenantForRequest(w, r, req.TenantID)
	if !ok {
		return
	}
	req.TenantID = tenantID

	resp, err := h.xkmsService.WrapKeyByID(r.Context(), &req)
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, resp, http.StatusOK)
}

// UnwrapKeyByIDHandler handles POST /api/v1/keys/unwrap-by-id requests. It
// unwraps key material with a server-side unwrapping key and imports the
// result as a new key. This is the service-layer primitive behind PKCS#11
// C_UnwrapKey.
func (h *HandlerContext) UnwrapKeyByIDHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, xkms.ErrNotInitialized, http.StatusServiceUnavailable)
		return
	}

	var req transport.UnwrapKeyByIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	tenantID, ok := h.tenantForRequest(w, r, req.TenantID)
	if !ok {
		return
	}
	req.TenantID = tenantID

	resp, err := h.xkmsService.UnwrapKeyByID(r.Context(), &req)
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, resp, http.StatusOK)
}

// ExportKeyMaterialHandler handles POST /api/v1/keys/{id}/export-material
// requests. It returns the raw plaintext bytes of an extractable symmetric
// key.
//
// SECURITY WARNING: this returns plaintext key material without any
// cryptographic protection. The service layer only releases it for symmetric
// keys created with exportable=true on a backend implementing
// backend.ImportExportBackend.
//
// The route carries no body: the key ID is a path parameter and the backend
// is a query parameter, matching ExportKeyHandler.
func (h *HandlerContext) ExportKeyMaterialHandler(w http.ResponseWriter, r *http.Request) {
	if h.xkmsService == nil {
		writeError(w, xkms.ErrNotInitialized, http.StatusServiceUnavailable)
		return
	}

	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	backendID := r.URL.Query().Get("backend")
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	resp, err := h.xkmsService.ExportKeyMaterial(r.Context(), &transport.ExportKeyMaterialRequest{
		KeyID:    keyID,
		Backend:  backendID,
		TenantID: callerTenantID(r.Context()),
	})
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, resp, http.StatusOK)
}
