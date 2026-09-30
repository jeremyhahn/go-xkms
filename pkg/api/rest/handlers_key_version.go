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
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// The key-version handlers serve the key-version API over REST:
//
//	GET  /api/v1/keys/{id}/versions                      list the versions
//	POST /api/v1/keys/{id}/versions/{version}/enable     enable one
//	POST /api/v1/keys/{id}/versions/{version}/disable    disable one
//	POST /api/v1/keys/{id}/versions/{version}/retire     retire one
//	POST /api/v1/keys/{id}/versions/enable-all           enable every disabled one
//	POST /api/v1/keys/{id}/versions/disable-all          disable every non-current one
//	POST /api/v1/keys/rotate-all                         rotate every key of a tenant
//
// Each names its key's backend with the "backend" query parameter, as the
// other key routes do, and acts in the caller's tenant. rotate-all takes the
// tenant from its JSON body ({"tenant_id": ...}); only a system caller may
// name another tenant. Responses are the pkg/api/transport types.

// keyVersionTarget reads the key ID and backend every per-key version route
// names, writing the 400 for a missing one.
func (h *HandlerContext) keyVersionTarget(w http.ResponseWriter, r *http.Request) (keyID, backendID string, ok bool) {
	keyID = chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return "", "", false
	}
	backendID = r.URL.Query().Get("backend")
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return "", "", false
	}
	if h.xkmsService == nil {
		mapKeyOpError(w, xkms.ErrNotInitialized)
		return "", "", false
	}
	return keyID, backendID, true
}

// ListKeyVersionsHandler handles GET /api/v1/keys/{id}/versions.
func (h *HandlerContext) ListKeyVersionsHandler(w http.ResponseWriter, r *http.Request) {
	keyID, backendID, ok := h.keyVersionTarget(w, r)
	if !ok {
		return
	}
	resp, err := h.xkmsService.ListKeyVersions(r.Context(), &transport.ListKeyVersionsRequest{
		Backend: backendID, KeyID: keyID, TenantID: callerTenantID(r.Context()),
	})
	respondKeyOp(w, resp, err)
}

// EnableKeyVersionHandler handles POST /api/v1/keys/{id}/versions/{version}/enable.
func (h *HandlerContext) EnableKeyVersionHandler(w http.ResponseWriter, r *http.Request) {
	h.keyVersionAction(w, r, h.xkmsService.EnableKeyVersion)
}

// DisableKeyVersionHandler handles POST /api/v1/keys/{id}/versions/{version}/disable.
func (h *HandlerContext) DisableKeyVersionHandler(w http.ResponseWriter, r *http.Request) {
	h.keyVersionAction(w, r, h.xkmsService.DisableKeyVersion)
}

// RetireKeyVersionHandler handles POST /api/v1/keys/{id}/versions/{version}/retire.
func (h *HandlerContext) RetireKeyVersionHandler(w http.ResponseWriter, r *http.Request) {
	h.keyVersionAction(w, r, h.xkmsService.RetireKeyVersion)
}

// keyVersionAction runs action on the version the route names. A version
// that is not a positive 32-bit integer is a 400.
func (h *HandlerContext) keyVersionAction(w http.ResponseWriter, r *http.Request,
	action func(context.Context, *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error)) {

	keyID, backendID, ok := h.keyVersionTarget(w, r)
	if !ok {
		return
	}
	version, err := strconv.ParseUint(chi.URLParam(r, "version"), 10, 32)
	if err != nil || version == 0 {
		writeError(w, ErrInvalidKeyVersion, http.StatusBadRequest)
		return
	}
	resp, err := action(r.Context(), &transport.KeyVersionRequest{
		Backend: backendID, KeyID: keyID, Version: uint32(version), TenantID: callerTenantID(r.Context()),
	})
	respondKeyOp(w, resp, err)
}

// EnableAllKeyVersionsHandler handles POST /api/v1/keys/{id}/versions/enable-all.
func (h *HandlerContext) EnableAllKeyVersionsHandler(w http.ResponseWriter, r *http.Request) {
	h.allKeyVersionsAction(w, r, h.xkmsService.EnableAllKeyVersions)
}

// DisableAllKeyVersionsHandler handles POST /api/v1/keys/{id}/versions/disable-all.
func (h *HandlerContext) DisableAllKeyVersionsHandler(w http.ResponseWriter, r *http.Request) {
	h.allKeyVersionsAction(w, r, h.xkmsService.DisableAllKeyVersions)
}

// allKeyVersionsAction runs a bulk version action on the key the route names.
func (h *HandlerContext) allKeyVersionsAction(w http.ResponseWriter, r *http.Request,
	action func(context.Context, *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error)) {

	keyID, backendID, ok := h.keyVersionTarget(w, r)
	if !ok {
		return
	}
	resp, err := action(r.Context(), &transport.AllKeyVersionsRequest{
		Backend: backendID, KeyID: keyID, TenantID: callerTenantID(r.Context()),
	})
	respondKeyOp(w, resp, err)
}

// RotateScopeKeysHandler handles POST /api/v1/keys/rotate-all. The body is
// optional: without one the caller's own tenant is rotated.
func (h *HandlerContext) RotateScopeKeysHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.RotateScopeKeysRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	if h.xkmsService == nil {
		mapKeyOpError(w, xkms.ErrNotInitialized)
		return
	}
	resp, err := h.xkmsService.RotateScopeKeys(r.Context(), &req)
	respondKeyOp(w, resp, err)
}

// respondKeyOp writes resp as a 200, or err through the key-operation
// classification.
func respondKeyOp[R any](w http.ResponseWriter, resp R, err error) {
	if err != nil {
		mapKeyOpError(w, err)
		return
	}
	writeJSON(w, resp, http.StatusOK)
}
