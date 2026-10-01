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
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/jeremyhahn/go-xkms/pkg/api/apierrors"
	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// OIDCCredentialHandlers serves the server-side OIDC credential API
// (pkg/oidc/credential) over REST: the collection under
// /api/v1/oidc/credentials and each credential under
// /api/v1/oidc/credentials/{scope}/{name}.
//
// The path names a credential's scope ("tenant" or "user") and name; the
// tenant_id and owner query parameters name its tenant and, for a personal
// credential, its owner -- both empty for the caller's own. Every handler
// delegates to the XKMSService's OIDC credential methods, whose credential
// service enforces the tenant binding and owner-only personal credentials.
// Request and response bodies are the pkg/api/transport types.
type OIDCCredentialHandlers struct {
	servicer transport.OIDCCredentialServicer
}

// NewOIDCCredentialHandlers returns the OIDC credential handlers over
// servicer.
func NewOIDCCredentialHandlers(servicer transport.OIDCCredentialServicer) *OIDCCredentialHandlers {
	return &OIDCCredentialHandlers{servicer: servicer}
}

// respondOIDCCredential writes resp with status, or the response of err
// classified through apierrors.OIDCCredentialClassOf -- the classification
// the gRPC and MCP handlers of the same API read.
func respondOIDCCredential[R any](w http.ResponseWriter, resp R, err error, status int) {
	respondClassified(w, resp, err, status, apierrors.OIDCCredentialClassOf)
}

// oidcCredentialRef returns the credential reference of a
// /api/v1/oidc/credentials/{scope}/{name} request.
func oidcCredentialRef(r *http.Request) *transport.OIDCCredentialRef {
	query := r.URL.Query()
	return &transport.OIDCCredentialRef{
		TenantID: query.Get("tenant_id"),
		Scope:    chi.URLParam(r, "scope"),
		Owner:    query.Get("owner"),
		Name:     chi.URLParam(r, "name"),
	}
}

// CreateHandler handles POST /api/v1/oidc/credentials.
func (h *OIDCCredentialHandlers) CreateHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.OIDCCredentialCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	resp, err := h.servicer.OIDCCredentialCreate(r.Context(), &req)
	respondOIDCCredential(w, resp, err, http.StatusCreated)
}

// ListHandler handles GET /api/v1/oidc/credentials.
func (h *OIDCCredentialHandlers) ListHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := h.servicer.OIDCCredentialList(r.Context(), &transport.OIDCCredentialListRequest{TenantID: tenantQuery(r)})
	respondOIDCCredential(w, resp, err, http.StatusOK)
}

// GetHandler handles GET /api/v1/oidc/credentials/{scope}/{name}.
func (h *OIDCCredentialHandlers) GetHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := h.servicer.OIDCCredentialGet(r.Context(), oidcCredentialRef(r))
	respondOIDCCredential(w, resp, err, http.StatusOK)
}

// DeleteHandler handles DELETE /api/v1/oidc/credentials/{scope}/{name}.
func (h *OIDCCredentialHandlers) DeleteHandler(w http.ResponseWriter, r *http.Request) {
	if err := h.servicer.OIDCCredentialDelete(r.Context(), oidcCredentialRef(r)); err != nil {
		writeClassifiedError(w, err, apierrors.OIDCCredentialClassOf)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ImportHandler handles POST /api/v1/oidc/credentials/{scope}/{name}/import.
// Its body carries the tokens; the path and query name the credential.
func (h *OIDCCredentialHandlers) ImportHandler(w http.ResponseWriter, r *http.Request) {
	var body wire.OIDCCredentialImportBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	resp, err := h.servicer.OIDCCredentialImport(r.Context(), &transport.OIDCCredentialImportRequest{
		OIDCCredentialRef: *oidcCredentialRef(r),
		Tokens:            body.Tokens,
	})
	respondOIDCCredential(w, resp, err, http.StatusOK)
}

// RefreshHandler handles POST /api/v1/oidc/credentials/{scope}/{name}/refresh.
func (h *OIDCCredentialHandlers) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := h.servicer.OIDCCredentialRefresh(r.Context(), oidcCredentialRef(r))
	respondOIDCCredential(w, resp, err, http.StatusOK)
}

// TokenHandler handles POST /api/v1/oidc/credentials/{scope}/{name}/token.
// The route is a POST, and its answer is marked no-store, so a bearer token
// is never held by a cache between the server and the caller.
func (h *OIDCCredentialHandlers) TokenHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	resp, err := h.servicer.OIDCCredentialGetAccessToken(r.Context(), oidcCredentialRef(r))
	respondOIDCCredential(w, resp, err, http.StatusOK)
}

// DeviceStartHandler handles POST /api/v1/oidc/credentials/{scope}/{name}/device.
func (h *OIDCCredentialHandlers) DeviceStartHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := h.servicer.OIDCCredentialDeviceStart(r.Context(), oidcCredentialRef(r))
	respondOIDCCredential(w, resp, err, http.StatusOK)
}

// DevicePollHandler handles POST
// /api/v1/oidc/credentials/{scope}/{name}/device/poll.
func (h *OIDCCredentialHandlers) DevicePollHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := h.servicer.OIDCCredentialDevicePoll(r.Context(), oidcCredentialRef(r))
	respondOIDCCredential(w, resp, err, http.StatusOK)
}
