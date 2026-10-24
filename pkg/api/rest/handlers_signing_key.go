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

	"github.com/jeremyhahn/go-xkms/pkg/api/apierrors"
	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// SigningKeyHandlers serves the repository signing-key API (go-xkms#1697)
// over REST under /api/v1/attestation/signing-keys. A repository path holds
// slashes, so the routes that name one read it from the repository query
// parameter. Every handler delegates to the XKMSService, which binds the
// call to the caller's tenant. Request and response bodies are the
// pkg/api/transport types.
type SigningKeyHandlers struct {
	servicer transport.SigningKeyServicer
}

// NewSigningKeyHandlers returns the signing-key handlers over servicer.
func NewSigningKeyHandlers(servicer transport.SigningKeyServicer) *SigningKeyHandlers {
	return &SigningKeyHandlers{servicer: servicer}
}

// respondSigningKey writes resp with status, or the response of err
// classified through apierrors.SigningKeyClassOf -- the classification the
// gRPC and MCP handlers of the same API read.
func respondSigningKey[R any](w http.ResponseWriter, resp R, err error, status int) {
	respondClassified(w, resp, err, status, apierrors.SigningKeyClassOf)
}

// repositoryQuery returns the repository a request names.
func repositoryQuery(r *http.Request) string {
	return r.URL.Query().Get(wire.SigningKeyRepositoryParam)
}

// SetHandler handles PUT /api/v1/attestation/signing-keys.
func (h *SigningKeyHandlers) SetHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.SetSigningKeyBindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	resp, err := h.servicer.SetSigningKeyBinding(r.Context(), &req)
	respondSigningKey(w, resp, err, http.StatusOK)
}

// ListHandler handles GET /api/v1/attestation/signing-keys.
func (h *SigningKeyHandlers) ListHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := h.servicer.ListSigningKeyBindings(r.Context())
	respondSigningKey(w, resp, err, http.StatusOK)
}

// GetHandler handles GET /api/v1/attestation/signing-keys/binding.
func (h *SigningKeyHandlers) GetHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := h.servicer.GetSigningKeyBinding(r.Context(), &transport.GetSigningKeyBindingRequest{Repository: repositoryQuery(r)})
	respondSigningKey(w, resp, err, http.StatusOK)
}

// DeleteHandler handles DELETE /api/v1/attestation/signing-keys/binding.
func (h *SigningKeyHandlers) DeleteHandler(w http.ResponseWriter, r *http.Request) {
	if err := h.servicer.DeleteSigningKeyBinding(r.Context(), &transport.DeleteSigningKeyBindingRequest{Repository: repositoryQuery(r)}); err != nil {
		writeClassifiedError(w, err, apierrors.SigningKeyClassOf)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ResolveHandler handles GET /api/v1/attestation/signing-keys/resolve.
func (h *SigningKeyHandlers) ResolveHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := h.servicer.ResolveSigningKey(r.Context(), &transport.ResolveSigningKeyRequest{Repository: repositoryQuery(r)})
	respondSigningKey(w, resp, err, http.StatusOK)
}

// SignCoRIMHandler handles POST /api/v1/attestation/signing-keys/sign-corim:
// it signs the request's CoRIM with the key ResolveSigningKey names for the
// repository, draft-ietf-rats-corim-11 §4.2.
func (h *SigningKeyHandlers) SignCoRIMHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.SignCoRIMRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	resp, err := h.servicer.SignCoRIM(r.Context(), &req)
	respondSigningKey(w, resp, err, http.StatusOK)
}
