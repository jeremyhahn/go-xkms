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
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TrustRootHandlers serves the platform trust-root store over REST, the
// server side of wire.TrustRootClient. The routes gate on the trust_roots
// resource (routes.go), matching the gRPC/MCP/Unix TrustRoot* handlers.
type TrustRootHandlers struct {
	servicer transport.TrustRootServicer
}

// NewTrustRootHandlers returns the trust-root handlers over servicer.
func NewTrustRootHandlers(servicer transport.TrustRootServicer) *TrustRootHandlers {
	return &TrustRootHandlers{servicer: servicer}
}

// trustRootClassOf classifies a trust-root store error through
// apierrors.TrustRootSentinelClasses, the table every transport shares.
func trustRootClassOf(err error) (apierrors.Class, bool) {
	return apierrors.ClassOf(apierrors.TrustRootSentinelClasses, err)
}

// ListHandler handles GET /trust-roots, optionally filtered by ?purpose=.
func (h *TrustRootHandlers) ListHandler(w http.ResponseWriter, r *http.Request) {
	req := transport.TrustRootListRequest{Purpose: r.URL.Query().Get("purpose")}
	resp, err := h.servicer.TrustRootList(r.Context(), &req)
	respondClassified(w, resp, err, http.StatusOK, trustRootClassOf)
}

// GetHandler handles GET /trust-roots/{fingerprint}.
func (h *TrustRootHandlers) GetHandler(w http.ResponseWriter, r *http.Request) {
	req := transport.TrustRootRequest{Fingerprint: chi.URLParam(r, "fingerprint")}
	resp, err := h.servicer.TrustRootGet(r.Context(), &req)
	respondClassified(w, resp, err, http.StatusOK, trustRootClassOf)
}

// ImportHandler handles POST /trust-roots. It answers 200 rather than 201:
// an import that only meets certificates already held creates nothing.
func (h *TrustRootHandlers) ImportHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.TrustRootImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	resp, err := h.servicer.TrustRootImport(r.Context(), &req)
	respondClassified(w, resp, err, http.StatusOK, trustRootClassOf)
}

// QuarantineHandler handles POST /trust-roots/{fingerprint}/quarantine.
func (h *TrustRootHandlers) QuarantineHandler(w http.ResponseWriter, r *http.Request) {
	req := transport.TrustRootRequest{Fingerprint: chi.URLParam(r, "fingerprint")}
	resp, err := h.servicer.TrustRootQuarantine(r.Context(), &req)
	respondClassified(w, resp, err, http.StatusOK, trustRootClassOf)
}

// RemoveHandler handles DELETE /trust-roots/{fingerprint}.
func (h *TrustRootHandlers) RemoveHandler(w http.ResponseWriter, r *http.Request) {
	req := transport.TrustRootRequest{Fingerprint: chi.URLParam(r, "fingerprint")}
	if err := h.servicer.TrustRootRemove(r.Context(), &req); err != nil {
		writeClassifiedError(w, err, trustRootClassOf)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
