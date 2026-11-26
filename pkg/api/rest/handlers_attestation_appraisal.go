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

// AttestationAppraisalHandlers serves the attestation Verifier API
// (go-xkms#1608) over REST: the trust anchors under
// /api/v1/attestation/endorsements, the signed CoRIM reference values under
// /api/v1/attestation/reference-values and quote appraisal at
// /api/v1/attestation/appraise. Every handler delegates to the XKMSService,
// which binds the call to the caller's tenant. Request and response bodies
// are the pkg/api/transport types.
type AttestationAppraisalHandlers struct {
	servicer transport.AttestationAppraisalServicer
}

// NewAttestationAppraisalHandlers returns the Verifier handlers over
// servicer.
func NewAttestationAppraisalHandlers(servicer transport.AttestationAppraisalServicer) *AttestationAppraisalHandlers {
	return &AttestationAppraisalHandlers{servicer: servicer}
}

// respondAppraisal writes resp with status, or the response of err
// classified through apierrors.AttestationAppraisalClassOf -- the
// classification the gRPC and MCP handlers of the same API read.
func respondAppraisal[R any](w http.ResponseWriter, resp R, err error) {
	respondClassified(w, resp, err, http.StatusOK, apierrors.AttestationAppraisalClassOf)
}

// respondAppraisalDeleted answers a removal with 204, or the classified
// response of err.
func respondAppraisalDeleted(w http.ResponseWriter, err error) {
	if err != nil {
		writeClassifiedError(w, err, apierrors.AttestationAppraisalClassOf)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// decodeAppraisalBody decodes the request body into req, answering 400 and
// reporting false when it is not JSON of that shape.
func decodeAppraisalBody(w http.ResponseWriter, r *http.Request, req any) bool {
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return false
	}
	return true
}

// PutEndorsementHandler handles PUT /api/v1/attestation/endorsements.
func (h *AttestationAppraisalHandlers) PutEndorsementHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.PutAttestationEndorsementRequest
	if !decodeAppraisalBody(w, r, &req) {
		return
	}
	resp, err := h.servicer.PutAttestationEndorsement(r.Context(), &req)
	respondAppraisal(w, resp, err)
}

// ListEndorsementsHandler handles GET /api/v1/attestation/endorsements,
// filtered by the kind query parameter when present.
func (h *AttestationAppraisalHandlers) ListEndorsementsHandler(w http.ResponseWriter, r *http.Request) {
	kind := transport.AttestationEndorsementKind(r.URL.Query().Get(wire.AttestationEndorsementKindParam))
	resp, err := h.servicer.ListAttestationEndorsements(r.Context(), &transport.ListAttestationEndorsementsRequest{Kind: kind})
	respondAppraisal(w, resp, err)
}

// DeleteEndorsementHandler handles DELETE
// /api/v1/attestation/endorsements/{name}.
func (h *AttestationAppraisalHandlers) DeleteEndorsementHandler(w http.ResponseWriter, r *http.Request) {
	err := h.servicer.DeleteAttestationEndorsement(r.Context(), &transport.DeleteAttestationEndorsementRequest{Name: chi.URLParam(r, "name")})
	respondAppraisalDeleted(w, err)
}

// PutReferenceValuesHandler handles PUT /api/v1/attestation/reference-values.
func (h *AttestationAppraisalHandlers) PutReferenceValuesHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.PutAttestationReferenceValuesRequest
	if !decodeAppraisalBody(w, r, &req) {
		return
	}
	resp, err := h.servicer.PutAttestationReferenceValues(r.Context(), &req)
	respondAppraisal(w, resp, err)
}

// GetReferenceValuesHandler handles GET
// /api/v1/attestation/reference-values/{name}.
func (h *AttestationAppraisalHandlers) GetReferenceValuesHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := h.servicer.GetAttestationReferenceValues(r.Context(), &transport.GetAttestationReferenceValuesRequest{Name: chi.URLParam(r, "name")})
	respondAppraisal(w, resp, err)
}

// ListReferenceValuesHandler handles GET /api/v1/attestation/reference-values.
func (h *AttestationAppraisalHandlers) ListReferenceValuesHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := h.servicer.ListAttestationReferenceValues(r.Context())
	respondAppraisal(w, resp, err)
}

// DeleteReferenceValuesHandler handles DELETE
// /api/v1/attestation/reference-values/{name}.
func (h *AttestationAppraisalHandlers) DeleteReferenceValuesHandler(w http.ResponseWriter, r *http.Request) {
	err := h.servicer.DeleteAttestationReferenceValues(r.Context(), &transport.DeleteAttestationReferenceValuesRequest{Name: chi.URLParam(r, "name")})
	respondAppraisalDeleted(w, err)
}

// AppraiseQuoteHandler handles POST /api/v1/attestation/appraise.
func (h *AttestationAppraisalHandlers) AppraiseQuoteHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.AppraiseAttestationQuoteRequest
	if !decodeAppraisalBody(w, r, &req) {
		return
	}
	resp, err := h.servicer.AppraiseAttestationQuote(r.Context(), &req)
	respondAppraisal(w, resp, err)
}
