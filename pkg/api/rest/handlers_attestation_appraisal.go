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
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// AttestationAppraisalHandlers serves the attestation Verifier API
// (go-xkms#1660): a tenant's endorsements and reference values, and quote
// appraisal. The routes gate each verb on its permission; the service binds
// every call to the caller's tenant.
type AttestationAppraisalHandlers struct {
	servicer transport.AttestationAppraisalServicer
}

// NewAttestationAppraisalHandlers returns the appraisal handlers over
// servicer.
func NewAttestationAppraisalHandlers(servicer transport.AttestationAppraisalServicer) *AttestationAppraisalHandlers {
	return &AttestationAppraisalHandlers{servicer: servicer}
}

// appraisalSentinelClasses classifies the errors of the appraisal verbs. A
// server without an Appraiser has nothing to answer with; a request the
// Appraiser cannot use, or evidence it refuses, is the caller's fault. The
// appraisal's typed errors wrap these sentinels.
var appraisalSentinelClasses = []apierrors.SentinelClass{
	{Sentinel: xkms.ErrNotConfigured, Class: apierrors.ClassUnavailable},
	{Sentinel: appraisal.ErrNilRequest, Class: apierrors.ClassInvalidArgument},
	{Sentinel: appraisal.ErrInvalidName, Class: apierrors.ClassInvalidArgument},
	{Sentinel: appraisal.ErrInvalidTenant, Class: apierrors.ClassInvalidArgument},
	{Sentinel: appraisal.ErrInvalidRepository, Class: apierrors.ClassInvalidArgument},
	{Sentinel: appraisal.ErrEndorsementInvalid, Class: apierrors.ClassInvalidArgument},
	{Sentinel: appraisal.ErrReferenceValuesRejected, Class: apierrors.ClassInvalidArgument},
	{Sentinel: appraisal.ErrInvalidAKIntermediate, Class: apierrors.ClassInvalidArgument},
	{Sentinel: appraisal.ErrRecordNotFound, Class: apierrors.ClassNotFound},
	{Sentinel: appraisal.ErrStoreUnavailable, Class: apierrors.ClassUnavailable},
}

// appraisalClassOf classifies an error of the appraisal verbs.
func appraisalClassOf(err error) (apierrors.Class, bool) {
	return apierrors.ClassOf(appraisalSentinelClasses, err)
}

// respondAppraisal writes resp with status, or the response of err
// classified through appraisalClassOf.
func respondAppraisal[R any](w http.ResponseWriter, resp R, err error, status int) {
	respondClassified(w, resp, err, status, appraisalClassOf)
}

// respondAppraisalDeleted writes 204, or the response of err.
func respondAppraisalDeleted(w http.ResponseWriter, err error) {
	if err != nil {
		writeClassifiedError(w, err, appraisalClassOf)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// decodeAppraisal decodes the request body into req, answering 400 when it
// cannot.
func decodeAppraisal(w http.ResponseWriter, r *http.Request, req any) bool {
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return false
	}
	return true
}

func nameQuery(r *http.Request) string {
	return r.URL.Query().Get(wire.AttestationNameParam)
}

// PutEndorsementHandler handles PUT /api/v1/attestation/endorsements.
func (h *AttestationAppraisalHandlers) PutEndorsementHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.PutAttestationEndorsementRequest
	if !decodeAppraisal(w, r, &req) {
		return
	}
	resp, err := h.servicer.PutAttestationEndorsement(r.Context(), &req)
	respondAppraisal(w, resp, err, http.StatusOK)
}

// ListEndorsementsHandler handles GET /api/v1/attestation/endorsements.
func (h *AttestationAppraisalHandlers) ListEndorsementsHandler(w http.ResponseWriter, r *http.Request) {
	req := transport.ListAttestationEndorsementsRequest{
		Kind: appraisal.EndorsementKind(r.URL.Query().Get(wire.AttestationKindParam)),
	}
	resp, err := h.servicer.ListAttestationEndorsements(r.Context(), &req)
	respondAppraisal(w, resp, err, http.StatusOK)
}

// DeleteEndorsementHandler handles DELETE /api/v1/attestation/endorsements.
func (h *AttestationAppraisalHandlers) DeleteEndorsementHandler(w http.ResponseWriter, r *http.Request) {
	err := h.servicer.DeleteAttestationEndorsement(r.Context(), &transport.DeleteAttestationEndorsementRequest{Name: nameQuery(r)})
	respondAppraisalDeleted(w, err)
}

// PutReferenceValuesHandler handles PUT /api/v1/attestation/reference-values.
func (h *AttestationAppraisalHandlers) PutReferenceValuesHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.PutAttestationReferenceValuesRequest
	if !decodeAppraisal(w, r, &req) {
		return
	}
	resp, err := h.servicer.PutAttestationReferenceValues(r.Context(), &req)
	respondAppraisal(w, resp, err, http.StatusOK)
}

// ListReferenceValuesHandler handles GET /api/v1/attestation/reference-values.
func (h *AttestationAppraisalHandlers) ListReferenceValuesHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := h.servicer.ListAttestationReferenceValues(r.Context())
	respondAppraisal(w, resp, err, http.StatusOK)
}

// GetReferenceValuesHandler handles
// GET /api/v1/attestation/reference-values/entry.
func (h *AttestationAppraisalHandlers) GetReferenceValuesHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := h.servicer.GetAttestationReferenceValues(r.Context(), &transport.GetAttestationReferenceValuesRequest{Name: nameQuery(r)})
	respondAppraisal(w, resp, err, http.StatusOK)
}

// DeleteReferenceValuesHandler handles
// DELETE /api/v1/attestation/reference-values/entry.
func (h *AttestationAppraisalHandlers) DeleteReferenceValuesHandler(w http.ResponseWriter, r *http.Request) {
	err := h.servicer.DeleteAttestationReferenceValues(r.Context(), &transport.DeleteAttestationReferenceValuesRequest{Name: nameQuery(r)})
	respondAppraisalDeleted(w, err)
}

// AppraiseHandler handles POST /api/v1/attestation/appraise.
func (h *AttestationAppraisalHandlers) AppraiseHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.AppraiseAttestationQuoteRequest
	if !decodeAppraisal(w, r, &req) {
		return
	}
	resp, err := h.servicer.AppraiseAttestationQuote(r.Context(), &req)
	respondAppraisal(w, resp, err, http.StatusOK)
}
