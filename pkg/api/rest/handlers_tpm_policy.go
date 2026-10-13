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
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/jeremyhahn/go-xkms/pkg/api/apierrors"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TPMPolicyHandlers serves the TPM policy API (pkg/tpmpolicy) over REST:
// named TPM policies under /api/v1/tpm/policies, the policy of a key under
// /api/v1/keys/{id}/tpm-policy, authority rotation, and a tenant's TPM mode
// and vTPM under /api/v1/tenants/{tenantID}/tpm.
//
// Every handler delegates to the XKMSService's TPM policy methods, which bind
// the target tenant: every caller acts on its own tenant and may not name
// another through tenant_id, and only a system-tenant caller may reach the
// tenant TPM mode and vTPM routes. Request and response bodies are the
// pkg/api/transport types.
type TPMPolicyHandlers struct {
	servicer transport.TPMPolicyServicer
}

// NewTPMPolicyHandlers returns the TPM policy handlers over servicer.
func NewTPMPolicyHandlers(servicer transport.TPMPolicyServicer) *TPMPolicyHandlers {
	return &TPMPolicyHandlers{servicer: servicer}
}

// classToHTTPStatus renders an apierrors.Class as an HTTP status. A
// precondition refusal -- a policy still assigned to keys, a tenant whose TPM
// mode is none -- conflicts with the resource's current state: 409.
var classToHTTPStatus = map[apierrors.Class]int{
	apierrors.ClassInternal:           http.StatusInternalServerError,
	apierrors.ClassInvalidArgument:    http.StatusBadRequest,
	apierrors.ClassNotFound:           http.StatusNotFound,
	apierrors.ClassAlreadyExists:      http.StatusConflict,
	apierrors.ClassPermissionDenied:   http.StatusForbidden,
	apierrors.ClassFailedPrecondition: http.StatusConflict,
	apierrors.ClassUnavailable:        http.StatusServiceUnavailable,
	apierrors.ClassUnimplemented:      http.StatusNotImplemented,
	apierrors.ClassUnauthenticated:    http.StatusUnauthorized,
	apierrors.ClassDataLoss:           http.StatusInternalServerError,
	apierrors.ClassDeadlineExceeded:   http.StatusGatewayTimeout,
	apierrors.ClassResourceExhausted:  http.StatusTooManyRequests,
}

// classifier classifies an error of one API: an apierrors *ClassOf
// function, the classification every transport of that API reads.
type classifier func(error) (apierrors.Class, bool)

// writeClassifiedError writes the response for an API error, classified
// through classOf. An unclassified error is a 500 whose text is withheld.
func writeClassifiedError(w http.ResponseWriter, err error, classOf classifier) {
	status := http.StatusInternalServerError
	if class, ok := classOf(err); ok {
		if mapped, known := classToHTTPStatus[class]; known {
			status = mapped
		}
	}
	writeError(w, err, status)
}

// writeTPMPolicyError writes the response for a TPM policy API error,
// classified through apierrors.TPMPolicyClassOf -- the classification the
// gRPC and MCP handlers of the same API read.
func writeTPMPolicyError(w http.ResponseWriter, err error) {
	writeClassifiedError(w, err, apierrors.TPMPolicyClassOf)
}

// decodeOptionalJSON decodes r's JSON body into v. An empty body leaves v
// unchanged: the action routes take their policy name from the path and
// need no body.
func decodeOptionalJSON(r *http.Request, v any) error {
	err := json.NewDecoder(r.Body).Decode(v)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// tenantQuery returns the tenant_id query parameter: the tenant a
// cross-tenant caller addresses; empty is the caller's own scope.
func tenantQuery(r *http.Request) string {
	return r.URL.Query().Get("tenant_id")
}

// respond writes resp with status, or the TPM policy error's response.
func respond[R any](w http.ResponseWriter, resp R, err error, status int) {
	respondClassified(w, resp, err, status, apierrors.TPMPolicyClassOf)
}

// respondClassified writes resp with status, or the response of err
// classified through classOf.
func respondClassified[R any](w http.ResponseWriter, resp R, err error, status int, classOf classifier) {
	if err != nil {
		writeClassifiedError(w, err, classOf)
		return
	}
	writeJSON(w, resp, status)
}

// CreatePolicyHandler handles POST /api/v1/tpm/policies.
func (h *TPMPolicyHandlers) CreatePolicyHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.TPMPolicyCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	resp, err := h.servicer.TPMPolicyCreate(r.Context(), &req)
	respond(w, resp, err, http.StatusCreated)
}

// ListPoliciesHandler handles GET /api/v1/tpm/policies.
func (h *TPMPolicyHandlers) ListPoliciesHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := h.servicer.TPMPolicyList(r.Context(), &transport.TPMPolicyListRequest{TenantID: tenantQuery(r)})
	respond(w, resp, err, http.StatusOK)
}

// GetPolicyHandler handles GET /api/v1/tpm/policies/{name}.
func (h *TPMPolicyHandlers) GetPolicyHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := h.servicer.TPMPolicyGet(r.Context(), &transport.TPMPolicyRequest{TenantID: tenantQuery(r), Name: chi.URLParam(r, "name")})
	respond(w, resp, err, http.StatusOK)
}

// ObjectsHandler handles GET /api/v1/tpm/policies/{name}/objects.
func (h *TPMPolicyHandlers) ObjectsHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := h.servicer.TPMPolicyObjects(r.Context(), &transport.TPMPolicyRequest{TenantID: tenantQuery(r), Name: chi.URLParam(r, "name")})
	respond(w, resp, err, http.StatusOK)
}

// policyAction decodes the optional TPMPolicyRequest body of a POST
// /api/v1/tpm/policies/{name}/<action> route; the path names the policy.
func policyAction(w http.ResponseWriter, r *http.Request) (*transport.TPMPolicyRequest, bool) {
	var req transport.TPMPolicyRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return nil, false
	}
	req.Name = chi.URLParam(r, "name")
	return &req, true
}

// UpdatePolicyHandler handles POST /api/v1/tpm/policies/{name}/update.
func (h *TPMPolicyHandlers) UpdatePolicyHandler(w http.ResponseWriter, r *http.Request) {
	req, ok := policyAction(w, r)
	if !ok {
		return
	}
	resp, err := h.servicer.TPMPolicyUpdate(r.Context(), req)
	respond(w, resp, err, http.StatusOK)
}

// RevokePolicyHandler handles POST /api/v1/tpm/policies/{name}/revoke.
func (h *TPMPolicyHandlers) RevokePolicyHandler(w http.ResponseWriter, r *http.Request) {
	req, ok := policyAction(w, r)
	if !ok {
		return
	}
	resp, err := h.servicer.TPMPolicyRevoke(r.Context(), req)
	respond(w, resp, err, http.StatusOK)
}

// VerifyPolicyHandler handles POST /api/v1/tpm/policies/{name}/verify.
func (h *TPMPolicyHandlers) VerifyPolicyHandler(w http.ResponseWriter, r *http.Request) {
	req, ok := policyAction(w, r)
	if !ok {
		return
	}
	resp, err := h.servicer.TPMPolicyVerify(r.Context(), req)
	respond(w, resp, err, http.StatusOK)
}

// AutoUnsealHandler handles POST /api/v1/tpm/policies/{name}/auto-unseal.
func (h *TPMPolicyHandlers) AutoUnsealHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.TPMPolicyAutoUnsealRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	req.Name = chi.URLParam(r, "name")
	resp, err := h.servicer.TPMPolicySetAutoUnseal(r.Context(), &req)
	respond(w, resp, err, http.StatusOK)
}

// DescriptionHandler handles POST /api/v1/tpm/policies/{name}/description.
func (h *TPMPolicyHandlers) DescriptionHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.TPMPolicyDescriptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	req.Name = chi.URLParam(r, "name")
	resp, err := h.servicer.TPMPolicySetDescription(r.Context(), &req)
	respond(w, resp, err, http.StatusOK)
}

// DeletePolicyHandler handles DELETE /api/v1/tpm/policies/{name}. Its
// optional body carries owner_auth; tenant_id comes from the body or the
// query.
func (h *TPMPolicyHandlers) DeletePolicyHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.TPMPolicyDeleteRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	req.Name = chi.URLParam(r, "name")
	if req.TenantID == "" {
		req.TenantID = tenantQuery(r)
	}
	if err := h.servicer.TPMPolicyDelete(r.Context(), &req); err != nil {
		writeTPMPolicyError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ObjectPolicyHandler handles GET /api/v1/keys/{id}/tpm-policy. The kind
// query parameter selects "key" (the default) or "sealed".
func (h *TPMPolicyHandlers) ObjectPolicyHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := h.servicer.TPMObjectPolicy(r.Context(), &transport.TPMObjectPolicyRequest{
		TenantID: tenantQuery(r),
		KeyID:    chi.URLParam(r, "id"),
		Kind:     r.URL.Query().Get("kind"),
	})
	respond(w, resp, err, http.StatusOK)
}

// RotateAuthorityHandler handles POST /api/v1/tpm/authority/rotate.
func (h *TPMPolicyHandlers) RotateAuthorityHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.TPMAuthorityRotateRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	resp, err := h.servicer.TPMPolicyRotateAuthority(r.Context(), &req)
	respond(w, resp, err, http.StatusOK)
}

// GetTenantModeHandler handles GET /api/v1/tenants/{tenantID}/tpm.
func (h *TPMPolicyHandlers) GetTenantModeHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := h.servicer.GetTenantTPMMode(r.Context(), chi.URLParam(r, "tenantID"))
	respond(w, resp, err, http.StatusOK)
}

// SetTenantModeHandler handles PUT /api/v1/tenants/{tenantID}/tpm.
func (h *TPMPolicyHandlers) SetTenantModeHandler(w http.ResponseWriter, r *http.Request) {
	var req transport.SetTenantTPMModeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}
	req.TenantID = chi.URLParam(r, "tenantID")
	resp, err := h.servicer.SetTenantTPMMode(r.Context(), &req)
	respond(w, resp, err, http.StatusOK)
}

// VTPMStatusHandler handles GET /api/v1/tenants/{tenantID}/tpm/vtpm.
func (h *TPMPolicyHandlers) VTPMStatusHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := h.servicer.TenantVTPMStatus(r.Context(), chi.URLParam(r, "tenantID"))
	respond(w, resp, err, http.StatusOK)
}

// VTPMStartHandler handles POST /api/v1/tenants/{tenantID}/tpm/vtpm/start.
func (h *TPMPolicyHandlers) VTPMStartHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := h.servicer.TenantVTPMStart(r.Context(), chi.URLParam(r, "tenantID"))
	respond(w, resp, err, http.StatusOK)
}

// VTPMStopHandler handles POST /api/v1/tenants/{tenantID}/tpm/vtpm/stop.
func (h *TPMPolicyHandlers) VTPMStopHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := h.servicer.TenantVTPMStop(r.Context(), chi.URLParam(r, "tenantID"))
	respond(w, resp, err, http.StatusOK)
}
