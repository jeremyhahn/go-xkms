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

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/seal/policy"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// PolicyHandlers provides HTTP handlers for PCR policy management.
//
// Every handler delegates to the XKMSService's Policy* methods and never to
// the policy manager itself: PCR policies bind the platform's sealed secrets
// to its measured boot state, and the service's requirePlatformScope is what
// refuses a tenant-scoped caller (go-xkms#1227). The routes' policy:* grants
// cannot, because a tenant-local Admin's self-scoped grants resolve against
// its own tenant.
type PolicyHandlers struct {
	servicer xkms.PolicyServicer
}

// NewPolicyHandlers creates a new PolicyHandlers instance over the
// XKMSService's PCR policy operations.
func NewPolicyHandlers(servicer xkms.PolicyServicer) *PolicyHandlers {
	return &PolicyHandlers{servicer: servicer}
}

// --- Request types ---

// PolicyCreateRequest is the request body for creating a new PCR policy.
type PolicyCreateRequest struct {
	Name       string `json:"name"`
	Bank       string `json:"bank"`        // e.g., "sha256"
	PCRIndices []int  `json:"pcr_indices"` // e.g., [0, 1, 2, 3, 7]
}

// --- Response types ---

// PolicyCreateResponse is the response after creating a PCR policy.
type PolicyCreateResponse struct {
	Name       string         `json:"name"`
	Bank       string         `json:"bank"`
	PCRIndices []int          `json:"pcr_indices"`
	PCRValues  map[int][]byte `json:"pcr_values"`
	CreatedAt  string         `json:"created_at"`
	Message    string         `json:"message"`
}

// PolicyInfo is a summary of a PCR policy returned in list responses.
type PolicyInfo struct {
	Name       string `json:"name"`
	Bank       string `json:"bank"`
	PCRIndices []int  `json:"pcr_indices"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

// PolicyListResponse is the response for listing PCR policies.
type PolicyListResponse struct {
	Policies []PolicyInfo `json:"policies"`
	Total    int          `json:"total"`
}

// PolicyGetResponse is the detailed response for a single PCR policy.
type PolicyGetResponse struct {
	Name       string         `json:"name"`
	Bank       string         `json:"bank"`
	PCRIndices []int          `json:"pcr_indices"`
	PCRValues  map[int][]byte `json:"pcr_values"`
	CreatedAt  string         `json:"created_at"`
	UpdatedAt  string         `json:"updated_at"`
}

// PolicyDeleteResponse is the response after deleting a PCR policy.
type PolicyDeleteResponse struct {
	Message string `json:"message"`
}

// PolicyRefreshResponse is the response after refreshing a PCR policy.
type PolicyRefreshResponse struct {
	Name       string `json:"name"`
	Bank       string `json:"bank"`
	PCRIndices []int  `json:"pcr_indices"`
	UpdatedAt  string `json:"updated_at"`
	Message    string `json:"message"`
}

// PolicyVerifyResponse is the response for verifying a PCR policy.
type PolicyVerifyResponse struct {
	Name    string `json:"name"`
	Valid   bool   `json:"valid"`
	Message string `json:"message"`
}

// PolicyExportResponse is the response for exporting a PCR policy.
type PolicyExportResponse struct {
	Name       string `json:"name"`
	PolicyJSON string `json:"policy_json"`
}

// --- Handlers ---

// CreatePolicyHandler handles POST /api/v1/policies requests.
// It creates a new PCR policy by capturing the current PCR values for the
// specified bank and indices.
func (h *PolicyHandlers) CreatePolicyHandler(w http.ResponseWriter, r *http.Request) {
	var req PolicyCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		policyWriteJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	created, err := h.servicer.PolicyCreate(r.Context(), &transport.PolicyCreateRequest{
		Name: req.Name,
		Bank: req.Bank,
		PCRs: req.PCRIndices,
	})
	if err != nil {
		policyWriteServiceError(w, err, "Failed to create policy")
		return
	}
	values, err := pcrValuesFromHex(created.Values)
	if err != nil {
		policyWriteJSONError(w, "Failed to create policy", http.StatusInternalServerError)
		return
	}

	resp := PolicyCreateResponse{
		Name:       created.Name,
		Bank:       created.Bank,
		PCRIndices: created.PCRs,
		PCRValues:  values,
		CreatedAt:  created.CreatedAt,
		Message:    "Policy created successfully",
	}

	writeJSON(w, resp, http.StatusCreated)
}

// ListPoliciesHandler handles GET /api/v1/policies requests.
// It returns all stored PCR policy definitions.
func (h *PolicyHandlers) ListPoliciesHandler(w http.ResponseWriter, r *http.Request) {
	list, err := h.servicer.PolicyList(r.Context())
	if err != nil {
		policyWriteServiceError(w, err, "Failed to list policies")
		return
	}

	infos := make([]PolicyInfo, len(list.Policies))
	for i, def := range list.Policies {
		infos[i] = PolicyInfo{
			Name:       def.Name,
			Bank:       def.Bank,
			PCRIndices: def.PCRs,
			CreatedAt:  def.CreatedAt,
			UpdatedAt:  def.UpdatedAt,
		}
	}

	resp := PolicyListResponse{
		Policies: infos,
		Total:    len(infos),
	}

	writeJSON(w, resp, http.StatusOK)
}

// GetPolicyHandler handles GET /api/v1/policies/{name} requests.
// It retrieves a single PCR policy by name, including its PCR values.
func (h *PolicyHandlers) GetPolicyHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		policyWriteJSONError(w, "Policy name is required", http.StatusBadRequest)
		return
	}

	def, err := h.servicer.PolicyGet(r.Context(), &transport.PolicyGetRequest{Name: name})
	if err != nil {
		policyWriteServiceError(w, err, "Failed to get policy")
		return
	}
	values, err := pcrValuesFromHex(def.Values)
	if err != nil {
		policyWriteJSONError(w, "Failed to get policy", http.StatusInternalServerError)
		return
	}

	resp := PolicyGetResponse{
		Name:       def.Name,
		Bank:       def.Bank,
		PCRIndices: def.PCRs,
		PCRValues:  values,
		CreatedAt:  def.CreatedAt,
		UpdatedAt:  def.UpdatedAt,
	}

	writeJSON(w, resp, http.StatusOK)
}

// DeletePolicyHandler handles DELETE /api/v1/policies/{name} requests.
// It removes a PCR policy by name.
func (h *PolicyHandlers) DeletePolicyHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		policyWriteJSONError(w, "Policy name is required", http.StatusBadRequest)
		return
	}

	if err := h.servicer.PolicyDelete(r.Context(), &transport.PolicyDeleteRequest{Name: name}); err != nil {
		policyWriteServiceError(w, err, "Failed to delete policy")
		return
	}

	resp := PolicyDeleteResponse{
		Message: "Policy deleted successfully",
	}

	writeJSON(w, resp, http.StatusOK)
}

// RefreshPolicyHandler handles POST /api/v1/policies/{name}/refresh requests.
// It re-reads the current PCR values for an existing policy and updates
// the stored definition. This is used after a legitimate system change
// (e.g., kernel update) to capture the new expected values.
func (h *PolicyHandlers) RefreshPolicyHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		policyWriteJSONError(w, "Policy name is required", http.StatusBadRequest)
		return
	}

	def, err := h.servicer.PolicyRefresh(r.Context(), &transport.PolicyRefreshRequest{Name: name})
	if err != nil {
		policyWriteServiceError(w, err, "Failed to refresh policy")
		return
	}

	resp := PolicyRefreshResponse{
		Name:       def.Name,
		Bank:       def.Bank,
		PCRIndices: def.PCRs,
		UpdatedAt:  def.UpdatedAt,
		Message:    "Policy refreshed successfully",
	}

	writeJSON(w, resp, http.StatusOK)
}

// VerifyPolicyHandler handles POST /api/v1/policies/{name}/verify requests.
// It reads the current PCR values and compares them against the stored policy.
// Returns whether all PCR values match the expected values.
func (h *PolicyHandlers) VerifyPolicyHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		policyWriteJSONError(w, "Policy name is required", http.StatusBadRequest)
		return
	}

	verified, err := h.servicer.PolicyVerify(r.Context(), &transport.PolicyVerifyRequest{Name: name})
	if err != nil {
		policyWriteServiceError(w, err, "Failed to verify policy")
		return
	}

	message := verified.Message
	if message == "" {
		if verified.Valid {
			message = "Policy verification passed"
		} else {
			message = "Policy verification failed: current PCR values do not match"
		}
	}

	resp := PolicyVerifyResponse{
		Name:    name,
		Valid:   verified.Valid,
		Message: message,
	}

	writeJSON(w, resp, http.StatusOK)
}

// ExportPolicyHandler handles GET /api/v1/policies/{name}/export requests.
// It serializes a named policy to a formatted JSON string suitable for
// backup, transfer, or inspection.
func (h *PolicyHandlers) ExportPolicyHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		policyWriteJSONError(w, "Policy name is required", http.StatusBadRequest)
		return
	}

	exported, err := h.servicer.PolicyExport(r.Context(), &transport.PolicyExportRequest{Name: name})
	if err != nil {
		policyWriteServiceError(w, err, "Failed to export policy")
		return
	}

	resp := PolicyExportResponse{
		Name:       name,
		PolicyJSON: exported.Data,
	}

	writeJSON(w, resp, http.StatusOK)
}

// pcrValuesFromHex decodes the service's hex-encoded PCR values back into the
// raw-byte map this transport's wire shape carries (see pkg/api/rest/wire's
// PCR Policy types).
func pcrValuesFromHex(values map[int]string) (map[int][]byte, error) {
	decoded := make(map[int][]byte, len(values))
	for idx, value := range values {
		raw, err := hex.DecodeString(value)
		if err != nil {
			return nil, err
		}
		decoded[idx] = raw
	}
	return decoded, nil
}

// policyErrorResponses maps the policy service's sentinels to the status and
// fixed message each answers with. The tenant binding's refusal
// (xkms.TenantBindingError, which unwraps to qrdbsdk.ErrTenantMissing)
// renders its own message -- the unknown-tenant text every transport answers
// with -- so policyWriteServiceError handles it before this table.
var policyErrorResponses = []struct {
	sentinel error
	status   int
	message  string
}{
	{xkms.ErrNotConfigured, http.StatusServiceUnavailable, "Policy manager not configured"},
	{policy.ErrPolicyNotFound, http.StatusNotFound, "Policy not found"},
	{policy.ErrInvalidName, http.StatusBadRequest, "Policy name must not be empty"},
	{policy.ErrInvalidBank, http.StatusBadRequest, "PCR bank must not be empty"},
	{policy.ErrUnsupportedBank, http.StatusBadRequest, "Unsupported PCR bank algorithm"},
	{policy.ErrNoPCRsSelected, http.StatusBadRequest, "At least one PCR index is required"},
	{policy.ErrPCRIndexOutOfRange, http.StatusBadRequest, "PCR index out of range (must be 0-23)"},
	{policy.ErrDuplicatePCRIndex, http.StatusBadRequest, "Duplicate PCR index"},
	{policy.ErrPolicyExists, http.StatusConflict, "Policy with this name already exists"},
}

// policyWriteServiceError writes the response for an error returned by the
// policy service. Anything unclassified is a 500 carrying fallback, never the
// error's own text.
func policyWriteServiceError(w http.ResponseWriter, err error, fallback string) {
	if errors.Is(err, qrdbsdk.ErrTenantMissing) {
		policyWriteJSONError(w, err.Error(), http.StatusNotFound)
		return
	}
	for _, entry := range policyErrorResponses {
		if errors.Is(err, entry.sentinel) {
			policyWriteJSONError(w, entry.message, entry.status)
			return
		}
	}
	policyWriteJSONError(w, fallback, http.StatusInternalServerError)
}

// policyWriteJSONError writes an error response in the standard JSON format.
func policyWriteJSONError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := map[string]string{"error": message}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		return
	}
}
