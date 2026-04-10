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
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/seal/policy"
)

// PolicyHandlers provides HTTP handlers for PCR policy management.
type PolicyHandlers struct {
	manager *policy.Manager
}

// NewPolicyHandlers creates a new PolicyHandlers instance.
func NewPolicyHandlers(manager *policy.Manager) *PolicyHandlers {
	return &PolicyHandlers{manager: manager}
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
	Name       string `json:"name"`
	Bank       string `json:"bank"`
	PCRIndices []int  `json:"pcr_indices"`
	CreatedAt  string `json:"created_at"`
	Message    string `json:"message"`
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

	def, err := h.manager.CreatePolicy(req.Name, req.Bank, req.PCRIndices)
	if err != nil {
		switch {
		case errors.Is(err, policy.ErrInvalidName):
			policyWriteJSONError(w, "Policy name must not be empty", http.StatusBadRequest)
		case errors.Is(err, policy.ErrInvalidBank):
			policyWriteJSONError(w, "PCR bank must not be empty", http.StatusBadRequest)
		case errors.Is(err, policy.ErrUnsupportedBank):
			policyWriteJSONError(w, "Unsupported PCR bank algorithm", http.StatusBadRequest)
		case errors.Is(err, policy.ErrNoPCRsSelected):
			policyWriteJSONError(w, "At least one PCR index is required", http.StatusBadRequest)
		case errors.Is(err, policy.ErrPCRIndexOutOfRange):
			policyWriteJSONError(w, "PCR index out of range (must be 0-23)", http.StatusBadRequest)
		case errors.Is(err, policy.ErrDuplicatePCRIndex):
			policyWriteJSONError(w, "Duplicate PCR index", http.StatusBadRequest)
		case errors.Is(err, policy.ErrPolicyExists):
			policyWriteJSONError(w, "Policy with this name already exists", http.StatusConflict)
		default:
			policyWriteJSONError(w, "Failed to create policy", http.StatusInternalServerError)
		}
		return
	}

	resp := PolicyCreateResponse{
		Name:       def.Name,
		Bank:       def.Bank,
		PCRIndices: def.PCRIndices,
		CreatedAt:  def.CreatedAt.Format("2006-01-02T15:04:05Z"),
		Message:    "Policy created successfully",
	}

	writeJSON(w, resp, http.StatusCreated)
}

// ListPoliciesHandler handles GET /api/v1/policies requests.
// It returns all stored PCR policy definitions.
func (h *PolicyHandlers) ListPoliciesHandler(w http.ResponseWriter, r *http.Request) {
	defs, err := h.manager.ListPolicies()
	if err != nil {
		policyWriteJSONError(w, "Failed to list policies", http.StatusInternalServerError)
		return
	}

	infos := make([]PolicyInfo, len(defs))
	for i, def := range defs {
		infos[i] = PolicyInfo{
			Name:       def.Name,
			Bank:       def.Bank,
			PCRIndices: def.PCRIndices,
			CreatedAt:  def.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt:  def.UpdatedAt.Format("2006-01-02T15:04:05Z"),
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

	def, err := h.manager.GetPolicy(name)
	if err != nil {
		if errors.Is(err, policy.ErrPolicyNotFound) {
			policyWriteJSONError(w, "Policy not found", http.StatusNotFound)
			return
		}
		policyWriteJSONError(w, "Failed to get policy", http.StatusInternalServerError)
		return
	}

	resp := PolicyGetResponse{
		Name:       def.Name,
		Bank:       def.Bank,
		PCRIndices: def.PCRIndices,
		PCRValues:  def.PCRValues,
		CreatedAt:  def.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:  def.UpdatedAt.Format("2006-01-02T15:04:05Z"),
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

	if err := h.manager.DeletePolicy(name); err != nil {
		if errors.Is(err, policy.ErrPolicyNotFound) {
			policyWriteJSONError(w, "Policy not found", http.StatusNotFound)
			return
		}
		policyWriteJSONError(w, "Failed to delete policy", http.StatusInternalServerError)
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

	def, err := h.manager.RefreshPolicy(name)
	if err != nil {
		if errors.Is(err, policy.ErrPolicyNotFound) {
			policyWriteJSONError(w, "Policy not found", http.StatusNotFound)
			return
		}
		policyWriteJSONError(w, "Failed to refresh policy", http.StatusInternalServerError)
		return
	}

	resp := PolicyRefreshResponse{
		Name:       def.Name,
		Bank:       def.Bank,
		PCRIndices: def.PCRIndices,
		UpdatedAt:  def.UpdatedAt.Format("2006-01-02T15:04:05Z"),
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

	valid, message, err := h.manager.VerifyPolicy(name)
	if err != nil {
		if errors.Is(err, policy.ErrPolicyNotFound) {
			policyWriteJSONError(w, "Policy not found", http.StatusNotFound)
			return
		}
		policyWriteJSONError(w, "Failed to verify policy", http.StatusInternalServerError)
		return
	}

	if message == "" {
		if valid {
			message = "Policy verification passed"
		} else {
			message = "Policy verification failed: current PCR values do not match"
		}
	}

	resp := PolicyVerifyResponse{
		Name:    name,
		Valid:   valid,
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

	exported, err := h.manager.ExportPolicy(name)
	if err != nil {
		if errors.Is(err, policy.ErrPolicyNotFound) {
			policyWriteJSONError(w, "Policy not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, policy.ErrExportFailed) {
			policyWriteJSONError(w, "Failed to export policy", http.StatusInternalServerError)
			return
		}
		policyWriteJSONError(w, "Failed to export policy", http.StatusInternalServerError)
		return
	}

	resp := PolicyExportResponse{
		Name:       name,
		PolicyJSON: exported,
	}

	writeJSON(w, resp, http.StatusOK)
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
