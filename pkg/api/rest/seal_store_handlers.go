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
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

// SealStoreHandlers provides HTTP handlers for platform store operations.
type SealStoreHandlers struct {
	store seal.PlatformStore
}

// NewSealStoreHandlers creates a new SealStoreHandlers instance.
func NewSealStoreHandlers(store seal.PlatformStore) *SealStoreHandlers {
	return &SealStoreHandlers{store: store}
}

// --- Request types ---

// SealStorePutRequest is the request body for storing a secret.
type SealStorePutRequest struct {
	Name   string `json:"name"`
	Secret string `json:"secret"` // base64-encoded secret
}

// --- Response types ---

// SealStoreGetResponse is the response for retrieving a secret.
type SealStoreGetResponse struct {
	Name   string `json:"name"`
	Secret string `json:"secret"` // base64-encoded secret
}

// SealStoreListResponse is the response for listing secret names.
type SealStoreListResponse struct {
	Names []string `json:"names"`
	Total int      `json:"total"`
}

// SealStoreDeleteResponse is the response after deleting a secret.
type SealStoreDeleteResponse struct {
	Message string `json:"message"`
}

// SealStoreResealResponse is the response after resealing a secret.
type SealStoreResealResponse struct {
	Name    string `json:"name"`
	Message string `json:"message"`
}

// SealStoreStatusResponse is the response for the platform store status endpoint.
type SealStoreStatusResponse struct {
	Available bool     `json:"available"`
	Names     []string `json:"names"`
	Total     int      `json:"total"`
}

// SealStorePutResponse is the response after storing a secret.
type SealStorePutResponse struct {
	Name    string `json:"name"`
	Message string `json:"message"`
}

// --- Handlers ---

// PutSecretHandler handles PUT /api/v1/platform-store/{name} requests.
// It stores a secret under the given name. The request body must contain
// the base64-encoded secret. If a secret already exists with this name,
// it is overwritten with a fresh seal operation.
func (h *SealStoreHandlers) PutSecretHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		platformStoreWriteJSONError(w, "Secret name is required", http.StatusBadRequest)
		return
	}

	var req SealStorePutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		platformStoreWriteJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Secret == "" {
		platformStoreWriteJSONError(w, "Secret value is required", http.StatusBadRequest)
		return
	}

	secret, err := base64.StdEncoding.DecodeString(req.Secret)
	if err != nil {
		platformStoreWriteJSONError(w, "Invalid base64-encoded secret", http.StatusBadRequest)
		return
	}

	if err := h.store.Put(r.Context(), name, secret); err != nil {
		if errors.Is(err, seal.ErrInvalidSecretName) {
			platformStoreWriteJSONError(w, "Invalid secret name", http.StatusBadRequest)
			return
		}
		platformStoreWriteJSONError(w, "Failed to store secret", http.StatusInternalServerError)
		return
	}

	resp := SealStorePutResponse{
		Name:    name,
		Message: "Secret stored successfully",
	}

	writeJSON(w, resp, http.StatusOK)
}

// GetSecretHandler handles GET /api/v1/platform-store/{name} requests.
// It retrieves and unseals the secret stored under the given name.
func (h *SealStoreHandlers) GetSecretHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		platformStoreWriteJSONError(w, "Secret name is required", http.StatusBadRequest)
		return
	}

	secret, err := h.store.Get(r.Context(), name)
	if err != nil {
		if errors.Is(err, seal.ErrSecretNotFound) {
			platformStoreWriteJSONError(w, "Secret not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, seal.ErrInvalidSecretName) {
			platformStoreWriteJSONError(w, "Invalid secret name", http.StatusBadRequest)
			return
		}
		platformStoreWriteJSONError(w, "Failed to retrieve secret", http.StatusInternalServerError)
		return
	}

	resp := SealStoreGetResponse{
		Name:   name,
		Secret: base64.StdEncoding.EncodeToString(secret),
	}

	writeJSON(w, resp, http.StatusOK)
}

// DeleteSecretHandler handles DELETE /api/v1/platform-store/{name} requests.
// It removes the secret stored under the given name.
func (h *SealStoreHandlers) DeleteSecretHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		platformStoreWriteJSONError(w, "Secret name is required", http.StatusBadRequest)
		return
	}

	if err := h.store.Delete(r.Context(), name); err != nil {
		if errors.Is(err, seal.ErrSecretNotFound) {
			platformStoreWriteJSONError(w, "Secret not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, seal.ErrInvalidSecretName) {
			platformStoreWriteJSONError(w, "Invalid secret name", http.StatusBadRequest)
			return
		}
		platformStoreWriteJSONError(w, "Failed to delete secret", http.StatusInternalServerError)
		return
	}

	resp := SealStoreDeleteResponse{
		Message: "Secret deleted successfully",
	}

	writeJSON(w, resp, http.StatusOK)
}

// ListSecretsHandler handles GET /api/v1/platform-store requests.
// It returns the names of all stored secrets.
func (h *SealStoreHandlers) ListSecretsHandler(w http.ResponseWriter, r *http.Request) {
	names, err := h.store.List(r.Context())
	if err != nil {
		platformStoreWriteJSONError(w, "Failed to list secrets", http.StatusInternalServerError)
		return
	}

	if names == nil {
		names = []string{}
	}

	resp := SealStoreListResponse{
		Names: names,
		Total: len(names),
	}

	writeJSON(w, resp, http.StatusOK)
}

// ResealSecretHandler handles POST /api/v1/platform-store/{name}/reseal requests.
// It re-seals a secret so it is protected with the current backend state
// (e.g., fresh TPM PCR values after a legitimate system change).
func (h *SealStoreHandlers) ResealSecretHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		platformStoreWriteJSONError(w, "Secret name is required", http.StatusBadRequest)
		return
	}

	if err := h.store.Reseal(r.Context(), name); err != nil {
		if errors.Is(err, seal.ErrSecretNotFound) {
			platformStoreWriteJSONError(w, "Secret not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, seal.ErrResealFailed) {
			platformStoreWriteJSONError(w, "Failed to reseal secret", http.StatusInternalServerError)
			return
		}
		platformStoreWriteJSONError(w, "Failed to reseal secret", http.StatusInternalServerError)
		return
	}

	resp := SealStoreResealResponse{
		Name:    name,
		Message: "Secret resealed successfully",
	}

	writeJSON(w, resp, http.StatusOK)
}

// StatusHandler handles GET /api/v1/platform-store/status requests.
// It returns the basic status of the platform store including a list of stored secret names.
func (h *SealStoreHandlers) StatusHandler(w http.ResponseWriter, r *http.Request) {
	names, err := h.store.List(r.Context())
	if err != nil {
		platformStoreWriteJSONError(w, "Failed to get platform store status", http.StatusInternalServerError)
		return
	}

	if names == nil {
		names = []string{}
	}

	resp := SealStoreStatusResponse{
		Available: true,
		Names:     names,
		Total:     len(names),
	}

	writeJSON(w, resp, http.StatusOK)
}

// platformStoreWriteJSONError writes an error response in the standard JSON format.
func platformStoreWriteJSONError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := map[string]string{"error": message}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		return
	}
}
