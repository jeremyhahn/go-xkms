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
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// SealStoreHandlers provides HTTP handlers for platform store operations.
//
// Every handler delegates to the XKMSService's SealStore* methods and never
// to the store itself: the platform store holds platform-global secrets (the
// backend credentials under credentials/<name>), and the service's
// requirePlatformScope is what refuses a tenant-scoped caller (go-xkms#1226).
// The routes' keys:* grants cannot, because a tenant-local Admin's
// self-scoped grants resolve against its own tenant.
type SealStoreHandlers struct {
	servicer xkms.SealStoreServicer
}

// NewSealStoreHandlers creates a new SealStoreHandlers instance over the
// XKMSService's platform-store operations.
func NewSealStoreHandlers(servicer xkms.SealStoreServicer) *SealStoreHandlers {
	return &SealStoreHandlers{servicer: servicer}
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

// PutSecretHandler handles PUT /api/v1/platform/secrets/{name} requests.
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

	if err := h.servicer.SealStorePut(r.Context(), &transport.SealStorePutRequest{Name: name, Secret: secret}); err != nil {
		platformStoreWriteServiceError(w, err, "Failed to store secret")
		return
	}

	resp := SealStorePutResponse{
		Name:    name,
		Message: "Secret stored successfully",
	}

	writeJSON(w, resp, http.StatusOK)
}

// GetSecretHandler handles GET /api/v1/platform/secrets/{name} requests.
// It retrieves and unseals the secret stored under the given name.
func (h *SealStoreHandlers) GetSecretHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		platformStoreWriteJSONError(w, "Secret name is required", http.StatusBadRequest)
		return
	}

	got, err := h.servicer.SealStoreGet(r.Context(), &transport.SealStoreGetRequest{Name: name})
	if err != nil {
		platformStoreWriteServiceError(w, err, "Failed to retrieve secret")
		return
	}

	resp := SealStoreGetResponse{
		Name:   name,
		Secret: base64.StdEncoding.EncodeToString(got.Secret),
	}

	writeJSON(w, resp, http.StatusOK)
}

// DeleteSecretHandler handles DELETE /api/v1/platform/secrets/{name} requests.
// It removes the secret stored under the given name.
func (h *SealStoreHandlers) DeleteSecretHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		platformStoreWriteJSONError(w, "Secret name is required", http.StatusBadRequest)
		return
	}

	if err := h.servicer.SealStoreDelete(r.Context(), &transport.SealStoreDeleteRequest{Name: name}); err != nil {
		platformStoreWriteServiceError(w, err, "Failed to delete secret")
		return
	}

	resp := SealStoreDeleteResponse{
		Message: "Secret deleted successfully",
	}

	writeJSON(w, resp, http.StatusOK)
}

// ListSecretsHandler handles GET /api/v1/platform/secrets requests.
// It returns the names of all stored secrets.
func (h *SealStoreHandlers) ListSecretsHandler(w http.ResponseWriter, r *http.Request) {
	list, err := h.servicer.SealStoreList(r.Context())
	if err != nil {
		platformStoreWriteServiceError(w, err, "Failed to list secrets")
		return
	}

	names := list.Names
	if names == nil {
		names = []string{}
	}

	resp := SealStoreListResponse{
		Names: names,
		Total: len(names),
	}

	writeJSON(w, resp, http.StatusOK)
}

// ResealSecretHandler handles POST /api/v1/platform/secrets/{name}/reseal
// requests. It re-seals a secret so it is protected with the current backend
// state (e.g., fresh TPM PCR values after a legitimate system change).
func (h *SealStoreHandlers) ResealSecretHandler(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		platformStoreWriteJSONError(w, "Secret name is required", http.StatusBadRequest)
		return
	}

	if err := h.servicer.SealStoreReseal(r.Context(), &transport.SealStoreResealRequest{Name: name}); err != nil {
		platformStoreWriteServiceError(w, err, "Failed to reseal secret")
		return
	}

	resp := SealStoreResealResponse{
		Name:    name,
		Message: "Secret resealed successfully",
	}

	writeJSON(w, resp, http.StatusOK)
}

// StatusHandler handles GET /api/v1/platform/status requests. It returns the
// basic status of the platform store including a list of stored secret names.
func (h *SealStoreHandlers) StatusHandler(w http.ResponseWriter, r *http.Request) {
	status, err := h.servicer.SealStoreStatus(r.Context())
	if err != nil {
		platformStoreWriteServiceError(w, err, "Failed to get platform store status")
		return
	}

	names := status.SecretNames
	if names == nil {
		names = []string{}
	}

	resp := SealStoreStatusResponse{
		Available: status.Available,
		Names:     names,
		Total:     len(names),
	}

	writeJSON(w, resp, http.StatusOK)
}

// platformStoreErrorResponses maps the platform-store service's sentinels to
// the status and fixed message each answers with. The tenant binding's
// refusal (xkms.TenantBindingError, which unwraps to qrdbsdk.ErrTenantMissing)
// renders its own message -- the unknown-tenant text every transport answers
// with -- so platformStoreWriteServiceError handles it before this table.
var platformStoreErrorResponses = []struct {
	sentinel error
	status   int
	message  string
}{
	{xkms.ErrNotConfigured, http.StatusServiceUnavailable, "Platform store not configured"},
	{seal.ErrSecretNotFound, http.StatusNotFound, "Secret not found"},
	{seal.ErrInvalidSecretName, http.StatusBadRequest, "Invalid secret name"},
}

// platformStoreWriteServiceError writes the response for an error returned by
// the platform-store service. Anything unclassified is a 500 carrying
// fallback, never the error's own text.
func platformStoreWriteServiceError(w http.ResponseWriter, err error, fallback string) {
	if errors.Is(err, qrdbsdk.ErrTenantMissing) {
		platformStoreWriteJSONError(w, err.Error(), http.StatusNotFound)
		return
	}
	for _, entry := range platformStoreErrorResponses {
		if errors.Is(err, entry.sentinel) {
			platformStoreWriteJSONError(w, entry.message, entry.status)
			return
		}
	}
	platformStoreWriteJSONError(w, fallback, http.StatusInternalServerError)
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
