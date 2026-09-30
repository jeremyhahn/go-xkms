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
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// PasswordHandlers provides HTTP handlers for password store operations.
//
// Every entry and session operation is delegated to the service layer
// (PasswordServicer). The servicer is the single place that resolves the
// caller's store -- the tenant's shared entries plus the caller's personal
// entries while the caller's personal session is open, or the unscoped system
// store for a request without an identity -- and enforces the shared-entry
// ownership rule on update and delete. The handlers only translate between
// the HTTP wire shapes and the transport types.
type PasswordHandlers struct {
	servicer PasswordServicer
}

// PasswordServicer is the service-layer seam the password endpoints delegate
// to; *xkms.XKMSService satisfies it.
type PasswordServicer interface {
	// PasswordAdd stores a new entry in the caller's store.
	PasswordAdd(ctx context.Context, req *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error)

	// PasswordGet returns one entry the caller can read.
	PasswordGet(ctx context.Context, req *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error)

	// PasswordList returns the entries the caller can read, optionally
	// filtered by scope or folder.
	PasswordList(ctx context.Context, req *transport.PasswordListRequest) (*transport.PasswordListResponse, error)

	// PasswordUpdate updates an entry and returns it as updated (a rename
	// or move re-keys it), refusing a shared entry the caller does not own
	// with staticpw.ErrNotOwner.
	PasswordUpdate(ctx context.Context, req *transport.PasswordUpdateRequest) (*transport.PasswordGetResponse, error)

	// PasswordGenerate generates a random password.
	PasswordGenerate(ctx context.Context, req *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error)

	// PasswordDelete deletes an entry, refusing a shared entry the caller
	// does not own with staticpw.ErrNotOwner.
	PasswordDelete(ctx context.Context, req *transport.PasswordDeleteRequest) error

	// PasswordStoreSetAccessMode selects the access-control strategy for the
	// password store addressed by the request context.
	PasswordStoreSetAccessMode(ctx context.Context, req *transport.PasswordStoreSetAccessModeRequest) error

	// PasswordStoreUnlock opens the caller's personal session with one of
	// the caller's own vault factors.
	PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error

	// PasswordStoreLock closes the caller's personal session.
	PasswordStoreLock(ctx context.Context) error

	// PasswordStoreStatus reports the lock and seal state of the store the
	// caller sees.
	PasswordStoreStatus(ctx context.Context) (*transport.PasswordStoreStatusResponse, error)

	// PasswordVaultStatus describes the caller's personal vault.
	PasswordVaultStatus(ctx context.Context) (*transport.PasswordVaultStatusResponse, error)

	// PasswordVaultEnroll enrolls a passphrase or passkey on the caller's
	// vault; the first enrollment initializes it and opens the session.
	PasswordVaultEnroll(ctx context.Context, req *transport.PasswordVaultEnrollRequest) (*transport.PasswordVaultEnrollResponse, error)

	// PasswordVaultRotate replaces the secret of one of the caller's factors.
	PasswordVaultRotate(ctx context.Context, req *transport.PasswordVaultRotateRequest) (*transport.PasswordVaultEnrollResponse, error)

	// PasswordVaultRemoveFactor removes one of the caller's factors.
	PasswordVaultRemoveFactor(ctx context.Context, req *transport.PasswordVaultRemoveFactorRequest) error

	// PasswordVaultRecover uses the caller's one-time recovery code to
	// enroll a new factor and open the session.
	PasswordVaultRecover(ctx context.Context, req *transport.PasswordVaultRecoverRequest) (*transport.PasswordVaultEnrollResponse, error)
}

// Compile-time check that the canonical servicer satisfies the seam.
var _ PasswordServicer = (*xkms.XKMSService)(nil)

// NewPasswordHandlers creates password handlers that delegate every store
// operation to servicer.
func NewPasswordHandlers(servicer PasswordServicer) *PasswordHandlers {
	return &PasswordHandlers{servicer: servicer}
}

// --- Request types ---

// PasswordAddRequest is the request body for adding a new password entry.
type PasswordAddRequest struct {
	Name       string `json:"name"`
	Title      string `json:"title,omitempty"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password"`
	URL        string `json:"url,omitempty"`
	Notes      string `json:"notes,omitempty"`
	FolderPath string `json:"folder_path,omitempty"`
	Shared     bool   `json:"shared,omitempty"`
}

// PasswordUpdateRequest is the request body for updating an existing password entry.
type PasswordUpdateRequest struct {
	Name       *string `json:"name,omitempty"`
	Title      *string `json:"title,omitempty"`
	Username   *string `json:"username,omitempty"`
	Password   *string `json:"password,omitempty"`
	URL        *string `json:"url,omitempty"`
	Notes      *string `json:"notes,omitempty"`
	FolderPath *string `json:"folder_path,omitempty"`
}

// PasswordGenerateRequest is the request body for generating a random password.
type PasswordGenerateRequest struct {
	Length  int    `json:"length,omitempty"`
	Charset string `json:"charset,omitempty"`
}

// PasswordStoreAccessModeRequest is the request body for selecting the
// password store access mode. Mode must be one of the staticpw access modes:
// "pin_per_operation" or "session_based".
type PasswordStoreAccessModeRequest struct {
	Mode string `json:"mode"`
}

// --- Response types ---

// PasswordAddResponse is the response after adding a password entry.
type PasswordAddResponse struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Message string `json:"message"`
}

// PasswordInfo is a summary of a password entry returned in list responses.
type PasswordInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Title      string `json:"title,omitempty"`
	Username   string `json:"username,omitempty"`
	URL        string `json:"url,omitempty"`
	FolderPath string `json:"folder_path,omitempty"`
	OwnerID    string `json:"owner_id,omitempty"`
	Shared     bool   `json:"shared,omitempty"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

// PasswordListResponse is the response for listing password entries.
type PasswordListResponse struct {
	Passwords []PasswordInfo `json:"passwords"`
	Total     int            `json:"total"`
}

// PasswordDetailResponse is the detailed response for a single password entry.
type PasswordDetailResponse struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Title      string `json:"title,omitempty"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password"`
	URL        string `json:"url,omitempty"`
	Notes      string `json:"notes,omitempty"`
	FolderPath string `json:"folder_path,omitempty"`
	OwnerID    string `json:"owner_id,omitempty"`
	Shared     bool   `json:"shared,omitempty"`
	ReadOnly   bool   `json:"read_only,omitempty"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

// PasswordUpdateResponse is the response after updating a password entry.
type PasswordUpdateResponse struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Message string `json:"message"`
}

// PasswordDeleteResponse is the response after deleting a password entry.
type PasswordDeleteResponse struct {
	Message string `json:"message"`
}

// PasswordGenerateResponse is the response for generating a random password.
type PasswordGenerateResponse struct {
	Password string `json:"password"`
	Length   int    `json:"length"`
}

// PasswordStoreAccessModeResponse is the response for the access-mode endpoint.
type PasswordStoreAccessModeResponse struct {
	Mode    string `json:"mode"`
	Message string `json:"message"`
}

// PasswordStoreStatusResponse is the response for the password store status endpoint.
type PasswordStoreStatusResponse struct {
	Available     bool   `json:"available"`
	IsLocked      bool   `json:"is_locked"`
	BarrierSealed bool   `json:"barrier_sealed"`
	PasswordCount int    `json:"password_count"`
	Message       string `json:"message"`
}

// --- Handlers ---

// AddPasswordHandler handles POST /api/v1/passwords requests.
// It decodes the request body and stores the new entry through the servicer.
func (h *PasswordHandlers) AddPasswordHandler(w http.ResponseWriter, r *http.Request) {
	var req PasswordAddRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		passwordWriteJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	resp, err := h.servicer.PasswordAdd(r.Context(), &transport.PasswordAddRequest{
		Name:       req.Name,
		Title:      req.Title,
		Username:   req.Username,
		Password:   req.Password,
		URL:        req.URL,
		Notes:      req.Notes,
		FolderPath: req.FolderPath,
		Shared:     req.Shared,
	})
	if err != nil {
		passwordWriteServiceError(w, err, "Failed to add password")
		return
	}

	writeJSON(w, PasswordAddResponse{
		ID:      resp.ID,
		Name:    resp.Name,
		Message: "Password added successfully",
	}, http.StatusCreated)
}

// ListPasswordsHandler handles GET /api/v1/passwords requests.
// It returns the entries the caller can read, optionally filtered by the
// scope (personal, shared, all) or folder query parameter.
func (h *PasswordHandlers) ListPasswordsHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	resp, err := h.servicer.PasswordList(r.Context(), &transport.PasswordListRequest{
		FolderPath: query.Get("folder"),
		Scope:      query.Get("scope"),
	})
	if err != nil {
		passwordWriteServiceError(w, err, "Failed to list passwords")
		return
	}

	infos := make([]PasswordInfo, len(resp.Passwords))
	for i, pw := range resp.Passwords {
		infos[i] = PasswordInfo{
			ID:         pw.ID,
			Name:       pw.Name,
			Title:      pw.Title,
			Username:   pw.Username,
			URL:        pw.URL,
			FolderPath: pw.FolderPath,
			OwnerID:    pw.OwnerID,
			Shared:     pw.Shared,
			CreatedAt:  pw.CreatedAt,
			UpdatedAt:  pw.UpdatedAt,
		}
	}

	writeJSON(w, PasswordListResponse{
		Passwords: infos,
		Total:     len(infos),
	}, http.StatusOK)
}

// GetPasswordHandler handles GET /api/v1/passwords/{id} requests.
// It retrieves a password entry by ID or name.
func (h *PasswordHandlers) GetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		passwordWriteJSONError(w, "Password ID is required", http.StatusBadRequest)
		return
	}

	pw, err := h.servicer.PasswordGet(r.Context(), &transport.PasswordGetRequest{ID: id})
	if err != nil {
		passwordWriteServiceError(w, err, "Failed to get password")
		return
	}

	writeJSON(w, PasswordDetailResponse{
		ID:         pw.ID,
		Name:       pw.Name,
		Title:      pw.Title,
		Username:   pw.Username,
		Password:   pw.Password,
		URL:        pw.URL,
		Notes:      pw.Notes,
		FolderPath: pw.FolderPath,
		OwnerID:    pw.OwnerID,
		Shared:     pw.Shared,
		ReadOnly:   pw.ReadOnly,
		CreatedAt:  pw.CreatedAt,
		UpdatedAt:  pw.UpdatedAt,
	}, http.StatusOK)
}

// UpdatePasswordHandler handles PUT /api/v1/passwords/{id} requests.
// It updates an existing entry, applying only the fields present in the
// request. The {id} path parameter may be an ID or a name; the response
// reports the entry's resulting ID and name.
func (h *PasswordHandlers) UpdatePasswordHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		passwordWriteJSONError(w, "Password ID is required", http.StatusBadRequest)
		return
	}

	var req PasswordUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		passwordWriteJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	updated, err := h.servicer.PasswordUpdate(r.Context(), &transport.PasswordUpdateRequest{
		ID:         id,
		Name:       req.Name,
		Title:      req.Title,
		Username:   req.Username,
		Password:   req.Password,
		URL:        req.URL,
		Notes:      req.Notes,
		FolderPath: req.FolderPath,
	})
	if err != nil {
		passwordWriteServiceError(w, err, "Failed to update password")
		return
	}

	// The servicer answers with the entry as updated: a rename or a move
	// re-keys it, so its ID is the new one.
	writeJSON(w, PasswordUpdateResponse{
		ID:      updated.ID,
		Name:    updated.Name,
		Message: "Password updated successfully",
	}, http.StatusOK)
}

// DeletePasswordHandler handles DELETE /api/v1/passwords/{id} requests.
// It removes a password entry by ID or name.
func (h *PasswordHandlers) DeletePasswordHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		passwordWriteJSONError(w, "Password ID is required", http.StatusBadRequest)
		return
	}

	if err := h.servicer.PasswordDelete(r.Context(), &transport.PasswordDeleteRequest{ID: id}); err != nil {
		passwordWriteServiceError(w, err, "Failed to delete password")
		return
	}

	writeJSON(w, PasswordDeleteResponse{
		Message: "Password deleted successfully",
	}, http.StatusOK)
}

// UnlockHandler handles POST /api/v1/passwords/unlock requests. It opens the
// caller's personal password session with one of the caller's vault factors;
// sessions are per user, so this never opens another user's personal entries.
//
// The body is a transport.PasswordVaultCredential: {"factor": "passphrase",
// "passphrase": ...} or {"factor": "passkey", "credential_id", "secret"} with
// the byte fields base64 encoded. A request without an identity has no
// personal vault and is answered with 501.
func (h *PasswordHandlers) UnlockHandler(w http.ResponseWriter, r *http.Request) {
	// An absent body is an unlock attempt with no credential, which the
	// servicer rejects as an invalid credential.
	var unlockReq transport.PasswordStoreUnlockRequest
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&unlockReq); err != nil && !errors.Is(err, io.EOF) {
			passwordWriteJSONError(w, "Invalid request body", http.StatusBadRequest)
			return
		}
	}
	defer clear(unlockReq.Secret)

	if err := h.servicer.PasswordStoreUnlock(r.Context(), &unlockReq); err != nil {
		passwordWriteUnlockError(w, err)
		return
	}

	h.writeStatus(w, r, "Store unlocked successfully", "Store unlocked but failed to get status")
}

// LockHandler handles POST /api/v1/passwords/lock requests. It closes the
// caller's personal password session; other users' sessions are untouched.
func (h *PasswordHandlers) LockHandler(w http.ResponseWriter, r *http.Request) {
	if err := h.servicer.PasswordStoreLock(r.Context()); err != nil {
		passwordWriteLockError(w, err)
		return
	}

	h.writeStatus(w, r, "Store locked successfully", "Store locked but failed to get status")
}

// StatusHandler handles GET /api/v1/passwords/status requests. It reports the
// caller's view of its store: whether its personal session is locked, the
// barrier's seal state, and how many entries it can read now.
func (h *PasswordHandlers) StatusHandler(w http.ResponseWriter, r *http.Request) {
	status, err := h.servicer.PasswordStoreStatus(r.Context())
	if err != nil {
		passwordWriteServiceError(w, err, "Failed to get store status")
		return
	}

	writeJSON(w, PasswordStoreStatusResponse{
		Available:     true,
		IsLocked:      status.IsLocked,
		BarrierSealed: status.BarrierSealed,
		PasswordCount: status.PasswordCount,
		Message:       "Password store status retrieved",
	}, http.StatusOK)
}

// writeStatus writes the caller's store status after a successful unlock or
// lock, with message on success and failMessage when the status read fails.
func (h *PasswordHandlers) writeStatus(w http.ResponseWriter, r *http.Request, message, failMessage string) {
	status, err := h.servicer.PasswordStoreStatus(r.Context())
	if err != nil {
		passwordWriteJSONError(w, failMessage, http.StatusInternalServerError)
		return
	}

	writeJSON(w, PasswordStoreStatusResponse{
		Available:     true,
		IsLocked:      status.IsLocked,
		BarrierSealed: status.BarrierSealed,
		PasswordCount: status.PasswordCount,
		Message:       message,
	}, http.StatusOK)
}

// SetAccessModeHandler handles POST /api/v1/passwords/access-mode requests.
// It delegates to the XKMS service layer, which owns the rules for which
// access-control strategy a given password store can enforce.
func (h *PasswordHandlers) SetAccessModeHandler(w http.ResponseWriter, r *http.Request) {
	var req PasswordStoreAccessModeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		passwordWriteJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.Mode == "" {
		passwordWriteJSONError(w, "Missing access mode", http.StatusBadRequest)
		return
	}

	if err := h.servicer.PasswordStoreSetAccessMode(r.Context(), &transport.PasswordStoreSetAccessModeRequest{
		Mode: req.Mode,
	}); err != nil {
		passwordHandleAccessModeError(w, err)
		return
	}

	writeJSON(w, PasswordStoreAccessModeResponse{
		Mode:    req.Mode,
		Message: "Password store access mode set",
	}, http.StatusOK)
}

// passwordHandleAccessModeError maps service-layer access mode errors to HTTP
// status codes. An unsupported (but well formed) mode is a capability
// boundary of the wired store, not a malformed request, so it maps to 501.
func passwordHandleAccessModeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, xkms.ErrInvalidAccessMode):
		passwordWriteJSONError(w, "Invalid access mode (allowed: pin_per_operation, session_based)", http.StatusBadRequest)
	case errors.Is(err, xkms.ErrNilRequest):
		passwordWriteJSONError(w, "Missing access mode", http.StatusBadRequest)
	case errors.Is(err, xkms.ErrNotConfigured):
		passwordWriteJSONError(w, "Password store not configured", http.StatusServiceUnavailable)
	case errors.Is(err, xkms.ErrOperationNotSupported):
		passwordWriteJSONError(w, "The wired password store cannot enforce the requested access mode", http.StatusNotImplemented)
	default:
		passwordHandleStoreError(w, err)
	}
}

// GeneratePasswordHandler handles POST /api/v1/passwords/generate requests.
// It generates a cryptographically random password using the specified parameters.
func (h *PasswordHandlers) GeneratePasswordHandler(w http.ResponseWriter, r *http.Request) {
	var req PasswordGenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		passwordWriteJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	generated, err := h.servicer.PasswordGenerate(r.Context(), &transport.PasswordGenerateRequest{
		Length:  req.Length,
		Charset: req.Charset,
	})
	if err != nil {
		passwordWriteServiceError(w, err, "Failed to generate password")
		return
	}

	resp := PasswordGenerateResponse{
		Password: generated.Password,
		Length:   len(generated.Password),
	}

	writeJSON(w, resp, http.StatusOK)
}

// passwordErrorMapping pairs a service-layer sentinel with the HTTP response
// it is reported as.
type passwordErrorMapping struct {
	target  error
	message string
	status  int
}

// passwordServiceErrorMappings maps the errors the password servicer returns
// onto HTTP responses. It is ordered: the first sentinel errors.Is matches
// wins, so wrapped errors resolve to their most specific cause.
var passwordServiceErrorMappings = []passwordErrorMapping{
	{staticpw.ErrPasswordNotFound, "Password not found", http.StatusNotFound},
	{staticpw.ErrPasswordExists, "Password with this name already exists", http.StatusConflict},
	{staticpw.ErrInvalidName, "Name is required", http.StatusBadRequest},
	{staticpw.ErrEmptyPassword, "Password is required", http.StatusBadRequest},
	{staticpw.ErrInvalidScope, "Invalid scope (use personal, shared, or all)", http.StatusBadRequest},
	{staticpw.ErrInvalidFolderPath, "Invalid folder path", http.StatusBadRequest},
	{staticpw.ErrFolderPathTooDeep, "Folder path exceeds maximum depth", http.StatusBadRequest},
	{staticpw.ErrInvalidUserID, "Invalid user identity", http.StatusBadRequest},
	{staticpw.ErrInvalidLength, "Invalid password length (min 8, max 128)", http.StatusBadRequest},
	{staticpw.ErrInvalidCharset, "Invalid charset", http.StatusBadRequest},
	{xkms.ErrNilRequest, "Invalid request", http.StatusBadRequest},
	{staticpw.ErrPasswordReadOnly, "Password is read-only", http.StatusForbidden},
	{staticpw.ErrNotOwner, "Not the owner of this password", http.StatusForbidden},
	{staticpw.ErrStoreLocked, "Password store is locked", http.StatusLocked},
	{staticpw.ErrStoreClosed, "Password store is closed", http.StatusServiceUnavailable},
	{seal.ErrTenantSealed, "Tenant barrier is sealed", http.StatusServiceUnavailable},
	{seal.ErrTenantNotFound, "Tenant not found", http.StatusNotFound},
	{staticpw.ErrNoSystemBarrier, "System password store is unavailable", http.StatusServiceUnavailable},
	{staticpw.ErrNotConfigured, "Password store not configured", http.StatusServiceUnavailable},
	{xkms.ErrNotConfigured, "Password store not configured", http.StatusServiceUnavailable},
}

// passwordWriteServiceError writes the HTTP response for an error returned by
// the password servicer, falling back to 500 with fallback as the message for
// an error no mapping names.
func passwordWriteServiceError(w http.ResponseWriter, err error, fallback string) {
	for _, m := range passwordServiceErrorMappings {
		if errors.Is(err, m.target) {
			passwordWriteJSONError(w, m.message, m.status)
			return
		}
	}
	passwordWriteJSONError(w, fallback, http.StatusInternalServerError)
}

// passwordHandleStoreError maps store resolution errors to HTTP status codes.
func passwordHandleStoreError(w http.ResponseWriter, err error) {
	passwordWriteServiceError(w, err, "Failed to access password store")
}

// passwordVaultErrorMappings maps the personal-vault errors onto HTTP
// responses. A malformed credential is the caller's mistake (400); a vault
// with no factor needs enrollment first (412); a credential that unwraps no
// factor is an authentication failure that must not say why (401).
var passwordVaultErrorMappings = []passwordErrorMapping{
	{staticpw.ErrVaultInvalidCredential, "Invalid vault credential: supply a passphrase or a passkey", http.StatusBadRequest},
	{staticpw.ErrVaultRecoveryFactor, "The recovery code is not a removable, rotatable or unlocking factor", http.StatusBadRequest},
	{staticpw.ErrVaultNotInitialized, "No vault factor is enrolled: enroll a passphrase or passkey first", http.StatusPreconditionFailed},
	{staticpw.ErrVaultCredentialRejected, "Credential rejected", http.StatusUnauthorized},
	{staticpw.ErrVaultFactorNotFound, "Vault factor not found", http.StatusNotFound},
	{staticpw.ErrVaultLastFactor, "Cannot remove the last passphrase or passkey", http.StatusConflict},
	{staticpw.ErrVaultPasskeyExists, "Passkey already enrolled", http.StatusConflict},
	{xkms.ErrOperationNotSupported, "The personal password vault requires an authenticated user", http.StatusNotImplemented},
}

// passwordWriteVaultError writes the HTTP response for an error returned by a
// personal-vault operation: the vault mappings first, then the store
// mappings, falling back to 500 with fallback as the message.
func passwordWriteVaultError(w http.ResponseWriter, err error, fallback string) {
	for _, m := range passwordVaultErrorMappings {
		if errors.Is(err, m.target) {
			passwordWriteJSONError(w, m.message, m.status)
			return
		}
	}
	passwordWriteServiceError(w, err, fallback)
}

// passwordWriteUnlockError maps the errors returned by
// XKMSService.PasswordStoreUnlock onto HTTP statuses: an already open session
// is a 409, everything else is a vault error.
func passwordWriteUnlockError(w http.ResponseWriter, err error) {
	if errors.Is(err, staticpw.ErrStoreNotLocked) {
		passwordWriteJSONError(w, "Store is already unlocked", http.StatusConflict)
		return
	}
	passwordWriteVaultError(w, err, "Failed to unlock store")
}

// passwordWriteLockError maps the errors returned by
// XKMSService.PasswordStoreLock onto HTTP statuses.
func passwordWriteLockError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, staticpw.ErrStoreAlreadyLocked):
		passwordWriteJSONError(w, "Store is already locked", http.StatusConflict)
	case errors.Is(err, xkms.ErrOperationNotSupported):
		passwordWriteJSONError(w, "Password store lock requires an authenticated user", http.StatusNotImplemented)
	default:
		passwordWriteServiceError(w, err, "Failed to lock store")
	}
}

// passwordWriteJSONError writes an error response in the standard JSON format.
func passwordWriteJSONError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := map[string]string{"error": message}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		return
	}
}
