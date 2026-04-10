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

package mcp

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
)

// --- Request types ---

// PasswordAddParams represents parameters for adding a password entry.
type PasswordAddParams struct {
	Name       string `json:"name"`
	Title      string `json:"title,omitempty"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password"`
	URL        string `json:"url,omitempty"`
	Notes      string `json:"notes,omitempty"`
	FolderPath string `json:"folder_path,omitempty"`
	Shared     bool   `json:"shared,omitempty"`
}

// PasswordGetParams represents parameters for getting a password entry.
type PasswordGetParams struct {
	ID string `json:"id"`
}

// PasswordListParams represents parameters for listing password entries.
type PasswordListParams struct {
	Folder string `json:"folder,omitempty"`
	Scope  string `json:"scope,omitempty"`
}

// PasswordUpdateParams represents parameters for updating a password entry.
type PasswordUpdateParams struct {
	ID         string  `json:"id"`
	Name       *string `json:"name,omitempty"`
	Title      *string `json:"title,omitempty"`
	Username   *string `json:"username,omitempty"`
	Password   *string `json:"password,omitempty"`
	URL        *string `json:"url,omitempty"`
	Notes      *string `json:"notes,omitempty"`
	FolderPath *string `json:"folder_path,omitempty"`
}

// PasswordDeleteParams represents parameters for deleting a password entry.
type PasswordDeleteParams struct {
	ID string `json:"id"`
}

// PasswordGenerateParams represents parameters for generating a random password.
type PasswordGenerateParams struct {
	Length  int    `json:"length,omitempty"`
	Charset string `json:"charset,omitempty"`
}

// --- Response types ---

// PasswordAddResult represents the result of adding a password entry.
type PasswordAddResult struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Message string `json:"message"`
}

// PasswordInfo represents a summary of a password entry.
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

// PasswordListResult represents the result of listing password entries.
type PasswordListResult struct {
	Passwords []PasswordInfo `json:"passwords"`
	Total     int            `json:"total"`
}

// PasswordDetailResult represents the detailed result of getting a password entry.
type PasswordDetailResult struct {
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

// PasswordUpdateResult represents the result of updating a password entry.
type PasswordUpdateResult struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Message string `json:"message"`
}

// PasswordDeleteResult represents the result of deleting a password entry.
type PasswordDeleteResult struct {
	Message string `json:"message"`
}

// PasswordStoreStatusResult represents the password store status.
type PasswordStoreStatusResult struct {
	Available     bool   `json:"available"`
	IsLocked      bool   `json:"is_locked"`
	BarrierSealed bool   `json:"barrier_sealed"`
	PasswordCount int    `json:"password_count"`
	Message       string `json:"message"`
}

// PasswordGenerateResult represents the result of generating a password.
type PasswordGenerateResult struct {
	Password string `json:"password"`
	Length   int    `json:"length"`
}

// --- Typed errors for password MCP handlers ---

var (
	// ErrPasswordStoreNotConfigured is returned when password store operations
	// are attempted without a configured TenantPasswordStoreManager.
	ErrPasswordStoreNotConfigured = errors.New("password store not configured")

	// ErrPasswordIDRequired is returned when an operation requires a password
	// ID but none was provided.
	ErrPasswordIDRequired = errors.New("password id is required")

	// ErrPasswordNameRequired is returned when adding a password requires
	// a name but none was provided.
	ErrPasswordNameRequired = errors.New("name is required")

	// ErrPasswordRequired is returned when a password value is required
	// but not provided.
	ErrPasswordRequired = errors.New("password is required")
)

// resolvePasswordStore returns the appropriate store for the request context.
// When a manager is configured and the identity has a TenantID, a scoped store
// (with personal/shared separation) is returned. Otherwise, the system store
// is returned.
func (s *Server) resolvePasswordStore(ctx context.Context) (staticpw.Store, error) {
	if s.passwordManager == nil {
		return nil, ErrPasswordStoreNotConfigured
	}

	identity := auth.GetIdentity(ctx)
	if identity != nil && identity.TenantID != "" {
		return s.passwordManager.ResolveScopedStore(identity.TenantID, identity.Subject)
	}

	return s.passwordManager.SystemStore(), nil
}

// handlePasswordAdd handles the password.add method.
func (s *Server) handlePasswordAdd(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params PasswordAddParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, err
	}

	store, err := s.resolvePasswordStore(ctx)
	if err != nil {
		return nil, mapPasswordStoreError(err)
	}

	pw := &staticpw.StaticPassword{
		Name:       params.Name,
		Title:      params.Title,
		Username:   params.Username,
		Password:   params.Password,
		URL:        params.URL,
		Notes:      params.Notes,
		FolderPath: params.FolderPath,
		Shared:     params.Shared,
	}

	if err := store.Add(pw); err != nil {
		return nil, mapPasswordError(err)
	}

	return PasswordAddResult{
		ID:      pw.ID,
		Name:    pw.Name,
		Message: "Password added successfully",
	}, nil
}

// handlePasswordGet handles the password.get method.
func (s *Server) handlePasswordGet(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params PasswordGetParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, err
	}

	if params.ID == "" {
		return nil, ErrPasswordIDRequired
	}

	store, err := s.resolvePasswordStore(ctx)
	if err != nil {
		return nil, mapPasswordStoreError(err)
	}

	pw, err := store.Get(params.ID)
	if err != nil {
		return nil, mapPasswordError(err)
	}

	return PasswordDetailResult{
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
		CreatedAt:  pw.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:  pw.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}, nil
}

// handlePasswordList handles the password.list method.
func (s *Server) handlePasswordList(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params PasswordListParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, err
	}

	store, err := s.resolvePasswordStore(ctx)
	if err != nil {
		return nil, mapPasswordStoreError(err)
	}

	var entries []*staticpw.StaticPassword

	// Scope-aware listing.
	if params.Scope != "" {
		ps := staticpw.PasswordScope(params.Scope)
		if !ps.IsValid() {
			return nil, staticpw.ErrInvalidScope
		}
		if scopedStore, ok := store.(*staticpw.ScopedStore); ok {
			entries, err = scopedStore.ListByScope(ps)
		} else {
			entries, err = store.List()
		}
	} else if params.Folder != "" {
		entries, err = store.ListByFolder(params.Folder)
	} else {
		entries, err = store.List()
	}

	if err != nil {
		return nil, mapPasswordError(err)
	}

	infos := make([]PasswordInfo, len(entries))
	for i, pw := range entries {
		infos[i] = PasswordInfo{
			ID:         pw.ID,
			Name:       pw.Name,
			Title:      pw.Title,
			Username:   pw.Username,
			URL:        pw.URL,
			FolderPath: pw.FolderPath,
			OwnerID:    pw.OwnerID,
			Shared:     pw.Shared,
			CreatedAt:  pw.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt:  pw.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		}
	}

	return PasswordListResult{
		Passwords: infos,
		Total:     len(infos),
	}, nil
}

// handlePasswordUpdate handles the password.update method.
func (s *Server) handlePasswordUpdate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params PasswordUpdateParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, err
	}

	if params.ID == "" {
		return nil, ErrPasswordIDRequired
	}

	store, err := s.resolvePasswordStore(ctx)
	if err != nil {
		return nil, mapPasswordStoreError(err)
	}

	// Get existing entry.
	existing, err := store.Get(params.ID)
	if err != nil {
		return nil, mapPasswordError(err)
	}

	// Apply updates from request (only non-nil pointer fields).
	if params.Name != nil {
		existing.Name = *params.Name
	}
	if params.Title != nil {
		existing.Title = *params.Title
	}
	if params.Username != nil {
		existing.Username = *params.Username
	}
	if params.Password != nil {
		existing.Password = *params.Password
	}
	if params.URL != nil {
		existing.URL = *params.URL
	}
	if params.Notes != nil {
		existing.Notes = *params.Notes
	}
	if params.FolderPath != nil {
		existing.FolderPath = *params.FolderPath
	}

	if err := store.Update(existing); err != nil {
		return nil, mapPasswordError(err)
	}

	return PasswordUpdateResult{
		ID:      existing.ID,
		Name:    existing.Name,
		Message: "Password updated successfully",
	}, nil
}

// handlePasswordDelete handles the password.delete method.
func (s *Server) handlePasswordDelete(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params PasswordDeleteParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, err
	}

	if params.ID == "" {
		return nil, ErrPasswordIDRequired
	}

	store, err := s.resolvePasswordStore(ctx)
	if err != nil {
		return nil, mapPasswordStoreError(err)
	}

	if err := store.Delete(params.ID); err != nil {
		return nil, mapPasswordError(err)
	}

	return PasswordDeleteResult{
		Message: "Password deleted successfully",
	}, nil
}

// handlePasswordUnlock handles the password.unlock method.
func (s *Server) handlePasswordUnlock(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.passwordManager == nil {
		return nil, ErrPasswordStoreNotConfigured
	}

	identity := auth.GetIdentity(ctx)
	if identity == nil || identity.TenantID == "" {
		return nil, staticpw.ErrInvalidTenantID
	}

	if err := s.passwordManager.UnlockTenant(identity.TenantID); err != nil {
		return nil, mapPasswordStoreError(err)
	}

	status, err := s.passwordManager.TenantStoreStatus(identity.TenantID)
	if err != nil {
		return nil, err
	}

	return PasswordStoreStatusResult{
		Available:     true,
		IsLocked:      status.IsLocked,
		BarrierSealed: status.BarrierSealed,
		PasswordCount: status.PasswordCount,
		Message:       "Store unlocked successfully",
	}, nil
}

// handlePasswordLock handles the password.lock method.
func (s *Server) handlePasswordLock(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.passwordManager == nil {
		return nil, ErrPasswordStoreNotConfigured
	}

	identity := auth.GetIdentity(ctx)
	if identity == nil || identity.TenantID == "" {
		return nil, staticpw.ErrInvalidTenantID
	}

	if err := s.passwordManager.LockTenant(identity.TenantID); err != nil {
		return nil, mapPasswordStoreError(err)
	}

	status, err := s.passwordManager.TenantStoreStatus(identity.TenantID)
	if err != nil {
		return nil, err
	}

	return PasswordStoreStatusResult{
		Available:     true,
		IsLocked:      status.IsLocked,
		BarrierSealed: status.BarrierSealed,
		PasswordCount: status.PasswordCount,
		Message:       "Store locked successfully",
	}, nil
}

// handlePasswordStatus handles the password.status method.
func (s *Server) handlePasswordStatus(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.passwordManager == nil {
		return PasswordStoreStatusResult{
			Available: false,
			Message:   "Password store not configured",
		}, nil
	}

	identity := auth.GetIdentity(ctx)
	if identity != nil && identity.TenantID != "" {
		status, err := s.passwordManager.TenantStoreStatus(identity.TenantID)
		if err != nil {
			if errors.Is(err, seal.ErrTenantNotFound) {
				return nil, seal.ErrTenantNotFound
			}
			return nil, err
		}

		return PasswordStoreStatusResult{
			Available:     true,
			IsLocked:      status.IsLocked,
			BarrierSealed: status.BarrierSealed,
			PasswordCount: status.PasswordCount,
			Message:       "Password store status retrieved",
		}, nil
	}

	// System-level fallback.
	return PasswordStoreStatusResult{
		Available: true,
		Message:   "Password store is available",
	}, nil
}

// handlePasswordGenerate handles the password.generate method.
func (s *Server) handlePasswordGenerate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params PasswordGenerateParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, err
	}

	// Apply defaults.
	length := params.Length
	if length == 0 {
		length = staticpw.DefaultLength
	}

	charset := params.Charset
	if charset == "" {
		charset = staticpw.CharsetAll
	}

	password, err := staticpw.GeneratePassword(length, charset)
	if err != nil {
		return nil, err
	}

	return PasswordGenerateResult{
		Password: password,
		Length:   length,
	}, nil
}

// mapPasswordError maps staticpw errors to appropriate MCP error messages.
func mapPasswordError(err error) error {
	switch {
	case errors.Is(err, staticpw.ErrInvalidName):
		return ErrPasswordNameRequired
	case errors.Is(err, staticpw.ErrEmptyPassword):
		return ErrPasswordRequired
	case errors.Is(err, staticpw.ErrPasswordExists):
		return staticpw.ErrPasswordExists
	case errors.Is(err, staticpw.ErrStoreClosed):
		return staticpw.ErrStoreClosed
	case errors.Is(err, staticpw.ErrPasswordNotFound):
		return staticpw.ErrPasswordNotFound
	case errors.Is(err, staticpw.ErrPasswordReadOnly):
		return staticpw.ErrPasswordReadOnly
	default:
		return err
	}
}

// mapPasswordStoreError maps store resolution errors to appropriate MCP error messages.
func mapPasswordStoreError(err error) error {
	switch {
	case errors.Is(err, staticpw.ErrStoreLocked):
		return staticpw.ErrStoreLocked
	case errors.Is(err, seal.ErrTenantSealed):
		return seal.ErrTenantSealed
	case errors.Is(err, seal.ErrTenantNotFound):
		return seal.ErrTenantNotFound
	case errors.Is(err, staticpw.ErrNotConfigured):
		return ErrPasswordStoreNotConfigured
	case errors.Is(err, staticpw.ErrInvalidUserID):
		return staticpw.ErrInvalidUserID
	case errors.Is(err, staticpw.ErrNotOwner):
		return staticpw.ErrNotOwner
	case errors.Is(err, staticpw.ErrInvalidScope):
		return staticpw.ErrInvalidScope
	default:
		return err
	}
}
