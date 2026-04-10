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

package xkms

import (
	"context"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
)

// PasswordServicer defines operations for managing the encrypted password store.
type PasswordServicer interface {
	PasswordAdd(ctx context.Context, req *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error)
	PasswordGet(ctx context.Context, req *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error)
	PasswordList(ctx context.Context, req *transport.PasswordListRequest) (*transport.PasswordListResponse, error)
	PasswordUpdate(ctx context.Context, req *transport.PasswordUpdateRequest) error
	PasswordDelete(ctx context.Context, req *transport.PasswordDeleteRequest) error
	PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error
	PasswordStoreLock(ctx context.Context) error
	PasswordStoreStatus(ctx context.Context) (*transport.PasswordStoreStatusResponse, error)
	PasswordStoreSetAccessMode(ctx context.Context, req *transport.PasswordStoreSetAccessModeRequest) error
	PasswordGenerate(ctx context.Context, req *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error)
}

// resolvePasswordStore returns the appropriate password store for the request
// context. If a TenantPasswordStoreManager is configured and the identity has
// a TenantID, the tenant-specific scoped store is returned (with personal/shared
// separation when a user Subject is present). Otherwise, falls back to the
// system passwordStore.
func (s *XKMSService) resolvePasswordStore(ctx context.Context) (staticpw.Store, error) {
	if s.passwordStoreManager != nil {
		identity := auth.GetIdentity(ctx)
		if identity != nil && identity.TenantID != "" {
			return s.passwordStoreManager.ResolveScopedStore(identity.TenantID, identity.Subject)
		}
	}
	if s.passwordStore != nil {
		return s.passwordStore, nil
	}
	return nil, ErrNotConfigured
}

// tenantIDFromContext extracts the tenant ID from the auth identity in ctx.
// Returns empty string if no identity or no tenant ID is set.
func tenantIDFromContext(ctx context.Context) string {
	identity := auth.GetIdentity(ctx)
	if identity == nil {
		return ""
	}
	return identity.TenantID
}

// checkSharedPasswordOwnership verifies that the caller is authorized to
// modify a shared password. Shared passwords can only be modified by their
// owner, or by users with admin or SO roles. Personal passwords (Shared=false)
// are not checked -- they are inherently scoped to their owner by key prefix.
func checkSharedPasswordOwnership(ctx context.Context, pw *staticpw.StaticPassword) error {
	if !pw.Shared {
		return nil // personal passwords are scoped by key prefix
	}
	identity := auth.GetIdentity(ctx)
	if identity == nil {
		return staticpw.ErrNotOwner
	}
	// Owner can always modify their own shared passwords.
	if identity.Subject == pw.OwnerID {
		return nil
	}
	// Admin and SO roles can modify any shared password.
	if identity.HasRole("admin") || identity.HasRole("so") {
		return nil
	}
	return staticpw.ErrNotOwner
}

// PasswordAdd adds a new password entry to the encrypted store.
func (s *XKMSService) PasswordAdd(ctx context.Context, req *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error) {
	store, err := s.resolvePasswordStore(ctx)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrNilRequest
	}

	var expiresAt time.Time
	if req.ExpiresAt != "" {
		parsed, parseErr := time.Parse(time.RFC3339, req.ExpiresAt)
		if parseErr != nil {
			return nil, ErrInvalidKeyAttributes
		}
		expiresAt = parsed
	}

	pw := &staticpw.StaticPassword{
		Name:       req.Name,
		Username:   req.Username,
		Password:   req.Password,
		URL:        req.URL,
		Notes:      req.Notes,
		FolderPath: req.FolderPath,
		ExpiresAt:  expiresAt,
		Shared:     req.Shared,
	}

	if err := store.Add(pw); err != nil {
		return nil, err
	}

	return &transport.PasswordAddResponse{
		ID:        pw.ID,
		Name:      pw.Name,
		CreatedAt: pw.CreatedAt.Format(time.RFC3339),
	}, nil
}

// PasswordGet retrieves a password entry from the store.
func (s *XKMSService) PasswordGet(ctx context.Context, req *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	store, err := s.resolvePasswordStore(ctx)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrNilRequest
	}

	pw, err := store.Get(req.ID)
	if err != nil {
		return nil, err
	}

	return staticPasswordToGetResponse(pw), nil
}

// PasswordList lists password entries, optionally filtered by folder path.
func (s *XKMSService) PasswordList(ctx context.Context, req *transport.PasswordListRequest) (*transport.PasswordListResponse, error) {
	store, err := s.resolvePasswordStore(ctx)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrNilRequest
	}

	var passwords []*staticpw.StaticPassword

	// Scope-aware listing: if scope is specified and the store supports it,
	// use ListByScope; otherwise fall back to folder or full list.
	if req.Scope != "" {
		scope := staticpw.PasswordScope(req.Scope)
		if !scope.IsValid() {
			return nil, staticpw.ErrInvalidScope
		}
		if scopedStore, ok := store.(*staticpw.ScopedStore); ok {
			passwords, err = scopedStore.ListByScope(scope)
		} else {
			passwords, err = store.List()
		}
	} else if req.FolderPath != "" {
		passwords, err = store.ListByFolder(req.FolderPath)
	} else {
		passwords, err = store.List()
	}
	if err != nil {
		return nil, err
	}

	items := make([]transport.PasswordGetResponse, 0, len(passwords))
	for _, pw := range passwords {
		items = append(items, *staticPasswordToGetResponse(pw))
	}

	return &transport.PasswordListResponse{
		Passwords:    items,
		PageResponse: transport.PageResponse{Total: len(items)},
	}, nil
}

// PasswordUpdate updates an existing password entry.
func (s *XKMSService) PasswordUpdate(ctx context.Context, req *transport.PasswordUpdateRequest) error {
	store, err := s.resolvePasswordStore(ctx)
	if err != nil {
		return err
	}
	if req == nil {
		return ErrNilRequest
	}

	existing, err := store.Get(req.ID)
	if err != nil {
		return err
	}

	if err := checkSharedPasswordOwnership(ctx, existing); err != nil {
		return err
	}

	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Username != nil {
		existing.Username = *req.Username
	}
	if req.Password != nil {
		existing.Password = *req.Password
	}
	if req.URL != nil {
		existing.URL = *req.URL
	}
	if req.Notes != nil {
		existing.Notes = *req.Notes
	}
	if req.FolderPath != nil {
		existing.FolderPath = *req.FolderPath
	}
	if req.ExpiresAt != nil {
		if *req.ExpiresAt == "" {
			existing.ExpiresAt = time.Time{}
		} else {
			parsed, parseErr := time.Parse(time.RFC3339, *req.ExpiresAt)
			if parseErr != nil {
				return ErrInvalidKeyAttributes
			}
			existing.ExpiresAt = parsed
		}
	}

	return store.Update(existing)
}

// PasswordDelete deletes a password entry from the store.
func (s *XKMSService) PasswordDelete(ctx context.Context, req *transport.PasswordDeleteRequest) error {
	store, err := s.resolvePasswordStore(ctx)
	if err != nil {
		return err
	}
	if req == nil {
		return ErrNilRequest
	}

	existing, err := store.Get(req.ID)
	if err != nil {
		return err
	}

	if err := checkSharedPasswordOwnership(ctx, existing); err != nil {
		return err
	}

	return store.Delete(req.ID)
}

// PasswordStoreUnlock unlocks the tenant password store session. When a
// TenantPasswordStoreManager is configured, it unlocks the tenant-specific
// store. Without a manager, returns ErrOperationNotSupported.
func (s *XKMSService) PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error {
	if s.passwordStoreManager != nil {
		tenantID := tenantIDFromContext(ctx)
		if tenantID != "" {
			return s.passwordStoreManager.UnlockTenant(tenantID)
		}
	}
	if s.passwordStore == nil {
		return ErrNotConfigured
	}
	return ErrOperationNotSupported
}

// PasswordStoreLock locks the tenant password store session. When a
// TenantPasswordStoreManager is configured, it locks the tenant-specific
// store. Without a manager, returns ErrOperationNotSupported.
func (s *XKMSService) PasswordStoreLock(ctx context.Context) error {
	if s.passwordStoreManager != nil {
		tenantID := tenantIDFromContext(ctx)
		if tenantID != "" {
			return s.passwordStoreManager.LockTenant(tenantID)
		}
	}
	if s.passwordStore == nil {
		return ErrNotConfigured
	}
	return ErrOperationNotSupported
}

// PasswordStoreStatus returns the current status of the password store.
// When a TenantPasswordStoreManager is configured and the identity has a
// TenantID, it returns per-tenant status including barrier seal state.
// Otherwise, returns system-level status.
func (s *XKMSService) PasswordStoreStatus(ctx context.Context) (*transport.PasswordStoreStatusResponse, error) {
	if s.passwordStoreManager != nil {
		tenantID := tenantIDFromContext(ctx)
		if tenantID != "" {
			status, err := s.passwordStoreManager.TenantStoreStatus(tenantID)
			if err != nil {
				return nil, err
			}
			return &transport.PasswordStoreStatusResponse{
				AccessMode:    "tenant",
				IsLocked:      status.IsLocked,
				BarrierSealed: status.BarrierSealed,
				PasswordCount: status.PasswordCount,
			}, nil
		}
	}

	// System-level fallback.
	if s.passwordStore == nil {
		return nil, ErrNotConfigured
	}

	passwords, err := s.passwordStore.List()
	if err != nil {
		return nil, err
	}

	return &transport.PasswordStoreStatusResponse{
		AccessMode:    "direct",
		IsLocked:      false,
		AutoUnsealed:  true,
		PasswordCount: len(passwords),
	}, nil
}

// PasswordStoreSetAccessMode sets the access mode for the password store.
// This requires PINManager integration and is not yet implemented.
func (s *XKMSService) PasswordStoreSetAccessMode(ctx context.Context, req *transport.PasswordStoreSetAccessModeRequest) error {
	if s.passwordStore == nil && s.passwordStoreManager == nil {
		return ErrNotConfigured
	}
	return ErrOperationNotSupported
}

// PasswordGenerate generates a random password with the specified constraints.
func (s *XKMSService) PasswordGenerate(ctx context.Context, req *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	if s.passwordStore == nil && s.passwordStoreManager == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}

	charset := buildCharset(req)

	pw, err := staticpw.GeneratePassword(req.Length, charset)
	if err != nil {
		return nil, err
	}

	return &transport.PasswordGenerateResponse{
		Password: pw,
	}, nil
}

// buildCharset constructs a character set string from the boolean flags in the
// generate request. When no flags are set, it defaults to "all".
func buildCharset(req *transport.PasswordGenerateRequest) string {
	if !req.Upper && !req.Lower && !req.Digits && !req.Symbols {
		return "all"
	}

	var sb strings.Builder
	if req.Upper {
		sb.WriteString("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	}
	if req.Lower {
		sb.WriteString("abcdefghijklmnopqrstuvwxyz")
	}
	if req.Digits {
		sb.WriteString("0123456789")
	}
	if req.Symbols {
		sb.WriteString(staticpw.CharsetSymbols)
	}
	return sb.String()
}

// staticPasswordToGetResponse converts a staticpw.StaticPassword to a
// transport.PasswordGetResponse.
func staticPasswordToGetResponse(pw *staticpw.StaticPassword) *transport.PasswordGetResponse {
	resp := &transport.PasswordGetResponse{
		ID:         pw.ID,
		Name:       pw.Name,
		Username:   pw.Username,
		Password:   pw.Password,
		URL:        pw.URL,
		Notes:      pw.Notes,
		FolderPath: pw.FolderPath,
		CreatedAt:  pw.CreatedAt.Format(time.RFC3339),
		UpdatedAt:  pw.UpdatedAt.Format(time.RFC3339),
		ReadOnly:   pw.ReadOnly,
		Encrypted:  strings.HasPrefix(pw.Password, "ENC:"),
		OwnerID:    pw.OwnerID,
		Shared:     pw.Shared,
	}

	if !pw.ExpiresAt.IsZero() {
		resp.ExpiresAt = pw.ExpiresAt.Format(time.RFC3339)
	}

	return resp
}
