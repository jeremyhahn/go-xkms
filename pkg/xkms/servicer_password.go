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
	"errors"
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

// Password store credential errors.
var (
	// ErrPasswordStoreUserPINRequired is returned when a tenant password store
	// unlock is attempted without the user PIN. Unlocking the store is a
	// credential-gated operation: the tenant barrier being unsealed proves the
	// tenant's data can be read by the server, not that this caller is
	// authorized to open the vault.
	ErrPasswordStoreUserPINRequired = errors.New("keystore: password store unlock requires the user PIN: set user_pin in the unlock request")

	// ErrPasswordStoreUserPINNotProvisioned is returned when a tenant password
	// store unlock is attempted on a deployment that has no user PIN to verify
	// against -- PIN management is disabled (pin.enabled=false, so no PIN
	// backend is wired) or the user PIN has never been set. There is no
	// credential to check, so the unlock fails closed instead of proceeding
	// without one.
	ErrPasswordStoreUserPINNotProvisioned = errors.New("keystore: password store unlock requires a provisioned user PIN: enable PIN management (pin.enabled=true) and set the user PIN before unlocking")

	// ErrPasswordDecryptNotSupported is returned when a caller requests an
	// on-demand decrypted read. The stores reachable through this servicer
	// (staticpw.BackendStore and staticpw.ScopedStore) are barrier backed:
	// confidentiality is provided by the barrier at the storage layer and Get
	// already returns the entry exactly as it was stored. Neither store
	// implements a field-level decryption entry point, so the request is
	// refused rather than answered with the stored value while the flag is
	// quietly dropped.
	ErrPasswordDecryptNotSupported = errors.New("keystore: password store does not support on-demand decryption: entries are returned as stored; do not set decrypt or user_pin on a get request")
)

// resolvePasswordStore returns the appropriate password store for the request
// context. If a TenantPasswordStoreManager is configured and the identity is
// bound to a real tenant, the tenant-specific scoped store is returned (with
// personal/shared separation when a user Subject is present). Otherwise, falls
// back to the system passwordStore.
//
// The tenant test is auth.IsCrossTenant, not TenantID != "": an identity in the
// reserved "system" tenant is platform-scoped, so scoping it would silently
// create a tenant store literally named "system" instead of using the system
// store — the same drift that made the transports reject system identities.
func (s *XKMSService) resolvePasswordStore(ctx context.Context) (staticpw.Store, error) {
	if s.passwordStoreManager != nil {
		identity := auth.GetIdentity(ctx)
		if !auth.IsCrossTenant(identity) {
			return s.passwordStoreManager.ResolveScopedStore(identity.TenantID, identity.Subject)
		}
	}
	if s.passwordStore != nil {
		return s.passwordStore, nil
	}
	return nil, ErrNotConfigured
}

// scopedTenantIDFromContext returns the tenant this request is scoped to, or
// "" when the caller is platform-scoped and therefore belongs on the system
// store.
//
// Platform scope covers both an absent identity and one rooted in the reserved
// "system" tenant, per auth.IsCrossTenant. Returning the raw TenantID instead
// would hand "system" to the tenant manager, which would then create and
// operate a per-tenant store literally named "system" alongside the real
// system store — silently splitting password state in two.
func scopedTenantIDFromContext(ctx context.Context) string {
	identity := auth.GetIdentity(ctx)
	if auth.IsCrossTenant(identity) {
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
//
// The request's Decrypt and UserPIN fields select an on-demand decrypted read,
// which the stores reachable here cannot perform (see
// ErrPasswordDecryptNotSupported). Either field being set is therefore an
// error: honouring the request is impossible, and answering it with the stored
// value would silently drop a security-relevant field of the request.
func (s *XKMSService) PasswordGet(ctx context.Context, req *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	store, err := s.resolvePasswordStore(ctx)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.Decrypt || req.UserPIN != "" {
		return nil, ErrPasswordDecryptNotSupported
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
	switch {
	case req.Scope != "":
		scope := staticpw.PasswordScope(req.Scope)
		if !scope.IsValid() {
			return nil, staticpw.ErrInvalidScope
		}
		if scopedStore, ok := store.(*staticpw.ScopedStore); ok {
			passwords, err = scopedStore.ListByScope(scope)
		} else {
			passwords, err = store.List()
		}
	case req.FolderPath != "":
		passwords, err = store.ListByFolder(req.FolderPath)
	default:
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

// PasswordStoreUnlock unlocks the tenant password store session.
//
// Sessions are a per-tenant capability: a tenant store is backed by its own
// TenantBarrier and starts locked, so it must be unlocked before entries can
// be read. The system-level store has no session of its own -- it is protected
// by the system barrier, which is unsealed once at startup -- so unlocking it
// is not a supported operation rather than an unfinished one. Callers reaching
// this method without a tenant identity therefore get ErrOperationNotSupported.
//
// The unlock itself is credential gated: the caller must supply the user PIN,
// which is verified through the service's PIN backend before the session is
// opened (verifyPasswordStoreUserPIN). A missing PIN, a wrong PIN, or a
// deployment with no provisioned user PIN all fail closed and leave the store
// locked. An unsealed tenant barrier is not, on its own, authorization to open
// the vault.
func (s *XKMSService) PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error {
	if req == nil {
		return ErrNilRequest
	}
	if s.passwordStoreManager != nil {
		tenantID := scopedTenantIDFromContext(ctx)
		if tenantID != "" {
			if err := s.verifyPasswordStoreUserPIN(req.UserPIN); err != nil {
				return err
			}
			return s.passwordStoreManager.UnlockTenant(tenantID)
		}
	}
	if s.passwordStore == nil {
		return ErrNotConfigured
	}
	return ErrOperationNotSupported
}

// verifyPasswordStoreUserPIN verifies userPIN against the configured PIN
// backend. It is the same verification path staticpw.SessionStore.Unlock uses
// for its own session unlock (PINBackend.VerifyUserPIN), so a password store
// session is opened by exactly one credential check no matter which store
// implementation is wired.
//
// A deployment with no PIN backend (pin.enabled=false) or with no user PIN set
// has no credential to verify, which is an explicit, reported state
// (ErrPasswordStoreUserPINNotProvisioned) rather than an unlock that proceeds
// without a credential.
func (s *XKMSService) verifyPasswordStoreUserPIN(userPIN string) error {
	if s.pinManager == nil || !s.pinManager.UserPINSet() {
		return ErrPasswordStoreUserPINNotProvisioned
	}
	if userPIN == "" {
		return ErrPasswordStoreUserPINRequired
	}
	return s.pinManager.VerifyUserPIN(userPIN)
}

// PasswordStoreLock locks the tenant password store session. It mirrors
// PasswordStoreUnlock: sessions exist only for tenant stores, so locking the
// system-level store reports ErrOperationNotSupported. See PasswordStoreUnlock
// for why that is a capability boundary and not an unfinished path.
//
// Locking needs no credential: it only ever removes access, so requiring one
// would risk leaving a store readable when the caller cannot produce a PIN.
func (s *XKMSService) PasswordStoreLock(ctx context.Context) error {
	if s.passwordStoreManager != nil {
		tenantID := scopedTenantIDFromContext(ctx)
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
		tenantID := scopedTenantIDFromContext(ctx)
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

// ErrInvalidAccessMode indicates the requested password store access mode is
// not one of the modes defined by staticpw.
var ErrInvalidAccessMode = errors.New("xkms: invalid password store access mode")

// PasswordAccessMode reports the access-control strategy the password store
// enforces for ctx.
//
// A tenant-scoped store is session based: it starts locked and stays readable
// until it is locked again, which is exactly staticpw.AccessSessionBased. The
// system-level store has no access-control strategy of its own -- entries are
// protected by the system barrier -- so it reports an empty mode.
// Returns ErrNotConfigured when no password store is wired.
func (s *XKMSService) PasswordAccessMode(ctx context.Context) (staticpw.AccessMode, error) {
	if s.passwordStoreManager != nil && scopedTenantIDFromContext(ctx) != "" {
		return staticpw.AccessSessionBased, nil
	}
	if s.passwordStore == nil {
		return "", ErrNotConfigured
	}
	return "", nil
}

// PasswordStoreSetAccessMode selects the access-control strategy for the
// password store addressed by ctx.
//
// The strategy is a composition-time property: it is decided by which store is
// wired at startup (a tenant store is session based, the system store is
// barrier protected with no session), and switching it while the store is live
// would silently change the security posture of already-readable entries. This
// method therefore validates the requested mode against the mode the addressed
// store actually enforces and is idempotent -- requesting the mode already in
// force succeeds, requesting a different one reports ErrOperationNotSupported
// so the caller learns the boundary instead of believing a change took effect.
//
// Returns ErrNilRequest for a nil request, ErrInvalidAccessMode for a mode
// outside the staticpw vocabulary, and ErrNotConfigured when no password store
// is wired.
func (s *XKMSService) PasswordStoreSetAccessMode(ctx context.Context, req *transport.PasswordStoreSetAccessModeRequest) error {
	// Configuration is checked before the request, matching the ordering used
	// by the other password servicer methods.
	effective, err := s.PasswordAccessMode(ctx)
	if err != nil {
		return err
	}
	if req == nil {
		return ErrNilRequest
	}

	requested := staticpw.AccessMode(req.Mode)
	switch requested {
	case staticpw.AccessPINPerOperation, staticpw.AccessSessionBased:
	default:
		return ErrInvalidAccessMode
	}

	if requested != effective {
		return ErrOperationNotSupported
	}
	return nil
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
