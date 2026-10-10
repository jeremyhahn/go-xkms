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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
)

// PasswordServicer defines operations for managing the encrypted password store.
type PasswordServicer interface {
	PasswordAdd(ctx context.Context, req *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error)
	PasswordGet(ctx context.Context, req *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error)
	PasswordList(ctx context.Context, req *transport.PasswordListRequest) (*transport.PasswordListResponse, error)
	PasswordUpdate(ctx context.Context, req *transport.PasswordUpdateRequest) (*transport.PasswordGetResponse, error)
	PasswordDelete(ctx context.Context, req *transport.PasswordDeleteRequest) error
	PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error
	PasswordStoreLock(ctx context.Context) error
	PasswordStoreStatus(ctx context.Context) (*transport.PasswordStoreStatusResponse, error)
	PasswordStoreSetAccessMode(ctx context.Context, req *transport.PasswordStoreSetAccessModeRequest) error
	PasswordGenerate(ctx context.Context, req *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error)
	PasswordVaultStatus(ctx context.Context) (*transport.PasswordVaultStatusResponse, error)
	PasswordVaultEnroll(ctx context.Context, req *transport.PasswordVaultEnrollRequest) (*transport.PasswordVaultEnrollResponse, error)
	PasswordVaultRotate(ctx context.Context, req *transport.PasswordVaultRotateRequest) (*transport.PasswordVaultEnrollResponse, error)
	PasswordVaultRemoveFactor(ctx context.Context, req *transport.PasswordVaultRemoveFactorRequest) error
	PasswordVaultRecover(ctx context.Context, req *transport.PasswordVaultRecoverRequest) (*transport.PasswordVaultEnrollResponse, error)
}

// passwordCaller returns the tenant scope name and subject a password request
// is served for, and false when ctx carries no identity.
//
// A system-tenant identity is served from the system tenant's own store,
// with shared entries and per-user personal entries like any tenant's; only
// a request with no identity at all (an internal caller, or authentication
// disabled) falls back to the unscoped system passwordStore.
func passwordCaller(ctx context.Context) (tenantID, subject string, ok bool) {
	identity := auth.GetIdentity(ctx)
	if identity == nil {
		return "", "", false
	}
	return scope.TenantName(identity.TenantID), identity.Subject, true
}

// resolvePasswordStore returns the password store the caller sees: with a
// TenantPasswordStoreManager configured and an identity present, the
// caller's tenant store (shared entries, plus the caller's personal entries
// while its personal session is open); otherwise the system passwordStore.
func (s *XKMSService) resolvePasswordStore(ctx context.Context) (staticpw.Store, error) {
	passwordStoreManager := s.passwordStoreManager.load()
	passwordStore := s.passwordStore.load()
	if passwordStoreManager != nil {
		if tenantID, subject, ok := passwordCaller(ctx); ok {
			return passwordStoreManager.ResolveScopedStore(ctx, tenantID, subject)
		}
	}
	if passwordStore != nil {
		return passwordStore, nil
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

// sharedPasswordAdministratorRoles are the qrdb built-in roles whose members
// may modify a shared password they do not own.
var sharedPasswordAdministratorRoles = []string{qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameSO}

// checkSharedPasswordOwnership verifies that the caller is authorized to
// modify a shared password. Shared passwords can only be modified by their
// owner, or by a member of the Admin or SO built-in role of the caller's
// tenant. Personal passwords (Shared=false) are not checked -- they are
// inherently scoped to their owner by key prefix.
//
// The override is a role-membership decision, not a resource:action one: the
// transports already required passwords:write or passwords:delete, which the
// Operator role holds exactly as Admin does, so no permission separates the
// administrator from any other vault writer. Membership is resolved through
// auth.HoldsSystemRole against the role identifiers the identity carries; a
// role NAME on the identity confers nothing (go-xkms#1074). Without a role
// client membership cannot be established and a non-owner is refused.
func (s *XKMSService) checkSharedPasswordOwnership(ctx context.Context, pw *staticpw.StaticPassword) error {
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
	if s.roles == nil {
		return staticpw.ErrNotOwner
	}
	for _, roleName := range sharedPasswordAdministratorRoles {
		held, err := auth.HoldsSystemRole(ctx, s.roles, identity, roleName)
		if err != nil {
			return err
		}
		if held {
			return nil
		}
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
		Title:      req.Title,
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
// Entries are returned exactly as stored: confidentiality at rest is
// provided by the tenant barrier at the storage layer, not by a
// per-request decryption step, so Get has nothing further to decrypt.
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
func (s *XKMSService) PasswordUpdate(ctx context.Context, req *transport.PasswordUpdateRequest) (*transport.PasswordGetResponse, error) {
	store, err := s.resolvePasswordStore(ctx)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrNilRequest
	}

	existing, err := store.Get(req.ID)
	if err != nil {
		return nil, err
	}

	if err := s.checkSharedPasswordOwnership(ctx, existing); err != nil {
		return nil, err
	}

	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Title != nil {
		existing.Title = *req.Title
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
				return nil, ErrInvalidKeyAttributes
			}
			existing.ExpiresAt = parsed
		}
	}

	// Update re-derives the entry's ID from its name and folder, so a rename
	// or a move answers with the new ID, never the one the request named.
	if err := store.Update(existing); err != nil {
		return nil, err
	}
	return staticPasswordToGetResponse(existing), nil
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

	if err := s.checkSharedPasswordOwnership(ctx, existing); err != nil {
		return err
	}

	return store.Delete(req.ID)
}

// PasswordStoreUnlock opens the caller's personal password session with one
// of the caller's own vault factors: a passphrase or a passkey
// (hmac-secret / PRF output). The factor unwraps the caller's DEK, so the
// session is exactly as private as the factor: neither the tenant key nor any
// deployment-wide credential opens it.
//
// Sessions are per user: each user of a tenant unlocks and locks their own
// personal entries, and one user's session never opens or closes another's.
// Shared entries need no session; they are usable whenever the tenant
// barrier is unsealed. The unscoped system passwordStore, which serves only
// requests without an identity, has no session of its own, so a request
// without an identity gets ErrOperationNotSupported.
func (s *XKMSService) PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error {
	if req == nil {
		if s.passwordStoreManager.load() == nil && s.passwordStore.load() == nil {
			return ErrNotConfigured
		}
		return ErrNilRequest
	}
	manager, tenantID, subject, err := s.vaultCaller(ctx)
	if err != nil {
		return err
	}
	cred, err := vaultCredential(ctx, req.PasswordVaultCredential)
	if err != nil {
		return err
	}
	defer cred.Secret.Destroy()
	return manager.UnlockUser(ctx, tenantID, subject, cred)
}

// PasswordStoreLock closes the caller's personal password session. It
// mirrors PasswordStoreUnlock: sessions are per user, so locking closes only
// the caller's, and a request without an identity reports
// ErrOperationNotSupported.
//
// Locking needs no credential: it only ever removes access, so requiring one
// would risk leaving entries readable when the caller cannot produce a PIN.
func (s *XKMSService) PasswordStoreLock(ctx context.Context) error {
	passwordStoreManager := s.passwordStoreManager.load()
	passwordStore := s.passwordStore.load()
	if passwordStoreManager != nil {
		if tenantID, subject, ok := passwordCaller(ctx); ok {
			return passwordStoreManager.LockUser(tenantID, subject)
		}
	}
	if passwordStore == nil {
		return ErrNotConfigured
	}
	return ErrOperationNotSupported
}

// PasswordStoreStatus returns the status of the password store the caller
// sees. With a TenantPasswordStoreManager configured and an identity present,
// it is the caller's view of its tenant store: whether its own personal
// session is locked, the tenant barrier's seal state, and how many entries it
// can read now. Otherwise it is the system passwordStore's status.
func (s *XKMSService) PasswordStoreStatus(ctx context.Context) (*transport.PasswordStoreStatusResponse, error) {
	passwordStoreManager := s.passwordStoreManager.load()
	passwordStore := s.passwordStore.load()
	if passwordStoreManager != nil {
		if tenantID, subject, ok := passwordCaller(ctx); ok {
			status, err := passwordStoreManager.UserStoreStatus(ctx, tenantID, subject)
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
	if passwordStore == nil {
		return nil, ErrNotConfigured
	}

	passwords, err := passwordStore.List()
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
// A tenant store, the system tenant's included, is session based: each user's
// personal entries start locked and stay readable until that user locks them
// again, which is exactly staticpw.AccessSessionBased. The unscoped system
// store serving requests without an identity has no access-control strategy
// of its own -- entries are protected by the system barrier -- so it reports
// an empty mode. Returns ErrNotConfigured when no password store is wired.
func (s *XKMSService) PasswordAccessMode(ctx context.Context) (staticpw.AccessMode, error) {
	passwordStoreManager := s.passwordStoreManager.load()
	passwordStore := s.passwordStore.load()
	if _, _, ok := passwordCaller(ctx); ok && passwordStoreManager != nil {
		return staticpw.AccessSessionBased, nil
	}
	if passwordStore == nil {
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
	passwordStoreManager := s.passwordStoreManager.load()
	passwordStore := s.passwordStore.load()
	if passwordStore == nil && passwordStoreManager == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}

	charset, err := generateCharset(req)
	if err != nil {
		return nil, err
	}

	pw, err := staticpw.GeneratePassword(req.Length, charset)
	if err != nil {
		return nil, err
	}

	return &transport.PasswordGenerateResponse{
		Password: pw,
	}, nil
}

// generateCharset returns the charset a generate request selects: the named
// or literal Charset when one is given (staticpw.GeneratePassword resolves
// "all" and "alphanumeric"), otherwise the class flags. Naming both is
// ambiguous and refused with staticpw.ErrInvalidCharset.
func generateCharset(req *transport.PasswordGenerateRequest) (string, error) {
	flags := req.Upper || req.Lower || req.Digits || req.Symbols
	if req.Charset != "" {
		if flags {
			return "", staticpw.ErrInvalidCharset
		}
		return req.Charset, nil
	}
	return buildCharset(req), nil
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
		Title:      pw.Title,
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
