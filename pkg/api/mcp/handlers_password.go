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
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
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

// PasswordAccessModeResult represents the result of setting the password
// store access mode.
type PasswordAccessModeResult struct {
	Mode    string `json:"mode"`
	Message string `json:"message"`
}

// --- Typed errors for password MCP handlers ---

var (
	// ErrPasswordStoreNotConfigured is returned when password store operations
	// are attempted without a password store wired into the XKMS service.
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
	// ErrCopyKeyIncomplete is returned when the service reports a copy as
	// not successful without returning an error, which its contract does
	// not do; the handler refuses to render that as success.
	ErrCopyKeyIncomplete = errors.New("mcp: copy key did not complete")
)

// errPasswordStoreNotConfigured classifies ErrPasswordStoreNotConfigured as
// Service unavailable, matching pkg/api/grpc/service_password.go's
// codes.Unavailable for the identical "no manager wired" condition
// (mapPasswordError's staticpw.ErrNotConfigured / xkms.ErrNotConfigured
// cases).
func errPasswordStoreNotConfigured() error {
	return &KeyOpError{Code: ErrCodeServiceUnavailable, Err: ErrPasswordStoreNotConfigured}
}

// passwordService returns the XKMS service every password handler delegates
// to, or the Service-unavailable error when none is wired. The servicer is
// the single place that resolves the caller's store and enforces the
// shared-entry ownership rule, so no handler touches a store directly.
func (s *Server) passwordService() (*xkms.XKMSService, error) {
	if s.xkmsService == nil {
		return nil, errPasswordStoreNotConfigured()
	}
	return s.xkmsService, nil
}

// handlePasswordAdd handles the password.add method.
func (s *Server) handlePasswordAdd(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params PasswordAddParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	svc, err := s.passwordService()
	if err != nil {
		return nil, err
	}

	resp, err := svc.PasswordAdd(ctx, &transport.PasswordAddRequest{
		Name:       params.Name,
		Title:      params.Title,
		Username:   params.Username,
		Password:   params.Password,
		URL:        params.URL,
		Notes:      params.Notes,
		FolderPath: params.FolderPath,
		Shared:     params.Shared,
	})
	if err != nil {
		return nil, mapPasswordError(err)
	}

	return PasswordAddResult{
		ID:      resp.ID,
		Name:    resp.Name,
		Message: "Password added successfully",
	}, nil
}

// handlePasswordGet handles the password.get method.
func (s *Server) handlePasswordGet(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params PasswordGetParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.ID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: ErrPasswordIDRequired}
	}

	svc, err := s.passwordService()
	if err != nil {
		return nil, err
	}

	pw, err := svc.PasswordGet(ctx, &transport.PasswordGetRequest{ID: params.ID})
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
		CreatedAt:  pw.CreatedAt,
		UpdatedAt:  pw.UpdatedAt,
	}, nil
}

// handlePasswordList handles the password.list method.
func (s *Server) handlePasswordList(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params PasswordListParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	svc, err := s.passwordService()
	if err != nil {
		return nil, err
	}

	resp, err := svc.PasswordList(ctx, &transport.PasswordListRequest{
		FolderPath: params.Folder,
		Scope:      params.Scope,
	})
	if err != nil {
		return nil, mapPasswordError(err)
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

	return PasswordListResult{
		Passwords: infos,
		Total:     len(infos),
	}, nil
}

// handlePasswordUpdate handles the password.update method. The entry is read
// first so an ID given as a name resolves to the entry's canonical ID and the
// result can report the entry's resulting ID and name.
func (s *Server) handlePasswordUpdate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params PasswordUpdateParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.ID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: ErrPasswordIDRequired}
	}

	svc, err := s.passwordService()
	if err != nil {
		return nil, err
	}

	existing, err := svc.PasswordGet(ctx, &transport.PasswordGetRequest{ID: params.ID})
	if err != nil {
		return nil, mapPasswordError(err)
	}

	if err := svc.PasswordUpdate(ctx, &transport.PasswordUpdateRequest{
		ID:         existing.ID,
		Name:       params.Name,
		Title:      params.Title,
		Username:   params.Username,
		Password:   params.Password,
		URL:        params.URL,
		Notes:      params.Notes,
		FolderPath: params.FolderPath,
	}); err != nil {
		return nil, mapPasswordError(err)
	}

	id, name := updatedPasswordIdentity(existing, params.Name, params.FolderPath)
	return PasswordUpdateResult{
		ID:      id,
		Name:    name,
		Message: "Password updated successfully",
	}, nil
}

// updatedPasswordIdentity returns the ID and name existing has after an
// update that set name and folder (nil when unchanged). An entry's ID is
// derived from its name and folder (staticpw.GenerateID), so renaming or
// moving it re-keys it and the result must report the new ID.
func updatedPasswordIdentity(existing *transport.PasswordGetResponse, name, folder *string) (string, string) {
	if name == nil && folder == nil {
		return existing.ID, existing.Name
	}
	newName, newFolder := existing.Name, existing.FolderPath
	if name != nil {
		newName = *name
	}
	if folder != nil {
		newFolder = *folder
	}
	return staticpw.GenerateID(newName, newFolder), newName
}

// handlePasswordDelete handles the password.delete method.
func (s *Server) handlePasswordDelete(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params PasswordDeleteParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.ID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: ErrPasswordIDRequired}
	}

	svc, err := s.passwordService()
	if err != nil {
		return nil, err
	}

	if err := svc.PasswordDelete(ctx, &transport.PasswordDeleteRequest{ID: params.ID}); err != nil {
		return nil, mapPasswordError(err)
	}

	return PasswordDeleteResult{
		Message: "Password deleted successfully",
	}, nil
}

// handlePasswordUnlock handles the password.unlock method. It opens the
// caller's personal password session; sessions are per user, so this never
// opens another user's personal entries.
//
// The servicer verifies the caller's user PIN before opening the session. A
// request without an identity has no personal session and is answered with
// Method not found by the servicer's ErrOperationNotSupported.
func (s *Server) handlePasswordUnlock(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := s.passwordService()
	if err != nil {
		return nil, err
	}

	// The user PIN is optional on the wire so an unprovisioned deployment gets
	// the servicer's precise "not provisioned" answer rather than a decode
	// failure. Absent params are an unlock attempt with no PIN, which the
	// servicer rejects.
	var unlockReq transport.PasswordStoreUnlockRequest
	if len(req.Params) > 0 {
		if err := decodeParams(req, &unlockReq); err != nil {
			return nil, err
		}
	}

	if err := svc.PasswordStoreUnlock(ctx, &unlockReq); err != nil {
		return nil, mapPasswordUnlockError(err)
	}

	return passwordStatusResult(ctx, svc, "Store unlocked successfully")
}

// handlePasswordLock handles the password.lock method. It closes the caller's
// personal password session; other users' sessions are untouched.
func (s *Server) handlePasswordLock(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := s.passwordService()
	if err != nil {
		return nil, err
	}

	if err := svc.PasswordStoreLock(ctx); err != nil {
		return nil, mapPasswordLockError(err)
	}

	return passwordStatusResult(ctx, svc, "Store locked successfully")
}

// handlePasswordStatus handles the password.status method. It reports the
// caller's view of its store: whether its personal session is locked, the
// barrier's seal state, and how many entries it can read now. A deployment
// with no password store reports Available=false rather than an error.
func (s *Server) handlePasswordStatus(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := s.passwordService()
	if err != nil {
		return passwordNotConfiguredStatus(), nil
	}

	result, err := passwordStatusResult(ctx, svc, "Password store status retrieved")
	if errors.Is(err, ErrPasswordStoreNotConfigured) {
		return passwordNotConfiguredStatus(), nil
	}
	return result, err
}

// passwordNotConfiguredStatus is the status reported when no password store
// is wired.
func passwordNotConfiguredStatus() PasswordStoreStatusResult {
	return PasswordStoreStatusResult{
		Available: false,
		Message:   "Password store not configured",
	}
}

// passwordStatusResult reads the caller's store status through svc and
// renders it with message.
func passwordStatusResult(ctx context.Context, svc *xkms.XKMSService, message string) (interface{}, error) {
	status, err := svc.PasswordStoreStatus(ctx)
	if err != nil {
		return nil, mapPasswordStoreError(err)
	}

	return PasswordStoreStatusResult{
		Available:     true,
		IsLocked:      status.IsLocked,
		BarrierSealed: status.BarrierSealed,
		PasswordCount: status.PasswordCount,
		Message:       message,
	}, nil
}

// handlePasswordGenerate handles the password.generate method.
func (s *Server) handlePasswordGenerate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params PasswordGenerateParams
	if err := decodeParams(req, &params); err != nil {
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
		return nil, mapPasswordError(err)
	}

	return PasswordGenerateResult{
		Password: password,
		Length:   length,
	}, nil
}

// handlePasswordSetAccessMode handles the password.setAccessMode method. It
// delegates to XKMSService.PasswordStoreSetAccessMode, which owns the rules
// for which access-control strategy the addressed password store can
// enforce; this handler only translates its result onto the wire, mirroring
// pkg/api/rest/password_handlers.go's SetAccessModeHandler.
func (s *Server) handlePasswordSetAccessMode(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, errPasswordStoreNotConfigured()
	}

	var params transport.PasswordStoreSetAccessModeRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if params.Mode == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: xkms.ErrInvalidAccessMode}
	}

	if err := s.xkmsService.PasswordStoreSetAccessMode(ctx, &params); err != nil {
		return nil, mapPasswordAccessModeError(err)
	}

	return PasswordAccessModeResult{
		Mode:    params.Mode,
		Message: "Password store access mode set",
	}, nil
}

// mapPasswordAccessModeError converts an error returned by
// XKMSService.PasswordStoreSetAccessMode into a *KeyOpError carrying the
// JSON-RPC error code InvokeMethod should report, mirroring
// pkg/api/rest/password_handlers.go's passwordHandleAccessModeError: a
// malformed request or an out-of-vocabulary mode is Invalid params, an
// unconfigured store is Service unavailable (matching REST's 503), and an
// unsupported (but well-formed) mode is a capability boundary of the wired
// store -- Method not found, MCP's signal for "not implemented here" -- not a
// caller error.
func mapPasswordAccessModeError(err error) error {
	switch {
	case errors.Is(err, xkms.ErrInvalidAccessMode), errors.Is(err, xkms.ErrNilRequest):
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: err}
	case errors.Is(err, xkms.ErrNotConfigured):
		return &KeyOpError{Code: ErrCodeServiceUnavailable, Err: ErrPasswordStoreNotConfigured}
	case errors.Is(err, xkms.ErrOperationNotSupported):
		return &KeyOpError{Code: ErrCodeMethodNotFound, Err: err}
	default:
		return &KeyOpError{Code: ErrCodeInternalError, Err: err}
	}
}

// mapPasswordError converts an error returned by an XKMSService password
// entry method into a *KeyOpError, mirroring the JSON-RPC-vocabulary-appropriate code
// pkg/api/grpc/service_password.go's mapPasswordError chooses for the same
// sentinel (its own per-case gRPC status message is not reproduced here;
// this transport keeps its own established wording per case). It used to
// return an unclassified, unwrapped sentinel for every case:
// pkg/apimodule's dispatcher (module_mcp.go) only recognises *KeyOpError, so
// every password.* handler that reached this function -- add, get, list,
// update, delete, unlock, lock, generate -- reported ErrCodeInternalError
// regardless of the actual condition (go-xkms#912).
func mapPasswordError(err error) error {
	switch {
	case errors.Is(err, staticpw.ErrInvalidName):
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: ErrPasswordNameRequired}
	case errors.Is(err, staticpw.ErrEmptyPassword):
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: ErrPasswordRequired}
	case errors.Is(err, staticpw.ErrInvalidLength):
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: staticpw.ErrInvalidLength}
	case errors.Is(err, staticpw.ErrInvalidCharset):
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: staticpw.ErrInvalidCharset}
	case errors.Is(err, staticpw.ErrInvalidTenantID):
		// Matches gRPC's codes.InvalidArgument (service_password.go).
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: staticpw.ErrInvalidTenantID}
	case errors.Is(err, staticpw.ErrInvalidFolderPath):
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: staticpw.ErrInvalidFolderPath}
	case errors.Is(err, staticpw.ErrFolderPathTooDeep):
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: staticpw.ErrFolderPathTooDeep}
	case errors.Is(err, staticpw.ErrPasswordExists):
		return &KeyOpError{Code: sdkssh.JSONRPCCodeDuplicate, Err: staticpw.ErrPasswordExists}
	case errors.Is(err, staticpw.ErrStoreClosed):
		return &KeyOpError{Code: ErrCodeServiceUnavailable, Err: staticpw.ErrStoreClosed}
	case errors.Is(err, staticpw.ErrPasswordNotFound):
		return &KeyOpError{Code: sdkssh.JSONRPCCodeNotFound, Err: staticpw.ErrPasswordNotFound}
	case errors.Is(err, staticpw.ErrPasswordReadOnly):
		return &KeyOpError{Code: ErrCodeForbidden, Err: staticpw.ErrPasswordReadOnly}
	case errors.Is(err, staticpw.ErrNotOwner):
		// A shared entry the caller does not own; matches gRPC's
		// codes.PermissionDenied and REST's 403.
		return &KeyOpError{Code: ErrCodeForbidden, Err: staticpw.ErrNotOwner}
	default:
		// Store resolution errors (not configured, locked, sealed, unknown
		// tenant, invalid identity or scope) reach the entry handlers too,
		// because the servicer resolves the caller's store on every call.
		return mapPasswordStoreError(err)
	}
}

// mapPasswordUnlockError converts an error returned by
// XKMSService.PasswordStoreUnlock into a *KeyOpError carrying the JSON-RPC
// code InvokeMethod should report. It reuses the KeyOpError envelope so the
// dispatcher does not collapse a missing-PIN rejection into a generic internal
// error, which would make an unlock denial indistinguishable from a crash.
//
// A failed PIN verification reports Invalid params without echoing the PIN
// backend's message, which can carry retry counters and lockout state.
func mapPasswordUnlockError(err error) error {
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, xkms.ErrPasswordStoreUserPINRequired),
		errors.Is(err, xkms.ErrPasswordStoreUserPINNotProvisioned):
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: err}
	case errors.Is(err, xkms.ErrOperationNotSupported):
		// A request without an identity has no personal session: a
		// capability boundary, reported as REST's 501 is.
		return &KeyOpError{Code: ErrCodeMethodNotFound, Err: err}
	case errors.Is(err, xkms.ErrNilRequest):
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: err}
	case errors.Is(err, xkms.ErrNotConfigured),
		errors.Is(err, staticpw.ErrInvalidUserID),
		errors.Is(err, staticpw.ErrNoSystemBarrier),
		errors.Is(err, seal.ErrTenantNotFound):
		return mapPasswordStoreError(err)
	case errors.Is(err, staticpw.ErrStoreNotLocked),
		errors.Is(err, seal.ErrTenantSealed):
		return classified(ErrCodeInternalError, err)
	default:
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "user PIN verification failed"}}
	}
}

// mapPasswordLockError converts an error returned by
// XKMSService.PasswordStoreLock into a *KeyOpError. It mirrors
// mapPasswordUnlockError: a request without an identity is a capability
// boundary (Method not found), and a session that is already locked is a
// client-facing precondition failure on the internal floor, as an already
// open session is on unlock.
func mapPasswordLockError(err error) error {
	switch {
	case errors.Is(err, xkms.ErrOperationNotSupported):
		return &KeyOpError{Code: ErrCodeMethodNotFound, Err: err}
	case errors.Is(err, staticpw.ErrStoreAlreadyLocked):
		return classified(ErrCodeInternalError, err)
	default:
		return mapPasswordStoreError(err)
	}
}

// mapPasswordStoreError converts an error the servicer reports while
// resolving the caller's store (or reading its status) into a *KeyOpError.
// It used to return an unclassified, unwrapped sentinel for every case, so
// every caller reported ErrCodeInternalError regardless of cause
// (go-xkms#912).
func mapPasswordStoreError(err error) error {
	switch {
	case errors.Is(err, ErrPasswordStoreNotConfigured),
		errors.Is(err, staticpw.ErrNotConfigured),
		errors.Is(err, xkms.ErrNotConfigured),
		errors.Is(err, staticpw.ErrNoSystemBarrier):
		return errPasswordStoreNotConfigured()
	case errors.Is(err, xkms.ErrNilRequest):
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: xkms.ErrNilRequest}
	case errors.Is(err, seal.ErrTenantNotFound):
		return &KeyOpError{Code: sdkssh.JSONRPCCodeNotFound, Err: seal.ErrTenantNotFound}
	case errors.Is(err, staticpw.ErrInvalidUserID):
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: staticpw.ErrInvalidUserID}
	case errors.Is(err, staticpw.ErrInvalidScope):
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: staticpw.ErrInvalidScope}
	case errors.Is(err, staticpw.ErrNotOwner):
		return &KeyOpError{Code: ErrCodeForbidden, Err: staticpw.ErrNotOwner}
	case errors.Is(err, staticpw.ErrStoreLocked), errors.Is(err, seal.ErrTenantSealed):
		// JSON-RPC has no FailedPrecondition code; matches the internal
		// floor mapPasswordUnlockError already uses for the same two
		// sentinels on the unlock path.
		return classified(ErrCodeInternalError, err)
	default:
		return &KeyOpError{Code: ErrCodeInternalError, Err: err}
	}
}
