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

package grpc

import (
	"context"
	"errors"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// PasswordAdd creates a new password entry in the encrypted store.
func (s *Service) PasswordAdd(ctx context.Context, req *pb.PasswordAddRequest) (*pb.PasswordAddResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}

	if err := s.authorize(ctx, auth.ResourcePasswords, auth.ActionWrite, req.Name); err != nil {
		return nil, err
	}

	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}

	transportReq := &transport.PasswordAddRequest{
		Name:       req.Name,
		Username:   req.Username,
		Password:   req.Password,
		URL:        req.Url,
		Notes:      req.Notes,
		FolderPath: req.FolderPath,
		ExpiresAt:  req.ExpiresAt,
		Shared:     req.Shared,
	}

	resp, addErr := svc.PasswordAdd(ctx, transportReq)
	if addErr != nil {
		return nil, mapPasswordError(addErr)
	}

	return &pb.PasswordAddResponse{
		Id:        resp.ID,
		Name:      resp.Name,
		CreatedAt: resp.CreatedAt,
	}, nil
}

// PasswordGet retrieves a password entry by ID or name.
func (s *Service) PasswordGet(ctx context.Context, req *pb.PasswordGetRequest) (*pb.PasswordGetResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}

	if err := s.authorize(ctx, auth.ResourcePasswords, auth.ActionRead, req.Id); err != nil {
		return nil, err
	}

	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}

	transportReq := &transport.PasswordGetRequest{
		ID: req.Id,
	}

	resp, getErr := svc.PasswordGet(ctx, transportReq)
	if getErr != nil {
		return nil, mapPasswordError(getErr)
	}

	return passwordGetResponseToProto(resp), nil
}

// PasswordList returns all password entries, optionally filtered by folder path or scope.
func (s *Service) PasswordList(ctx context.Context, req *pb.PasswordListRequest) (*pb.PasswordListResponse, error) {
	if req == nil {
		req = &pb.PasswordListRequest{}
	}

	if err := s.authorize(ctx, auth.ResourcePasswords, auth.ActionRead, ""); err != nil {
		return nil, err
	}

	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}

	transportReq := &transport.PasswordListRequest{
		FolderPath: req.FolderPath,
		Scope:      req.Scope,
	}

	resp, listErr := svc.PasswordList(ctx, transportReq)
	if listErr != nil {
		return nil, mapPasswordError(listErr)
	}

	passwords := make([]*pb.PasswordEntry, 0, len(resp.Passwords))
	for _, pw := range resp.Passwords {
		passwords = append(passwords, passwordEntryToProto(&pw))
	}

	return &pb.PasswordListResponse{
		Passwords: passwords,
		Total:     int32(resp.Total), // #nosec G115 - Password count fits in int32
	}, nil
}

// PasswordUpdate updates an existing password entry.
func (s *Service) PasswordUpdate(ctx context.Context, req *pb.PasswordUpdateRequest) (*pb.PasswordUpdateResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}

	if err := s.authorize(ctx, auth.ResourcePasswords, auth.ActionWrite, req.Id); err != nil {
		return nil, err
	}

	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}

	transportReq := &transport.PasswordUpdateRequest{
		ID: req.Id,
	}

	// Apply only provided fields using pointer semantics
	if req.Name != nil {
		transportReq.Name = req.Name
	}
	if req.Username != nil {
		transportReq.Username = req.Username
	}
	if req.Password != nil {
		transportReq.Password = req.Password
	}
	if req.Url != nil {
		transportReq.URL = req.Url
	}
	if req.Notes != nil {
		transportReq.Notes = req.Notes
	}
	if req.FolderPath != nil {
		transportReq.FolderPath = req.FolderPath
	}
	if req.ExpiresAt != nil {
		transportReq.ExpiresAt = req.ExpiresAt
	}

	if updateErr := svc.PasswordUpdate(ctx, transportReq); updateErr != nil {
		return nil, mapPasswordError(updateErr)
	}

	return &pb.PasswordUpdateResponse{
		Id:      req.Id,
		Message: "Password updated successfully",
	}, nil
}

// PasswordDelete removes a password entry from the store.
func (s *Service) PasswordDelete(ctx context.Context, req *pb.PasswordDeleteRequest) (*pb.PasswordDeleteResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}

	if err := s.authorize(ctx, auth.ResourcePasswords, auth.ActionDelete, req.Id); err != nil {
		return nil, err
	}

	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}

	transportReq := &transport.PasswordDeleteRequest{
		ID: req.Id,
	}

	if deleteErr := svc.PasswordDelete(ctx, transportReq); deleteErr != nil {
		return nil, mapPasswordError(deleteErr)
	}

	return &pb.PasswordDeleteResponse{
		Success: true,
		Message: "Password deleted successfully",
	}, nil
}

// PasswordStoreUnlock unlocks the tenant password store session.
func (s *Service) PasswordStoreUnlock(ctx context.Context, req *pb.PasswordStoreUnlockRequest) (*pb.PasswordStoreStatusResponse, error) {
	if req == nil {
		req = &pb.PasswordStoreUnlockRequest{}
	}

	if err := s.authorize(ctx, auth.ResourcePasswords, auth.ActionUnlock, ""); err != nil {
		return nil, err
	}

	// NOTE: unlike the REST, QUIC, and MCP handlers, this deliberately does NOT
	// reject a platform-scoped caller up front. This same service is served
	// over the Unix socket, which sets no authentication interceptor because
	// the trust boundary is the socket's file mode — so a nil identity is
	// legitimate there, not an unauthenticated caller. The scoping is enforced
	// one layer down instead: XKMSService.scopedTenantIDFromContext resolves a
	// platform-scoped caller to the system store rather than inventing a
	// per-tenant store named "system".
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}

	transportReq := &transport.PasswordStoreUnlockRequest{
		UserPIN: req.Pin,
	}

	if unlockErr := svc.PasswordStoreUnlock(ctx, transportReq); unlockErr != nil {
		return nil, mapPasswordUnlockError(unlockErr)
	}

	// Return updated status
	statusResp, statusErr := svc.PasswordStoreStatus(ctx)
	if statusErr != nil {
		// Unlock succeeded but status retrieval failed
		return &pb.PasswordStoreStatusResponse{
			IsLocked: false,
			Message:  "Store unlocked successfully",
		}, nil
	}

	return &pb.PasswordStoreStatusResponse{
		AccessMode:    statusResp.AccessMode,
		IsLocked:      statusResp.IsLocked,
		BarrierSealed: statusResp.BarrierSealed,
		AutoUnsealed:  statusResp.AutoUnsealed,
		PasswordCount: int32(statusResp.PasswordCount), // #nosec G115 - Password count fits in int32
		Message:       "Store unlocked successfully",
	}, nil
}

// PasswordStoreLock locks the tenant password store session.
func (s *Service) PasswordStoreLock(ctx context.Context, req *pb.PasswordStoreLockRequest) (*pb.PasswordStoreStatusResponse, error) {
	if err := s.authorize(ctx, auth.ResourcePasswords, auth.ActionLock, ""); err != nil {
		return nil, err
	}

	// See PasswordStoreUnlock: no up-front scope rejection here, because the
	// Unix socket serves this same service with a nil identity by design.
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}

	if lockErr := svc.PasswordStoreLock(ctx); lockErr != nil {
		return nil, mapPasswordError(lockErr)
	}

	// Return updated status
	statusResp, statusErr := svc.PasswordStoreStatus(ctx)
	if statusErr != nil {
		// Lock succeeded but status retrieval failed
		return &pb.PasswordStoreStatusResponse{
			IsLocked: true,
			Message:  "Store locked successfully",
		}, nil
	}

	return &pb.PasswordStoreStatusResponse{
		AccessMode:    statusResp.AccessMode,
		IsLocked:      statusResp.IsLocked,
		BarrierSealed: statusResp.BarrierSealed,
		AutoUnsealed:  statusResp.AutoUnsealed,
		PasswordCount: int32(statusResp.PasswordCount), // #nosec G115 - Password count fits in int32
		Message:       "Store locked successfully",
	}, nil
}

// PasswordStoreStatus returns the current status of the password store.
func (s *Service) PasswordStoreStatus(ctx context.Context, req *pb.PasswordStoreStatusRequest) (*pb.PasswordStoreStatusResponse, error) {
	if err := s.authorize(ctx, auth.ResourcePasswords, auth.ActionRead, "status"); err != nil {
		return nil, err
	}

	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}

	statusResp, statusErr := svc.PasswordStoreStatus(ctx)
	if statusErr != nil {
		return nil, mapPasswordError(statusErr)
	}

	return &pb.PasswordStoreStatusResponse{
		AccessMode:    statusResp.AccessMode,
		IsLocked:      statusResp.IsLocked,
		BarrierSealed: statusResp.BarrierSealed,
		AutoUnsealed:  statusResp.AutoUnsealed,
		PasswordCount: int32(statusResp.PasswordCount), // #nosec G115 - Password count fits in int32
	}, nil
}

// PasswordGenerate generates a random password with the specified constraints.
func (s *Service) PasswordGenerate(ctx context.Context, req *pb.PasswordGenerateRequest) (*pb.PasswordGenerateResponse, error) {
	if req == nil {
		req = &pb.PasswordGenerateRequest{}
	}

	if err := s.authorize(ctx, auth.ResourcePasswords, auth.ActionGenerate, ""); err != nil {
		return nil, err
	}

	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}

	transportReq := &transport.PasswordGenerateRequest{
		Length:  int(req.Length),
		Upper:   req.Upper,
		Lower:   req.Lower,
		Digits:  req.Digits,
		Symbols: req.Symbols,
	}

	resp, genErr := svc.PasswordGenerate(ctx, transportReq)
	if genErr != nil {
		return nil, mapPasswordError(genErr)
	}

	return &pb.PasswordGenerateResponse{
		Password: resp.Password,
		Length:   int32(len(resp.Password)), // #nosec G115 - Password length fits in int32
	}, nil
}

// PasswordStoreSetAccessMode selects the access-control strategy for the
// password store addressed by the request context. Gated the same as its
// PasswordAdd/PasswordUpdate siblings (passwords:write): the unified gRPC
// server denies any RPC without a (qrdb.v1.permission) option by default, so
// -- like the rest of this family -- it cannot rely on a permission-free
// tier the way pkg/api/rest/routes.go's session helper does for the REST
// equivalent (POST /api/v1/passwords/access-mode).
func (s *Service) PasswordStoreSetAccessMode(ctx context.Context, req *pb.PasswordStoreSetAccessModeRequest) (*pb.PasswordStoreSetAccessModeResponse, error) {
	if req == nil || req.Mode == "" {
		return nil, status.Error(codes.InvalidArgument, "mode is required")
	}
	if err := s.authorize(ctx, auth.ResourcePasswords, auth.ActionWrite, ""); err != nil {
		return nil, err
	}

	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}

	if err := svc.PasswordStoreSetAccessMode(ctx, &transport.PasswordStoreSetAccessModeRequest{
		Mode: req.Mode,
	}); err != nil {
		return nil, mapAccessModeError(err)
	}

	return &pb.PasswordStoreSetAccessModeResponse{
		Mode:    req.Mode,
		Message: "Password store access mode set",
	}, nil
}

// mapAccessModeError maps the errors PasswordStoreSetAccessMode returns. An
// unsupported (but well-formed) mode is a capability boundary of the wired
// store, not a malformed request, so it maps to FailedPrecondition rather
// than InvalidArgument -- mirroring the REST handler's 501.
func mapAccessModeError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, xkms.ErrInvalidAccessMode):
		return status.Error(codes.FailedPrecondition, "invalid access mode (allowed: pin_per_operation, session_based)")
	case errors.Is(err, xkms.ErrNotConfigured):
		return status.Error(codes.Unavailable, "password store not configured")
	case errors.Is(err, xkms.ErrNilRequest):
		return status.Error(codes.InvalidArgument, "request is required")
	default:
		return mapPasswordError(err)
	}
}

// mapPasswordError converts staticpw and xkms errors to appropriate gRPC status codes.
// mapPasswordUnlockError maps the errors returned by
// XKMSService.PasswordStoreUnlock. It defers to mapPasswordError for every
// recognised sentinel and differs only in its fallback: on the unlock path a
// residual error is a failed PIN verification from the PIN backend, which is
// PermissionDenied rather than Internal. The backend's message is not echoed
// because it can carry retry counters and lockout state.
func mapPasswordUnlockError(err error) error {
	if err == nil {
		return nil
	}

	// A wrong PIN produces an error that matches none of the known sentinels,
	// so mapPasswordError would report it as Internal. Detect that case by
	// checking whether the mapping fell through to its default.
	mapped := mapPasswordError(err)
	if status.Code(mapped) == codes.Internal && !isKnownInternalPasswordError(err) {
		return status.Error(codes.PermissionDenied, "user PIN verification failed")
	}
	return mapped
}

// isKnownInternalPasswordError reports whether err is one of the genuine
// internal faults mapPasswordError deliberately maps to codes.Internal, as
// opposed to an unrecognised error that merely fell through to the default.
func isKnownInternalPasswordError(err error) bool {
	return errors.Is(err, staticpw.ErrNilStore) ||
		errors.Is(err, staticpw.ErrNilBarrierRegistry)
}

func mapPasswordError(err error) error {
	if err == nil {
		return nil
	}

	switch {
	// Not found errors
	case errors.Is(err, staticpw.ErrPasswordNotFound):
		return status.Error(codes.NotFound, "password not found")

	// Conflict errors
	case errors.Is(err, staticpw.ErrPasswordExists):
		return status.Error(codes.AlreadyExists, "password with this name already exists")
	case errors.Is(err, staticpw.ErrStoreNotLocked):
		return status.Error(codes.FailedPrecondition, "store is already unlocked")
	case errors.Is(err, staticpw.ErrStoreAlreadyLocked):
		return status.Error(codes.FailedPrecondition, "store is already locked")

	// Validation errors
	case errors.Is(err, staticpw.ErrInvalidName):
		return status.Error(codes.InvalidArgument, "name is required")
	case errors.Is(err, staticpw.ErrEmptyPassword):
		return status.Error(codes.InvalidArgument, "password is required")
	case errors.Is(err, staticpw.ErrInvalidLength):
		return status.Error(codes.InvalidArgument, "invalid password length (min 8, max 128)")
	case errors.Is(err, staticpw.ErrInvalidScope):
		return status.Error(codes.InvalidArgument, "invalid scope (use personal, shared, or all)")
	case errors.Is(err, staticpw.ErrInvalidTenantID):
		return status.Error(codes.InvalidArgument, "invalid tenant ID")
	case errors.Is(err, staticpw.ErrInvalidUserID):
		return status.Error(codes.InvalidArgument, "invalid user identity")
	case errors.Is(err, staticpw.ErrInvalidFolderPath):
		return status.Error(codes.InvalidArgument, "invalid folder path")
	case errors.Is(err, staticpw.ErrFolderPathTooDeep):
		return status.Error(codes.InvalidArgument, "folder path exceeds maximum depth")

	// Permission errors
	case errors.Is(err, staticpw.ErrPasswordReadOnly):
		return status.Error(codes.PermissionDenied, "password is read-only")
	case errors.Is(err, staticpw.ErrNotOwner):
		return status.Error(codes.PermissionDenied, "not the owner of this password")

	// Unavailable errors
	case errors.Is(err, staticpw.ErrStoreClosed):
		return status.Error(codes.Unavailable, "password store is closed")
	case errors.Is(err, staticpw.ErrStoreLocked):
		return status.Error(codes.FailedPrecondition, "password store is locked")
	case errors.Is(err, staticpw.ErrNotConfigured):
		return status.Error(codes.Unavailable, "password store not configured")
	case errors.Is(err, seal.ErrTenantSealed):
		return status.Error(codes.Unavailable, "tenant barrier is sealed")
	case errors.Is(err, seal.ErrTenantNotFound):
		return status.Error(codes.NotFound, "tenant not found")

	// Configuration/nil errors
	case errors.Is(err, staticpw.ErrNilStore):
		return status.Error(codes.Internal, "password store not initialized")
	case errors.Is(err, staticpw.ErrNilBarrierRegistry):
		return status.Error(codes.Internal, "barrier registry not configured")

	// xkms errors
	case errors.Is(err, xkms.ErrNotConfigured):
		return status.Error(codes.Unavailable, "password store not configured")
	case errors.Is(err, xkms.ErrOperationNotSupported):
		return status.Error(codes.Unimplemented, "operation not supported")
	case errors.Is(err, xkms.ErrNilRequest):
		return status.Error(codes.InvalidArgument, "request is required")

	// Password store user-PIN errors. These are distinguished from one another
	// so an operator can tell "you sent no PIN" from "this deployment has no
	// PIN to check"; a wrong PIN is reported by the PIN backend and is mapped
	// by mapPasswordUnlockError, which owns the unlock path.
	case errors.Is(err, xkms.ErrPasswordStoreUserPINRequired):
		return status.Error(codes.InvalidArgument, xkms.ErrPasswordStoreUserPINRequired.Error())
	case errors.Is(err, xkms.ErrPasswordStoreUserPINNotProvisioned):
		return status.Error(codes.FailedPrecondition, xkms.ErrPasswordStoreUserPINNotProvisioned.Error())

	default:
		// Check for error message patterns for errors that may be wrapped
		errMsg := err.Error()
		if strings.Contains(errMsg, "not found") {
			return status.Error(codes.NotFound, errMsg)
		}
		if strings.Contains(errMsg, "already exists") {
			return status.Error(codes.AlreadyExists, errMsg)
		}
		if strings.Contains(errMsg, "locked") {
			return status.Error(codes.FailedPrecondition, errMsg)
		}
		return status.Error(codes.Internal, errMsg)
	}
}

// passwordGetResponseToProto converts a transport.PasswordGetResponse to protobuf.
func passwordGetResponseToProto(resp *transport.PasswordGetResponse) *pb.PasswordGetResponse {
	var createdAt, updatedAt, expiresAt *timestamppb.Timestamp

	if resp.CreatedAt != "" {
		createdAt = parseTimestamp(resp.CreatedAt)
	}
	if resp.UpdatedAt != "" {
		updatedAt = parseTimestamp(resp.UpdatedAt)
	}
	if resp.ExpiresAt != "" {
		expiresAt = parseTimestamp(resp.ExpiresAt)
	}

	return &pb.PasswordGetResponse{
		Entry: &pb.PasswordEntry{
			Id:         resp.ID,
			Name:       resp.Name,
			Username:   resp.Username,
			Password:   resp.Password,
			Url:        resp.URL,
			Notes:      resp.Notes,
			FolderPath: resp.FolderPath,
			BackendId:  resp.BackendID,
			ExpiresAt:  expiresAt,
			CreatedAt:  createdAt,
			UpdatedAt:  updatedAt,
			ReadOnly:   resp.ReadOnly,
			Encrypted:  resp.Encrypted,
			OwnerId:    resp.OwnerID,
			Shared:     resp.Shared,
		},
	}
}

// passwordEntryToProto converts a transport.PasswordGetResponse to a protobuf PasswordEntry.
func passwordEntryToProto(resp *transport.PasswordGetResponse) *pb.PasswordEntry {
	var createdAt, updatedAt, expiresAt *timestamppb.Timestamp

	if resp.CreatedAt != "" {
		createdAt = parseTimestamp(resp.CreatedAt)
	}
	if resp.UpdatedAt != "" {
		updatedAt = parseTimestamp(resp.UpdatedAt)
	}
	if resp.ExpiresAt != "" {
		expiresAt = parseTimestamp(resp.ExpiresAt)
	}

	return &pb.PasswordEntry{
		Id:         resp.ID,
		Name:       resp.Name,
		Username:   resp.Username,
		Password:   resp.Password,
		Url:        resp.URL,
		Notes:      resp.Notes,
		FolderPath: resp.FolderPath,
		BackendId:  resp.BackendID,
		ExpiresAt:  expiresAt,
		CreatedAt:  createdAt,
		UpdatedAt:  updatedAt,
		ReadOnly:   resp.ReadOnly,
		Encrypted:  resp.Encrypted,
		OwnerId:    resp.OwnerID,
		Shared:     resp.Shared,
	}
}

// parseTimestamp parses an RFC3339 timestamp string to a protobuf Timestamp.
// Returns nil if the string is empty or parsing fails.
func parseTimestamp(ts string) *timestamppb.Timestamp {
	if ts == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return nil
	}
	return timestamppb.New(t)
}
