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

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
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

	if err := s.authorize(ctx, "passwords", "write", req.Name); err != nil {
		return nil, err
	}

	svc, err := xkms.Get()
	if err != nil {
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

	if err := s.authorize(ctx, "passwords", "read", req.Id); err != nil {
		return nil, err
	}

	svc, err := xkms.Get()
	if err != nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}

	transportReq := &transport.PasswordGetRequest{
		ID:      req.Id,
		Decrypt: req.Decrypt,
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

	if err := s.authorize(ctx, "passwords", "read", ""); err != nil {
		return nil, err
	}

	svc, err := xkms.Get()
	if err != nil {
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

	if err := s.authorize(ctx, "passwords", "write", req.Id); err != nil {
		return nil, err
	}

	svc, err := xkms.Get()
	if err != nil {
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

	if err := s.authorize(ctx, "passwords", "delete", req.Id); err != nil {
		return nil, err
	}

	svc, err := xkms.Get()
	if err != nil {
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

	if err := s.authorize(ctx, "passwords", "unlock", ""); err != nil {
		return nil, err
	}

	svc, err := xkms.Get()
	if err != nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}

	transportReq := &transport.PasswordStoreUnlockRequest{
		UserPIN: req.Pin,
	}

	if unlockErr := svc.PasswordStoreUnlock(ctx, transportReq); unlockErr != nil {
		return nil, mapPasswordError(unlockErr)
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
	if err := s.authorize(ctx, "passwords", "lock", ""); err != nil {
		return nil, err
	}

	svc, err := xkms.Get()
	if err != nil {
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
	if err := s.authorize(ctx, "passwords", "read", "status"); err != nil {
		return nil, err
	}

	svc, err := xkms.Get()
	if err != nil {
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

	if err := s.authorize(ctx, "passwords", "generate", ""); err != nil {
		return nil, err
	}

	svc, err := xkms.Get()
	if err != nil {
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

// mapPasswordError converts staticpw and xkms errors to appropriate gRPC status codes.
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
	case errors.Is(err, staticpw.ErrNilEncrypter):
		return status.Error(codes.Internal, "encrypter not configured")
	case errors.Is(err, staticpw.ErrNilBarrierRegistry):
		return status.Error(codes.Internal, "barrier registry not configured")

	// xkms errors
	case errors.Is(err, xkms.ErrNotConfigured):
		return status.Error(codes.Unavailable, "password store not configured")
	case errors.Is(err, xkms.ErrOperationNotSupported):
		return status.Error(codes.Unimplemented, "operation not supported")
	case errors.Is(err, xkms.ErrNilRequest):
		return status.Error(codes.InvalidArgument, "request is required")

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
