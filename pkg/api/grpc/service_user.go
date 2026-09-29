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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// userInfoToProto projects a transport.UserInfo onto its protobuf form.
func userInfoToProto(u transport.UserInfo) *pb.UserInfo {
	return &pb.UserInfo{
		Id:          u.ID,
		Username:    u.Username,
		Email:       u.Email,
		DisplayName: u.DisplayName,
		Role:        u.Role,
		Enabled:     u.Enabled,
	}
}

// CreateUser creates a new xkms user, backed by the embedded qrdb node.
func (s *Service) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.UserResponse, error) {
	if req == nil || req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if err := s.authorize(ctx, auth.ResourceUsers, auth.ActionCreate, req.Username); err != nil {
		return nil, err
	}
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, cErr := svc.CreateUser(ctx, &transport.CreateUserRequest{
		Username:             req.Username,
		Email:                req.Email,
		WithoutEmailLoginKey: req.WithoutEmailLoginKey,
		DisplayName:          req.DisplayName,
		Role:                 req.Role,
		TenantID:             req.TenantId,
	})
	if cErr != nil {
		return nil, status.Error(createUserErrorCode(cErr), cErr.Error())
	}
	return &pb.UserResponse{User: userInfoToProto(resp.User)}, nil
}

// ListUsers lists xkms users.
func (s *Service) ListUsers(ctx context.Context, _ *pb.ListUsersRequest) (*pb.ListUsersResponse, error) {
	if err := s.authorize(ctx, auth.ResourceUsers, auth.ActionList, ""); err != nil {
		return nil, err
	}
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, lErr := svc.ListUsers(ctx)
	if lErr != nil {
		return nil, status.Error(codes.Internal, lErr.Error())
	}
	users := make([]*pb.UserInfo, len(resp.Users))
	for i, u := range resp.Users {
		users[i] = userInfoToProto(u)
	}
	return &pb.ListUsersResponse{Users: users}, nil
}

// GetUser resolves an xkms user by username.
func (s *Service) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.UserResponse, error) {
	if req == nil || req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if err := s.authorize(ctx, auth.ResourceUsers, auth.ActionRead, req.Username); err != nil {
		return nil, err
	}
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, gErr := svc.GetUser(ctx, req.Username)
	if gErr != nil {
		return nil, status.Error(codes.NotFound, gErr.Error())
	}
	return &pb.UserResponse{User: userInfoToProto(resp.User)}, nil
}

// DeleteUser removes an xkms user by username.
func (s *Service) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*pb.DeleteUserResponse, error) {
	if req == nil || req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if err := s.authorize(ctx, auth.ResourceUsers, auth.ActionDelete, req.Username); err != nil {
		return nil, err
	}
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	if dErr := svc.DeleteUser(ctx, req.Username); dErr != nil {
		return nil, status.Error(codes.Internal, dErr.Error())
	}
	return &pb.DeleteUserResponse{Username: req.Username, Deleted: true}, nil
}

// EnableUser enables an xkms user by username. It requires users:enable
// (go-qrdb permission.UsersEnable) rather than the coarser users:update,
// so a role can grant re-activation without also granting DisableUser or
// the general user-mutation surface (go-xkms#1249).
func (s *Service) EnableUser(ctx context.Context, req *pb.EnableUserRequest) (*pb.UserResponse, error) {
	if req.GetUsername() == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if err := s.authorize(ctx, auth.ResourceUsers, auth.ActionEnable, req.GetUsername()); err != nil {
		return nil, err
	}
	return s.setUserEnabled(ctx, req.GetUsername(), true)
}

// DisableUser disables an xkms user by username. It requires users:disable
// (go-qrdb permission.UsersDisable) rather than the coarser users:update,
// for the same reason EnableUser requires users:enable (go-xkms#1249).
func (s *Service) DisableUser(ctx context.Context, req *pb.DisableUserRequest) (*pb.UserResponse, error) {
	if req.GetUsername() == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if err := s.authorize(ctx, auth.ResourceUsers, auth.ActionDisable, req.GetUsername()); err != nil {
		return nil, err
	}
	return s.setUserEnabled(ctx, req.GetUsername(), false)
}

// setUserEnabled performs the toggle and returns the updated user. Callers
// (EnableUser, DisableUser) authorize before calling this helper — each with
// its own permission — so this helper itself must never hold an authorize
// call site.
func (s *Service) setUserEnabled(ctx context.Context, username string, enabled bool) (*pb.UserResponse, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	var err error
	if enabled {
		err = svc.EnableUser(ctx, username)
	} else {
		err = svc.DisableUser(ctx, username)
	}
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	resp, gErr := svc.GetUser(ctx, username)
	if gErr != nil {
		return nil, status.Error(codes.Internal, gErr.Error())
	}
	return &pb.UserResponse{User: userInfoToProto(resp.User)}, nil
}

// BindUserCert binds an mTLS certificate SPKI thumbprint to an xkms user.
func (s *Service) BindUserCert(ctx context.Context, req *pb.BindUserCertRequest) (*pb.UserResponse, error) {
	if req == nil || req.GetUsername() == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if req.GetThumbprint() == "" {
		return nil, status.Error(codes.InvalidArgument, "thumbprint is required")
	}
	if err := s.authorize(ctx, auth.ResourceUsers, auth.ActionUpdate, req.GetUsername()); err != nil {
		return nil, err
	}
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	if bErr := svc.BindUserCert(ctx, req.GetUsername(), req.GetThumbprint(), req.GetNotAfterUnix()); bErr != nil {
		return nil, status.Error(codes.Internal, bErr.Error())
	}
	resp, gErr := svc.GetUser(ctx, req.GetUsername())
	if gErr != nil {
		return nil, status.Error(codes.Internal, gErr.Error())
	}
	return &pb.UserResponse{User: userInfoToProto(resp.User)}, nil
}

// ListUserCredentials lists the credentials registered to an xkms user.
func (s *Service) ListUserCredentials(ctx context.Context, req *pb.ListUserCredentialsRequest) (*pb.ListUserCredentialsResponse, error) {
	if req == nil || req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if err := s.authorize(ctx, auth.ResourceUsers, auth.ActionRead, req.Username); err != nil {
		return nil, err
	}
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, lErr := svc.ListUserCredentials(ctx, req.Username)
	if lErr != nil {
		return nil, status.Error(codes.NotFound, lErr.Error())
	}
	creds := make([]*pb.UserCredential, len(resp.Credentials))
	for i, c := range resp.Credentials {
		creds[i] = &pb.UserCredential{Id: c.ID, Name: c.DisplayName}
	}
	return &pb.ListUserCredentialsResponse{Credentials: creds}, nil
}

// createUserErrorCode classifies a CreateUser failure.
//
// A missing login key is malformed CLIENT input: InvalidArgument tells the
// caller to fix the request, where Internal tells it to retry something that
// can never succeed and buries a fixable mistake in the server's error rate.
// It is a named function rather than an inline branch so the classification can
// be tested without standing up a full Service.
func createUserErrorCode(err error) codes.Code {
	if errors.Is(err, xkms.ErrEmailRequired) {
		return codes.InvalidArgument
	}
	return codes.Internal
}
