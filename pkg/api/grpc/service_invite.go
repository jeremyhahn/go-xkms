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
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Invitation redemption (go-xkms#1294 part B): how an account CreateUser
// provisioned with zero credentials enrolls its first one. Registered on
// KeystoreService, so this one implementation serves both the gRPC
// transport and the Unix-socket transport, which registers the same
// service over a Unix listener (pkg/api/unix/grpc_server.go).
//
// Every RPC here is deliberately ungated, for the same reason the
// FIDO2/WebAuthn ceremony RPCs in service_fido2.go are: there is no
// credential yet to authenticate a request with, and requiring one would be
// circular. The REST transport (pkg/api/rest/handlers_invite.go) leaves the
// same four routes public against the same XKMSService methods, so the
// transports agree.

// invitationErrorStatus maps an XKMSService invite-redemption error to the
// gRPC status every transport-agreed case gets. xkms.ErrInviteUnusable is
// the one opaque answer every unusable token gets (absent, expired, already
// redeemed, malformed) — mapped to NotFound, mirroring the REST transport's
// 404. A PIV certificate error carries its own detail, since it describes
// the caller's own input, not a probeable secret.
func invitationErrorStatus(err error) error {
	var certDecode *xkms.ErrPIVCertDecode
	var certRejected *xkms.ErrPIVCertRejected
	switch {
	case errors.Is(err, xkms.ErrInviteUnusable):
		return status.Error(codes.NotFound, xkms.ErrInviteUnusable.Error())
	case errors.As(err, &certDecode):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.As(err, &certRejected):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, xkms.ErrNotConfigured):
		return status.Error(codes.Unavailable, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

// GetInvite resolves a still-usable invitation's metadata without consuming it.
func (s *Service) GetInvite(ctx context.Context, req *pb.GetInviteRequest) (*pb.GetInviteResponse, error) {
	if req == nil || req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, err := svc.GetInvite(ctx, &transport.GetInviteRequest{TenantID: req.TenantId, Token: req.Token})
	if err != nil {
		return nil, invitationErrorStatus(err)
	}
	return &pb.GetInviteResponse{
		Email:       resp.Email,
		DisplayName: resp.DisplayName,
		ExpiresAt:   timestamppb.New(resp.ExpiresAt),
		Methods:     resp.Methods,
	}, nil
}

// BeginInviteRegistration opens the invite-authorized WebAuthn registration
// ceremony for the token's account.
func (s *Service) BeginInviteRegistration(ctx context.Context, req *pb.BeginInviteRegistrationRequest) (*pb.BeginInviteRegistrationResponse, error) {
	if req == nil || req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, err := svc.BeginInviteRegistration(ctx, &transport.BeginInviteRegistrationRequest{TenantID: req.TenantId, Token: req.Token})
	if err != nil {
		return nil, invitationErrorStatus(err)
	}
	return &pb.BeginInviteRegistrationResponse{SessionId: resp.SessionID, OptionsJson: resp.OptionsJSON}, nil
}

// FinishInviteRegistration completes the invite-authorized WebAuthn
// registration ceremony: it binds the credential, activates the account,
// and redeems the invitation.
func (s *Service) FinishInviteRegistration(ctx context.Context, req *pb.FinishInviteRegistrationRequest) (*pb.FinishInviteRegistrationResponse, error) {
	if req == nil || req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}
	if req.SessionId == "" || req.AttestationJson == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id and attestation_json are required")
	}
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, err := svc.FinishInviteRegistration(ctx, &transport.FinishInviteRegistrationRequest{
		TenantID:        req.TenantId,
		Token:           req.Token,
		SessionID:       req.SessionId,
		AttestationJSON: req.AttestationJson,
	})
	if err != nil {
		return nil, invitationErrorStatus(err)
	}
	return &pb.FinishInviteRegistrationResponse{UserId: resp.UserID}, nil
}

// ActivateInvitePIV activates the account by verifying a presented PIV
// certificate instead of a WebAuthn ceremony.
func (s *Service) ActivateInvitePIV(ctx context.Context, req *pb.ActivateInvitePIVRequest) (*pb.ActivateInvitePIVResponse, error) {
	if req == nil || req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}
	if req.CertPem == "" {
		return nil, status.Error(codes.InvalidArgument, "cert_pem is required")
	}
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, err := svc.ActivateInvitePIV(ctx, &transport.ActivateInvitePIVRequest{
		TenantID: req.TenantId,
		Token:    req.Token,
		CertPEM:  req.CertPem,
	})
	if err != nil {
		return nil, invitationErrorStatus(err)
	}
	return &pb.ActivateInvitePIVResponse{UserId: resp.UserID}, nil
}
