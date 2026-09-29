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

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// BeginRegistration begins a WebAuthn registration ceremony, delegating to the
// XKMSService singleton (which shares one WebAuthn relying-party service with
// the REST browser ceremony). It returns the JSON-marshaled options plus an
// opaque session ID.
//
// Deliberately ungated: a WebAuthn ceremony runs BEFORE the caller has an
// identity to authorize -- requiring a permission to log in would be
// circular. The REST transport leaves the same four ceremonies ungated
// against the same relying-party service, so the transports agree. This is
// recorded explicitly because an ungated RPC is otherwise indistinguishable
// from a missing gate, which is exactly the bug that the SSH surface in
// service_ssh.go had.
func (s *Service) BeginRegistration(ctx context.Context, req *pb.BeginRegistrationRequest) (*pb.BeginRegistrationResponse, error) {
	if req == nil || req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, cErr := svc.BeginRegistration(ctx, &transport.BeginRegistrationRequest{
		Email:       req.Email,
		DisplayName: req.DisplayName,
	})
	if cErr != nil {
		if errors.Is(cErr, webauthn.ErrRegistrationRefused) {
			return nil, status.Error(codes.PermissionDenied, webauthn.ErrRegistrationRefused.Error())
		}
		if webauthn.IsSessionLimit(cErr) {
			return nil, status.Error(codes.ResourceExhausted, "too many unfinished ceremonies; retry later")
		}
		return nil, status.Error(codes.Internal, cErr.Error())
	}
	return &pb.BeginRegistrationResponse{
		SessionId:   resp.SessionID,
		OptionsJson: resp.OptionsJSON,
	}, nil
}

// FinishRegistration completes a WebAuthn registration ceremony, delegating to
// the XKMSService singleton. The request carries the session ID from
// BeginRegistration and the authenticator attestation as WebAuthn
// PublicKeyCredential JSON.
//
// Deliberately ungated: a WebAuthn ceremony runs BEFORE the caller has an
// identity to authorize -- requiring a permission to log in would be
// circular. The REST transport leaves the same four ceremonies ungated
// against the same relying-party service, so the transports agree. This is
// recorded explicitly because an ungated RPC is otherwise indistinguishable
// from a missing gate, which is exactly the bug that the SSH surface in
// service_ssh.go had.
func (s *Service) FinishRegistration(ctx context.Context, req *pb.FinishRegistrationRequest) (*pb.FinishRegistrationResponse, error) {
	if req == nil || req.SessionId == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id is required")
	}
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, cErr := svc.FinishRegistration(ctx, &transport.FinishRegistrationRequest{
		SessionID:       req.SessionId,
		AttestationJSON: req.AttestationJson,
	})
	if cErr != nil {
		return nil, status.Error(codes.InvalidArgument, cErr.Error())
	}
	return &pb.FinishRegistrationResponse{
		Success:      resp.Success,
		CredentialId: resp.CredentialID,
		Token:        resp.Token,
		Message:      resp.Message,
	}, nil
}

// BeginAuthentication begins a WebAuthn authentication (login) ceremony,
// delegating to the XKMSService singleton (which shares one WebAuthn
// relying-party service with the REST browser ceremony). It returns the
// JSON-marshaled assertion options plus an opaque session ID.
//
// Deliberately ungated: a WebAuthn ceremony runs BEFORE the caller has an
// identity to authorize -- requiring a permission to log in would be
// circular. The REST transport leaves the same four ceremonies ungated
// against the same relying-party service, so the transports agree. This is
// recorded explicitly because an ungated RPC is otherwise indistinguishable
// from a missing gate, which is exactly the bug that the SSH surface in
// service_ssh.go had.
func (s *Service) BeginAuthentication(ctx context.Context, req *pb.BeginAuthenticationRequest) (*pb.BeginAuthenticationResponse, error) {
	if req == nil || req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, cErr := svc.BeginAuthentication(ctx, &transport.BeginAuthenticationRequest{
		Email: req.Email,
	})
	if cErr != nil {
		if webauthn.IsSessionLimit(cErr) {
			return nil, status.Error(codes.ResourceExhausted, "too many unfinished ceremonies; retry later")
		}
		return nil, status.Error(codes.Internal, cErr.Error())
	}
	return &pb.BeginAuthenticationResponse{
		SessionId:   resp.SessionID,
		OptionsJson: resp.OptionsJSON,
	}, nil
}

// FinishAuthentication completes a WebAuthn authentication (login) ceremony,
// delegating to the XKMSService singleton. The request carries the session ID
// from BeginAuthentication and the authenticator assertion as WebAuthn
// PublicKeyCredential JSON.
//
// Deliberately ungated: a WebAuthn ceremony runs BEFORE the caller has an
// identity to authorize -- requiring a permission to log in would be
// circular. The REST transport leaves the same four ceremonies ungated
// against the same relying-party service, so the transports agree. This is
// recorded explicitly because an ungated RPC is otherwise indistinguishable
// from a missing gate, which is exactly the bug that the SSH surface in
// service_ssh.go had.
func (s *Service) FinishAuthentication(ctx context.Context, req *pb.FinishAuthenticationRequest) (*pb.FinishAuthenticationResponse, error) {
	if req == nil || req.SessionId == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id is required")
	}
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, cErr := svc.FinishAuthentication(ctx, &transport.FinishAuthenticationRequest{
		SessionID:     req.SessionId,
		Email:         req.Email,
		AssertionJSON: req.AssertionJson,
	})
	if cErr != nil {
		return nil, status.Error(codes.InvalidArgument, cErr.Error())
	}
	return &pb.FinishAuthenticationResponse{
		Success:  resp.Success,
		Token:    resp.Token,
		Username: resp.Username,
		Message:  resp.Message,
	}, nil
}
