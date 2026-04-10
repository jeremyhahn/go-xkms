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

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// grpcCAMethodIssueEK issues an Endorsement Key certificate.
type grpcCAMethodIssueEK interface {
	IssueEKCertificate(ctx context.Context, req *transport.IssueEKCertificateRequest) (*transport.IssueEKCertificateResponse, error)
}

// grpcCAMethodIssueAK issues an Attestation Key certificate.
type grpcCAMethodIssueAK interface {
	IssueAKCertificate(ctx context.Context, req *transport.IssueAKCertificateRequest) (*transport.IssueAKCertificateResponse, error)
}

// grpcCAMethodSignTCGCSR signs a TCG-CSR-IDEVID.
type grpcCAMethodSignTCGCSR interface {
	SignTCGCSR(ctx context.Context, req *transport.SignTCGCSRRequest) (*transport.SignTCGCSRResponse, error)
}

// grpcCAMethodEnrollDevice performs full TCG device enrollment.
type grpcCAMethodEnrollDevice interface {
	EnrollDevice(ctx context.Context, req *transport.EnrollDeviceRequest) (*transport.EnrollDeviceResponse, error)
}

// IssueEKCertificate issues an Endorsement Key certificate for a TPM.
func (s *Service) IssueEKCertificate(ctx context.Context, req *pb.IssueEKCertificateRequest) (*pb.IssueEKCertificateResponse, error) {
	ca := getCAInstance()
	if ca == nil {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	if err := s.authorize(ctx, "ca", "write", ""); err != nil {
		return nil, err
	}

	if req.GetCommonName() == "" {
		return nil, status.Error(codes.InvalidArgument, "common name is required")
	}

	if len(req.GetEkPublicKey()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "EK public key is required")
	}

	issuer, ok := ca.(grpcCAMethodIssueEK)
	if !ok {
		return nil, status.Error(codes.Unavailable, "CA does not support TCG operations")
	}

	resp, err := issuer.IssueEKCertificate(ctx, &transport.IssueEKCertificateRequest{
		CommonName:   req.GetCommonName(),
		Organization: req.GetOrganization(),
		EKPublicKey:  req.GetEkPublicKey(),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to issue EK certificate: %v", err)
	}

	return &pb.IssueEKCertificateResponse{
		CertificateDer: resp.CertificateDER,
		CertificatePem: resp.CertificatePEM,
		SerialNumber:   resp.SerialNumber,
	}, nil
}

// IssueAKCertificate issues an Attestation Key certificate for a TPM.
func (s *Service) IssueAKCertificate(ctx context.Context, req *pb.IssueAKCertificateRequest) (*pb.IssueAKCertificateResponse, error) {
	ca := getCAInstance()
	if ca == nil {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	if err := s.authorize(ctx, "ca", "write", ""); err != nil {
		return nil, err
	}

	if req.GetCommonName() == "" {
		return nil, status.Error(codes.InvalidArgument, "common name is required")
	}

	if len(req.GetPublicKey()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "public key is required")
	}

	issuer, ok := ca.(grpcCAMethodIssueAK)
	if !ok {
		return nil, status.Error(codes.Unavailable, "CA does not support TCG operations")
	}

	resp, err := issuer.IssueAKCertificate(ctx, &transport.IssueAKCertificateRequest{
		CommonName:   req.GetCommonName(),
		Organization: req.GetOrganization(),
		PublicKey:    req.GetPublicKey(),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to issue AK certificate: %v", err)
	}

	return &pb.IssueAKCertificateResponse{
		CertificateDer: resp.CertificateDER,
		CertificatePem: resp.CertificatePEM,
		SerialNumber:   resp.SerialNumber,
	}, nil
}

// SignTCGCSR signs a TCG-CSR-IDEVID and returns IAK and IDevID certificates.
func (s *Service) SignTCGCSR(ctx context.Context, req *pb.SignTCGCSRRequest) (*pb.SignTCGCSRResponse, error) {
	ca := getCAInstance()
	if ca == nil {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	if err := s.authorize(ctx, "ca", "write", ""); err != nil {
		return nil, err
	}

	if req.GetCommonName() == "" {
		return nil, status.Error(codes.InvalidArgument, "common name is required")
	}

	if len(req.GetTcgCsr()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "TCG CSR data is required")
	}

	signer, ok := ca.(grpcCAMethodSignTCGCSR)
	if !ok {
		return nil, status.Error(codes.Unavailable, "CA does not support TCG operations")
	}

	resp, err := signer.SignTCGCSR(ctx, &transport.SignTCGCSRRequest{
		CommonName:   req.GetCommonName(),
		Organization: req.GetOrganization(),
		TCGCSR:       req.GetTcgCsr(),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to sign TCG CSR: %v", err)
	}

	return &pb.SignTCGCSRResponse{
		IakCertDer:    resp.IAKCertDER,
		IdevidCertDer: resp.IDevIDCertDER,
	}, nil
}

// EnrollDevice performs full TCG device enrollment with credential activation challenge.
func (s *Service) EnrollDevice(ctx context.Context, req *pb.EnrollDeviceRequest) (*pb.EnrollDeviceResponse, error) {
	ca := getCAInstance()
	if ca == nil {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	if err := s.authorize(ctx, "ca", "write", ""); err != nil {
		return nil, err
	}

	if req.GetCommonName() == "" {
		return nil, status.Error(codes.InvalidArgument, "common name is required")
	}

	if len(req.GetPackedCsr()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "packed CSR data is required")
	}

	enroller, ok := ca.(grpcCAMethodEnrollDevice)
	if !ok {
		return nil, status.Error(codes.Unavailable, "CA does not support TCG operations")
	}

	resp, err := enroller.EnrollDevice(ctx, &transport.EnrollDeviceRequest{
		CommonName:   req.GetCommonName(),
		Organization: req.GetOrganization(),
		PackedCSR:    req.GetPackedCsr(),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to enroll device: %v", err)
	}

	return &pb.EnrollDeviceResponse{
		IakCertDer:      resp.IAKCertDER,
		IdevidCertDer:   resp.IDevIDCertDER,
		CredentialBlob:  resp.CredentialBlob,
		EncryptedSecret: resp.EncryptedSecret,
		PlainSecret:     resp.PlainSecret,
	}, nil
}
