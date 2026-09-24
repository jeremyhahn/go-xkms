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
	"math/big"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// Typed errors for CA gRPC operations.
var (
	// ErrCANotConfigured is returned when no CA has been wired via SetCA.
	ErrCANotConfigured = errors.New("grpc: CA not configured")

	// ErrCAOperationFailed is returned when a CA operation fails internally.
	ErrCAOperationFailed = errors.New("grpc: CA operation failed")

	// ErrInvalidSerialNumber is returned when a serial number cannot be parsed.
	ErrInvalidSerialNumber = errors.New("grpc: invalid serial number format")
)

// SetCA configures the CA servicer for this Service. The composition root
// passes the *xkms.XKMSService, which exposes the transport-shaped CA
// methods (GetCACertificate, SignCSR, IssueCertificate, etc.) that the
// handlers in this file and service_ca_tcg.go delegate to. It is optional,
// auxiliary wiring performed by the composition root after NewService,
// mirroring SetSSHClient. A nil ca (the default) causes CA RPCs to return
// codes.Unavailable.
func (s *Service) SetCA(ca any) {
	s.ca = ca
}

// CA returns the configured CA instance, or nil if not set.
func (s *Service) CA() any {
	return s.ca
}

// Local duck-typed interfaces for CA operations.
// These break the import cycle: pkg/ca imports pkg/xkms, so this package
// cannot name the CA servicer's concrete type for these operations. The
// interfaces mirror the transport-shaped CA methods on *xkms.XKMSService,
// which the composition root wires via SetCA. This is the same delegation
// contract used by the REST and QUIC transports.

// grpcCAMethodCert retrieves the CA certificate.
type grpcCAMethodCert interface {
	GetCACertificate(ctx context.Context, req *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error)
}

// grpcCAMethodSignCSR signs a certificate signing request.
type grpcCAMethodSignCSR interface {
	SignCSR(ctx context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error)
}

// grpcCAMethodIssue issues a certificate.
type grpcCAMethodIssue interface {
	IssueCertificate(ctx context.Context, req *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error)
}

// grpcCAMethodRevoke revokes a certificate by serial number.
type grpcCAMethodRevoke interface {
	RevokeCertificate(ctx context.Context, req *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error)
}

// grpcCAMethodCRL generates a certificate revocation list.
type grpcCAMethodCRL interface {
	GenerateCRL(ctx context.Context, req *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error)
}

// grpcCAMethodIsRevoked checks if a certificate serial number is revoked.
type grpcCAMethodIsRevoked interface {
	IsRevoked(ctx context.Context, req *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error)
}

// GetCACertificate retrieves the CA certificate with metadata.
func (s *Service) GetCACertificate(ctx context.Context, req *pb.GetCACertificateRequest) (*pb.GetCACertificateResponse, error) {
	ca := s.ca
	if ca == nil {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	if err := s.authorize(ctx, auth.ResourceCerts, auth.ActionRead, ""); err != nil {
		return nil, err
	}

	certGetter, ok := ca.(grpcCAMethodCert)
	if !ok {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	resp, err := certGetter.GetCACertificate(ctx, &transport.GetCACertificateRequest{})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get CA certificate: %v", err)
	}

	return &pb.GetCACertificateResponse{
		CertificatePem: resp.CertificatePEM,
		Subject:        resp.Subject,
		Issuer:         resp.Issuer,
		SerialNumber:   resp.SerialNumber,
		NotBefore:      resp.NotBefore,
		NotAfter:       resp.NotAfter,
		IsCa:           resp.IsCA,
	}, nil
}

// SignCSR signs a certificate signing request and returns the signed certificate.
func (s *Service) SignCSR(ctx context.Context, req *pb.SignCSRRequest) (*pb.SignCSRResponse, error) {
	ca := s.ca
	if ca == nil {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	if err := s.authorize(ctx, auth.ResourceCerts, auth.ActionGenerate, ""); err != nil {
		return nil, err
	}

	if len(req.GetCsrPem()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "CSR PEM is required")
	}

	signer, ok := ca.(grpcCAMethodSignCSR)
	if !ok {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	resp, err := signer.SignCSR(ctx, &transport.SignCSRRequest{
		CSRPEM:       req.GetCsrPem(),
		Profile:      req.GetProfile(),
		ValidityDays: int(req.GetValidityDays()),
	})
	if err != nil {
		return nil, wrapWriteError(ctx, s.xkmsService, err, codes.Internal, "failed to sign CSR: %v", err)
	}

	return &pb.SignCSRResponse{
		CertificatePem: resp.CertificatePEM,
		ChainPem:       resp.ChainPEM,
		SerialNumber:   resp.SerialNumber,
	}, nil
}

// IssueCertificate issues a new certificate with the specified parameters.
func (s *Service) IssueCertificate(ctx context.Context, req *pb.IssueCertificateRequest) (*pb.IssueCertificateResponse, error) {
	ca := s.ca
	if ca == nil {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	if err := s.authorize(ctx, auth.ResourceCerts, auth.ActionGenerate, ""); err != nil {
		return nil, err
	}

	if req.GetCommonName() == "" {
		return nil, status.Error(codes.InvalidArgument, "common name is required")
	}

	issuer, ok := ca.(grpcCAMethodIssue)
	if !ok {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	resp, err := issuer.IssueCertificate(ctx, &transport.IssueCertificateRequest{
		CommonName:   req.GetCommonName(),
		Organization: req.GetOrganization(),
		SANs:         req.GetSans(),
		ValidityDays: int(req.GetValidityDays()),
		Profile:      req.GetProfile(),
		Algorithm:    req.GetAlgorithm(),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to issue certificate: %v", err)
	}

	return &pb.IssueCertificateResponse{
		CertificatePem: resp.CertificatePEM,
		ChainPem:       resp.ChainPEM,
		PrivateKeyPem:  resp.PrivateKeyPEM,
		SerialNumber:   resp.SerialNumber,
	}, nil
}

// RevokeCertificate revokes a certificate by its serial number.
func (s *Service) RevokeCertificate(ctx context.Context, req *pb.RevokeCertificateRequest) (*pb.RevokeCertificateResponse, error) {
	ca := s.ca
	if ca == nil {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	if err := s.authorize(ctx, auth.ResourceCerts, auth.ActionRevoke, ""); err != nil {
		return nil, err
	}

	if req.GetSerialNumber() == "" {
		return nil, status.Error(codes.InvalidArgument, "serial number is required")
	}

	revoker, ok := ca.(grpcCAMethodRevoke)
	if !ok {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	if _, err := parseCASerialHex(req.GetSerialNumber()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	resp, err := revoker.RevokeCertificate(ctx, &transport.RevokeCertificateRequest{
		SerialNumber: req.GetSerialNumber(),
		Reason:       int(req.GetReason()),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to revoke certificate: %v", err)
	}

	return &pb.RevokeCertificateResponse{
		Success: resp.Success,
		Message: resp.Message,
	}, nil
}

// GenerateCRL generates a certificate revocation list.
func (s *Service) GenerateCRL(ctx context.Context, req *pb.GenerateCRLRequest) (*pb.GenerateCRLResponse, error) {
	ca := s.ca
	if ca == nil {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	if err := s.authorize(ctx, auth.ResourceCerts, auth.ActionRead, ""); err != nil {
		return nil, err
	}

	generator, ok := ca.(grpcCAMethodCRL)
	if !ok {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	resp, err := generator.GenerateCRL(ctx, &transport.GenerateCRLRequest{})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate CRL: %v", err)
	}

	return &pb.GenerateCRLResponse{
		CrlPem: resp.CRLPEM,
	}, nil
}

// IsRevoked checks if a certificate has been revoked by its serial number.
func (s *Service) IsRevoked(ctx context.Context, req *pb.IsRevokedRequest) (*pb.IsRevokedResponse, error) {
	ca := s.ca
	if ca == nil {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	if err := s.authorize(ctx, auth.ResourceCerts, auth.ActionRead, ""); err != nil {
		return nil, err
	}

	if req.GetSerialNumber() == "" {
		return nil, status.Error(codes.InvalidArgument, "serial number is required")
	}

	checker, ok := ca.(grpcCAMethodIsRevoked)
	if !ok {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	if _, err := parseCASerialHex(req.GetSerialNumber()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	resp, err := checker.IsRevoked(ctx, &transport.IsRevokedRequest{
		SerialNumber: req.GetSerialNumber(),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to check revocation status: %v", err)
	}

	return &pb.IsRevokedResponse{
		Revoked: resp.Revoked,
		Message: resp.Message,
	}, nil
}

// parseCASerialHex parses a hex serial number string, stripping optional 0x/0X prefix.
func parseCASerialHex(s string) (*big.Int, error) {
	serialStr := strings.TrimPrefix(s, "0x")
	serialStr = strings.TrimPrefix(serialStr, "0X")
	serial := new(big.Int)
	if _, ok := serial.SetString(serialStr, 16); !ok {
		return nil, &errs.Detail{Err: ErrInvalidSerialNumber, Detail: s}
	}
	return serial, nil
}
