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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

// Package-level CA instance, set via SetCA and protected by a read-write mutex.
var (
	caInstanceMu sync.RWMutex
	caInstance   any
)

// SetCA configures the Certificate Authority for the gRPC service.
// This must be called before any CA RPCs can be used.
func SetCA(ca any) {
	caInstanceMu.Lock()
	defer caInstanceMu.Unlock()
	caInstance = ca
}

// GetCA returns the configured CA instance, or nil if not set.
func GetCA() any {
	caInstanceMu.RLock()
	defer caInstanceMu.RUnlock()
	return caInstance
}

// getCAInstance returns the CA instance or nil. Caller must handle nil.
func getCAInstance() any {
	caInstanceMu.RLock()
	defer caInstanceMu.RUnlock()
	return caInstance
}

// Local duck-typed interfaces for CA operations.
// These break the import cycle: pkg/ca imports pkg/xkms, so this package
// cannot import pkg/ca. Instead, we define minimal interfaces using only
// stdlib types. The concrete ca.CA type satisfies these via duck typing.

// grpcCAMethodCert retrieves the CA certificate.
type grpcCAMethodCert interface {
	CACertificate() (*x509.Certificate, error)
}

// grpcCAMethodSignCSR signs a CSR using raw parameters.
type grpcCAMethodSignCSR interface {
	SignCSRRaw(csrPEM []byte, profile string, validityDays int) (*x509.Certificate, error)
}

// grpcCAMethodIssue issues a certificate using raw parameters.
type grpcCAMethodIssue interface {
	IssueCertificateRaw(
		commonName, organization string,
		sans []string,
		validityDays int,
		profile, algorithm string,
	) (certPEM, chainPEM, keyPEM []byte, serialHex string, err error)
}

// grpcCAMethodRevoke revokes a certificate by serial number.
type grpcCAMethodRevoke interface {
	Revoke(serial *big.Int, reason int) error
}

// grpcCAMethodCRL generates a certificate revocation list.
type grpcCAMethodCRL interface {
	GenerateCRL() ([]byte, error)
}

// grpcCAMethodIsRevoked checks if a certificate serial number is revoked.
type grpcCAMethodIsRevoked interface {
	IsRevoked(serial *big.Int) (bool, error)
}

// GetCACertificate retrieves the CA certificate with metadata.
func (s *Service) GetCACertificate(ctx context.Context, req *pb.GetCACertificateRequest) (*pb.GetCACertificateResponse, error) {
	ca := getCAInstance()
	if ca == nil {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	if err := s.authorize(ctx, "ca", "read", ""); err != nil {
		return nil, err
	}

	certGetter, ok := ca.(grpcCAMethodCert)
	if !ok {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	cert, err := certGetter.CACertificate()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get CA certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	return &pb.GetCACertificateResponse{
		CertificatePem: certPEM,
		Subject:        cert.Subject.String(),
		Issuer:         cert.Issuer.String(),
		SerialNumber:   cert.SerialNumber.Text(16),
		NotBefore:      cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		NotAfter:       cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		IsCa:           cert.IsCA,
	}, nil
}

// SignCSR signs a certificate signing request and returns the signed certificate.
func (s *Service) SignCSR(ctx context.Context, req *pb.SignCSRRequest) (*pb.SignCSRResponse, error) {
	ca := getCAInstance()
	if ca == nil {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	if err := s.authorize(ctx, "ca", "write", ""); err != nil {
		return nil, err
	}

	if len(req.GetCsrPem()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "CSR PEM is required")
	}

	signer, ok := ca.(grpcCAMethodSignCSR)
	if !ok {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	cert, err := signer.SignCSRRaw(req.GetCsrPem(), req.GetProfile(), int(req.GetValidityDays()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to sign CSR: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// Attempt to get the CA certificate for the chain.
	var chainPEM []byte
	if certGetter, ok := ca.(grpcCAMethodCert); ok {
		if caCert, caErr := certGetter.CACertificate(); caErr == nil {
			chainPEM = pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: caCert.Raw,
			})
		}
	}

	return &pb.SignCSRResponse{
		CertificatePem: certPEM,
		ChainPem:       chainPEM,
		SerialNumber:   cert.SerialNumber.Text(16),
	}, nil
}

// IssueCertificate issues a new certificate with the specified parameters.
func (s *Service) IssueCertificate(ctx context.Context, req *pb.IssueCertificateRequest) (*pb.IssueCertificateResponse, error) {
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

	issuer, ok := ca.(grpcCAMethodIssue)
	if !ok {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	certPEM, chainPEM, keyPEM, serialHex, err := issuer.IssueCertificateRaw(
		req.GetCommonName(),
		req.GetOrganization(),
		req.GetSans(),
		int(req.GetValidityDays()),
		req.GetProfile(),
		req.GetAlgorithm(),
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to issue certificate: %v", err)
	}

	return &pb.IssueCertificateResponse{
		CertificatePem: certPEM,
		ChainPem:       chainPEM,
		PrivateKeyPem:  keyPEM,
		SerialNumber:   serialHex,
	}, nil
}

// RevokeCertificate revokes a certificate by its serial number.
func (s *Service) RevokeCertificate(ctx context.Context, req *pb.RevokeCertificateRequest) (*pb.RevokeCertificateResponse, error) {
	ca := getCAInstance()
	if ca == nil {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	if err := s.authorize(ctx, "ca", "write", ""); err != nil {
		return nil, err
	}

	if req.GetSerialNumber() == "" {
		return nil, status.Error(codes.InvalidArgument, "serial number is required")
	}

	revoker, ok := ca.(grpcCAMethodRevoke)
	if !ok {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	serial, err := parseCASerialHex(req.GetSerialNumber())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	if err := revoker.Revoke(serial, int(req.GetReason())); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to revoke certificate: %v", err)
	}

	return &pb.RevokeCertificateResponse{
		Success: true,
		Message: fmt.Sprintf("certificate %s revoked", req.GetSerialNumber()),
	}, nil
}

// GenerateCRL generates a certificate revocation list.
func (s *Service) GenerateCRL(ctx context.Context, req *pb.GenerateCRLRequest) (*pb.GenerateCRLResponse, error) {
	ca := getCAInstance()
	if ca == nil {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	if err := s.authorize(ctx, "ca", "read", ""); err != nil {
		return nil, err
	}

	generator, ok := ca.(grpcCAMethodCRL)
	if !ok {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	crlDER, err := generator.GenerateCRL()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate CRL: %v", err)
	}

	crlPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	})

	return &pb.GenerateCRLResponse{
		CrlPem: crlPEM,
	}, nil
}

// IsRevoked checks if a certificate has been revoked by its serial number.
func (s *Service) IsRevoked(ctx context.Context, req *pb.IsRevokedRequest) (*pb.IsRevokedResponse, error) {
	ca := getCAInstance()
	if ca == nil {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	if err := s.authorize(ctx, "ca", "read", ""); err != nil {
		return nil, err
	}

	if req.GetSerialNumber() == "" {
		return nil, status.Error(codes.InvalidArgument, "serial number is required")
	}

	checker, ok := ca.(grpcCAMethodIsRevoked)
	if !ok {
		return nil, status.Error(codes.Unavailable, ErrCANotConfigured.Error())
	}

	serial, err := parseCASerialHex(req.GetSerialNumber())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	revoked, err := checker.IsRevoked(serial)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to check revocation status: %v", err)
	}

	resp := &pb.IsRevokedResponse{
		Revoked: revoked,
	}
	if revoked {
		resp.Message = "certificate is revoked"
	} else {
		resp.Message = "certificate is not revoked"
	}

	return resp, nil
}

// parseCASerialHex parses a hex serial number string, stripping optional 0x/0X prefix.
func parseCASerialHex(s string) (*big.Int, error) {
	serialStr := strings.TrimPrefix(s, "0x")
	serialStr = strings.TrimPrefix(serialStr, "0X")
	serial := new(big.Int)
	if _, ok := serial.SetString(serialStr, 16); !ok {
		return nil, fmt.Errorf("%w: %s", ErrInvalidSerialNumber, s)
	}
	return serial, nil
}
