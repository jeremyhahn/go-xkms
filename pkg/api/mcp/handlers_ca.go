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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// errXKMSServiceUnavailable classifies ErrXKMSServiceUnavailable as Service
// unavailable, mirroring pkg/api/grpc/service_ca.go's codes.Unavailable
// check for a nil CA instance: neither transport can serve a CA method when
// the CA (or, here, the whole xkms service) is not wired up.
func errXKMSServiceUnavailable() error {
	return &KeyOpError{Code: ErrCodeServiceUnavailable, Err: ErrXKMSServiceUnavailable}
}

// handleGetCABundle handles the xkms.ca.bundle method.
// It retrieves the CA certificate bundle in PEM format.
func (s *Server) handleGetCABundle(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, errXKMSServiceUnavailable()
	}

	var params transport.GetCABundleRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	resp, err := svc.GetCABundle(ctx, &params)
	if err != nil {
		return nil, mapCAError(err)
	}
	return resp, nil
}

// handleGetCACertificate handles the xkms.ca.certificate method.
// It retrieves the CA certificate with metadata (subject, issuer, serial, validity).
func (s *Server) handleGetCACertificate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, errXKMSServiceUnavailable()
	}

	var params transport.GetCACertificateRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	resp, err := svc.GetCACertificate(ctx, &params)
	if err != nil {
		return nil, mapCAError(err)
	}
	return resp, nil
}

// handleSignCSR handles the xkms.ca.sign-csr method.
// It signs a PKCS#10 certificate signing request using the CA.
func (s *Server) handleSignCSR(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, errXKMSServiceUnavailable()
	}

	var params transport.SignCSRRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	resp, err := svc.SignCSR(ctx, &params)
	if err != nil {
		return nil, mapCAError(err)
	}
	return resp, nil
}

// handleIssueCertificate handles the xkms.ca.issue method.
// It issues a new certificate from the CA with the specified profile and parameters.
func (s *Server) handleIssueCertificate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, errXKMSServiceUnavailable()
	}

	var params transport.IssueCertificateRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	resp, err := svc.IssueCertificate(ctx, &params)
	if err != nil {
		return nil, mapCAError(err)
	}
	return resp, nil
}

// handleRevokeCertificate handles the xkms.ca.revoke method.
// It revokes a certificate by serial number with an RFC 5280 reason code.
func (s *Server) handleRevokeCertificate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, errXKMSServiceUnavailable()
	}

	var params transport.RevokeCertificateRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	resp, err := svc.RevokeCertificate(ctx, &params)
	if err != nil {
		return nil, mapCAError(err)
	}
	return resp, nil
}

// handleGenerateCRL handles the xkms.ca.crl method.
// It generates a certificate revocation list (CRL) from the CA.
func (s *Server) handleGenerateCRL(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, errXKMSServiceUnavailable()
	}

	var params transport.GenerateCRLRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	resp, err := svc.GenerateCRL(ctx, &params)
	if err != nil {
		return nil, mapCAError(err)
	}
	return resp, nil
}

// handleIsRevoked handles the xkms.ca.is-revoked method.
// It checks whether a certificate has been revoked by its serial number.
func (s *Server) handleIsRevoked(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, errXKMSServiceUnavailable()
	}

	var params transport.IsRevokedRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	resp, err := svc.IsRevoked(ctx, &params)
	if err != nil {
		return nil, mapCAError(err)
	}
	return resp, nil
}
