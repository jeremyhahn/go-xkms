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
	"encoding/json"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// handleGetCABundle handles the xkms.ca.bundle method.
// It retrieves the CA certificate bundle in PEM format.
func (s *Server) handleGetCABundle(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := xkms.Get()
	if err != nil {
		return nil, ErrXKMSServiceUnavailable
	}

	var params transport.GetCABundleRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, err
	}

	return svc.GetCABundle(ctx, &params)
}

// handleGetCACertificate handles the xkms.ca.certificate method.
// It retrieves the CA certificate with metadata (subject, issuer, serial, validity).
func (s *Server) handleGetCACertificate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := xkms.Get()
	if err != nil {
		return nil, ErrXKMSServiceUnavailable
	}

	var params transport.GetCACertificateRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, err
	}

	return svc.GetCACertificate(ctx, &params)
}

// handleSignCSR handles the xkms.ca.sign-csr method.
// It signs a PKCS#10 certificate signing request using the CA.
func (s *Server) handleSignCSR(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := xkms.Get()
	if err != nil {
		return nil, ErrXKMSServiceUnavailable
	}

	var params transport.SignCSRRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, err
	}

	return svc.SignCSR(ctx, &params)
}

// handleIssueCertificate handles the xkms.ca.issue method.
// It issues a new certificate from the CA with the specified profile and parameters.
func (s *Server) handleIssueCertificate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := xkms.Get()
	if err != nil {
		return nil, ErrXKMSServiceUnavailable
	}

	var params transport.IssueCertificateRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, err
	}

	return svc.IssueCertificate(ctx, &params)
}

// handleRevokeCertificate handles the xkms.ca.revoke method.
// It revokes a certificate by serial number with an RFC 5280 reason code.
func (s *Server) handleRevokeCertificate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := xkms.Get()
	if err != nil {
		return nil, ErrXKMSServiceUnavailable
	}

	var params transport.RevokeCertificateRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, err
	}

	return svc.RevokeCertificate(ctx, &params)
}

// handleGenerateCRL handles the xkms.ca.crl method.
// It generates a certificate revocation list (CRL) from the CA.
func (s *Server) handleGenerateCRL(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := xkms.Get()
	if err != nil {
		return nil, ErrXKMSServiceUnavailable
	}

	var params transport.GenerateCRLRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, err
	}

	return svc.GenerateCRL(ctx, &params)
}

// handleIsRevoked handles the xkms.ca.is-revoked method.
// It checks whether a certificate has been revoked by its serial number.
func (s *Server) handleIsRevoked(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := xkms.Get()
	if err != nil {
		return nil, ErrXKMSServiceUnavailable
	}

	var params transport.IsRevokedRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, err
	}

	return svc.IsRevoked(ctx, &params)
}
