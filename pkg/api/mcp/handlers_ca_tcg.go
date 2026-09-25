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

// handleIssueEKCertificate handles the xkms.ca.tcg.issue-ek method.
// It issues an Endorsement Key certificate for a TPM device.
func (s *Server) handleIssueEKCertificate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, errXKMSServiceUnavailable()
	}

	var params transport.IssueEKCertificateRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	resp, err := svc.IssueEKCertificate(ctx, &params)
	if err != nil {
		return nil, mapCAError(err)
	}
	return resp, nil
}

// handleIssueAKCertificate handles the xkms.ca.tcg.issue-ak method.
// It issues an Attestation Key certificate for a TPM device.
func (s *Server) handleIssueAKCertificate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, errXKMSServiceUnavailable()
	}

	var params transport.IssueAKCertificateRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	resp, err := svc.IssueAKCertificate(ctx, &params)
	if err != nil {
		return nil, mapCAError(err)
	}
	return resp, nil
}

// handleSignTCGCSR handles the xkms.ca.tcg.sign-csr method.
// It signs a TCG-CSR-IDEVID and returns IAK and IDevID certificates.
func (s *Server) handleSignTCGCSR(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, errXKMSServiceUnavailable()
	}

	var params transport.SignTCGCSRRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	resp, err := svc.SignTCGCSR(ctx, &params)
	if err != nil {
		return nil, mapCAError(err)
	}
	return resp, nil
}

// handleEnrollDevice handles the xkms.ca.tcg.enroll method.
// It performs full TCG device enrollment with credential activation challenge.
func (s *Server) handleEnrollDevice(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, errXKMSServiceUnavailable()
	}

	var params transport.EnrollDeviceRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	resp, err := svc.EnrollDevice(ctx, &params)
	if err != nil {
		return nil, mapCAError(err)
	}
	return resp, nil
}
