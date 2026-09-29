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

// The PIV methods delegate to the XKMSService's PIV methods: the PIV card is
// the server's own hardware, and the service's requirePlatformScope is what
// refuses a tenant-scoped caller (go-xkms#1227).

// handleListPIVSlots handles the listPIVSlots method.
func (s *Server) handleListPIVSlots(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.ListPIVSlotsRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	resp, err := s.xkmsService.ListPIVSlots(ctx, &params)
	if err != nil {
		return nil, mapPIVError(err, "failed to list PIV slots")
	}

	return resp, nil
}

// handleGetPIVCertificate handles the getPIVCertificate method.
func (s *Server) handleGetPIVCertificate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.GetPIVCertificateRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	resp, err := s.xkmsService.GetPIVCertificate(ctx, &params)
	if err != nil {
		return nil, mapPIVError(err, "failed to get PIV certificate")
	}

	return resp, nil
}

// handleStorePIVCertificate handles the storePIVCertificate method.
func (s *Server) handleStorePIVCertificate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.StorePIVCertificateRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if err := s.xkmsService.StorePIVCertificate(ctx, &params); err != nil {
		return nil, mapPIVError(err, "failed to store PIV certificate")
	}

	return map[string]string{"status": "ok"}, nil
}

// handleDeletePIVCertificate handles the deletePIVCertificate method.
func (s *Server) handleDeletePIVCertificate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.DeletePIVCertificateRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if err := s.xkmsService.DeletePIVCertificate(ctx, &params); err != nil {
		return nil, mapPIVError(err, "failed to delete PIV certificate")
	}

	return map[string]string{"status": "ok"}, nil
}

// handleGeneratePIVKey handles the generatePIVKey method.
func (s *Server) handleGeneratePIVKey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.GeneratePIVKeyRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	resp, err := s.xkmsService.GeneratePIVKey(ctx, &params)
	if err != nil {
		return nil, mapPIVError(err, "failed to generate PIV key")
	}

	return resp, nil
}

// handleImportPIVCertificate handles the importPIVCertificate method.
func (s *Server) handleImportPIVCertificate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.StorePIVCertificateRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if err := s.xkmsService.ImportPIVCertificate(ctx, &params); err != nil {
		return nil, mapPIVError(err, "failed to import PIV certificate")
	}

	return map[string]string{"status": "ok"}, nil
}

// handleExportPIVCertificate handles the exportPIVCertificate method.
func (s *Server) handleExportPIVCertificate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.GetPIVCertificateRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	resp, err := s.xkmsService.ExportPIVCertificate(ctx, &params)
	if err != nil {
		return nil, mapPIVError(err, "failed to export PIV certificate")
	}

	return resp, nil
}

// handleGeneratePIVCSR handles the generatePIVCSR method.
func (s *Server) handleGeneratePIVCSR(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.GeneratePIVCSRRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	resp, err := s.xkmsService.GeneratePIVCSR(ctx, &params)
	if err != nil {
		return nil, mapPIVError(err, "failed to generate PIV CSR")
	}

	return resp, nil
}
