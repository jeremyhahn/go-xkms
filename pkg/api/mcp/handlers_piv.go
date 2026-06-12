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
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// handleListPIVSlots handles the listPIVSlots method.
func (s *Server) handleListPIVSlots(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.ListPIVSlotsRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	resp, err := xkms.ListPIVSlots(ctx, &params)
	if err != nil {
		return nil, fmt.Errorf("failed to list PIV slots: %w", err)
	}

	return resp, nil
}

// handleGetPIVCertificate handles the getPIVCertificate method.
func (s *Server) handleGetPIVCertificate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.GetPIVCertificateRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	resp, err := xkms.GetPIVCertificate(ctx, &params)
	if err != nil {
		return nil, fmt.Errorf("failed to get PIV certificate: %w", err)
	}

	return resp, nil
}

// handleStorePIVCertificate handles the storePIVCertificate method.
func (s *Server) handleStorePIVCertificate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.StorePIVCertificateRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if err := xkms.StorePIVCertificate(ctx, &params); err != nil {
		return nil, fmt.Errorf("failed to store PIV certificate: %w", err)
	}

	return map[string]string{"status": "ok"}, nil
}

// handleDeletePIVCertificate handles the deletePIVCertificate method.
func (s *Server) handleDeletePIVCertificate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.DeletePIVCertificateRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if err := xkms.DeletePIVCertificate(ctx, &params); err != nil {
		return nil, fmt.Errorf("failed to delete PIV certificate: %w", err)
	}

	return map[string]string{"status": "ok"}, nil
}

// handleGeneratePIVKey handles the generatePIVKey method.
func (s *Server) handleGeneratePIVKey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.GeneratePIVKeyRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	resp, err := xkms.GeneratePIVKey(ctx, &params)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PIV key: %w", err)
	}

	return resp, nil
}

// handleImportPIVCertificate handles the importPIVCertificate method.
func (s *Server) handleImportPIVCertificate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.StorePIVCertificateRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if err := xkms.ImportPIVCertificate(ctx, &params); err != nil {
		return nil, fmt.Errorf("failed to import PIV certificate: %w", err)
	}

	return map[string]string{"status": "ok"}, nil
}

// handleExportPIVCertificate handles the exportPIVCertificate method.
func (s *Server) handleExportPIVCertificate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.GetPIVCertificateRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	resp, err := xkms.ExportPIVCertificate(ctx, &params)
	if err != nil {
		return nil, fmt.Errorf("failed to export PIV certificate: %w", err)
	}

	return resp, nil
}

// handleGeneratePIVCSR handles the generatePIVCSR method.
func (s *Server) handleGeneratePIVCSR(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.GeneratePIVCSRRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	resp, err := xkms.GeneratePIVCSR(ctx, &params)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PIV CSR: %w", err)
	}

	return resp, nil
}
