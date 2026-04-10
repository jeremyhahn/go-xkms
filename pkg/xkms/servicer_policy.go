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

package xkms

import (
	"context"
	"encoding/hex"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/seal/policy"
)

// PolicyServicer defines operations for managing PCR policies.
type PolicyServicer interface {
	PolicyCreate(ctx context.Context, req *transport.PolicyCreateRequest) (*transport.PolicyCreateResponse, error)
	PolicyGet(ctx context.Context, req *transport.PolicyGetRequest) (*transport.PolicyGetResponse, error)
	PolicyList(ctx context.Context) (*transport.PolicyListResponse, error)
	PolicyDelete(ctx context.Context, req *transport.PolicyDeleteRequest) error
	PolicyRefresh(ctx context.Context, req *transport.PolicyRefreshRequest) (*transport.PolicyGetResponse, error)
	PolicyVerify(ctx context.Context, req *transport.PolicyVerifyRequest) (*transport.PolicyVerifyResponse, error)
	PolicyExport(ctx context.Context, req *transport.PolicyExportRequest) (*transport.PolicyExportResponse, error)
}

// PolicyCreate creates a new PCR policy with the specified parameters.
func (s *XKMSService) PolicyCreate(ctx context.Context, req *transport.PolicyCreateRequest) (*transport.PolicyCreateResponse, error) {
	if s.policyManager == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	def, err := s.policyManager.CreatePolicy(req.Name, req.Bank, req.PCRs)
	if err != nil {
		return nil, err
	}
	return &transport.PolicyCreateResponse{
		Name:      def.Name,
		Bank:      def.Bank,
		PCRs:      def.PCRIndices,
		Values:    pcrValuesToHex(def.PCRValues),
		CreatedAt: def.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}, nil
}

// PolicyGet retrieves a PCR policy by name.
func (s *XKMSService) PolicyGet(ctx context.Context, req *transport.PolicyGetRequest) (*transport.PolicyGetResponse, error) {
	if s.policyManager == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	def, err := s.policyManager.GetPolicy(req.Name)
	if err != nil {
		return nil, err
	}
	return policyDefToGetResponse(def), nil
}

// PolicyList returns all registered PCR policies.
func (s *XKMSService) PolicyList(ctx context.Context) (*transport.PolicyListResponse, error) {
	if s.policyManager == nil {
		return nil, ErrNotConfigured
	}
	defs, err := s.policyManager.ListPolicies()
	if err != nil {
		return nil, err
	}
	policies := make([]transport.PolicyGetResponse, 0, len(defs))
	for _, def := range defs {
		policies = append(policies, *policyDefToGetResponse(def))
	}
	return &transport.PolicyListResponse{
		Policies:     policies,
		PageResponse: transport.PageResponse{Total: len(policies)},
	}, nil
}

// PolicyDelete deletes a PCR policy by name.
func (s *XKMSService) PolicyDelete(ctx context.Context, req *transport.PolicyDeleteRequest) error {
	if s.policyManager == nil {
		return ErrNotConfigured
	}
	if req == nil {
		return ErrNilRequest
	}
	return s.policyManager.DeletePolicy(req.Name)
}

// PolicyRefresh refreshes a PCR policy with current PCR values.
func (s *XKMSService) PolicyRefresh(ctx context.Context, req *transport.PolicyRefreshRequest) (*transport.PolicyGetResponse, error) {
	if s.policyManager == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	def, err := s.policyManager.RefreshPolicy(req.Name)
	if err != nil {
		return nil, err
	}
	return policyDefToGetResponse(def), nil
}

// PolicyVerify verifies that current PCR values match the policy.
func (s *XKMSService) PolicyVerify(ctx context.Context, req *transport.PolicyVerifyRequest) (*transport.PolicyVerifyResponse, error) {
	if s.policyManager == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	valid, message, err := s.policyManager.VerifyPolicy(req.Name)
	if err != nil {
		return nil, err
	}
	return &transport.PolicyVerifyResponse{
		Name:    req.Name,
		Valid:   valid,
		Message: message,
	}, nil
}

// PolicyExport exports a PCR policy for external use.
func (s *XKMSService) PolicyExport(ctx context.Context, req *transport.PolicyExportRequest) (*transport.PolicyExportResponse, error) {
	if s.policyManager == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	data, err := s.policyManager.ExportPolicy(req.Name)
	if err != nil {
		return nil, err
	}
	return &transport.PolicyExportResponse{
		Data: data,
	}, nil
}

// pcrValuesToHex converts PCR values from map[int][]byte to map[int]string
// using hex encoding for transport.
func pcrValuesToHex(values map[int][]byte) map[int]string {
	result := make(map[int]string, len(values))
	for idx, val := range values {
		result[idx] = hex.EncodeToString(val)
	}
	return result
}

// policyDefToGetResponse converts a PolicyDefinition to a transport PolicyGetResponse.
func policyDefToGetResponse(def *policy.PolicyDefinition) *transport.PolicyGetResponse {
	return &transport.PolicyGetResponse{
		Name:      def.Name,
		Bank:      def.Bank,
		PCRs:      def.PCRIndices,
		Values:    pcrValuesToHex(def.PCRValues),
		CreatedAt: def.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt: def.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
}
