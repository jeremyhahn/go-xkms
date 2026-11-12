// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

	"github.com/jeremyhahn/go-xkms/pkg/api/apierrors"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// The attestation.endorsement.*, attestation.reference_values.* and
// attestation.appraise handlers are the MCP server side of the attestation
// Verifier's appraisal API (row 1660). Each decodes its parameters -- the
// fields of the transport request -- and delegates to XKMSService, which
// binds the call to the caller's tenant; they gate on the same
// resource:action pair as the REST routes (pkg/api/rest/routes.go).

// attestationAppraisalCall decodes the params into a P, calls the service and
// maps its error through the appraisal classification.
func attestationAppraisalCall[P, R any](s *Server, ctx context.Context, req *JSONRPCRequest, op string, call func(context.Context, *P) (R, error)) (interface{}, error) {
	return servicerCall(s, ctx, req, op, mapAttestationAppraisalError, call)
}

// mapAttestationAppraisalError converts an appraisal API error into a
// *KeyOpError.
func mapAttestationAppraisalError(err error, operation string) error {
	return mapClassifiedError(err, operation, apierrors.AttestationAppraisalClassOf)
}

// handleAttestationEndorsementPut stores a trust anchor.
func (s *Server) handleAttestationEndorsementPut(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return attestationAppraisalCall(s, ctx, req, "attestation endorsement put", s.xkmsService.PutAttestationEndorsement)
}

// handleAttestationEndorsementList lists the trust anchors, optionally by kind.
func (s *Server) handleAttestationEndorsementList(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return attestationAppraisalCall(s, ctx, req, "attestation endorsement list", s.xkmsService.ListAttestationEndorsements)
}

// handleAttestationEndorsementDelete removes a trust anchor and echoes the
// request.
func (s *Server) handleAttestationEndorsementDelete(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return attestationAppraisalCall(s, ctx, req, "attestation endorsement delete", func(ctx context.Context, params *transport.DeleteAttestationEndorsementRequest) (*transport.DeleteAttestationEndorsementRequest, error) {
		if err := s.xkmsService.DeleteAttestationEndorsement(ctx, params); err != nil {
			return nil, err
		}
		return params, nil
	})
}

// handleAttestationReferenceValuesPut verifies a signed CoRIM and stores its
// reference values.
func (s *Server) handleAttestationReferenceValuesPut(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return attestationAppraisalCall(s, ctx, req, "attestation reference values put", s.xkmsService.PutAttestationReferenceValues)
}

// handleAttestationReferenceValuesGet returns stored reference values.
func (s *Server) handleAttestationReferenceValuesGet(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return attestationAppraisalCall(s, ctx, req, "attestation reference values get", s.xkmsService.GetAttestationReferenceValues)
}

// handleAttestationReferenceValuesList lists the stored reference values.
func (s *Server) handleAttestationReferenceValuesList(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return attestationAppraisalCall(s, ctx, req, "attestation reference values list", func(ctx context.Context, _ *struct{}) (*transport.ListAttestationReferenceValuesResponse, error) {
		return s.xkmsService.ListAttestationReferenceValues(ctx)
	})
}

// handleAttestationReferenceValuesDelete removes stored reference values and
// echoes the request.
func (s *Server) handleAttestationReferenceValuesDelete(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return attestationAppraisalCall(s, ctx, req, "attestation reference values delete", func(ctx context.Context, params *transport.DeleteAttestationReferenceValuesRequest) (*transport.DeleteAttestationReferenceValuesRequest, error) {
		if err := s.xkmsService.DeleteAttestationReferenceValues(ctx, params); err != nil {
			return nil, err
		}
		return params, nil
	})
}

// handleAttestationAppraise appraises a TPM quote and returns the attestation
// result.
func (s *Server) handleAttestationAppraise(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return attestationAppraisalCall(s, ctx, req, "attestation appraise", s.xkmsService.AppraiseAttestationQuote)
}
