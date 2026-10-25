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
// attestation.quote.appraise handlers are the MCP server side of the
// attestation Verifier API (go-xkms#1608). Each decodes its parameters --
// the fields of the transport request -- and delegates to XKMSService, which
// binds the call to the caller's tenant; they gate on the
// attestation_endorsements:*, attestation_reference_values:* and
// attestation_verifier:verify pairs in server.go's rpcMethods table.

// appraisalCall decodes a P from req and runs call with it, mapping its
// error through the Verifier classification.
func appraisalCall[P, R any](s *Server, ctx context.Context, req *JSONRPCRequest, op string, call func(context.Context, *P) (R, error)) (interface{}, error) {
	return servicerCall(s, ctx, req, op, mapAppraisalError, call)
}

// mapAppraisalError converts a Verifier API error into a *KeyOpError
// through apierrors.AttestationAppraisalClassOf.
func mapAppraisalError(err error, operation string) error {
	return mapClassifiedError(err, operation, apierrors.AttestationAppraisalClassOf)
}

// handleEndorsementPut handles attestation.endorsement.put.
func (s *Server) handleEndorsementPut(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return appraisalCall(s, ctx, req, "endorsement put", s.xkmsService.PutAttestationEndorsement)
}

// handleEndorsementList handles attestation.endorsement.list.
func (s *Server) handleEndorsementList(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return appraisalCall(s, ctx, req, "endorsement list", s.xkmsService.ListAttestationEndorsements)
}

// handleEndorsementDelete handles attestation.endorsement.delete, answering
// with the request it removed.
func (s *Server) handleEndorsementDelete(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return appraisalCall(s, ctx, req, "endorsement delete", func(ctx context.Context, params *transport.DeleteAttestationEndorsementRequest) (*transport.DeleteAttestationEndorsementRequest, error) {
		if err := s.xkmsService.DeleteAttestationEndorsement(ctx, params); err != nil {
			return nil, err
		}
		return params, nil
	})
}

// handleReferenceValuesPut handles attestation.reference_values.put.
func (s *Server) handleReferenceValuesPut(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return appraisalCall(s, ctx, req, "reference values put", s.xkmsService.PutAttestationReferenceValues)
}

// handleReferenceValuesGet handles attestation.reference_values.get.
func (s *Server) handleReferenceValuesGet(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return appraisalCall(s, ctx, req, "reference values get", s.xkmsService.GetAttestationReferenceValues)
}

// handleReferenceValuesList handles attestation.reference_values.list, which
// takes no parameters.
func (s *Server) handleReferenceValuesList(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return appraisalCall(s, ctx, req, "reference values list", func(ctx context.Context, _ *struct{}) (*transport.ListAttestationReferenceValuesResponse, error) {
		return s.xkmsService.ListAttestationReferenceValues(ctx)
	})
}

// handleReferenceValuesDelete handles attestation.reference_values.delete,
// answering with the request it removed.
func (s *Server) handleReferenceValuesDelete(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return appraisalCall(s, ctx, req, "reference values delete", func(ctx context.Context, params *transport.DeleteAttestationReferenceValuesRequest) (*transport.DeleteAttestationReferenceValuesRequest, error) {
		if err := s.xkmsService.DeleteAttestationReferenceValues(ctx, params); err != nil {
			return nil, err
		}
		return params, nil
	})
}

// handleQuoteAppraise handles attestation.quote.appraise.
func (s *Server) handleQuoteAppraise(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return appraisalCall(s, ctx, req, "quote appraise", s.xkmsService.AppraiseAttestationQuote)
}
