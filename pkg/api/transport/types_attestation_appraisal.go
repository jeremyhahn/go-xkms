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

package transport

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
)

// AttestationAppraisalService is the attestation Verifier (go-xkms#1608):
// the store of trust anchors (endorsements) and signed reference values, and
// the appraisal of TPM quote evidence against them. Every method acts on the
// caller's tenant.
type AttestationAppraisalService interface {
	// PutAttestationEndorsement stores a trust anchor.
	// Permission: attestation_endorsements:create.
	PutAttestationEndorsement(ctx context.Context, req *PutAttestationEndorsementRequest) (*AttestationEndorsement, error)

	// ListAttestationEndorsements lists trust anchors, optionally by kind.
	// Permission: attestation_endorsements:list.
	ListAttestationEndorsements(ctx context.Context, req *ListAttestationEndorsementsRequest) (*ListAttestationEndorsementsResponse, error)

	// DeleteAttestationEndorsement removes a trust anchor.
	// Permission: attestation_endorsements:delete.
	DeleteAttestationEndorsement(ctx context.Context, req *DeleteAttestationEndorsementRequest) error

	// PutAttestationReferenceValues verifies and stores a signed CoRIM.
	// Permission: attestation_reference_values:create.
	PutAttestationReferenceValues(ctx context.Context, req *PutAttestationReferenceValuesRequest) (*AttestationReferenceValues, error)

	// GetAttestationReferenceValues returns stored reference values.
	// Permission: attestation_reference_values:get.
	GetAttestationReferenceValues(ctx context.Context, req *GetAttestationReferenceValuesRequest) (*AttestationReferenceValues, error)

	// ListAttestationReferenceValues lists stored reference values.
	// Permission: attestation_reference_values:list.
	ListAttestationReferenceValues(ctx context.Context) (*ListAttestationReferenceValuesResponse, error)

	// DeleteAttestationReferenceValues removes stored reference values.
	// Permission: attestation_reference_values:delete.
	DeleteAttestationReferenceValues(ctx context.Context, req *DeleteAttestationReferenceValuesRequest) error

	// AppraiseAttestationQuote appraises TPM quote evidence and returns the
	// attestation result. Permission: attestation_verifier:verify.
	AppraiseAttestationQuote(ctx context.Context, req *AppraiseAttestationQuoteRequest) (*AttestationResult, error)
}

// AttestationAppraisalServicer is the server side of
// AttestationAppraisalService.
type AttestationAppraisalServicer interface {
	AttestationAppraisalService
}

// The appraisal request and response types are aliases of the appraisal
// domain types, which carry the JSON tags, as types_signing_key.go does.
type (
	AttestationEndorsementKind              = appraisal.EndorsementKind
	AttestationEndorsement                  = appraisal.Endorsement
	PutAttestationEndorsementRequest        = appraisal.PutEndorsementRequest
	ListAttestationEndorsementsRequest      = appraisal.ListEndorsementsRequest
	ListAttestationEndorsementsResponse     = appraisal.ListEndorsementsResponse
	DeleteAttestationEndorsementRequest     = appraisal.DeleteEndorsementRequest
	AttestationReferenceValues              = appraisal.ReferenceValues
	PutAttestationReferenceValuesRequest    = appraisal.PutReferenceValuesRequest
	GetAttestationReferenceValuesRequest    = appraisal.GetReferenceValuesRequest
	ListAttestationReferenceValuesResponse  = appraisal.ListReferenceValuesResponse
	DeleteAttestationReferenceValuesRequest = appraisal.DeleteReferenceValuesRequest
	AppraiseAttestationQuoteRequest         = appraisal.AppraiseQuoteRequest
	AttestationResult                       = appraisal.AttestationResult
	AttestationAppraisalCheck               = appraisal.AppraisalCheck
	AttestationAppraisalOutcome             = appraisal.AppraisalOutcome
)
