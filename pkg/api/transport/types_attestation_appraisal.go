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

// AttestationAppraisalService is the attestation Verifier (go-xkms#1660): it
// manages a tenant's trust anchors and reference values and appraises TPM
// quotes against them. Every call acts on the caller's tenant. The REST and
// embedded transports serve it; the other transports do not yet, so it is
// not part of Client.
type AttestationAppraisalService interface {
	// PutAttestationEndorsement stores a trust anchor.
	// Permission: attestation_endorsements:create.
	PutAttestationEndorsement(ctx context.Context, req *PutAttestationEndorsementRequest) (*AttestationEndorsement, error)

	// ListAttestationEndorsements lists the trust anchors, optionally by kind.
	// Permission: attestation_endorsements:list.
	ListAttestationEndorsements(ctx context.Context, req *ListAttestationEndorsementsRequest) (*ListAttestationEndorsementsResponse, error)

	// DeleteAttestationEndorsement removes a trust anchor.
	// Permission: attestation_endorsements:delete.
	DeleteAttestationEndorsement(ctx context.Context, req *DeleteAttestationEndorsementRequest) error

	// PutAttestationReferenceValues verifies a signed CoRIM and stores its
	// reference values. Permission: attestation_reference_values:create.
	PutAttestationReferenceValues(ctx context.Context, req *PutAttestationReferenceValuesRequest) (*AttestationReferenceValues, error)

	// GetAttestationReferenceValues returns stored reference values.
	// Permission: attestation_reference_values:get.
	GetAttestationReferenceValues(ctx context.Context, req *GetAttestationReferenceValuesRequest) (*AttestationReferenceValues, error)

	// ListAttestationReferenceValues lists the stored reference values.
	// Permission: attestation_reference_values:list.
	ListAttestationReferenceValues(ctx context.Context) (*ListAttestationReferenceValuesResponse, error)

	// DeleteAttestationReferenceValues removes stored reference values.
	// Permission: attestation_reference_values:delete.
	DeleteAttestationReferenceValues(ctx context.Context, req *DeleteAttestationReferenceValuesRequest) error

	// AppraiseAttestationQuote appraises a TPM quote and returns the
	// attestation result. Permission: attestation_verifier:verify.
	AppraiseAttestationQuote(ctx context.Context, req *AppraiseAttestationQuoteRequest) (*AttestationResult, error)
}

// AttestationAppraisalServicer is the server side of
// AttestationAppraisalService.
type AttestationAppraisalServicer interface {
	AttestationAppraisalService
}

// The appraisal request and response types are aliases of the appraisal
// package's, so every transport carries the one definition.
type (
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
)
