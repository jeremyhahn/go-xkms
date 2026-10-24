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

package xkms

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
)

// The attestation Verifier service layer. Each method appraises or manages
// the reference material of the caller's tenant (callerTenant) and delegates
// to the wired appraisal.Appraiser, which validates the request and returns
// its typed errors. Every method returns ErrNotConfigured when no Appraiser
// is wired. The permission each operation requires is named on the method;
// the wire layers enforce it before calling in.

// SetAttestationAppraiser wires the Appraiser the Verifier methods delegate
// to. A server without a Verifier wires none, and every method returns
// ErrNotConfigured.
func (s *XKMSService) SetAttestationAppraiser(a *appraisal.Appraiser) { s.appraiser.store(a) }

// AttestationAppraiser returns the wired Appraiser, or nil when none is wired.
func (s *XKMSService) AttestationAppraiser() *appraisal.Appraiser { return s.appraiser.load() }

// attestationAppraiser returns the wired Appraiser and the caller's tenant,
// or ErrNotConfigured when no Appraiser is wired.
func (s *XKMSService) attestationAppraiser(ctx context.Context) (*appraisal.Appraiser, string, error) {
	appraiser := s.appraiser.load()
	if appraiser == nil {
		return nil, "", ErrNotConfigured
	}
	return appraiser, callerTenant(ctx), nil
}

// PutAttestationEndorsement stores a trust anchor (an attestation-key root or
// a reference-value signer) for the caller's tenant.
//
// Permission: attestation_endorsements:create.
func (s *XKMSService) PutAttestationEndorsement(ctx context.Context, req *appraisal.PutEndorsementRequest) (*appraisal.Endorsement, error) {
	appraiser, tenant, err := s.attestationAppraiser(ctx)
	if err != nil {
		return nil, err
	}
	return appraiser.PutEndorsement(ctx, tenant, req)
}

// ListAttestationEndorsements lists the caller's tenant's trust anchors,
// optionally filtered by kind.
//
// Permission: attestation_endorsements:list.
func (s *XKMSService) ListAttestationEndorsements(ctx context.Context, req *appraisal.ListEndorsementsRequest) (*appraisal.ListEndorsementsResponse, error) {
	appraiser, tenant, err := s.attestationAppraiser(ctx)
	if err != nil {
		return nil, err
	}
	return appraiser.ListEndorsements(ctx, tenant, req)
}

// DeleteAttestationEndorsement removes one of the caller's tenant's trust
// anchors.
//
// Permission: attestation_endorsements:delete.
func (s *XKMSService) DeleteAttestationEndorsement(ctx context.Context, req *appraisal.DeleteEndorsementRequest) error {
	appraiser, tenant, err := s.attestationAppraiser(ctx)
	if err != nil {
		return err
	}
	return appraiser.DeleteEndorsement(ctx, tenant, req)
}

// PutAttestationReferenceValues verifies a signed CoRIM against the caller's
// tenant's reference-value signers and stores its reference values.
//
// Permission: attestation_reference_values:create.
func (s *XKMSService) PutAttestationReferenceValues(ctx context.Context, req *appraisal.PutReferenceValuesRequest) (*appraisal.ReferenceValues, error) {
	appraiser, tenant, err := s.attestationAppraiser(ctx)
	if err != nil {
		return nil, err
	}
	return appraiser.PutReferenceValues(ctx, tenant, req)
}

// GetAttestationReferenceValues returns one of the caller's tenant's stored
// reference values.
//
// Permission: attestation_reference_values:get.
func (s *XKMSService) GetAttestationReferenceValues(ctx context.Context, req *appraisal.GetReferenceValuesRequest) (*appraisal.ReferenceValues, error) {
	appraiser, tenant, err := s.attestationAppraiser(ctx)
	if err != nil {
		return nil, err
	}
	return appraiser.GetReferenceValues(ctx, tenant, req)
}

// ListAttestationReferenceValues lists the caller's tenant's stored reference
// values.
//
// Permission: attestation_reference_values:list.
func (s *XKMSService) ListAttestationReferenceValues(ctx context.Context) (*appraisal.ListReferenceValuesResponse, error) {
	appraiser, tenant, err := s.attestationAppraiser(ctx)
	if err != nil {
		return nil, err
	}
	return appraiser.ListReferenceValues(ctx, tenant)
}

// DeleteAttestationReferenceValues removes one of the caller's tenant's
// stored reference values.
//
// Permission: attestation_reference_values:delete.
func (s *XKMSService) DeleteAttestationReferenceValues(ctx context.Context, req *appraisal.DeleteReferenceValuesRequest) error {
	appraiser, tenant, err := s.attestationAppraiser(ctx)
	if err != nil {
		return err
	}
	return appraiser.DeleteReferenceValues(ctx, tenant, req)
}

// AppraiseAttestationQuote appraises a TPM quote against the caller's
// tenant's endorsements and named reference values, returning an attestation
// result.
//
// Permission: attestation_verifier:verify.
func (s *XKMSService) AppraiseAttestationQuote(ctx context.Context, req *appraisal.AppraiseQuoteRequest) (*appraisal.AttestationResult, error) {
	appraiser, tenant, err := s.attestationAppraiser(ctx)
	if err != nil {
		return nil, err
	}
	return appraiser.AppraiseQuote(ctx, tenant, req)
}
