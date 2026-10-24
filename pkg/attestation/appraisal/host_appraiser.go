// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-quicbaas.
//
// go-quicbaas is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package service

import (
	"context"
	"crypto"
	"encoding/pem"
	stderrors "errors"
	"slices"
	"time"

	"github.com/jeremyhahn/go-quicbaas/pkg/errors"
	"github.com/jeremyhahn/go-quicbaas/pkg/orchestration"
)

var (
	// ErrHostAppraiserNoStore is returned by NewHostAppraiser when no
	// attestation store is supplied: without one there are no reference
	// values to appraise against.
	ErrHostAppraiserNoStore = &errors.QBError{Code: errors.ErrInvalidInput, Op: "service.NewHostAppraiser", Err: errHostAppraiserNoStore}

	errHostAppraiserNoStore = stderrors.New("an attestation store is required")
)

// hostAppraiser is the Verifier seen through orchestration's HostAppraiser
// seam: a TPMAttestingRuntime collects and binds the host evidence, and the
// Verifier appraises it against signed reference values.
type hostAppraiser struct {
	svc *attestationService
}

// NewHostAppraiser returns the Verifier over store as an
// orchestration.HostAppraiser, for NewTPMAttestingRuntime. store must hold
// the tenant's ak-root and reference-signer endorsements and the reference
// values a ContainerSpec names; pass the same store the server's Verifier
// uses so the records an operator stores are the ones appraised against.
func NewHostAppraiser(store AttestationStore, opts ...AttestationOption) (orchestration.HostAppraiser, error) {
	if store == nil {
		return nil, ErrHostAppraiserNoStore
	}
	svc := &attestationService{now: time.Now}
	for _, opt := range opts {
		opt(svc)
	}
	svc.store = store
	return &hostAppraiser{svc: svc}, nil
}

// ReferencePCRs returns the PCR indices the named reference values cover in
// bank, ascending. The signed CoRIM is verified again, as appraisal does, so
// the registers to quote come from values a reference signer still endorses.
// Digests in other banks are not counted: the baseline compares in the
// quoted bank only.
func (a *hostAppraiser) ReferencePCRs(ctx context.Context, name string, bank crypto.Hash) ([]uint32, error) {
	const op = "HostAppraiser.ReferencePCRs"
	record, err := a.svc.GetReferenceValues(ctx, &GetReferenceValuesRequest{Name: name})
	if err != nil {
		return nil, err
	}
	store, err := a.svc.verifierStore(op)
	if err != nil {
		return nil, err
	}
	manifest, err := a.svc.verifyCoRIM(ctx, store, record.SignedCoRIM)
	if err != nil {
		return nil, verifierError(op, errors.ErrInvalidInput, err)
	}
	var digests map[int][][]byte
	if slices.Contains(referenceBanks, bank) {
		digests, err = manifest.PCRDigests(bank)
		if err != nil {
			return nil, verifierError(op, errors.ErrInvalidInput, &ReferenceValuesRejectedError{Reason: err.Error(), Cause: err})
		}
	}
	if len(digests) == 0 {
		return nil, verifierError(op, errors.ErrInvalidInput, &orchestration.ReferenceBankUncoveredError{ReferenceValues: name, Bank: bank})
	}
	pcrs := make([]uint32, 0, len(digests))
	for idx := range digests {
		pcrs = append(pcrs, uint32(idx)) // #nosec G115 -- PCRDigests bounds idx to 0..23
	}
	slices.Sort(pcrs)
	return pcrs, nil
}

// AppraiseHost appraises the host evidence with AppraiseQuote and reports
// every check that did not pass, with the divergent PCRs on the baseline.
func (a *hostAppraiser) AppraiseHost(ctx context.Context, ev *orchestration.HostEvidence) (*orchestration.HostAppraisal, error) {
	if ev == nil {
		return nil, ErrAttestationNilRequest
	}
	req := &AppraiseQuoteRequest{
		Quote:           ev.Quoted,
		Signature:       ev.Signature,
		Nonce:           ev.Nonce,
		PCRs:            ev.PCRs,
		EventLog:        ev.EventLog,
		ReferenceValues: ev.ReferenceValues,
	}
	if ev.AKCertificate != nil {
		req.AKCertificatePEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ev.AKCertificate.Raw})
	}
	result, divergences, err := a.svc.appraiseQuote(ctx, req, ev.LaunchPCRs)
	if err != nil {
		return nil, err
	}

	appraisal := &orchestration.HostAppraisal{
		Verified:             result.Verified,
		CryptographicFailure: result.CryptographicFailure,
	}
	for _, check := range result.Checks {
		if check.Outcome != AppraisalForged && check.Outcome != AppraisalAbsent {
			continue
		}
		failure := orchestration.HostAppraisalFailure{
			Check:   check.Name,
			Outcome: string(check.Outcome),
			Reason:  check.Reason,
		}
		if check.Name == AppraisalCheckBaseline {
			for _, d := range divergences {
				failure.PCRs = append(failure.PCRs, orchestration.PCRDivergence{
					Index:    uint32(d.Index),
					Expected: d.Expected,
					Quoted:   d.Quoted,
				})
			}
		}
		appraisal.Failures = append(appraisal.Failures, failure)
	}
	return appraisal, nil
}
