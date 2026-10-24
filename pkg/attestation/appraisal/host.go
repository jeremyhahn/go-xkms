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

package appraisal

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"slices"
	"strconv"
	"strings"
)

// HostEvidence is bound host TPM evidence: a quote, the PCR values bound to
// it and the certificate of the attestation key that signed it.
type HostEvidence struct {
	// ReferenceValues names the stored reference values to compare against.
	ReferenceValues string

	// AKCertificate is the certificate of the attestation key that signed
	// Quoted.
	AKCertificate *x509.Certificate

	// Nonce is the qualifying data the quote is bound to.
	Nonce []byte

	// Quoted is the raw TPMS_ATTEST structure produced by the TPM.
	Quoted []byte

	// Signature is the attestation key's signature over Quoted.
	Signature []byte

	// PCRs are the quoted PCR values keyed by index, already bound to Quoted.
	PCRs map[uint32][]byte

	// EventLog is the raw TCG measurement log, when the host exposes one.
	EventLog []byte

	// LaunchPCRs are quoted registers a container runtime extends at
	// container launch, not the boot chain. The boot event log does not
	// record them, so its replay leaves them out; the reference values judge
	// them.
	LaunchPCRs []uint32
}

// HostAppraisal is the Verifier's verdict on a HostEvidence.
type HostAppraisal struct {
	// Verified is true only when every check passed.
	Verified bool

	// CryptographicFailure is true when a check found evidence that was
	// present and wrong, as opposed to evidence that was missing.
	CryptographicFailure bool

	// Failures lists the checks that did not pass, in evaluation order.
	Failures []HostAppraisalFailure
}

// HostAppraisalFailure is one appraisal check that did not pass.
type HostAppraisalFailure struct {
	// Check names the check, for example "baseline".
	Check string

	// Outcome is "forged" or "absent".
	Outcome string

	// Reason says why the check did not pass.
	Reason string

	// PCRs lists the registers whose quoted value the reference values do
	// not admit. Empty for checks that are not about PCR values.
	PCRs []PCRDivergence
}

// PCRDivergence is one PCR whose quoted value the reference values do not
// admit. PCR values are public measurements, so carrying them is safe.
type PCRDivergence struct {
	// Index is the PCR index.
	Index uint32

	// Expected are the digests the reference values admit for Index. Empty
	// when the reference values do not cover Index.
	Expected [][]byte

	// Quoted is the quoted digest. Empty when the quote does not cover
	// Index.
	Quoted []byte
}

// ReferencePCRs returns the PCR indices the tenant's named reference values
// cover in bank, the hash of the PCR bank the host quotes, ascending. A host
// quotes exactly these registers. The signed CoRIM is verified again, as
// appraisal does, so the registers come from values a reference signer still
// endorses. Digests in other banks are not counted: the baseline compares in
// the quoted bank only, so reference values that cover no register in bank
// are a *ReferenceBankUncoveredError.
func (a *Appraiser) ReferencePCRs(ctx context.Context, tenant, name string, bank crypto.Hash) ([]uint32, error) {
	record, err := a.store.GetReferenceValues(ctx, tenant, name)
	if err != nil {
		return nil, err
	}
	manifest, err := a.verifyCoRIM(ctx, tenant, record.SignedCoRIM)
	if err != nil {
		return nil, err
	}
	var digests map[int][][]byte
	if slices.Contains(referenceBanks, bank) {
		digests, err = manifest.PCRDigests(bank)
		if err != nil {
			return nil, &ReferenceValuesRejectedError{Reason: err.Error(), Cause: err}
		}
	}
	if len(digests) == 0 {
		return nil, &ReferenceBankUncoveredError{ReferenceValues: name, Bank: bank}
	}
	pcrs := make([]uint32, 0, len(digests))
	for idx := range digests {
		pcrs = append(pcrs, uint32(idx)) // #nosec G115 -- PCRDigests bounds idx to 0..23
	}
	slices.Sort(pcrs)
	return pcrs, nil
}

// AppraiseHost appraises host evidence against the tenant's reference values
// it names, as AppraiseQuote does, and reports every check that did not pass,
// with the divergent PCRs on the baseline. A returned error means the
// appraisal could not run; evidence that fails is reported in the
// HostAppraisal.
func (a *Appraiser) AppraiseHost(ctx context.Context, tenant string, ev *HostEvidence) (*HostAppraisal, error) {
	if ev == nil {
		return nil, ErrNilRequest
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
	result, divergences, err := a.appraiseQuote(ctx, tenant, req, ev.LaunchPCRs)
	if err != nil {
		return nil, err
	}

	appraisal := &HostAppraisal{
		Verified:             result.Verified,
		CryptographicFailure: result.CryptographicFailure,
	}
	for _, check := range result.Checks {
		if check.Outcome != AppraisalForged && check.Outcome != AppraisalAbsent {
			continue
		}
		failure := HostAppraisalFailure{
			Check:   check.Name,
			Outcome: string(check.Outcome),
			Reason:  check.Reason,
		}
		if check.Name == AppraisalCheckBaseline {
			for _, d := range divergences {
				failure.PCRs = append(failure.PCRs, PCRDivergence{
					Index:    uint32(d.Index), // #nosec G115 -- PCR indices are 0..23
					Expected: d.Expected,
					Quoted:   d.Quoted,
				})
			}
		}
		appraisal.Failures = append(appraisal.Failures, failure)
	}
	return appraisal, nil
}

// ReferenceBankUncoveredError indicates the named reference values hold no
// PCR digest in the bank the host quotes, so there is nothing to quote or
// appraise. Digests in other banks never stand in for the quoted one.
type ReferenceBankUncoveredError struct {
	ReferenceValues string
	Bank            crypto.Hash
}

// Error implements the error interface.
func (e *ReferenceBankUncoveredError) Error() string {
	return ErrReferenceBankUncovered.Error() + ": reference values " + e.ReferenceValues +
		" cover no PCR in the " + e.Bank.String() + " bank"
}

// Unwrap returns the sentinel error for errors.Is support.
func (e *ReferenceBankUncoveredError) Unwrap() error {
	return ErrReferenceBankUncovered
}

// HostAppraisalError indicates the Verifier did not verify a host's
// evidence against the named reference values. It carries the failing
// checks, never secret material. It unwraps to ErrHostNotVerified and, when
// a quoted PCR diverges from the reference values, to ErrPCRMismatch.
type HostAppraisalError struct {
	Image                string
	ReferenceValues      string
	CryptographicFailure bool
	Failures             []HostAppraisalFailure
}

// Error implements the error interface.
func (e *HostAppraisalError) Error() string {
	var b strings.Builder
	b.WriteString(ErrHostNotVerified.Error())
	b.WriteString(": ")
	b.WriteString(e.Image)
	b.WriteString(" against reference values ")
	b.WriteString(e.ReferenceValues)
	for _, failure := range e.Failures {
		b.WriteString("; ")
		b.WriteString(failure.Check)
		b.WriteString(" ")
		b.WriteString(failure.Outcome)
		if failure.Reason != "" {
			b.WriteString(": ")
			b.WriteString(failure.Reason)
		}
		for _, pcr := range failure.PCRs {
			b.WriteString("; PCR ")
			b.WriteString(strconv.FormatUint(uint64(pcr.Index), 10))
			b.WriteString(" expected ")
			b.WriteString(hexDigests(pcr.Expected))
			b.WriteString(" but quoted ")
			b.WriteString(hexOrAbsent(pcr.Quoted))
		}
	}
	return b.String()
}

// Unwrap returns the sentinels for errors.Is support.
func (e *HostAppraisalError) Unwrap() []error {
	for _, failure := range e.Failures {
		if len(failure.PCRs) > 0 {
			return []error{ErrHostNotVerified, ErrPCRMismatch}
		}
	}
	return []error{ErrHostNotVerified}
}

// hexDigests renders a set of admissible digests.
func hexDigests(digests [][]byte) string {
	if len(digests) == 0 {
		return hexOrAbsent(nil)
	}
	parts := make([]string, 0, len(digests))
	for _, digest := range digests {
		parts = append(parts, hexOrAbsent(digest))
	}
	return strings.Join(parts, "|")
}
