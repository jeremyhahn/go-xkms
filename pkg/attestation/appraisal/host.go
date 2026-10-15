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

package orchestration

import (
	"context"
	"crypto"
	"crypto/x509"
	"strings"
)

// maxReferenceValuesNameLen is the longest reference-values name the
// Verifier stores. It mirrors the Verifier's record-name rule so a spec that
// names an unstorable record is refused offline, before any quote is taken.
const maxReferenceValuesNameLen = 253

// HostAppraiser appraises a host's TPM evidence against reference values the
// Verifier holds by name. Orchestration collects and binds the evidence; the
// Verifier owns the comparison with the signed golden values. The service
// layer supplies the implementation (service.NewHostAppraiser), so this
// package never imports it.
//
// Both methods are tenant-scoped: the reference values are looked up under
// the tenant carried by ctx.
type HostAppraiser interface {
	// ReferencePCRs returns the PCR indices the named reference values
	// cover in bank, the hash of the PCR bank the host quotes, ascending.
	// The runtime quotes exactly these registers. Reference values that
	// cover no register in bank are a *ReferenceBankUncoveredError.
	ReferencePCRs(ctx context.Context, name string, bank crypto.Hash) ([]uint32, error)

	// AppraiseHost appraises evidence against the reference values it
	// names. A returned error means the appraisal could not run; a verdict
	// that the evidence fails is reported in the HostAppraisal.
	AppraiseHost(ctx context.Context, evidence *HostEvidence) (*HostAppraisal, error)
}

// HostEvidence is the bound host evidence a TPMAttestingRuntime hands to its
// HostAppraiser.
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

	// LaunchPCRs are quoted registers the runtime extends at container
	// launch, not the boot chain. The boot event log does not record them,
	// so its replay leaves them out; the reference values judge them.
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

// validateReferenceValuesName applies the Verifier's record-name rule: a
// name is non-empty, at most maxReferenceValuesNameLen bytes, and holds no
// '/' that could escape its key prefix.
func validateReferenceValuesName(name string) error {
	if name == "" {
		return &InputValidationError{Field: "reference_values", Message: "cannot be empty"}
	}
	if len(name) > maxReferenceValuesNameLen || strings.ContainsRune(name, '/') {
		return &InputValidationError{
			Field:   "reference_values",
			Message: "must be at most " + intToStr(maxReferenceValuesNameLen) + " bytes and contain no '/'",
		}
	}
	return nil
}

// HostAppraisalError indicates the Verifier did not verify a host's
// evidence against the named reference values. It carries the failing
// checks, never secret material. It unwraps to ErrHostNotVerified and, when
// a quoted PCR diverges from the reference values, to ErrPCRMismatch.
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
			b.WriteString(intToStr(int(pcr.Index)))
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
