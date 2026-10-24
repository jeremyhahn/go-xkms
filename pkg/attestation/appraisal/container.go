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
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"sort"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/evidence"
	xkmstpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"

	"github.com/jeremyhahn/go-quicbaas/pkg/interfaces"
)

// appraise hands the bound evidence to the Verifier and turns anything short
// of a verified appraisal into a HostAppraisalError.
func (r *TPMAttestingRuntime) appraise(ctx context.Context, spec *ContainerSpec, nonce []byte, quote xkmstpm2.Quote, bound *boundPCRs) error {
	akCert, err := r.tpm.IAKCertificate()
	if err != nil {
		return &ContainerQuoteError{Image: spec.Image, Cause: err}
	}
	appraisal, err := r.appraiser.AppraiseHost(ctx, &HostEvidence{
		ReferenceValues: spec.ReferenceValues,
		AKCertificate:   akCert,
		Nonce:           nonce,
		Quoted:          quote.Quoted,
		Signature:       quote.Signature,
		PCRs:            bound.values,
		EventLog:        quote.EventLog,
		LaunchPCRs:      []uint32{uint32(spec.EffectiveMeasurementPCR())},
	})
	if err != nil {
		return err
	}
	if appraisal != nil && appraisal.Verified {
		return nil
	}
	appraisalErr := &HostAppraisalError{Image: spec.Image, ReferenceValues: spec.ReferenceValues}
	if appraisal != nil {
		appraisalErr.CryptographicFailure = appraisal.CryptographicFailure
		appraisalErr.Failures = appraisal.Failures
	}
	return appraisalErr
}

// =============================================================================
// Binding the PCR read to the signed quote
// =============================================================================
//
// A TPM2_Quote signs a TPMS_ATTEST structure whose TPMS_QUOTE_INFO carries the
// PCR selection and one pcrDigest — H(PCR[i1] || PCR[i2] || …) over the
// selected registers in selection order. It does NOT carry the individual PCR
// values, so those must come from a separate, unsigned TPM2_PCR_Read.
//
// Comparing golden values against that read alone establishes nothing: the
// read carries no signature, and a PCR can be extended in the window between
// the quote and the read. bindQuotedPCRs closes the gap by requiring the
// values that were read to reproduce the digest inside the signed body, and
// by requiring the body's extraData to be the nonce this process just
// generated.
//
// Every TPM structure here is parsed and checked by go-xkms's evidence
// primitives (pkg/attestation/evidence) and every bank mapping comes from
// go-xkms (tpm2.ParsePCRBankAlgID). Nothing in this file hand-rolls a TPM
// structure or recomputes a digest.

// boundPCRs is a PCR read that has been proven to agree with a signed quote.
// Its values are the only ones Attest will compare against a golden set.
type boundPCRs struct {
	// bank is the PCR bank the signed selection named.
	bank string

	// values are the read PCR values, keyed by index, that reproduce the
	// signed pcrDigest.
	values map[uint32][]byte
}

// bindQuotedPCRs proves that the PCR values read back from the TPM are the
// values the TPM committed to when it signed quoted, and that the quote is
// fresh.
//
// What this establishes: the returned values are exactly the ones covered by
// the signed pcrDigest, and the signed body carries this attestation's nonce.
// A TOCTOU change between the quote and the read, or a tampered read path,
// makes the values fail to reproduce the signed digest and is rejected.
//
// What this does NOT establish: that the signature over quoted verifies under
// a trusted attestation key. That check needs the AK public key and its
// certificate chain, neither of which the narrow HostTPM seam exposes, and it
// belongs to the remote verifier that consumes ContainerAttestation.Quoted and
// .Signature. Locally, the quote body is trusted because it came from the
// host's own TPM handle; what is being defended against here is a divergence
// between that body and the separate PCR read.
//
// Every check is go-xkms's evidence primitive: ParseQuote (a TPM-generated
// TPM2_Quote over exactly one accepted bank), VerifyQualifyingData (the nonce,
// in constant time) and VerifyPCRValues (the reported set equals the
// selection and hashes to the signed digest). Nothing here re-derives the
// digest or decodes a selection bitmap.
func bindQuotedPCRs(image string, quoted, nonce []byte, banks []xkmstpm2.PCRBank) (*boundPCRs, error) {
	quote, err := evidence.ParseQuote(quoted)
	if err != nil {
		return nil, &QuoteBindingError{
			Image:  image,
			Reason: "signed quote body is not a single-bank TPM2_Quote",
			Cause:  err,
		}
	}

	// Freshness: the nonce must be inside the signed body, not merely
	// alongside it.
	if err := quote.VerifyQualifyingData(nonce); err != nil {
		return nil, &QuoteBindingError{
			Image:  image,
			Reason: "signed quote does not carry the nonce this attestation generated",
			Cause:  err,
		}
	}

	bankName, err := pcrBankName(uint16(quote.Bank))
	if err != nil {
		return nil, err
	}
	read, err := flattenPCRBanks(banks, bankName)
	if err != nil {
		return nil, err
	}

	reported := make(map[int][]byte, len(quote.Selected))
	for _, index := range quote.Selected {
		value, ok := read[uint32(index)]
		if !ok {
			return nil, &QuoteBindingError{
				Image: image,
				Reason: "PCR " + intToStr(index) + " is in the signed selection but absent from the " +
					bankName + " read",
			}
		}
		reported[index] = value
	}

	if err := quote.VerifyPCRValues(reported); err != nil {
		return nil, &QuotedPCRDigestMismatchError{
			Image:  image,
			Bank:   bankName,
			Signed: bytes.Clone(quote.PCRDigest),
			Cause:  err,
		}
	}

	values := make(map[uint32][]byte, len(reported))
	for index, value := range reported {
		values[uint32(index)] = value
	}
	return &boundPCRs{bank: bankName, values: values}, nil
}

// pcrBankName maps the TPM algorithm ID carried in a signed PCR selection back
// to the bank name go-xkms reports from ReadPCRs. The mapping is derived from
// go-xkms rather than restated, so a bank added upstream needs no constant
// here.
func pcrBankName(algID uint16) (string, error) {
	for _, name := range supportedPCRBankNames {
		id, err := xkmstpm2.ParsePCRBankAlgID(name)
		if err != nil {
			return "", err
		}
		if uint16(id) == algID {
			return name, nil
		}
	}
	return "", &PCRBankUnavailableError{Requested: "TPM algorithm 0x" + hexOrAbsent([]byte{byte(algID >> 8), byte(algID)})}
}

// flattenPCRBanks reduces the multi-bank PCR read to a single index->digest
// map for the named bank.
//
// The match is case-insensitive: go-xkms ReadPCRs reports "SHA256" while every
// bank name in this package (and in a ContainerSpec) is lowercase, and an
// exact comparison silently missed on every multi-bank host. A bank that is
// genuinely absent is an error, never a fallback to whichever bank happened to
// be first — reading PCRs from an unintended bank produces measurements that
// look valid and mean nothing.
func flattenPCRBanks(banks []xkmstpm2.PCRBank, name string) (map[uint32][]byte, error) {
	for _, bank := range banks {
		if !strings.EqualFold(bank.Algorithm, name) {
			continue
		}
		out := make(map[uint32][]byte, len(bank.PCRs))
		for _, pcr := range bank.PCRs {
			if pcr.ID < 0 {
				continue
			}
			value := make([]byte, len(pcr.Value))
			copy(value, pcr.Value)
			out[uint32(pcr.ID)] = value
		}
		return out, nil
	}

	available := make([]string, 0, len(banks))
	for _, bank := range banks {
		available = append(available, bank.Algorithm)
	}
	return nil, &PCRBankUnavailableError{Requested: name, Available: available}
}

// =============================================================================
// Typed Attestation Errors
// =============================================================================

// QuoteBindingError indicates the PCR values read from the TPM could not be
// tied to the signed quote body, so they are not evidence of anything. It
// covers an unparseable or non-quote TPMS_ATTEST, a quote that does not carry
// this attestation's nonce, and a selection that names a bank or a register
// the read did not supply.
type QuoteBindingError struct {
	Image  string
	Reason string
	Cause  error
}

// Error implements the error interface.
func (e *QuoteBindingError) Error() string {
	msg := ErrQuoteNotBound.Error() + ": " + e.Image + ": " + e.Reason
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap returns the sentinel and the cause for errors.Is support.
func (e *QuoteBindingError) Unwrap() []error {
	if e.Cause == nil {
		return []error{ErrQuoteNotBound}
	}
	return []error{ErrQuoteNotBound, e.Cause}
}

// QuotedPCRDigestMismatchError indicates the PCR values the TPM reported do
// not reproduce the pcrDigest inside the signed quote. The signed evidence and
// the PCR read disagree about the state of the host, so neither may be
// trusted. Cause is go-xkms's evidence error naming the exact check that
// failed (set, register size or digest).
//
// It reports both ErrQuotedPCRDigestMismatch and ErrQuoteNotBound, so a caller
// can catch the specific failure or the whole class of unbound quotes.
type QuotedPCRDigestMismatchError struct {
	Image  string
	Bank   string
	Signed []byte
	Cause  error
}

// Error implements the error interface.
func (e *QuotedPCRDigestMismatchError) Error() string {
	msg := ErrQuotedPCRDigestMismatch.Error() + ": " + e.Image + ": the " + e.Bank +
		" PCR read does not reproduce the digest the signed quote commits to (" +
		hexOrAbsent(e.Signed) + ")"
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap returns both sentinels and the cause for errors.Is support.
func (e *QuotedPCRDigestMismatchError) Unwrap() []error {
	if e.Cause == nil {
		return []error{ErrQuotedPCRDigestMismatch, ErrQuoteNotBound}
	}
	return []error{ErrQuotedPCRDigestMismatch, ErrQuoteNotBound, e.Cause}
}

// PCRBankUnavailableError indicates the PCR bank a verification step requires
// is not one the TPM reported. It is returned instead of silently reading a
// different bank, which would yield measurements that are well-formed and
// meaningless.
type PCRBankUnavailableError struct {
	Requested string
	Available []string
}

// Error implements the error interface.
func (e *PCRBankUnavailableError) Error() string {
	msg := ErrPCRBankUnavailable.Error() + ": " + e.Requested
	if len(e.Available) > 0 {
		msg += " (the TPM reported: " + strings.Join(e.Available, ", ") + ")"
	} else {
		msg += " (the TPM reported no banks)"
	}
	return msg
}

// Unwrap returns the sentinel error for errors.Is support.
func (e *PCRBankUnavailableError) Unwrap() error {
	return ErrPCRBankUnavailable
}

// hexOrAbsent renders a PCR digest for an error message, distinguishing an
// empty digest from an absent one.
func hexOrAbsent(b []byte) string {
	if len(b) == 0 {
		return "<absent>"
	}
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexDigits[c>>4], hexDigits[c&0x0f])
	}
	return string(out)
}
