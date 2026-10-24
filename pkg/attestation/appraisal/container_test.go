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
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"maps"
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
	xkmsevidence "github.com/jeremyhahn/go-xkms/pkg/attestation/evidence"
	xkmstpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

const (
	// tpmGeneratedMagic is TPM_GENERATED_VALUE (0xFF || "TCG").
	tpmGeneratedMagic = 0xff544347

	// tpmSTAttestQuoteType is TPM_ST_ATTEST_QUOTE.
	tpmSTAttestQuoteType = 0x8018

	// pcrBitmapBytes covers PCR 0-23, the TCG PC Client register range.
	pcrBitmapBytes = 3
)

// testSelection is one bank's worth of a quote's TPML_PCR_SELECTION.
type testSelection struct {
	bank    string
	indices []uint32
}

// encodeTPMSAttestSelections builds the signed body of a TPM2_Quote over
// selections, committing to pcrDigest and carrying nonce as qualifying data.
// A quote may select registers across several banks, and the pcrDigest then
// covers them in selection order.
func encodeTPMSAttestSelections(t *testing.T, nonce []byte, selections []testSelection, pcrDigest []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	writeUint32 := func(v uint32) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		buf.Write(b[:])
	}
	writeUint16 := func(v uint16) {
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], v)
		buf.Write(b[:])
	}
	writeSized := func(b []byte) {
		writeUint16(uint16(len(b)))
		buf.Write(b)
	}

	writeUint32(tpmGeneratedMagic)
	writeUint16(tpmSTAttestQuoteType)
	writeSized([]byte("qualified-signer"))
	writeSized(nonce)

	// TPMS_CLOCK_INFO: clock, resetCount, restartCount, safe.
	var clock [8]byte
	binary.BigEndian.PutUint64(clock[:], 1234)
	buf.Write(clock[:])
	writeUint32(1) // resetCount
	writeUint32(0) // restartCount
	buf.WriteByte(1)

	// firmwareVersion
	var firmware [8]byte
	binary.BigEndian.PutUint64(firmware[:], 0xdeadbeef)
	buf.Write(firmware[:])

	writeUint32(uint32(len(selections)))
	for _, selection := range selections {
		algID, err := xkmstpm2.ParsePCRBankAlgID(selection.bank)
		if err != nil {
			t.Fatalf("ParsePCRBankAlgID(%q): %v", selection.bank, err)
		}
		writeUint16(uint16(algID))
		buf.WriteByte(pcrBitmapBytes)
		bitmap := make([]byte, pcrBitmapBytes)
		for _, index := range selection.indices {
			bitmap[index/8] |= 1 << (index % 8)
		}
		buf.Write(bitmap)
	}

	writeSized(pcrDigest)

	return buf.Bytes()
}

// quotePCRDigest reproduces the TPM's pcrDigest: the bank hash over the
// selected PCR values concatenated in ascending index order.
func quotePCRDigest(t *testing.T, bank string, values [][]byte) []byte {
	t.Helper()

	hash, err := xkmstpm2.ParsePCRBankCryptoHash(bank)
	if err != nil {
		t.Fatalf("ParsePCRBankCryptoHash(%q): %v", bank, err)
	}
	h := hash.New()
	for _, value := range values {
		h.Write(value)
	}
	return h.Sum(nil)
}

func TestFlattenPCRBanks(t *testing.T) {
	t.Run("SelectsRequestedBank", func(t *testing.T) {
		banks := []xkmstpm2.PCRBank{
			{Algorithm: "sha1", PCRs: []xkmstpm2.PCR{{ID: 7, Value: []byte{0x01}}}},
			{Algorithm: "sha256", PCRs: []xkmstpm2.PCR{{ID: 7, Value: []byte{0x02}}}},
		}
		got, err := flattenPCRBanks(banks, "sha256")
		if err != nil {
			t.Fatalf("flattenPCRBanks: %v", err)
		}
		if !bytes.Equal(got[7], []byte{0x02}) {
			t.Fatalf("PCR 7 = %x, want the sha256 bank value", got[7])
		}
	})

	// go-xkms ReadPCRs reports "SHA1"/"SHA256"/"SHA384"/"SHA512" while every
	// bank name in this package is lowercase. An exact comparison missed on
	// every multi-bank host and silently read a different bank.
	t.Run("MatchesBankNameCaseInsensitively", func(t *testing.T) {
		cases := []struct {
			name      string
			reported  string
			requested string
		}{
			{name: "XKMSUppercaseReport", reported: "SHA256", requested: "sha256"},
			{name: "LowercaseReport", reported: "sha256", requested: "SHA256"},
			{name: "MixedCase", reported: "Sha384", requested: "sHa384"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				banks := []xkmstpm2.PCRBank{
					{Algorithm: "SHA1", PCRs: []xkmstpm2.PCR{{ID: 7, Value: []byte{0x01}}}},
					{Algorithm: tc.reported, PCRs: []xkmstpm2.PCR{{ID: 7, Value: []byte{0x02}}}},
				}
				got, err := flattenPCRBanks(banks, tc.requested)
				if err != nil {
					t.Fatalf("flattenPCRBanks: %v", err)
				}
				if !bytes.Equal(got[7], []byte{0x02}) {
					t.Fatalf("PCR 7 = %x, want the %s bank value (never the first bank)", got[7], tc.reported)
				}
			})
		}
	})

	// The old behaviour fell back to banks[0], so a host without the
	// requested bank produced measurements from an unintended one with no
	// error at all.
	t.Run("AbsentBankIsAnErrorNotAFallback", func(t *testing.T) {
		banks := []xkmstpm2.PCRBank{
			{Algorithm: "SHA1", PCRs: []xkmstpm2.PCR{{ID: 7, Value: []byte{0x01}}}},
		}
		got, err := flattenPCRBanks(banks, "sha384")
		if got != nil {
			t.Fatalf("no PCR values may be returned for an absent bank, got %v", got)
		}
		if !errors.Is(err, ErrPCRBankUnavailable) {
			t.Fatalf("error %v does not wrap ErrPCRBankUnavailable", err)
		}
		var unavailable *PCRBankUnavailableError
		if !errors.As(err, &unavailable) {
			t.Fatalf("expected *PCRBankUnavailableError, got %T", err)
		}
		if unavailable.Requested != "sha384" {
			t.Errorf("Requested = %q, want sha384", unavailable.Requested)
		}
		if !reflect.DeepEqual(unavailable.Available, []string{"SHA1"}) {
			t.Errorf("Available = %v, want [SHA1]", unavailable.Available)
		}
		if unavailable.Error() == "" {
			t.Error("error message must not be empty")
		}
	})

	t.Run("EmptyInputIsAnError", func(t *testing.T) {
		got, err := flattenPCRBanks(nil, "sha256")
		if got != nil {
			t.Fatalf("expected no values, got %v", got)
		}
		if !errors.Is(err, ErrPCRBankUnavailable) {
			t.Fatalf("error %v does not wrap ErrPCRBankUnavailable", err)
		}
		if err.Error() == "" {
			t.Fatal("error message must not be empty")
		}
	})

	t.Run("SkipsNegativeIndices", func(t *testing.T) {
		banks := []xkmstpm2.PCRBank{
			{Algorithm: "sha256", PCRs: []xkmstpm2.PCR{{ID: -1, Value: []byte{0x01}}}},
		}
		got, err := flattenPCRBanks(banks, "sha256")
		if err != nil {
			t.Fatalf("flattenPCRBanks: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("negative PCR ids must be skipped, got %v", got)
		}
	})
}

// =============================================================================
// Binding the PCR read to the signed quote
// =============================================================================

// TestBindQuotedPCRs_RefusesQuotesNoSingleBankReferenceCanJudge covers the
// selections go-xkms's evidence primitive refuses: a quote over two banks
// (whose index->value map a golden comparison cannot use) and a quote over
// the SHA-1 bank (not acceptable evidence of state). Both are absences, not
// forgeries, and both leave the quote unbound.
func TestBindQuotedPCRs_RefusesQuotesNoSingleBankReferenceCanJudge(t *testing.T) {
	sha1Value := bytes.Repeat([]byte{0x11}, 20)
	sha256Value := bytes.Repeat([]byte{0x22}, sha256.Size)
	nonce := []byte("nonce-for-a-refused-quote")
	banks := []xkmstpm2.PCRBank{
		{Algorithm: "SHA1", PCRs: []xkmstpm2.PCR{{ID: 7, Value: sha1Value}}},
		{Algorithm: "SHA256", PCRs: []xkmstpm2.PCR{{ID: 7, Value: sha256Value}}},
	}

	cases := map[string]struct {
		selections []testSelection
		digest     []byte
	}{
		"TwoBanks": {
			selections: []testSelection{{bank: "sha1", indices: []uint32{7}}, {bank: "sha256", indices: []uint32{7}}},
			digest:     quotePCRDigest(t, "sha256", [][]byte{sha1Value, sha256Value}),
		},
		"SHA1Bank": {
			// The digest is the signing scheme's SHA-256 over the SHA-1
			// register, as a TPM produces it; the bank is what is refused.
			selections: []testSelection{{bank: "sha1", indices: []uint32{7}}},
			digest:     quotePCRDigest(t, "sha256", [][]byte{sha1Value}),
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			quoted := encodeTPMSAttestSelections(t, nonce, tc.selections, tc.digest)
			_, err := bindQuotedPCRs("alpine", quoted, nonce, banks)
			if !errors.Is(err, ErrQuoteNotBound) {
				t.Fatalf("error %v does not wrap ErrQuoteNotBound", err)
			}
			if !errors.Is(err, xkmsevidence.ErrAbsent) {
				t.Fatalf("error %v must carry go-xkms's absent-evidence cause", err)
			}
		})
	}
}

// TestBindQuotedPCRs_ShortRegisterIsRejected proves a read whose register is
// not the bank's digest size cannot bind, even when its bytes happen to hash
// to the signed digest: go-xkms checks the register size before the digest.
func TestBindQuotedPCRs_ShortRegisterIsRejected(t *testing.T) {
	short := bytes.Repeat([]byte{0x44}, 16)
	nonce := []byte("nonce-for-a-short-register")
	quoted := encodeTPMSAttestSelections(t, nonce,
		[]testSelection{{bank: "sha256", indices: []uint32{7}}},
		quotePCRDigest(t, "sha256", [][]byte{short}))
	banks := []xkmstpm2.PCRBank{{Algorithm: "SHA256", PCRs: []xkmstpm2.PCR{{ID: 7, Value: short}}}}

	_, err := bindQuotedPCRs("alpine", quoted, nonce, banks)
	if !errors.Is(err, ErrQuotedPCRDigestMismatch) {
		t.Fatalf("error %v does not wrap ErrQuotedPCRDigestMismatch", err)
	}
}

// TestPCRBankName proves the TPM algorithm ID in a signed selection maps back
// to the bank name go-xkms reports, using go-xkms's own mapping in both
// directions.
func TestPCRBankName(t *testing.T) {
	t.Run("EverySupportedBankRoundTrips", func(t *testing.T) {
		for _, bank := range supportedPCRBankNames {
			algID, err := xkmstpm2.ParsePCRBankAlgID(bank)
			if err != nil {
				t.Fatalf("ParsePCRBankAlgID(%q): %v", bank, err)
			}
			got, err := pcrBankName(uint16(algID))
			if err != nil {
				t.Fatalf("pcrBankName(0x%04x): %v", uint16(algID), err)
			}
			if got != bank {
				t.Fatalf("pcrBankName(0x%04x) = %q, want %q", uint16(algID), got, bank)
			}
		}
	})

	t.Run("UnknownAlgorithmIsRejected", func(t *testing.T) {
		if _, err := pcrBankName(0x0099); !errors.Is(err, ErrPCRBankUnavailable) {
			t.Fatalf("error %v does not wrap ErrPCRBankUnavailable", err)
		}
	})
}

func TestAttestationErrorsUnwrap(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		target error
	}{
		{
			name: "PCRMismatch",
			err: &HostAppraisalError{Image: "alpine", ReferenceValues: "golden", CryptographicFailure: true, Failures: []HostAppraisalFailure{{
				Check: "baseline", Outcome: "forged",
				PCRs: []PCRDivergence{{Index: 7, Expected: [][]byte{{0x01}}, Quoted: []byte{0x02}}},
			}}},
			target: ErrPCRMismatch,
		},
		{
			name: "PCRMismatchAbsent",
			err: &HostAppraisalError{Image: "alpine", ReferenceValues: "golden", Failures: []HostAppraisalFailure{{
				Check: "baseline", Outcome: "absent",
				PCRs: []PCRDivergence{{Index: 7, Expected: [][]byte{{0x01}}}},
			}}},
			target: ErrPCRMismatch,
		},
		{
			name:   "HostNotVerified",
			err:    &HostAppraisalError{Image: "alpine", ReferenceValues: "golden", Failures: []HostAppraisalFailure{{Check: "ak-certificate", Outcome: "absent"}}},
			target: ErrHostNotVerified,
		},
		{
			name:   "QuoteBindingNoCause",
			err:    &QuoteBindingError{Image: "alpine", Reason: "not a quote"},
			target: ErrQuoteNotBound,
		},
		{
			name:   "QuoteBindingWithCause",
			err:    &QuoteBindingError{Image: "alpine", Reason: "unparseable", Cause: errors.New("short buffer")},
			target: ErrQuoteNotBound,
		},
		{
			name:   "QuotedPCRDigestMismatch",
			err:    &QuotedPCRDigestMismatchError{Image: "alpine", Bank: "sha256", Signed: []byte{0x01}, Cause: errors.New("digest differs")},
			target: ErrQuotedPCRDigestMismatch,
		},
		{
			name:   "QuotedPCRDigestMismatchIsAlsoUnbound",
			err:    &QuotedPCRDigestMismatchError{Image: "alpine", Bank: "sha256", Signed: []byte{0x01}, Cause: errors.New("digest differs")},
			target: ErrQuoteNotBound,
		},
		{
			name:   "PCRBankUnavailable",
			err:    &PCRBankUnavailableError{Requested: "sha384", Available: []string{"SHA1", "SHA256"}},
			target: ErrPCRBankUnavailable,
		},
		{
			name:   "PCRBankUnavailableNoBanks",
			err:    &PCRBankUnavailableError{Requested: "sha256"},
			target: ErrPCRBankUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.err, tt.target) {
				t.Fatalf("%v does not wrap %v", tt.err, tt.target)
			}
			if tt.err.Error() == "" {
				t.Fatal("error message must not be empty")
			}
		})
	}
}

// containerEvidence returns the evidence a container runtime hands the
// Appraiser: the world's AK quoting pcrs over nonce, with the SHA-256 PCR
// read taken alongside the quote.
func (w *verifierWorld) containerEvidence(t *testing.T, pcrs map[uint32][]byte, nonce []byte) *ContainerEvidence {
	t.Helper()
	quote, err := appraisaltest.SignQuote(w.ak, pcrs, nonce)
	if err != nil {
		t.Fatalf("SignQuote: %v", err)
	}
	bank := xkmstpm2.PCRBank{Algorithm: "SHA256"}
	for index, value := range pcrs {
		bank.PCRs = append(bank.PCRs, xkmstpm2.PCR{ID: int32(index), Value: value})
	}
	return &ContainerEvidence{
		Image:           "alpine",
		ReferenceValues: "golden",
		AKCertificate:   w.ak.Certificate,
		Nonce:           nonce,
		Quote:           xkmstpm2.Quote{Quoted: quote.Attest, Signature: quote.Signature},
		Banks:           []xkmstpm2.PCRBank{bank},
	}
}

func TestAppraiser_AppraiseContainer(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x5A}, sha256.Size)

	t.Run("GenuineEvidencePasses", func(t *testing.T) {
		w := newHostWorld(t)
		if err := w.app.AppraiseContainer(w.ctx, w.tenant, w.containerEvidence(t, w.pcrs, nonce)); err != nil {
			t.Fatalf("AppraiseContainer: %v", err)
		}
	})

	t.Run("NilEvidenceIsRefused", func(t *testing.T) {
		w := newHostWorld(t)
		if err := w.app.AppraiseContainer(w.ctx, w.tenant, nil); !errors.Is(err, ErrNilRequest) {
			t.Fatalf("error %v, want ErrNilRequest", err)
		}
	})

	t.Run("QuoteOverAnotherNonceIsNotBound", func(t *testing.T) {
		w := newHostWorld(t)
		ev := w.containerEvidence(t, w.pcrs, nonce)
		ev.Nonce = bytes.Repeat([]byte{0xA5}, sha256.Size)
		err := w.app.AppraiseContainer(w.ctx, w.tenant, ev)
		var binding *QuoteBindingError
		if !errors.As(err, &binding) {
			t.Fatalf("expected *QuoteBindingError, got %T: %v", err, err)
		}
		if !errors.Is(err, ErrQuoteNotBound) {
			t.Fatalf("error %v does not wrap ErrQuoteNotBound", err)
		}
	})

	t.Run("ReadDisagreeingWithTheQuoteIsRefused", func(t *testing.T) {
		w := newHostWorld(t)
		ev := w.containerEvidence(t, w.pcrs, nonce)
		for i := range ev.Banks[0].PCRs {
			if ev.Banks[0].PCRs[i].ID == 7 {
				ev.Banks[0].PCRs[i].Value = bytes.Repeat([]byte{0xEE}, sha256.Size)
			}
		}
		err := w.app.AppraiseContainer(w.ctx, w.tenant, ev)
		var mismatch *QuotedPCRDigestMismatchError
		if !errors.As(err, &mismatch) {
			t.Fatalf("expected *QuotedPCRDigestMismatchError, got %T: %v", err, err)
		}
	})

	t.Run("DriftedPCRIsAPCRMismatch", func(t *testing.T) {
		w := newHostWorld(t)
		drifted := maps.Clone(w.pcrs)
		digest := sha256.Sum256([]byte("unexpected boot component"))
		drifted[7] = digest[:]
		err := w.app.AppraiseContainer(w.ctx, w.tenant, w.containerEvidence(t, drifted, nonce))
		if !errors.Is(err, ErrPCRMismatch) || !errors.Is(err, ErrHostNotVerified) {
			t.Fatalf("error %v does not wrap ErrPCRMismatch and ErrHostNotVerified", err)
		}
		var appraisal *HostAppraisalError
		if !errors.As(err, &appraisal) {
			t.Fatalf("expected *HostAppraisalError, got %T", err)
		}
		if appraisal.Image != "alpine" || appraisal.ReferenceValues != "golden" {
			t.Errorf("error names %q against %q, want alpine against golden", appraisal.Image, appraisal.ReferenceValues)
		}
		if !appraisal.CryptographicFailure {
			t.Error("a drifted PCR is a cryptographic failure")
		}
	})

	t.Run("UnknownReferenceValuesAreNotVerified", func(t *testing.T) {
		w := newHostWorld(t)
		ev := w.containerEvidence(t, w.pcrs, nonce)
		ev.ReferenceValues = "unknown"
		err := w.app.AppraiseContainer(w.ctx, w.tenant, ev)
		if !errors.Is(err, ErrHostNotVerified) {
			t.Fatalf("error %v does not wrap ErrHostNotVerified", err)
		}
		if errors.Is(err, ErrPCRMismatch) {
			t.Fatal("missing reference values are not a PCR mismatch")
		}
		var appraisal *HostAppraisalError
		if !errors.As(err, &appraisal) {
			t.Fatalf("expected *HostAppraisalError, got %T", err)
		}
		if appraisal.CryptographicFailure {
			t.Error("missing reference values are absent evidence, not a cryptographic failure")
		}
	})

	t.Run("InvalidTenantIsRefused", func(t *testing.T) {
		w := newHostWorld(t)
		err := w.app.AppraiseContainer(w.ctx, "a/b", w.containerEvidence(t, w.pcrs, nonce))
		if !errors.Is(err, ErrInvalidTenant) {
			t.Fatalf("error %v, want ErrInvalidTenant", err)
		}
	})
}
