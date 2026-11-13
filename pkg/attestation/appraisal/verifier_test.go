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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
	"github.com/jeremyhahn/go-xkms/pkg/dao"
)

// verifierWorld is a tenant with endorsed reference values and an attester.
type verifierWorld struct {
	app        *Appraiser
	kv         *faultKV
	ctx        context.Context
	tenant     string
	akCA       *appraisaltest.Authority
	rvCA       *appraisaltest.Authority
	signerCert *x509.Certificate
	signerKey  crypto.Signer
	ak         *appraisaltest.AttestationKey
	pcrs       map[uint32][]byte
	corim      []byte
}

func newVerifierWorld(t testing.TB) *verifierWorld {
	t.Helper()
	w := &verifierWorld{kv: newFaultKV(), ctx: context.Background(), tenant: "acme"}
	store, err := NewStore(StoreConfig{DAOs: dao.NewStoreFactory(w.kv)})
	if err != nil {
		t.Fatal(err)
	}
	if w.app, err = NewAppraiser(store); err != nil {
		t.Fatal(err)
	}
	if w.akCA, err = appraisaltest.NewAuthority("AK CA"); err != nil {
		t.Fatal(err)
	}
	if w.rvCA, err = appraisaltest.NewAuthority("Reference Value CA"); err != nil {
		t.Fatal(err)
	}
	signerCert, signerKey, err := appraisaltest.SignerUnder(w.rvCA)
	if err != nil {
		t.Fatal(err)
	}
	w.signerCert = signerCert
	w.signerKey = signerKey
	if w.ak, err = appraisaltest.IssueAttestationKey(w.akCA, true); err != nil {
		t.Fatal(err)
	}
	w.pcrs = appraisaltest.PCRValues(0, 4, 7)
	if w.corim, err = appraisaltest.SignCoRIM(w.pcrs, signerKey, []*x509.Certificate{signerCert}); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *verifierWorld) endorse(t testing.TB) {
	t.Helper()
	if _, err := w.app.PutEndorsement(w.ctx, w.tenant, &PutEndorsementRequest{Name: "ak-ca", Kind: EndorsementAKRoot, CertificatePEM: w.akCA.CertificatePEM()}); err != nil {
		t.Fatalf("PutEndorsement ak-root: %v", err)
	}
	if _, err := w.app.PutEndorsement(w.ctx, w.tenant, &PutEndorsementRequest{Name: "rv-ca", Kind: EndorsementReferenceSigner, CertificatePEM: w.rvCA.CertificatePEM()}); err != nil {
		t.Fatalf("PutEndorsement reference-signer: %v", err)
	}
	if _, err := w.app.PutReferenceValues(w.ctx, w.tenant, &PutReferenceValuesRequest{Name: "golden", SignedCoRIM: w.corim}); err != nil {
		t.Fatalf("PutReferenceValues: %v", err)
	}
}

func (w *verifierWorld) appraise(t *testing.T, pcrs map[uint32][]byte, nonce []byte, signNonce []byte) *AttestationResult {
	t.Helper()
	quote, err := appraisaltest.SignQuote(w.ak, pcrs, signNonce)
	if err != nil {
		t.Fatal(err)
	}
	result, err := w.app.AppraiseQuote(w.ctx, w.tenant, &AppraiseQuoteRequest{
		AKCertificatePEM: w.ak.CertificatePEM(),
		Quote:            quote.Attest,
		Signature:        quote.Signature,
		Nonce:            nonce,
		PCRs:             pcrs,
		ReferenceValues:  "golden",
	})
	if err != nil {
		t.Fatalf("AppraiseQuote: %v", err)
	}
	return result
}

func outcomeOf(r *AttestationResult, check string) AppraisalOutcome {
	for _, c := range r.Checks {
		if c.Name == check {
			return c.Outcome
		}
	}
	return ""
}

func TestVerifier_AppraisesGenuineEvidenceAgainstSignedReferenceValues(t *testing.T) {
	w := newVerifierWorld(t)
	w.endorse(t)
	nonce := []byte("verifier-nonce-1")
	result := w.appraise(t, w.pcrs, nonce, nonce)

	if !result.Verified || result.CryptographicFailure {
		t.Fatalf("result = %+v, want verified", result)
	}
	for _, check := range []string{AppraisalCheckAKCertificate, AppraisalCheckQuote, AppraisalCheckBaseline} {
		if outcomeOf(result, check) != AppraisalPass {
			t.Fatalf("%s = %s, want pass (%+v)", check, outcomeOf(result, check), result.Checks)
		}
	}
	if outcomeOf(result, AppraisalCheckEventLog) != AppraisalSkipped {
		t.Fatalf("event log = %s, want skipped without a log", outcomeOf(result, AppraisalCheckEventLog))
	}
	if result.BaselineSource != BaselineSourceSigned || result.ManifestID == "" || result.Signer == "" || result.ReferenceValues != "golden" {
		t.Fatalf("result does not identify its signed baseline: %+v", result)
	}
}

// TestVerifier_BaselineUsesTheQuotedBankNotTheSigningHash drives a quote
// whose signing scheme hash (SHA-384, named by the PCR digest length) differs
// from its PCR bank (SHA-256), as a TPM produces when an attestation key with
// a SHA-384 scheme quotes the SHA-256 bank. The quoted registers are SHA-256
// values, so the reference values must be read in the bank's algorithm; read
// in the signing hash they hold no digest for any PCR and the baseline could
// never pass.
func TestVerifier_BaselineUsesTheQuotedBankNotTheSigningHash(t *testing.T) {
	w := newVerifierWorld(t)
	w.endorse(t)
	nonce := []byte("verifier-nonce-bank")

	indices := []uint32{0, 4, 7}
	pcrDigest := sha512.New384()
	selection := make([]uint, 0, len(indices))
	for _, idx := range indices {
		pcrDigest.Write(w.pcrs[idx])
		selection = append(selection, uint(idx))
	}
	attest := tpm2.Marshal(tpm2.TPMSAttest{
		Magic:           tpm2.TPMGeneratedValue,
		Type:            tpm2.TPMSTAttestQuote,
		QualifiedSigner: tpm2.TPM2BName{Buffer: []byte("ak")},
		ExtraData:       tpm2.TPM2BData{Buffer: nonce},
		ClockInfo:       tpm2.TPMSClockInfo{Clock: 1, Safe: true},
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
			PCRSelect: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(selection...),
			}}},
			PCRDigest: tpm2.TPM2BDigest{Buffer: pcrDigest.Sum(nil)},
		}),
	})
	signed := sha512.Sum384(attest)
	signature, err := ecdsa.SignASN1(rand.Reader, w.ak.Key, signed[:])
	if err != nil {
		t.Fatal(err)
	}

	result, err := w.app.AppraiseQuote(w.ctx, w.tenant, &AppraiseQuoteRequest{
		AKCertificatePEM: w.ak.CertificatePEM(),
		Quote:            attest,
		Signature:        signature,
		Nonce:            nonce,
		PCRs:             w.pcrs,
		ReferenceValues:  "golden",
	})
	if err != nil {
		t.Fatalf("AppraiseQuote: %v", err)
	}
	if outcomeOf(result, AppraisalCheckQuote) != AppraisalPass {
		t.Fatalf("quote = %s, want pass: the SHA-384 scheme over the SHA-256 bank must verify (%+v)", outcomeOf(result, AppraisalCheckQuote), result.Checks)
	}
	if outcomeOf(result, AppraisalCheckBaseline) != AppraisalPass || !result.Verified {
		t.Fatalf("baseline = %s, want pass against the SHA-256 reference values (%+v)", outcomeOf(result, AppraisalCheckBaseline), result.Checks)
	}
}

func TestVerifier_PinnedKeySigner(t *testing.T) {
	w := newVerifierWorld(t)
	signer, err := appraisaltest.NewAuthority("pinned signer")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := signer.PublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	corim, err := appraisaltest.SignCoRIM(w.pcrs, signer.Key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.app.PutEndorsement(w.ctx, w.tenant, &PutEndorsementRequest{Name: "pinned", Kind: EndorsementReferenceSigner, PublicKeyPEM: pub}); err != nil {
		t.Fatalf("PutEndorsement: %v", err)
	}
	rv, err := w.app.PutReferenceValues(w.ctx, w.tenant, &PutReferenceValuesRequest{Name: "pinned-golden", SignedCoRIM: corim})
	if err != nil {
		t.Fatalf("PutReferenceValues: %v", err)
	}
	if len(rv.PCRIndices) != 3 || rv.PCRIndices[0] != 0 || rv.PCRIndices[2] != 7 {
		t.Fatalf("PCR indices = %v, want [0 4 7]", rv.PCRIndices)
	}
}

// TestVerifier_RefusesTrustOnFirstUse pins the TOFU fix: reference values
// that no stored signer endorses are refused, however plausible they look.
func TestVerifier_RefusesTrustOnFirstUse(t *testing.T) {
	w := newVerifierWorld(t)
	_, err := w.app.PutReferenceValues(w.ctx, w.tenant, &PutReferenceValuesRequest{Name: "golden", SignedCoRIM: w.corim})
	var rejected *ReferenceValuesRejectedError
	if !errors.As(err, &rejected) || !strings.Contains(rejected.Reason, "first use") {
		t.Fatalf("no signer stored: %v, want a TOFU refusal", err)
	}

	other, err := appraisaltest.NewAuthority("some other CA")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.app.PutEndorsement(w.ctx, w.tenant, &PutEndorsementRequest{Name: "other", Kind: EndorsementReferenceSigner, CertificatePEM: other.CertificatePEM()}); err != nil {
		t.Fatal(err)
	}
	_, err = w.app.PutReferenceValues(w.ctx, w.tenant, &PutReferenceValuesRequest{Name: "golden", SignedCoRIM: w.corim})
	if !errors.As(err, &rejected) || !errors.Is(err, ErrReferenceValuesRejected) {
		t.Fatalf("unendorsed signer: %v, want ReferenceValuesRejectedError", err)
	}
}

func TestVerifier_DivergentPCRIsACryptographicFailure(t *testing.T) {
	w := newVerifierWorld(t)
	w.endorse(t)
	tampered := appraisaltest.PCRValues(0, 4, 7)
	tampered[4] = appraisaltest.PCRValues(9)[9]
	nonce := []byte("n")
	result := w.appraise(t, tampered, nonce, nonce)
	if result.Verified || !result.CryptographicFailure || outcomeOf(result, AppraisalCheckBaseline) != AppraisalForged {
		t.Fatalf("result = %+v, want a forged baseline", result)
	}
	if outcomeOf(result, AppraisalCheckQuote) != AppraisalPass {
		t.Fatal("the quote itself is genuine")
	}
}

func TestVerifier_WrongNonceIsForged(t *testing.T) {
	w := newVerifierWorld(t)
	w.endorse(t)
	result := w.appraise(t, w.pcrs, []byte("expected"), []byte("replayed"))
	if result.Verified || !result.CryptographicFailure || outcomeOf(result, AppraisalCheckQuote) != AppraisalForged {
		t.Fatalf("result = %+v, want a forged quote", result)
	}
	if outcomeOf(result, AppraisalCheckBaseline) != AppraisalAbsent {
		t.Fatal("a baseline is not evaluated over an unverified quote")
	}
}

func TestVerifier_UnrestrictedAKIsForged(t *testing.T) {
	w := newVerifierWorld(t)
	w.endorse(t)
	var err error
	if w.ak, err = appraisaltest.IssueAttestationKey(w.akCA, false); err != nil {
		t.Fatal(err)
	}
	result := w.appraise(t, w.pcrs, []byte("n"), []byte("n"))
	if result.Verified || outcomeOf(result, AppraisalCheckAKCertificate) != AppraisalForged {
		t.Fatalf("result = %+v, want the AK certificate refused", result)
	}
}

func TestVerifier_MissingAnchorsAreAbsencesNotForgeries(t *testing.T) {
	w := newVerifierWorld(t)
	result := w.appraise(t, w.pcrs, []byte("n"), []byte("n"))
	if result.Verified || result.CryptographicFailure {
		t.Fatalf("result = %+v, want unverified without a cryptographic failure", result)
	}
	if outcomeOf(result, AppraisalCheckAKCertificate) != AppraisalAbsent || outcomeOf(result, AppraisalCheckBaseline) != AppraisalAbsent {
		t.Fatalf("checks = %+v", result.Checks)
	}
}

// TestVerifier_DeletingTheSignerWithdrawsItsBaselines proves the signature is
// re-checked at every appraisal.
func TestVerifier_DeletingTheSignerWithdrawsItsBaselines(t *testing.T) {
	w := newVerifierWorld(t)
	w.endorse(t)
	if err := w.app.DeleteEndorsement(w.ctx, w.tenant, &DeleteEndorsementRequest{Name: "rv-ca"}); err != nil {
		t.Fatal(err)
	}
	result := w.appraise(t, w.pcrs, []byte("n"), []byte("n"))
	if result.Verified || outcomeOf(result, AppraisalCheckBaseline) != AppraisalAbsent {
		t.Fatalf("result = %+v, want the baseline withdrawn", result)
	}
}

func TestVerifier_EventLogAndUnknownReferenceValues(t *testing.T) {
	w := newVerifierWorld(t)
	w.endorse(t)
	quote, err := appraisaltest.SignQuote(w.ak, w.pcrs, []byte("n"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := w.app.AppraiseQuote(w.ctx, w.tenant, &AppraiseQuoteRequest{
		AKCertificatePEM: w.ak.CertificatePEM(), Quote: quote.Attest, Signature: quote.Signature,
		Nonce: []byte("n"), PCRs: w.pcrs, EventLog: []byte{1, 2, 3}, ReferenceValues: "no-such",
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcomeOf(result, AppraisalCheckEventLog) != AppraisalForged {
		t.Fatalf("malformed event log = %s, want forged", outcomeOf(result, AppraisalCheckEventLog))
	}
	if outcomeOf(result, AppraisalCheckBaseline) != AppraisalAbsent {
		t.Fatalf("unknown reference values = %s, want absent", outcomeOf(result, AppraisalCheckBaseline))
	}
	result, err = w.app.AppraiseQuote(w.ctx, w.tenant, &AppraiseQuoteRequest{Nonce: []byte("n")})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verified || outcomeOf(result, AppraisalCheckAKCertificate) != AppraisalAbsent || outcomeOf(result, AppraisalCheckBaseline) != AppraisalAbsent {
		t.Fatalf("empty evidence = %+v", result.Checks)
	}
}

func TestVerifier_EndorsementValidation(t *testing.T) {
	w := newVerifierWorld(t)
	ak, err := appraisaltest.IssueAttestationKey(w.akCA, true)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := w.rvCA.PublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]*PutEndorsementRequest{
		"bad kind":        {Name: "x", Kind: "nope", CertificatePEM: w.akCA.CertificatePEM()},
		"neither":         {Name: "x", Kind: EndorsementAKRoot},
		"both":            {Name: "x", Kind: EndorsementReferenceSigner, CertificatePEM: w.akCA.CertificatePEM(), PublicKeyPEM: pub},
		"ak-root key":     {Name: "x", Kind: EndorsementAKRoot, PublicKeyPEM: pub},
		"not a CA":        {Name: "x", Kind: EndorsementAKRoot, CertificatePEM: ak.CertificatePEM()},
		"garbage cert":    {Name: "x", Kind: EndorsementAKRoot, CertificatePEM: []byte("junk")},
		"garbage key":     {Name: "x", Kind: EndorsementReferenceSigner, PublicKeyPEM: []byte("junk")},
		"slash in name":   {Name: "a/b", Kind: EndorsementAKRoot, CertificatePEM: w.akCA.CertificatePEM()},
		"empty name":      {Name: "", Kind: EndorsementAKRoot, CertificatePEM: w.akCA.CertificatePEM()},
		"oversize name":   {Name: strings.Repeat("n", 254), Kind: EndorsementAKRoot, CertificatePEM: w.akCA.CertificatePEM()},
		"reference roots": {Name: "x", Kind: EndorsementReferenceSigner, CertificatePEM: ak.CertificatePEM()},
	}
	for name, req := range cases {
		want := ErrEndorsementInvalid
		if strings.HasSuffix(name, " name") {
			want = ErrInvalidName
		}
		if _, err := w.app.PutEndorsement(w.ctx, w.tenant, req); !errors.Is(err, want) {
			t.Fatalf("%s: %v, want %v", name, err, want)
		}
	}
	if _, err := w.app.PutEndorsement(w.ctx, w.tenant, nil); !errors.Is(err, ErrNilRequest) {
		t.Fatalf("nil: %v", err)
	}
}

func TestVerifier_RecordsListGetDeleteAndTenancy(t *testing.T) {
	w := newVerifierWorld(t)
	w.endorse(t)

	listed, err := w.app.ListEndorsements(w.ctx, w.tenant, &ListEndorsementsRequest{Kind: EndorsementAKRoot})
	if err != nil || len(listed.Endorsements) != 1 || listed.Endorsements[0].Name != "ak-ca" {
		t.Fatalf("ListEndorsements(ak-root) = %+v, %v", listed, err)
	}
	all, err := w.app.ListEndorsements(w.ctx, w.tenant, nil)
	if err != nil || len(all.Endorsements) != 2 || all.Endorsements[0].Name != "ak-ca" {
		t.Fatalf("ListEndorsements = %+v, %v", all, err)
	}

	rv, err := w.app.GetReferenceValues(w.ctx, w.tenant, &GetReferenceValuesRequest{Name: "golden"})
	if err != nil || len(rv.SignedCoRIM) == 0 || rv.ManifestID == "" {
		t.Fatalf("GetReferenceValues = %+v, %v", rv, err)
	}
	rvs, err := w.app.ListReferenceValues(w.ctx, w.tenant)
	if err != nil || len(rvs.ReferenceValues) != 1 || rvs.ReferenceValues[0].SignedCoRIM != nil {
		t.Fatalf("ListReferenceValues = %+v, %v (bodies are omitted)", rvs, err)
	}

	// Another tenant sees none of it.
	if none, err := w.app.ListEndorsements(w.ctx, "globex", nil); err != nil || len(none.Endorsements) != 0 {
		t.Fatalf("another tenant listed %+v, %v", none, err)
	}
	if _, err := w.app.GetReferenceValues(w.ctx, "globex", &GetReferenceValuesRequest{Name: "golden"}); !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("another tenant read reference values: %v", err)
	}

	if err := w.app.DeleteReferenceValues(w.ctx, w.tenant, &DeleteReferenceValuesRequest{Name: "golden"}); err != nil {
		t.Fatal(err)
	}
	if err := w.app.DeleteReferenceValues(w.ctx, w.tenant, &DeleteReferenceValuesRequest{Name: "golden"}); !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("second delete = %v, want not found", err)
	}
	if err := w.app.DeleteEndorsement(w.ctx, w.tenant, &DeleteEndorsementRequest{Name: "nope"}); !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("delete missing endorsement = %v", err)
	}
	if err := w.app.DeleteEndorsement(w.ctx, w.tenant, &DeleteEndorsementRequest{Name: "a/b"}); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("delete bad name = %v", err)
	}
	for name, err := range map[string]error{
		"get nil":   func() error { _, err := w.app.GetReferenceValues(w.ctx, w.tenant, nil); return err }(),
		"put nil":   func() error { _, err := w.app.PutReferenceValues(w.ctx, w.tenant, nil); return err }(),
		"del nil":   w.app.DeleteReferenceValues(w.ctx, w.tenant, nil),
		"del e nil": w.app.DeleteEndorsement(w.ctx, w.tenant, nil),
		"appraise":  func() error { _, err := w.app.AppraiseQuote(w.ctx, w.tenant, nil); return err }(),
		"get badnm": func() error {
			_, err := w.app.GetReferenceValues(w.ctx, w.tenant, &GetReferenceValuesRequest{Name: ""})
			return err
		}(),
		"put badnm": func() error {
			_, err := w.app.PutReferenceValues(w.ctx, w.tenant, &PutReferenceValuesRequest{Name: ""})
			return err
		}(),
		"put nobody": func() error {
			_, err := w.app.PutReferenceValues(w.ctx, w.tenant, &PutReferenceValuesRequest{Name: "x"})
			return err
		}(),
	} {
		if err == nil {
			t.Fatalf("%s: no error", name)
		}
	}
}

// TestAppraiserDeletesAnEndorsementNamedBeforeTheDotRule is the upgrade
// regression at the Appraiser: an endorsement stored as ".." before
// ValidateName refused that name is still a trust anchor, so an operator
// must still be able to revoke it.
func TestAppraiserDeletesAnEndorsementNamedBeforeTheDotRule(t *testing.T) {
	w := newVerifierWorld(t)
	seedStoredRecord(t, w.app.store.endorsements, w.tenant, "..", Endorsement{Name: "..", Kind: EndorsementAKRoot, CertificatePEM: []byte("pem")})

	if listed, err := w.app.ListEndorsements(w.ctx, w.tenant, nil); err != nil || len(listed.Endorsements) != 1 || listed.Endorsements[0].Name != ".." {
		t.Fatalf("ListEndorsements = %+v, %v; want the stored \"..\"", listed, err)
	}
	if err := w.app.DeleteEndorsement(w.ctx, w.tenant, &DeleteEndorsementRequest{Name: ".."}); err != nil {
		t.Fatalf("DeleteEndorsement(\"..\") = %v, want the stored record deleted", err)
	}
	if listed, err := w.app.ListEndorsements(w.ctx, w.tenant, nil); err != nil || len(listed.Endorsements) != 0 {
		t.Fatalf("ListEndorsements after delete = %+v, %v", listed, err)
	}
	if err := w.app.DeleteEndorsement(w.ctx, w.tenant, &DeleteEndorsementRequest{Name: "a/b"}); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("DeleteEndorsement(\"a/b\") = %v, want ErrInvalidName", err)
	}
}

func TestVerifier_StoreFailures(t *testing.T) {
	w := newVerifierWorld(t)
	w.endorse(t)
	w.kv.failReads, w.kv.failWrites = true, true
	checks := map[string]error{}
	_, checks["put endorsement"] = w.app.PutEndorsement(w.ctx, w.tenant, &PutEndorsementRequest{Name: "x", Kind: EndorsementAKRoot, CertificatePEM: w.akCA.CertificatePEM()})
	_, checks["list endorsements"] = w.app.ListEndorsements(w.ctx, w.tenant, nil)
	_, checks["put refvals"] = w.app.PutReferenceValues(w.ctx, w.tenant, &PutReferenceValuesRequest{Name: "x", SignedCoRIM: w.corim})
	_, checks["get refvals"] = w.app.GetReferenceValues(w.ctx, w.tenant, &GetReferenceValuesRequest{Name: "golden"})
	_, checks["list refvals"] = w.app.ListReferenceValues(w.ctx, w.tenant)
	checks["delete refvals"] = w.app.DeleteReferenceValues(w.ctx, w.tenant, &DeleteReferenceValuesRequest{Name: "golden"})
	_, checks["appraise"] = w.app.AppraiseQuote(w.ctx, w.tenant, &AppraiseQuoteRequest{AKCertificatePEM: w.ak.CertificatePEM(), ReferenceValues: "golden"})
	for name, err := range checks {
		if !errors.Is(err, ErrStoreUnavailable) {
			t.Fatalf("%s against a failing store = %v, want ErrStoreUnavailable", name, err)
		}
	}
}

func TestComparePCRBaseline(t *testing.T) {
	a, b := []byte{1, 1}, []byte{2, 2}
	if got, _ := comparePCRBaseline(map[int][]byte{0: a}, map[int][][]byte{0: {b, a}}); got.Outcome != AppraisalPass {
		t.Fatalf("a second acceptable digest = %+v, want pass", got)
	}
	if got, _ := comparePCRBaseline(map[int][]byte{0: a, 1: a}, map[int][][]byte{0: {a}}); got.Outcome != AppraisalAbsent {
		t.Fatalf("index set mismatch = %+v, want absent", got)
	}
	if got, _ := comparePCRBaseline(map[int][]byte{0: a}, map[int][][]byte{}); got.Outcome != AppraisalAbsent {
		t.Fatalf("no reference digests = %+v, want absent", got)
	}
	if got, _ := comparePCRBaseline(map[int][]byte{0: a}, map[int][][]byte{0: {b}}); got.Outcome != AppraisalForged {
		t.Fatalf("divergent value = %+v, want forged", got)
	}

	// The cases below moved here from orchestration's TestVerifyExpectedPCRs
	// when the Tier 1 golden comparison moved onto the Verifier.
	golden := bytes.Repeat([]byte{0xAB}, sha256.Size)

	t.Run("MatchingSetPasses", func(t *testing.T) {
		got, divergences := comparePCRBaseline(
			map[int][]byte{7: golden, 8: {0x01}},
			map[int][][]byte{7: {golden}, 8: {{0x01}}},
		)
		if got.Outcome != AppraisalPass || len(divergences) != 0 {
			t.Fatalf("matching set = %+v, %+v; want pass with no divergence", got, divergences)
		}
	})

	t.Run("AbsentPCRIsAMismatch", func(t *testing.T) {
		got, divergences := comparePCRBaseline(map[int][]byte{}, map[int][][]byte{7: {golden}})
		if got.Outcome == AppraisalPass {
			t.Fatalf("absent PCR = %+v, want a failing baseline", got)
		}
		if len(divergences) != 1 || divergences[0].Index != 7 || divergences[0].Quoted != nil {
			t.Fatalf("divergences = %+v, want PCR 7 with no quoted value", divergences)
		}
	})

	t.Run("ExtraQuotedPCRIsAbsent", func(t *testing.T) {
		got, divergences := comparePCRBaseline(
			map[int][]byte{7: golden, 8: {0x01}},
			map[int][][]byte{7: {golden}},
		)
		if got.Outcome != AppraisalAbsent {
			t.Fatalf("extra quoted PCR = %+v, want absent", got)
		}
		if len(divergences) != 1 || divergences[0].Index != 8 || divergences[0].Expected != nil {
			t.Fatalf("divergences = %+v, want PCR 8 with no reference digest", divergences)
		}
	})

	t.Run("LowestFailingIndexIsReported", func(t *testing.T) {
		got, divergences := comparePCRBaseline(
			map[int][]byte{0: {0x01}, 7: {0x02}, 14: {0x03}},
			map[int][][]byte{14: {golden}, 0: {golden}, 7: {golden}},
		)
		if got.Outcome != AppraisalForged {
			t.Fatalf("divergent set = %+v, want forged", got)
		}
		if len(divergences) != 3 || divergences[0].Index != 0 {
			t.Fatalf("divergences = %+v, want all three with the lowest failing index 0 first", divergences)
		}
		if !bytes.Equal(divergences[0].Quoted, []byte{0x01}) || !bytes.Equal(divergences[0].Expected[0], golden) {
			t.Fatalf("divergence 0 = %+v, want the quoted and expected digests", divergences[0])
		}
	})
}

func TestVerifierErrors_Messages(t *testing.T) {
	cause := errors.New("c")
	for _, err := range []error{
		&NameError{Name: "a/b"},
		&EndorsementInvalidError{Reason: "r"},
		&RecordNotFoundError{Kind: "k", Name: "n"},
		&ReferenceValuesRejectedError{Reason: "r", Cause: cause},
		&StoreError{Op: "get", Key: "k", Err: cause},
		&ConfigError{Field: "f", Reason: "r", Cause: cause},
		&TenantError{Tenant: "a/b", Cause: cause},
	} {
		if err.Error() == "" {
			t.Fatalf("%T has an empty message", err)
		}
	}
	if !errors.Is(&ReferenceValuesRejectedError{Cause: cause}, cause) {
		t.Fatal("ReferenceValuesRejectedError does not unwrap")
	}
}

// BenchmarkAppraiseQuote measures one full appraisal: AK chain, quote
// signature, PCR digest and the signed-baseline comparison (including the
// CoRIM signature re-check).
func BenchmarkAppraiseQuote(b *testing.B) {
	w := newVerifierWorld(b)
	w.endorse(b)
	nonce := []byte("bench")
	quote, err := appraisaltest.SignQuote(w.ak, w.pcrs, nonce)
	if err != nil {
		b.Fatal(err)
	}
	req := &AppraiseQuoteRequest{
		AKCertificatePEM: w.ak.CertificatePEM(), Quote: quote.Attest, Signature: quote.Signature,
		Nonce: nonce, PCRs: w.pcrs, ReferenceValues: "golden",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.app.AppraiseQuote(w.ctx, w.tenant, req); err != nil {
			b.Fatal(err)
		}
	}
}

// The Verifier fails closed: on every verb, a request with no tenant bound
// stores, reads and appraises nothing, never acting as the system tenant.
func TestAppraiser_RefusesAnInvalidTenant(t *testing.T) {
	w := newVerifierWorld(t)
	w.endorse(t)
	quote, err := appraisaltest.SignQuote(w.ak, map[uint32][]byte{0: make([]byte, 32)}, []byte("nonce"))
	if err != nil {
		t.Fatal(err)
	}
	bad := "a/b"
	checks := map[string]error{
		"DeleteEndorsement":     w.app.DeleteEndorsement(w.ctx, bad, &DeleteEndorsementRequest{Name: "ak-ca"}),
		"DeleteReferenceValues": w.app.DeleteReferenceValues(w.ctx, bad, &DeleteReferenceValuesRequest{Name: "golden"}),
	}
	_, checks["PutEndorsement"] = w.app.PutEndorsement(w.ctx, bad, &PutEndorsementRequest{Name: "ak-ca2", Kind: EndorsementAKRoot, CertificatePEM: w.akCA.CertificatePEM()})
	_, checks["ListEndorsements"] = w.app.ListEndorsements(w.ctx, bad, nil)
	_, checks["PutReferenceValues"] = w.app.PutReferenceValues(w.ctx, bad, &PutReferenceValuesRequest{Name: "golden2", SignedCoRIM: w.corim})
	_, checks["GetReferenceValues"] = w.app.GetReferenceValues(w.ctx, bad, &GetReferenceValuesRequest{Name: "golden"})
	_, checks["ListReferenceValues"] = w.app.ListReferenceValues(w.ctx, bad)
	_, checks["AppraiseQuote"] = w.app.AppraiseQuote(w.ctx, bad, &AppraiseQuoteRequest{
		AKCertificatePEM: w.ak.CertificatePEM(),
		Quote:            quote.Attest,
		Signature:        quote.Signature,
		Nonce:            []byte("nonce"),
		PCRs:             map[uint32][]byte{0: make([]byte, 32)},
		ReferenceValues:  "golden",
	})
	for op, err := range checks {
		if !errors.Is(err, ErrInvalidTenant) {
			t.Errorf("%s with tenant %q = %v, want ErrInvalidTenant", op, bad, err)
		}
	}
	// The tenant's records are untouched.
	if list, err := w.app.ListEndorsements(w.ctx, w.tenant, nil); err != nil || len(list.Endorsements) != 2 {
		t.Fatalf("acme's endorsements after the refusals = %+v, %v", list, err)
	}
}
