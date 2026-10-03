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
	"crypto/x509"
	stderrors "errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/pkg/errors"
	"github.com/jeremyhahn/go-quicbaas/pkg/service/attestationtest"
	"github.com/jeremyhahn/go-quicbaas/pkg/tenantctx"
)

// verifierWorld is a tenant with endorsed reference values and an attester.
type verifierWorld struct {
	svc        AttestationService
	store      *attestationtest.MemoryStore
	ctx        context.Context
	akCA       *attestationtest.Authority
	rvCA       *attestationtest.Authority
	signerCert *x509.Certificate
	ak         *attestationtest.AttestationKey
	pcrs       map[uint32][]byte
	corim      []byte
}

func newVerifierWorld(t testing.TB) *verifierWorld {
	t.Helper()
	w := &verifierWorld{store: attestationtest.NewMemoryStore(), ctx: tenantctx.WithTenant(context.Background(), "acme")}
	w.svc = NewAttestationService(nil, nil, WithAttestationStore(w.store))
	var err error
	if w.akCA, err = attestationtest.NewAuthority("AK CA"); err != nil {
		t.Fatal(err)
	}
	if w.rvCA, err = attestationtest.NewAuthority("Reference Value CA"); err != nil {
		t.Fatal(err)
	}
	signerCert, signerKey, err := attestationtest.SignerUnder(w.rvCA)
	if err != nil {
		t.Fatal(err)
	}
	w.signerCert = signerCert
	if w.ak, err = attestationtest.IssueAttestationKey(w.akCA, true); err != nil {
		t.Fatal(err)
	}
	w.pcrs = attestationtest.PCRValues(0, 4, 7)
	if w.corim, err = attestationtest.SignCoRIM(w.pcrs, signerKey, []*x509.Certificate{signerCert}); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *verifierWorld) endorse(t testing.TB) {
	t.Helper()
	if _, err := w.svc.PutEndorsement(w.ctx, &PutEndorsementRequest{Name: "ak-ca", Kind: EndorsementAKRoot, CertificatePEM: w.akCA.CertificatePEM()}); err != nil {
		t.Fatalf("PutEndorsement ak-root: %v", err)
	}
	if _, err := w.svc.PutEndorsement(w.ctx, &PutEndorsementRequest{Name: "rv-ca", Kind: EndorsementReferenceSigner, CertificatePEM: w.rvCA.CertificatePEM()}); err != nil {
		t.Fatalf("PutEndorsement reference-signer: %v", err)
	}
	if _, err := w.svc.PutReferenceValues(w.ctx, &PutReferenceValuesRequest{Name: "golden", SignedCoRIM: w.corim}); err != nil {
		t.Fatalf("PutReferenceValues: %v", err)
	}
}

func (w *verifierWorld) appraise(t *testing.T, pcrs map[uint32][]byte, nonce []byte, signNonce []byte) *AttestationResult {
	t.Helper()
	quote, err := attestationtest.SignQuote(w.ak, pcrs, signNonce)
	if err != nil {
		t.Fatal(err)
	}
	result, err := w.svc.AppraiseQuote(w.ctx, &AppraiseQuoteRequest{
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

func TestVerifier_PinnedKeySigner(t *testing.T) {
	w := newVerifierWorld(t)
	signer, err := attestationtest.NewAuthority("pinned signer")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := signer.PublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	corim, err := attestationtest.SignCoRIM(w.pcrs, signer.Key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.PutEndorsement(w.ctx, &PutEndorsementRequest{Name: "pinned", Kind: EndorsementReferenceSigner, PublicKeyPEM: pub}); err != nil {
		t.Fatalf("PutEndorsement: %v", err)
	}
	rv, err := w.svc.PutReferenceValues(w.ctx, &PutReferenceValuesRequest{Name: "pinned-golden", SignedCoRIM: corim})
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
	_, err := w.svc.PutReferenceValues(w.ctx, &PutReferenceValuesRequest{Name: "golden", SignedCoRIM: w.corim})
	var rejected *ReferenceValuesRejectedError
	if !stderrors.As(err, &rejected) || !strings.Contains(rejected.Reason, "first use") {
		t.Fatalf("no signer stored: %v, want a TOFU refusal", err)
	}

	other, err := attestationtest.NewAuthority("some other CA")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.PutEndorsement(w.ctx, &PutEndorsementRequest{Name: "other", Kind: EndorsementReferenceSigner, CertificatePEM: other.CertificatePEM()}); err != nil {
		t.Fatal(err)
	}
	_, err = w.svc.PutReferenceValues(w.ctx, &PutReferenceValuesRequest{Name: "golden", SignedCoRIM: w.corim})
	if !stderrors.As(err, &rejected) || codeOf(t, err) != errors.ErrInvalidInput {
		t.Fatalf("unendorsed signer: %v, want ReferenceValuesRejectedError", err)
	}
}

func TestVerifier_DivergentPCRIsACryptographicFailure(t *testing.T) {
	w := newVerifierWorld(t)
	w.endorse(t)
	tampered := attestationtest.PCRValues(0, 4, 7)
	tampered[4] = attestationtest.PCRValues(9)[9]
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
	if w.ak, err = attestationtest.IssueAttestationKey(w.akCA, false); err != nil {
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
	if err := w.svc.DeleteEndorsement(w.ctx, &DeleteEndorsementRequest{Name: "rv-ca"}); err != nil {
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
	quote, err := attestationtest.SignQuote(w.ak, w.pcrs, []byte("n"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := w.svc.AppraiseQuote(w.ctx, &AppraiseQuoteRequest{
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
	result, err = w.svc.AppraiseQuote(w.ctx, &AppraiseQuoteRequest{Nonce: []byte("n")})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verified || outcomeOf(result, AppraisalCheckAKCertificate) != AppraisalAbsent || outcomeOf(result, AppraisalCheckBaseline) != AppraisalAbsent {
		t.Fatalf("empty evidence = %+v", result.Checks)
	}
}

func TestVerifier_EndorsementValidation(t *testing.T) {
	w := newVerifierWorld(t)
	ak, err := attestationtest.IssueAttestationKey(w.akCA, true)
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
		if _, err := w.svc.PutEndorsement(w.ctx, req); codeOf(t, err) != errors.ErrInvalidInput {
			t.Fatalf("%s: %v, want invalid input", name, err)
		}
	}
	if _, err := w.svc.PutEndorsement(w.ctx, nil); err != ErrAttestationNilRequest {
		t.Fatalf("nil: %v", err)
	}
}

func TestVerifier_RecordsListGetDeleteAndTenancy(t *testing.T) {
	w := newVerifierWorld(t)
	w.endorse(t)

	listed, err := w.svc.ListEndorsements(w.ctx, &ListEndorsementsRequest{Kind: EndorsementAKRoot})
	if err != nil || len(listed.Endorsements) != 1 || listed.Endorsements[0].Name != "ak-ca" {
		t.Fatalf("ListEndorsements(ak-root) = %+v, %v", listed, err)
	}
	all, err := w.svc.ListEndorsements(w.ctx, nil)
	if err != nil || len(all.Endorsements) != 2 || all.Endorsements[0].Name != "ak-ca" {
		t.Fatalf("ListEndorsements = %+v, %v", all, err)
	}

	rv, err := w.svc.GetReferenceValues(w.ctx, &GetReferenceValuesRequest{Name: "golden"})
	if err != nil || len(rv.SignedCoRIM) == 0 || rv.ManifestID == "" {
		t.Fatalf("GetReferenceValues = %+v, %v", rv, err)
	}
	rvs, err := w.svc.ListReferenceValues(w.ctx)
	if err != nil || len(rvs.ReferenceValues) != 1 || rvs.ReferenceValues[0].SignedCoRIM != nil {
		t.Fatalf("ListReferenceValues = %+v, %v (bodies are omitted)", rvs, err)
	}

	// Another tenant sees none of it.
	other := tenantctx.WithTenant(context.Background(), "globex")
	if none, err := w.svc.ListEndorsements(other, nil); err != nil || len(none.Endorsements) != 0 {
		t.Fatalf("another tenant listed %+v, %v", none, err)
	}
	if _, err := w.svc.GetReferenceValues(other, &GetReferenceValuesRequest{Name: "golden"}); codeOf(t, err) != errors.ErrNotFound {
		t.Fatalf("another tenant read reference values: %v", err)
	}

	if err := w.svc.DeleteReferenceValues(w.ctx, &DeleteReferenceValuesRequest{Name: "golden"}); err != nil {
		t.Fatal(err)
	}
	if err := w.svc.DeleteReferenceValues(w.ctx, &DeleteReferenceValuesRequest{Name: "golden"}); codeOf(t, err) != errors.ErrNotFound {
		t.Fatalf("second delete = %v, want not found", err)
	}
	if err := w.svc.DeleteEndorsement(w.ctx, &DeleteEndorsementRequest{Name: "nope"}); codeOf(t, err) != errors.ErrNotFound {
		t.Fatalf("delete missing endorsement = %v", err)
	}
	if err := w.svc.DeleteEndorsement(w.ctx, &DeleteEndorsementRequest{Name: "a/b"}); codeOf(t, err) != errors.ErrInvalidInput {
		t.Fatalf("delete bad name = %v", err)
	}
	for name, err := range map[string]error{
		"get nil":   func() error { _, err := w.svc.GetReferenceValues(w.ctx, nil); return err }(),
		"put nil":   func() error { _, err := w.svc.PutReferenceValues(w.ctx, nil); return err }(),
		"del nil":   w.svc.DeleteReferenceValues(w.ctx, nil),
		"del e nil": w.svc.DeleteEndorsement(w.ctx, nil),
		"appraise":  func() error { _, err := w.svc.AppraiseQuote(w.ctx, nil); return err }(),
		"get badnm": func() error {
			_, err := w.svc.GetReferenceValues(w.ctx, &GetReferenceValuesRequest{Name: ""})
			return err
		}(),
		"put badnm": func() error {
			_, err := w.svc.PutReferenceValues(w.ctx, &PutReferenceValuesRequest{Name: ""})
			return err
		}(),
		"put nobody": func() error {
			_, err := w.svc.PutReferenceValues(w.ctx, &PutReferenceValuesRequest{Name: "x"})
			return err
		}(),
	} {
		if err == nil {
			t.Fatalf("%s: no error", name)
		}
	}
}

func TestVerifier_StoreFailures(t *testing.T) {
	unconfigured := NewAttestationService(nil, nil)
	ctx := context.Background()
	var unavailable *AttestationStoreUnavailableError
	if _, err := unconfigured.ListReferenceValues(ctx); !stderrors.As(err, &unavailable) || codeOf(t, err) != errors.ErrUnavailable {
		t.Fatalf("no store = %v", err)
	}
	if _, err := unconfigured.AppraiseQuote(ctx, &AppraiseQuoteRequest{}); !stderrors.As(err, &unavailable) {
		t.Fatalf("appraise with no store = %v", err)
	}

	w := newVerifierWorld(t)
	w.endorse(t)
	w.store.Fail = stderrors.New("store down")
	checks := map[string]error{}
	_, checks["put endorsement"] = w.svc.PutEndorsement(w.ctx, &PutEndorsementRequest{Name: "x", Kind: EndorsementAKRoot, CertificatePEM: w.akCA.CertificatePEM()})
	_, checks["list endorsements"] = w.svc.ListEndorsements(w.ctx, nil)
	_, checks["put refvals"] = w.svc.PutReferenceValues(w.ctx, &PutReferenceValuesRequest{Name: "x", SignedCoRIM: w.corim})
	_, checks["get refvals"] = w.svc.GetReferenceValues(w.ctx, &GetReferenceValuesRequest{Name: "golden"})
	_, checks["list refvals"] = w.svc.ListReferenceValues(w.ctx)
	checks["delete refvals"] = w.svc.DeleteReferenceValues(w.ctx, &DeleteReferenceValuesRequest{Name: "golden"})
	_, checks["appraise"] = w.svc.AppraiseQuote(w.ctx, &AppraiseQuoteRequest{AKCertificatePEM: w.ak.CertificatePEM(), ReferenceValues: "golden"})
	for name, err := range checks {
		if err == nil {
			t.Fatalf("%s succeeded against a failing store", name)
		}
	}
}

func TestComparePCRBaseline(t *testing.T) {
	a, b := []byte{1, 1}, []byte{2, 2}
	if got := comparePCRBaseline(map[int][]byte{0: a}, map[int][][]byte{0: {b, a}}); got.Outcome != AppraisalPass {
		t.Fatalf("a second acceptable digest = %+v, want pass", got)
	}
	if got := comparePCRBaseline(map[int][]byte{0: a, 1: a}, map[int][][]byte{0: {a}}); got.Outcome != AppraisalAbsent {
		t.Fatalf("index set mismatch = %+v, want absent", got)
	}
	if got := comparePCRBaseline(map[int][]byte{0: a}, map[int][][]byte{}); got.Outcome != AppraisalAbsent {
		t.Fatalf("no reference digests = %+v, want absent", got)
	}
	if got := comparePCRBaseline(map[int][]byte{0: a}, map[int][][]byte{0: {b}}); got.Outcome != AppraisalForged {
		t.Fatalf("divergent value = %+v, want forged", got)
	}
}

func TestVerifierErrors_Messages(t *testing.T) {
	cause := stderrors.New("c")
	for _, err := range []error{
		&AttestationNameError{Name: "a/b"},
		&EndorsementInvalidError{Reason: "r"},
		&AttestationRecordNotFoundError{Kind: "k", Name: "n"},
		&ReferenceValuesRejectedError{Reason: "r", Cause: cause},
		&AttestationStoreUnavailableError{},
	} {
		if err.Error() == "" {
			t.Fatalf("%T has an empty message", err)
		}
	}
	if !stderrors.Is(&ReferenceValuesRejectedError{Cause: cause}, cause) {
		t.Fatal("ReferenceValuesRejectedError does not unwrap")
	}
}

// verifierCode returns the status code of a Verifier error.
// BenchmarkAppraiseQuote measures one full appraisal: AK chain, quote
// signature, PCR digest and the signed-baseline comparison (including the
// CoRIM signature re-check).
func BenchmarkAppraiseQuote(b *testing.B) {
	w := newVerifierWorld(b)
	w.endorse(b)
	nonce := []byte("bench")
	quote, err := attestationtest.SignQuote(w.ak, w.pcrs, nonce)
	if err != nil {
		b.Fatal(err)
	}
	req := &AppraiseQuoteRequest{
		AKCertificatePEM: w.ak.CertificatePEM(), Quote: quote.Attest, Signature: quote.Signature,
		Nonce: nonce, PCRs: w.pcrs, ReferenceValues: "golden",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.svc.AppraiseQuote(w.ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}

// The Verifier fails closed: on every verb, a request with no tenant bound
// stores, reads and appraises nothing, never acting as the system tenant.
func TestAttestationVerifier_RefusesARequestWithNoTenant(t *testing.T) {
	w := newVerifierWorld(t)
	w.endorse(t)
	quote, err := attestationtest.SignQuote(w.ak, map[uint32][]byte{0: make([]byte, 32)}, []byte("nonce"))
	if err != nil {
		t.Fatal(err)
	}
	none := context.Background()
	checks := map[string]error{
		"DeleteEndorsement":     w.svc.DeleteEndorsement(none, &DeleteEndorsementRequest{Name: "ak-ca"}),
		"DeleteReferenceValues": w.svc.DeleteReferenceValues(none, &DeleteReferenceValuesRequest{Name: "golden"}),
	}
	_, checks["PutEndorsement"] = w.svc.PutEndorsement(none, &PutEndorsementRequest{Name: "ak-ca2", Kind: EndorsementAKRoot, CertificatePEM: w.akCA.CertificatePEM()})
	_, checks["ListEndorsements"] = w.svc.ListEndorsements(none, nil)
	_, checks["PutReferenceValues"] = w.svc.PutReferenceValues(none, &PutReferenceValuesRequest{Name: "golden2", SignedCoRIM: w.corim})
	_, checks["GetReferenceValues"] = w.svc.GetReferenceValues(none, &GetReferenceValuesRequest{Name: "golden"})
	_, checks["ListReferenceValues"] = w.svc.ListReferenceValues(none)
	_, checks["AppraiseQuote"] = w.svc.AppraiseQuote(none, &AppraiseQuoteRequest{
		AKCertificatePEM: w.ak.CertificatePEM(),
		Quote:            quote.Attest,
		Signature:        quote.Signature,
		Nonce:            []byte("nonce"),
		PCRs:             map[uint32][]byte{0: make([]byte, 32)},
		ReferenceValues:  "golden",
	})
	for op, err := range checks {
		var missing *tenantctx.MissingTenantError
		if !stderrors.As(err, &missing) || codeOf(t, err) != errors.ErrForbidden {
			t.Errorf("%s with no tenant = %v, want ErrForbidden wrapping *tenantctx.MissingTenantError", op, err)
		}
	}
	// The tenant's records are untouched.
	if list, err := w.svc.ListEndorsements(w.ctx, nil); err != nil || len(list.Endorsements) != 2 {
		t.Fatalf("acme's endorsements after the refusals = %+v, %v", list, err)
	}
}
