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

package evidence

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

type quoteSpec struct {
	bank       tpm2.TPMAlgID
	hash       crypto.Hash
	pcrs       map[int][]byte
	extra      []byte
	digest     []byte
	selections []tpm2.TPMSPCRSelection
	attestType tpm2.TPMISTAttest
}

func pcrValues(size int, indices ...int) map[int][]byte {
	out := make(map[int][]byte, len(indices))
	for _, idx := range indices {
		v := make([]byte, size)
		for i := range v {
			v[i] = byte(idx + i)
		}
		out[idx] = v
	}
	return out
}

func buildAttest(t *testing.T, s quoteSpec) []byte {
	t.Helper()
	if s.bank == 0 {
		s.bank = tpm2.TPMAlgSHA256
	}
	if s.hash == 0 {
		s.hash = crypto.SHA256
	}
	indices := make([]int, 0, len(s.pcrs))
	for idx := range s.pcrs {
		indices = append(indices, idx)
	}
	sort.Ints(indices)
	h := s.hash.New()
	sel := make([]uint, 0, len(indices))
	for _, idx := range indices {
		h.Write(s.pcrs[idx])
		sel = append(sel, uint(idx))
	}
	digest := h.Sum(nil)
	if s.digest != nil {
		digest = s.digest
	}
	selections := s.selections
	if selections == nil {
		selections = []tpm2.TPMSPCRSelection{{Hash: s.bank, PCRSelect: tpm2.PCClientCompatible.PCRs(sel...)}}
	}
	attested := tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
		PCRSelect: tpm2.TPMLPCRSelection{PCRSelections: selections},
		PCRDigest: tpm2.TPM2BDigest{Buffer: digest},
	})
	attestType := tpm2.TPMSTAttestQuote
	if s.attestType != 0 {
		attestType = s.attestType
		attested = tpm2.NewTPMUAttest(tpm2.TPMSTAttestCertify, &tpm2.TPMSCertifyInfo{
			Name:          tpm2.TPM2BName{Buffer: []byte("name")},
			QualifiedName: tpm2.TPM2BName{Buffer: []byte("qname")},
		})
	}
	return tpm2.Marshal(tpm2.TPMSAttest{
		Magic:           tpm2.TPMGeneratedValue,
		Type:            attestType,
		QualifiedSigner: tpm2.TPM2BName{Buffer: []byte("signer")},
		ExtraData:       tpm2.TPM2BData{Buffer: s.extra},
		ClockInfo:       tpm2.TPMSClockInfo{Clock: 42, ResetCount: 2, RestartCount: 3, Safe: true},
		FirmwareVersion: 7,
		Attested:        attested,
	})
}

func digestOf(h crypto.Hash, data []byte) []byte {
	d := h.New()
	d.Write(data)
	return d.Sum(nil)
}

func signECDSA(t *testing.T, key *ecdsa.PrivateKey, h crypto.Hash, data []byte) []byte {
	t.Helper()
	sig, err := ecdsa.SignASN1(rand.Reader, key, digestOf(h, data))
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func mustECDSA(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func wantClass(t *testing.T, err error, class Class, check, substr string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("error = %v, want *Error", err)
	}
	if e.Class != class || e.Check != check {
		t.Fatalf("error = %s/%s %q, want %s/%s", e.Class, e.Check, e.Reason, class, check)
	}
	if !strings.Contains(e.Reason, substr) {
		t.Fatalf("reason %q does not mention %q", e.Reason, substr)
	}
	sentinel := ErrForged
	if class == ClassAbsent {
		sentinel = ErrAbsent
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("errors.Is(%v, %v) = false", err, sentinel)
	}
}

func TestVerifyQuote_ECDSA(t *testing.T) {
	for name, tc := range map[string]struct {
		curve elliptic.Curve
		bank  tpm2.TPMAlgID
		hash  crypto.Hash
	}{
		"P256/SHA256": {elliptic.P256(), tpm2.TPMAlgSHA256, crypto.SHA256},
		"P384/SHA384": {elliptic.P384(), tpm2.TPMAlgSHA384, crypto.SHA384},
	} {
		t.Run(name, func(t *testing.T) {
			key := mustECDSA(t, tc.curve)
			pcrs := pcrValues(tc.hash.Size(), 0, 7, 14)
			nonce := []byte("nonce-123")
			attest := buildAttest(t, quoteSpec{bank: tc.bank, hash: tc.hash, pcrs: pcrs, extra: nonce})
			q, err := VerifyQuote(QuoteInput{Attest: attest, Signature: signECDSA(t, key, tc.hash, attest), Key: &key.PublicKey, QualifyingData: nonce, PCRs: pcrs})
			if err != nil {
				t.Fatalf("VerifyQuote: %v", err)
			}
			if q.Bank != tc.bank || q.Hash != tc.hash || FormatIndices(q.Selected) != "[0,7,14]" {
				t.Fatalf("quote = bank %v hash %v selected %v", q.Bank, q.Hash, q.Selected)
			}
			if q.Clock != (ClockInfo{Clock: 42, ResetCount: 2, RestartCount: 3, Safe: true}) || q.FirmwareVersion != 7 || string(q.QualifiedSigner) != "signer" {
				t.Fatalf("quote metadata = %+v fw %d signer %q", q.Clock, q.FirmwareVersion, q.QualifiedSigner)
			}
			if !q.Covers(7) || q.Covers(8) {
				t.Fatal("Covers disagrees with the selection")
			}
		})
	}
}

func TestVerifySignature_RawECDSAAndRSA(t *testing.T) {
	pcrs := pcrValues(32, 0)
	attest := buildAttest(t, quoteSpec{pcrs: pcrs, extra: []byte("n")})
	q, err := ParseQuote(attest)
	if err != nil {
		t.Fatal(err)
	}

	ec := mustECDSA(t, elliptic.P256())
	r, s, err := ecdsa.Sign(rand.Reader, ec, digestOf(crypto.SHA256, attest))
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	if err := q.VerifySignature(&ec.PublicKey, raw); err != nil {
		t.Fatalf("raw r||s: %v", err)
	}

	rk := mustRSA(t)
	pkcs, err := rsa.SignPKCS1v15(rand.Reader, rk, crypto.SHA256, digestOf(crypto.SHA256, attest))
	if err != nil {
		t.Fatal(err)
	}
	if err := q.VerifySignature(&rk.PublicKey, pkcs); err != nil {
		t.Fatalf("RSASSA: %v", err)
	}
	pss, err := rsa.SignPSS(rand.Reader, rk, crypto.SHA256, digestOf(crypto.SHA256, attest), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.VerifySignature(&rk.PublicKey, pss); err != nil {
		t.Fatalf("RSA-PSS: %v", err)
	}
}

func TestVerifySignature_Failures(t *testing.T) {
	pcrs := pcrValues(32, 0)
	attest := buildAttest(t, quoteSpec{pcrs: pcrs, extra: []byte("n")})
	q, err := ParseQuote(attest)
	if err != nil {
		t.Fatal(err)
	}
	ec := mustECDSA(t, elliptic.P256())
	other := mustECDSA(t, elliptic.P256())
	sig := signECDSA(t, ec, crypto.SHA256, attest)
	wantClass(t, q.VerifySignature(&other.PublicKey, sig), ClassForged, CheckSignature, "ECDSA")
	wantClass(t, q.VerifySignature(&other.PublicKey, make([]byte, 64)), ClassForged, CheckSignature, "ECDSA")
	wantClass(t, q.VerifySignature(&mustRSA(t).PublicKey, sig), ClassForged, CheckSignature, "RSA")
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wantClass(t, q.VerifySignature(pub, sig), ClassForged, CheckSignature, "not supported")
	wantClass(t, q.VerifySignature(&ec.PublicKey, nil), ClassAbsent, CheckSignature, "no quote signature")
}

func TestParseQuote_Failures(t *testing.T) {
	pcrs := pcrValues(32, 0)
	good := buildAttest(t, quoteSpec{pcrs: pcrs})

	_, err := ParseQuote(nil)
	wantClass(t, err, ClassAbsent, CheckQuote, "no quote")

	_, err = ParseQuote([]byte{1, 2, 3})
	wantClass(t, err, ClassForged, CheckQuote, "not a TPMS_ATTEST")

	badMagic := append([]byte(nil), good...)
	badMagic[0] ^= 0xFF
	_, err = ParseQuote(badMagic)
	wantClass(t, err, ClassForged, CheckQuote, "")

	_, err = ParseQuote(buildAttest(t, quoteSpec{pcrs: pcrs, attestType: tpm2.TPMSTAttestCertify}))
	wantClass(t, err, ClassForged, CheckQuote, "not a TPM2_Quote")

	_, err = ParseQuote(buildAttest(t, quoteSpec{pcrs: pcrs, digest: make([]byte, 20)}))
	wantClass(t, err, ClassForged, CheckQuote, "names no supported hash")

	_, err = ParseQuote(buildAttest(t, quoteSpec{pcrs: pcrs, selections: []tpm2.TPMSPCRSelection{{Hash: tpm2.TPMAlgSHA256, PCRSelect: []byte{0, 0, 0}}}}))
	wantClass(t, err, ClassAbsent, CheckQuote, "selects no PCRs")

	_, err = ParseQuote(buildAttest(t, quoteSpec{pcrs: pcrs, selections: []tpm2.TPMSPCRSelection{
		{Hash: tpm2.TPMAlgSHA256, PCRSelect: tpm2.PCClientCompatible.PCRs(0)},
		{Hash: tpm2.TPMAlgSHA384, PCRSelect: tpm2.PCClientCompatible.PCRs(0)},
	}}))
	wantClass(t, err, ClassAbsent, CheckQuote, "2 PCR banks")

	_, err = ParseQuote(buildAttest(t, quoteSpec{pcrs: pcrs, selections: []tpm2.TPMSPCRSelection{{Hash: tpm2.TPMAlgSHA1, PCRSelect: tpm2.PCClientCompatible.PCRs(0)}}}))
	wantClass(t, err, ClassAbsent, CheckQuote, "not accepted")
}

func TestVerifyPCRValues(t *testing.T) {
	pcrs := pcrValues(32, 0, 7)
	q, err := ParseQuote(buildAttest(t, quoteSpec{pcrs: pcrs}))
	if err != nil {
		t.Fatal(err)
	}
	if err := q.VerifyPCRValues(pcrs); err != nil {
		t.Fatalf("VerifyPCRValues: %v", err)
	}
	wantClass(t, q.VerifyPCRValues(nil), ClassAbsent, CheckPCRDigest, "no PCR values")
	wantClass(t, q.VerifyPCRValues(pcrValues(32, 0)), ClassForged, CheckPCRDigest, "does not equal the quoted selection")
	wantClass(t, q.VerifyPCRValues(pcrValues(32, 0, 8)), ClassForged, CheckPCRDigest, "does not equal the quoted selection")
	short := pcrValues(32, 0, 7)
	short[7] = short[7][:20]
	wantClass(t, q.VerifyPCRValues(short), ClassForged, CheckPCRDigest, "32-byte registers")
	tampered := pcrValues(32, 0, 7)
	tampered[7][0] ^= 1
	wantClass(t, q.VerifyPCRValues(tampered), ClassForged, CheckPCRDigest, "do not hash")
}

func TestVerifyQualifyingData(t *testing.T) {
	q, err := ParseQuote(buildAttest(t, quoteSpec{pcrs: pcrValues(32, 0), extra: []byte("nonce")}))
	if err != nil {
		t.Fatal(err)
	}
	if err := q.VerifyQualifyingData([]byte("nonce")); err != nil {
		t.Fatal(err)
	}
	wantClass(t, q.VerifyQualifyingData([]byte("other")), ClassForged, CheckQualifyingData, "expected value")
	wantClass(t, q.VerifyQualifyingData(nil), ClassAbsent, CheckQualifyingData, "no qualifying data")
}

func TestVerifyQuote_Failures(t *testing.T) {
	key := mustECDSA(t, elliptic.P256())
	pcrs := pcrValues(32, 0)
	attest := buildAttest(t, quoteSpec{pcrs: pcrs, extra: []byte("n")})
	sig := signECDSA(t, key, crypto.SHA256, attest)
	good := QuoteInput{Attest: attest, Signature: sig, Key: &key.PublicKey, QualifyingData: []byte("n"), PCRs: pcrs}

	for name, tc := range map[string]struct {
		mutate func(*QuoteInput)
		class  Class
		check  string
	}{
		"no attest":    {func(in *QuoteInput) { in.Attest = nil }, ClassAbsent, CheckQuote},
		"no signature": {func(in *QuoteInput) { in.Signature = nil }, ClassAbsent, CheckSignature},
		"no key":       {func(in *QuoteInput) { in.Key = nil }, ClassAbsent, CheckSignature},
		"no qd":        {func(in *QuoteInput) { in.QualifyingData = nil }, ClassAbsent, CheckQualifyingData},
		"no pcrs":      {func(in *QuoteInput) { in.PCRs = nil }, ClassAbsent, CheckPCRDigest},
		"garbage":      {func(in *QuoteInput) { in.Attest = []byte{0} }, ClassForged, CheckQuote},
		"bad sig":      {func(in *QuoteInput) { in.Signature = signECDSA(t, key, crypto.SHA256, []byte("x")) }, ClassForged, CheckSignature},
		"wrong nonce":  {func(in *QuoteInput) { in.QualifyingData = []byte("m") }, ClassForged, CheckQualifyingData},
		"wrong pcrs":   {func(in *QuoteInput) { in.PCRs = pcrValues(32, 1) }, ClassForged, CheckPCRDigest},
	} {
		t.Run(name, func(t *testing.T) {
			in := good
			tc.mutate(&in)
			_, err := VerifyQuote(in)
			wantClass(t, err, tc.class, tc.check, "")
		})
	}
}

func TestComparePCRs(t *testing.T) {
	ref := pcrValues(32, 0, 7)
	if err := ComparePCRs(pcrValues(32, 0, 7), ref); err != nil {
		t.Fatal(err)
	}
	wantClass(t, ComparePCRs(pcrValues(32, 0), nil), ClassAbsent, CheckBaseline, "no reference")
	wantClass(t, ComparePCRs(pcrValues(32, 0), ref), ClassAbsent, CheckBaseline, "does not equal the baseline set")
	wantClass(t, ComparePCRs(pcrValues(32, 0, 8), ref), ClassAbsent, CheckBaseline, "does not equal the baseline set")
	diverged := pcrValues(32, 0, 7)
	diverged[7][3] ^= 1
	wantClass(t, ComparePCRs(diverged, ref), ClassForged, CheckBaseline, "PCR [7] diverges")
}

func TestBankDigestSize(t *testing.T) {
	if n, ok := BankDigestSize(tpm2.TPMAlgSHA384); !ok || n != 48 {
		t.Fatalf("SHA-384 = %d %v", n, ok)
	}
	if _, ok := BankDigestSize(tpm2.TPMAlgSHA1); ok {
		t.Fatal("SHA-1 bank accepted")
	}
}

func TestErrorFormatting(t *testing.T) {
	cause := errors.New("cause")
	e := &Error{Class: ClassForged, Check: CheckQuote, Reason: "r", Cause: cause}
	if e.Error() != "evidence: quote: r" || !errors.Is(e, cause) || errors.Is(e, ErrAbsent) {
		t.Fatalf("Error() = %q", e.Error())
	}
	if ClassForged.String() != "forged" || ClassAbsent.String() != "absent" || Class(0).String() != "unknown" {
		t.Fatal("Class.String")
	}
}
