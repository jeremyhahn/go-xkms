// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package peer

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
)

// verify runs the fixture verifier and fails the test on an error.
func verify(t *testing.T, f *fixture, ev Evidence, pol Policy) Verdict {
	t.Helper()
	v, err := f.verifier().Verify(context.Background(), ev, pol)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return v
}

// expectFailure asserts a negative verdict of the given class whose reason
// mentions want, and that the named check is the one reported false.
func expectFailure(t *testing.T, v Verdict, class FailureClass, want string, failed func(Checks) bool) {
	t.Helper()
	if v.Passed {
		t.Fatalf("verdict passed; want failure %q", want)
	}
	if v.Failure != class {
		t.Fatalf("failure class = %s, want %s (reason %q)", v.Failure, class, v.Reason)
	}
	if !strings.Contains(v.Reason, want) {
		t.Fatalf("reason %q does not mention %q", v.Reason, want)
	}
	if failed(v.Checks) {
		t.Fatalf("the check under test is reported as holding: %+v", v.Checks)
	}
}

func TestVerify_PassesWithRSAKey(t *testing.T) {
	f := newFixture(t)
	v := verify(t, f, f.evidence(t), f.policy())
	if !v.Passed {
		t.Fatalf("verdict failed: %s", v.Reason)
	}
	if v.Checks != allChecks {
		t.Fatalf("checks = %+v", v.Checks)
	}
	if v.Failure != FailureNone || v.Reason != "" {
		t.Fatalf("failure = %s %q on a pass", v.Failure, v.Reason)
	}
	if !v.VerifiedAt.Equal(fixtureNow) {
		t.Fatalf("VerifiedAt = %v", v.VerifiedAt)
	}
	if v.EvidenceAge != time.Minute {
		t.Fatalf("EvidenceAge = %v", v.EvidenceAge)
	}
	if len(v.PCRs) != 3 || !bytes.Equal(v.PCRs[10], f.pcrs[10]) {
		t.Fatalf("proven PCRs = %v", v.PCRs)
	}
}

func TestVerify_ProvenPCRsDoNotAliasEvidence(t *testing.T) {
	f := newFixture(t)
	ev := f.evidence(t)
	v := verify(t, f, ev, f.policy())
	ev.PCRs[10][0] ^= 0xff
	if !bytes.Equal(v.PCRs[10], f.pcrs[10]) {
		t.Fatal("verdict PCRs alias the evidence buffers")
	}
}

func TestVerify_PassesWithRSAPSSSignature(t *testing.T) {
	f := newFixture(t)
	ev := f.evidence(t)
	ev.Signature = signRSAPSS(t, f.key, crypto.SHA256, ev.Quote)
	if v := verify(t, f, ev, f.policy()); !v.Passed {
		t.Fatalf("RSA-PSS verdict failed: %s", v.Reason)
	}
}

func TestVerify_PassesWithECDSAKey(t *testing.T) {
	for name, raw := range map[string]bool{"asn1": false, "raw": true} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			key := newECKey(t, elliptic.P256())
			ev := f.evidence(t)
			ev.AKCertificatePEM = f.ca.issueAK(t, &key.PublicKey, akCertOptions{})
			if raw {
				ev.Signature = signECDSARaw(t, key, crypto.SHA256, ev.Quote)
			} else {
				ev.Signature = signECDSAASN1(t, key, crypto.SHA256, ev.Quote)
			}
			if v := verify(t, f, ev, f.policy()); !v.Passed {
				t.Fatalf("ECDSA verdict failed: %s", v.Reason)
			}
		})
	}
}

func TestVerify_PassesWithSHA384BankAndP384Key(t *testing.T) {
	f := newFixture(t)
	key := newECKey(t, elliptic.P384())
	f.pcrs = map[int][]byte{0: fillPCR(0x01, 48), 10: fillPCR(0x0a, 48)}
	quoted := buildQuote(t, f.nonce, f.pcrs, quoteOptions{bank: tpm2.TPMAlgSHA384})
	ev := f.evidenceFor(t, quoted)
	ev.AKCertificatePEM = f.ca.issueAK(t, &key.PublicKey, akCertOptions{})
	ev.Signature = signECDSAASN1(t, key, crypto.SHA384, quoted)
	if v := verify(t, f, ev, f.policy()); !v.Passed {
		t.Fatalf("SHA-384 verdict failed: %s", v.Reason)
	}
}

func TestVerify_ReportsTPMClock(t *testing.T) {
	f := newFixture(t)
	clock := tpm2.TPMSClockInfo{Clock: 123456, ResetCount: 3, RestartCount: 1, Safe: true}
	ev := f.evidenceFor(t, buildQuote(t, f.nonce, f.pcrs, quoteOptions{clock: clock, firmware: 0x0102}))
	v := verify(t, f, ev, f.policy())
	if v.Clock != (ClockInfo{Clock: 123456, ResetCount: 3, RestartCount: 1, Safe: true}) {
		t.Fatalf("Clock = %+v", v.Clock)
	}
	if v.FirmwareVersion != 0x0102 {
		t.Fatalf("FirmwareVersion = %#x", v.FirmwareVersion)
	}
}

// --- AK certificate -------------------------------------------------------

func TestVerify_NoCertificateIsAbsence(t *testing.T) {
	f := newFixture(t)
	ev := f.evidence(t)
	ev.AKCertificatePEM = nil
	v := verify(t, f, ev, f.policy())
	expectFailure(t, v, FailureAbsence, "no attestation key certificate", func(c Checks) bool { return c.AKCertificate })
	if v.Checks.Signature {
		t.Fatal("signature reported as verified with no trusted key")
	}
	if v.PCRs != nil {
		t.Fatal("PCR values reported as proven with no trusted key")
	}
}

func TestVerify_NoAnchorsIsAbsence(t *testing.T) {
	f := newFixture(t)
	pol := f.policy()
	pol.Anchors = nil
	v := verify(t, f, f.evidence(t), pol)
	expectFailure(t, v, FailureAbsence, "no trust anchors", func(c Checks) bool { return c.AKCertificate })
}

func TestVerify_UnrestrictedCertificateIsRefused(t *testing.T) {
	f := newFixture(t)
	ev := f.evidence(t)
	ev.AKCertificatePEM = f.ca.issueAK(t, &f.key.PublicKey, akCertOptions{unrestricted: true})
	v := verify(t, f, ev, f.policy())
	expectFailure(t, v, FailureCryptographic, "tcg-cap-verifiedTPMRestricted", func(c Checks) bool { return c.AKCertificate })

	pol := f.policy()
	pol.AllowUnrestrictedAK = true
	if v := verify(t, f, ev, pol); !v.Passed {
		t.Fatalf("AllowUnrestrictedAK did not waive the requirement: %s", v.Reason)
	}
}

func TestVerify_LegacyPolicyIdentifierIsAccepted(t *testing.T) {
	f := newFixture(t)
	ev := f.evidence(t)
	leaf, _, fail := parseAKCertificates(ev.AKCertificatePEM)
	if fail != nil {
		t.Fatal(fail.reason)
	}
	leaf.Policies = nil
	leaf.PolicyIdentifiers = append(leaf.PolicyIdentifiers, oidTCGVerifiedTPMRestricted)
	if !carriesVerifiedTPMRestricted(leaf) {
		t.Fatal("legacy PolicyIdentifiers form not recognised")
	}
	leaf.PolicyIdentifiers = nil
	if carriesVerifiedTPMRestricted(leaf) {
		t.Fatal("certificate with no policies reported as Restricted")
	}
}

func TestVerify_CertificateFromForeignCAIsCryptographic(t *testing.T) {
	f := newFixture(t)
	other := newTestCA(t)
	ev := f.evidence(t)
	ev.AKCertificatePEM = other.issueAK(t, &f.key.PublicKey, akCertOptions{})
	v := verify(t, f, ev, f.policy())
	expectFailure(t, v, FailureCryptographic, "does not chain", func(c Checks) bool { return c.AKCertificate })
}

func TestVerify_ExpiredCertificateIsCryptographic(t *testing.T) {
	f := newFixture(t)
	ev := f.evidence(t)
	ev.AKCertificatePEM = f.ca.issueAK(t, &f.key.PublicKey, akCertOptions{notAfter: fixtureNow.Add(-time.Second)})
	v := verify(t, f, ev, f.policy())
	expectFailure(t, v, FailureCryptographic, "does not chain", func(c Checks) bool { return c.AKCertificate })
}

func TestVerify_IntermediateCarriedInEvidenceCompletesChain(t *testing.T) {
	f := newFixture(t)
	ev := f.evidence(t)
	ev.AKCertificatePEM = append(ev.AKCertificatePEM, pemCertificate(f.ca.intermediate)...)
	pol := f.policy()
	pol.Intermediates = nil
	if v := verify(t, f, ev, pol); !v.Passed {
		t.Fatalf("chain with evidence-carried intermediate failed: %s", v.Reason)
	}
}

func TestVerify_MissingIntermediateIsCryptographic(t *testing.T) {
	f := newFixture(t)
	pol := f.policy()
	pol.Intermediates = nil
	v := verify(t, f, f.evidence(t), pol)
	expectFailure(t, v, FailureCryptographic, "does not chain", func(c Checks) bool { return c.AKCertificate })
}

func TestVerify_MalformedCertificateIsCryptographic(t *testing.T) {
	f := newFixture(t)
	for name, pemBytes := range map[string][]byte{
		"not pem":     []byte("garbage"),
		"wrong block": []byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"),
		"bad der":     []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
	} {
		t.Run(name, func(t *testing.T) {
			ev := f.evidence(t)
			ev.AKCertificatePEM = pemBytes
			v := verify(t, f, ev, f.policy())
			expectFailure(t, v, FailureCryptographic, "attestation key certificate", func(c Checks) bool { return c.AKCertificate })
		})
	}
}

// --- quote structure -------------------------------------------------------

func TestVerify_NoQuoteIsAbsence(t *testing.T) {
	f := newFixture(t)
	ev := f.evidence(t)
	ev.Quote = nil
	v := verify(t, f, ev, f.policy())
	expectFailure(t, v, FailureAbsence, "no quote", func(c Checks) bool { return c.Signature || c.Nonce || c.PCRDigest })
}

func TestVerify_MalformedQuoteIsCryptographic(t *testing.T) {
	f := newFixture(t)
	ev := f.evidence(t)
	ev.Quote = []byte{0xff, 0x54, 0x43, 0x47, 0x00}
	v := verify(t, f, ev, f.policy())
	expectFailure(t, v, FailureCryptographic, "not a TPMS_ATTEST", func(c Checks) bool { return c.Signature || c.Nonce || c.PCRDigest || c.RequiredPCRs })
}

func TestVerify_WrongMagicIsCryptographic(t *testing.T) {
	f := newFixture(t)
	quoted := buildQuote(t, f.nonce, f.pcrs, quoteOptions{magic: 0x01020304})
	v := verify(t, f, f.evidenceFor(t, quoted), f.policy())
	expectFailure(t, v, FailureCryptographic, "TPM_GENERATED_VALUE", func(c Checks) bool { return c.Nonce })
}

func TestVerify_CertifyStructureIsNotAQuote(t *testing.T) {
	f := newFixture(t)
	quoted := buildQuote(t, f.nonce, f.pcrs, quoteOptions{attestType: tpm2.TPMSTAttestCertify})
	v := verify(t, f, f.evidenceFor(t, quoted), f.policy())
	expectFailure(t, v, FailureCryptographic, "not a TPM2_Quote", func(c Checks) bool { return c.Nonce })
}

func TestVerify_UnknownDigestLengthIsCryptographic(t *testing.T) {
	f := newFixture(t)
	quoted := buildQuote(t, f.nonce, f.pcrs, quoteOptions{digest: fillPCR(0x00, 20)})
	v := verify(t, f, f.evidenceFor(t, quoted), f.policy())
	expectFailure(t, v, FailureCryptographic, "names no supported hash", func(c Checks) bool { return c.PCRDigest })
}

func TestVerify_EmptySelectionIsAbsence(t *testing.T) {
	f := newFixture(t)
	quoted := buildQuote(t, f.nonce, f.pcrs, quoteOptions{noSelection: true})
	v := verify(t, f, f.evidenceFor(t, quoted), f.policy())
	expectFailure(t, v, FailureAbsence, "selects no PCRs", func(c Checks) bool { return c.PCRDigest })
}

func TestVerify_MultiBankSelectionIsAbsence(t *testing.T) {
	f := newFixture(t)
	quoted := buildQuote(t, f.nonce, f.pcrs, quoteOptions{extraBank: true})
	v := verify(t, f, f.evidenceFor(t, quoted), f.policy())
	expectFailure(t, v, FailureAbsence, "2 PCR banks", func(c Checks) bool { return c.PCRDigest })
}

func TestVerify_SHA1BankIsAbsence(t *testing.T) {
	f := newFixture(t)
	f.pcrs = map[int][]byte{0: fillPCR(0x01, 20), 10: fillPCR(0x0a, 20)}
	// A SHA-1 bank quoted by a SHA-256 signing scheme: the digest is 32 bytes.
	quoted := buildQuote(t, f.nonce, f.pcrs, quoteOptions{bank: tpm2.TPMAlgSHA1, digestHash: crypto.SHA256})
	v := verify(t, f, f.evidenceFor(t, quoted), f.policy())
	expectFailure(t, v, FailureAbsence, "not accepted", func(c Checks) bool { return c.PCRDigest })
}

// --- signature -------------------------------------------------------------

func TestVerify_NoSignatureIsAbsence(t *testing.T) {
	f := newFixture(t)
	ev := f.evidence(t)
	ev.Signature = nil
	v := verify(t, f, ev, f.policy())
	expectFailure(t, v, FailureAbsence, "no quote signature", func(c Checks) bool { return c.Signature })
}

func TestVerify_BadSignatureIsCryptographic(t *testing.T) {
	f := newFixture(t)
	ev := f.evidence(t)
	ev.Signature[len(ev.Signature)/2] ^= 0x01
	v := verify(t, f, ev, f.policy())
	expectFailure(t, v, FailureCryptographic, "signature does not verify", func(c Checks) bool { return c.Signature })
	if v.Checks.Baseline || v.PCRs != nil {
		t.Fatal("PCR values treated as proven under a bad signature")
	}
}

func TestVerify_SignatureFromAnotherKeyIsCryptographic(t *testing.T) {
	f := newFixture(t)
	other := newRSAKey(t)
	ev := f.evidence(t)
	ev.Signature = signRSAPKCS1(t, other, crypto.SHA256, ev.Quote)
	v := verify(t, f, ev, f.policy())
	expectFailure(t, v, FailureCryptographic, "(RSA)", func(c Checks) bool { return c.Signature })
}

func TestVerify_BadECDSASignatureIsCryptographic(t *testing.T) {
	f := newFixture(t)
	key := newECKey(t, elliptic.P256())
	ev := f.evidence(t)
	ev.AKCertificatePEM = f.ca.issueAK(t, &key.PublicKey, akCertOptions{})
	ev.Signature = signECDSARaw(t, key, crypto.SHA256, ev.Quote)
	ev.Signature[3] ^= 0x01
	v := verify(t, f, ev, f.policy())
	expectFailure(t, v, FailureCryptographic, "(ECDSA)", func(c Checks) bool { return c.Signature })
}

func TestVerify_TamperedQuoteFailsSignature(t *testing.T) {
	f := newFixture(t)
	ev := f.evidence(t)
	// Flip a bit inside the PCR digest: the structure still parses, the
	// signature no longer covers it.
	ev.Quote[len(ev.Quote)-1] ^= 0x01
	v := verify(t, f, ev, f.policy())
	expectFailure(t, v, FailureCryptographic, "signature does not verify", func(c Checks) bool { return c.Signature })
}

// --- nonce and channel binding ---------------------------------------------

func TestVerify_NoNonceIsAbsence(t *testing.T) {
	f := newFixture(t)
	ev := f.evidence(t)
	ev.Nonce = nil
	v := verify(t, f, ev, f.policy())
	expectFailure(t, v, FailureAbsence, "no nonce", func(c Checks) bool { return c.Nonce || c.ChannelBinding })
}

func TestVerify_WrongNonceIsCryptographic(t *testing.T) {
	f := newFixture(t)
	quoted := buildQuote(t, []byte("a-different-nonce"), f.pcrs, quoteOptions{})
	v := verify(t, f, f.evidenceFor(t, quoted), f.policy())
	expectFailure(t, v, FailureCryptographic, "does not carry the verifier's nonce", func(c Checks) bool { return c.Nonce })
	if !v.Checks.Signature {
		t.Fatal("a replayed quote still carries a valid signature; the nonce is what must fail")
	}
	if v.PCRs != nil {
		t.Fatal("PCR values of a replayed quote reported as proven")
	}
}

func TestVerify_ChannelBindingPasses(t *testing.T) {
	f := newFixture(t)
	binding := fillPCR(0xcb, 32)
	quoted := buildQuote(t, f.nonce, f.pcrs, quoteOptions{extraData: QualifyingData(f.nonce, binding)})
	pol := f.policy()
	pol.ChannelBinding = binding
	v := verify(t, f, f.evidenceFor(t, quoted), pol)
	if !v.Passed {
		t.Fatalf("bound quote failed: %s", v.Reason)
	}
	if !v.Checks.ChannelBinding || !v.Checks.Nonce {
		t.Fatalf("checks = %+v", v.Checks)
	}
}

func TestVerify_ChannelBindingMismatchIsCryptographic(t *testing.T) {
	f := newFixture(t)
	quoted := buildQuote(t, f.nonce, f.pcrs, quoteOptions{extraData: QualifyingData(f.nonce, fillPCR(0x01, 32))})
	pol := f.policy()
	pol.ChannelBinding = fillPCR(0x02, 32)
	v := verify(t, f, f.evidenceFor(t, quoted), pol)
	expectFailure(t, v, FailureCryptographic, "binding to this channel", func(c Checks) bool { return c.Nonce || c.ChannelBinding })
}

func TestVerify_UnboundQuoteUnderBindingPolicyIsCryptographic(t *testing.T) {
	f := newFixture(t)
	pol := f.policy()
	pol.ChannelBinding = fillPCR(0x02, 32)
	v := verify(t, f, f.evidence(t), pol)
	expectFailure(t, v, FailureCryptographic, "bare nonce", func(c Checks) bool { return c.ChannelBinding })
	if !v.Checks.Nonce {
		t.Fatal("the nonce itself was echoed and must be reported as such")
	}
}

func TestVerify_BoundQuoteUnderUnboundPolicyFailsNonce(t *testing.T) {
	f := newFixture(t)
	quoted := buildQuote(t, f.nonce, f.pcrs, quoteOptions{extraData: QualifyingData(f.nonce, fillPCR(0x01, 32))})
	v := verify(t, f, f.evidenceFor(t, quoted), f.policy())
	expectFailure(t, v, FailureCryptographic, "does not carry the verifier's nonce", func(c Checks) bool { return c.Nonce })
}

// --- PCR digest -------------------------------------------------------------

func TestVerify_NoPCRValuesIsAbsence(t *testing.T) {
	f := newFixture(t)
	ev := f.evidence(t)
	ev.PCRs = nil
	v := verify(t, f, ev, f.policy())
	expectFailure(t, v, FailureAbsence, "no PCR values", func(c Checks) bool { return c.PCRDigest })
}

func TestVerify_ReportedValuesNotMatchingDigestIsCryptographic(t *testing.T) {
	f := newFixture(t)
	ev := f.evidence(t)
	ev.PCRs[7][0] ^= 0x01
	v := verify(t, f, ev, f.policy())
	expectFailure(t, v, FailureCryptographic, "do not hash to the signed PCR digest", func(c Checks) bool { return c.PCRDigest })
	if v.Checks.Baseline || v.PCRs != nil {
		t.Fatal("unproven values reached the baseline comparison")
	}
}

func TestVerify_ReportedSetNotMatchingSelectionIsCryptographic(t *testing.T) {
	f := newFixture(t)
	for name, mutate := range map[string]func(map[int][]byte){
		"extra":   func(m map[int][]byte) { m[14] = fillPCR(0x14, 32) },
		"missing": func(m map[int][]byte) { delete(m, 10) },
		"swapped": func(m map[int][]byte) { m[11] = m[10]; delete(m, 10) },
	} {
		t.Run(name, func(t *testing.T) {
			ev := f.evidence(t)
			mutate(ev.PCRs)
			v := verify(t, f, ev, f.policy())
			expectFailure(t, v, FailureCryptographic, "does not equal the quoted selection", func(c Checks) bool { return c.PCRDigest })
		})
	}
}

func TestVerify_WrongValueLengthIsCryptographic(t *testing.T) {
	f := newFixture(t)
	ev := f.evidence(t)
	ev.PCRs[0] = fillPCR(0x11, 20)
	v := verify(t, f, ev, f.policy())
	expectFailure(t, v, FailureCryptographic, "20 bytes", func(c Checks) bool { return c.PCRDigest })
}

// --- required PCRs ------------------------------------------------------------

func TestVerify_RequiredPCRNotQuotedIsAbsence(t *testing.T) {
	f := newFixture(t)
	// The peer quotes the firmware registers only and reports honestly.
	f.pcrs = map[int][]byte{0: fillPCR(0x11, 32), 7: fillPCR(0x77, 32)}
	pol := f.policy()
	pol.Baseline = copyPCRs(f.pcrs)
	pol.Baseline[10] = fillPCR(0xaa, 32)
	v := verify(t, f, f.evidence(t), pol)
	expectFailure(t, v, FailureAbsence, "required PCR [10] was not quoted", func(c Checks) bool { return c.RequiredPCRs })
	if v.Checks.Baseline {
		t.Fatal("a quote that omits PCR 10 must not satisfy a baseline that includes it")
	}
}

func TestVerify_NoRequiredPCRsHolds(t *testing.T) {
	f := newFixture(t)
	pol := f.policy()
	pol.RequiredPCRs = nil
	if v := verify(t, f, f.evidence(t), pol); !v.Passed || !v.Checks.RequiredPCRs {
		t.Fatalf("verdict = %+v", v)
	}
}

// --- baseline -----------------------------------------------------------------

func TestVerify_IMADivergenceWhileFirmwareMatchesIsCryptographic(t *testing.T) {
	f := newFixture(t)
	// The peer's userspace changed: PCR 10 moved, PCR 0 and 7 did not. The
	// peer reports its real values, so the digest proves them.
	f.pcrs[10] = fillPCR(0xab, 32)
	pol := f.policy()
	pol.Baseline = goldenPCRs()
	v := verify(t, f, f.evidence(t), pol)
	expectFailure(t, v, FailureCryptographic, "PCR [10] diverges", func(c Checks) bool { return c.Baseline })
	if !v.Checks.PCRDigest || !v.Checks.Signature {
		t.Fatalf("the divergence must be proven, not a digest failure: %+v", v.Checks)
	}
	if v.PCRs == nil {
		t.Fatal("proven values must be reported alongside the divergence")
	}
}

func TestVerify_AllDivergentPCRsAreNamed(t *testing.T) {
	f := newFixture(t)
	f.pcrs[7] = fillPCR(0x78, 32)
	f.pcrs[10] = fillPCR(0xab, 32)
	pol := f.policy()
	pol.Baseline = goldenPCRs()
	v := verify(t, f, f.evidence(t), pol)
	expectFailure(t, v, FailureCryptographic, "PCR [7,10] diverges", func(c Checks) bool { return c.Baseline })
}

func TestVerify_NoBaselineIsAbsenceWithProvenValues(t *testing.T) {
	f := newFixture(t)
	pol := f.policy()
	pol.Baseline = nil
	pol.RequiredPCRs = nil
	v := verify(t, f, f.evidence(t), pol)
	expectFailure(t, v, FailureAbsence, "no PCR baseline", func(c Checks) bool { return c.Baseline })
	// The trust-on-first-use consumer relies on this: everything else held
	// and the values are proven, so they may be captured as a baseline.
	if !v.Checks.AKCertificate || !v.Checks.Signature || !v.Checks.Nonce || !v.Checks.PCRDigest {
		t.Fatalf("checks = %+v", v.Checks)
	}
	if len(v.PCRs) != 3 {
		t.Fatalf("proven PCRs = %v", v.PCRs)
	}
}

func TestVerify_BaselineSetMismatchIsAbsence(t *testing.T) {
	f := newFixture(t)
	pol := f.policy()
	pol.Baseline[14] = fillPCR(0x14, 32)
	v := verify(t, f, f.evidence(t), pol)
	expectFailure(t, v, FailureAbsence, "does not equal the baseline set", func(c Checks) bool { return c.Baseline })
}

func TestVerify_BaselineNotEvaluatedWhenValuesUnproven(t *testing.T) {
	f := newFixture(t)
	ev := f.evidence(t)
	ev.AKCertificatePEM = nil
	v := verify(t, f, ev, f.policy())
	if !strings.Contains(v.Reason, "baseline not evaluated") || v.Checks.Baseline {
		t.Fatalf("verdict = %+v", v)
	}
}

// --- freshness --------------------------------------------------------------

func TestVerify_StaleEvidenceIsAbsence(t *testing.T) {
	f := newFixture(t)
	ev := f.evidence(t)
	ev.CollectedAt = fixtureNow.Add(-11 * time.Minute)
	v := verify(t, f, ev, f.policy())
	expectFailure(t, v, FailureAbsence, "11m0s old", func(c Checks) bool { return c.Freshness })
	if v.EvidenceAge != 11*time.Minute {
		t.Fatalf("EvidenceAge = %v", v.EvidenceAge)
	}
	if !v.Checks.Signature || !v.Checks.Baseline {
		t.Fatal("stale evidence is still cryptographically sound; only freshness fails")
	}
}

func TestVerify_EvidenceAtExactlyMaxAgePasses(t *testing.T) {
	f := newFixture(t)
	ev := f.evidence(t)
	ev.CollectedAt = fixtureNow.Add(-10 * time.Minute)
	if v := verify(t, f, ev, f.policy()); !v.Passed {
		t.Fatalf("evidence at the bound failed: %s", v.Reason)
	}
}

func TestVerify_UndatedEvidenceUnderAgePolicyIsAbsence(t *testing.T) {
	f := newFixture(t)
	ev := f.evidence(t)
	ev.CollectedAt = time.Time{}
	v := verify(t, f, ev, f.policy())
	expectFailure(t, v, FailureAbsence, "no collection time", func(c Checks) bool { return c.Freshness })
}

func TestVerify_FutureEvidenceIsAbsence(t *testing.T) {
	f := newFixture(t)
	ev := f.evidence(t)
	ev.CollectedAt = fixtureNow.Add(time.Second)
	v := verify(t, f, ev, f.policy())
	expectFailure(t, v, FailureAbsence, "in the verifier's future", func(c Checks) bool { return c.Freshness })
}

func TestVerify_NoMaxAgeSkipsFreshness(t *testing.T) {
	f := newFixture(t)
	ev := f.evidence(t)
	ev.CollectedAt = fixtureNow.Add(-48 * time.Hour)
	pol := f.policy()
	pol.MaxEvidenceAge = 0
	v := verify(t, f, ev, pol)
	if !v.Passed || v.EvidenceAge != 48*time.Hour {
		t.Fatalf("verdict = %+v", v)
	}
}

// --- classification ---------------------------------------------------------

func TestVerify_CryptographicDominatesAbsence(t *testing.T) {
	f := newFixture(t)
	ev := f.evidence(t)
	ev.Signature[0] ^= 0x01
	ev.CollectedAt = fixtureNow.Add(-time.Hour)
	v := verify(t, f, ev, f.policy())
	if v.Failure != FailureCryptographic {
		t.Fatalf("failure = %s; a bad signature beside stale evidence is still cryptographic", v.Failure)
	}
	if !strings.Contains(v.Reason, "signature") || !strings.Contains(v.Reason, "old") {
		t.Fatalf("reason %q must list every failure", v.Reason)
	}
}

func TestVerify_EmptyEvidenceIsAbsenceOnEveryCheck(t *testing.T) {
	f := newFixture(t)
	v := verify(t, f, Evidence{}, f.policy())
	if v.Passed || v.Failure != FailureAbsence {
		t.Fatalf("verdict = %+v", v)
	}
	if v.Checks != (Checks{}) {
		t.Fatalf("checks = %+v; nothing can hold with no evidence", v.Checks)
	}
}

// --- errors -----------------------------------------------------------------

func TestVerify_CancelledContextIsError(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.verifier().Verify(ctx, f.evidence(t), f.policy())
	var ce *ContextError
	if !errors.As(err, &ce) || !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestVerify_InvalidPolicyIsError(t *testing.T) {
	f := newFixture(t)
	for name, mutate := range map[string]func(*Policy){
		"negative age":         func(p *Policy) { p.MaxEvidenceAge = -time.Second },
		"negative baseline":    func(p *Policy) { p.Baseline[-1] = fillPCR(0, 32) },
		"empty baseline value": func(p *Policy) { p.Baseline[0] = nil },
		"negative required":    func(p *Policy) { p.RequiredPCRs = []int{-1} },
		"required no baseline": func(p *Policy) { p.RequiredPCRs = []int{14} },
	} {
		t.Run(name, func(t *testing.T) {
			pol := f.policy()
			mutate(&pol)
			_, err := f.verifier().Verify(context.Background(), f.evidence(t), pol)
			var pe *PolicyError
			if !errors.As(err, &pe) {
				t.Fatalf("err = %v, want *PolicyError", err)
			}
			if pe.Field == "" || !strings.Contains(err.Error(), "invalid policy") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestVerify_RequiredPCRWithoutAnyBaselineIsNotAPolicyError(t *testing.T) {
	// An empty baseline is a verdict-level absence, not a configuration
	// error, so a required PCR beside it must not turn into one.
	f := newFixture(t)
	pol := f.policy()
	pol.Baseline = nil
	v := verify(t, f, f.evidence(t), pol)
	if v.Failure != FailureAbsence || !v.Checks.RequiredPCRs {
		t.Fatalf("verdict = %+v", v)
	}
}

func TestNewVerifier_DefaultClockIsUTCNow(t *testing.T) {
	before := time.Now().UTC()
	v := NewVerifier().(*verifier)
	now := v.now()
	if now.Location() != time.UTC || now.Before(before) {
		t.Fatalf("default clock = %v", now)
	}
	// A nil clock option keeps the default.
	v = NewVerifier(WithClock(nil)).(*verifier)
	if v.now == nil {
		t.Fatal("nil clock accepted")
	}
}

func pemCertificate(cert *x509.Certificate) []byte {
	return pemEncode("CERTIFICATE", cert.Raw)
}

func TestVerify_UnsupportedAKKeyTypeIsCryptographic(t *testing.T) {
	f := newFixture(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ev := f.evidence(t)
	ev.AKCertificatePEM = f.ca.issueAK(t, pub, akCertOptions{})
	v := verify(t, f, ev, f.policy())
	expectFailure(t, v, FailureCryptographic, "unsupported public key type", func(c Checks) bool { return c.AKCertificate })
}

func TestVerify_BaselineSetOfSameSizeButDifferentIndicesIsAbsence(t *testing.T) {
	f := newFixture(t)
	pol := f.policy()
	pol.RequiredPCRs = nil
	delete(pol.Baseline, 10)
	pol.Baseline[14] = fillPCR(0x14, 32)
	v := verify(t, f, f.evidence(t), pol)
	expectFailure(t, v, FailureAbsence, "does not equal the baseline set [0,7,14]", func(c Checks) bool { return c.Baseline })
}
