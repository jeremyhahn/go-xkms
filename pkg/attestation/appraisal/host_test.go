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
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"slices"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
)

// launchPCR is the register these tests treat as the one a container runtime
// extends at launch: a PCR the boot event log never records.
const launchPCR = uint32(16)

// newHostWorld returns a tenant with endorsed "golden" reference values.
func newHostWorld(t *testing.T) *verifierWorld {
	t.Helper()
	w := newVerifierWorld(t)
	w.endorse(t)
	return w
}

// hostEvidence quotes pcrs under the world's attestation key and returns the
// host evidence naming referenceValues.
func (w *verifierWorld) hostEvidence(t *testing.T, pcrs map[uint32][]byte, referenceValues string) *HostEvidence {
	t.Helper()
	nonce := []byte("host-appraiser-nonce")
	quote, err := appraisaltest.SignQuote(w.ak, pcrs, nonce)
	if err != nil {
		t.Fatal(err)
	}
	return &HostEvidence{
		ReferenceValues: referenceValues,
		AKCertificate:   w.ak.Certificate,
		Nonce:           nonce,
		Quoted:          quote.Attest,
		Signature:       quote.Signature,
		PCRs:            pcrs,
	}
}

// putReferenceValues stores SHA-256 reference values for pcrs under name,
// signed by the endorsed reference signer.
func (w *verifierWorld) putReferenceValues(t *testing.T, name string, pcrs map[uint32][]byte) {
	t.Helper()
	w.putReferenceDigests(t, name, appraisaltest.SHA256Digests(pcrs))
}

// putReferenceDigests stores reference values holding digests under name,
// signed by the endorsed reference signer.
func (w *verifierWorld) putReferenceDigests(t *testing.T, name string, digests []appraisaltest.PCRDigest) {
	t.Helper()
	corim, err := appraisaltest.SignCoRIMDigests(digests, w.signerKey, []*x509.Certificate{w.signerCert})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.app.PutReferenceValues(w.ctx, w.tenant, &PutReferenceValuesRequest{Name: name, SignedCoRIM: corim}); err != nil {
		t.Fatalf("PutReferenceValues(%s): %v", name, err)
	}
}

func TestAppraiser_ReferencePCRs(t *testing.T) {
	w := newHostWorld(t)

	t.Run("ReadsTheStoredIndices", func(t *testing.T) {
		indices, err := w.app.ReferencePCRs(w.ctx, w.tenant, "golden", crypto.SHA256)
		if err != nil {
			t.Fatalf("ReferencePCRs: %v", err)
		}
		if want := []uint32{0, 4, 7}; !slices.Equal(indices, want) {
			t.Fatalf("indices = %v, want %v", indices, want)
		}
	})

	t.Run("OnlyTheQuotedBankIsCounted", func(t *testing.T) {
		w.putReferenceDigests(t, "mixed", []appraisaltest.PCRDigest{
			{Index: 0, Hash: crypto.SHA256, Value: bytes.Repeat([]byte{0x10}, sha256.Size)},
			{Index: 7, Hash: crypto.SHA384, Value: bytes.Repeat([]byte{0x17}, sha512.Size384)},
		})
		for bank, want := range map[crypto.Hash][]uint32{crypto.SHA256: {0}, crypto.SHA384: {7}} {
			indices, err := w.app.ReferencePCRs(w.ctx, w.tenant, "mixed", bank)
			if err != nil {
				t.Fatalf("ReferencePCRs(%s): %v", bank, err)
			}
			if !slices.Equal(indices, want) {
				t.Fatalf("ReferencePCRs(%s) = %v, want %v", bank, indices, want)
			}
		}
	})

	t.Run("OtherBankOnlyIsRefused", func(t *testing.T) {
		w.putReferenceDigests(t, "sha384-only", []appraisaltest.PCRDigest{
			{Index: 0, Hash: crypto.SHA384, Value: bytes.Repeat([]byte{0x20}, sha512.Size384)},
			{Index: 7, Hash: crypto.SHA384, Value: bytes.Repeat([]byte{0x27}, sha512.Size384)},
		})
		_, err := w.app.ReferencePCRs(w.ctx, w.tenant, "sha384-only", crypto.SHA256)
		assertBankUncovered(t, err, "sha384-only", crypto.SHA256)
	})

	t.Run("SHA1BankIsRefused", func(t *testing.T) {
		_, err := w.app.ReferencePCRs(w.ctx, w.tenant, "golden", crypto.SHA1)
		assertBankUncovered(t, err, "golden", crypto.SHA1)
	})

	t.Run("UnknownNameIsNotFound", func(t *testing.T) {
		_, err := w.app.ReferencePCRs(w.ctx, w.tenant, "missing", crypto.SHA256)
		if !errors.Is(err, ErrRecordNotFound) {
			t.Fatalf("ReferencePCRs(missing) = %v, want ErrRecordNotFound", err)
		}
	})

	t.Run("InvalidNameIsRefused", func(t *testing.T) {
		_, err := w.app.ReferencePCRs(w.ctx, w.tenant, "a/b", crypto.SHA256)
		if !errors.Is(err, ErrInvalidName) {
			t.Fatalf("ReferencePCRs(a/b) = %v, want ErrInvalidName", err)
		}
	})

	t.Run("InvalidTenantIsRefused", func(t *testing.T) {
		_, err := w.app.ReferencePCRs(w.ctx, "a/b", "golden", crypto.SHA256)
		if !errors.Is(err, ErrInvalidTenant) {
			t.Fatalf("ReferencePCRs with tenant a/b = %v, want ErrInvalidTenant", err)
		}
	})

	t.Run("NoLongerEndorsedIsRefused", func(t *testing.T) {
		w := newHostWorld(t)
		if err := w.app.DeleteEndorsement(w.ctx, w.tenant, &DeleteEndorsementRequest{Name: "rv-ca"}); err != nil {
			t.Fatalf("DeleteEndorsement: %v", err)
		}
		_, err := w.app.ReferencePCRs(w.ctx, w.tenant, "golden", crypto.SHA256)
		var rejected *ReferenceValuesRejectedError
		if !errors.As(err, &rejected) || !errors.Is(err, ErrReferenceValuesRejected) {
			t.Fatalf("ReferencePCRs with no reference signer = %v, want *ReferenceValuesRejectedError", err)
		}
	})
}

// assertBankUncovered fails t unless err reports that the reference values
// named name hold no digest in bank.
func assertBankUncovered(t *testing.T, err error, name string, bank crypto.Hash) {
	t.Helper()
	var uncovered *ReferenceBankUncoveredError
	if !errors.As(err, &uncovered) || !errors.Is(err, ErrReferenceBankUncovered) {
		t.Fatalf("ReferencePCRs(%s, %s) = %v, want *ReferenceBankUncoveredError", name, bank, err)
	}
	if uncovered.ReferenceValues != name || uncovered.Bank != bank {
		t.Fatalf("uncovered = %+v, want %s in %s", uncovered, name, bank)
	}
}

func TestAppraiser_AppraiseHost(t *testing.T) {
	w := newHostWorld(t)

	t.Run("GenuineEvidencePasses", func(t *testing.T) {
		appraisal, err := w.app.AppraiseHost(w.ctx, w.tenant, w.hostEvidence(t, w.pcrs, "golden"))
		if err != nil {
			t.Fatalf("AppraiseHost: %v", err)
		}
		if !appraisal.Verified || appraisal.CryptographicFailure || len(appraisal.Failures) != 0 {
			t.Fatalf("appraisal = %+v, want verified with no failures", appraisal)
		}
	})

	t.Run("DriftedPCRIsACryptographicFailure", func(t *testing.T) {
		drifted := appraisaltest.PCRValues(0, 4, 7)
		drifted[4] = bytes.Repeat([]byte{0xEE}, len(drifted[4]))
		appraisal, err := w.app.AppraiseHost(w.ctx, w.tenant, w.hostEvidence(t, drifted, "golden"))
		if err != nil {
			t.Fatalf("AppraiseHost: %v", err)
		}
		if appraisal.Verified || !appraisal.CryptographicFailure {
			t.Fatalf("appraisal = %+v, want an unverified cryptographic failure", appraisal)
		}
		if len(appraisal.Failures) != 1 {
			t.Fatalf("failures = %+v, want only the baseline", appraisal.Failures)
		}
		failure := appraisal.Failures[0]
		if failure.Check != AppraisalCheckBaseline || failure.Outcome != string(AppraisalForged) {
			t.Fatalf("failure = %+v, want a forged baseline", failure)
		}
		if len(failure.PCRs) != 1 || failure.PCRs[0].Index != 4 ||
			!bytes.Equal(failure.PCRs[0].Quoted, drifted[4]) ||
			len(failure.PCRs[0].Expected) != 1 || !bytes.Equal(failure.PCRs[0].Expected[0], w.pcrs[4]) {
			t.Fatalf("divergences = %+v, want PCR 4 with its expected and quoted digests", failure.PCRs)
		}
	})

	t.Run("UnknownNameIsAbsent", func(t *testing.T) {
		appraisal, err := w.app.AppraiseHost(w.ctx, w.tenant, w.hostEvidence(t, w.pcrs, "missing"))
		if err != nil {
			t.Fatalf("AppraiseHost: %v", err)
		}
		if appraisal.Verified || appraisal.CryptographicFailure {
			t.Fatalf("appraisal = %+v, want unverified without a cryptographic failure", appraisal)
		}
		if len(appraisal.Failures) != 1 || appraisal.Failures[0].Outcome != string(AppraisalAbsent) ||
			len(appraisal.Failures[0].PCRs) != 0 {
			t.Fatalf("failures = %+v, want one absent baseline with no PCR divergence", appraisal.Failures)
		}
	})

	t.Run("MissingAKCertificateIsAbsent", func(t *testing.T) {
		ev := w.hostEvidence(t, w.pcrs, "golden")
		ev.AKCertificate = nil
		appraisal, err := w.app.AppraiseHost(w.ctx, w.tenant, ev)
		if err != nil {
			t.Fatalf("AppraiseHost: %v", err)
		}
		if appraisal.Verified || appraisal.CryptographicFailure {
			t.Fatalf("appraisal = %+v, want unverified without a cryptographic failure", appraisal)
		}
		if appraisal.Failures[0].Check != AppraisalCheckAKCertificate {
			t.Fatalf("first failure = %+v, want the AK certificate check", appraisal.Failures[0])
		}
	})

	t.Run("InvalidTenantIsRefused", func(t *testing.T) {
		_, err := w.app.AppraiseHost(w.ctx, "a/b", w.hostEvidence(t, w.pcrs, "golden"))
		if !errors.Is(err, ErrInvalidTenant) {
			t.Fatalf("AppraiseHost with tenant a/b = %v, want ErrInvalidTenant", err)
		}
	})

	t.Run("NilEvidenceIsRefused", func(t *testing.T) {
		if _, err := w.app.AppraiseHost(w.ctx, w.tenant, nil); !errors.Is(err, ErrNilRequest) {
			t.Fatalf("AppraiseHost(nil) = %v, want ErrNilRequest", err)
		}
	})
}

// failureOf returns the failure of check in appraisal, or nil.
func failureOf(appraisal *HostAppraisal, check string) *HostAppraisalFailure {
	for i := range appraisal.Failures {
		if appraisal.Failures[i].Check == check {
			return &appraisal.Failures[i]
		}
	}
	return nil
}

// issueAKUnderIntermediate makes the world's attestation key one an
// intermediate of the endorsed AK root issued, and returns that intermediate.
// The tenant endorses only the root.
func (w *verifierWorld) issueAKUnderIntermediate(t *testing.T) *x509.Certificate {
	t.Helper()
	intermediate, err := appraisaltest.NewIntermediateAuthority(w.akCA, "AK Intermediate CA")
	if err != nil {
		t.Fatal(err)
	}
	if w.ak, err = appraisaltest.IssueAttestationKey(intermediate, true); err != nil {
		t.Fatal(err)
	}
	return intermediate.Certificate
}

// otherIntermediate returns an intermediate of the endorsed AK root that did
// not issue the world's attestation key.
func (w *verifierWorld) otherIntermediate(t *testing.T) *x509.Certificate {
	t.Helper()
	other, err := appraisaltest.NewIntermediateAuthority(w.akCA, "Other AK Intermediate CA")
	if err != nil {
		t.Fatal(err)
	}
	return other.Certificate
}

func TestAppraiser_AppraiseHostAKIntermediates(t *testing.T) {
	t.Run("SuppliedIntermediateChainsToTheEndorsedRoot", func(t *testing.T) {
		w := newHostWorld(t)
		intermediate := w.issueAKUnderIntermediate(t)
		ev := w.hostEvidence(t, w.pcrs, "golden")
		ev.AKIntermediates = []*x509.Certificate{intermediate}
		appraisal, err := w.app.AppraiseHost(w.ctx, w.tenant, ev)
		if err != nil {
			t.Fatalf("AppraiseHost: %v", err)
		}
		if !appraisal.Verified || len(appraisal.Failures) != 0 {
			t.Fatalf("appraisal = %+v, want verified with no failures", appraisal)
		}
	})

	forged := map[string]func(w *verifierWorld, t *testing.T, intermediate *x509.Certificate) []*x509.Certificate{
		"MissingIntermediateIsForged": func(*verifierWorld, *testing.T, *x509.Certificate) []*x509.Certificate {
			return nil
		},
		"AnotherIntermediateIsForged": func(w *verifierWorld, t *testing.T, _ *x509.Certificate) []*x509.Certificate {
			return []*x509.Certificate{w.otherIntermediate(t)}
		},
		"UnrelatedCertificateIsForged": func(w *verifierWorld, _ *testing.T, _ *x509.Certificate) []*x509.Certificate {
			return []*x509.Certificate{w.signerCert}
		},
	}
	for name, intermediates := range forged {
		t.Run(name, func(t *testing.T) {
			w := newHostWorld(t)
			intermediate := w.issueAKUnderIntermediate(t)
			ev := w.hostEvidence(t, w.pcrs, "golden")
			ev.AKIntermediates = intermediates(w, t, intermediate)
			appraisal, err := w.app.AppraiseHost(w.ctx, w.tenant, ev)
			if err != nil {
				t.Fatalf("AppraiseHost: %v", err)
			}
			if appraisal.Verified || !appraisal.CryptographicFailure {
				t.Fatalf("appraisal = %+v, want an unverified cryptographic failure", appraisal)
			}
			failure := failureOf(appraisal, AppraisalCheckAKCertificate)
			if failure == nil || failure.Outcome != string(AppraisalForged) {
				t.Fatalf("failures = %+v, want a forged AK certificate check", appraisal.Failures)
			}
		})
	}

	t.Run("IntermediatesWithoutTheLeafAreAbsent", func(t *testing.T) {
		w := newHostWorld(t)
		intermediate := w.issueAKUnderIntermediate(t)
		ev := w.hostEvidence(t, w.pcrs, "golden")
		ev.AKCertificate = nil
		ev.AKIntermediates = []*x509.Certificate{intermediate}
		appraisal, err := w.app.AppraiseHost(w.ctx, w.tenant, ev)
		if err != nil {
			t.Fatalf("AppraiseHost: %v", err)
		}
		failure := failureOf(appraisal, AppraisalCheckAKCertificate)
		if appraisal.Verified || failure == nil || failure.Outcome != string(AppraisalAbsent) {
			t.Fatalf("appraisal = %+v, want an absent AK certificate check", appraisal)
		}
	})

	t.Run("NilIntermediateIsRefused", func(t *testing.T) {
		w := newHostWorld(t)
		intermediate := w.issueAKUnderIntermediate(t)
		ev := w.hostEvidence(t, w.pcrs, "golden")
		ev.AKIntermediates = []*x509.Certificate{intermediate, nil}
		_, err := w.app.AppraiseHost(w.ctx, w.tenant, ev)
		if !errors.Is(err, ErrInvalidAKIntermediate) {
			t.Fatalf("AppraiseHost = %v, want ErrInvalidAKIntermediate", err)
		}
		var nilEntry *AKIntermediateError
		if !errors.As(err, &nilEntry) || nilEntry.Index != 1 {
			t.Fatalf("AppraiseHost = %v, want an *AKIntermediateError at index 1", err)
		}
	})
}

// TestAppraiser_EventLogLeavesTheLaunchPCROut drives host evidence whose
// quote covers boot registers, which the event log explains, and the launch
// register a container runtime extends, which only the signed reference
// values judge.
func TestAppraiser_EventLogLeavesTheLaunchPCROut(t *testing.T) {
	w := newHostWorld(t)
	digest := func(b byte) []byte { return bytes.Repeat([]byte{b}, sha256.Size) }
	bootLog, boot := appraisaltest.BootEventLog([]appraisaltest.LogEvent{
		{PCR: 0, Digest: digest(0x01)},
		{PCR: 7, Digest: digest(0x07)},
		{PCR: 0, Digest: digest(0x02)},
	})
	launched := appraisaltest.ExtendSHA256(make([]byte, sha256.Size), digest(0x16))
	measured := func() map[uint32][]byte {
		return map[uint32][]byte{0: boot[0], 7: boot[7], launchPCR: launched}
	}
	w.putReferenceValues(t, "measured", measured())

	appraise := func(t *testing.T, pcrs map[uint32][]byte, eventLog []byte, launchPCRs []uint32) *HostAppraisal {
		t.Helper()
		ev := w.hostEvidence(t, pcrs, "measured")
		ev.EventLog = eventLog
		ev.LaunchPCRs = launchPCRs
		appraisal, err := w.app.AppraiseHost(w.ctx, w.tenant, ev)
		if err != nil {
			t.Fatalf("AppraiseHost: %v", err)
		}
		return appraisal
	}

	t.Run("BootLogAndExtendedLaunchPCRPass", func(t *testing.T) {
		appraisal := appraise(t, measured(), bootLog, []uint32{launchPCR})
		if !appraisal.Verified || len(appraisal.Failures) != 0 {
			t.Fatalf("appraisal = %+v, want verified with no failures", appraisal)
		}
	})

	t.Run("ReplayingTheLaunchPCRWouldFail", func(t *testing.T) {
		// Without the launch register named, the replay demands its reset
		// value, which a measured launch never leaves behind.
		appraisal := appraise(t, measured(), bootLog, nil)
		failure := failureOf(appraisal, AppraisalCheckEventLog)
		if appraisal.Verified || failure == nil || failure.Outcome != string(AppraisalForged) {
			t.Fatalf("appraisal = %+v, want a forged event log", appraisal)
		}
	})

	t.Run("TamperedBootPCRIsForged", func(t *testing.T) {
		// PCR 7 matches signed reference values, but the log does not explain it.
		tampered := measured()
		tampered[7] = digest(0xEE)
		w.putReferenceValues(t, "tampered-boot", tampered)
		ev := w.hostEvidence(t, tampered, "tampered-boot")
		ev.EventLog = bootLog
		ev.LaunchPCRs = []uint32{launchPCR}
		appraisal, err := w.app.AppraiseHost(w.ctx, w.tenant, ev)
		if err != nil {
			t.Fatalf("AppraiseHost: %v", err)
		}
		if appraisal.Verified || !appraisal.CryptographicFailure || len(appraisal.Failures) != 1 {
			t.Fatalf("appraisal = %+v, want only the event log to fail", appraisal)
		}
		if failure := failureOf(appraisal, AppraisalCheckEventLog); failure == nil || failure.Outcome != string(AppraisalForged) {
			t.Fatalf("failures = %+v, want a forged event log", appraisal.Failures)
		}
	})

	t.Run("LogEventsForTheLaunchPCRAreIgnored", func(t *testing.T) {
		// A log that records the measurement PCR does not get to judge it:
		// the runtime's extension is never in the firmware log, so the
		// signed reference values are the only authority for that register.
		withLaunch, _ := appraisaltest.BootEventLog([]appraisaltest.LogEvent{
			{PCR: 0, Digest: digest(0x01)},
			{PCR: 7, Digest: digest(0x07)},
			{PCR: 0, Digest: digest(0x02)},
			{PCR: launchPCR, Digest: digest(0x99)},
		})
		appraisal := appraise(t, measured(), withLaunch, []uint32{launchPCR})
		if !appraisal.Verified || len(appraisal.Failures) != 0 {
			t.Fatalf("appraisal = %+v, want verified: the log's launch PCR events are not replayed", appraisal)
		}

		drifted := measured()
		drifted[launchPCR] = digest(0xEE)
		appraisal = appraise(t, drifted, withLaunch, []uint32{launchPCR})
		failure := failureOf(appraisal, AppraisalCheckBaseline)
		if appraisal.Verified || failure == nil || failure.Outcome != string(AppraisalForged) {
			t.Fatalf("appraisal = %+v, want the baseline to refuse a drifted launch PCR", appraisal)
		}
		if failureOf(appraisal, AppraisalCheckEventLog) != nil {
			t.Fatalf("failures = %+v, want the event log to pass", appraisal.Failures)
		}
	})

	t.Run("OnlyTheLaunchPCRQuotedSkipsTheReplay", func(t *testing.T) {
		launchOnly := map[uint32][]byte{launchPCR: launched}
		w.putReferenceValues(t, "launch-only", launchOnly)
		ev := w.hostEvidence(t, launchOnly, "launch-only")
		ev.EventLog = bootLog
		ev.LaunchPCRs = []uint32{launchPCR}
		appraisal, err := w.app.AppraiseHost(w.ctx, w.tenant, ev)
		if err != nil {
			t.Fatalf("AppraiseHost: %v", err)
		}
		if !appraisal.Verified || len(appraisal.Failures) != 0 {
			t.Fatalf("appraisal = %+v, want verified with the replay skipped", appraisal)
		}
	})

	t.Run("MalformedLogIsStillForged", func(t *testing.T) {
		appraisal := appraise(t, measured(), []byte{1, 2, 3}, []uint32{launchPCR})
		failure := failureOf(appraisal, AppraisalCheckEventLog)
		if appraisal.Verified || failure == nil || failure.Outcome != string(AppraisalForged) {
			t.Fatalf("appraisal = %+v, want a forged event log", appraisal)
		}
	})
}
