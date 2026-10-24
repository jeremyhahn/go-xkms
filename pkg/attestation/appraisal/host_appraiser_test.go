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
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	stderrors "errors"
	"slices"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/pkg/errors"
	"github.com/jeremyhahn/go-quicbaas/pkg/orchestration"
	"github.com/jeremyhahn/go-quicbaas/pkg/service/attestationtest"
	"github.com/jeremyhahn/go-quicbaas/pkg/tenantctx"
)

// newHostAppraiserWorld returns an endorsed verifier world and a host
// appraiser over the same store.
func newHostAppraiserWorld(t *testing.T) (*verifierWorld, orchestration.HostAppraiser) {
	t.Helper()
	w := newVerifierWorld(t)
	w.endorse(t)
	appraiser, err := NewHostAppraiser(w.store)
	if err != nil {
		t.Fatalf("NewHostAppraiser: %v", err)
	}
	return w, appraiser
}

// hostEvidence signs pcrs with the world's attestation key and returns the
// evidence a TPMAttestingRuntime would hand over.
func (w *verifierWorld) hostEvidence(t *testing.T, pcrs map[uint32][]byte, referenceValues string) *orchestration.HostEvidence {
	t.Helper()
	nonce := []byte("host-appraiser-nonce")
	quote, err := attestationtest.SignQuote(w.ak, pcrs, nonce)
	if err != nil {
		t.Fatal(err)
	}
	return &orchestration.HostEvidence{
		ReferenceValues: referenceValues,
		AKCertificate:   w.ak.Certificate,
		Nonce:           nonce,
		Quoted:          quote.Attest,
		Signature:       quote.Signature,
		PCRs:            pcrs,
	}
}

func TestNewHostAppraiser(t *testing.T) {
	t.Run("RequiresAStore", func(t *testing.T) {
		appraiser, err := NewHostAppraiser(nil)
		if !stderrors.Is(err, ErrHostAppraiserNoStore) || appraiser != nil {
			t.Fatalf("NewHostAppraiser(nil) = %v, %v; want ErrHostAppraiserNoStore", appraiser, err)
		}
		if codeOf(t, err) != errors.ErrInvalidInput {
			t.Fatalf("code = %v, want ErrInvalidInput", codeOf(t, err))
		}
	})

	t.Run("OptionsApply", func(t *testing.T) {
		appraiser, err := NewHostAppraiser(attestationtest.NewMemoryStore(), WithAttestationStore(nil))
		if err != nil {
			t.Fatalf("NewHostAppraiser: %v", err)
		}
		// The store argument wins over an option that would clear it.
		if appraiser.(*hostAppraiser).svc.store == nil {
			t.Fatal("the store argument was overridden by an option")
		}
	})
}

func TestHostAppraiser_ReferencePCRs(t *testing.T) {
	w, appraiser := newHostAppraiserWorld(t)

	t.Run("ReadsTheStoredIndices", func(t *testing.T) {
		indices, err := appraiser.ReferencePCRs(w.ctx, "golden", crypto.SHA256)
		if err != nil {
			t.Fatalf("ReferencePCRs: %v", err)
		}
		if want := []uint32{0, 4, 7}; !slices.Equal(indices, want) {
			t.Fatalf("indices = %v, want %v", indices, want)
		}
	})

	t.Run("OnlyTheQuotedBankIsCounted", func(t *testing.T) {
		w.putReferenceDigests(t, "mixed", []attestationtest.PCRDigest{
			{Index: 0, Hash: crypto.SHA256, Value: bytes.Repeat([]byte{0x10}, sha256.Size)},
			{Index: 7, Hash: crypto.SHA384, Value: bytes.Repeat([]byte{0x17}, sha512.Size384)},
		})
		for bank, want := range map[crypto.Hash][]uint32{crypto.SHA256: {0}, crypto.SHA384: {7}} {
			indices, err := appraiser.ReferencePCRs(w.ctx, "mixed", bank)
			if err != nil {
				t.Fatalf("ReferencePCRs(%s): %v", bank, err)
			}
			if !slices.Equal(indices, want) {
				t.Fatalf("ReferencePCRs(%s) = %v, want %v", bank, indices, want)
			}
		}
	})

	t.Run("OtherBankOnlyIsRefused", func(t *testing.T) {
		w.putReferenceDigests(t, "sha384-only", []attestationtest.PCRDigest{
			{Index: 0, Hash: crypto.SHA384, Value: bytes.Repeat([]byte{0x20}, sha512.Size384)},
			{Index: 7, Hash: crypto.SHA384, Value: bytes.Repeat([]byte{0x27}, sha512.Size384)},
		})
		_, err := appraiser.ReferencePCRs(w.ctx, "sha384-only", crypto.SHA256)
		assertBankUncovered(t, err, "sha384-only", crypto.SHA256)
	})

	t.Run("SHA1BankIsRefused", func(t *testing.T) {
		_, err := appraiser.ReferencePCRs(w.ctx, "golden", crypto.SHA1)
		assertBankUncovered(t, err, "golden", crypto.SHA1)
	})

	t.Run("UnknownNameIsNotFound", func(t *testing.T) {
		_, err := appraiser.ReferencePCRs(w.ctx, "missing", crypto.SHA256)
		if codeOf(t, err) != errors.ErrNotFound {
			t.Fatalf("ReferencePCRs(missing) = %v, want ErrNotFound", err)
		}
	})

	t.Run("InvalidNameIsRefused", func(t *testing.T) {
		_, err := appraiser.ReferencePCRs(w.ctx, "a/b", crypto.SHA256)
		if codeOf(t, err) != errors.ErrInvalidInput {
			t.Fatalf("ReferencePCRs(a/b) = %v, want ErrInvalidInput", err)
		}
	})

	t.Run("NoTenantIsRefused", func(t *testing.T) {
		_, err := appraiser.ReferencePCRs(context.Background(), "golden", crypto.SHA256)
		var missing *tenantctx.MissingTenantError
		if !stderrors.As(err, &missing) {
			t.Fatalf("ReferencePCRs with no tenant = %v, want *tenantctx.MissingTenantError", err)
		}
	})

	t.Run("NoLongerEndorsedIsRefused", func(t *testing.T) {
		w, appraiser := newHostAppraiserWorld(t)
		if err := w.svc.DeleteEndorsement(w.ctx, &DeleteEndorsementRequest{Name: "rv-ca"}); err != nil {
			t.Fatalf("DeleteEndorsement: %v", err)
		}
		_, err := appraiser.ReferencePCRs(w.ctx, "golden", crypto.SHA256)
		var rejected *ReferenceValuesRejectedError
		if !stderrors.As(err, &rejected) || codeOf(t, err) != errors.ErrInvalidInput {
			t.Fatalf("ReferencePCRs with no reference signer = %v, want ErrInvalidInput *ReferenceValuesRejectedError", err)
		}
	})
}

// assertBankUncovered requires err to be the typed refusal of reference
// values that hold no digest in bank.
func assertBankUncovered(t *testing.T, err error, name string, bank crypto.Hash) {
	t.Helper()
	var uncovered *orchestration.ReferenceBankUncoveredError
	if !stderrors.As(err, &uncovered) || !stderrors.Is(err, orchestration.ErrReferenceBankUncovered) {
		t.Fatalf("ReferencePCRs(%s, %s) = %v, want *orchestration.ReferenceBankUncoveredError", name, bank, err)
	}
	if uncovered.ReferenceValues != name || uncovered.Bank != bank {
		t.Fatalf("uncovered = %+v, want %s in %s", uncovered, name, bank)
	}
	if codeOf(t, err) != errors.ErrInvalidInput {
		t.Fatalf("code of %v, want ErrInvalidInput", err)
	}
}

func TestHostAppraiser_AppraiseHost(t *testing.T) {
	w, appraiser := newHostAppraiserWorld(t)

	t.Run("GenuineEvidencePasses", func(t *testing.T) {
		appraisal, err := appraiser.AppraiseHost(w.ctx, w.hostEvidence(t, w.pcrs, "golden"))
		if err != nil {
			t.Fatalf("AppraiseHost: %v", err)
		}
		if !appraisal.Verified || appraisal.CryptographicFailure || len(appraisal.Failures) != 0 {
			t.Fatalf("appraisal = %+v, want verified with no failures", appraisal)
		}
	})

	t.Run("DriftedPCRIsACryptographicFailure", func(t *testing.T) {
		drifted := attestationtest.PCRValues(0, 4, 7)
		drifted[4] = bytes.Repeat([]byte{0xEE}, len(drifted[4]))
		appraisal, err := appraiser.AppraiseHost(w.ctx, w.hostEvidence(t, drifted, "golden"))
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
		appraisal, err := appraiser.AppraiseHost(w.ctx, w.hostEvidence(t, w.pcrs, "missing"))
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
		appraisal, err := appraiser.AppraiseHost(w.ctx, ev)
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

	t.Run("NoTenantIsRefused", func(t *testing.T) {
		_, err := appraiser.AppraiseHost(context.Background(), w.hostEvidence(t, w.pcrs, "golden"))
		var missing *tenantctx.MissingTenantError
		if !stderrors.As(err, &missing) || codeOf(t, err) != errors.ErrForbidden {
			t.Fatalf("AppraiseHost with no tenant = %v, want ErrForbidden wrapping *tenantctx.MissingTenantError", err)
		}
	})

	t.Run("NilEvidenceIsRefused", func(t *testing.T) {
		if _, err := appraiser.AppraiseHost(w.ctx, nil); !stderrors.Is(err, ErrAttestationNilRequest) {
			t.Fatalf("AppraiseHost(nil) = %v, want ErrAttestationNilRequest", err)
		}
	})
}

// putReferenceValues signs pcrs as a CoRIM under the world's endorsed
// reference signer and stores it as name.
func (w *verifierWorld) putReferenceValues(t *testing.T, name string, pcrs map[uint32][]byte) {
	t.Helper()
	w.putReferenceDigests(t, name, attestationtest.SHA256Digests(pcrs))
}

// putReferenceDigests signs digests in any mix of banks and stores them as
// the reference values name.
func (w *verifierWorld) putReferenceDigests(t *testing.T, name string, digests []attestationtest.PCRDigest) {
	t.Helper()
	corim, err := attestationtest.SignCoRIMDigests(digests, w.signerKey, []*x509.Certificate{w.signerCert})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.PutReferenceValues(w.ctx, &PutReferenceValuesRequest{Name: name, SignedCoRIM: corim}); err != nil {
		t.Fatalf("PutReferenceValues(%s): %v", name, err)
	}
}

// failureOf returns the appraisal failure of check, or nil when it did not fail.
func failureOf(appraisal *orchestration.HostAppraisal, check string) *orchestration.HostAppraisalFailure {
	for i := range appraisal.Failures {
		if appraisal.Failures[i].Check == check {
			return &appraisal.Failures[i]
		}
	}
	return nil
}

// TestHostAppraiser_EventLogLeavesTheLaunchPCROut drives a measured launch:
// the firmware log explains the boot registers, and the runtime extended the
// measurement PCR after boot, so the log cannot explain that register. The
// replay covers every other quoted register; the reference values judge the
// measurement PCR.
func TestHostAppraiser_EventLogLeavesTheLaunchPCROut(t *testing.T) {
	w, appraiser := newHostAppraiserWorld(t)
	const launchPCR = uint32(orchestration.MeasurementPCRDefault)
	digest := func(b byte) []byte { return bytes.Repeat([]byte{b}, sha256.Size) }
	bootLog, boot := attestationtest.BootEventLog([]attestationtest.LogEvent{
		{PCR: 0, Digest: digest(0x01)},
		{PCR: 7, Digest: digest(0x07)},
		{PCR: 0, Digest: digest(0x02)},
	})
	launched := attestationtest.ExtendSHA256(make([]byte, sha256.Size), digest(0x16))
	measured := func() map[uint32][]byte {
		return map[uint32][]byte{0: boot[0], 7: boot[7], launchPCR: launched}
	}
	w.putReferenceValues(t, "measured", measured())

	appraise := func(t *testing.T, pcrs map[uint32][]byte, eventLog []byte, launchPCRs []uint32) *orchestration.HostAppraisal {
		t.Helper()
		ev := w.hostEvidence(t, pcrs, "measured")
		ev.EventLog = eventLog
		ev.LaunchPCRs = launchPCRs
		appraisal, err := appraiser.AppraiseHost(w.ctx, ev)
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
		appraisal, err := appraiser.AppraiseHost(w.ctx, ev)
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
		withLaunch, _ := attestationtest.BootEventLog([]attestationtest.LogEvent{
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
		appraisal, err := appraiser.AppraiseHost(w.ctx, ev)
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
