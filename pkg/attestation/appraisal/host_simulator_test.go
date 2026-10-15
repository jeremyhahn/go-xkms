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

//go:build tpm_simulator

package orchestration

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/evidence"

	"github.com/jeremyhahn/go-quicbaas/pkg/service/attestationtest"
	"github.com/jeremyhahn/go-quicbaas/pkg/testutil/tpmsim"
)

// These tests drive the production quote producer — a provisioned go-xkms
// TPM on the in-process simulator — through the attesting runtime and the
// Verifier, so nothing between TPM2_Quote and AppraiseQuote is a double.

// simulatorReferencePCRs are the registers the reference values cover. PCR 16
// is the platform PCR and the measured-launch PCR: the Verifier compares equal
// sets, so every workload's reference values carry it.
var simulatorReferencePCRs = []uint{0, 7, MeasurementPCRDefault}

// enrolledSimulator provisions the simulator and enrolls its IAK under a
// tenant AK root, returning the TPM and that root.
func enrolledSimulator(t *testing.T) (*tpmsim.Simulator, *attestationtest.Authority) {
	t.Helper()
	if NewTestHostAppraiser == nil {
		t.Fatal("NewTestHostAppraiser is not installed; host_appraisal_verifier_test.go installs it")
	}
	sim := tpmsim.Provision(t)
	akRoot, err := attestationtest.NewAuthority("Tenant AK root")
	if err != nil {
		t.Fatal(err)
	}
	sim.EnrollIAK(t, func(pub crypto.PublicKey) (*x509.Certificate, error) {
		return attestationtest.CertifyAttestationKey(akRoot, pub, true)
	})
	return sim, akRoot
}

// readSimulatorPCRs reads the SHA-256 register values the TPM holds now.
func readSimulatorPCRs(t *testing.T, sim *tpmsim.Simulator) map[uint32][]byte {
	t.Helper()
	banks, err := sim.TPM.ReadPCRs(simulatorReferencePCRs)
	if err != nil {
		t.Fatalf("ReadPCRs: %v", err)
	}
	values, err := flattenPCRBanks(banks, DefaultMeasurementBank)
	if err != nil {
		t.Fatalf("flattenPCRBanks: %v", err)
	}
	return values
}

func newSimulatorRuntime(t *testing.T, sim *tpmsim.Simulator, akRoot *attestationtest.Authority, reference map[uint32][]byte) *TPMAttestingRuntime {
	t.Helper()
	rt, err := NewTPMAttestingRuntime(&recordingRuntime{}, sim.TPM, NewTestHostAppraiser(t, akRoot, attestationtest.SHA256Digests(reference)), newContainerTestLogger(t))
	if err != nil {
		t.Fatalf("NewTPMAttestingRuntime: %v", err)
	}
	return rt
}

func simulatorSpec(level TrustLevel) *ContainerSpec {
	return &ContainerSpec{
		Image:           "alpine@" + testDigest,
		TrustLevel:      level,
		TrustLabel:      "prod-agent",
		ReferenceValues: "golden",
	}
}

func TestSimulatorTPM_IAKCertificateCarriesVerifiedTPMRestricted(t *testing.T) {
	sim, akRoot := enrolledSimulator(t)

	cert, err := sim.TPM.IAKCertificate()
	if err != nil {
		t.Fatalf("IAKCertificate: %v", err)
	}
	if !evidence.CarriesVerifiedTPMRestricted(cert) {
		t.Fatal("the enrolled IAK certificate must carry tcg-cap-verifiedTPMRestricted")
	}
	if err := cert.CheckSignatureFrom(akRoot.Certificate); err != nil {
		t.Fatalf("the enrolled IAK certificate must chain to the tenant AK root: %v", err)
	}
}

func TestSimulatorTPM_AttestedHostVerifies(t *testing.T) {
	sim, akRoot := enrolledSimulator(t)
	rt := newSimulatorRuntime(t, sim, akRoot, readSimulatorPCRs(t, sim))

	result, err := rt.Attest(t.Context(), simulatorSpec(TrustLevelAttested), "container-1")
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if result.PCRBank != DefaultMeasurementBank {
		t.Errorf("PCRBank = %q, want %q", result.PCRBank, DefaultMeasurementBank)
	}
	if len(result.PCRs) != len(simulatorReferencePCRs) {
		t.Errorf("evidence carries %d PCRs, want %d", len(result.PCRs), len(simulatorReferencePCRs))
	}
}

func TestSimulatorTPM_MeasuredLaunchVerifies(t *testing.T) {
	sim, akRoot := enrolledSimulator(t)
	spec := simulatorSpec(TrustLevelMeasured)

	// The reference values for a measured launch carry the value the launch
	// extends the measurement PCR to, computed before the launch happens.
	measurement, err := LaunchMeasurement(spec)
	if err != nil {
		t.Fatalf("LaunchMeasurement: %v", err)
	}
	reference := readSimulatorPCRs(t, sim)
	reference[uint32(MeasurementPCRDefault)] = expectedExtend(reference[uint32(MeasurementPCRDefault)], measurement)
	rt := newSimulatorRuntime(t, sim, akRoot, reference)

	if _, err := rt.Run(t.Context(), spec); err != nil {
		t.Fatalf("Run: %v", err)
	}
	result, err := rt.Attest(t.Context(), spec, "container-1")
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if !result.Measured {
		t.Error("Tier 2 evidence must report a measured launch")
	}
	if got := result.PCRs[uint32(MeasurementPCRDefault)]; !bytes.Equal(got, reference[uint32(MeasurementPCRDefault)]) {
		t.Fatalf("quoted measurement PCR = %x, replay yields %x", got, reference[uint32(MeasurementPCRDefault)])
	}
}

func TestSimulatorTPM_ChangedPCRIsRefused(t *testing.T) {
	sim, akRoot := enrolledSimulator(t)
	rt := newSimulatorRuntime(t, sim, akRoot, readSimulatorPCRs(t, sim))

	// The register moves after the reference values were signed.
	if err := sim.TPM.ExtendPCR(7, DefaultMeasurementBank, []byte("unexpected boot component")); err != nil {
		t.Fatalf("ExtendPCR: %v", err)
	}

	_, err := rt.Attest(t.Context(), simulatorSpec(TrustLevelAttested), "container-1")
	if !errors.Is(err, ErrPCRMismatch) {
		t.Fatalf("error %v does not wrap ErrPCRMismatch", err)
	}
	var appraisal *HostAppraisalError
	if !errors.As(err, &appraisal) {
		t.Fatalf("expected *HostAppraisalError, got %T", err)
	}
	if !appraisal.CryptographicFailure {
		t.Error("a drifted PCR is a cryptographic failure of the baseline")
	}
	var diverged []uint32
	for _, failure := range appraisal.Failures {
		for _, pcr := range failure.PCRs {
			diverged = append(diverged, pcr.Index)
		}
	}
	if len(diverged) != 1 || diverged[0] != 7 {
		t.Fatalf("diverging PCRs = %v, want [7]", diverged)
	}
}

func TestSimulatorTPM_AKCertificateNotChainingToTheTenantRootIsRefused(t *testing.T) {
	sim, _ := enrolledSimulator(t)
	otherRoot, err := attestationtest.NewAuthority("Another tenant's AK root")
	if err != nil {
		t.Fatal(err)
	}
	rt := newSimulatorRuntime(t, sim, otherRoot, readSimulatorPCRs(t, sim))

	_, err = rt.Attest(t.Context(), simulatorSpec(TrustLevelAttested), "container-1")
	if !errors.Is(err, ErrHostNotVerified) {
		t.Fatalf("error %v does not wrap ErrHostNotVerified", err)
	}
	if errors.Is(err, ErrPCRMismatch) {
		t.Fatalf("an untrusted AK says nothing about PCRs, got %v", err)
	}
	var appraisal *HostAppraisalError
	if !errors.As(err, &appraisal) {
		t.Fatalf("expected *HostAppraisalError, got %T", err)
	}
	if !appraisal.CryptographicFailure {
		t.Error("an AK certificate that does not chain is a cryptographic failure")
	}
	if !hasFailedCheck(appraisal.Failures, "ak-certificate", "forged") {
		t.Fatalf("failures %+v do not name a forged ak-certificate check", appraisal.Failures)
	}
}

// The runtime draws its own nonce, so a quote over a different one is fed to
// the Verifier directly: a real quote replayed against a fresh challenge.
func TestSimulatorTPM_QuoteOverAnotherNonceIsRefusedByTheVerifier(t *testing.T) {
	sim, akRoot := enrolledSimulator(t)
	appraiser := NewTestHostAppraiser(t, akRoot, attestationtest.SHA256Digests(readSimulatorPCRs(t, sim)))

	quotedNonce := bytes.Repeat([]byte{0x5A}, attestationNonceBytes)
	quote, err := sim.TPM.Quote(simulatorReferencePCRs, quotedNonce)
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}
	banks, err := sim.TPM.ReadPCRs(simulatorReferencePCRs)
	if err != nil {
		t.Fatalf("ReadPCRs: %v", err)
	}
	bound, err := bindQuotedPCRs("alpine", quote.Quoted, quotedNonce, banks)
	if err != nil {
		t.Fatalf("bindQuotedPCRs: %v", err)
	}
	akCert, err := sim.TPM.IAKCertificate()
	if err != nil {
		t.Fatalf("IAKCertificate: %v", err)
	}
	appraise := func(nonce []byte) *HostAppraisal {
		t.Helper()
		appraisal, err := appraiser.AppraiseHost(t.Context(), &HostEvidence{
			ReferenceValues: "golden",
			AKCertificate:   akCert,
			Nonce:           nonce,
			Quoted:          quote.Quoted,
			Signature:       quote.Signature,
			PCRs:            bound.values,
		})
		if err != nil {
			t.Fatalf("AppraiseHost: %v", err)
		}
		return appraisal
	}

	if appraisal := appraise(quotedNonce); !appraisal.Verified {
		t.Fatalf("the quote must verify against its own nonce, failures %+v", appraisal.Failures)
	}

	freshNonce := bytes.Repeat([]byte{0xA5}, attestationNonceBytes)
	appraisal := appraise(freshNonce)
	if appraisal.Verified {
		t.Fatal("a quote over another nonce must not verify")
	}
	if !appraisal.CryptographicFailure {
		t.Error("a nonce mismatch is a cryptographic failure")
	}
	if !hasFailedCheck(appraisal.Failures, "quote", "forged") {
		t.Fatalf("failures %+v do not name a forged quote check", appraisal.Failures)
	}
}

func hasFailedCheck(failures []HostAppraisalFailure, check, outcome string) bool {
	for _, failure := range failures {
		if failure.Check == check && failure.Outcome == outcome {
			return true
		}
	}
	return false
}
