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

//go:build tpm_simulator

package appraisal

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/evidence"
	xkmstpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/tpm2test"
)

// simulatorBank is the PCR bank the simulator tests extend and appraise.
const simulatorBank = "sha256"

// simulatorReferencePCRs are the registers the simulator tests quote: two
// boot registers and the container launch register.
var simulatorReferencePCRs = []uint{0, 7, uint(launchPCR)}

// simulatorHost is a provisioned TPM simulator whose IAK certificate chains
// to the AK root endorsed in world.
type simulatorHost struct {
	tpm   xkmstpm2.TrustedPlatformModule
	world *verifierWorld
}

// newSimulatorHost provisions the TPM simulator, certifies its IAK under the
// world's AK root and installs that certificate in the TPM.
func newSimulatorHost(t *testing.T) *simulatorHost {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	sim, err := xkmstpm2.OpenSimulator()
	if err != nil {
		t.Fatalf("OpenSimulator: %v", err)
	}
	t.Cleanup(func() {
		if err := sim.Close(); err != nil {
			t.Errorf("closing the TPM simulator: %v", err)
		}
	})

	factory, err := store.NewMemoryStorageFactory(logger)
	if err != nil {
		t.Fatalf("NewMemoryStorageFactory: %v", err)
	}
	t.Cleanup(func() {
		if err := factory.Close(); err != nil {
			t.Errorf("closing the storage factory: %v", err)
		}
	})

	config := xkmstpm2.DefaultConfig
	config.UseSimulator = false // the transport is supplied explicitly
	config.Device = ""
	tpm, err := xkmstpm2.NewTPM2(&xkmstpm2.Params{
		Config:    &config,
		Logger:    logger,
		Backend:   factory.KeyBackend(),
		CertStore: store.NewMemoryCertStore(logger),
		Transport: sim.Transport(),
	})
	if tpm != nil {
		t.Cleanup(func() {
			if err := tpm.Close(); err != nil {
				t.Errorf("closing the TPM: %v", err)
			}
		})
	}
	if errors.Is(err, xkmstpm2.ErrNotInitialized) {
		err = tpm.Provision(nil)
	}
	if err != nil {
		t.Fatalf("provisioning the simulator: %v", err)
	}
	if err := tpm2test.EnrollPlatformSRK(tpm, &config); err != nil {
		t.Fatalf("EnrollPlatformSRK: %v", err)
	}

	world := newHostWorld(t)
	iak, err := tpm.IAK()
	if err != nil {
		t.Fatalf("IAK: %v", err)
	}
	cert, err := appraisaltest.CertifyAttestationKey(world.akCA, iak, true)
	if err != nil {
		t.Fatalf("CertifyAttestationKey: %v", err)
	}
	if err := tpm.ProvisionIAKCert(nil, cert); err != nil {
		t.Fatalf("ProvisionIAKCert: %v", err)
	}
	return &simulatorHost{tpm: tpm, world: world}
}

// readPCRs returns the simulator's current values of the quoted registers.
func (h *simulatorHost) readPCRs(t *testing.T) map[uint32][]byte {
	t.Helper()
	banks, err := h.tpm.ReadPCRs(simulatorReferencePCRs)
	if err != nil {
		t.Fatalf("ReadPCRs: %v", err)
	}
	values, err := flattenPCRBanks(banks, simulatorBank)
	if err != nil {
		t.Fatalf("flattenPCRBanks: %v", err)
	}
	return values
}

// containerEvidence quotes the simulator over nonce and returns the evidence
// a container runtime hands the Appraiser.
func (h *simulatorHost) containerEvidence(t *testing.T, nonce []byte, referenceValues string) *ContainerEvidence {
	t.Helper()
	quote, err := h.tpm.Quote(simulatorReferencePCRs, nonce)
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}
	// The simulator has no boot log; a log the host happens to expose does
	// not describe the simulator's registers.
	quote.EventLog = nil
	banks, err := h.tpm.ReadPCRs(simulatorReferencePCRs)
	if err != nil {
		t.Fatalf("ReadPCRs: %v", err)
	}
	akCert, err := h.tpm.IAKCertificate()
	if err != nil {
		t.Fatalf("IAKCertificate: %v", err)
	}
	return &ContainerEvidence{
		Image:           "alpine",
		ReferenceValues: referenceValues,
		AKCertificate:   akCert,
		Nonce:           nonce,
		Quote:           quote,
		Banks:           banks,
		LaunchPCRs:      []uint32{launchPCR},
	}
}

func simulatorNonce(fill byte) []byte {
	return bytes.Repeat([]byte{fill}, sha256.Size)
}

func TestSimulatorTPM_IAKCertificateCarriesVerifiedTPMRestricted(t *testing.T) {
	host := newSimulatorHost(t)

	cert, err := host.tpm.IAKCertificate()
	if err != nil {
		t.Fatalf("IAKCertificate: %v", err)
	}
	if !evidence.CarriesVerifiedTPMRestricted(cert) {
		t.Fatal("the enrolled IAK certificate must carry tcg-cap-verifiedTPMRestricted")
	}
	if err := cert.CheckSignatureFrom(host.world.akCA.Certificate); err != nil {
		t.Fatalf("the enrolled IAK certificate must chain to the tenant AK root: %v", err)
	}
}

func TestSimulatorTPM_AttestedHostVerifies(t *testing.T) {
	host := newSimulatorHost(t)
	host.world.putReferenceValues(t, "simulator", host.readPCRs(t))

	ev := host.containerEvidence(t, simulatorNonce(0x5A), "simulator")
	if err := host.world.app.AppraiseContainer(host.world.ctx, host.world.tenant, ev); err != nil {
		t.Fatalf("AppraiseContainer: %v", err)
	}
}

func TestSimulatorTPM_MeasuredLaunchVerifies(t *testing.T) {
	host := newSimulatorHost(t)

	// The reference values for a measured launch carry the value the launch
	// extends the launch PCR to, computed before the launch happens.
	measurement := []byte("alpine@sha256:launch-measurement")
	digest := sha256.Sum256(measurement)
	reference := host.readPCRs(t)
	reference[launchPCR] = appraisaltest.ExtendSHA256(reference[launchPCR], digest[:])
	host.world.putReferenceValues(t, "measured", reference)

	if err := host.tpm.ExtendPCR(int(launchPCR), simulatorBank, measurement); err != nil {
		t.Fatalf("ExtendPCR: %v", err)
	}
	if got := host.readPCRs(t)[launchPCR]; !bytes.Equal(got, reference[launchPCR]) {
		t.Fatalf("launch PCR = %x, replay yields %x", got, reference[launchPCR])
	}

	ev := host.containerEvidence(t, simulatorNonce(0x5A), "measured")
	if err := host.world.app.AppraiseContainer(host.world.ctx, host.world.tenant, ev); err != nil {
		t.Fatalf("AppraiseContainer: %v", err)
	}
}

func TestSimulatorTPM_ChangedPCRIsRefused(t *testing.T) {
	host := newSimulatorHost(t)
	host.world.putReferenceValues(t, "simulator", host.readPCRs(t))

	// The register moves after the reference values were signed.
	if err := host.tpm.ExtendPCR(7, simulatorBank, []byte("unexpected boot component")); err != nil {
		t.Fatalf("ExtendPCR: %v", err)
	}

	ev := host.containerEvidence(t, simulatorNonce(0x5A), "simulator")
	err := host.world.app.AppraiseContainer(host.world.ctx, host.world.tenant, ev)
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
	host := newSimulatorHost(t)
	host.world.putReferenceValues(t, "simulator", host.readPCRs(t))

	otherRoot, err := appraisaltest.NewAuthority("Another tenant's AK root")
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}
	iak, err := host.tpm.IAK()
	if err != nil {
		t.Fatalf("IAK: %v", err)
	}
	foreign, err := appraisaltest.CertifyAttestationKey(otherRoot, iak, true)
	if err != nil {
		t.Fatalf("CertifyAttestationKey: %v", err)
	}

	ev := host.containerEvidence(t, simulatorNonce(0x5A), "simulator")
	ev.AKCertificate = foreign
	err = host.world.app.AppraiseContainer(host.world.ctx, host.world.tenant, ev)
	if !errors.Is(err, ErrHostNotVerified) {
		t.Fatalf("error %v does not wrap ErrHostNotVerified", err)
	}
	if errors.Is(err, ErrPCRMismatch) {
		t.Fatal("an untrusted AK certificate is not a PCR mismatch")
	}
	var appraisal *HostAppraisalError
	if !errors.As(err, &appraisal) {
		t.Fatalf("expected *HostAppraisalError, got %T", err)
	}
	if !hasFailedCheck(appraisal.Failures, "ak-certificate", "forged") {
		t.Fatalf("failures %+v do not name a forged ak-certificate check", appraisal.Failures)
	}
}

func TestSimulatorTPM_QuoteOverAnotherNonceIsRefusedByTheVerifier(t *testing.T) {
	host := newSimulatorHost(t)
	host.world.putReferenceValues(t, "simulator", host.readPCRs(t))

	quotedNonce := simulatorNonce(0x5A)
	ev := host.containerEvidence(t, quotedNonce, "simulator")
	bound, err := bindQuotedPCRs(ev.Image, ev.Quote.Quoted, quotedNonce, ev.Banks)
	if err != nil {
		t.Fatalf("bindQuotedPCRs: %v", err)
	}
	appraise := func(nonce []byte) *HostAppraisal {
		t.Helper()
		appraisal, err := host.world.app.AppraiseHost(host.world.ctx, host.world.tenant, &HostEvidence{
			ReferenceValues: "simulator",
			AKCertificate:   ev.AKCertificate,
			Nonce:           nonce,
			Quoted:          ev.Quote.Quoted,
			Signature:       ev.Quote.Signature,
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

	appraisal := appraise(simulatorNonce(0xA5))
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
