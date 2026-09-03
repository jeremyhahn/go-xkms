// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package initialize

import (
	"context"
	"crypto"
	"errors"
	"strings"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	xkmspiv "github.com/jeremyhahn/go-xkms/pkg/factor/piv"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	xkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// This file covers the administrator-enrollment PIV seam (issue #199): the
// admin path must reach a real card when one is attached, and must refuse
// rather than silently record a software credential when one is not.

// cardGenerator stands in for a PKCS#11- or TPM2-backed PIV generator with a
// reader attached. It implements xkmspiv.GeneratorAvailability, which is how a
// hardware generator reports an empty reader before any state changes.
type cardGenerator struct {
	available bool
	reason    string
	inner     xkms.PIVKeyGenerator
}

func newCardGenerator(available bool, reason string) *cardGenerator {
	return &cardGenerator{available: available, reason: reason, inner: xkms.NewSoftwarePIVKeyGenerator()}
}

func (g *cardGenerator) GeneratePIVKey(slot pivcert.PIVSlot, algorithm, cn string) (crypto.Signer, error) {
	return g.inner.GeneratePIVKey(slot, algorithm, cn)
}

func (g *cardGenerator) GetPIVSigner(slot pivcert.PIVSlot, cn string) (crypto.Signer, error) {
	return g.inner.GetPIVSigner(slot, cn)
}

func (g *cardGenerator) Available(context.Context) (bool, string) { return g.available, g.reason }

// TestPreflightAdminFactors_PIVWithNoGeneratorFails is the regression test for
// the vulnerability in issue #199. Before the seam existed this preflight
// PASSED and the ceremony went on to enroll a software key that an operator
// holding a smartcard could not distinguish from a hardware one.
func TestPreflightAdminFactors_PIVWithNoGeneratorFails(t *testing.T) {
	err := PreflightAdminFactors(context.Background(), AdminEnrollmentConfig{
		Plan:     mustPlan(t, "piv"),
		Username: "administrator",
		TenantID: "system",
		// PIVGenerator deliberately absent, AllowSoftwarePIV deliberately clear.
	})
	if err == nil {
		t.Fatal("a planned piv factor with no generator attached must fail preflight")
	}
	var unavailable *qrdbsdk.AdminFactorUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("err = %T (%v), want *AdminFactorUnavailableError", err, err)
	}
	if unavailable.Factor != qrdbsdk.FactorPIV {
		t.Errorf("Factor = %v, want piv", unavailable.Factor)
	}
	if !strings.Contains(unavailable.Reason, xkmspiv.NoGeneratorReason) {
		t.Errorf("Reason = %q, want it to carry %q", unavailable.Reason, xkmspiv.NoGeneratorReason)
	}
}

// TestPreflightAdminFactors_PIVWithAReachableCardPasses verifies the seam is
// what makes hardware reachable at all: with a generator attached and a card
// present, the plan preflights cleanly.
func TestPreflightAdminFactors_PIVWithAReachableCardPasses(t *testing.T) {
	err := PreflightAdminFactors(context.Background(), AdminEnrollmentConfig{
		Plan:         mustPlan(t, "piv"),
		Username:     "administrator",
		TenantID:     "system",
		PIVGenerator: newCardGenerator(true, ""),
	})
	if err != nil {
		t.Fatalf("piv must preflight cleanly with a reachable card attached, got %v", err)
	}
}

// TestPreflightAdminFactors_PIVWithAnEmptyReaderFails verifies the attached
// generator's own answer is the one that decides, so an empty reader is caught
// before the barrier is initialized rather than partway through.
func TestPreflightAdminFactors_PIVWithAnEmptyReaderFails(t *testing.T) {
	err := PreflightAdminFactors(context.Background(), AdminEnrollmentConfig{
		Plan:         mustPlan(t, "piv"),
		Username:     "administrator",
		TenantID:     "system",
		PIVGenerator: newCardGenerator(false, "no smartcard in reader"),
	})
	if err == nil {
		t.Fatal("a planned piv factor whose card is absent must fail preflight")
	}
	if !strings.Contains(err.Error(), "no smartcard in reader") {
		t.Errorf("err = %v, want the generator's own reason", err)
	}
}

// TestPreflightAdminFactors_PIVSoftwareOptInPasses verifies a software-only
// deployment can still enroll PIV — but only by naming AllowSoftwarePIV, so it
// cannot be reached by omission.
func TestPreflightAdminFactors_PIVSoftwareOptInPasses(t *testing.T) {
	err := PreflightAdminFactors(context.Background(), AdminEnrollmentConfig{
		Plan:             mustPlan(t, "piv"),
		Username:         "administrator",
		TenantID:         "system",
		AllowSoftwarePIV: true,
	})
	if err != nil {
		t.Fatalf("an explicit software-PIV opt-in must preflight cleanly, got %v", err)
	}
}

// TestEnrollAdminFactors_PIVWithNoGeneratorFails is the defence in depth behind
// the preflight. Preflight is a separate call a caller may skip, so enrollment
// must refuse on its own rather than trust that it ran.
func TestEnrollAdminFactors_PIVWithNoGeneratorFails(t *testing.T) {
	enrolled, err := EnrollAdminFactors(context.Background(), AdminEnrollmentConfig{
		Plan:     mustPlan(t, "piv"),
		Username: "administrator",
		TenantID: "system",
	})
	if err == nil {
		t.Fatal("piv enrollment with no generator attached must fail")
	}
	if !strings.Contains(err.Error(), xkmspiv.NoGeneratorReason) {
		t.Errorf("err = %v, want it to carry %q", err, xkmspiv.NoGeneratorReason)
	}
	for _, e := range enrolled {
		if e.Factor == qrdbsdk.FactorPIV {
			t.Fatal("a refused piv factor must not appear as enrolled")
		}
	}
}

// TestEnrollAdminFactors_PIVWithAGeneratorEnrolls verifies the attached
// generator is the one that produces the key, closing the loop on the seam.
func TestEnrollAdminFactors_PIVWithAGeneratorEnrolls(t *testing.T) {
	enrolled, err := EnrollAdminFactors(context.Background(), AdminEnrollmentConfig{
		Plan:         mustPlan(t, "piv"),
		Username:     "administrator",
		TenantID:     "system",
		PIVGenerator: newCardGenerator(true, ""),
	})
	if err != nil {
		t.Fatalf("EnrollAdminFactors(piv): %v", err)
	}
	if len(enrolled) != 1 {
		t.Fatalf("expected exactly one enrolled factor, got %d", len(enrolled))
	}
	if enrolled[0].Factor != qrdbsdk.FactorPIV {
		t.Errorf("enrolled factor = %v, want piv", enrolled[0].Factor)
	}
	if len(enrolled[0].Enrollment.PublicKey) == 0 {
		t.Error("the enrollment must carry the slot certificate")
	}
}
