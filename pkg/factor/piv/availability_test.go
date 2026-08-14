// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package piv

import (
	"context"
	"crypto"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
)

// probingGenerator reaches a card and can therefore report availability.
type probingGenerator struct {
	ok     bool
	reason string
}

func (g *probingGenerator) GeneratePIVKey(pivcert.PIVSlot, string, string) (crypto.Signer, error) {
	return nil, nil
}

func (g *probingGenerator) GetPIVSigner(pivcert.PIVSlot, string) (crypto.Signer, error) {
	return nil, nil
}

func (g *probingGenerator) Available(context.Context) (bool, string) {
	return g.ok, g.reason
}

// plainGenerator is hardware-agnostic and cannot answer availability.
type plainGenerator struct{}

func (g *plainGenerator) GeneratePIVKey(pivcert.PIVSlot, string, string) (crypto.Signer, error) {
	return nil, nil
}

func (g *plainGenerator) GetPIVSigner(pivcert.PIVSlot, string) (crypto.Signer, error) {
	return nil, nil
}

func TestFactor_AvailableDelegatesToAProbingGenerator(t *testing.T) {
	f := New(Config{Generator: &probingGenerator{ok: false, reason: "no smartcard reader"}})
	ok, reason := f.Available(context.Background())
	if ok {
		t.Fatal("Available() = true, want false when the card is unreachable")
	}
	if reason != "no smartcard reader" {
		t.Errorf("reason = %q, want the generator's reason", reason)
	}

	f = New(Config{Generator: &probingGenerator{ok: true}})
	if ok, reason := f.Available(context.Background()); !ok {
		t.Fatalf("Available() = false (%s), want true", reason)
	}
}

func TestFactor_AvailableWhenGeneratorCannotProbe(t *testing.T) {
	// A software generator has no card to be missing. Reporting it
	// unavailable would block software-only deployments from enrolling a PIV
	// factor they can legitimately use.
	f := New(Config{Generator: &plainGenerator{}})
	if ok, reason := f.Available(context.Background()); !ok {
		t.Fatalf("Available() = false (%s), want true for a non-probing generator", reason)
	}
}

func TestFactor_SatisfiesTheCeremonyAvailabilityProbe(t *testing.T) {
	// Compile-time proof the PIV factor plugs into the shared init preflight
	// without any parallel enrollment seam.
	var _ qrdbsdk.AdminFactorAvailability = New(Config{Generator: &plainGenerator{}})
}
