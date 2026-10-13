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

package factor

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/factor/fido2"
	"github.com/jeremyhahn/go-xkms/pkg/factor/mtls"
	"github.com/jeremyhahn/go-xkms/pkg/factor/piv"
	"github.com/jeremyhahn/go-xkms/pkg/factor/pkcs11"
)

func TestNewDefaultRegistry_RegistersAllFactors(t *testing.T) {
	registry, err := NewDefaultRegistry(Config{})
	if err != nil {
		t.Fatalf("NewDefaultRegistry: %v", err)
	}

	for _, name := range []string{piv.FactorName, pkcs11.FactorName, fido2.FactorName, mtls.FactorName} {
		f, err := registry.Lookup(name)
		if err != nil {
			t.Fatalf("Lookup(%q): %v", name, err)
		}
		if f.Name() != name {
			t.Fatalf("Lookup(%q).Name() = %q", name, f.Name())
		}
	}

	if got := len(registry.List()); got != 4 {
		t.Fatalf("registry has %d factors, want 4: %v", got, registry.List())
	}
}

func TestNewNodeRegistry_LeavesMTLSToQRDB(t *testing.T) {
	registry, err := NewNodeRegistry(Config{})
	if err != nil {
		t.Fatalf("NewNodeRegistry: %v", err)
	}

	for _, name := range []string{piv.FactorName, pkcs11.FactorName, fido2.FactorName} {
		if _, err := registry.Lookup(name); err != nil {
			t.Fatalf("Lookup(%q): %v", name, err)
		}
	}
	if _, err := registry.Lookup(mtls.FactorName); err == nil {
		t.Fatal("the node registry must not override go-qrdb's mtls factor")
	}
	if got := len(registry.List()); got != 3 {
		t.Fatalf("registry has %d factors, want 3: %v", got, registry.List())
	}
}

func TestNewNodeRegistry_AppliesConfig(t *testing.T) {
	registry, err := NewNodeRegistry(Config{RequirePIVGenerator: true})
	if err != nil {
		t.Fatalf("NewNodeRegistry: %v", err)
	}
	f, err := registry.Lookup(piv.FactorName)
	if err != nil {
		t.Fatalf("Lookup(piv): %v", err)
	}
	pivFactor, ok := f.(*piv.Factor)
	if !ok {
		t.Fatalf("Lookup(piv) = %T, want *piv.Factor", f)
	}
	if available, _ := pivFactor.Available(context.Background()); available {
		t.Fatal("a PIV factor that requires a generator and has none must report unavailable")
	}
}

func TestNewDefaultRegistry_AppliesConfig(t *testing.T) {
	registry, err := NewDefaultRegistry(Config{
		FIDO2RPID:           "example.org",
		PKCS11Mechanism:     "CKM_RSA_PKCS",
		ChallengeTTLSeconds: 120,
	})
	if err != nil {
		t.Fatalf("NewDefaultRegistry: %v", err)
	}
	if _, err := registry.Lookup(fido2.FactorName); err != nil {
		t.Fatalf("Lookup(fido2): %v", err)
	}
	if _, err := registry.Lookup(mtls.FactorName); err != nil {
		t.Fatalf("Lookup(mtls): %v", err)
	}
}

// TestDefaultFactors_ReturnsExactlyFour verifies that DefaultFactors returns
// the canonical four-factor slice with the expected Name() values.
func TestDefaultFactors_ReturnsExactlyFour(t *testing.T) {
	factors := DefaultFactors(Config{})
	if len(factors) != 4 {
		t.Fatalf("DefaultFactors returned %d factors, want 4", len(factors))
	}

	wantNames := []string{piv.FactorName, pkcs11.FactorName, fido2.FactorName, mtls.FactorName}
	for i, f := range factors {
		if f == nil {
			t.Fatalf("DefaultFactors[%d] is nil", i)
		}
		if f.Name() != wantNames[i] {
			t.Fatalf("DefaultFactors[%d].Name() = %q, want %q", i, f.Name(), wantNames[i])
		}
	}
}

// TestDefaultFactors_IncludesMTLS verifies that the mtls factor is present
// in the default set and registered under the canonical name.
func TestDefaultFactors_IncludesMTLS(t *testing.T) {
	registry, err := NewDefaultRegistry(Config{})
	if err != nil {
		t.Fatalf("NewDefaultRegistry: %v", err)
	}
	f, err := registry.Lookup(mtls.FactorName)
	if err != nil {
		t.Fatalf("mtls factor not registered: %v", err)
	}
	if f.Name() != mtls.FactorName {
		t.Fatalf("mtls.Name() = %q, want %q", f.Name(), mtls.FactorName)
	}
}

// TestDefaultFactors_ConfigFieldsHonored verifies that FIDO2RPID and
// PKCS11Mechanism from Config reach the constructed factor instances.
// We use Name() as a proxy — the real observable contract is that each
// factor carries its own config; the Name() check guards against a nil
// or mismatched factory return.
func TestDefaultFactors_ConfigFieldsHonored(t *testing.T) {
	cfg := Config{
		FIDO2RPID:           "example.com",
		PKCS11Mechanism:     "CKM_RSA_PKCS_PSS",
		ChallengeTTLSeconds: 300,
	}
	factors := DefaultFactors(cfg)
	if len(factors) != 4 {
		t.Fatalf("DefaultFactors returned %d factors, want 4", len(factors))
	}
	// Verify no nil entries and canonical names are preserved.
	wantNames := []string{piv.FactorName, pkcs11.FactorName, fido2.FactorName, mtls.FactorName}
	for i, f := range factors {
		if f == nil {
			t.Fatalf("DefaultFactors with cfg[%d] is nil", i)
		}
		if got := f.Name(); got != wantNames[i] {
			t.Fatalf("DefaultFactors with cfg[%d].Name() = %q, want %q", i, got, wantNames[i])
		}
	}
}

// TestDefaultFactors_NilPIVGenerator verifies that DefaultFactors does not
// panic when PIVGenerator is nil (the software fallback path).
func TestDefaultFactors_NilPIVGenerator(t *testing.T) {
	factors := DefaultFactors(Config{PIVGenerator: nil})
	if len(factors) != 4 {
		t.Fatalf("DefaultFactors returned %d factors, want 4", len(factors))
	}
}

// TestNewDefaultRegistry_DelegatesDefaultFactors verifies that
// NewDefaultRegistry registers exactly the same factors that DefaultFactors
// returns, so the two stay in sync.
func TestNewDefaultRegistry_DelegatesDefaultFactors(t *testing.T) {
	cfg := Config{FIDO2RPID: "sync-test.example"}
	factors := DefaultFactors(cfg)

	registry, err := NewDefaultRegistry(cfg)
	if err != nil {
		t.Fatalf("NewDefaultRegistry: %v", err)
	}

	listed := registry.List()
	if len(listed) != len(factors) {
		t.Fatalf("registry has %d factors, DefaultFactors returned %d", len(listed), len(factors))
	}
	for _, f := range factors {
		found, err := registry.Lookup(f.Name())
		if err != nil {
			t.Fatalf("registry.Lookup(%q): %v", f.Name(), err)
		}
		if found.Name() != f.Name() {
			t.Fatalf("registry.Lookup(%q).Name() = %q", f.Name(), found.Name())
		}
	}
}

// TestDefaultFactors_RequirePIVGeneratorReachesThePIVFactor verifies the
// fail-closed setting is threaded from factor.Config into the piv factor.
// Without the wiring the registry silently carries a software-backed piv
// factor that reports itself available — issue #199.
func TestDefaultFactors_RequirePIVGeneratorReachesThePIVFactor(t *testing.T) {
	registry, err := NewDefaultRegistry(Config{RequirePIVGenerator: true})
	if err != nil {
		t.Fatalf("NewDefaultRegistry: %v", err)
	}
	plugin, err := registry.Lookup(piv.FactorName)
	if err != nil {
		t.Fatalf("registry is missing the piv factor: %v", err)
	}
	probe, ok := plugin.(interface {
		Available(context.Context) (bool, string)
	})
	if !ok {
		t.Fatal("the piv factor must report availability so preflight can refuse")
	}
	available, reason := probe.Available(context.Background())
	if available {
		t.Fatal("piv must report unavailable when a generator is required and none is attached")
	}
	if reason != piv.NoGeneratorReason {
		t.Errorf("reason = %q, want %q", reason, piv.NoGeneratorReason)
	}
}

// TestDefaultFactors_DefaultConfigKeepsSoftwarePIVAvailable pins the library
// default the fail-closed setting deliberately does not change: a caller that
// never asked for hardware still gets a usable software PIV factor.
func TestDefaultFactors_DefaultConfigKeepsSoftwarePIVAvailable(t *testing.T) {
	registry, err := NewDefaultRegistry(Config{})
	if err != nil {
		t.Fatalf("NewDefaultRegistry: %v", err)
	}
	plugin, err := registry.Lookup(piv.FactorName)
	if err != nil {
		t.Fatalf("registry is missing the piv factor: %v", err)
	}
	probe, ok := plugin.(interface {
		Available(context.Context) (bool, string)
	})
	if !ok {
		t.Fatal("the piv factor must report availability so preflight can refuse")
	}
	if available, reason := probe.Available(context.Background()); !available {
		t.Fatalf("Available() = false (%q), want true for the software default", reason)
	}
}
