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
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/factor/fido2"
	"github.com/jeremyhahn/go-xkms/pkg/factor/piv"
	"github.com/jeremyhahn/go-xkms/pkg/factor/pkcs11"
)

func TestNewDefaultRegistry_RegistersAllFactors(t *testing.T) {
	registry, err := NewDefaultRegistry(Config{})
	if err != nil {
		t.Fatalf("NewDefaultRegistry: %v", err)
	}

	for _, name := range []string{piv.FactorName, pkcs11.FactorName, fido2.FactorName} {
		f, err := registry.Lookup(name)
		if err != nil {
			t.Fatalf("Lookup(%q): %v", name, err)
		}
		if f.Name() != name {
			t.Fatalf("Lookup(%q).Name() = %q", name, f.Name())
		}
	}

	if got := len(registry.List()); got != 3 {
		t.Fatalf("registry has %d factors, want 3: %v", got, registry.List())
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
}
