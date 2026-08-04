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

package backend

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// contains reports whether algos includes want.
func contains(algos []keys.Algorithm, want keys.Algorithm) bool {
	for _, a := range algos {
		if a == want {
			return true
		}
	}
	return false
}

func TestSupportedAlgorithms_TPM2ExcludesEd25519(t *testing.T) {
	algos := SupportedAlgorithms(types.StoreTPM2)

	if contains(algos, keys.AlgorithmEd25519) {
		t.Fatalf("SupportedAlgorithms(StoreTPM2) must not include Ed25519 (TPM 2.0 has no native Ed25519 key object); got %v", algos)
	}
	for _, want := range []keys.Algorithm{keys.AlgorithmRSA, keys.AlgorithmECDSAP256, keys.AlgorithmECDSAP384, keys.AlgorithmECDSAP521} {
		if !contains(algos, want) {
			t.Errorf("SupportedAlgorithms(StoreTPM2) missing expected algorithm %q; got %v", want, algos)
		}
	}
	if len(algos) != 4 {
		t.Errorf("SupportedAlgorithms(StoreTPM2) = %v, want exactly 4 algorithms", algos)
	}
}

func TestSupportedAlgorithms_SoftwarePKCS11PhoneIncludeFullSet(t *testing.T) {
	full := []keys.Algorithm{
		keys.AlgorithmEd25519,
		keys.AlgorithmRSA,
		keys.AlgorithmECDSAP256,
		keys.AlgorithmECDSAP384,
		keys.AlgorithmECDSAP521,
	}

	for _, st := range []types.StoreType{types.StoreSoftware, types.StorePKCS11, types.StorePhone} {
		algos := SupportedAlgorithms(st)
		if len(algos) != len(full) {
			t.Errorf("SupportedAlgorithms(%s) = %v, want %v", st, algos, full)
			continue
		}
		for _, want := range full {
			if !contains(algos, want) {
				t.Errorf("SupportedAlgorithms(%s) missing %q; got %v", st, want, algos)
			}
		}
	}
}

// TestSupportedAlgorithms_UnknownStoreTypeFailsOpen ensures a store type this
// package has no explicit rule for (e.g. a remote xkms backend the client
// cannot introspect, or types.StoreUnknown) returns the full algorithm set
// rather than blocking generation client-side; the backend itself remains
// the final authority and GenerateKey returns its own typed error for an
// actually-unsupported combination.
func TestSupportedAlgorithms_UnknownStoreTypeFailsOpen(t *testing.T) {
	algos := SupportedAlgorithms(types.StoreUnknown)
	if !contains(algos, keys.AlgorithmEd25519) {
		t.Fatalf("SupportedAlgorithms(StoreUnknown) should fail open to the full set; got %v", algos)
	}
	if len(algos) != 5 {
		t.Errorf("SupportedAlgorithms(StoreUnknown) = %v, want all 5 algorithms", algos)
	}
}

// TestSupportedAlgorithms_ReturnsIndependentSlice guards against a caller's
// mutation of the returned slice corrupting the package-level defaults on a
// subsequent call.
func TestSupportedAlgorithms_ReturnsIndependentSlice(t *testing.T) {
	first := SupportedAlgorithms(types.StoreTPM2)
	first[0] = keys.AlgorithmEd25519

	second := SupportedAlgorithms(types.StoreTPM2)
	if contains(second, keys.AlgorithmEd25519) && second[0] == keys.AlgorithmEd25519 {
		t.Fatalf("mutating a previously returned slice affected a later call: %v", second)
	}
}
