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

package ssh_test

import (
	"slices"
	"testing"

	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// TestSupportedAlgorithms_TPM2ExcludesEd25519 verifies the SDK re-export
// mirrors pkg/ssh/backend.SupportedAlgorithms: TPM 2.0 has no native Ed25519
// key object type, so it must not appear in the category's algorithm list.
func TestSupportedAlgorithms_TPM2ExcludesEd25519(t *testing.T) {
	algos := sdkssh.SupportedAlgorithms("tpm2")

	if slices.Contains(algos, "ed25519") {
		t.Fatalf("SupportedAlgorithms(%q) = %v, must not include ed25519", "tpm2", algos)
	}
	for _, want := range []string{"rsa", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521"} {
		if !slices.Contains(algos, want) {
			t.Errorf("SupportedAlgorithms(%q) missing %q; got %v", "tpm2", want, algos)
		}
	}
}

// TestSupportedAlgorithms_UnknownCategoryFailsOpen verifies an unrecognized
// or remote-only category (e.g. "xkms", "" ) falls back to the full
// algorithm set rather than blocking generation client-side.
func TestSupportedAlgorithms_UnknownCategoryFailsOpen(t *testing.T) {
	for _, category := range []string{"xkms", "", "some-future-backend"} {
		algos := sdkssh.SupportedAlgorithms(category)
		if !slices.Contains(algos, "ed25519") {
			t.Errorf("SupportedAlgorithms(%q) = %v, want full set including ed25519", category, algos)
		}
		if len(algos) != 5 {
			t.Errorf("SupportedAlgorithms(%q) = %v, want 5 algorithms", category, algos)
		}
	}
}

// TestSupportedAlgorithms_SoftwarePKCS11PhoneIncludeEd25519 verifies the
// backend categories that support Ed25519 natively continue to offer it.
func TestSupportedAlgorithms_SoftwarePKCS11PhoneIncludeEd25519(t *testing.T) {
	for _, category := range []string{"software", "pkcs11", "phone"} {
		algos := sdkssh.SupportedAlgorithms(category)
		if !slices.Contains(algos, "ed25519") {
			t.Errorf("SupportedAlgorithms(%q) = %v, want ed25519 included", category, algos)
		}
	}
}
