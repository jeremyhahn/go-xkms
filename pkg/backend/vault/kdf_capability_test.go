// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

//go:build vault

package vault

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestBackendDoesNotAdvertiseKeyDerivation pins a deliberate absence.
//
// This backend's symmetric keys never leave the service that holds them, and
// that service exposes no key-derivation operation over them. There is
// therefore no correct implementation of types.SymmetricKeyDeriver here: the
// only ways to produce a key would be to export material the service will not
// release, or to run the KDF over something that is not the key — which is the
// defect that made C_DeriveKey derive from a key's label.
//
// Not implementing the interface is what makes the refusal truthful. The
// service layer's type assertion fails and the caller receives
// ErrOperationNotSupported naming this backend, before any derivation is
// attempted. A stub that satisfied the interface and returned an error would
// advertise a capability that does not exist.
func TestBackendDoesNotAdvertiseKeyDerivation(t *testing.T) {
	var provider types.KeyProvider = (*Backend)(nil)

	if _, ok := provider.(types.SymmetricKeyDeriver); ok {
		t.Fatal("this backend advertises derivation from a stored symmetric key, but it cannot " +
			"reach that key's material and has no KDF over it; either the implementation is real " +
			"and this test should be replaced with an oracle comparison, or the capability is a " +
			"stub and must be removed")
	}
}
