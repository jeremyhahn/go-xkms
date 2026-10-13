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

//go:build pkcs11

package pkcs11

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/enclaveprovider/enclaveprovidertest"
)

// TestEnclaveProvider_Conformance runs go-enclave's provider conformance
// suite, in both modes, over a SoftHSM AES-256-GCM sealing key.
//
// The residue sweep is skipped: SoftHSM decrypts inside this process, and
// when Go's asynchronous preemption signal lands while the plaintext is in
// vector registers the kernel saves them on the thread's signal stack, which
// the Go runtime allocates from its heap, beyond any wipe. Under
// GODEBUG=asyncpreemptoff=1 the sweep finds no copy, so the provider retains
// none; a hardware token decrypts on the device. The tampered-blob property
// needs SoftHSM 2.7.0, which answers a GCM tag mismatch with
// CKR_ENCRYPTED_DATA_INVALID (see sealer_authentication_test.go).
func TestEnclaveProvider_Conformance(t *testing.T) {
	b, attrs := newSealingBackend(t, "enclave-provider", "enclave-provider-seal")
	enclaveprovidertest.Run(t, enclaveprovidertest.Backend{
		Sealer:           b,
		KeyAttributes:    attrs,
		SkipResidueSweep: "SoftHSM decrypts in this process; a preemption signal can save its plaintext registers on the Go-allocated signal stack (no copy under GODEBUG=asyncpreemptoff=1)",
	})
}
