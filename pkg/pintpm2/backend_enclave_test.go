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

package pintpm2

import (
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// TestTPM2Backend_FIDO2Hash_ByteAccess pins the go-enclave v0.11.1 contract
// the FIDO2 PIN hash cache relies on: the cached hash is an
// enclave.ByteAccess holding exactly FIDO2PINHashSize bytes, and
// destroyFIDO2Enclave releases it.
func TestTPM2Backend_FIDO2Hash_ByteAccess(t *testing.T) {
	b, _ := newProvisionedTPM2Backend(t, "user-pin")
	cached := b.fido2Enclave.Load()
	if cached == nil {
		t.Fatal("expected the FIDO2 hash to be cached")
	}
	var enc enclave.ByteAccess = cached
	if got := enc.Size(); got != qrdbsdk.FIDO2PINHashSize {
		t.Fatalf("Size() = %d, want %d", got, qrdbsdk.FIDO2PINHashSize)
	}
	match, err := enc.EqualTo(qrdbsdk.ComputeFIDO2PINHash("user-pin"))
	if err != nil {
		t.Fatalf("EqualTo: %v", err)
	}
	if !match {
		t.Fatal("cached enclave does not hold the PIN hash")
	}
	if err := destroyFIDO2Enclave(enc); err != nil {
		t.Fatalf("destroyFIDO2Enclave: %v", err)
	}
	if enc.IsAlive() {
		t.Fatal("enclave still alive after destroyFIDO2Enclave")
	}
}

// TestTPM2Backend_VerifyFIDO2Hash_NoCacheFailsClosed pins that a backend with
// no cached hash reports false rather than panicking.
func TestTPM2Backend_VerifyFIDO2Hash_NoCacheFailsClosed(t *testing.T) {
	b := NewTPM2Backend(newMockPlatformAuth("", false))
	if b.VerifyFIDO2Hash(qrdbsdk.ComputeFIDO2PINHash("user-pin")) {
		t.Fatal("VerifyFIDO2Hash reported a match with no cached hash")
	}
}
