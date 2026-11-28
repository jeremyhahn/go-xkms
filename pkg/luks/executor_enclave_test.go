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

package luks

import (
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// TestProtectPassphrase_ByteAccess pins the go-enclave v0.11.1 contract the
// executor relies on: the passphrase is held as an enclave.ByteAccess (the
// type go-luks2 Format and Unlock take), it holds exactly the passphrase
// bytes, and destroyPassphrase releases it.
func TestProtectPassphrase_ByteAccess(t *testing.T) {
	var pass enclave.ByteAccess
	pass, err := protectPassphrase("correct horse battery staple")
	if err != nil {
		t.Fatalf("protectPassphrase: %v", err)
	}
	if !pass.IsAlive() {
		t.Fatal("passphrase enclave is not alive after protectPassphrase")
	}
	if got, want := pass.Size(), len("correct horse battery staple"); got != want {
		t.Fatalf("Size() = %d, want %d", got, want)
	}
	equal, err := pass.EqualTo([]byte("correct horse battery staple"))
	if err != nil {
		t.Fatalf("EqualTo: %v", err)
	}
	if !equal {
		t.Fatal("passphrase enclave does not hold the passphrase")
	}
	if err := destroyPassphrase(pass); err != nil {
		t.Fatalf("destroyPassphrase: %v", err)
	}
	if pass.IsAlive() {
		t.Fatal("passphrase enclave still alive after destroyPassphrase")
	}
}
