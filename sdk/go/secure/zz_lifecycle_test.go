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

package secure_test

import (
	"context"
	"testing"

	xkmssecure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// TestNewTerminalProvider pins the re-exported constructor — the alias
// identity is checked separately by TestAliasedValuesCrossTheModuleBoundary,
// but nothing else in this package calls the constructor itself.
func TestNewTerminalProvider(t *testing.T) {
	p := xkmssecure.NewTerminalProvider()
	if p == nil {
		t.Fatal("NewTerminalProvider returned nil")
	}
}

// TestWipeAll pins the forwarding of WipeAll: a Buffer live when it runs is
// destroyed with every other enclave. The "zz_" prefix keeps it last in the
// package, since it wipes everything the package's tests hold.
func TestWipeAll(t *testing.T) {
	buf, err := xkmssecure.NewBufferFromBytes([]byte("wiped by WipeAll"))
	if err != nil {
		t.Fatalf("NewBufferFromBytes: %v", err)
	}
	if _, err := xkmssecure.WipeAll(context.Background()); err != nil {
		t.Fatalf("WipeAll: %v", err)
	}
	if b := buf.Bytes(); len(b) != 0 {
		t.Fatalf("the buffer survived WipeAll: %d bytes", len(b))
	}
}
