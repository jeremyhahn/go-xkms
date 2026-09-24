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

// TestPurgeLifecycle pins the forwarding contract of CatchInterrupt,
// EnablePurge, Purge and PurgeOrPanic end to end: PurgeOrPanic panics until
// the subsystem is armed, and stops panicking once it is.
//
// This depends on no earlier test in this package having armed the secure
// subsystem (secure_test.go and secure_reexport_test.go do not call
// CatchInterrupt or EnablePurge). The "zz_" file name prefix keeps this file
// last in the package's test compilation order, so TestPurgeBeforeInit in
// secure_test.go still observes the pre-arm NotInitializedError path when
// the whole package's tests run together.
func TestPurgeLifecycle(t *testing.T) {
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("PurgeOrPanic did not panic before the subsystem was armed")
			}
		}()
		xkmssecure.PurgeOrPanic()
	}()

	xkmssecure.CatchInterrupt()
	xkmssecure.EnablePurge() // idempotent: CatchInterrupt already armed the subsystem

	if err := xkmssecure.Purge(); err != nil {
		t.Fatalf("Purge after CatchInterrupt: %v", err)
	}

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("PurgeOrPanic panicked after the subsystem was armed: %v", r)
			}
		}()
		xkmssecure.PurgeOrPanic()
	}()
}
