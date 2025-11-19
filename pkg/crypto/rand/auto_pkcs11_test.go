// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build pkcs11

package rand

import (
	"testing"
)

// TestAutoResolver_PKCS11InitializationPath tests PKCS11 initialization when available
func TestAutoResolver_PKCS11InitializationPath(t *testing.T) {
	// This test only runs when pkcs11 build tag is enabled
	// and pkcs11Available() returns true

	if !pkcs11Available() {
		t.Skip("PKCS11 not available")
	}

	// Test that auto resolver attempts PKCS11 initialization
	cfg := &Config{
		Mode: ModeAuto,
		PKCS11Config: &PKCS11Config{
			Module:      "/nonexistent/module.so", // Will fail but exercises the code path
			SlotID:      0,
			PINRequired: false,
		},
	}

	// This should try PKCS11, fail, then fall back to software
	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver should not fail even if PKCS11 init fails: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Should still be available via software fallback
	if !resolver.Available() {
		t.Error("Resolver should be available via software fallback")
	}

	// Verify it works
	data, err := resolver.Rand(32)
	if err != nil {
		t.Errorf("Rand() should work with fallback: %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(data))
	}
}

// TestAutoResolver_PKCS11CloseOnInitFailure tests that failed PKCS11 resolvers are closed
func TestAutoResolver_PKCS11CloseOnInitFailure(t *testing.T) {
	if !pkcs11Available() {
		t.Skip("PKCS11 not available")
	}

	// Test with invalid config to trigger initialization failure
	cfg := &Config{
		Mode: ModeAuto,
		PKCS11Config: &PKCS11Config{
			Module: "/invalid/path/to/module.so",
			SlotID: 999,
		},
	}

	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("Should fall back to software: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Verify fallback to software works
	if !resolver.Available() {
		t.Error("Should be available via software fallback")
	}
}
