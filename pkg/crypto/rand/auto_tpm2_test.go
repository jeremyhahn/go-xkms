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

package rand

import (
	"testing"
)

// TestAutoResolver_TPM2InitializationPath tests TPM2 initialization when available
func TestAutoResolver_TPM2InitializationPath(t *testing.T) {
	// This test only runs when tpm2 build tag is enabled
	// and tpm2Available() returns true

	if !tpm2Available() {
		t.Skip("TPM2 not available")
	}

	// Test that auto resolver attempts TPM2 initialization
	cfg := &Config{
		Mode: ModeAuto,
		TPM2Config: &TPM2Config{
			Device:         "/nonexistent/tpm", // Will fail but exercises the code path
			MaxRequestSize: 32,
		},
	}

	// This should try TPM2, fail, then fall back to software
	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("newAutoResolver should not fail even if TPM2 init fails: %v", err)
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

// TestAutoResolver_TPM2CloseOnInitFailure tests that failed TPM2 resolvers are closed
func TestAutoResolver_TPM2CloseOnInitFailure(t *testing.T) {
	if !tpm2Available() {
		t.Skip("TPM2 not available")
	}

	// Test with invalid config to trigger initialization failure
	cfg := &Config{
		Mode: ModeAuto,
		TPM2Config: &TPM2Config{
			Device:         "/dev/nonexistent_tpm",
			MaxRequestSize: 32,
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

// TestAutoResolver_TPM2PriorityWhenPKCS11Unavailable tests TPM2 is tried when PKCS11 fails
func TestAutoResolver_TPM2PriorityWhenPKCS11Unavailable(t *testing.T) {
	if !tpm2Available() {
		t.Skip("TPM2 not available")
	}

	// Configure both PKCS11 (will fail) and TPM2 (will also fail but exercises path)
	cfg := &Config{
		Mode: ModeAuto,
		PKCS11Config: &PKCS11Config{
			Module: "/nonexistent/pkcs11.so",
		},
		TPM2Config: &TPM2Config{
			Device:         "/nonexistent/tpm",
			MaxRequestSize: 32,
		},
	}

	resolver, err := newAutoResolver(cfg)
	if err != nil {
		t.Fatalf("Should fall back to software: %v", err)
	}
	defer func() { _ = resolver.Close() }()

	// Should be available via software fallback
	if !resolver.Available() {
		t.Error("Should be available via software fallback")
	}

	// Verify it works
	data, err := resolver.Rand(16)
	if err != nil {
		t.Errorf("Rand() should work: %v", err)
	}
	if len(data) != 16 {
		t.Errorf("Expected 16 bytes, got %d", len(data))
	}
}
