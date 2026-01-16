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

package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestBackendsCmd_Exists(t *testing.T) {
	if backendsCmd == nil {
		t.Fatal("backendsCmd should not be nil")
	}
}

func TestBackendsCmd_Properties(t *testing.T) {
	if backendsCmd.Use != "backends" {
		t.Errorf("backendsCmd.Use = %v, want backends", backendsCmd.Use)
	}

	if backendsCmd.Short == "" {
		t.Error("backendsCmd.Short should not be empty")
	}
}

func TestBackendsCmd_HasSubcommands(t *testing.T) {
	subcommands := backendsCmd.Commands()

	// Check for list and info subcommands
	foundList := false
	foundInfo := false

	for _, cmd := range subcommands {
		name := cmd.Name()
		if name == "list" {
			foundList = true
		}
		// The info command Use is "info <backend>", but Name() returns "info"
		if strings.HasPrefix(cmd.Use, "info") {
			foundInfo = true
		}
	}

	if !foundList {
		t.Error("expected subcommand 'list' not found")
	}

	if !foundInfo {
		t.Error("expected subcommand 'info' not found")
	}
}

func TestBackendsListCmd_Exists(t *testing.T) {
	if backendsListCmd == nil {
		t.Fatal("backendsListCmd should not be nil")
	}
}

func TestBackendsListCmd_Properties(t *testing.T) {
	if backendsListCmd.Use != "list" {
		t.Errorf("backendsListCmd.Use = %v, want list", backendsListCmd.Use)
	}

	if backendsListCmd.Short == "" {
		t.Error("backendsListCmd.Short should not be empty")
	}
}

func TestBackendsInfoCmd_Exists(t *testing.T) {
	if backendsInfoCmd == nil {
		t.Fatal("backendsInfoCmd should not be nil")
	}
}

func TestBackendsInfoCmd_Properties(t *testing.T) {
	if backendsInfoCmd.Use != "info <backend>" {
		t.Errorf("backendsInfoCmd.Use = %v, want 'info <backend>'", backendsInfoCmd.Use)
	}

	if backendsInfoCmd.Short == "" {
		t.Error("backendsInfoCmd.Short should not be empty")
	}
}

func TestGetBackendCapabilities_Software(t *testing.T) {
	caps, err := getBackendCapabilities("software")
	if err != nil {
		t.Fatalf("getBackendCapabilities(software) returned error: %v", err)
	}

	if !caps.Keys {
		t.Error("software backend should support Keys")
	}
	if caps.HardwareBacked {
		t.Error("software backend should not be hardware backed")
	}
	if !caps.Signing {
		t.Error("software backend should support Signing")
	}
	if !caps.Decryption {
		t.Error("software backend should support Decryption")
	}
	if !caps.KeyRotation {
		t.Error("software backend should support KeyRotation")
	}
	if !caps.SymmetricEncryption {
		t.Error("software backend should support SymmetricEncryption")
	}
	if !caps.Import {
		t.Error("software backend should support Import")
	}
	if !caps.Export {
		t.Error("software backend should support Export")
	}
}

func TestGetBackendCapabilities_PKCS8(t *testing.T) {
	caps, err := getBackendCapabilities("pkcs8")
	if err != nil {
		t.Fatalf("getBackendCapabilities(pkcs8) returned error: %v", err)
	}

	if !caps.Keys {
		t.Error("pkcs8 backend should support Keys")
	}
	if caps.HardwareBacked {
		t.Error("pkcs8 backend should not be hardware backed")
	}
	if !caps.Signing {
		t.Error("pkcs8 backend should support Signing")
	}
}

func TestGetBackendCapabilities_PKCS11(t *testing.T) {
	caps, err := getBackendCapabilities("pkcs11")
	if err != nil {
		t.Fatalf("getBackendCapabilities(pkcs11) returned error: %v", err)
	}

	if !caps.Keys {
		t.Error("pkcs11 backend should support Keys")
	}
	if !caps.HardwareBacked {
		t.Error("pkcs11 backend should be hardware backed")
	}
	if !caps.Signing {
		t.Error("pkcs11 backend should support Signing")
	}
	if caps.KeyRotation {
		t.Error("pkcs11 backend should not support KeyRotation")
	}
}

func TestGetBackendCapabilities_TPM2(t *testing.T) {
	caps, err := getBackendCapabilities("tpm2")
	if err != nil {
		t.Fatalf("getBackendCapabilities(tpm2) returned error: %v", err)
	}

	if !caps.Keys {
		t.Error("tpm2 backend should support Keys")
	}
	if !caps.HardwareBacked {
		t.Error("tpm2 backend should be hardware backed")
	}
	if !caps.Signing {
		t.Error("tpm2 backend should support Signing")
	}
	if caps.KeyRotation {
		t.Error("tpm2 backend should not support KeyRotation")
	}
}

func TestGetBackendCapabilities_CloudKMS(t *testing.T) {
	cloudBackends := []string{"awskms", "gcpkms", "azurekv"}

	for _, backend := range cloudBackends {
		t.Run(backend, func(t *testing.T) {
			caps, err := getBackendCapabilities(backend)
			if err != nil {
				t.Fatalf("getBackendCapabilities(%s) returned error: %v", backend, err)
			}

			if !caps.Keys {
				t.Errorf("%s backend should support Keys", backend)
			}
			if !caps.HardwareBacked {
				t.Errorf("%s backend should be hardware backed", backend)
			}
			if !caps.KeyRotation {
				t.Errorf("%s backend should support KeyRotation", backend)
			}
		})
	}
}

func TestGetBackendCapabilities_Vault(t *testing.T) {
	caps, err := getBackendCapabilities("vault")
	if err != nil {
		t.Fatalf("getBackendCapabilities(vault) returned error: %v", err)
	}

	if !caps.Keys {
		t.Error("vault backend should support Keys")
	}
	if caps.HardwareBacked {
		t.Error("vault backend should not be hardware backed")
	}
	if !caps.KeyRotation {
		t.Error("vault backend should support KeyRotation")
	}
	if !caps.Export {
		t.Error("vault backend should support Export")
	}
}

func TestGetBackendCapabilities_Unknown(t *testing.T) {
	_, err := getBackendCapabilities("unknown-backend")
	if err == nil {
		t.Error("getBackendCapabilities(unknown-backend) should return error")
	}
}

func TestListBackendsLocal(t *testing.T) {
	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	// This should not panic
	listBackendsLocal(printer)

	// Verify some output was generated
	if buf.Len() == 0 {
		t.Error("listBackendsLocal should produce output")
	}
}

func TestBackendInfoLocal_ValidBackend(t *testing.T) {
	buf := new(bytes.Buffer)
	printer := NewPrinter("json", buf)

	// Test with a valid backend
	backendInfoLocal(printer, "software")

	// Verify some output was generated
	if buf.Len() == 0 {
		t.Error("backendInfoLocal should produce output for valid backend")
	}
}

func TestBackendsListCmd_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			buf := new(bytes.Buffer)
			printer := NewPrinter(format, buf)

			// Call listBackendsLocal which doesn't require a running server
			listBackendsLocal(printer)

			// Verify output was generated
			if buf.Len() == 0 {
				t.Errorf("listBackendsLocal with %s format should produce output", format)
			}
		})
	}
}

func TestBackendsInfoCmd_AllFormats(t *testing.T) {
	formats := []string{"text", "json", "table"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			buf := new(bytes.Buffer)
			printer := NewPrinter(format, buf)

			// Call backendInfoLocal which doesn't require a running server
			backendInfoLocal(printer, "software")

			// Verify output was generated
			if buf.Len() == 0 {
				t.Errorf("backendInfoLocal with %s format should produce output", format)
			}
		})
	}
}
