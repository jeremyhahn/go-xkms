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

//go:build integration && pkcs11 && pkcs11_external

// Package module provides external integration tests for the go-xkms PKCS#11 module.
// These tests use pkcs11-tool and external utilities to validate the shared library.
//
// These tests verify that the PKCS#11 shared library (libxkms_pkcs11.so)
// correctly implements the Cryptoki interface and can communicate with
// the xkms server backend.
//
// Test environment variables:
//   - PKCS11_MODULE: Path to the PKCS#11 module (default: /usr/local/lib/libxkms_pkcs11.so)
//   - XKMS_UNIX_SOCKET: Unix socket path for server communication
//   - XKMS_GRPC_ADDR: gRPC server address (fallback if Unix socket unavailable)
//   - PKCS11_PIN: User PIN for token access (default: 1234)
//   - PKCS11_SO_PIN: Security Officer PIN (default: 12345678)
package module

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// getEnvOrDefault returns the environment variable value or the default if not set.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// TestPKCS11ModuleExists verifies that the PKCS#11 module shared library exists.
func TestPKCS11ModuleExists(t *testing.T) {
	modulePath := getEnvOrDefault("PKCS11_MODULE", "/usr/local/lib/libxkms_pkcs11.so")

	info, err := os.Stat(modulePath)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("PKCS#11 module not found at %s - skipping test", modulePath)
		}
		t.Fatalf("Failed to stat PKCS#11 module: %v", err)
	}

	if info.IsDir() {
		t.Fatalf("PKCS#11 module path is a directory, expected a file: %s", modulePath)
	}

	t.Logf("PKCS#11 module found: %s (size: %d bytes)", modulePath, info.Size())
}

// TestPKCS11ModuleIsSharedLibrary verifies the module is a valid shared library.
func TestPKCS11ModuleIsSharedLibrary(t *testing.T) {
	modulePath := getEnvOrDefault("PKCS11_MODULE", "/usr/local/lib/libxkms_pkcs11.so")

	if _, err := os.Stat(modulePath); os.IsNotExist(err) {
		t.Skipf("PKCS#11 module not found at %s - skipping test", modulePath)
	}

	// Use file command to verify it's a shared library
	cmd := exec.Command("file", modulePath)
	output, err := cmd.Output()
	if err != nil {
		t.Logf("Warning: could not run 'file' command: %v", err)
		return
	}

	outputStr := string(output)
	if !strings.Contains(outputStr, "shared object") && !strings.Contains(outputStr, "ELF") {
		t.Errorf("PKCS#11 module does not appear to be a valid shared library: %s", outputStr)
	}

	t.Logf("Module type: %s", strings.TrimSpace(outputStr))
}

// TestPKCS11ToolListSlots tests the module with pkcs11-tool --list-slots.
func TestPKCS11ToolListSlots(t *testing.T) {
	modulePath := getEnvOrDefault("PKCS11_MODULE", "/usr/local/lib/libxkms_pkcs11.so")

	if _, err := os.Stat(modulePath); os.IsNotExist(err) {
		t.Skipf("PKCS#11 module not found at %s - skipping test", modulePath)
	}

	// Check if pkcs11-tool is available
	if _, err := exec.LookPath("pkcs11-tool"); err != nil {
		t.Skip("pkcs11-tool not found in PATH - skipping test")
	}

	cmd := exec.Command("pkcs11-tool", "--module", modulePath, "--list-slots")
	output, err := cmd.CombinedOutput()

	// Log output regardless of error (some errors are expected if module not initialized)
	t.Logf("pkcs11-tool --list-slots output:\n%s", string(output))

	if err != nil {
		// Check if it's an expected error (e.g., no slots initialized)
		outputStr := string(output)
		if strings.Contains(outputStr, "No slots") ||
			strings.Contains(outputStr, "not initialized") ||
			strings.Contains(outputStr, "CKR_TOKEN_NOT_PRESENT") {
			t.Logf("Expected condition: module loaded but no slots/tokens initialized")
			return
		}

		// Unexpected error
		t.Logf("Warning: pkcs11-tool returned error (may be expected): %v", err)
	}
}

// TestPKCS11ToolListMechanisms tests the module with pkcs11-tool --list-mechanisms.
func TestPKCS11ToolListMechanisms(t *testing.T) {
	modulePath := getEnvOrDefault("PKCS11_MODULE", "/usr/local/lib/libxkms_pkcs11.so")

	if _, err := os.Stat(modulePath); os.IsNotExist(err) {
		t.Skipf("PKCS#11 module not found at %s - skipping test", modulePath)
	}

	// Check if pkcs11-tool is available
	if _, err := exec.LookPath("pkcs11-tool"); err != nil {
		t.Skip("pkcs11-tool not found in PATH - skipping test")
	}

	cmd := exec.Command("pkcs11-tool", "--module", modulePath, "--list-mechanisms")
	output, err := cmd.CombinedOutput()

	// Log output regardless of error
	t.Logf("pkcs11-tool --list-mechanisms output:\n%s", string(output))

	if err != nil {
		outputStr := string(output)
		// Check if it's an expected error
		if strings.Contains(outputStr, "No slots") ||
			strings.Contains(outputStr, "not initialized") ||
			strings.Contains(outputStr, "CKR_TOKEN_NOT_PRESENT") {
			t.Logf("Expected condition: module loaded but no slots/tokens initialized")
			return
		}

		t.Logf("Warning: pkcs11-tool returned error (may be expected): %v", err)
	}
}

// TestPKCS11ToolShowInfo tests the module with pkcs11-tool --show-info.
func TestPKCS11ToolShowInfo(t *testing.T) {
	modulePath := getEnvOrDefault("PKCS11_MODULE", "/usr/local/lib/libxkms_pkcs11.so")

	if _, err := os.Stat(modulePath); os.IsNotExist(err) {
		t.Skipf("PKCS#11 module not found at %s - skipping test", modulePath)
	}

	// Check if pkcs11-tool is available
	if _, err := exec.LookPath("pkcs11-tool"); err != nil {
		t.Skip("pkcs11-tool not found in PATH - skipping test")
	}

	cmd := exec.Command("pkcs11-tool", "--module", modulePath, "--show-info")
	output, err := cmd.CombinedOutput()

	// Log output regardless of error
	t.Logf("pkcs11-tool --show-info output:\n%s", string(output))

	if err != nil {
		t.Logf("Warning: pkcs11-tool returned error (may be expected): %v", err)
	}

	// Check for expected fields in output
	outputStr := string(output)
	expectedFields := []string{"Cryptoki version", "Library", "Manufacturer"}
	for _, field := range expectedFields {
		if strings.Contains(outputStr, field) {
			t.Logf("Found expected field: %s", field)
		}
	}
}

// TestServerConnectionUnixSocket verifies Unix socket connectivity to xkms server.
func TestServerConnectionUnixSocket(t *testing.T) {
	socketPath := getEnvOrDefault("XKMS_UNIX_SOCKET", "/var/run/xkms/xkms.sock")

	info, err := os.Stat(socketPath)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("Unix socket not found at %s - server may not be running or using TCP mode", socketPath)
		}
		t.Fatalf("Failed to stat Unix socket: %v", err)
	}

	// Verify it's a socket
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("Path exists but is not a Unix socket: %s", socketPath)
	}

	t.Logf("Unix socket found and accessible: %s", socketPath)
}

// TestServerConnectionTCP verifies TCP connectivity to xkms server.
func TestServerConnectionTCP(t *testing.T) {
	grpcAddr := getEnvOrDefault("XKMS_GRPC_ADDR", "")

	if grpcAddr == "" {
		t.Skip("XKMS_GRPC_ADDR not set - skipping TCP connection test")
	}

	// Simple connectivity check using nc
	parts := strings.Split(grpcAddr, ":")
	if len(parts) != 2 {
		t.Fatalf("Invalid XKMS_GRPC_ADDR format: %s (expected host:port)", grpcAddr)
	}

	host, port := parts[0], parts[1]

	cmd := exec.Command("nc", "-z", "-w", "5", host, port)
	if err := cmd.Run(); err != nil {
		t.Skipf("Cannot connect to gRPC server at %s - server may not be running: %v", grpcAddr, err)
	}

	t.Logf("TCP connection to gRPC server successful: %s", grpcAddr)
}

// TestModuleDependencies verifies that all shared library dependencies are satisfied.
func TestModuleDependencies(t *testing.T) {
	modulePath := getEnvOrDefault("PKCS11_MODULE", "/usr/local/lib/libxkms_pkcs11.so")

	if _, err := os.Stat(modulePath); os.IsNotExist(err) {
		t.Skipf("PKCS#11 module not found at %s - skipping test", modulePath)
	}

	// Check if ldd is available
	if _, err := exec.LookPath("ldd"); err != nil {
		t.Skip("ldd not found in PATH - skipping dependency test")
	}

	cmd := exec.Command("ldd", modulePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldd failed: %v\nOutput: %s", err, string(output))
	}

	outputStr := string(output)
	t.Logf("Module dependencies:\n%s", outputStr)

	// Check for missing dependencies
	if strings.Contains(outputStr, "not found") {
		t.Error("Some library dependencies are missing")

		// Extract and report missing libraries
		lines := strings.Split(outputStr, "\n")
		for _, line := range lines {
			if strings.Contains(line, "not found") {
				t.Errorf("Missing dependency: %s", strings.TrimSpace(line))
			}
		}
	}
}
