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
	"debug/elf"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// requireModulePath returns the path of the built PKCS#11 shared library.
//
// run_with_server compiles build/lib/libxkms_pkcs11.so before every PKCS#11
// Makefile target and exports PKCS11_MODULE, so a missing library means the
// build step failed. Skipping on it reported the module as verified when it had
// never even been produced.
func requireModulePath(t *testing.T) string {
	t.Helper()

	modulePath := getEnvOrDefault("PKCS11_MODULE", "/usr/local/lib/libxkms_pkcs11.so")
	info, err := os.Stat(modulePath)
	if err != nil {
		t.Fatalf("PKCS#11 module not readable at %s: %v; the harness builds it with "+
			"`go build -buildmode=c-shared ./cmd/pkcs11-module` and exports PKCS11_MODULE",
			modulePath, err)
	}
	if info.IsDir() {
		t.Fatalf("PKCS#11 module path is a directory, expected a file: %s", modulePath)
	}
	return modulePath
}

// requireBinary asserts an external tool the harness depends on is on PATH.
func requireBinary(t *testing.T, name, provider string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Fatalf("%s is not on PATH: %v; the devcontainer image provides it via %s",
			name, err, provider)
	}
}

// TestPKCS11ModuleExists verifies that the PKCS#11 module shared library exists.
func TestPKCS11ModuleExists(t *testing.T) {
	modulePath := requireModulePath(t)

	info, err := os.Stat(modulePath)
	if err != nil {
		t.Fatalf("Failed to stat PKCS#11 module: %v", err)
	}
	if info.Size() == 0 {
		t.Fatalf("PKCS#11 module at %s is empty", modulePath)
	}

	t.Logf("PKCS#11 module found: %s (size: %d bytes)", modulePath, info.Size())
}

// TestPKCS11ModuleIsSharedLibrary verifies the module really is a dynamically
// loadable shared object.
//
// The ELF header is parsed directly instead of shelling out to file(1): the
// previous version returned early with a warning when the tool was missing, so
// on a host without file(1) it asserted nothing at all while still reporting
// PASS. debug/elf also checks more than a substring match — the object must be
// ET_DYN (what dlopen needs) and expose the Cryptoki entry point.
func TestPKCS11ModuleIsSharedLibrary(t *testing.T) {
	modulePath := requireModulePath(t)

	f, err := elf.Open(modulePath)
	if err != nil {
		t.Fatalf("PKCS#11 module at %s is not a valid ELF object: %v", modulePath, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			t.Errorf("closing ELF module: %v", cerr)
		}
	}()

	if f.Type != elf.ET_DYN {
		t.Fatalf("PKCS#11 module ELF type = %v, want %v (it must be dlopen-able)", f.Type, elf.ET_DYN)
	}

	syms, err := f.DynamicSymbols()
	if err != nil {
		t.Fatalf("reading dynamic symbols from %s: %v", modulePath, err)
	}
	const entryPoint = "C_GetFunctionList"
	for _, sym := range syms {
		if sym.Name == entryPoint {
			t.Logf("module %s: %v, exports %s", modulePath, f.Type, entryPoint)
			return
		}
	}
	t.Fatalf("PKCS#11 module does not export %s; a Cryptoki library is unusable without it", entryPoint)
}

// TestPKCS11ToolListSlots tests the module with pkcs11-tool --list-slots.
func TestPKCS11ToolListSlots(t *testing.T) {
	modulePath := requireModulePath(t)
	requireBinary(t, "pkcs11-tool", "the opensc package")

	cmd := exec.Command("pkcs11-tool", "--module", modulePath, "--list-slots")
	output, err := cmd.CombinedOutput()
	t.Logf("pkcs11-tool --list-slots output:\n%s", string(output))
	if err != nil {
		t.Fatalf("pkcs11-tool --list-slots failed: %v", err)
	}

	// The "no slots / token not present" branch this test used to tolerate
	// cannot happen: SlotManager always publishes slot 0 with a token
	// (pkg/pkcs11/module/token.go NewSlotManager), so an empty slot list is a
	// module defect, not an environment condition.
	if !strings.Contains(string(output), "Slot 0") {
		t.Fatalf("pkcs11-tool --list-slots did not report slot 0; the module always publishes it:\n%s", string(output))
	}
}

// TestPKCS11ToolListMechanisms tests the module with pkcs11-tool --list-mechanisms.
func TestPKCS11ToolListMechanisms(t *testing.T) {
	modulePath := requireModulePath(t)
	requireBinary(t, "pkcs11-tool", "the opensc package")

	cmd := exec.Command("pkcs11-tool", "--module", modulePath, "--list-mechanisms")
	output, err := cmd.CombinedOutput()
	t.Logf("pkcs11-tool --list-mechanisms output:\n%s", string(output))
	if err != nil {
		t.Fatalf("pkcs11-tool --list-mechanisms failed: %v", err)
	}

	// Same reasoning as --list-slots: slot 0 always carries a token, and the
	// module's mechanism table (defaultMechanismInfo) always advertises the
	// RSA PKCS#1 family, so an empty or failing listing is a real regression.
	if !strings.Contains(string(output), "RSA-PKCS") {
		t.Fatalf("mechanism list does not advertise RSA-PKCS; the module always publishes it:\n%s", string(output))
	}
}

// TestPKCS11ToolShowInfo tests the module with pkcs11-tool --show-info.
func TestPKCS11ToolShowInfo(t *testing.T) {
	modulePath := requireModulePath(t)
	requireBinary(t, "pkcs11-tool", "the opensc package")

	cmd := exec.Command("pkcs11-tool", "--module", modulePath, "--show-info")
	output, err := cmd.CombinedOutput()
	t.Logf("pkcs11-tool --show-info output:\n%s", string(output))
	if err != nil {
		t.Fatalf("pkcs11-tool --show-info failed: %v", err)
	}

	// C_GetInfo is answered entirely from the module's own CK_INFO, so every
	// one of these fields is always present. The old loop logged the ones it
	// found and never failed on the ones it did not, which meant a module
	// returning an empty CK_INFO still passed.
	outputStr := string(output)
	for _, field := range []string{"Cryptoki version", "Library", "Manufacturer"} {
		if !strings.Contains(outputStr, field) {
			t.Errorf("C_GetInfo output is missing %q:\n%s", field, outputStr)
		}
	}
}

// TestServerConnectionUnixSocket verifies Unix socket connectivity to xkms server.
func TestServerConnectionUnixSocket(t *testing.T) {
	socketPath := getEnvOrDefault("XKMS_UNIX_SOCKET", "/var/run/xkms/xkms.sock")

	// run_with_server polls for this socket before handing control to the test
	// binary, so its absence means xkms-server never came up.
	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("Unix socket not present at %s: %v; xkms-server must be running "+
			"(XKMS_UNIX_SOCKET selects a different path)", socketPath, err)
	}

	// Verify it's a socket
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("Path exists but is not a Unix socket: %s", socketPath)
	}

	t.Logf("Unix socket found and accessible: %s", socketPath)
}

// TestServerConnectionTCP verifies TCP connectivity to xkms server.
func TestServerConnectionTCP(t *testing.T) {
	// The PKCS#11 Makefile targets export XKMS_GRPC_ADDR=xkms-server:9443.
	grpcAddr := os.Getenv("XKMS_GRPC_ADDR")
	if grpcAddr == "" {
		t.Fatal("XKMS_GRPC_ADDR is not set; the PKCS#11 harness must point the test at " +
			"the xkms-server gRPC endpoint")
	}
	requireBinary(t, "nc", "netcat-openbsd")

	// Simple connectivity check using nc
	parts := strings.Split(grpcAddr, ":")
	if len(parts) != 2 {
		t.Fatalf("Invalid XKMS_GRPC_ADDR format: %s (expected host:port)", grpcAddr)
	}

	host, port := parts[0], parts[1]

	cmd := exec.Command("nc", "-z", "-w", "5", host, port)
	if err := cmd.Run(); err != nil {
		t.Fatalf("cannot reach the gRPC server at %s: %v; run_with_server waits for this "+
			"port before starting the tests", grpcAddr, err)
	}

	t.Logf("TCP connection to gRPC server successful: %s", grpcAddr)
}

// TestModuleDependencies verifies that all shared library dependencies are satisfied.
func TestModuleDependencies(t *testing.T) {
	modulePath := requireModulePath(t)
	requireBinary(t, "ldd", "libc-bin")

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
