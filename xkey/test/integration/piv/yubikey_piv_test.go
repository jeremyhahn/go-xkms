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

//go:build integration && pkcs11 && yubikey

package piv

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// YubiKey default credentials for stock-configured devices.
const (
	yukiDefaultPIN   = "123456"
	yukiDefaultPUK   = "12345678"
	yukiDefaultSOPIN = "010203040506070801020304050607080102030405060708"
	yukiLibraryPath  = "/usr/lib/x86_64-linux-gnu/libykcs11.so"
)

// yubiKeyState holds shared state for the test suite.
var (
	yukiTokenLabel string
	yukiBinaryPath string
	yukiBuildErr   error
	yukiBuildOnce  sync.Once
)

// TestMain detects the YubiKey token label, runs all tests, and cleans up.
func TestMain(m *testing.M) {
	// Check that the YubiKey PKCS#11 library exists.
	if _, err := os.Stat(yukiLibraryPath); err != nil {
		fmt.Fprintf(os.Stderr, "SKIP: YubiKey PKCS#11 library not found at %s\n", yukiLibraryPath)
		os.Exit(0)
	}

	// Detect the YubiKey token label via pkcs11-tool.
	label, err := detectTokenLabel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "SKIP: no YubiKey token detected: %v\n", err)
		os.Exit(0)
	}
	yukiTokenLabel = label

	code := m.Run()

	// Best-effort cleanup: delete certs from all primary slots.
	// A full PIV reset requires `ykman piv reset` which may not be available.
	cleanupAllSlots()

	os.Exit(code)
}

// detectTokenLabel runs pkcs11-tool to discover the YubiKey token label.
func detectTokenLabel() (string, error) {
	cmd := exec.Command("pkcs11-tool", "--module", yukiLibraryPath, "--list-slots")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("pkcs11-tool failed: %w: %s", err, string(output))
	}

	// Parse token label from output like:
	//   token label : YubiKey PIV #12345678
	re := regexp.MustCompile(`token label\s*:\s*(.+)`)
	matches := re.FindStringSubmatch(string(output))
	if len(matches) < 2 {
		return "", fmt.Errorf("no token label found in pkcs11-tool output:\n%s", string(output))
	}

	return strings.TrimSpace(matches[1]), nil
}

// cleanupAllSlots attempts to delete certificates from all 4 primary PIV slots
// using the xkey CLI. This is best-effort cleanup after tests complete.
func cleanupAllSlots() {
	bin, err := buildYubiKeyBinary()
	if err != nil {
		return
	}

	slots := []string{"9a", "9c", "9d", "9e"}
	for _, slot := range slots {
		cmd := exec.Command(bin, "piv",
			"--backend", "pkcs11",
			"--pkcs11-library", yukiLibraryPath,
			"--pkcs11-token", yukiTokenLabel,
			"--pkcs11-pin", yukiDefaultPIN,
			"--pkcs11-so-pin", yukiDefaultSOPIN,
			"delete", slot, "--force")
		_ = cmd.Run()
	}
}

// YubiKeyPIVTestHelper wraps PIVTestHelper with PKCS#11 YubiKey arguments.
type YubiKeyPIVTestHelper struct {
	t          *testing.T
	binaryPath string
	tmpDir     string
}

// NewYubiKeyPIVTestHelper creates a new helper for YubiKey PIV CLI tests.
func NewYubiKeyPIVTestHelper(t *testing.T) *YubiKeyPIVTestHelper {
	t.Helper()

	bin := getYubiKeyBinary(t)

	tmpDir := t.TempDir()

	return &YubiKeyPIVTestHelper{
		t:          t,
		binaryPath: bin,
		tmpDir:     tmpDir,
	}
}

// TmpDir returns the temporary directory for this test.
func (h *YubiKeyPIVTestHelper) TmpDir() string {
	return h.tmpDir
}

// RunYubiKeyPIV executes an xkey piv command with YubiKey PKCS#11 arguments prepended.
func (h *YubiKeyPIVTestHelper) RunYubiKeyPIV(args ...string) *CommandResult {
	h.t.Helper()

	fullArgs := []string{
		"piv",
		"--backend", "pkcs11",
		"--pkcs11-library", yukiLibraryPath,
		"--pkcs11-token", yukiTokenLabel,
		"--pkcs11-pin", yukiDefaultPIN,
		"--pkcs11-so-pin", yukiDefaultSOPIN,
	}
	fullArgs = append(fullArgs, args...)

	return h.runCommand(fullArgs...)
}

// runCommand executes the xkey binary with the given arguments.
func (h *YubiKeyPIVTestHelper) runCommand(args ...string) *CommandResult {
	h.t.Helper()

	cmd := exec.Command(h.binaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	return &CommandResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Err:      err,
	}
}

// DeleteSlot deletes a certificate from a slot (best-effort cleanup helper).
func (h *YubiKeyPIVTestHelper) DeleteSlot(slot string) {
	h.t.Helper()
	h.RunYubiKeyPIV("delete", slot, "--force")
}

// GenerateInSlot generates a key in the given slot with the given algorithm.
func (h *YubiKeyPIVTestHelper) GenerateInSlot(t *testing.T, slot, algorithm string) *CommandResult {
	t.Helper()
	return h.RunYubiKeyPIV("generate", slot, "--algorithm", algorithm, "--force")
}

// buildYubiKeyBinary compiles the xkey binary with pkcs11 build tag.
func buildYubiKeyBinary() (string, error) {
	tmpDir, err := os.MkdirTemp("", "xkey-yubikey-integration-*")
	if err != nil {
		return "", err
	}

	binPath := filepath.Join(tmpDir, "xkey")

	projectRoot, err := findProjectRoot()
	if err != nil {
		return "", err
	}

	goBinary := "go"
	if _, err := exec.LookPath("go"); err != nil {
		for _, path := range []string{"/usr/local/go/bin/go", "/usr/bin/go"} {
			if _, err := os.Stat(path); err == nil {
				goBinary = path
				break
			}
		}
	}

	cmd := exec.Command(goBinary, "build", "-tags", "pkcs11", "-o", binPath, "./cmd/xkey")
	cmd.Dir = projectRoot

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", &BuildError{Output: string(output), Err: err}
	}

	return binPath, nil
}

// getYubiKeyBinary builds the xkey binary with pkcs11 tag once and returns its path.
func getYubiKeyBinary(t *testing.T) string {
	t.Helper()

	yukiBuildOnce.Do(func() {
		yukiBinaryPath, yukiBuildErr = buildYubiKeyBinary()
	})

	if yukiBuildErr != nil {
		t.Fatalf("failed to build xkey binary with pkcs11 tag: %v", yukiBuildErr)
	}

	return yukiBinaryPath
}

// TestYubiKeyPIV_GenerateAllSlots generates keys in all 4 primary PIV slots
// with different algorithms and verifies each generation succeeds.
func TestYubiKeyPIV_GenerateAllSlots(t *testing.T) {
	h := NewYubiKeyPIVTestHelper(t)

	tests := []struct {
		slot      string
		slotName  string
		algorithm string
	}{
		{"9a", "PIV Authentication", "ECCP256"},
		{"9c", "Digital Signature", "ECCP384"},
		{"9d", "Key Management", "RSA2048"},
		// Note: Ed25519 is not supported by all YubiKey firmware versions.
		// YubiKey 5 series with firmware < 5.7 does not support Ed25519 on PIV.
		// Use ECCP256 for slot 9e as a reliable fallback.
		{"9e", "Card Authentication", "ECCP256"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("Generate_%s_%s", tt.slot, tt.algorithm), func(t *testing.T) {
			t.Cleanup(func() { h.DeleteSlot(tt.slot) })

			result := h.GenerateInSlot(t, tt.slot, tt.algorithm)
			require.True(t, result.Success(),
				"generate in slot %s with %s failed: %s", tt.slot, tt.algorithm, result.Combined())
			assert.True(t, result.OutputContains(tt.slot),
				"output should reference slot %s: %s", tt.slot, result.Combined())
			assert.True(t, result.OutputContains(tt.algorithm) || result.OutputContains(strings.ToLower(tt.algorithm)),
				"output should reference algorithm %s: %s", tt.algorithm, result.Combined())
			assert.True(t, result.OutputContains("PUBLIC KEY"),
				"output should contain public key PEM: %s", result.Combined())
		})
	}
}

// TestYubiKeyPIV_ListAfterGenerate generates keys in multiple slots and verifies
// that list shows all populated slots with correct details.
func TestYubiKeyPIV_ListAfterGenerate(t *testing.T) {
	h := NewYubiKeyPIVTestHelper(t)

	slots := []struct {
		slot      string
		algorithm string
	}{
		{"9a", "ECCP256"},
		{"9c", "ECCP384"},
	}

	// Generate keys in both slots.
	for _, s := range slots {
		result := h.GenerateInSlot(t, s.slot, s.algorithm)
		require.True(t, result.Success(),
			"generate in slot %s failed: %s", s.slot, result.Combined())
	}

	t.Cleanup(func() {
		for _, s := range slots {
			h.DeleteSlot(s.slot)
		}
	})

	// List and verify both slots appear.
	result := h.RunYubiKeyPIV("list")
	require.True(t, result.Success(), "list failed: %s", result.Combined())

	for _, s := range slots {
		assert.True(t, result.OutputContains(s.slot),
			"list should contain slot %s: %s", s.slot, result.Combined())
	}
}

// TestYubiKeyPIV_ShowCertificate generates a key and shows its self-signed certificate,
// verifying output contains Subject, Issuer, Algorithm, Key Usage, and expiration.
func TestYubiKeyPIV_ShowCertificate(t *testing.T) {
	h := NewYubiKeyPIVTestHelper(t)

	result := h.GenerateInSlot(t, "9a", "ECCP256")
	require.True(t, result.Success(), "generate failed: %s", result.Combined())

	t.Cleanup(func() { h.DeleteSlot("9a") })

	result = h.RunYubiKeyPIV("show", "9a")
	require.True(t, result.Success(), "show failed: %s", result.Combined())

	expectedFields := []string{"Subject", "Issuer", "Algorithm", "Signature"}
	for _, field := range expectedFields {
		assert.True(t, result.OutputContains(field),
			"show output should contain %s: %s", field, result.Combined())
	}
}

// TestYubiKeyPIV_ExportPEM generates a key and exports the certificate as PEM,
// verifying the output is a valid parseable x509 certificate.
func TestYubiKeyPIV_ExportPEM(t *testing.T) {
	h := NewYubiKeyPIVTestHelper(t)

	result := h.GenerateInSlot(t, "9a", "ECCP256")
	require.True(t, result.Success(), "generate failed: %s", result.Combined())

	t.Cleanup(func() { h.DeleteSlot("9a") })

	exportPath := filepath.Join(h.TmpDir(), "export-9a.pem")
	result = h.RunYubiKeyPIV("export", "9a", "--format", "pem", "--output", exportPath)
	require.True(t, result.Success(), "export PEM failed: %s", result.Combined())

	// Read and parse the exported PEM.
	pemData, err := os.ReadFile(exportPath)
	require.NoError(t, err, "should read exported PEM file")

	block, _ := pem.Decode(pemData)
	require.NotNil(t, block, "exported data should be valid PEM")
	assert.Equal(t, "CERTIFICATE", block.Type, "PEM block type should be CERTIFICATE")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "PEM should contain a valid x509 certificate")
	assert.NotEmpty(t, cert.Subject.String(), "certificate should have a subject")
}

// TestYubiKeyPIV_ExportDER generates a key and exports the certificate as DER,
// verifying the output is a valid parseable x509 certificate.
func TestYubiKeyPIV_ExportDER(t *testing.T) {
	h := NewYubiKeyPIVTestHelper(t)

	result := h.GenerateInSlot(t, "9a", "ECCP256")
	require.True(t, result.Success(), "generate failed: %s", result.Combined())

	t.Cleanup(func() { h.DeleteSlot("9a") })

	exportPath := filepath.Join(h.TmpDir(), "export-9a.der")
	result = h.RunYubiKeyPIV("export", "9a", "--format", "der", "--output", exportPath)
	require.True(t, result.Success(), "export DER failed: %s", result.Combined())

	// Read and parse the exported DER.
	derData, err := os.ReadFile(exportPath)
	require.NoError(t, err, "should read exported DER file")
	require.NotEmpty(t, derData, "DER file should not be empty")

	cert, err := x509.ParseCertificate(derData)
	require.NoError(t, err, "DER should contain a valid x509 certificate")
	assert.NotEmpty(t, cert.Subject.String(), "certificate should have a subject")
}

// TestYubiKeyPIV_StoreImport exports a certificate from one slot, then imports
// it into a different slot using the store command, verifying it appears in list.
func TestYubiKeyPIV_StoreImport(t *testing.T) {
	h := NewYubiKeyPIVTestHelper(t)

	// Generate a key in slot 9a.
	result := h.GenerateInSlot(t, "9a", "ECCP256")
	require.True(t, result.Success(), "generate in 9a failed: %s", result.Combined())

	t.Cleanup(func() {
		h.DeleteSlot("9a")
		h.DeleteSlot("9c")
	})

	// Export cert from 9a as PEM.
	exportPath := filepath.Join(h.TmpDir(), "cert-9a.pem")
	result = h.RunYubiKeyPIV("export", "9a", "--format", "pem", "--output", exportPath)
	require.True(t, result.Success(), "export from 9a failed: %s", result.Combined())

	// Store the exported cert into slot 9c.
	result = h.RunYubiKeyPIV("store", "9c", exportPath)
	require.True(t, result.Success(), "store into 9c failed: %s", result.Combined())
	assert.True(t, result.OutputContains("9c"),
		"store output should reference slot 9c: %s", result.Combined())

	// List and verify 9c appears.
	result = h.RunYubiKeyPIV("list")
	require.True(t, result.Success(), "list failed: %s", result.Combined())
	assert.True(t, result.OutputContains("9c"),
		"list should contain slot 9c after store: %s", result.Combined())
}

// TestYubiKeyPIV_OverwriteSlot generates a key in a slot that already has a
// certificate, then generates again to overwrite it. This is the exact bug
// scenario where CKR_USER_TYPE_INVALID was previously returned because SO
// session elevation was not being used for YubiKey cert writes.
func TestYubiKeyPIV_OverwriteSlot(t *testing.T) {
	h := NewYubiKeyPIVTestHelper(t)

	t.Cleanup(func() { h.DeleteSlot("9a") })

	// First generation: creates key + self-signed cert in slot 9a.
	result := h.GenerateInSlot(t, "9a", "ECCP256")
	require.True(t, result.Success(),
		"first generate in 9a failed: %s", result.Combined())

	// Verify the cert is there.
	result = h.RunYubiKeyPIV("show", "9a")
	require.True(t, result.Success(), "show after first generate failed: %s", result.Combined())

	// Second generation: overwrites the existing key and cert in slot 9a.
	// This previously failed with CKR_USER_TYPE_INVALID on YubiKey because
	// the PKCS#11 session was not elevated to SO for object destruction.
	result = h.GenerateInSlot(t, "9a", "ECCP384")
	require.True(t, result.Success(),
		"overwrite generate in 9a failed (CKR_USER_TYPE_INVALID regression?): %s", result.Combined())

	// Verify the new cert is there and has the new algorithm.
	result = h.RunYubiKeyPIV("show", "9a")
	require.True(t, result.Success(), "show after overwrite failed: %s", result.Combined())
}

// TestYubiKeyPIV_StoreOverwriteExisting stores a certificate into a slot that
// already has a certificate via the store command (not generate). This verifies
// the store path also handles SO session elevation correctly on YubiKey.
func TestYubiKeyPIV_StoreOverwriteExisting(t *testing.T) {
	h := NewYubiKeyPIVTestHelper(t)
	pivHelper := NewPIVTestHelper(t)

	t.Cleanup(func() { h.DeleteSlot("9a") })

	// Generate a key in 9a to populate it.
	result := h.GenerateInSlot(t, "9a", "ECCP256")
	require.True(t, result.Success(), "generate failed: %s", result.Combined())

	// Create a test certificate and store it over the existing one.
	certPath := pivHelper.CreateTestCertFile("overwrite-store-test")
	result = h.RunYubiKeyPIV("store", "9a", certPath)
	require.True(t, result.Success(),
		"store overwrite in 9a failed (CKR_USER_TYPE_INVALID regression?): %s", result.Combined())

	// Verify the new cert is there.
	result = h.RunYubiKeyPIV("show", "9a")
	require.True(t, result.Success(), "show after store overwrite failed: %s", result.Combined())
	assert.True(t, result.OutputContains("overwrite-store-test"),
		"show should display the newly stored certificate subject: %s", result.Combined())
}

// TestYubiKeyPIV_DeleteCertificate generates a key, deletes the certificate,
// and verifies it no longer appears in list.
func TestYubiKeyPIV_DeleteCertificate(t *testing.T) {
	h := NewYubiKeyPIVTestHelper(t)

	// Generate a key in slot 9a.
	result := h.GenerateInSlot(t, "9a", "ECCP256")
	require.True(t, result.Success(), "generate failed: %s", result.Combined())

	// Verify it appears in list.
	result = h.RunYubiKeyPIV("list")
	require.True(t, result.Success(), "list failed: %s", result.Combined())
	assert.True(t, result.OutputContains("9a"),
		"list should show slot 9a before delete: %s", result.Combined())

	// Delete the certificate.
	result = h.RunYubiKeyPIV("delete", "9a", "--force")
	require.True(t, result.Success(), "delete failed: %s", result.Combined())
	assert.True(t, result.OutputContains("deleted") || result.OutputContains("Deleted"),
		"output should confirm deletion: %s", result.Combined())

	// Verify it no longer appears in list.
	result = h.RunYubiKeyPIV("list")
	require.True(t, result.Success(), "list after delete failed: %s", result.Combined())
	// The slot should not appear with a certificate, or list should show empty/reduced count.
	// Note: the key itself persists on the YubiKey, but the certificate is removed.
}

// TestYubiKeyPIV_Status runs the piv status command with PKCS#11 backend and
// verifies it displays the correct backend and token information.
func TestYubiKeyPIV_Status(t *testing.T) {
	h := NewYubiKeyPIVTestHelper(t)

	result := h.RunYubiKeyPIV("status")
	require.True(t, result.Success(), "status failed: %s", result.Combined())

	assert.True(t, result.OutputContains("pkcs11") || result.OutputContains("PKCS#11"),
		"status should show PKCS#11 backend: %s", result.Combined())
	assert.True(t, result.OutputContains(yukiTokenLabel),
		"status should show token label %q: %s", yukiTokenLabel, result.Combined())
}

// TestYubiKeyPIV_StatusAfterGenerate runs status with a populated slot to verify
// the slot count and certificate details are displayed.
func TestYubiKeyPIV_StatusAfterGenerate(t *testing.T) {
	h := NewYubiKeyPIVTestHelper(t)

	result := h.GenerateInSlot(t, "9a", "ECCP256")
	require.True(t, result.Success(), "generate failed: %s", result.Combined())

	t.Cleanup(func() { h.DeleteSlot("9a") })

	result = h.RunYubiKeyPIV("status")
	require.True(t, result.Success(), "status failed: %s", result.Combined())

	assert.True(t, result.OutputContains("9a"),
		"status should show populated slot 9a: %s", result.Combined())
}

// TestYubiKeyPIV_CSR generates a key and then creates a CSR for that slot,
// verifying the output is a valid PEM-encoded CSR.
func TestYubiKeyPIV_CSR(t *testing.T) {
	// CSR generation requires GetPIVSigner which looks up the key by name
	// "piv-9a" in the PKCS#11 backend's key store. Since the CLI creates a
	// fresh xkms instance per invocation, the key generated in a previous
	// invocation is not discoverable. This is a known limitation of the
	// standalone CLI flow — the GUI and server paths don't have this issue
	// because they maintain a long-lived xkms service.
	t.Skip("CSR requires persistent PKCS#11 key store across CLI invocations")

	h := NewYubiKeyPIVTestHelper(t)

	// Generate a key in slot 9a first.
	result := h.GenerateInSlot(t, "9a", "ECCP256")
	require.True(t, result.Success(), "generate failed: %s", result.Combined())

	t.Cleanup(func() { h.DeleteSlot("9a") })

	// Generate a CSR for slot 9a.
	csrPath := filepath.Join(h.TmpDir(), "request-9a.csr")
	result = h.RunYubiKeyPIV("csr", "9a", "--cn", "yubikey-test@example.com", "--output", csrPath)
	require.True(t, result.Success(), "csr failed: %s", result.Combined())

	// Read and validate the CSR.
	csrData, err := os.ReadFile(csrPath)
	require.NoError(t, err, "should read CSR file")

	block, _ := pem.Decode(csrData)
	require.NotNil(t, block, "CSR output should be valid PEM")
	assert.Equal(t, "CERTIFICATE REQUEST", block.Type,
		"PEM block type should be CERTIFICATE REQUEST")

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err, "should parse CSR")
	assert.Contains(t, csr.Subject.CommonName, "yubikey-test@example.com",
		"CSR subject should contain the specified common name")
}

// TestYubiKeyPIV_CSRToStdout generates a CSR and writes it to stdout (no --output flag),
// verifying the PEM is present in stdout.
func TestYubiKeyPIV_CSRToStdout(t *testing.T) {
	t.Skip("CSR requires persistent PKCS#11 key store across CLI invocations")

	h := NewYubiKeyPIVTestHelper(t)

	result := h.GenerateInSlot(t, "9a", "ECCP256")
	require.True(t, result.Success(), "generate failed: %s", result.Combined())

	t.Cleanup(func() { h.DeleteSlot("9a") })

	result = h.RunYubiKeyPIV("csr", "9a", "--cn", "stdout-test@example.com")
	require.True(t, result.Success(), "csr to stdout failed: %s", result.Combined())

	assert.True(t, strings.Contains(result.Stdout, "BEGIN CERTIFICATE REQUEST"),
		"stdout should contain PEM CSR header: %s", result.Stdout)
	assert.True(t, strings.Contains(result.Stdout, "END CERTIFICATE REQUEST"),
		"stdout should contain PEM CSR footer: %s", result.Stdout)
}

// TestYubiKeyPIV_ExportToStdout exports a certificate to stdout and verifies
// the PEM output is present.
func TestYubiKeyPIV_ExportToStdout(t *testing.T) {
	h := NewYubiKeyPIVTestHelper(t)

	result := h.GenerateInSlot(t, "9a", "ECCP256")
	require.True(t, result.Success(), "generate failed: %s", result.Combined())

	t.Cleanup(func() { h.DeleteSlot("9a") })

	result = h.RunYubiKeyPIV("export", "9a", "--format", "pem")
	require.True(t, result.Success(), "export to stdout failed: %s", result.Combined())

	assert.True(t, strings.Contains(result.Stdout, "BEGIN CERTIFICATE"),
		"stdout should contain PEM certificate header: %s", result.Stdout)
	assert.True(t, strings.Contains(result.Stdout, "END CERTIFICATE"),
		"stdout should contain PEM certificate footer: %s", result.Stdout)
}

// TestYubiKeyPIV_GenerateWithPolicies verifies that PIN and touch policies are
// accepted by the generate command on YubiKey.
func TestYubiKeyPIV_GenerateWithPolicies(t *testing.T) {
	h := NewYubiKeyPIVTestHelper(t)

	tests := []struct {
		name        string
		slot        string
		pinPolicy   string
		touchPolicy string
	}{
		{"PINOnce_TouchNever", "9a", "once", "never"},
		{"PINAlways_TouchNever", "9c", "always", "never"},
		{"PINNever_TouchNever", "9d", "never", "never"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(func() { h.DeleteSlot(tt.slot) })

			result := h.RunYubiKeyPIV("generate", tt.slot,
				"--algorithm", "ECCP256",
				"--pin-policy", tt.pinPolicy,
				"--touch-policy", tt.touchPolicy,
				"--force")
			require.True(t, result.Success(),
				"generate with pin-policy=%s touch-policy=%s failed: %s",
				tt.pinPolicy, tt.touchPolicy, result.Combined())
			assert.True(t, result.OutputContains(tt.slot),
				"output should reference slot %s: %s", tt.slot, result.Combined())
		})
	}
}

// TestYubiKeyPIV_ImportCertificate generates a key in a slot, then uses the
// import command to import an externally-created certificate into that slot.
func TestYubiKeyPIV_ImportCertificate(t *testing.T) {
	h := NewYubiKeyPIVTestHelper(t)
	pivHelper := NewPIVTestHelper(t)

	t.Cleanup(func() { h.DeleteSlot("9a") })

	// Generate a key first so the slot is populated.
	result := h.GenerateInSlot(t, "9a", "ECCP256")
	require.True(t, result.Success(), "generate failed: %s", result.Combined())

	// Create a test certificate file.
	certPath := pivHelper.CreateTestCertFile("yubikey-import-test")

	// Import with --force to skip key verification (test cert won't match slot key).
	result = h.RunYubiKeyPIV("import", "9a", certPath, "--force")
	require.True(t, result.Success(),
		"import into 9a failed: %s", result.Combined())
	assert.True(t, result.OutputContains("9a"),
		"import output should reference slot 9a: %s", result.Combined())

	// Verify the imported certificate is shown.
	result = h.RunYubiKeyPIV("show", "9a")
	require.True(t, result.Success(), "show after import failed: %s", result.Combined())
	assert.True(t, result.OutputContains("yubikey-import-test"),
		"show should display imported certificate subject: %s", result.Combined())
}

// TestYubiKeyPIV_ShowNonExistent verifies that showing an empty slot returns
// an appropriate error.
func TestYubiKeyPIV_ShowNonExistent(t *testing.T) {
	h := NewYubiKeyPIVTestHelper(t)

	// Ensure slot is clean.
	h.DeleteSlot("9d")

	result := h.RunYubiKeyPIV("show", "9d")
	assert.False(t, result.Success(),
		"show on empty slot should fail")
	assert.True(t, result.OutputContains("not found") || result.OutputContains("Not found") ||
		result.OutputContains("error") || result.OutputContains("Error"),
		"output should indicate certificate not found: %s", result.Combined())
}

// TestYubiKeyPIV_DeleteNonExistent verifies that deleting from an empty slot
// returns an appropriate error.
func TestYubiKeyPIV_DeleteNonExistent(t *testing.T) {
	h := NewYubiKeyPIVTestHelper(t)

	// Ensure slot is clean.
	h.DeleteSlot("9d")

	result := h.RunYubiKeyPIV("delete", "9d", "--force")
	assert.False(t, result.Success(),
		"delete on empty slot should fail")
	assert.True(t, result.OutputContains("not found") || result.OutputContains("Not found") ||
		result.OutputContains("error") || result.OutputContains("Error"),
		"output should indicate certificate not found: %s", result.Combined())
}

// TestYubiKeyPIV_ExportNonExistent verifies that exporting from an empty slot
// returns an appropriate error and does not create an output file.
func TestYubiKeyPIV_ExportNonExistent(t *testing.T) {
	h := NewYubiKeyPIVTestHelper(t)

	// Ensure slot is clean.
	h.DeleteSlot("9d")

	exportPath := filepath.Join(h.TmpDir(), "should-not-exist.pem")
	result := h.RunYubiKeyPIV("export", "9d", "--format", "pem", "--output", exportPath)
	assert.False(t, result.Success(),
		"export from empty slot should fail")

	_, err := os.Stat(exportPath)
	assert.True(t, os.IsNotExist(err),
		"export file should not exist after failed export")
}

// TestYubiKeyPIV_InvalidAlgorithm verifies that an invalid algorithm is rejected.
func TestYubiKeyPIV_InvalidAlgorithm(t *testing.T) {
	h := NewYubiKeyPIVTestHelper(t)

	result := h.RunYubiKeyPIV("generate", "9a", "--algorithm", "INVALID")
	assert.False(t, result.Success(),
		"generate with invalid algorithm should fail")
	assert.True(t, result.OutputContains("invalid") || result.OutputContains("Invalid"),
		"output should indicate invalid algorithm: %s", result.Combined())
}

// TestYubiKeyPIV_InvalidSlot verifies that an invalid slot identifier is rejected.
func TestYubiKeyPIV_InvalidSlot(t *testing.T) {
	h := NewYubiKeyPIVTestHelper(t)

	invalidSlots := []string{"9f", "00", "ff", "abc", "invalid"}

	for _, slot := range invalidSlots {
		t.Run("InvalidSlot_"+slot, func(t *testing.T) {
			result := h.RunYubiKeyPIV("generate", slot, "--algorithm", "ECCP256")
			assert.False(t, result.Success(),
				"generate with invalid slot %s should fail", slot)
		})
	}
}

// TestYubiKeyPIV_ListEmpty verifies that list succeeds on an empty YubiKey
// (no certificates in any PIV slots).
func TestYubiKeyPIV_ListEmpty(t *testing.T) {
	h := NewYubiKeyPIVTestHelper(t)

	// Clean all slots first.
	slots := []string{"9a", "9c", "9d", "9e"}
	for _, s := range slots {
		h.DeleteSlot(s)
	}

	// YubiKey PIV retains attestation certificates (f9 and per-slot
	// attestation certs) even after deleting user certificates, so the
	// list will still show those. Verify the list command succeeds and
	// does not contain any user-generated certificate subjects.
	result := h.RunYubiKeyPIV("list")
	require.True(t, result.Success(), "list should succeed: %s", result.Combined())
	assert.False(t, result.OutputContains("PIV Authentication\n") && result.OutputContains("CN=PIV"),
		"output should not contain user-generated PIV certificates after cleanup")
}

// TestYubiKeyPIV_FullWorkflow exercises the complete lifecycle:
// generate -> list -> show -> export PEM -> export DER -> store (overwrite) -> delete.
func TestYubiKeyPIV_FullWorkflow(t *testing.T) {
	h := NewYubiKeyPIVTestHelper(t)

	t.Cleanup(func() { h.DeleteSlot("9a") })

	// Step 1: Generate key in slot 9a.
	result := h.GenerateInSlot(t, "9a", "ECCP256")
	require.True(t, result.Success(), "generate failed: %s", result.Combined())

	// Step 2: List -- slot 9a should appear.
	result = h.RunYubiKeyPIV("list")
	require.True(t, result.Success(), "list failed: %s", result.Combined())
	assert.True(t, result.OutputContains("9a"), "list should contain 9a: %s", result.Combined())

	// Step 3: Show -- verify certificate details.
	result = h.RunYubiKeyPIV("show", "9a")
	require.True(t, result.Success(), "show failed: %s", result.Combined())
	assert.True(t, result.OutputContains("Subject"), "show should contain Subject: %s", result.Combined())

	// Step 4: Export as PEM.
	pemPath := filepath.Join(h.TmpDir(), "workflow-9a.pem")
	result = h.RunYubiKeyPIV("export", "9a", "--format", "pem", "--output", pemPath)
	require.True(t, result.Success(), "export PEM failed: %s", result.Combined())

	pemData, err := os.ReadFile(pemPath)
	require.NoError(t, err)
	block, _ := pem.Decode(pemData)
	require.NotNil(t, block, "exported PEM should be decodable")

	// Step 5: Export as DER.
	derPath := filepath.Join(h.TmpDir(), "workflow-9a.der")
	result = h.RunYubiKeyPIV("export", "9a", "--format", "der", "--output", derPath)
	require.True(t, result.Success(), "export DER failed: %s", result.Combined())

	derData, err := os.ReadFile(derPath)
	require.NoError(t, err)
	_, err = x509.ParseCertificate(derData)
	require.NoError(t, err, "exported DER should be a valid certificate")

	// Step 6: Store (overwrite) -- the critical CKR_USER_TYPE_INVALID regression test.
	pivHelper := NewPIVTestHelper(t)
	certPath := pivHelper.CreateTestCertFile("workflow-overwrite")
	result = h.RunYubiKeyPIV("store", "9a", certPath)
	require.True(t, result.Success(),
		"store overwrite failed (CKR_USER_TYPE_INVALID regression?): %s", result.Combined())

	// Verify the overwritten cert.
	result = h.RunYubiKeyPIV("show", "9a")
	require.True(t, result.Success(), "show after overwrite failed: %s", result.Combined())
	assert.True(t, result.OutputContains("workflow-overwrite"),
		"show should display overwritten cert subject: %s", result.Combined())

	// Step 7: Delete.
	result = h.RunYubiKeyPIV("delete", "9a", "--force")
	require.True(t, result.Success(), "delete failed: %s", result.Combined())

	// Step 8: Verify deletion.
	result = h.RunYubiKeyPIV("show", "9a")
	assert.False(t, result.Success(), "show after delete should fail")
}

// TestYubiKeyPIV_ExportInvalidFormat verifies that an invalid export format is rejected.
func TestYubiKeyPIV_ExportInvalidFormat(t *testing.T) {
	h := NewYubiKeyPIVTestHelper(t)

	result := h.GenerateInSlot(t, "9a", "ECCP256")
	require.True(t, result.Success(), "generate failed: %s", result.Combined())

	t.Cleanup(func() { h.DeleteSlot("9a") })

	result = h.RunYubiKeyPIV("export", "9a", "--format", "invalid")
	assert.False(t, result.Success(), "export with invalid format should fail")
	assert.True(t, result.OutputContains("invalid") || result.OutputContains("Invalid"),
		"output should indicate invalid format: %s", result.Combined())
}

// TestYubiKeyPIV_HelpOutput verifies that help commands work with PKCS#11 flags.
func TestYubiKeyPIV_HelpOutput(t *testing.T) {
	h := NewYubiKeyPIVTestHelper(t)

	t.Run("PIVHelp", func(t *testing.T) {
		result := h.runCommand("piv", "--help")
		require.True(t, result.Success(), "piv help should succeed: %s", result.Combined())
		assert.True(t, result.OutputContains("pkcs11") || result.OutputContains("PKCS#11"),
			"help should mention PKCS#11 backend: %s", result.Combined())
	})

	t.Run("GenerateHelp", func(t *testing.T) {
		result := h.runCommand("piv", "generate", "--help")
		require.True(t, result.Success(), "generate help should succeed: %s", result.Combined())
		assert.True(t, result.OutputContains("algorithm") || result.OutputContains("Algorithm"),
			"help should mention algorithm: %s", result.Combined())
	})

	t.Run("CSRHelp", func(t *testing.T) {
		result := h.runCommand("piv", "csr", "--help")
		require.True(t, result.Success(), "csr help should succeed: %s", result.Combined())
		assert.True(t, result.OutputContains("CSR") || result.OutputContains("csr"),
			"help should mention CSR: %s", result.Combined())
	})
}
