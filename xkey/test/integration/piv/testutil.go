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

//go:build integration

package piv

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// binaryPath holds the path to the built xkey binary.
// It is built once per test run using sync.Once.
var (
	binaryPath     string
	binaryBuildErr error
	binaryOnce     sync.Once
)

// getBinary builds the xkey binary once and returns its path.
// This ensures we only compile once per test run for efficiency.
func getBinary(t *testing.T) string {
	t.Helper()

	binaryOnce.Do(func() {
		binaryPath, binaryBuildErr = buildXkeyBinary()
	})

	if binaryBuildErr != nil {
		t.Fatalf("Failed to build xkey binary: %v", binaryBuildErr)
	}

	return binaryPath
}

// buildXkeyBinary compiles the xkey binary and returns its path.
func buildXkeyBinary() (string, error) {
	// Create a persistent temp directory for the binary
	tmpDir, err := os.MkdirTemp("", "xkey-piv-integration-*")
	if err != nil {
		return "", err
	}

	binaryPath := filepath.Join(tmpDir, "xkey")

	// Find project root by looking for go.mod
	projectRoot, err := findProjectRoot()
	if err != nil {
		return "", err
	}

	// Use full path to go since tests may run with sudo where PATH is reset
	goBinary := "go"
	if _, err := exec.LookPath("go"); err != nil {
		// Try common installation paths
		for _, path := range []string{"/usr/local/go/bin/go", "/usr/bin/go"} {
			if _, err := os.Stat(path); err == nil {
				goBinary = path
				break
			}
		}
	}
	cmd := exec.Command(goBinary, "build", "-o", binaryPath, "./cmd/xkey")
	cmd.Dir = projectRoot

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", &BuildError{Output: string(output), Err: err}
	}

	return binaryPath, nil
}

// BuildError represents a binary build failure.
type BuildError struct {
	Output string
	Err    error
}

func (e *BuildError) Error() string {
	return "build failed: " + e.Err.Error() + "\nOutput: " + e.Output
}

func (e *BuildError) Unwrap() error {
	return e.Err
}

// findProjectRoot locates the project root by searching for go.mod.
func findProjectRoot() (string, error) {
	// Start from current directory and walk up
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		goModPath := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	// Fallback: try relative paths from typical test locations
	candidates := []string{
		"../../../..",
		"../../..",
		"../..",
		"..",
	}

	for _, candidate := range candidates {
		absPath, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		goModPath := filepath.Join(absPath, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			return absPath, nil
		}
	}

	return "", os.ErrNotExist
}

// CommandResult holds the result of a CLI command execution.
type CommandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

// Success returns true if the command succeeded (exit code 0).
func (r *CommandResult) Success() bool {
	return r.ExitCode == 0 && r.Err == nil
}

// Combined returns stdout and stderr combined.
func (r *CommandResult) Combined() string {
	if r.Stderr == "" {
		return r.Stdout
	}
	if r.Stdout == "" {
		return r.Stderr
	}
	return r.Stdout + "\n" + r.Stderr
}

// PIVTestHelper provides helper methods for PIV CLI integration tests.
type PIVTestHelper struct {
	t           *testing.T
	binaryPath  string
	storagePath string
}

// NewPIVTestHelper creates a new test helper with a temp storage directory.
func NewPIVTestHelper(t *testing.T) *PIVTestHelper {
	t.Helper()

	storagePath, err := os.MkdirTemp("", "piv-cli-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp storage directory: %v", err)
	}

	t.Cleanup(func() {
		os.RemoveAll(storagePath)
	})

	return &PIVTestHelper{
		t:           t,
		binaryPath:  getBinary(t),
		storagePath: storagePath,
	}
}

// StoragePath returns the temporary storage path for this test.
func (h *PIVTestHelper) StoragePath() string {
	return h.storagePath
}

// RunPIV executes an xkey piv command with the test storage path.
func (h *PIVTestHelper) RunPIV(args ...string) *CommandResult {
	h.t.Helper()

	// Prepend piv command and storage-path flag
	fullArgs := []string{"piv", "--storage-path", h.storagePath}
	fullArgs = append(fullArgs, args...)

	return h.RunCommand(fullArgs...)
}

// RunCommand executes the xkey binary with the given arguments.
func (h *PIVTestHelper) RunCommand(args ...string) *CommandResult {
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

// GenerateTestCertificate creates a self-signed test certificate.
func (h *PIVTestHelper) GenerateTestCertificate(commonName string) *x509.Certificate {
	h.t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		h.t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
	if err != nil {
		h.t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"PIV Integration Test"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		h.t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		h.t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// WriteCertificatePEM writes a certificate to a file in PEM format.
func (h *PIVTestHelper) WriteCertificatePEM(cert *x509.Certificate, path string) {
	h.t.Helper()

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	if err := os.WriteFile(path, pemData, 0600); err != nil {
		h.t.Fatalf("Failed to write certificate file: %v", err)
	}
}

// WriteCertificateDER writes a certificate to a file in DER format.
func (h *PIVTestHelper) WriteCertificateDER(cert *x509.Certificate, path string) {
	h.t.Helper()

	if err := os.WriteFile(path, cert.Raw, 0600); err != nil {
		h.t.Fatalf("Failed to write certificate file: %v", err)
	}
}

// CreateTestCertFile generates a test certificate and writes it to a temp file.
// Returns the path to the certificate file.
func (h *PIVTestHelper) CreateTestCertFile(commonName string) string {
	h.t.Helper()

	cert := h.GenerateTestCertificate(commonName)

	tmpFile, err := os.CreateTemp("", "piv-test-cert-*.pem")
	if err != nil {
		h.t.Fatalf("Failed to create temp cert file: %v", err)
	}
	tmpFile.Close()

	h.t.Cleanup(func() {
		os.Remove(tmpFile.Name())
	})

	h.WriteCertificatePEM(cert, tmpFile.Name())

	return tmpFile.Name()
}

// OutputContains checks if the command output contains a substring.
func (r *CommandResult) OutputContains(substr string) bool {
	return strings.Contains(r.Stdout, substr) || strings.Contains(r.Stderr, substr)
}

// OutputContainsAll checks if the command output contains all substrings.
func (r *CommandResult) OutputContainsAll(substrs ...string) bool {
	combined := r.Combined()
	for _, substr := range substrs {
		if !strings.Contains(combined, substr) {
			return false
		}
	}
	return true
}
