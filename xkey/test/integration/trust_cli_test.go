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

//go:build integration && linux

// Package xkey provides integration tests for the local trust-store verbs
// of the "xkey trust" command group (add, list, show, classify, remove),
// exercised against the compiled CLI binary with an isolated HOME so the
// host user's real trust store is never touched. The bootstrap, fetch,
// install, and uninstall verbs are intentionally excluded here: they
// require a live server or mutate the OS trust store.
package xkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
)

// isolateTrustHome creates a temporary directory and points HOME at it.
// "xkey trust" commands resolve the store path via $HOME/.xkey/data/trust
// (see openTrustStore in cmd/xkey/cmd/trust.go) rather than XKEY_HOME, so
// isolating HOME is required to keep these tests hermetic.
func isolateTrustHome(t *testing.T) string {
	t.Helper()

	dir := SetupCleanEnvironment(t)
	t.Setenv("HOME", dir)
	return dir
}

// generateSelfSignedTrustCert creates a self-signed ECDSA P-256 CA
// certificate for trust-store tests and returns both the parsed
// certificate and its PEM encoding.
func generateSelfSignedTrustCert(t *testing.T, commonName string) (*x509.Certificate, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("Failed to parse generated certificate: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, pemBytes
}

// writeCertFile writes PEM-encoded certificate bytes to a new file inside
// dir and returns the file path.
func writeCertFile(t *testing.T, dir, name string, pemBytes []byte) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatalf("Failed to write cert file %s: %v", path, err)
	}
	return path
}

// fieldValue returns the trimmed value following the first line in output
// whose trimmed text starts with label (e.g. "Purpose:"). It fails the test
// if the label is not found, avoiding brittle assumptions about exact
// column alignment in the CLI's tabular/labelled output.
func fieldValue(t *testing.T, output, label string) string {
	t.Helper()

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, label) {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, label))
		}
	}
	t.Fatalf("Field %q not found in output:\n%s", label, output)
	return ""
}

// ---------------------------------------------------------------------------
// Full lifecycle: add -> list -> show -> classify -> remove
// ---------------------------------------------------------------------------

// TestTrustCLI_Lifecycle_AddListShowClassifyRemove exercises the full
// happy path across all five local trust-store verbs against a single
// self-signed certificate.
func TestTrustCLI_Lifecycle_AddListShowClassifyRemove(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := isolateTrustHome(t)

	cert, pemBytes := generateSelfSignedTrustCert(t, "xKey Integration Test CA")
	fingerprint := truststore.Fingerprint(cert)
	pemPath := writeCertFile(t, home, "test-ca.pem", pemBytes)

	// add
	addOut := RunXKeyExpectSuccess(t, binary, "", "trust", "add", pemPath, "--purpose", "general")
	if !strings.Contains(addOut, "Certificates added: 1") {
		t.Fatalf("Expected 'Certificates added: 1', got: %s", addOut)
	}

	// list shows it
	listOut := RunXKeyExpectSuccess(t, binary, "", "trust", "list")
	if !strings.Contains(listOut, "xKey Integration Test CA") {
		t.Errorf("Expected list output to contain the certificate's CN, got: %s", listOut)
	}
	if !strings.Contains(listOut, fingerprint[:16]+"...") {
		t.Errorf("Expected list output to contain the truncated fingerprint, got: %s", listOut)
	}

	// show by full fingerprint
	showOut := RunXKeyExpectSuccess(t, binary, "", "trust", "show", fingerprint)
	if !strings.Contains(showOut, "xKey Integration Test CA") {
		t.Errorf("Expected show output to contain the certificate's CN, got: %s", showOut)
	}
	if !strings.Contains(showOut, fingerprint) {
		t.Errorf("Expected show output to contain the full fingerprint, got: %s", showOut)
	}
	if purpose := fieldValue(t, showOut, "Purpose:"); purpose != "general" {
		t.Errorf("Expected purpose 'general', got: %q", purpose)
	}

	// classify to another purpose
	classifyOut := RunXKeyExpectSuccess(t, binary, "", "trust", "classify", fingerprint, "--purpose", "user-ca")
	if !strings.Contains(classifyOut, fingerprint+" classified as user-ca") {
		t.Errorf("Expected classify output to confirm new purpose, got: %s", classifyOut)
	}

	showAfterOut := RunXKeyExpectSuccess(t, binary, "", "trust", "show", fingerprint)
	if purpose := fieldValue(t, showAfterOut, "Purpose:"); purpose != "user-ca" {
		t.Errorf("Expected updated purpose 'user-ca', got: %q", purpose)
	}

	// remove
	removeOut := RunXKeyExpectSuccess(t, binary, "", "trust", "remove", fingerprint)
	if !strings.Contains(removeOut, "Certificate removed: "+fingerprint) {
		t.Errorf("Expected remove confirmation, got: %s", removeOut)
	}

	// list no longer shows it
	listAfterOut := RunXKeyExpectSuccess(t, binary, "", "trust", "list")
	if strings.Contains(listAfterOut, fingerprint[:16]) {
		t.Errorf("Expected removed certificate to be absent from list, got: %s", listAfterOut)
	}
	if !strings.Contains(listAfterOut, "No trusted certificates found.") {
		t.Errorf("Expected empty trust store message, got: %s", listAfterOut)
	}
}

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

// TestTrustCLI_Add_NonexistentFile_Fails verifies that "trust add" fails
// when the given PEM file does not exist.
func TestTrustCLI_Add_NonexistentFile_Fails(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := isolateTrustHome(t)

	missing := filepath.Join(home, "does-not-exist.pem")
	errOutput := RunXKeyExpectFailure(t, binary, "", "trust", "add", missing)

	if !strings.Contains(errOutput, "failed to read PEM file") {
		t.Errorf("Expected 'failed to read PEM file' in error output, got: %s", errOutput)
	}
}

// TestTrustCLI_Show_UnknownFingerprint_Fails verifies that "trust show"
// fails for a well-formed but unknown fingerprint.
func TestTrustCLI_Show_UnknownFingerprint_Fails(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolateTrustHome(t)

	unknown := strings.Repeat("ab", 32) // 64 lowercase hex chars, valid format, absent
	errOutput := RunXKeyExpectFailure(t, binary, "", "trust", "show", unknown)

	if !strings.Contains(errOutput, "certificate not found") {
		t.Errorf("Expected 'certificate not found' in error output, got: %s", errOutput)
	}
}

// TestTrustCLI_Classify_UnknownFingerprint_Fails verifies that "trust
// classify" fails for a well-formed but unknown fingerprint.
func TestTrustCLI_Classify_UnknownFingerprint_Fails(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolateTrustHome(t)

	unknown := strings.Repeat("cd", 32)
	errOutput := RunXKeyExpectFailure(t, binary, "", "trust", "classify", unknown, "--purpose", "general")

	if !strings.Contains(errOutput, "classify failed") {
		t.Errorf("Expected 'classify failed' in error output, got: %s", errOutput)
	}
}

// TestTrustCLI_Remove_UnknownFingerprint_Fails verifies that "trust remove"
// fails for a well-formed but unknown fingerprint.
func TestTrustCLI_Remove_UnknownFingerprint_Fails(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolateTrustHome(t)

	unknown := strings.Repeat("ef", 32)
	errOutput := RunXKeyExpectFailure(t, binary, "", "trust", "remove", unknown)

	if !strings.Contains(errOutput, "certificate not found") {
		t.Errorf("Expected 'certificate not found' in error output, got: %s", errOutput)
	}
}

// TestTrustCLI_List_StoreOpenFailure_Fails verifies that "trust list" fails
// when the default trust store path is blocked by a non-directory file.
func TestTrustCLI_List_StoreOpenFailure_Fails(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := isolateTrustHome(t)

	blockedParent := filepath.Join(home, ".xkey", "data")
	if err := os.MkdirAll(blockedParent, 0700); err != nil {
		t.Fatalf("Failed to create parent dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(blockedParent, "trust"), []byte("not a directory"), 0600); err != nil {
		t.Fatalf("Failed to write blocking file: %v", err)
	}

	errOutput := RunXKeyExpectFailure(t, binary, "", "trust", "list")
	if !strings.Contains(errOutput, "failed to open trust store") {
		t.Errorf("Expected 'failed to open trust store' in error output, got: %s", errOutput)
	}
}
