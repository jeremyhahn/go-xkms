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
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/client"
)

// ============================================================================
// Additional coverage tests for remote functions
// ============================================================================

// Test listBackendsRemote with client create error
func TestListBackendsRemote_ClientCreateError(t *testing.T) {
	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactoryWithError(errors.New("client creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		listBackendsRemote(cfg, printer)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test listBackendsRemote with connect error
func TestListBackendsRemote_ConnectError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.shouldConnect = false
	mockClient.connectErr = errors.New("connection refused")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		listBackendsRemote(cfg, printer)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test backendInfoRemote with client create error
func TestBackendInfoRemote_ClientCreateError(t *testing.T) {
	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactoryWithError(errors.New("client creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		backendInfoRemote(cfg, printer, "software")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test backendInfoRemote with connect error
func TestBackendInfoRemote_ConnectError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.shouldConnect = false
	mockClient.connectErr = errors.New("connection refused")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		backendInfoRemote(cfg, printer, "software")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test generateKeyRemote with symmetric key type
func TestGenerateKeyRemote_SymmetricKey(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.generateKeyResp = &client.GenerateKeyResponse{
		KeyID:   "aes-key",
		KeyType: "symmetric",
		Message: "Key generated successfully",
	}

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	generateKeyRemote(cfg, printer, "aes-key", "symmetric", "", "", 256, "", false)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from generateKeyRemote")
	}
}

// Test generateKeyRemote with AES key type
func TestGenerateKeyRemote_AESKey(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.generateKeyResp = &client.GenerateKeyResponse{
		KeyID:   "aes-key",
		KeyType: "aes",
		Message: "Key generated successfully",
	}

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	generateKeyRemote(cfg, printer, "aes-key", "aes", "", "", 256, "", false)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from generateKeyRemote")
	}
}

// Test listKeysRemote with client create error
func TestListKeysRemote_ClientCreateError(t *testing.T) {
	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactoryWithError(errors.New("client creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		listKeysRemote(cfg, printer)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test listKeysRemote with connect error
func TestListKeysRemote_ConnectError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.shouldConnect = false
	mockClient.connectErr = errors.New("connection refused")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		listKeysRemote(cfg, printer)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test getKeyRemote with client create error
func TestGetKeyRemote_ClientCreateError(t *testing.T) {
	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactoryWithError(errors.New("client creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		getKeyRemote(cfg, printer, "test-key")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test getKeyRemote with connect error
func TestGetKeyRemote_ConnectError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.shouldConnect = false
	mockClient.connectErr = errors.New("connection refused")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		getKeyRemote(cfg, printer, "test-key")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test deleteKeyRemote with client create error
func TestDeleteKeyRemote_ClientCreateError(t *testing.T) {
	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactoryWithError(errors.New("client creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		deleteKeyRemote(cfg, printer, "test-key")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test deleteKeyRemote with connect error
func TestDeleteKeyRemote_ConnectError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.shouldConnect = false
	mockClient.connectErr = errors.New("connection refused")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		deleteKeyRemote(cfg, printer, "test-key")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test signRemote with client create error
func TestSignRemote_ClientCreateError(t *testing.T) {
	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactoryWithError(errors.New("client creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		signRemote(cfg, printer, "test-key", "data", "SHA256")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test signRemote with connect error
func TestSignRemote_ConnectError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.shouldConnect = false
	mockClient.connectErr = errors.New("connection refused")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		signRemote(cfg, printer, "test-key", "data", "SHA256")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test rotateKeyRemote with client create error
func TestRotateKeyRemote_ClientCreateError(t *testing.T) {
	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactoryWithError(errors.New("client creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		rotateKeyRemote(cfg, printer, "test-key")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test rotateKeyRemote with connect error
func TestRotateKeyRemote_ConnectError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.shouldConnect = false
	mockClient.connectErr = errors.New("connection refused")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		rotateKeyRemote(cfg, printer, "test-key")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test encryptRemote with client create error
func TestEncryptRemote_ClientCreateError(t *testing.T) {
	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactoryWithError(errors.New("client creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		encryptRemote(cfg, printer, "aes-key", "data", "")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test encryptRemote with connect error
func TestEncryptRemote_ConnectError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.shouldConnect = false
	mockClient.connectErr = errors.New("connection refused")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		encryptRemote(cfg, printer, "aes-key", "data", "")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test decryptRemote with client create error
func TestDecryptRemote_ClientCreateError(t *testing.T) {
	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactoryWithError(errors.New("client creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	ciphertext := base64.StdEncoding.EncodeToString([]byte("encrypted-data"))
	exitCode := captureExit(t, func() {
		decryptRemote(cfg, printer, "aes-key", ciphertext, "", "", "")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test decryptRemote with connect error
func TestDecryptRemote_ConnectError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.shouldConnect = false
	mockClient.connectErr = errors.New("connection refused")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	ciphertext := base64.StdEncoding.EncodeToString([]byte("encrypted-data"))
	exitCode := captureExit(t, func() {
		decryptRemote(cfg, printer, "aes-key", ciphertext, "", "", "")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test decryptRemote with AAD
func TestDecryptRemote_WithAAD(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	ciphertext := base64.StdEncoding.EncodeToString([]byte("encrypted-data"))
	nonce := base64.StdEncoding.EncodeToString([]byte("nonce"))
	tag := base64.StdEncoding.EncodeToString([]byte("tag"))

	decryptRemote(cfg, printer, "aes-key", ciphertext, "additional-data", nonce, tag)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from decryptRemote")
	}
}

// Test verifyRemote with client create error
func TestVerifyRemote_ClientCreateError(t *testing.T) {
	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactoryWithError(errors.New("client creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	sigBase64 := base64.StdEncoding.EncodeToString([]byte("signature"))
	exitCode := captureExit(t, func() {
		verifyRemote(cfg, printer, "test-key", "data", sigBase64, "SHA256")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test verifyRemote with connect error
func TestVerifyRemote_ConnectError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.shouldConnect = false
	mockClient.connectErr = errors.New("connection refused")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	sigBase64 := base64.StdEncoding.EncodeToString([]byte("signature"))
	exitCode := captureExit(t, func() {
		verifyRemote(cfg, printer, "test-key", "data", sigBase64, "SHA256")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test encryptAsymRemote with client create error
func TestEncryptAsymRemote_ClientCreateError(t *testing.T) {
	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactoryWithError(errors.New("client creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		encryptAsymRemote(cfg, printer, "rsa-key", "secret", "SHA256")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test encryptAsymRemote with connect error
func TestEncryptAsymRemote_ConnectError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.shouldConnect = false
	mockClient.connectErr = errors.New("connection refused")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		encryptAsymRemote(cfg, printer, "rsa-key", "secret", "SHA256")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// ============================================================================
// Certificate remote function coverage tests
// ============================================================================

// Test saveCertRemote with client create error
func TestSaveCertRemote_ClientCreateError(t *testing.T) {
	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactoryWithError(errors.New("client creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		saveCertRemote(cfg, printer, "test-key", validTestCertPEM)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test saveCertRemote with connect error
func TestSaveCertRemote_ConnectError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.shouldConnect = false
	mockClient.connectErr = errors.New("connection refused")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		saveCertRemote(cfg, printer, "test-key", validTestCertPEM)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test getCertRemote with client create error
func TestGetCertRemote_ClientCreateError(t *testing.T) {
	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactoryWithError(errors.New("client creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		getCertRemote(cfg, printer, "test-key")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test getCertRemote with connect error
func TestGetCertRemote_ConnectError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.shouldConnect = false
	mockClient.connectErr = errors.New("connection refused")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		getCertRemote(cfg, printer, "test-key")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test getCertRemote with invalid PEM
func TestGetCertRemote_InvalidPEM(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.getCertResp = &client.GetCertificateResponse{
		KeyID:          "test-key",
		CertificatePEM: "not-a-valid-pem",
	}

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		getCertRemote(cfg, printer, "test-key")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test getCertRemote with malformed certificate
func TestGetCertRemote_MalformedCert(t *testing.T) {
	mockClient := NewMockClient()
	// Valid PEM structure but invalid certificate content
	mockClient.getCertResp = &client.GetCertificateResponse{
		KeyID:          "test-key",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\naW52YWxpZC1jZXJ0aWZpY2F0ZS1kYXRh\n-----END CERTIFICATE-----",
	}

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		getCertRemote(cfg, printer, "test-key")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test deleteCertRemote with client create error
func TestDeleteCertRemote_ClientCreateError(t *testing.T) {
	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactoryWithError(errors.New("client creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		deleteCertRemote(cfg, printer, "test-key")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test deleteCertRemote with connect error
func TestDeleteCertRemote_ConnectError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.shouldConnect = false
	mockClient.connectErr = errors.New("connection refused")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		deleteCertRemote(cfg, printer, "test-key")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test listCertsRemote with client create error
func TestListCertsRemote_ClientCreateError(t *testing.T) {
	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactoryWithError(errors.New("client creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		listCertsRemote(cfg, printer)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test listCertsRemote with connect error
func TestListCertsRemote_ConnectError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.shouldConnect = false
	mockClient.connectErr = errors.New("connection refused")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		listCertsRemote(cfg, printer)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test certExistsRemote with client create error
func TestCertExistsRemote_ClientCreateError(t *testing.T) {
	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactoryWithError(errors.New("client creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		certExistsRemote(cfg, printer, "test-key")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test certExistsRemote with connect error
func TestCertExistsRemote_ConnectError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.shouldConnect = false
	mockClient.connectErr = errors.New("connection refused")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		certExistsRemote(cfg, printer, "test-key")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test saveChainRemote with client create error
func TestSaveChainRemote_ClientCreateError(t *testing.T) {
	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactoryWithError(errors.New("client creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		saveChainRemote(cfg, printer, "test-key", []string{validTestCertPEM})
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test saveChainRemote with connect error
func TestSaveChainRemote_ConnectError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.shouldConnect = false
	mockClient.connectErr = errors.New("connection refused")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		saveChainRemote(cfg, printer, "test-key", []string{validTestCertPEM})
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test getChainRemote with client create error
func TestGetChainRemote_ClientCreateError(t *testing.T) {
	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactoryWithError(errors.New("client creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		getChainRemote(cfg, printer, "test-key")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test getChainRemote with connect error
func TestGetChainRemote_ConnectError(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.shouldConnect = false
	mockClient.connectErr = errors.New("connection refused")

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		getChainRemote(cfg, printer, "test-key")
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// ============================================================================
// Additional edge case tests for export/import functions
// ============================================================================

// Test exportKeyRemote with write file error
func TestExportKeyRemote_WriteFileError(t *testing.T) {
	mockClient := NewMockClient()

	// Use invalid path that cannot be written to
	outputFile := "/nonexistent-directory/exported-key.json"

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		exportKeyRemote(cfg, printer, "test-key", outputFile, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test getImportParamsRemote with write file error
func TestGetImportParamsRemote_WriteFileError(t *testing.T) {
	mockClient := NewMockClient()

	// Use invalid path that cannot be written to
	outputFile := "/nonexistent-directory/import-params.json"

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		getImportParamsRemote(cfg, printer, "test-key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, outputFile)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test wrapKeyRemote with write file error
func TestWrapKeyRemote_WriteFileError(t *testing.T) {
	mockClient := NewMockClient()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	params := &backend.ImportParameters{
		WrappingPublicKey: &rsaKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	// Use invalid path that cannot be written to
	outputFile := "/nonexistent-directory/wrapped-key.json"

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		wrapKeyRemote(cfg, printer, []byte("key-material"), params, outputFile)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// Test unwrapKeyRemote with write file error
func TestUnwrapKeyRemote_WriteFileError(t *testing.T) {
	mockClient := NewMockClient()

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key-material"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	params := &backend.ImportParameters{
		WrappingPublicKey: &rsaKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	// Use invalid path that cannot be written to
	outputFile := "/nonexistent-directory/unwrapped-key.bin"

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	exitCode := captureExit(t, func() {
		unwrapKeyRemote(cfg, printer, wrapped, params, outputFile)
	})

	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

// ============================================================================
// JSON output format tests
// ============================================================================

// Test listKeysRemote with JSON output
func TestListKeysRemote_JSONOutput(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "json",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	listKeysRemote(cfg, printer)

	output := buf.String()
	if output == "" {
		t.Error("Expected JSON output from listKeysRemote")
	}
}

// Test getKeyRemote with JSON output
func TestGetKeyRemote_JSONOutput(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "json",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	getKeyRemote(cfg, printer, "test-key")

	output := buf.String()
	if output == "" {
		t.Error("Expected JSON output from getKeyRemote")
	}
}

// Test listBackendsRemote with JSON output
func TestListBackendsRemote_JSONOutput(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "json",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	listBackendsRemote(cfg, printer)

	output := buf.String()
	if output == "" {
		t.Error("Expected JSON output from listBackendsRemote")
	}
}

// Test backendInfoRemote with JSON output
func TestBackendInfoRemote_JSONOutput(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "json",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	backendInfoRemote(cfg, printer, "software")

	output := buf.String()
	if output == "" {
		t.Error("Expected JSON output from backendInfoRemote")
	}
}

// Test signRemote with JSON output
func TestSignRemote_JSONOutput(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "json",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	signRemote(cfg, printer, "test-key", "data to sign", "SHA256")

	output := buf.String()
	if output == "" {
		t.Error("Expected JSON output from signRemote")
	}
}

// Test getCertRemote with JSON output
func TestGetCertRemote_JSONOutput(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "json",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	getCertRemote(cfg, printer, "test-key")

	output := buf.String()
	if output == "" {
		t.Error("Expected JSON output from getCertRemote")
	}
}

// Test listCertsRemote with JSON output
func TestListCertsRemote_JSONOutput(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "json",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	listCertsRemote(cfg, printer)

	output := buf.String()
	if output == "" {
		t.Error("Expected JSON output from listCertsRemote")
	}
}

// ============================================================================
// Additional backendInfo capability parsing tests
// ============================================================================

// Test backendInfoRemote with full capabilities
func TestBackendInfoRemote_WithAllCapabilities(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.getBackendResp = &client.BackendInfo{
		ID:             "software",
		Type:           "software",
		HardwareBacked: false,
		Capabilities: map[string]interface{}{
			"keys":                 true,
			"signing":              true,
			"decryption":           true,
			"key_rotation":         true,
			"symmetric_encryption": true,
			"import":               true,
			"export":               true,
		},
	}

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	backendInfoRemote(cfg, printer, "software")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from backendInfoRemote")
	}
}

// Test backendInfoRemote with partial capabilities
func TestBackendInfoRemote_WithPartialCapabilities(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.getBackendResp = &client.BackendInfo{
		ID:             "tpm2",
		Type:           "tpm2",
		HardwareBacked: true,
		Capabilities: map[string]interface{}{
			"keys":    true,
			"signing": true,
			// missing other capabilities
		},
	}

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "tpm2",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	backendInfoRemote(cfg, printer, "tpm2")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from backendInfoRemote")
	}
}

// Test backendInfoRemote with empty capabilities
func TestBackendInfoRemote_WithEmptyCapabilities(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.getBackendResp = &client.BackendInfo{
		ID:             "custom",
		Type:           "custom",
		HardwareBacked: false,
		Capabilities:   map[string]interface{}{},
	}

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	backendInfoRemote(cfg, printer, "custom")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from backendInfoRemote")
	}
}

// ============================================================================
// Test getImportParams without output file
// ============================================================================

// Test getImportParamsRemote with empty output file
func TestGetImportParamsRemote_NoOutputFile(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	getImportParamsRemote(cfg, printer, "test-key", "tls", "rsa", 2048, "", backend.WrappingAlgorithmRSAES_OAEP_SHA_256, "")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from getImportParamsRemote")
	}
}

// ============================================================================
// Test copyKey with curve parameter
// ============================================================================

// Test copyKeyRemote with ECDSA curve
func TestCopyKeyRemote_WithCurve(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	copyKeyRemote(cfg, printer, "source-key", "dest-key", "tpm2", "signing", "ecdsa", 0, "P-256", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from copyKeyRemote")
	}
}

// ============================================================================
// Test verifyRemote with valid signature
// ============================================================================

// Test verifyRemote with valid verify response
func TestVerifyRemote_SuccessMessage(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.verifyResp = &client.VerifyResponse{
		Valid:   true,
		Message: "Signature is valid",
	}

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	sigBase64 := base64.StdEncoding.EncodeToString([]byte("valid-signature"))
	verifyRemote(cfg, printer, "test-key", "original data", sigBase64, "SHA256")

	output := buf.String()
	if output == "" {
		t.Error("Expected output from verifyRemote")
	}
}

// ============================================================================
// Test encryptAsym with JSON output
// ============================================================================

// Test encryptAsymRemote with JSON output
func TestEncryptAsymRemote_JSONOutput(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "json",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	encryptAsymRemote(cfg, printer, "rsa-key", "secret", "SHA256")

	output := buf.String()
	if output == "" {
		t.Error("Expected JSON output from encryptAsymRemote")
	}
}

// ============================================================================
// Test encryptRemote with JSON output
// ============================================================================

// Test encryptRemote with JSON output
func TestEncryptRemote_JSONOutput(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "json",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	encryptRemote(cfg, printer, "aes-key", "secret data", "")

	output := buf.String()
	if output == "" {
		t.Error("Expected JSON output from encryptRemote")
	}
}

// ============================================================================
// Test decryptRemote with JSON output
// ============================================================================

// Test decryptRemote with JSON output
func TestDecryptRemote_JSONOutput(t *testing.T) {
	mockClient := NewMockClient()
	buf := &bytes.Buffer{}
	printer := NewPrinter("json", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "json",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	ciphertext := base64.StdEncoding.EncodeToString([]byte("encrypted-data"))
	nonce := base64.StdEncoding.EncodeToString([]byte("nonce"))
	tag := base64.StdEncoding.EncodeToString([]byte("tag"))

	decryptRemote(cfg, printer, "aes-key", ciphertext, "", nonce, tag)

	output := buf.String()
	if output == "" {
		t.Error("Expected JSON output from decryptRemote")
	}
}

// ============================================================================
// Test import/export with success output files
// ============================================================================

// Test importKeyRemote success message
func TestImportKeyRemote_SuccessMessage(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.importKeyResp = &client.ImportKeyResponse{
		Success: true,
		KeyID:   "imported-key",
		Message: "Key imported successfully",
	}

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key-material"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	importKeyRemote(cfg, printer, "imported-key", wrapped)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from importKeyRemote")
	}
}

// Test exportKeyRemote with valid output
func TestExportKeyRemote_ValidOutput(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.exportKeyResp = &client.ExportKeyResponse{
		KeyID:              "test-key",
		WrappedKeyMaterial: []byte("wrapped-key-material-data"),
		Algorithm:          "RSA-OAEP",
	}

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "exported-key.json")

	buf := &bytes.Buffer{}
	printer := NewPrinter("text", buf)

	cfg := &Config{
		Backend:       "software",
		OutputFormat:  "text",
		ClientFactory: createMockClientFactory(mockClient),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	exportKeyRemote(cfg, printer, "test-key", outputFile, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)

	output := buf.String()
	if output == "" {
		t.Error("Expected output from exportKeyRemote")
	}

	// Verify file was created
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Error("Expected output file to be created")
	}
}
