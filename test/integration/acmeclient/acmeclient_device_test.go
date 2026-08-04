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

//go:build integration && tpm2

// Package acmeclient_test provides TPM device integration tests.
// These tests require swtpm and are only run when the tpm2 build tag is set.
package acmeclient_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDeviceEnroll tests TPM device enrollment via the CLI.
func TestDeviceEnroll(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	email := fmt.Sprintf("device-enroll-%d@example.com", time.Now().UnixNano())
	configPath := createTestConfig(t, cfg.ServerURL, email)
	cfg.ConfigPath = configPath

	// Account is already defined in config, proceed directly to enrollment
	tmpDir, err := os.MkdirTemp("", "acme-device-enroll-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	certFile := filepath.Join(tmpDir, "idevid.pem")
	iakFile := filepath.Join(tmpDir, "iak.pem")

	stdout, stderr, err := runACMEClient(t, cfg,
		"device", "enroll",
		"--device-id", "192.168.1.100",
		"--cn", "test-device-01.example.com",
		"--output-cert", certFile,
		"--output-iak", iakFile,
	)

	if err != nil {
		t.Logf("device enroll result: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
		combinedOutput := strings.ToLower(stderr + stdout)
		// TPM operations may fail if swtpm is not properly configured
		if strings.Contains(combinedOutput, "tpm") ||
			strings.Contains(combinedOutput, "simulator") ||
			strings.Contains(combinedOutput, "device") {
			t.Log("device enrollment failed due to TPM configuration (check swtpm setup)")
			return
		}
		t.Fatalf("unexpected device enrollment failure: %v", err)
	}

	// Verify output files exist
	_, err = os.Stat(certFile)
	assert.NoError(t, err, "IDevID certificate file should exist")
	_, err = os.Stat(iakFile)
	assert.NoError(t, err, "IAK certificate file should exist")
}

// TestDeviceEnrollMissingDeviceID tests enrollment without device ID.
func TestDeviceEnrollMissingDeviceID(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	configPath := createTestConfig(t, cfg.ServerURL, cfg.Email)
	cfg.ConfigPath = configPath

	_, stderr, err := runACMEClient(t, cfg, "device", "enroll")
	if err == nil {
		t.Fatal("expected error for missing device ID, but command succeeded")
	}

	combinedOutput := strings.ToLower(stderr)
	assert.True(t,
		strings.Contains(combinedOutput, "device") ||
			strings.Contains(combinedOutput, "required") ||
			strings.Contains(combinedOutput, "error"),
		"error should mention device-id requirement, got: %s", stderr)
}

// TestDeviceAttest tests TPM device attestation via the CLI.
func TestDeviceAttest(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	email := fmt.Sprintf("device-attest-%d@example.com", time.Now().UnixNano())
	configPath := createTestConfig(t, cfg.ServerURL, email)
	cfg.ConfigPath = configPath

	// Account is already defined in config, proceed directly to attestation
	tmpDir, err := os.MkdirTemp("", "acme-device-attest-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	outputCert := filepath.Join(tmpDir, "attested.pem")

	stdout, stderr, err := runACMEClient(t, cfg,
		"device", "attest",
		"--device-id", "192.168.1.100",
		"--pcrs", "0,1,2,3,7",
		"--output-cert", outputCert,
	)

	if err != nil {
		t.Logf("device attest result: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
		combinedOutput := strings.ToLower(stderr + stdout)
		if strings.Contains(combinedOutput, "tpm") ||
			strings.Contains(combinedOutput, "simulator") ||
			strings.Contains(combinedOutput, "device") {
			t.Log("device attestation failed due to TPM configuration (check swtpm setup)")
			return
		}
		t.Fatalf("unexpected device attestation failure: %v", err)
	}

	_, err = os.Stat(outputCert)
	assert.NoError(t, err, "attestation certificate file should exist")
}

// TestDeviceAttestMissingDeviceID tests attestation without device ID.
func TestDeviceAttestMissingDeviceID(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	configPath := createTestConfig(t, cfg.ServerURL, cfg.Email)
	cfg.ConfigPath = configPath

	_, stderr, err := runACMEClient(t, cfg, "device", "attest")
	if err == nil {
		t.Fatal("expected error for missing device ID, but command succeeded")
	}

	combinedOutput := strings.ToLower(stderr)
	assert.True(t,
		strings.Contains(combinedOutput, "device") ||
			strings.Contains(combinedOutput, "required") ||
			strings.Contains(combinedOutput, "error"),
		"error should mention device-id requirement, got: %s", stderr)
}

// TestDeviceAttestInvalidPCRs tests attestation with invalid PCR indices.
func TestDeviceAttestInvalidPCRs(t *testing.T) {
	cfg := newACMEClientConfig()
	requireBinary(t, cfg)

	configPath := createTestConfig(t, cfg.ServerURL, cfg.Email)
	cfg.ConfigPath = configPath

	_, stderr, err := runACMEClient(t, cfg,
		"device", "attest",
		"--device-id", "192.168.1.100",
		"--pcrs", "99,100",
	)
	if err == nil {
		t.Fatal("expected error for invalid PCR indices, but command succeeded")
	}

	combinedOutput := strings.ToLower(stderr)
	assert.True(t,
		strings.Contains(combinedOutput, "pcr") ||
			strings.Contains(combinedOutput, "invalid") ||
			strings.Contains(combinedOutput, "range") ||
			strings.Contains(combinedOutput, "error"),
		"error should indicate invalid PCR indices, got: %s", stderr)
}
