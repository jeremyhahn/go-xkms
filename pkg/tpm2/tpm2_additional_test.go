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

//go:build tpm2

package tpm2

import (
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/tpm2/mocks"
)

// TestTPM2KeyStore_TPM tests the TPM accessor method
func TestTPM2KeyStore_TPM(t *testing.T) {
	mockTPM := mocks.NewMockTPM()
	ks := &TPM2KeyStore{tpm: mockTPM}

	if ks.TPM() == nil {
		t.Error("TPM() should return non-nil")
	}

	ks2 := &TPM2KeyStore{tpm: nil}
	if ks2.TPM() != nil {
		t.Error("TPM() should return nil when not set")
	}
}

// TestSimulatorCloser_Send tests the Send method
func TestSimulatorCloser_Send(t *testing.T) {
	mockTPM := mocks.NewMockTPM()
	mockTPM.SendFunc = func(input []byte) ([]byte, error) {
		return []byte("response"), nil
	}

	sc := &simulatorCloser{transport: mockTPM}
	result, err := sc.Send([]byte("test"))

	if err != nil {
		t.Errorf("Send() unexpected error: %v", err)
	}
	if string(result) != "response" {
		t.Errorf("Send() = %s, want response", result)
	}
}

// TestTPM2KeyStore_HMAC tests HMAC session creation (password auth mode)
func TestTPM2KeyStore_HMAC(t *testing.T) {
	config := DefaultConfig()
	config.EncryptSession = false // Test password auth path only
	ks := &TPM2KeyStore{config: config}

	session := ks.HMAC([]byte("testauth"))
	if session == nil {
		t.Error("HMAC() returned nil session")
	}

	session2 := ks.HMAC(nil)
	if session2 == nil {
		t.Error("HMAC() returned nil session with nil auth")
	}
}

// Note: HMACSession, HMACSaltedSession, loadSRKName, sealPIN, unsealPIN, loadKey,
// loadKeyWithSession, Sign, and Decrypt require actual TPM Send() interaction and
// session management which cannot be properly mocked. They are thoroughly tested in
// integration tests (tpm2_integration_test.go).
