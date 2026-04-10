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

package phone

import (
	"crypto/x509"
	"testing"
)

// mockPlatformVerifier implements PlatformVerifier for testing.
type mockPlatformVerifier struct {
	platform string
	result   *VerifiedAttestation
	err      error
}

func (m *mockPlatformVerifier) VerifyAttestation(derChain [][]byte, nonce []byte) (*VerifiedAttestation, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

func (m *mockPlatformVerifier) Platform() string {
	return m.platform
}

func TestRegisterPlatform_AndLookup(t *testing.T) {
	const testPlatform = "test-platform-register"

	// Register a factory.
	RegisterPlatform(testPlatform, func(trustPool *x509.CertPool, cfg *AttestationConfig) (PlatformVerifier, error) {
		return &mockPlatformVerifier{platform: testPlatform}, nil
	})

	// Look it up.
	verifier, err := NewPlatformVerifier(testPlatform, nil, nil)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if verifier == nil {
		t.Fatal("expected non-nil verifier")
	}
	if verifier.Platform() != testPlatform {
		t.Errorf("expected platform %q, got %q", testPlatform, verifier.Platform())
	}

	// Clean up registry.
	platformVerifiersMu.Lock()
	delete(platformVerifiers, testPlatform)
	platformVerifiersMu.Unlock()
}

func TestNewPlatformVerifier_UnsupportedPlatform(t *testing.T) {
	_, err := NewPlatformVerifier("nonexistent-platform", nil, nil)
	if err != ErrUnsupportedPlatform {
		t.Errorf("expected ErrUnsupportedPlatform, got %v", err)
	}
}

func TestNewPlatformVerifier_FactoryError(t *testing.T) {
	const testPlatform = "test-platform-error"
	factoryErr := ErrInvalidConfig

	RegisterPlatform(testPlatform, func(trustPool *x509.CertPool, cfg *AttestationConfig) (PlatformVerifier, error) {
		return nil, factoryErr
	})

	_, err := NewPlatformVerifier(testPlatform, nil, nil)
	if err != factoryErr {
		t.Errorf("expected factory error %v, got %v", factoryErr, err)
	}

	// Clean up registry.
	platformVerifiersMu.Lock()
	delete(platformVerifiers, testPlatform)
	platformVerifiersMu.Unlock()
}

func TestNewPlatformVerifier_PassesConfigAndPool(t *testing.T) {
	const testPlatform = "test-platform-config"

	pool := x509.NewCertPool()
	cfg := &AttestationConfig{
		Platform:         testPlatform,
		MinSecurityLevel: "tee",
		VerifyBootState:  true,
	}

	var receivedPool *x509.CertPool
	var receivedCfg *AttestationConfig

	RegisterPlatform(testPlatform, func(trustPool *x509.CertPool, c *AttestationConfig) (PlatformVerifier, error) {
		receivedPool = trustPool
		receivedCfg = c
		return &mockPlatformVerifier{platform: testPlatform}, nil
	})

	_, err := NewPlatformVerifier(testPlatform, pool, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedPool != pool {
		t.Error("expected factory to receive the cert pool")
	}
	if receivedCfg != cfg {
		t.Error("expected factory to receive the config")
	}

	// Clean up registry.
	platformVerifiersMu.Lock()
	delete(platformVerifiers, testPlatform)
	platformVerifiersMu.Unlock()
}

func TestVerifiedAttestation_Fields(t *testing.T) {
	va := &VerifiedAttestation{
		SecurityBackend: "android-keystore-strongbox",
		PlatformData:    "test-data",
	}

	if va.SecurityBackend != "android-keystore-strongbox" {
		t.Errorf("expected android-keystore-strongbox, got %s", va.SecurityBackend)
	}
	if va.PlatformData != "test-data" {
		t.Errorf("expected test-data, got %v", va.PlatformData)
	}
}
