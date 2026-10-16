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

package issuance

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultProfile(t *testing.T) {
	p := DefaultProfile()

	assert.Equal(t, "default", p.Name)
	assert.Equal(t, 398, p.MaxValidityDays)
	assert.True(t, p.RequireCT)
	assert.Equal(t, "default", p.LintProfile)

	// Check allowed algorithms
	assert.Contains(t, p.AllowedKeyAlgorithms, x509.RSA)
	assert.Contains(t, p.AllowedKeyAlgorithms, x509.ECDSA)
	assert.Contains(t, p.AllowedKeyAlgorithms, x509.Ed25519)

	// Check key usages
	assert.Contains(t, p.AllowedKeyUsages, x509.KeyUsageDigitalSignature)
	assert.Contains(t, p.AllowedKeyUsages, x509.KeyUsageKeyEncipherment)

	// Check extended key usages
	assert.Contains(t, p.AllowedExtKeyUsages, x509.ExtKeyUsageServerAuth)
	assert.Contains(t, p.AllowedExtKeyUsages, x509.ExtKeyUsageClientAuth)
}

func TestTLSProfile(t *testing.T) {
	p := TLSProfile()

	assert.Equal(t, "tls", p.Name)
	assert.Equal(t, 398, p.MaxValidityDays)
	assert.True(t, p.RequireCT)
	assert.Equal(t, "tls", p.LintProfile)

	// TLS profile should allow RSA and ECDSA
	assert.Contains(t, p.AllowedKeyAlgorithms, x509.RSA)
	assert.Contains(t, p.AllowedKeyAlgorithms, x509.ECDSA)

	// TLS profile should only allow ServerAuth
	assert.Contains(t, p.AllowedExtKeyUsages, x509.ExtKeyUsageServerAuth)
	assert.NotContains(t, p.AllowedExtKeyUsages, x509.ExtKeyUsageClientAuth)
}

func TestInternalProfile(t *testing.T) {
	p := InternalProfile()

	assert.Equal(t, "internal", p.Name)
	assert.Greater(t, p.MaxValidityDays, 398) // Should be longer than BR requirement
	assert.False(t, p.RequireCT)              // No CT for internal certs
	assert.Equal(t, "lenient", p.LintProfile)

	// Internal profile should allow more algorithms
	assert.Contains(t, p.AllowedKeyAlgorithms, x509.Ed25519)

	// Internal profile allows code signing
	assert.Contains(t, p.AllowedExtKeyUsages, x509.ExtKeyUsageCodeSigning)
}

func TestSerialMetadata(t *testing.T) {
	m := SerialMetadata{
		RequestID: "req-123",
		Subject:   "CN=test.example.com",
		Profile:   "default",
	}

	assert.Equal(t, "req-123", m.RequestID)
	assert.Equal(t, "CN=test.example.com", m.Subject)
	assert.Equal(t, "default", m.Profile)
}

func TestRequestFields(t *testing.T) {
	req := &Request{
		TenantID: testTenant,
		Profile:  "tls",
		SkipCT:   true,
		SkipLint: true,
		RequestMetadata: map[string]string{
			"client_id": "test-client",
		},
	}

	assert.Equal(t, "tls", req.Profile)
	assert.True(t, req.SkipCT)
	assert.True(t, req.SkipLint)
	assert.Equal(t, "test-client", req.RequestMetadata["client_id"])
}

func TestResultFields(t *testing.T) {
	result := &Result{
		IssuanceID: "issue-abc123",
	}

	assert.Equal(t, "issue-abc123", result.IssuanceID)
}
