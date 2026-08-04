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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/ct"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test additional error paths

func TestIssuer_SignerErrors(t *testing.T) {
	t.Run("signer error getting certificate", func(t *testing.T) {
		signer := newMockSigner(t)
		signer.certErr = errors.New("cert not available")

		config := Config{
			Signer:  signer,
			Enabled: true,
			Profiles: map[string]Profile{
				"internal": InternalProfile(),
			},
			DefaultProfile: "internal",
		}

		issuer, err := NewIssuer(config)
		require.NoError(t, err)

		csr, _ := createTestCSR(t)
		req := &Request{
			CSR:       csr,
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(0, 0, 90),
			Profile:   "internal",
			SkipCT:    true,
		}

		_, err = issuer.Issue(context.Background(), req)
		assert.Error(t, err)
	})

	t.Run("signer error getting signer", func(t *testing.T) {
		signer := newMockSigner(t)
		signer.signerErr = errors.New("signer not available")

		config := Config{
			Signer:  signer,
			Enabled: true,
			Profiles: map[string]Profile{
				"internal": InternalProfile(),
			},
			DefaultProfile: "internal",
		}

		issuer, err := NewIssuer(config)
		require.NoError(t, err)

		csr, _ := createTestCSR(t)
		req := &Request{
			CSR:       csr,
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(0, 0, 90),
			Profile:   "internal",
			SkipCT:    true,
		}

		_, err = issuer.Issue(context.Background(), req)
		assert.Error(t, err)
	})
}

func TestIssuer_WithTemplate(t *testing.T) {
	signer := newMockSigner(t)
	linter := &mockLinter{passed: true}

	config := Config{
		Signer:  signer,
		Linter:  linter,
		Enabled: true,
		Profiles: map[string]Profile{
			"internal": InternalProfile(),
		},
		DefaultProfile: "internal",
	}

	issuer, err := NewIssuer(config)
	require.NoError(t, err)

	csr, csrKey := createTestCSR(t)

	// Create a custom template
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "custom.example.com",
			Organization: []string{"Custom Org"},
		},
		DNSNames:    []string{"custom.example.com"},
		PublicKey:   &csrKey.PublicKey,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	req := &Request{
		CSR:       csr,
		Template:  template,
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, 90),
		Profile:   "internal",
		SkipCT:    true,
	}

	result, err := issuer.Issue(context.Background(), req)
	require.NoError(t, err)

	assert.Equal(t, "custom.example.com", result.FinalCert.Subject.CommonName)
}

func TestIssuer_SkipLint(t *testing.T) {
	signer := newMockSigner(t)
	// Linter that would fail
	linter := &mockLinter{passed: false, summary: "would fail"}

	config := Config{
		Signer:  signer,
		Linter:  linter,
		Enabled: true,
		Profiles: map[string]Profile{
			"internal": InternalProfile(),
		},
		DefaultProfile: "internal",
	}

	issuer, err := NewIssuer(config)
	require.NoError(t, err)

	csr, _ := createTestCSR(t)
	req := &Request{
		CSR:       csr,
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, 90),
		Profile:   "internal",
		SkipCT:    true,
		SkipLint:  true, // Skip linting
	}

	// Should succeed because linting is skipped
	result, err := issuer.Issue(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestIssuer_LinterError(t *testing.T) {
	signer := newMockSigner(t)
	linter := &mockLinter{lintErr: errors.New("linter crashed")}

	config := Config{
		Signer:  signer,
		Linter:  linter,
		Enabled: true,
		Profiles: map[string]Profile{
			"internal": InternalProfile(),
		},
		DefaultProfile: "internal",
	}

	issuer, err := NewIssuer(config)
	require.NoError(t, err)

	csr, _ := createTestCSR(t)
	req := &Request{
		CSR:       csr,
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, 90),
		Profile:   "internal",
		SkipCT:    true,
	}

	_, err = issuer.Issue(context.Background(), req)
	assert.Error(t, err)
}

func TestIssuer_SerialStorageErrors(t *testing.T) {
	signer := newMockSigner(t)
	serialStorage := newMockSerialStorage()
	serialStorage.err = errors.New("storage error")

	config := Config{
		Signer:        signer,
		SerialStorage: serialStorage,
		Enabled:       true,
		Profiles: map[string]Profile{
			"internal": InternalProfile(),
		},
		DefaultProfile: "internal",
	}

	issuer, err := NewIssuer(config)
	require.NoError(t, err)

	csr, _ := createTestCSR(t)
	req := &Request{
		CSR:       csr,
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, 90),
		Profile:   "internal",
		SkipCT:    true,
	}

	_, err = issuer.Issue(context.Background(), req)
	assert.Error(t, err)
}

func TestIssuer_MissingSCTs(t *testing.T) {
	signer := newMockSigner(t)
	linter := &mockLinter{passed: true}
	ctSubmitter := &mockCTSubmitter{
		scts: []ct.SignedCertificateTimestamp{}, // Empty SCTs
	}

	config := Config{
		Signer:      signer,
		Linter:      linter,
		CTSubmitter: ctSubmitter,
		Enabled:     true,
	}

	issuer, err := NewIssuer(config)
	require.NoError(t, err)

	csr, _ := createTestCSR(t)
	req := &Request{
		CSR:       csr,
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, 90),
	}

	// Should succeed but with empty SCTs
	result, err := issuer.Issue(context.Background(), req)
	require.NoError(t, err)
	assert.Empty(t, result.SCTs)
}

func TestIssuer_InvalidCSRSignature(t *testing.T) {
	signer := newMockSigner(t)

	config := Config{
		Signer:  signer,
		Enabled: true,
	}

	issuer, err := NewIssuer(config)
	require.NoError(t, err)

	// Create CSR with invalid signature
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	// Corrupt the signature
	csr.Signature = []byte("corrupted")

	req := &Request{
		CSR:       csr,
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, 90),
	}

	_, err = issuer.Issue(context.Background(), req)
	assert.Error(t, err)
}

func TestIssuer_ZeroValidityPeriod(t *testing.T) {
	signer := newMockSigner(t)

	config := Config{
		Signer:  signer,
		Enabled: true,
	}

	issuer, err := NewIssuer(config)
	require.NoError(t, err)

	csr, _ := createTestCSR(t)

	t.Run("zero NotBefore", func(t *testing.T) {
		req := &Request{
			CSR:      csr,
			NotAfter: time.Now().AddDate(0, 0, 90),
		}
		_, err = issuer.Issue(context.Background(), req)
		assert.Error(t, err)
	})

	t.Run("zero NotAfter", func(t *testing.T) {
		req := &Request{
			CSR:       csr,
			NotBefore: time.Now(),
		}
		_, err = issuer.Issue(context.Background(), req)
		assert.Error(t, err)
	})
}

func TestIssuer_AllAuditCallbacks(t *testing.T) {
	signer := newMockSigner(t)
	linter := &mockLinter{passed: true}
	ctSubmitter := &mockCTSubmitter{}
	certStorage := newMockCertStorage()
	serialStorage := newMockSerialStorage()
	auditLogger := &mockAuditLogger{}

	config := Config{
		Signer:        signer,
		Linter:        linter,
		CTSubmitter:   ctSubmitter,
		CertStorage:   certStorage,
		SerialStorage: serialStorage,
		AuditLogger:   auditLogger,
		Enabled:       true,
	}

	issuer, err := NewIssuer(config)
	require.NoError(t, err)

	csr, _ := createTestCSR(t)
	req := &Request{
		CSR:       csr,
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, 90),
	}

	result, err := issuer.Issue(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify all audit callbacks were called
	assert.Equal(t, 1, auditLogger.intents)
	assert.Equal(t, 1, auditLogger.precerts)
	assert.Equal(t, 1, auditLogger.cts)
	assert.Equal(t, 1, auditLogger.completes)
	assert.Equal(t, 0, auditLogger.failures)
}

func TestIsAllowedAlgorithm(t *testing.T) {
	allowed := []x509.PublicKeyAlgorithm{x509.RSA, x509.ECDSA}

	assert.True(t, isAllowedAlgorithm(x509.RSA, allowed))
	assert.True(t, isAllowedAlgorithm(x509.ECDSA, allowed))
	assert.False(t, isAllowedAlgorithm(x509.Ed25519, allowed))
	assert.False(t, isAllowedAlgorithm(x509.DSA, allowed))
}

func TestGenerateSerialEntropyCheck(t *testing.T) {
	i := &issuer{}

	// Generate multiple serials and ensure they're unique
	seen := make(map[string]struct{})
	for j := 0; j < 100; j++ {
		serial, err := i.generateSerial()
		require.NoError(t, err)

		// Serial should be positive
		assert.True(t, serial.Sign() > 0)

		// Serial should be unique
		key := serial.String()
		_, exists := seen[key]
		assert.False(t, exists, "duplicate serial generated")
		seen[key] = struct{}{}
	}
}

// Additional mock implementations for edge cases

func TestIssuer_AlgorithmNotAllowed(t *testing.T) {
	signer := newMockSigner(t)

	// Create profile that only allows RSA
	rsaOnlyProfile := Profile{
		Name:                 "rsa-only",
		MaxValidityDays:      365,
		AllowedKeyAlgorithms: []x509.PublicKeyAlgorithm{x509.RSA},
	}

	config := Config{
		Signer:  signer,
		Enabled: true,
		Profiles: map[string]Profile{
			"rsa-only": rsaOnlyProfile,
		},
		DefaultProfile: "rsa-only",
	}

	issuer, err := NewIssuer(config)
	require.NoError(t, err)

	// Create ECDSA CSR
	csr, _ := createTestCSR(t) // This creates an ECDSA CSR
	req := &Request{
		CSR:       csr,
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, 90),
	}

	_, err = issuer.Issue(context.Background(), req)
	assert.Error(t, err)

	var csrErr *CSRValidationError
	assert.ErrorAs(t, err, &csrErr)
	assert.Contains(t, csrErr.Message, "not allowed")
}

func TestIssuer_IssuerChainError(t *testing.T) {
	signer := newMockSigner(t)
	linter := &mockLinter{passed: true}

	// Create a mock CT submitter that will try to get the issuer chain
	ctSubmitter := &mockCTSubmitter{}

	config := Config{
		Signer:      signer,
		Linter:      linter,
		CTSubmitter: ctSubmitter,
		Enabled:     true,
	}

	issuer, err := NewIssuer(config)
	require.NoError(t, err)

	csr, _ := createTestCSR(t)
	req := &Request{
		CSR:       csr,
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, 90),
	}

	// Should succeed
	result, err := issuer.Issue(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestMockSerialStorageOperations(t *testing.T) {
	storage := newMockSerialStorage()

	serial := big.NewInt(12345)
	metadata := SerialMetadata{RequestID: "test"}

	// Reserve
	err := storage.ReserveSerial(context.Background(), serial, metadata)
	require.NoError(t, err)

	// Check if used
	used, err := storage.IsSerialUsed(context.Background(), serial)
	require.NoError(t, err)
	assert.True(t, used)

	// Confirm
	err = storage.ConfirmSerial(context.Background(), serial)
	require.NoError(t, err)

	// Revoke
	err = storage.RevokeReservation(context.Background(), serial)
	require.NoError(t, err)

	// Should no longer be used
	used, err = storage.IsSerialUsed(context.Background(), serial)
	require.NoError(t, err)
	assert.False(t, used)
}

func TestMockCertStorageOperations(t *testing.T) {
	storage := newMockCertStorage()

	// Create test cert
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial := big.NewInt(99999)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Store certificate
	err = storage.StoreCertificate(context.Background(), cert)
	require.NoError(t, err)

	// Store precert
	err = storage.StorePrecert(context.Background(), cert)
	require.NoError(t, err)

	// Get by serial
	retrieved, err := storage.GetCertificateBySerial(context.Background(), serial)
	require.NoError(t, err)
	assert.Equal(t, serial, retrieved.SerialNumber)

	// Get non-existent
	_, err = storage.GetCertificateBySerial(context.Background(), big.NewInt(1))
	assert.Error(t, err)
}
