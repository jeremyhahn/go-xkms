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
	"crypto"
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

// Test for TBS verification failure path

func TestIssuer_TBSVerificationFailure(t *testing.T) {
	t.Run("TBS verification success path", func(t *testing.T) {
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

		csr, _ := createTestCSR(t)
		req := &Request{
			TenantID:  testTenant,
			CSR:       csr,
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(0, 0, 90),
			SkipCT:    true,
		}

		// Should succeed normally as the signer is deterministic
		result, err := issuer.Issue(context.Background(), req)
		require.NoError(t, err)
		assert.NotNil(t, result)
	})
}

// Test for profile that doesn't require CT

func TestIssuer_ProfileWithoutCT(t *testing.T) {
	signer := newMockSigner(t)
	linter := &mockLinter{passed: true}
	certStorage := newMockCertStorage()

	// Create profile that doesn't require CT
	noCTProfile := Profile{
		Name:            "no-ct",
		MaxValidityDays: 365,
		RequireCT:       false, // No CT required
		AllowedKeyAlgorithms: []x509.PublicKeyAlgorithm{
			x509.ECDSA,
		},
	}

	config := Config{
		Signer:      signer,
		Linter:      linter,
		CertStorage: certStorage,
		Enabled:     true,
		Profiles: map[string]Profile{
			"no-ct": noCTProfile,
		},
		DefaultProfile: "no-ct",
	}

	issuer, err := NewIssuer(config)
	require.NoError(t, err)

	csr, _ := createTestCSR(t)
	req := &Request{
		TenantID:  testTenant,
		CSR:       csr,
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, 90),
	}

	result, err := issuer.Issue(context.Background(), req)
	require.NoError(t, err)
	assert.Empty(t, result.SCTs) // No SCTs because CT is not required
}

// Test for CT submission with nil CTSubmitter when required

func TestIssuer_CTRequired_NoSubmitter(t *testing.T) {
	signer := newMockSigner(t)
	linter := &mockLinter{passed: true}

	// Profile requires CT but no submitter is configured
	ctRequiredProfile := Profile{
		Name:            "ct-required",
		MaxValidityDays: 398,
		RequireCT:       true, // CT required
		AllowedKeyAlgorithms: []x509.PublicKeyAlgorithm{
			x509.ECDSA,
		},
	}

	config := Config{
		Signer:      signer,
		Linter:      linter,
		CTSubmitter: nil, // No CT submitter
		Enabled:     true,
		Profiles: map[string]Profile{
			"ct-required": ctRequiredProfile,
		},
		DefaultProfile: "ct-required",
	}

	issuer, err := NewIssuer(config)
	require.NoError(t, err)

	csr, _ := createTestCSR(t)
	req := &Request{
		TenantID:  testTenant,
		CSR:       csr,
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, 90),
	}

	// Should succeed but with no SCTs because CTSubmitter is nil
	result, err := issuer.Issue(context.Background(), req)
	require.NoError(t, err)
	assert.Empty(t, result.SCTs)
}

// Test for serial confirmation logging (line 277-279)

func TestIssuer_SerialConfirmation(t *testing.T) {
	signer := newMockSigner(t)
	linter := &mockLinter{passed: true}
	serialStorage := &confirmFailSerialStorage{
		reserved: make(map[string]bool),
	}

	config := Config{
		Signer:        signer,
		Linter:        linter,
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
		TenantID:  testTenant,
		CSR:       csr,
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, 90),
		SkipCT:    true,
	}

	// Should succeed even if ConfirmSerial fails (it just logs)
	result, err := issuer.Issue(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, serialStorage.confirmCalled)
}

type confirmFailSerialStorage struct {
	reserved      map[string]bool
	confirmCalled bool
}

func (s *confirmFailSerialStorage) ReserveSerial(ctx context.Context, serial *big.Int, metadata SerialMetadata) error {
	s.reserved[serial.String()] = true
	return nil
}

func (s *confirmFailSerialStorage) ConfirmSerial(ctx context.Context, serial *big.Int) error {
	s.confirmCalled = true
	return errors.New("confirm failed") // This error should be logged but not returned
}

func (s *confirmFailSerialStorage) RevokeReservation(ctx context.Context, serial *big.Int) error {
	delete(s.reserved, serial.String())
	return nil
}

func (s *confirmFailSerialStorage) IsSerialUsed(ctx context.Context, serial *big.Int) (bool, error) {
	return s.reserved[serial.String()], nil
}

// Test for CT issuer chain error

func TestIssuer_CTIssuerChainError(t *testing.T) {
	linter := &mockLinter{passed: true}
	ctSubmitter := &mockCTSubmitter{}

	// Signer that fails on the Certificate() call getIssuerChain makes. The
	// issuer resolves its signing identity once up front, so that is the
	// second call.
	signer := &issuerChainFailSigner{
		failOnCall: 2,
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
		TenantID:  testTenant,
		CSR:       csr,
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, 90),
	}

	_, err = issuer.Issue(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "chain")
}

type issuerChainFailSigner struct {
	key        *ecdsa.PrivateKey
	cert       *x509.Certificate
	callNum    int
	failOnCall int
}

func (s *issuerChainFailSigner) init() {
	if s.key == nil {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "Test CA"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().AddDate(10, 0, 0),
			IsCA:         true,
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(certDER)
		s.key = key
		s.cert = cert
	}
}

func (s *issuerChainFailSigner) Signer() (crypto.Signer, error) {
	s.init()
	return s.key, nil
}

func (s *issuerChainFailSigner) Certificate() (*x509.Certificate, error) {
	s.init()
	s.callNum++
	if s.callNum >= s.failOnCall {
		return nil, errors.New("failed to get issuer chain")
	}
	return s.cert, nil
}

func (s *issuerChainFailSigner) SignCertificate(template, parent *x509.Certificate, pub, priv interface{}) ([]byte, error) {
	s.init()
	return x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
}

// Test for replacePoisonWithSCTs with valid SCTs

func TestIssuer_ReplacePoisonWithSCTs_ValidSCTs(t *testing.T) {
	signer := newMockSigner(t)
	linter := &mockLinter{passed: true}

	// Use mock submitter that returns valid SCTs
	ctSubmitter := &mockCTSubmitter{
		scts: []ct.SignedCertificateTimestamp{
			{Version: ct.V1, Timestamp: 12345},
		},
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
		TenantID:  testTenant,
		CSR:       csr,
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, 90),
	}

	result, err := issuer.Issue(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.SCTs)
}

// Test for template with extra extensions

func TestIssuer_TemplateWithExtraExtensions(t *testing.T) {
	signer := newMockSigner(t)
	linter := &mockLinter{passed: true}
	ctSubmitter := &mockCTSubmitter{
		scts: []ct.SignedCertificateTimestamp{
			{Version: ct.V1, Timestamp: 12345},
		},
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

	// Create template with extra extensions
	template := &x509.Certificate{
		Subject:     csr.Subject,
		PublicKey:   csr.PublicKey,
		DNSNames:    csr.DNSNames,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       []int{1, 2, 3, 4, 5},
				Critical: false,
				Value:    []byte("custom extension"),
			},
		},
	}

	req := &Request{
		TenantID:  testTenant,
		CSR:       csr,
		Template:  template,
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, 90),
	}

	result, err := issuer.Issue(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, result)
}
