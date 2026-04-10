// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Accessor Tests
// =============================================================================

func TestCA_IsInitialized(t *testing.T) {
	ca := setupTestCA(t)
	assert.True(t, ca.IsInitialized())
}

func TestCA_IsInitialized_NotInitialized(t *testing.T) {
	ca := &CA{}
	assert.False(t, ca.IsInitialized())
}

func TestCA_Public(t *testing.T) {
	ca := setupTestCA(t)
	pub := ca.Public()
	require.NotNil(t, pub)
	_, ok := pub.(*ecdsa.PublicKey)
	assert.True(t, ok, "expected ECDSA public key")
}

func TestCA_Public_NotInitialized(t *testing.T) {
	ca := &CA{}
	pub := ca.Public()
	assert.Nil(t, pub)
}

func TestCA_KeyStore(t *testing.T) {
	ca := setupTestCA(t)
	ks := ca.KeyStore()
	assert.NotNil(t, ks)
}

func TestCA_CertStore(t *testing.T) {
	ca := setupTestCA(t)
	cs := ca.CertStore()
	assert.NotNil(t, cs)
}

func TestCA_Config(t *testing.T) {
	ca := setupTestCA(t)
	cfg := ca.Config()
	require.NotNil(t, cfg)
	assert.NotEmpty(t, cfg.Subject.CommonName)
}

func TestCA_Identity(t *testing.T) {
	ca := setupTestCA(t)
	id := ca.Identity()
	assert.NotEmpty(t, id)
	assert.Equal(t, "Test Root CA", id)
}

func TestCA_Identity_NilConfig(t *testing.T) {
	ca := &CA{config: &MultiIdentityCAConfig{}}
	id := ca.Identity()
	assert.Empty(t, id)
}

// =============================================================================
// Sign Tests
// =============================================================================

func TestCA_Sign(t *testing.T) {
	ca := setupTestCA(t)
	digest := sha256.Sum256([]byte("test data"))
	sig, err := ca.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)

	pub := ca.Public().(*ecdsa.PublicKey)
	valid := ecdsa.VerifyASN1(pub, digest[:], sig)
	assert.True(t, valid)
}

func TestCA_Sign_NotInitialized(t *testing.T) {
	ca := &CA{}
	digest := sha256.Sum256([]byte("test"))
	_, err := ca.Sign(rand.Reader, digest[:], crypto.SHA256)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// =============================================================================
// Load Tests
// =============================================================================

func TestCA_Load_AlreadyInitialized(t *testing.T) {
	ca := setupTestCA(t)
	err := ca.Load()
	assert.ErrorIs(t, err, ErrAlreadyInitialized)
}

func TestCA_Load_AfterInit(t *testing.T) {
	ca1 := setupTestCA(t)
	ca2 := &CA{
		keyStore:    ca1.keyStore,
		certStore:   ca1.certStore,
		config:      ca1.config,
		revocations: make(map[string]*RevocationInfo),
	}
	err := ca2.Load()
	require.NoError(t, err)
	assert.True(t, ca2.IsInitialized())
}

// =============================================================================
// Revoke Tests
// =============================================================================

func TestCA_Revoke(t *testing.T) {
	ca := setupTestCA(t)
	serial := big.NewInt(12345)
	require.NoError(t, ca.Revoke(serial, 1))
	revoked, err := ca.IsRevoked(serial)
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestCA_Revoke_NilSerial(t *testing.T) {
	ca := setupTestCA(t)
	err := ca.Revoke(nil, 1)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestCA_Revoke_AlreadyRevoked(t *testing.T) {
	ca := setupTestCA(t)
	serial := big.NewInt(99999)
	require.NoError(t, ca.Revoke(serial, 1))
	err := ca.Revoke(serial, 1)
	assert.ErrorIs(t, err, ErrAlreadyRevoked)
}

func TestCA_Revoke_NotInitialized(t *testing.T) {
	ca := &CA{}
	err := ca.Revoke(big.NewInt(1), 1)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// =============================================================================
// GenerateCRL Tests
// =============================================================================

func TestCA_GenerateCRL(t *testing.T) {
	ca := setupTestCA(t)
	require.NoError(t, ca.Revoke(big.NewInt(111), 1))
	require.NoError(t, ca.Revoke(big.NewInt(222), 4))

	crlDER, err := ca.GenerateCRL()
	require.NoError(t, err)
	assert.NotEmpty(t, crlDER)

	crl, err := x509.ParseRevocationList(crlDER)
	require.NoError(t, err)
	assert.Len(t, crl.RevokedCertificateEntries, 2)
}

func TestCA_GenerateCRL_NotInitialized(t *testing.T) {
	ca := &CA{}
	_, err := ca.GenerateCRL()
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestCA_GenerateCRL_Empty(t *testing.T) {
	ca := setupTestCA(t)
	crlDER, err := ca.GenerateCRL()
	require.NoError(t, err)

	crl, err := x509.ParseRevocationList(crlDER)
	require.NoError(t, err)
	assert.Empty(t, crl.RevokedCertificateEntries)
}

// =============================================================================
// IssueCertificate Tests
// =============================================================================

func TestCA_IssueCertificate(t *testing.T) {
	ca := setupTestCA(t)
	request := &CertificateRequest{
		Subject: Subject{
			CommonName:   "test-server.example.com",
			Organization: "Test Org",
		},
		SANS: &SubjectAlternativeNames{
			DNS: []string{"test-server.example.com"},
		},
		Valid: 365,
	}

	issued, err := ca.IssueCertificate(request)
	require.NoError(t, err)
	require.NotNil(t, issued)
	assert.NotNil(t, issued.Certificate)
	assert.Equal(t, "test-server.example.com", issued.Certificate.Subject.CommonName)
}

func TestCA_IssueCertificate_NotInitialized(t *testing.T) {
	ca := &CA{}
	request := &CertificateRequest{
		Subject: Subject{CommonName: "test"},
	}
	_, err := ca.IssueCertificate(request)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestCA_IssueCertificate_DuplicateCN(t *testing.T) {
	ca := setupTestCA(t)
	request := &CertificateRequest{
		Subject: Subject{
			CommonName:   "duplicate.example.com",
			Organization: "Test",
		},
		SANS: &SubjectAlternativeNames{
			DNS: []string{"duplicate.example.com"},
		},
		Valid: 365,
	}

	_, err := ca.IssueCertificate(request)
	require.NoError(t, err)

	_, err = ca.IssueCertificate(request)
	assert.ErrorIs(t, err, ErrCertificateAlreadyExists)
}

// =============================================================================
// mergeSubjects Tests
// =============================================================================

func TestMergeSubjects(t *testing.T) {
	result := mergeSubjects(
		pkix.Name{
			CommonName:   "issuer-cn",
			Organization: []string{"Issuer Org"},
			Country:      []string{"US"},
		},
		&Subject{
			CommonName:   "request-cn",
			Organization: "Request Org",
		},
	)
	assert.Equal(t, "request-cn", result.CommonName)
	assert.Equal(t, []string{"Request Org"}, result.Organization)
	assert.Equal(t, []string{"US"}, result.Country)
}

func TestMergeSubjects_EmptyOverride(t *testing.T) {
	result := mergeSubjects(
		pkix.Name{
			CommonName:   "issuer-cn",
			Organization: []string{"Issuer Org"},
		},
		&Subject{},
	)
	assert.Equal(t, "issuer-cn", result.CommonName)
	assert.Equal(t, []string{"Issuer Org"}, result.Organization)
}

// =============================================================================
// CACertificate / CABundle Tests
// =============================================================================

func TestCA_CACertificate(t *testing.T) {
	ca := setupTestCA(t)
	cert, err := ca.CACertificate()
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.True(t, cert.IsCA)
}

func TestCA_CACertificate_NotInitialized(t *testing.T) {
	ca := &CA{}
	_, err := ca.CACertificate()
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestCA_CABundle(t *testing.T) {
	ca := setupTestCA(t)
	bundle, err := ca.CABundle()
	require.NoError(t, err)
	assert.NotEmpty(t, bundle)
}

func TestCA_CABundle_NotInitialized(t *testing.T) {
	ca := &CA{}
	_, err := ca.CABundle()
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// =============================================================================
// signatureAlgorithmToName Tests
// =============================================================================

func TestSignatureAlgorithmToName(t *testing.T) {
	got := signatureAlgorithmToName(x509.ECDSAWithSHA256)
	assert.Equal(t, types.SigECDSAWithSHA256, got)

	got = signatureAlgorithmToName(x509.SHA256WithRSA)
	assert.Equal(t, types.SigSHA256WithRSA, got)

	got = signatureAlgorithmToName(x509.PureEd25519)
	assert.Equal(t, types.SigEd25519, got)

	// Default case returns ECDSA-SHA256
	got = signatureAlgorithmToName(x509.UnknownSignatureAlgorithm)
	assert.Equal(t, types.SigECDSAWithSHA256, got)
}

// =============================================================================
// Profile Tests
// =============================================================================

func TestCA_ProfileRegistry_Register(t *testing.T) {
	ca := setupTestCA(t)
	require.NotNil(t, ca.profiles)

	profile := NewProfileBuilder("custom-test").
		WithKeyUsage(x509.KeyUsageDigitalSignature).
		WithExtKeyUsage(x509.ExtKeyUsageServerAuth).
		WithDefaultValidity(365).
		Build()

	err := ca.profiles.Register("custom-test", profile)
	require.NoError(t, err)
}

func TestCA_ProfileApply(t *testing.T) {
	profile := NewServerProfile()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	err := profile.Apply(template, nil)
	require.NoError(t, err)
	assert.True(t, template.KeyUsage&x509.KeyUsageDigitalSignature != 0)
}

func TestCA_ProfileBuilder(t *testing.T) {
	profile := NewProfileBuilder("test-builder").
		WithKeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment).
		WithExtKeyUsage(x509.ExtKeyUsageClientAuth).
		WithDefaultValidity(730).
		AsCA().
		Build()

	assert.Equal(t, "test-builder", profile.Name())
	assert.Equal(t, 730, profile.DefaultValidity())
}

func TestCA_ProfileRegistry_List(t *testing.T) {
	ca := setupTestCA(t)
	profiles := ca.profiles.List()
	assert.NotEmpty(t, profiles)
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestHybridCertError(t *testing.T) {
	inner := assert.AnError
	e := &HybridCertError{Op: "test", Err: inner}
	assert.Contains(t, e.Error(), inner.Error())
	assert.ErrorIs(t, e, inner)
}

func TestHybridVerificationError(t *testing.T) {
	e := &HybridVerificationError{Component: "classical", Reason: "bad hybrid cert"}
	assert.Contains(t, e.Error(), "bad hybrid cert")
}

func TestQuantumCertError(t *testing.T) {
	inner := assert.AnError
	e := &QuantumCertError{Err: inner}
	assert.Contains(t, e.Error(), inner.Error())
	assert.ErrorIs(t, e, inner)
}

func TestQuantumAlgorithmError(t *testing.T) {
	e := &QuantumAlgorithmError{Algorithm: "unsupported algorithm"}
	assert.Contains(t, e.Error(), "unsupported algorithm")
}

func TestQuantumVerificationError(t *testing.T) {
	e := &QuantumVerificationError{Reason: "encoding failed"}
	assert.Contains(t, e.Error(), "encoding failed")
}

// =============================================================================
// CertificateRequest Validate Tests
// =============================================================================

func TestCertificateRequest_Validate_MissingCN(t *testing.T) {
	req := &CertificateRequest{
		Subject: Subject{Organization: "Test"},
	}
	err := req.Validate()
	assert.Error(t, err)
}

func TestCertificateRequest_Validate_NegativeValid(t *testing.T) {
	req := &CertificateRequest{
		Subject: Subject{CommonName: "test"},
		Valid:   -1,
	}
	err := req.Validate()
	assert.ErrorIs(t, err, ErrInvalidValidityPeriod)
}
