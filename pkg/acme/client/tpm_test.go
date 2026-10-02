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

package client

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TestCOSEAlgorithmFromSignatureAlgorithm tests COSE algorithm conversion
func TestCOSEAlgorithmFromSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		sigAlgo  x509.SignatureAlgorithm
		expected COSEAlgorithm
	}{
		{
			name:     "ECDSA-SHA256",
			sigAlgo:  x509.ECDSAWithSHA256,
			expected: COSEAlgorithmES256,
		},
		{
			name:     "ECDSA-SHA384",
			sigAlgo:  x509.ECDSAWithSHA384,
			expected: COSEAlgorithmES384,
		},
		{
			name:     "ECDSA-SHA512",
			sigAlgo:  x509.ECDSAWithSHA512,
			expected: COSEAlgorithmES512,
		},
		{
			name:     "RSA-SHA256",
			sigAlgo:  x509.SHA256WithRSA,
			expected: COSEAlgorithmRS256,
		},
		{
			name:     "RSA-SHA384",
			sigAlgo:  x509.SHA384WithRSA,
			expected: COSEAlgorithmRS384,
		},
		{
			name:     "RSA-SHA512",
			sigAlgo:  x509.SHA512WithRSA,
			expected: COSEAlgorithmRS512,
		},
		{
			name:     "RSA-PSS-SHA256",
			sigAlgo:  x509.SHA256WithRSAPSS,
			expected: COSEAlgorithmPS256,
		},
		{
			name:     "RSA-PSS-SHA384",
			sigAlgo:  x509.SHA384WithRSAPSS,
			expected: COSEAlgorithmPS384,
		},
		{
			name:     "RSA-PSS-SHA512",
			sigAlgo:  x509.SHA512WithRSAPSS,
			expected: COSEAlgorithmPS512,
		},
		{
			name:     "Ed25519",
			sigAlgo:  x509.PureEd25519,
			expected: COSEAlgorithmEdDSA,
		},
		{
			name:     "Unknown",
			sigAlgo:  x509.UnknownSignatureAlgorithm,
			expected: COSEAlgorithmUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := COSEAlgorithmFromSignatureAlgorithm(tt.sigAlgo)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// simpleTPM is a simple in-memory TPM mock that implements TPMModule
// for basic unit testing of the TPM interface.
type simpleTPM struct {
	ekKey    crypto.PublicKey
	ekCert   *x509.Certificate
	ekAttrs  *KeyAttributes
	iakAttrs *KeyAttributes
	idevid   *IDevIDCSR
	closeErr error
}

func (s *simpleTPM) EK() crypto.PublicKey {
	if s.ekKey != nil {
		return s.ekKey
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &key.PublicKey
}

func (s *simpleTPM) EKCertificate() (*x509.Certificate, error) {
	if s.ekCert != nil {
		return s.ekCert, nil
	}
	return nil, ErrEKNotFound
}

func (s *simpleTPM) EKAttributes() (*KeyAttributes, error) {
	if s.ekAttrs != nil {
		return s.ekAttrs, nil
	}
	return &KeyAttributes{
		KeyID:              "simple-ek",
		Algorithm:          "RSA-2048",
		SignatureAlgorithm: x509.SHA256WithRSA,
	}, nil
}

func (s *simpleTPM) TPMManufacturer() (string, error) { return testTPMManufacturer, nil }

func (s *simpleTPM) IAKAttributes() (*KeyAttributes, error) {
	if s.iakAttrs != nil {
		return s.iakAttrs, nil
	}
	return &KeyAttributes{
		KeyID:              "simple-iak",
		Algorithm:          "RSA-2048",
		SignatureAlgorithm: x509.SHA256WithRSA,
	}, nil
}

func (s *simpleTPM) CreateIDevID(qualifyingData []byte) (*IDevIDCSR, error) {
	if s.idevid != nil {
		return s.idevid, nil
	}
	return &IDevIDCSR{
		CSR:            []byte("simple-csr"),
		QualifyingData: qualifyingData,
	}, nil
}

func (s *simpleTPM) ActivateCredential(credBlob, encSecret []byte) ([]byte, error) {
	return []byte("simple-activated-secret"), nil
}

func (s *simpleTPM) ProvisionEKCert(certDER []byte) error {
	return nil
}

func (s *simpleTPM) ProvisionIAKCert(cert *x509.Certificate) error {
	return nil
}

// DeviceIdentity implements TPMModule with the fixed test identity.
func (s *simpleTPM) DeviceIdentity() (string, error) { return testDeviceIdentity, nil }

func (s *simpleTPM) CreateAttestedKey(name, keyAuth string) (*AttestedKey, error) {
	return newTestAttestedKey(keyAuth)
}

func (s *simpleTPM) Close() error {
	return s.closeErr
}

// TestSimpleTPM_EK tests the EK method
func TestSimpleTPM_EK(t *testing.T) {
	tpm := &simpleTPM{}
	ek := tpm.EK()
	assert.NotNil(t, ek)
}

// TestSimpleTPM_EKCertificate tests EK certificate retrieval
func TestSimpleTPM_EKCertificate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		expectedCert, _ := createTestCertificate()
		tpm := &simpleTPM{ekCert: expectedCert}
		cert, err := tpm.EKCertificate()
		require.NoError(t, err)
		assert.Equal(t, expectedCert, cert)
	})

	t.Run("not found", func(t *testing.T) {
		tpm := &simpleTPM{}
		_, err := tpm.EKCertificate()
		assert.ErrorIs(t, err, ErrEKNotFound)
	})
}

// TestSimpleTPM_EKAttributes tests EK attributes retrieval
func TestSimpleTPM_EKAttributes(t *testing.T) {
	t.Run("default attributes", func(t *testing.T) {
		tpm := &simpleTPM{}
		attrs, err := tpm.EKAttributes()
		require.NoError(t, err)
		assert.Equal(t, "simple-ek", attrs.KeyID)
		assert.Equal(t, "RSA-2048", attrs.Algorithm)
	})

	t.Run("custom attributes", func(t *testing.T) {
		tpm := &simpleTPM{
			ekAttrs: &KeyAttributes{
				KeyID:     "custom-ek",
				Algorithm: "ECDSA-P256",
			},
		}
		attrs, err := tpm.EKAttributes()
		require.NoError(t, err)
		assert.Equal(t, "custom-ek", attrs.KeyID)
	})
}

// TestSimpleTPM_IAKAttributes tests IAK attributes retrieval
func TestSimpleTPM_IAKAttributes(t *testing.T) {
	tpm := &simpleTPM{}
	attrs, err := tpm.IAKAttributes()
	require.NoError(t, err)
	assert.Equal(t, "simple-iak", attrs.KeyID)
}

// TestSimpleTPM_CreateIDevID tests IDevID creation
func TestSimpleTPM_CreateIDevID(t *testing.T) {
	tpm := &simpleTPM{}
	csr, err := tpm.CreateIDevID([]byte("nonce"))
	require.NoError(t, err)
	assert.Equal(t, []byte("nonce"), csr.QualifyingData)
}

// TestSimpleTPM_ActivateCredential tests credential activation
func TestSimpleTPM_ActivateCredential(t *testing.T) {
	tpm := &simpleTPM{}
	secret, err := tpm.ActivateCredential([]byte("blob"), []byte("enc"))
	require.NoError(t, err)
	assert.Equal(t, []byte("simple-activated-secret"), secret)
}

// TestSimpleTPM_ProvisionEKCert tests EK cert provisioning
func TestSimpleTPM_ProvisionEKCert(t *testing.T) {
	tpm := &simpleTPM{}
	err := tpm.ProvisionEKCert([]byte("cert-data"))
	require.NoError(t, err)
}

// TestSimpleTPM_Close tests closing the TPM
func TestSimpleTPM_Close(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		tpm := &simpleTPM{}
		err := tpm.Close()
		require.NoError(t, err)
	})

	t.Run("error", func(t *testing.T) {
		tpm := &simpleTPM{closeErr: errors.New("close failed")}
		err := tpm.Close()
		assert.Error(t, err)
	})
}

// TestSimpleTPM_InterfaceCompliance ensures simpleTPM implements TPMModule
func TestSimpleTPM_InterfaceCompliance(t *testing.T) {
	var _ TPMModule = (*simpleTPM)(nil)
}

// TestKeyAttributes_Fields tests KeyAttributes struct fields
func TestKeyAttributes_Fields(t *testing.T) {
	attrs := &KeyAttributes{
		KeyID:              "key-id-001",
		Algorithm:          "RSA-2048",
		SignatureAlgorithm: x509.SHA256WithRSA,
		Hash:               crypto.SHA256,
		KeyType:            "TPM",
		TPMHandle:          0x81000002,
		TPMPublicBytes:     []byte("public-bytes"),
	}

	assert.Equal(t, "key-id-001", attrs.KeyID)
	assert.Equal(t, "RSA-2048", attrs.Algorithm)
	assert.Equal(t, x509.SHA256WithRSA, attrs.SignatureAlgorithm)
	assert.Equal(t, crypto.SHA256, attrs.Hash)
	assert.Equal(t, "TPM", attrs.KeyType)
	assert.Equal(t, uint32(0x81000002), attrs.TPMHandle)
	assert.Equal(t, []byte("public-bytes"), attrs.TPMPublicBytes)
}

// TestTPMModule_Interface tests that our mock implements TPMModule
func TestTPMModule_Interface(t *testing.T) {
	mock := &mockTPM{}

	// Test that mock implements TPMModule interface
	var _ TPMModule = mock

	// Test interface methods - default mock returns non-nil EK
	assert.NotNil(t, mock.EK())
	_, err := mock.EKCertificate()
	assert.NoError(t, err)
	_, err = mock.EKAttributes()
	assert.NoError(t, err)
	_, err = mock.IAKAttributes()
	assert.NoError(t, err)
	_, err = mock.CreateIDevID(nil)
	assert.NoError(t, err)
	_, err = mock.ActivateCredential(nil, nil)
	assert.NoError(t, err)
	err = mock.ProvisionEKCert(nil)
	assert.NoError(t, err)
	_, err = mock.CreateAttestedKey("device", "key-auth")
	assert.NoError(t, err)
	err = mock.Close()
	assert.NoError(t, err)
}

// TestMockTPM_AllMethods tests the functional mock TPM with all methods configured
func TestMockTPM_AllMethods(t *testing.T) {
	ekKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ekCert, _ := createTestCertificate()
	iakCert, _ := createTestCertificate()

	mock := &mockTPM{
		ekFunc: func() crypto.PublicKey {
			return &ekKey.PublicKey
		},
		ekCertFunc: func() (*x509.Certificate, error) {
			return ekCert, nil
		},
		ekAttributesFunc: func() (*KeyAttributes, error) {
			return &KeyAttributes{
				KeyID:     "ek-001",
				Algorithm: "RSA-2048",
			}, nil
		},
		iakAttributesFunc: func() (*KeyAttributes, error) {
			return &KeyAttributes{
				KeyID:              "iak-001",
				Algorithm:          "RSA-2048",
				SignatureAlgorithm: x509.SHA256WithRSAPSS,
			}, nil
		},
		createIDevIDFunc: func(qualifyingData []byte) (*IDevIDCSR, error) {
			return &IDevIDCSR{
				CSR:            []byte("idevid-csr"),
				EKCert:         ekCert,
				QualifyingData: qualifyingData,
			}, nil
		},
		activateCredentialFunc: func(credBlob, secret []byte) ([]byte, error) {
			return []byte("activated-secret"), nil
		},
		attestFunc: func(name, keyAuth string) (*AttestedKey, error) {
			assert.Equal(t, "device", name)
			return newTestAttestedKey(keyAuth)
		},
	}

	// Test EK
	ek := mock.EK()
	assert.NotNil(t, ek)

	// Test EKCertificate
	cert, err := mock.EKCertificate()
	assert.NoError(t, err)
	assert.NotNil(t, cert)

	// Test EKAttributes
	ekAttrs, err := mock.EKAttributes()
	assert.NoError(t, err)
	assert.Equal(t, "ek-001", ekAttrs.KeyID)

	// Test IAKAttributes
	iakAttrs, err := mock.IAKAttributes()
	assert.NoError(t, err)
	assert.Equal(t, "iak-001", iakAttrs.KeyID)

	// Test CreateIDevID
	csr, err := mock.CreateIDevID([]byte("qualifying-data"))
	assert.NoError(t, err)
	assert.Equal(t, []byte("qualifying-data"), csr.QualifyingData)

	// Test ActivateCredential
	activated, err := mock.ActivateCredential([]byte("cred"), []byte("enc"))
	assert.NoError(t, err)
	assert.Equal(t, []byte("activated-secret"), activated)

	// Test CreateAttestedKey
	attested, err := mock.CreateAttestedKey("device", "key-auth")
	assert.NoError(t, err)
	assert.NotNil(t, attested.Signer)

	// Suppress unused variable warning
	_ = iakCert
}

// TestIDevIDCSR_StructFields tests IDevIDCSR struct field population
func TestIDevIDCSR_StructFields(t *testing.T) {
	cert, _ := createTestCertificate()

	csr := &IDevIDCSR{
		CSR:                []byte("idevid-csr-data"),
		IAKPublic:          []byte("iak-public-key"),
		IDevIDPublic:       []byte("idevid-public-key"),
		EKCert:             cert,
		QualifyingData:     []byte("qualifying-data"),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		CertifyInfo:        []byte("certify-info"),
		Signature:          []byte("csr-signature"),
	}

	assert.NotNil(t, csr.EKCert)
	assert.Equal(t, "Test EK Certificate", csr.EKCert.Subject.CommonName)
	assert.Equal(t, x509.ECDSAWithSHA256, csr.SignatureAlgorithm)
	assert.Equal(t, []byte("certify-info"), csr.CertifyInfo)
}

// TestEnrollmentResult_IAKCertificate tests EnrollmentResult IAK certificate field
func TestEnrollmentResult_IAKCertificate(t *testing.T) {
	iakCert, _ := createTestCertificate()

	result := &EnrollmentResult{
		IAKCertificate: iakCert,
	}

	assert.NotNil(t, result.IAKCertificate)
	assert.Equal(t, "Test EK Certificate", result.IAKCertificate.Subject.CommonName)
}

// =====================================
// Tests from tpm_adapter_unit_test.go
// =====================================

type mockXKMSTPM struct {
	// Fixed properties configuration
	fixedProps      *xkmssdk.PropertiesFixed
	fixedPropsError error

	// EK configuration
	ekPublicKey  crypto.PublicKey
	ekCert       *x509.Certificate
	ekAttrs      *xkmssdk.KeyAttributes
	ekError      error
	ekCertError  error
	ekAttrsError error

	// IAK configuration
	iakPublicKey  crypto.PublicKey
	iakAttrs      *xkmssdk.KeyAttributes
	iakError      error
	iakAttrsError error

	// IDevID configuration
	idevidAttrs            *xkmssdk.KeyAttributes
	idevidCSR              *xkmssdk.TCG_CSR_IDEVID
	idevidError            error
	receivedQualifyingData []byte // captures what CreateIDevID was called with

	// ActivateCredential configuration
	activateSecret []byte
	activateError  error

	// ProvisionEKCert configuration
	provisionError error

	// ProvisionIAKCert configuration
	provisionIAKError  error
	provisionedIAKCert *x509.Certificate

	// ParseEKCertificate configuration
	parsedEKCert *x509.Certificate
	parseError   error

	// Quote configuration
	quote      xkmssdk.Quote
	quoteError error

	// Platform SRK configuration
	platformSRKError error

	// Config
	config *xkmssdk.TPMConfig

	// Close configuration
	closeError error
}

// Implement all TrustedPlatformModule interface methods

func (m *mockXKMSTPM) ActivateCredential(credentialBlob, encryptedSecret []byte) ([]byte, error) {
	if m.activateError != nil {
		return nil, m.activateError
	}
	return m.activateSecret, nil
}

func (m *mockXKMSTPM) AnswerCredentialChallenge(key *xkmssdk.ActivationKey, challenge *xkmssdk.CredentialChallenge) ([]byte, error) {
	return nil, nil
}

func (m *mockXKMSTPM) ClearForReprovision() (bool, error) { return false, nil }

func (m *mockXKMSTPM) CreateActivationKey() (*xkmssdk.ActivationKey, error) { return nil, nil }

func (m *mockXKMSTPM) State() (*xkmssdk.ProvisioningState, error) { return nil, nil }

func (m *mockXKMSTPM) AKProfile() (xkmssdk.AKProfile, error) {
	return xkmssdk.AKProfile{}, nil
}

func (m *mockXKMSTPM) AlgID() tpm2.TPMAlgID {
	return tpm2.TPMAlgSHA256
}

func (m *mockXKMSTPM) CalculateName(algID tpm2.TPMAlgID, publicArea []byte) {}

func (m *mockXKMSTPM) Clear(lockoutAuth []byte) error {
	return nil
}

func (m *mockXKMSTPM) Close() error {
	return m.closeError
}

func (m *mockXKMSTPM) FactoryReset(ownerAuth []byte) error {
	return nil
}

func (m *mockXKMSTPM) FactoryResetWithClear(ownerAuth []byte) error {
	return nil
}

func (m *mockXKMSTPM) ForceClear() error {
	return nil
}

func (m *mockXKMSTPM) Config() *xkmssdk.TPMConfig {
	return m.config
}

func (m *mockXKMSTPM) CreateECDSA(keyAttrs *xkmssdk.KeyAttributes, backend xkmssdk.TPMKeyBackend, overwrite bool) (*ecdsa.PublicKey, error) {
	return nil, nil
}

func (m *mockXKMSTPM) CreateEK(keyAttrs *xkmssdk.KeyAttributes) error {
	return nil
}

func (m *mockXKMSTPM) CreateSecretKey(keyAttrs *xkmssdk.KeyAttributes, backend xkmssdk.TPMKeyBackend) error {
	return nil
}

func (m *mockXKMSTPM) CreateIAK(ekAttrs *xkmssdk.KeyAttributes, qualifyingData []byte) (*xkmssdk.KeyAttributes, error) {
	if m.iakError != nil {
		return nil, m.iakError
	}
	return m.iakAttrs, nil
}

func (m *mockXKMSTPM) CreateIDevID(akAttrs *xkmssdk.KeyAttributes, ekCert *x509.Certificate, qualifyingData []byte) (*xkmssdk.KeyAttributes, *xkmssdk.TCG_CSR_IDEVID, error) {
	m.receivedQualifyingData = qualifyingData
	if m.idevidError != nil {
		return nil, nil, m.idevidError
	}
	return m.idevidAttrs, m.idevidCSR, nil
}

func (m *mockXKMSTPM) CreatePlatformPolicy() error {
	return nil
}

func (m *mockXKMSTPM) CreateRSA(keyAttrs *xkmssdk.KeyAttributes, backend xkmssdk.TPMKeyBackend, overwrite bool) (*rsa.PublicKey, error) {
	return nil, nil
}

func (m *mockXKMSTPM) CreateKeySession(keyAttrs *xkmssdk.KeyAttributes) (tpm2.Session, func() error, error) {
	return nil, func() error { return nil }, nil
}

func (m *mockXKMSTPM) CreateSession(keyAttrs *xkmssdk.KeyAttributes) (tpm2.Session, func() error, error) {
	return nil, func() error { return nil }, nil
}

func (m *mockXKMSTPM) CreateSRK(keyAttrs *xkmssdk.KeyAttributes) error {
	return nil
}

func (m *mockXKMSTPM) CreateTCG_CSR_IDEVID(ekCert *x509.Certificate, akAttrs *xkmssdk.KeyAttributes, idevidAttrs *xkmssdk.KeyAttributes) (xkmssdk.TCG_CSR_IDEVID, error) {
	return xkmssdk.TCG_CSR_IDEVID{}, nil
}

func (m *mockXKMSTPM) DeleteKey(keyAttrs *xkmssdk.KeyAttributes, backend xkmssdk.TPMKeyBackend) error {
	return nil
}

func (m *mockXKMSTPM) Device() string {
	return "/dev/tpmrm0"
}

func (m *mockXKMSTPM) EK() (crypto.PublicKey, error) {
	if m.ekError != nil {
		return nil, m.ekError
	}
	return m.ekPublicKey, nil
}

func (m *mockXKMSTPM) EKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, nil
}

func (m *mockXKMSTPM) EKAttributes() (*xkmssdk.KeyAttributes, error) {
	if m.ekAttrsError != nil {
		return nil, m.ekAttrsError
	}
	return m.ekAttrs, nil
}

func (m *mockXKMSTPM) EKCertificate() (*x509.Certificate, error) {
	if m.ekCertError != nil {
		return nil, m.ekCertError
	}
	return m.ekCert, nil
}

func (m *mockXKMSTPM) EKCertificateRSA() (*x509.Certificate, error) {
	return nil, nil
}

func (m *mockXKMSTPM) EKCertificateEC() (*x509.Certificate, error) {
	return nil, nil
}

func (m *mockXKMSTPM) EKECC() (*ecdsa.PublicKey, error) {
	if pk, ok := m.ekPublicKey.(*ecdsa.PublicKey); ok {
		return pk, nil
	}
	return nil, nil
}

func (m *mockXKMSTPM) EKRSA() (*rsa.PublicKey, error) {
	if pk, ok := m.ekPublicKey.(*rsa.PublicKey); ok {
		return pk, nil
	}
	return nil, nil
}

func (m *mockXKMSTPM) EventLog() ([]byte, error) {
	return nil, nil
}

func (m *mockXKMSTPM) FixedProperties() (*xkmssdk.PropertiesFixed, error) {
	return m.fixedProps, m.fixedPropsError
}

func (m *mockXKMSTPM) Flush(handle tpm2.TPMHandle) {}

func (m *mockXKMSTPM) GoldenMeasurements() ([]byte, error) {
	return nil, nil
}

func (m *mockXKMSTPM) HMACSaltedSession(handle tpm2.TPMHandle, pub tpm2.TPMTPublic, auth []byte) (tpm2.Session, func() error, error) {
	return nil, func() error { return nil }, nil
}

func (m *mockXKMSTPM) HMACSession(auth []byte) (tpm2.Session, func() error, error) {
	return nil, func() error { return nil }, nil
}

func (m *mockXKMSTPM) IAK() (crypto.PublicKey, error) {
	return m.iakPublicKey, nil
}

func (m *mockXKMSTPM) IAKAttributes() (*xkmssdk.KeyAttributes, error) {
	if m.iakAttrsError != nil {
		return nil, m.iakAttrsError
	}
	return m.iakAttrs, nil
}

func (m *mockXKMSTPM) IDevID() (crypto.PublicKey, error) {
	return nil, nil
}

func (m *mockXKMSTPM) IDevIDAttributes() (*xkmssdk.KeyAttributes, error) {
	return m.idevidAttrs, nil
}

func (m *mockXKMSTPM) Info() (string, error) {
	return "Mock TPM", nil
}

func (m *mockXKMSTPM) IsFIPS140_2() (bool, error) {
	return false, nil
}

func (m *mockXKMSTPM) IsPlatformPCRExtended() (bool, error) {
	return false, nil
}

func (m *mockXKMSTPM) ExtendPCR(pcrIndex int, hashAlg string, data []byte) error {
	return nil
}

func (m *mockXKMSTPM) Install(soPIN xkmssdk.Password, opts *xkmssdk.InstallOptions) error {
	return nil
}

func (m *mockXKMSTPM) KeyAttributes(handle tpm2.TPMHandle) (*xkmssdk.KeyAttributes, error) {
	return nil, nil
}

func (m *mockXKMSTPM) LoadKeyPair(keyAttrs *xkmssdk.KeyAttributes, session *tpm2.Session, backend xkmssdk.TPMKeyBackend) (*tpm2.LoadResponse, error) {
	return nil, nil
}

func (m *mockXKMSTPM) MakeCredential(akName tpm2.TPM2BName, secret []byte) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, nil
}

func (m *mockXKMSTPM) MakeCredentialWithExternalEK(ekCert *x509.Certificate, iakPubBytes []byte, secret []byte) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, nil
}

func (m *mockXKMSTPM) NonceSession(secret xkmssdk.Password) (tpm2.Session, func() error, error) {
	return nil, func() error { return nil }, nil
}

func (m *mockXKMSTPM) NVRead(keyAttrs *xkmssdk.KeyAttributes, dataSize uint16) ([]byte, error) {
	return nil, nil
}

func (m *mockXKMSTPM) NVWrite(keyAttrs *xkmssdk.KeyAttributes) error {
	return nil
}

func (m *mockXKMSTPM) Open() error {
	return nil
}

func (m *mockXKMSTPM) ParseEKCertificate(ekCert []byte) (*x509.Certificate, error) {
	if m.parseError != nil {
		return nil, m.parseError
	}
	return m.parsedEKCert, nil
}

func (m *mockXKMSTPM) ParsedEventLog() ([]xkmssdk.TPMEvent, error) {
	return nil, nil
}

func (m *mockXKMSTPM) ParsePublicKey(tpm2BPublic []byte) (crypto.PublicKey, error) {
	return nil, nil
}

func (m *mockXKMSTPM) PlatformPolicyDigestHash() ([]byte, error) {
	return nil, nil
}

func (m *mockXKMSTPM) PlatformPolicyDigest() (tpm2.TPM2BDigest, error) {
	return tpm2.TPM2BDigest{}, nil
}

func (m *mockXKMSTPM) PlatformPolicySession(nonce []byte) (tpm2.Session, func() error, error) {
	return nil, func() error { return nil }, nil
}

func (m *mockXKMSTPM) PlatformQuote(keyAttrs *xkmssdk.KeyAttributes) (xkmssdk.Quote, []byte, error) {
	return xkmssdk.Quote{}, nil, nil
}

func (m *mockXKMSTPM) Provision(soPIN xkmssdk.Password) error {
	return nil
}

func (m *mockXKMSTPM) ProvisionEKCert(hierarchyAuth, ekCert []byte) error {
	return m.provisionError
}

func (m *mockXKMSTPM) ProvisionOwner(hierarchyAuth xkmssdk.Password) (*xkmssdk.KeyAttributes, error) {
	return nil, nil
}

func (m *mockXKMSTPM) Quote(pcrs []uint, nonce []byte) (xkmssdk.Quote, error) {
	if m.quoteError != nil {
		return xkmssdk.Quote{}, m.quoteError
	}
	return m.quote, nil
}

func (m *mockXKMSTPM) CertifyKey(keyAttrs *xkmssdk.KeyAttributes, nonce []byte, backend xkmssdk.TPMKeyBackend) (*xkmssdk.CertifyResult, error) {
	return nil, nil
}

func (m *mockXKMSTPM) Random() ([]byte, error) {
	return nil, nil
}

func (m *mockXKMSTPM) RandomBytes(fixedLength int) ([]byte, error) {
	return nil, nil
}

func (m *mockXKMSTPM) RandomHex(fixedLength int) ([]byte, error) {
	return nil, nil
}

func (m *mockXKMSTPM) RandomSource() io.Reader {
	return rand.Reader
}

func (m *mockXKMSTPM) Read(data []byte) (n int, err error) {
	return rand.Read(data)
}

func (m *mockXKMSTPM) ReadHandle(handle tpm2.TPMHandle) (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, nil
}

func (m *mockXKMSTPM) ReadPCRs(pcrList []uint) ([]xkmssdk.PCRBank, error) {
	return nil, nil
}

func (m *mockXKMSTPM) RSADecrypt(keyAttrs *xkmssdk.KeyAttributes, backend xkmssdk.TPMKeyBackend, blob []byte) ([]byte, error) {
	return nil, nil
}

func (m *mockXKMSTPM) RSAEncrypt(handle tpm2.TPMHandle, name tpm2.TPM2BName, message []byte) ([]byte, error) {
	return nil, nil
}

func (m *mockXKMSTPM) SaveKeyPair(keyAttrs *xkmssdk.KeyAttributes, outPrivate tpm2.TPM2BPrivate, outPublic tpm2.TPM2B[tpm2.TPMTPublic, *tpm2.TPMTPublic], backend xkmssdk.TPMKeyBackend, overwrite bool) error {
	return nil
}

func (m *mockXKMSTPM) Seal(ctx context.Context, data []byte, opts *xkmssdk.SealOptions) (*xkmssdk.SealedData, error) {
	return nil, nil
}

func (m *mockXKMSTPM) SealKey(keyAttrs *xkmssdk.KeyAttributes, backend xkmssdk.TPMKeyBackend, overwrite bool) (*tpm2.CreateResponse, error) {
	return nil, nil
}

func (m *mockXKMSTPM) Sign(randReader io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func (m *mockXKMSTPM) SetHierarchyAuth(oldSecret, newSecret xkmssdk.Password, hierarchy *tpm2.TPMHandle) error {
	return nil
}

func (m *mockXKMSTPM) SecretFromShares(shares []string) (string, error) {
	return "", nil
}

func (m *mockXKMSTPM) ShareSecret(secret []byte, shares int) ([]string, error) {
	return nil, nil
}

func (m *mockXKMSTPM) VerifyAuth(handle tpm2.TPMHandle, authValue []byte) error {
	return nil
}

func (m *mockXKMSTPM) ChangeAuth(handle tpm2.TPMHandle, currentAuth, newAuth []byte) error {
	return nil
}

func (m *mockXKMSTPM) SRKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, nil
}

func (m *mockXKMSTPM) SSRKAttributes() (*xkmssdk.KeyAttributes, error) {
	return nil, nil
}

func (m *mockXKMSTPM) SSRK() *xkmssdk.SRKConfig {
	return nil
}

func (m *mockXKMSTPM) PlatformKeyStore() xkmssdk.PlatformKeyStorer {
	return nil
}

func (m *mockXKMSTPM) SupportedAlgorithms() ([]string, error) {
	return nil, nil
}

func (m *mockXKMSTPM) SupportedCommands() ([]string, error) {
	return nil, nil
}

func (m *mockXKMSTPM) SupportedECCCurves() ([]string, error) {
	return nil, nil
}

func (m *mockXKMSTPM) Transport() transport.TPM {
	return nil
}

func (m *mockXKMSTPM) Unseal(ctx context.Context, sealed *xkmssdk.SealedData, opts *xkmssdk.UnsealOptions) ([]byte, error) {
	return nil, nil
}

func (m *mockXKMSTPM) UnsealKey(keyAttrs *xkmssdk.KeyAttributes, backend xkmssdk.TPMKeyBackend) ([]byte, error) {
	return nil, nil
}

func (m *mockXKMSTPM) CanSeal() bool {
	return true
}

func (m *mockXKMSTPM) WriteEKCert(ekCert []byte) error {
	return nil
}

// IDevID/IAK Certificate management methods
func (m *mockXKMSTPM) IDevIDCertificate() (*x509.Certificate, error) {
	return nil, nil
}

func (m *mockXKMSTPM) ProvisionIDevIDCert(cert *x509.Certificate) error {
	return nil
}

func (m *mockXKMSTPM) DeleteIDevIDCertificate() error {
	return nil
}

func (m *mockXKMSTPM) IAKCertificate() (*x509.Certificate, error) {
	return nil, nil
}

func (m *mockXKMSTPM) ProvisionIAKCert(cert *x509.Certificate) error {
	if m.provisionIAKError != nil {
		return m.provisionIAKError
	}
	m.provisionedIAKCert = cert
	return nil
}

func (m *mockXKMSTPM) DeleteIAKCertificate() error {
	return nil
}

func (m *mockXKMSTPM) CreateLAK(_ xkmssdk.Password, _ xkmssdk.TPMKeyBackend, _ bool) (*xkmssdk.KeyAttributes, error) {
	return nil, nil
}

func (m *mockXKMSTPM) LAKAttributes() (*xkmssdk.KeyAttributes, error) {
	return nil, nil
}

func (m *mockXKMSTPM) LAK() (crypto.PublicKey, error) {
	return nil, nil
}

func (m *mockXKMSTPM) CertifyLAK(_ []byte, _ xkmssdk.TPMKeyBackend) (*xkmssdk.CertifyResult, error) {
	return nil, nil
}

func (m *mockXKMSTPM) CertifyKeyWithLAK(_ *xkmssdk.KeyAttributes, _ []byte, _ xkmssdk.TPMKeyBackend) (*xkmssdk.CertifyResult, error) {
	return nil, nil
}

func (m *mockXKMSTPM) LAKCertificate() (*x509.Certificate, error) {
	return nil, nil
}

func (m *mockXKMSTPM) ProvisionLAKCert(cert *x509.Certificate) error {
	return nil
}

func (m *mockXKMSTPM) DeleteLAKCertificate() error {
	return nil
}

// NV space methods
func (m *mockXKMSTPM) NVDefineCounter(keyAttrs *xkmssdk.KeyAttributes) error {
	return nil
}

func (m *mockXKMSTPM) NVDefineExtend(keyAttrs *xkmssdk.KeyAttributes) error {
	return nil
}

func (m *mockXKMSTPM) NVIncrement(keyAttrs *xkmssdk.KeyAttributes) (uint64, error) {
	return 0, nil
}

func (m *mockXKMSTPM) NVExtend(keyAttrs *xkmssdk.KeyAttributes, data []byte) error {
	return nil
}

func (m *mockXKMSTPM) NVReadCounter(keyAttrs *xkmssdk.KeyAttributes) (uint64, error) {
	return 0, nil
}

func (m *mockXKMSTPM) NVReadExtend(keyAttrs *xkmssdk.KeyAttributes) ([]byte, error) {
	return nil, nil
}

func (m *mockXKMSTPM) NVUndefine(keyAttrs *xkmssdk.KeyAttributes) error {
	return nil
}

func (m *mockXKMSTPM) VerifyTCGCSR(csr *xkmssdk.TCG_CSR_IDEVID, sigAlgo x509.SignatureAlgorithm) (*xkmssdk.KeyAttributes, *xkmssdk.UNPACKED_TCG_CSR_IDEVID, error) {
	return nil, nil, nil
}

func (m *mockXKMSTPM) VerifyTCG_CSR_IAK(csr *xkmssdk.TCG_CSR_IDEVID, sigAlgo x509.SignatureAlgorithm) (*xkmssdk.KeyAttributes, *xkmssdk.UNPACKED_TCG_CSR_IDEVID, error) {
	return nil, nil, nil
}

func (m *mockXKMSTPM) VerifyTCG_CSR_IDevID(csr *xkmssdk.TCG_CSR_IDEVID, signatureAlgorithm x509.SignatureAlgorithm) (*xkmssdk.KeyAttributes, *xkmssdk.UNPACKED_TCG_CSR_IDEVID, error) {
	return nil, nil, nil
}

func (m *mockXKMSTPM) GenerateSymmetricKey(attrs *xkmssdk.KeyAttributes) (xkmssdk.SymmetricKey, error) {
	return nil, nil
}

func (m *mockXKMSTPM) GetSymmetricKey(attrs *xkmssdk.KeyAttributes) (xkmssdk.SymmetricKey, error) {
	return nil, nil
}

func (m *mockXKMSTPM) SymmetricEncrypter(attrs *xkmssdk.KeyAttributes) (xkmssdk.SymmetricEncrypter, error) {
	return nil, nil
}

func (m *mockXKMSTPM) SignValidate(keyAttrs *xkmssdk.KeyAttributes, digest, validationDigest []byte) ([]byte, error) {
	return nil, nil
}

func (m *mockXKMSTPM) HashSequence(keyAttrs *xkmssdk.KeyAttributes, data []byte) ([]byte, []byte, error) {
	return nil, nil, nil
}

func (m *mockXKMSTPM) Hash(keyAttrs *xkmssdk.KeyAttributes, data []byte) ([]byte, []byte, error) {
	return nil, nil, nil
}

func (m *mockXKMSTPM) ECDHZGen(keyAttrs *xkmssdk.KeyAttributes, peerPublicKey *tpm2.TPMSECCPoint, backend xkmssdk.TPMKeyBackend) ([]byte, error) {
	return nil, nil
}

// Handle enumeration methods
func (m *mockXKMSTPM) ListPersistentHandles() ([]tpm2.TPMHandle, error) {
	return nil, nil
}

func (m *mockXKMSTPM) ListTransientHandles() ([]tpm2.TPMHandle, error) {
	return nil, nil
}

// NV index enumeration
func (m *mockXKMSTPM) ListNVIndexes() ([]xkmssdk.NVIndexInfo, error) {
	return nil, nil
}

// Dictionary attack lockout management
func (m *mockXKMSTPM) DictionaryAttackLockoutReset(lockoutAuth []byte) error {
	return nil
}

func (m *mockXKMSTPM) PlatformSRKAttributes() (*xkmssdk.KeyAttributes, error) {
	return nil, m.platformSRKError
}

// Helper functions for creating test data

func newTestECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func newTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

func newTestCertificateFromPublicKey(t *testing.T, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test EK Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Self-sign the certificate
	var certDER []byte
	var err error

	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		privKey, _ := ecdsa.GenerateKey(key.Curve, rand.Reader)
		certDER, err = x509.CreateCertificate(rand.Reader, template, template, pub, privKey)
	case *rsa.PublicKey:
		privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		certDER, err = x509.CreateCertificate(rand.Reader, template, template, pub, privKey)
	default:
		t.Fatalf("unsupported key type: %T", pub)
	}

	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

// Tests for XKMSTPMAdapter methods

func TestNewXKMSTPMAdapter(t *testing.T) {
	mockTPM := &mockXKMSTPM{}
	adapter := NewXKMSTPMAdapter(mockTPM, nil)

	assert.NotNil(t, adapter)
	assert.NotNil(t, adapter.tpm)
	assert.Nil(t, adapter.ekAttrs)
	assert.Nil(t, adapter.iakAttrs)
	assert.Nil(t, adapter.ekCert)
}

func TestXKMSTPMAdapter_EK(t *testing.T) {
	t.Run("returns ECDSA public key", func(t *testing.T) {
		ecKey := newTestECDSAKey(t)
		mockTPM := &mockXKMSTPM{
			ekPublicKey: &ecKey.PublicKey,
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		result := adapter.EK()

		require.NotNil(t, result)
		ecdsaKey, ok := result.(*ecdsa.PublicKey)
		assert.True(t, ok)
		assert.Equal(t, &ecKey.PublicKey, ecdsaKey)
	})

	t.Run("returns RSA public key", func(t *testing.T) {
		rsaKey := newTestRSAKey(t)
		mockTPM := &mockXKMSTPM{
			ekPublicKey: &rsaKey.PublicKey,
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		result := adapter.EK()

		require.NotNil(t, result)
		rsaPubKey, ok := result.(*rsa.PublicKey)
		assert.True(t, ok)
		assert.Equal(t, &rsaKey.PublicKey, rsaPubKey)
	})

	t.Run("returns nil when no EK", func(t *testing.T) {
		mockTPM := &mockXKMSTPM{
			ekPublicKey: nil,
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		result := adapter.EK()
		assert.Nil(t, result)
	})

	t.Run("returns nil when underlying TPM errors", func(t *testing.T) {
		ecKey := newTestECDSAKey(t)
		mockTPM := &mockXKMSTPM{
			// Even with a public key configured, an error from the
			// underlying TPM must make EK() return nil rather than the key.
			ekPublicKey: &ecKey.PublicKey,
			ekError:     errors.New("tpm communication failure"),
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		result := adapter.EK()
		assert.Nil(t, result)
	})
}

func TestXKMSTPMAdapter_EKCertificate(t *testing.T) {
	t.Run("returns certificate successfully", func(t *testing.T) {
		ecKey := newTestECDSAKey(t)
		cert := newTestCertificateFromPublicKey(t, &ecKey.PublicKey)
		mockTPM := &mockXKMSTPM{
			ekCert: cert,
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		result, err := adapter.EKCertificate()

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, cert, result)
	})

	t.Run("caches certificate after first retrieval", func(t *testing.T) {
		ecKey := newTestECDSAKey(t)
		cert := newTestCertificateFromPublicKey(t, &ecKey.PublicKey)
		mockTPM := &mockXKMSTPM{
			ekCert: cert,
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		// First call
		result1, err := adapter.EKCertificate()
		require.NoError(t, err)

		// Modify mock to return different cert
		ecKey2 := newTestECDSAKey(t)
		cert2 := newTestCertificateFromPublicKey(t, &ecKey2.PublicKey)
		mockTPM.ekCert = cert2

		// Second call should return cached cert
		result2, err := adapter.EKCertificate()
		require.NoError(t, err)

		assert.Equal(t, result1, result2)
		assert.NotEqual(t, cert2, result2)
	})

	t.Run("returns error when certificate not found", func(t *testing.T) {
		mockTPM := &mockXKMSTPM{
			ekCertError: errors.New("certificate not found in NVRAM"),
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		result, err := adapter.EKCertificate()

		require.Error(t, err)
		assert.Nil(t, result)
		var caErr *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, caerrors.NotFound, caErr.Type)
		assert.Contains(t, err.Error(), "certificate not found in NVRAM")
	})
}

func TestXKMSTPMAdapter_EKAttributes(t *testing.T) {
	t.Run("returns attributes successfully for ECDSA key", func(t *testing.T) {
		ecKey := newTestECDSAKey(t)
		attrs := &xkmssdk.KeyAttributes{
			CN:                 "ek-key",
			KeyAlgorithm:       x509.ECDSA,
			SignatureAlgorithm: x509.ECDSAWithSHA256,
			Hash:               crypto.SHA256,
			KeyType:            xkmssdk.KeyTypeEndorsement,
			ECCAttributes: &xkmssdk.ECCAttributes{
				Curve: elliptic.P256(),
			},
			TPMAttributes: &xkmssdk.TPMAttributes{
				Handle:         0x81010001,
				PublicKeyBytes: []byte("tpm-public-bytes"),
			},
		}
		mockTPM := &mockXKMSTPM{
			ekAttrs:     attrs,
			ekPublicKey: &ecKey.PublicKey,
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		result, err := adapter.EKAttributes()

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "ek-key", result.KeyID)
		assert.Contains(t, result.Algorithm, "ECDSA")
		assert.Contains(t, result.Algorithm, "P-256")
		assert.Equal(t, x509.ECDSAWithSHA256, result.SignatureAlgorithm)
		assert.Equal(t, crypto.SHA256, result.Hash)
		assert.Equal(t, uint32(0x81010001), result.TPMHandle)
		assert.Equal(t, []byte("tpm-public-bytes"), result.TPMPublicBytes)
	})

	t.Run("returns attributes successfully for RSA key", func(t *testing.T) {
		rsaKey := newTestRSAKey(t)
		attrs := &xkmssdk.KeyAttributes{
			CN:                 "ek-rsa-key",
			KeyAlgorithm:       x509.RSA,
			SignatureAlgorithm: x509.SHA256WithRSA,
			Hash:               crypto.SHA256,
			KeyType:            xkmssdk.KeyTypeEndorsement,
			RSAAttributes: &xkmssdk.RSAAttributes{
				KeySize: 2048,
			},
			TPMAttributes: &xkmssdk.TPMAttributes{
				Handle: 0x81010002,
			},
		}
		mockTPM := &mockXKMSTPM{
			ekAttrs:     attrs,
			ekPublicKey: &rsaKey.PublicKey,
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		result, err := adapter.EKAttributes()

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "ek-rsa-key", result.KeyID)
		assert.Equal(t, "RSA-2048", result.Algorithm)
		assert.Equal(t, x509.SHA256WithRSA, result.SignatureAlgorithm)
	})

	t.Run("caches attributes after first retrieval", func(t *testing.T) {
		attrs := &xkmssdk.KeyAttributes{
			CN:           "ek-key",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      xkmssdk.KeyTypeEndorsement,
		}
		mockTPM := &mockXKMSTPM{
			ekAttrs: attrs,
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		// First call
		result1, err := adapter.EKAttributes()
		require.NoError(t, err)

		// Modify mock
		mockTPM.ekAttrs = &xkmssdk.KeyAttributes{
			CN:           "different-key",
			KeyAlgorithm: x509.RSA,
		}

		// Second call should return cached
		result2, err := adapter.EKAttributes()
		require.NoError(t, err)

		assert.Equal(t, result1.KeyID, result2.KeyID)
	})

	t.Run("returns error when EK not available", func(t *testing.T) {
		mockTPM := &mockXKMSTPM{
			ekAttrsError: errors.New("EK not provisioned"),
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		result, err := adapter.EKAttributes()

		require.Error(t, err)
		assert.Nil(t, result)
		var caErr *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, caerrors.NotFound, caErr.Type)
	})
}

func TestXKMSTPMAdapter_IAKAttributes(t *testing.T) {
	t.Run("returns attributes successfully", func(t *testing.T) {
		ecKey := newTestECDSAKey(t)
		attrs := &xkmssdk.KeyAttributes{
			CN:                 "iak-key",
			KeyAlgorithm:       x509.ECDSA,
			SignatureAlgorithm: x509.ECDSAWithSHA256,
			Hash:               crypto.SHA256,
			KeyType:            xkmssdk.KeyTypeAttestation,
			ECCAttributes: &xkmssdk.ECCAttributes{
				Curve: elliptic.P256(),
			},
			TPMAttributes: &xkmssdk.TPMAttributes{
				Handle:         0x81010003,
				PublicKeyBytes: []byte("iak-public-bytes"),
				CertifyInfo:    []byte("certify-info"),
				Signature:      []byte("signature"),
			},
		}
		mockTPM := &mockXKMSTPM{
			iakAttrs:     attrs,
			iakPublicKey: &ecKey.PublicKey,
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		result, err := adapter.IAKAttributes()

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "iak-key", result.KeyID)
		assert.Contains(t, result.Algorithm, "ECDSA")
		assert.Equal(t, x509.ECDSAWithSHA256, result.SignatureAlgorithm)
		assert.Equal(t, uint32(0x81010003), result.TPMHandle)
	})

	t.Run("caches attributes", func(t *testing.T) {
		attrs := &xkmssdk.KeyAttributes{
			CN:           "iak-key",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      xkmssdk.KeyTypeAttestation,
		}
		mockTPM := &mockXKMSTPM{
			iakAttrs: attrs,
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		result1, _ := adapter.IAKAttributes()

		mockTPM.iakAttrs = &xkmssdk.KeyAttributes{CN: "different"}
		result2, _ := adapter.IAKAttributes()

		assert.Equal(t, result1.KeyID, result2.KeyID)
	})

	t.Run("returns error when IAK not available", func(t *testing.T) {
		mockTPM := &mockXKMSTPM{
			iakAttrsError: errors.New("IAK not created"),
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		result, err := adapter.IAKAttributes()

		require.Error(t, err)
		assert.Nil(t, result)
		var caErr *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, caerrors.NotFound, caErr.Type)
	})
}

func TestXKMSTPMAdapter_CreateIDevID(t *testing.T) {
	t.Run("creates IDevID successfully", func(t *testing.T) {
		ecKey := newTestECDSAKey(t)
		ekCert := newTestCertificateFromPublicKey(t, &ecKey.PublicKey)

		iakAttrs := &xkmssdk.KeyAttributes{
			CN:                 "iak-key",
			KeyAlgorithm:       x509.ECDSA,
			SignatureAlgorithm: x509.ECDSAWithSHA256,
			KeyType:            xkmssdk.KeyTypeAttestation,
			TPMAttributes: &xkmssdk.TPMAttributes{
				PublicKeyBytes: []byte("iak-public"),
				CertifyInfo:    []byte("certify-info"),
				Signature:      []byte("signature"),
			},
		}

		idevidAttrs := &xkmssdk.KeyAttributes{
			CN:           "idevid-key",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      xkmssdk.KeyTypeSigning,
			TPMAttributes: &xkmssdk.TPMAttributes{
				PublicKeyBytes: []byte("idevid-public"),
			},
		}

		mockTPM := &mockXKMSTPM{
			ekCert:      ekCert,
			iakAttrs:    iakAttrs,
			idevidAttrs: idevidAttrs,
			idevidCSR: &xkmssdk.TCG_CSR_IDEVID{
				StructVer: [4]byte{0, 0, 0, 1},
				Contents:  [4]byte{0, 0, 1, 0},
				Signature: []byte("csr-signature"),
			},
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		qualifyingData := []byte("test-nonce-12345")
		result, err := adapter.CreateIDevID(qualifyingData)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.NotEmpty(t, result.CSR)
		assert.Equal(t, ekCert, result.EKCert)
		assert.Equal(t, qualifyingData, result.QualifyingData)
		assert.Equal(t, x509.ECDSAWithSHA256, result.SignatureAlgorithm)
		assert.Equal(t, []byte("iak-public"), result.IAKPublic)
		assert.Equal(t, []byte("idevid-public"), result.IDevIDPublic)
		assert.Equal(t, []byte("certify-info"), result.CertifyInfo)
		assert.Equal(t, []byte("signature"), result.Signature)
	})

	// TestXKMSTPMAdapter_CreateIDevID/hashes oversized qualifying data covers
	// tpm.go's SHA-256 fallback: ACME HTTP-01 keyAuth (~66 bytes) is longer
	// than the TPM's TPM2B_DATA MAX_DIGEST_BUFFER (maxTPMQualifyingData), so
	// CreateIDevID must hash it down to 32 bytes before calling into the TPM
	// rather than passing the oversized buffer through and letting
	// TPM2_Certify reject it.
	t.Run("hashes oversized qualifying data before calling the TPM", func(t *testing.T) {
		ecKey := newTestECDSAKey(t)
		ekCert := newTestCertificateFromPublicKey(t, &ecKey.PublicKey)

		iakAttrs := &xkmssdk.KeyAttributes{
			CN:           "iak-key",
			KeyAlgorithm: x509.ECDSA,
			TPMAttributes: &xkmssdk.TPMAttributes{
				PublicKeyBytes: []byte("iak-public"),
			},
		}

		mockTPM := &mockXKMSTPM{
			ekCert:   ekCert,
			iakAttrs: iakAttrs,
			idevidAttrs: &xkmssdk.KeyAttributes{
				TPMAttributes: &xkmssdk.TPMAttributes{},
			},
			idevidCSR: &xkmssdk.TCG_CSR_IDEVID{},
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		oversized := bytes.Repeat([]byte("a"), maxTPMQualifyingData+1)
		result, err := adapter.CreateIDevID(oversized)

		require.NoError(t, err)
		require.NotNil(t, result)
		wantHash := sha256.Sum256(oversized)
		assert.Equal(t, wantHash[:], mockTPM.receivedQualifyingData,
			"expected the TPM to receive the SHA-256 hash, not the raw oversized buffer")
		// The caller-facing result still reports the original, unhashed input.
		assert.Equal(t, oversized, result.QualifyingData)
	})

	t.Run("returns error when IAK not available", func(t *testing.T) {
		mockTPM := &mockXKMSTPM{
			iakAttrsError: errors.New("IAK not found"),
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		result, err := adapter.CreateIDevID([]byte("nonce"))

		require.Error(t, err)
		assert.Nil(t, result)
		var caErr *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, caerrors.NotFound, caErr.Type)
	})

	t.Run("returns error when EK certificate not available", func(t *testing.T) {
		iakAttrs := &xkmssdk.KeyAttributes{
			CN:           "iak-key",
			KeyAlgorithm: x509.ECDSA,
		}
		mockTPM := &mockXKMSTPM{
			iakAttrs:    iakAttrs,
			ekCertError: errors.New("EK cert not in NVRAM"),
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		result, err := adapter.CreateIDevID([]byte("nonce"))

		require.Error(t, err)
		assert.Nil(t, result)
		var caErr *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, caerrors.NotFound, caErr.Type)
	})

	t.Run("returns error when CreateIDevID fails", func(t *testing.T) {
		ecKey := newTestECDSAKey(t)
		ekCert := newTestCertificateFromPublicKey(t, &ecKey.PublicKey)
		iakAttrs := &xkmssdk.KeyAttributes{
			CN:           "iak-key",
			KeyAlgorithm: x509.ECDSA,
		}

		mockTPM := &mockXKMSTPM{
			ekCert:      ekCert,
			iakAttrs:    iakAttrs,
			idevidError: errors.New("TPM operation failed"),
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		result, err := adapter.CreateIDevID([]byte("nonce"))

		require.Error(t, err)
		assert.Nil(t, result)
		var caErr *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, caerrors.InternalServer, caErr.Type)
	})

	t.Run("uses cached IAK attributes", func(t *testing.T) {
		ecKey := newTestECDSAKey(t)
		ekCert := newTestCertificateFromPublicKey(t, &ecKey.PublicKey)

		iakAttrs := &xkmssdk.KeyAttributes{
			CN:                 "iak-key",
			KeyAlgorithm:       x509.ECDSA,
			SignatureAlgorithm: x509.ECDSAWithSHA256,
			TPMAttributes: &xkmssdk.TPMAttributes{
				PublicKeyBytes: []byte("iak-public"),
			},
		}

		idevidAttrs := &xkmssdk.KeyAttributes{
			CN: "idevid-key",
		}

		mockTPM := &mockXKMSTPM{
			ekCert:      ekCert,
			iakAttrs:    iakAttrs,
			idevidAttrs: idevidAttrs,
			idevidCSR:   &xkmssdk.TCG_CSR_IDEVID{},
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		// Pre-populate cache
		_, _ = adapter.IAKAttributes()

		// Now set error on iakAttrs - should use cache
		mockTPM.iakAttrsError = errors.New("should not be called")

		result, err := adapter.CreateIDevID([]byte("nonce"))
		require.NoError(t, err)
		assert.NotNil(t, result)
	})
}

func TestXKMSTPMAdapter_ActivateCredential(t *testing.T) {
	t.Run("activates credential successfully", func(t *testing.T) {
		expectedSecret := []byte("activated-secret-value")
		mockTPM := &mockXKMSTPM{
			activateSecret: expectedSecret,
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		credentialBlob := []byte("credential-blob")
		encryptedSecret := []byte("encrypted-secret")

		result, err := adapter.ActivateCredential(credentialBlob, encryptedSecret)

		require.NoError(t, err)
		assert.Equal(t, expectedSecret, result)
	})

	t.Run("returns error on activation failure", func(t *testing.T) {
		mockTPM := &mockXKMSTPM{
			activateError: errors.New("TPM2_ActivateCredential failed: authorization error"),
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		result, err := adapter.ActivateCredential([]byte("blob"), []byte("secret"))

		require.Error(t, err)
		assert.Nil(t, result)
		var caErr *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, caerrors.InternalServer, caErr.Type)
		assert.Contains(t, err.Error(), "authorization error")
	})

	t.Run("handles empty credential blob", func(t *testing.T) {
		mockTPM := &mockXKMSTPM{
			activateSecret: []byte("secret"),
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		result, err := adapter.ActivateCredential([]byte{}, []byte("secret"))

		require.NoError(t, err)
		assert.NotEmpty(t, result)
	})
}

func TestXKMSTPMAdapter_ProvisionEKCert(t *testing.T) {
	t.Run("provisions certificate successfully", func(t *testing.T) {
		ecKey := newTestECDSAKey(t)
		cert := newTestCertificateFromPublicKey(t, &ecKey.PublicKey)

		mockTPM := &mockXKMSTPM{
			parsedEKCert: cert,
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		err := adapter.ProvisionEKCert(cert.Raw)

		require.NoError(t, err)
		// Verify certificate was cached
		cachedCert, cacheErr := adapter.EKCertificate()
		require.NoError(t, cacheErr)
		assert.Equal(t, cert, cachedCert)
	})

	t.Run("returns error on provision failure", func(t *testing.T) {
		mockTPM := &mockXKMSTPM{
			provisionError: errors.New("NVRAM write failed"),
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		err := adapter.ProvisionEKCert([]byte("cert-der"))

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to provision EK certificate")
		assert.Contains(t, err.Error(), "NVRAM write failed")
	})

	t.Run("returns error on certificate parse failure", func(t *testing.T) {
		mockTPM := &mockXKMSTPM{
			parseError: errors.New("invalid certificate format"),
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		err := adapter.ProvisionEKCert([]byte("invalid-cert"))

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse provisioned EK certificate")
	})
}

func TestXKMSTPMAdapter_ProvisionIAKCert(t *testing.T) {
	t.Run("provisions certificate successfully", func(t *testing.T) {
		ecKey := newTestECDSAKey(t)
		cert := newTestCertificateFromPublicKey(t, &ecKey.PublicKey)

		mockTPM := &mockXKMSTPM{}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		err := adapter.ProvisionIAKCert(cert)

		require.NoError(t, err)
		assert.Equal(t, cert, mockTPM.provisionedIAKCert)
	})

	t.Run("returns error on provision failure", func(t *testing.T) {
		ecKey := newTestECDSAKey(t)
		cert := newTestCertificateFromPublicKey(t, &ecKey.PublicKey)

		mockTPM := &mockXKMSTPM{
			provisionIAKError: errors.New("NVRAM write failed"),
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		err := adapter.ProvisionIAKCert(cert)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to provision IAK certificate")
		assert.Contains(t, err.Error(), "NVRAM write failed")
	})
}

func TestXKMSTPMAdapter_Close(t *testing.T) {
	t.Run("closes successfully", func(t *testing.T) {
		mockTPM := &mockXKMSTPM{}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		err := adapter.Close()

		require.NoError(t, err)
	})

	t.Run("returns error on close failure", func(t *testing.T) {
		mockTPM := &mockXKMSTPM{
			closeError: errors.New("failed to close TPM handle"),
		}
		adapter := NewXKMSTPMAdapter(mockTPM, nil)

		err := adapter.Close()

		require.Error(t, err)
		assert.Equal(t, "failed to close TPM handle", err.Error())
	})
}

func TestConvertKeyAttributes_Extended(t *testing.T) {
	t.Run("converts nil attributes", func(t *testing.T) {
		result := convertKeyAttributes(nil)
		assert.Nil(t, result)
	})

	t.Run("converts ECDSA attributes with curve", func(t *testing.T) {
		attrs := &xkmssdk.KeyAttributes{
			CN:                 "test-key",
			KeyAlgorithm:       x509.ECDSA,
			SignatureAlgorithm: x509.ECDSAWithSHA256,
			Hash:               crypto.SHA256,
			KeyType:            xkmssdk.KeyTypeAttestation,
			ECCAttributes: &xkmssdk.ECCAttributes{
				Curve: elliptic.P384(),
			},
			TPMAttributes: &xkmssdk.TPMAttributes{
				Handle:         0x81010005,
				PublicKeyBytes: []byte("pub-bytes"),
			},
		}

		result := convertKeyAttributes(attrs)

		require.NotNil(t, result)
		assert.Equal(t, "test-key", result.KeyID)
		assert.Equal(t, "ECDSA-P-384", result.Algorithm)
		assert.Equal(t, x509.ECDSAWithSHA256, result.SignatureAlgorithm)
		assert.Equal(t, crypto.SHA256, result.Hash)
		assert.Equal(t, "ATTESTATION", result.KeyType)
		assert.Equal(t, uint32(0x81010005), result.TPMHandle)
		assert.Equal(t, []byte("pub-bytes"), result.TPMPublicBytes)
	})

	t.Run("converts ECDSA attributes without curve", func(t *testing.T) {
		attrs := &xkmssdk.KeyAttributes{
			CN:           "ecdsa-no-curve",
			KeyAlgorithm: x509.ECDSA,
		}

		result := convertKeyAttributes(attrs)

		assert.Equal(t, "ECDSA", result.Algorithm)
	})

	t.Run("converts RSA attributes with key size", func(t *testing.T) {
		attrs := &xkmssdk.KeyAttributes{
			CN:           "rsa-key",
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &xkmssdk.RSAAttributes{
				KeySize: 4096,
			},
		}

		result := convertKeyAttributes(attrs)

		assert.Equal(t, "RSA-4096", result.Algorithm)
	})

	t.Run("converts RSA attributes without key size", func(t *testing.T) {
		attrs := &xkmssdk.KeyAttributes{
			CN:           "rsa-no-size",
			KeyAlgorithm: x509.RSA,
		}

		result := convertKeyAttributes(attrs)

		assert.Equal(t, "RSA", result.Algorithm)
	})

	t.Run("converts Ed25519 attributes", func(t *testing.T) {
		attrs := &xkmssdk.KeyAttributes{
			CN:           "ed25519-key",
			KeyAlgorithm: x509.Ed25519,
		}

		result := convertKeyAttributes(attrs)

		assert.Equal(t, "Ed25519", result.Algorithm)
	})

	t.Run("converts unknown algorithm", func(t *testing.T) {
		attrs := &xkmssdk.KeyAttributes{
			CN:           "unknown-key",
			KeyAlgorithm: x509.DSA,
		}

		result := convertKeyAttributes(attrs)

		assert.Equal(t, "DSA", result.Algorithm)
	})

	t.Run("handles nil TPMAttributes", func(t *testing.T) {
		attrs := &xkmssdk.KeyAttributes{
			CN:            "no-tpm",
			KeyAlgorithm:  x509.ECDSA,
			TPMAttributes: nil,
		}

		result := convertKeyAttributes(attrs)

		assert.Equal(t, uint32(0), result.TPMHandle)
		assert.Nil(t, result.TPMPublicBytes)
	})
}

func TestXKMSTPMAdapter_InterfaceCompliance(t *testing.T) {
	// Verify XKMSTPMAdapter implements TPMModule interface
	var _ TPMModule = (*XKMSTPMAdapter)(nil)
}

// =====================================
// Tests from tpm_simple_test.go
// =====================================

func TestConvertKeyAttributes_Comprehensive(t *testing.T) {
	t.Run("nil attributes", func(t *testing.T) {
		result := convertKeyAttributes(nil)
		require.Nil(t, result)
	})

	t.Run("RSA attributes", func(t *testing.T) {
		attrs := &xkmssdk.KeyAttributes{
			CN:                 "test-rsa",
			KeyAlgorithm:       x509.RSA,
			SignatureAlgorithm: x509.SHA256WithRSA,
			Hash:               crypto.SHA256,
			KeyType:            xkmssdk.KeyTypeEndorsement,
			RSAAttributes: &xkmssdk.RSAAttributes{
				KeySize: 2048,
			},
			TPMAttributes: &xkmssdk.TPMAttributes{
				Handle:         0x81010001,
				PublicKeyBytes: []byte("test-public"),
			},
		}

		result := convertKeyAttributes(attrs)
		require.NotNil(t, result)
		require.Equal(t, "test-rsa", result.KeyID)
		require.Equal(t, "RSA-2048", result.Algorithm)
		require.Equal(t, x509.SHA256WithRSA, result.SignatureAlgorithm)
		require.Equal(t, "ENDORSEMENT", result.KeyType)
		require.Equal(t, uint32(0x81010001), result.TPMHandle)
		require.Equal(t, []byte("test-public"), result.TPMPublicBytes)
	})

	t.Run("ECDSA attributes with curve", func(t *testing.T) {
		attrs := &xkmssdk.KeyAttributes{
			CN:                 "test-ec",
			KeyAlgorithm:       x509.ECDSA,
			SignatureAlgorithm: x509.ECDSAWithSHA256,
			Hash:               crypto.SHA256,
			KeyType:            xkmssdk.KeyTypeAttestation,
			ECCAttributes: &xkmssdk.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		result := convertKeyAttributes(attrs)
		require.NotNil(t, result)
		require.Equal(t, "ECDSA-P-256", result.Algorithm)
		require.Equal(t, "ATTESTATION", result.KeyType)
	})

	t.Run("ECDSA attributes without curve", func(t *testing.T) {
		attrs := &xkmssdk.KeyAttributes{
			CN:                 "test-ec-nocurve",
			KeyAlgorithm:       x509.ECDSA,
			SignatureAlgorithm: x509.ECDSAWithSHA384,
			Hash:               crypto.SHA384,
			KeyType:            xkmssdk.KeyTypeIDevID,
		}

		result := convertKeyAttributes(attrs)
		require.NotNil(t, result)
		require.Equal(t, "ECDSA", result.Algorithm)
	})

	t.Run("Ed25519 attributes", func(t *testing.T) {
		attrs := &xkmssdk.KeyAttributes{
			CN:                 "test-ed",
			KeyAlgorithm:       x509.Ed25519,
			SignatureAlgorithm: x509.PureEd25519,
			Hash:               crypto.Hash(0),
			KeyType:            xkmssdk.KeyTypeIDevID,
		}

		result := convertKeyAttributes(attrs)
		require.NotNil(t, result)
		require.Equal(t, "Ed25519", result.Algorithm)
		require.Equal(t, "IDevID", result.KeyType)
	})

	t.Run("RSA without size", func(t *testing.T) {
		attrs := &xkmssdk.KeyAttributes{
			CN:                 "test-rsa-nosize",
			KeyAlgorithm:       x509.RSA,
			SignatureAlgorithm: x509.SHA512WithRSA,
			Hash:               crypto.SHA512,
			KeyType:            xkmssdk.KeyTypeEndorsement,
		}

		result := convertKeyAttributes(attrs)
		require.NotNil(t, result)
		require.Equal(t, "RSA", result.Algorithm)
	})

	t.Run("unknown algorithm", func(t *testing.T) {
		attrs := &xkmssdk.KeyAttributes{
			CN:                 "test-unknown",
			KeyAlgorithm:       x509.PublicKeyAlgorithm(999),
			SignatureAlgorithm: x509.UnknownSignatureAlgorithm,
			Hash:               crypto.SHA256,
			KeyType:            xkmssdk.KeyTypeEndorsement,
		}

		result := convertKeyAttributes(attrs)
		require.NotNil(t, result)
		// Unknown algorithms return their numeric string representation
		require.Equal(t, "999", result.Algorithm)
	})
}

func TestSignatureAlgorithmFromCOSE_AllAlgorithms(t *testing.T) {
	tests := []struct {
		name     string
		coseAlg  COSEAlgorithm
		expected x509.SignatureAlgorithm
	}{
		{"ES256", COSEAlgorithmES256, x509.ECDSAWithSHA256},
		{"ES384", COSEAlgorithmES384, x509.ECDSAWithSHA384},
		{"ES512", COSEAlgorithmES512, x509.ECDSAWithSHA512},
		{"RS256", COSEAlgorithmRS256, x509.SHA256WithRSA},
		{"RS384", COSEAlgorithmRS384, x509.SHA384WithRSA},
		{"RS512", COSEAlgorithmRS512, x509.SHA512WithRSA},
		{"PS256", COSEAlgorithmPS256, x509.SHA256WithRSAPSS},
		{"PS384", COSEAlgorithmPS384, x509.SHA384WithRSAPSS},
		{"PS512", COSEAlgorithmPS512, x509.SHA512WithRSAPSS},
		{"EdDSA", COSEAlgorithmEdDSA, x509.PureEd25519},
		{"Unknown", COSEAlgorithmUnknown, x509.UnknownSignatureAlgorithm},
		{"Invalid", COSEAlgorithm(9999), x509.UnknownSignatureAlgorithm},
		{"Negative", COSEAlgorithm(-999), x509.UnknownSignatureAlgorithm},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SignatureAlgorithmFromCOSE(tt.coseAlg)
			require.Equal(t, tt.expected, result,
				"COSE algorithm %d should map to %v, got %v", tt.coseAlg, tt.expected, result)
		})
	}
}

func TestXKMSTPMAdapter_EdgeCases(t *testing.T) {
	t.Run("NewXKMSTPMAdapter with nil", func(t *testing.T) {
		// Should not panic
		adapter := NewXKMSTPMAdapter(nil, nil)
		require.NotNil(t, adapter)
		require.Nil(t, adapter.tpm)
	})

	t.Run("TPMModule interface compliance", func(t *testing.T) {
		// This ensures our XKMSTPMAdapter implements TPMModule
		var _ TPMModule = (*XKMSTPMAdapter)(nil)
	})
}

func TestKeyAttributes_Structure(t *testing.T) {
	t.Run("create KeyAttributes with all fields", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		attrs := &KeyAttributes{
			KeyID:              "test-key-001",
			Algorithm:          "ECDSA-P256",
			PublicKey:          &key.PublicKey,
			Certificate:        nil,
			SignatureAlgorithm: x509.ECDSAWithSHA256,
			Hash:               crypto.SHA256,
			KeyType:            "attestation",
			TPMHandle:          0x81010001,
			TPMPublicBytes:     []byte("tpm-public-data"),
		}

		require.Equal(t, "test-key-001", attrs.KeyID)
		require.Equal(t, "ECDSA-P256", attrs.Algorithm)
		require.NotNil(t, attrs.PublicKey)
		require.Equal(t, x509.ECDSAWithSHA256, attrs.SignatureAlgorithm)
		require.Equal(t, crypto.SHA256, attrs.Hash)
		require.Equal(t, "attestation", attrs.KeyType)
		require.Equal(t, uint32(0x81010001), attrs.TPMHandle)
		require.Equal(t, []byte("tpm-public-data"), attrs.TPMPublicBytes)
	})
}

func TestIDevIDCSR_Structure(t *testing.T) {
	t.Run("create IDevIDCSR with all fields", func(t *testing.T) {
		cert, _ := generateTestCertificate(t, "EK Test")

		csr := &IDevIDCSR{
			CSR:                []byte("csr-data"),
			IAKPublic:          []byte("iak-public"),
			EKCert:             cert,
			QualifyingData:     []byte("nonce"),
			IDevIDPublic:       []byte("idevid-public"),
			SignatureAlgorithm: x509.ECDSAWithSHA256,
			CertifyInfo:        []byte("certify-info"),
			Signature:          []byte("signature"),
		}

		require.NotEmpty(t, csr.CSR)
		require.NotEmpty(t, csr.IAKPublic)
		require.NotNil(t, csr.EKCert)
		require.NotEmpty(t, csr.QualifyingData)
		require.NotEmpty(t, csr.IDevIDPublic)
		require.Equal(t, x509.ECDSAWithSHA256, csr.SignatureAlgorithm)
		require.NotEmpty(t, csr.CertifyInfo)
		require.NotEmpty(t, csr.Signature)
	})
}

// testTPMManufacturer is the TCG manufacturer code swtpm reports ("IBM"),
// returned by every TPM test double.
const testTPMManufacturer = "id:49424D00"

func TestXKMSTPMAdapter_TPMManufacturer(t *testing.T) {
	t.Run("returns the code the TPM reports", func(t *testing.T) {
		adapter := NewXKMSTPMAdapter(&mockXKMSTPM{
			fixedProps: &xkmssdk.PropertiesFixed{Manufacturer: "Infineon", ManufacturerCode: "id:49465800"},
		}, nil)

		code, err := adapter.TPMManufacturer()

		require.NoError(t, err)
		assert.Equal(t, "id:49465800", code)
	})

	t.Run("fails when the fixed properties cannot be read", func(t *testing.T) {
		adapter := NewXKMSTPMAdapter(&mockXKMSTPM{fixedPropsError: errors.New("tpm unavailable")}, nil)

		code, err := adapter.TPMManufacturer()

		assert.Empty(t, code)
		var caErr *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, caerrors.NotFound, caErr.Type)
	})

	t.Run("fails when the TPM reports no code", func(t *testing.T) {
		adapter := NewXKMSTPMAdapter(&mockXKMSTPM{
			fixedProps: &xkmssdk.PropertiesFixed{Manufacturer: "Infineon"},
		}, nil)

		code, err := adapter.TPMManufacturer()

		assert.Empty(t, code)
		var caErr *caerrors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, caerrors.NotFound, caErr.Type)
	})
}

// TestXKMSTPMAdapter_CreateAttestedKeyRefusals covers what the adapter refuses
// before the TPM is asked for anything. Its success path runs against the
// simulator in tpm_simulator_test.go.
func TestXKMSTPMAdapter_CreateAttestedKeyRefusals(t *testing.T) {
	keys := xkmssdk.NewFileBackend(slog.New(slog.NewTextHandler(io.Discard, nil)), newMemoryStorage(t))

	t.Run("no name", func(t *testing.T) {
		attested, err := NewXKMSTPMAdapter(&mockXKMSTPM{}, keys).CreateAttestedKey("", "key-auth")
		assert.ErrorIs(t, err, ErrAttestedKeyNameRequired)
		assert.Nil(t, attested)
	})

	t.Run("no key store", func(t *testing.T) {
		attested, err := NewXKMSTPMAdapter(&mockXKMSTPM{}, nil).CreateAttestedKey("device", "key-auth")
		assert.ErrorIs(t, err, ErrKeyBackendNotConfigured)
		assert.Nil(t, attested)
	})

	t.Run("no Platform SRK", func(t *testing.T) {
		missing := errors.New("platform SRK not enrolled")
		attested, err := NewXKMSTPMAdapter(&mockXKMSTPM{platformSRKError: missing}, keys).CreateAttestedKey("device", "key-auth")
		assert.ErrorIs(t, err, ErrAttestedKeyFailed)
		assert.ErrorIs(t, err, missing)
		assert.Nil(t, attested)
	})
}

// newMemoryStorage is an in-memory store for TPM key blobs.
func newMemoryStorage(t *testing.T) xkmssdk.StorageBackend {
	t.Helper()
	backend, err := xkmssdk.NewMemoryBackend()
	require.NoError(t, err)
	return backend
}

// testDeviceIdentity is the identity the test TPM doubles attest under.
const testDeviceIdentity = "test-device-identity"
