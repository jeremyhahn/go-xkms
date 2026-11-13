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

package mocks

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/mock"
)

// MockCertificateAuthority is a testify mock implementation of ca.TCGCA.
// It provides mock functionality for all CA operations including certificate
// signing, verification, TPM attestation, and key management.
type MockCertificateAuthority struct {
	mock.Mock
}

// Ensure MockCertificateAuthority implements ca.TCGCA.
var _ ca.TCGCA = (*MockCertificateAuthority)(nil)

// ========================================================================
// crypto.Signer Interface
// ========================================================================

// Sign implements crypto.Signer.Sign.
func (m *MockCertificateAuthority) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	args := m.Called(rand, digest, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

// Public implements crypto.Signer.Public.
func (m *MockCertificateAuthority) Public() crypto.PublicKey {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(crypto.PublicKey)
}

// ========================================================================
// Lifecycle
// ========================================================================

// Init explicitly initializes the CA by creating root and intermediate certificates.
func (m *MockCertificateAuthority) Init(ctx context.Context) error {
	args := m.Called()
	return args.Error(0)
}

// Load loads an existing CA from storage.
func (m *MockCertificateAuthority) Load(ctx context.Context) error {
	args := m.Called()
	return args.Error(0)
}

// IsInitialized checks whether the CA has been initialized.
func (m *MockCertificateAuthority) IsInitialized() bool {
	args := m.Called()
	return args.Bool(0)
}

// ========================================================================
// CSR / Issuance
// ========================================================================

// SignCSR signs a CSR using the provided options.
func (m *MockCertificateAuthority) SignCSR(ctx context.Context, csrPEM []byte, opts *ca.SignOptions) (*x509.Certificate, error) {
	args := m.Called(csrPEM, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*x509.Certificate), args.Error(1)
}

// ReserveSerial reserves a serial number for a later SignCSR.
func (m *MockCertificateAuthority) ReserveSerial(ctx context.Context) (*big.Int, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*big.Int), args.Error(1)
}

// CreateCSR generates a CSR for the given request.
func (m *MockCertificateAuthority) CreateCSR(ctx context.Context, request *ca.CertificateRequest) ([]byte, error) {
	args := m.Called(request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

// IssueCertificate issues a certificate directly without ACME protocol.
func (m *MockCertificateAuthority) IssueCertificate(ctx context.Context, request *ca.CertificateRequest) (*ca.IssuedCertificate, error) {
	args := m.Called(request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ca.IssuedCertificate), args.Error(1)
}

// IssueCertificateForKey issues a certificate for a caller-held public key.
func (m *MockCertificateAuthority) IssueCertificateForKey(ctx context.Context, request *ca.CertificateRequest, publicKey crypto.PublicKey) (*ca.IssuedCertificate, error) {
	args := m.Called(request, publicKey)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ca.IssuedCertificate), args.Error(1)
}

// IssueCertificateWithProfile issues a certificate using a named profile.
func (m *MockCertificateAuthority) IssueCertificateWithProfile(ctx context.Context, request *ca.CertificateRequest, profile string) (*ca.IssuedCertificate, error) {
	args := m.Called(request, profile)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ca.IssuedCertificate), args.Error(1)
}

// ========================================================================
// Trust Chain
// ========================================================================

// CACertificate returns the CA's certificate.
func (m *MockCertificateAuthority) CACertificate() (*x509.Certificate, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*x509.Certificate), args.Error(1)
}

// CABundle returns the CA bundle PEM.
func (m *MockCertificateAuthority) CABundle() ([]byte, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

// Verify verifies a certificate against the CA's trust chain.
func (m *MockCertificateAuthority) Verify(cert *x509.Certificate, xsigner ...crypto.Signer) ([][]*x509.Certificate, error) {
	var signer crypto.Signer
	if len(xsigner) > 0 {
		signer = xsigner[0]
	}
	args := m.Called(cert, signer)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([][]*x509.Certificate), args.Error(1)
}

// TrustedRoot returns the root CA certificate.
func (m *MockCertificateAuthority) TrustedRoot() (*x509.Certificate, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*x509.Certificate), args.Error(1)
}

// TrustedIntermediate returns the intermediate CA certificate.
func (m *MockCertificateAuthority) TrustedIntermediate() (*x509.Certificate, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*x509.Certificate), args.Error(1)
}

// ========================================================================
// Revocation
// ========================================================================

// Revoke marks a certificate with the given serial as revoked.
func (m *MockCertificateAuthority) Revoke(ctx context.Context, serial *big.Int, reason int) error {
	args := m.Called(serial, reason)
	return args.Error(0)
}

// RevokeCert revokes the given certificate, optionally deleting its keys.
func (m *MockCertificateAuthority) RevokeCert(ctx context.Context, cert *x509.Certificate, opts ca.RevokeOptions) error {
	args := m.Called(cert, opts)
	return args.Error(0)
}

// IsRevoked checks if a certificate serial number is revoked.
func (m *MockCertificateAuthority) IsRevoked(serial *big.Int) (bool, error) {
	args := m.Called(serial)
	return args.Bool(0), args.Error(1)
}

// GenerateCRL generates a Certificate Revocation List.
func (m *MockCertificateAuthority) GenerateCRL(ctx context.Context) ([]byte, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

// CRL returns the current CRL DER, regenerating it first when necessary.
func (m *MockCertificateAuthority) CRL(ctx context.Context) ([]byte, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

// ========================================================================
// TLS Helpers
// ========================================================================

// TLSCertificate returns a TLS certificate for the given key attributes.
func (m *MockCertificateAuthority) TLSCertificate(ctx context.Context, attrs *types.KeyAttributes) (tls.Certificate, error) {
	args := m.Called(attrs)
	return args.Get(0).(tls.Certificate), args.Error(1)
}

// TLSConfig returns a TLS configuration for the given key attributes.
func (m *MockCertificateAuthority) TLSConfig(ctx context.Context, attrs *types.KeyAttributes) (*tls.Config, error) {
	args := m.Called(attrs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*tls.Config), args.Error(1)
}

// ServerTLSConfig returns a server TLS configuration.
func (m *MockCertificateAuthority) ServerTLSConfig(ctx context.Context, attrs *types.KeyAttributes, requireClientCert bool) (*tls.Config, error) {
	args := m.Called(attrs, requireClientCert)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*tls.Config), args.Error(1)
}

// ClientTLSConfig returns a client TLS configuration with SNI.
func (m *MockCertificateAuthority) ClientTLSConfig(ctx context.Context, attrs *types.KeyAttributes, serverName string) (*tls.Config, error) {
	args := m.Called(attrs, serverName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*tls.Config), args.Error(1)
}

// TLSBundle returns a PEM bundle (chain + private key).
func (m *MockCertificateAuthority) TLSBundle(ctx context.Context, attrs *types.KeyAttributes) ([]byte, error) {
	args := m.Called(attrs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

// TLSBundleWithCrossSigner returns a TLS bundle with cross-signed certs prepended.
func (m *MockCertificateAuthority) TLSBundleWithCrossSigner(ctx context.Context, attrs *types.KeyAttributes, xsigner crypto.Signer) ([]byte, error) {
	args := m.Called(attrs, xsigner)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

// TLSConfigWithXSigner returns a TLS config with cross-signer trust augmentation.
func (m *MockCertificateAuthority) TLSConfigWithXSigner(ctx context.Context, attrs *types.KeyAttributes, xsigner crypto.Signer) (*tls.Config, error) {
	args := m.Called(attrs, xsigner)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*tls.Config), args.Error(1)
}

// ========================================================================
// Trust Pool Builders
// ========================================================================

// TrustedRootCertPool returns a cert pool containing the root CA.
func (m *MockCertificateAuthority) TrustedRootCertPool(cert *x509.Certificate) (*x509.CertPool, error) {
	args := m.Called(cert)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*x509.CertPool), args.Error(1)
}

// TrustedIntermediateCertPool returns a cert pool containing the intermediate CAs.
func (m *MockCertificateAuthority) TrustedIntermediateCertPool(cert *x509.Certificate) (*x509.CertPool, error) {
	args := m.Called(cert)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*x509.CertPool), args.Error(1)
}

// TrustedRootCertPoolWithXSigner is the cross-sign-aware root pool.
func (m *MockCertificateAuthority) TrustedRootCertPoolWithXSigner(cert *x509.Certificate, xsigner crypto.Signer) (*x509.CertPool, error) {
	args := m.Called(cert, xsigner)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*x509.CertPool), args.Error(1)
}

// TrustedIntermediateCertPoolWithXSigner is the cross-sign-aware intermediate pool.
func (m *MockCertificateAuthority) TrustedIntermediateCertPoolWithXSigner(cert *x509.Certificate, xsigner crypto.Signer) (*x509.CertPool, error) {
	args := m.Called(cert, xsigner)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*x509.CertPool), args.Error(1)
}

// CABundleCertPool returns a cert pool from the full CA bundle.
func (m *MockCertificateAuthority) CABundleCertPool() (*x509.CertPool, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*x509.CertPool), args.Error(1)
}

// OSTrustStore returns the operating system's trusted certificate pool.
func (m *MockCertificateAuthority) OSTrustStore() (*x509.CertPool, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*x509.CertPool), args.Error(1)
}

// ========================================================================
// Storage Access
// ========================================================================

// KeyStore returns access to the keystore.
func (m *MockCertificateAuthority) KeyStore() xkms.Backend {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(xkms.Backend)
}

// CertStore returns access to the certificate store.
func (m *MockCertificateAuthority) CertStore() certstore.CertStore {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(certstore.CertStore)
}

// ========================================================================
// Signing Identity Accessors
// ========================================================================

// Config returns the issuing CA identity.
func (m *MockCertificateAuthority) Config() *ca.Identity {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*ca.Identity)
}

// Identity returns the CA's identity string.
func (m *MockCertificateAuthority) Identity() string {
	args := m.Called()
	return args.String(0)
}

// Signer returns a crypto.Signer backed by the CA's issuing identity key.
func (m *MockCertificateAuthority) Signer(ctx context.Context) (crypto.Signer, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(crypto.Signer), args.Error(1)
}

// PrivateKey retrieves a private key handle.
func (m *MockCertificateAuthority) PrivateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	args := m.Called(attrs)
	return args.Get(0), args.Error(1)
}

// PubKey returns the public key.
func (m *MockCertificateAuthority) PubKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PublicKey, error) {
	args := m.Called(attrs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(crypto.PublicKey), args.Error(1)
}

// SignedBlob signs arbitrary data using the CA's signing key.
func (m *MockCertificateAuthority) SignedBlob(ctx context.Context, data []byte) ([]byte, error) {
	args := m.Called(data)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

// ========================================================================
// Certificate Retrieval & Import
// ========================================================================

// Issued reports whether a certificate for cn has been issued.
func (m *MockCertificateAuthority) Issued(ctx context.Context, cn string) (bool, error) {
	args := m.Called(ctx, cn)
	return args.Bool(0), args.Error(1)
}

// Exists reports whether a certificate exists for cn with the given algorithm.
func (m *MockCertificateAuthority) Exists(ctx context.Context, cn string, algo x509.PublicKeyAlgorithm) (bool, error) {
	args := m.Called(ctx, cn, algo)
	return args.Bool(0), args.Error(1)
}

// Certificate retrieves a certificate using its KeyAttributes.
func (m *MockCertificateAuthority) Certificate(ctx context.Context, attrs *types.KeyAttributes) (*x509.Certificate, error) {
	args := m.Called(ctx, attrs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*x509.Certificate), args.Error(1)
}

// CertificatePEM retrieves a certificate in PEM form.
func (m *MockCertificateAuthority) CertificatePEM(ctx context.Context, cn string) ([]byte, error) {
	args := m.Called(ctx, cn)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

// ImportCertificate stores an externally-issued certificate.
func (m *MockCertificateAuthority) ImportCertificate(ctx context.Context, cert *x509.Certificate) error {
	args := m.Called(ctx, cert)
	return args.Error(0)
}

// ImportCertificatePEM parses and imports a PEM-encoded certificate.
func (m *MockCertificateAuthority) ImportCertificatePEM(ctx context.Context, cn string, pemBytes []byte) error {
	args := m.Called(ctx, cn, pemBytes)
	return args.Error(0)
}

// PEM returns a certificate in PEM form.
func (m *MockCertificateAuthority) PEM(ctx context.Context, attrs *types.KeyAttributes) ([]byte, error) {
	args := m.Called(ctx, attrs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

// ========================================================================
// Object Store Helpers
// ========================================================================

// Blob returns raw blob data from the CA's object store.
func (m *MockCertificateAuthority) Blob(key []byte) ([]byte, error) {
	args := m.Called(key)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

// ImportBlob stores raw blob data in the CA's object store.
func (m *MockCertificateAuthority) ImportBlob(key, data []byte) error {
	args := m.Called(key, data)
	return args.Error(0)
}

// ========================================================================
// Trust Chain Extensions
// ========================================================================

// ImportDistributionCRLs imports CRLs from distribution points in the certificate.
func (m *MockCertificateAuthority) ImportDistributionCRLs(cert *x509.Certificate) error {
	args := m.Called(cert)
	return args.Error(0)
}

// ImportIssuingCAs recursively imports issuing CAs via AIA.
func (m *MockCertificateAuthority) ImportIssuingCAs(ctx context.Context, cert *x509.Certificate) error {
	args := m.Called(ctx, cert)
	return args.Error(0)
}

// ImportIssuingCAsInto imports issuing CAs via AIA into a caller-owned store.
func (m *MockCertificateAuthority) ImportIssuingCAsInto(ctx context.Context, cert *x509.Certificate, store certstore.CertStore) error {
	args := m.Called(ctx, cert, store)
	return args.Error(0)
}

// ParseBundle parses a PEM-encoded certificate bundle.
func (m *MockCertificateAuthority) ParseBundle(bundle []byte) ([]*x509.Certificate, error) {
	args := m.Called(bundle)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*x509.Certificate), args.Error(1)
}

// RootCertificate walks the chain to find the root CA.
func (m *MockCertificateAuthority) RootCertificate(childCert *x509.Certificate) (*x509.Certificate, error) {
	args := m.Called(childCert)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*x509.Certificate), args.Error(1)
}

// ========================================================================
// Cross-Signing
// ========================================================================

// ImportXSignedCertificate persists a cross-signed certificate.
func (m *MockCertificateAuthority) ImportXSignedCertificate(issuerCN string, cert *x509.Certificate) error {
	args := m.Called(issuerCN, cert)
	return args.Error(0)
}

// XSignedCertificate retrieves a cross-signed certificate.
func (m *MockCertificateAuthority) XSignedCertificate(issuerCN string, attrs *types.KeyAttributes) (*x509.Certificate, error) {
	args := m.Called(issuerCN, attrs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*x509.Certificate), args.Error(1)
}

// XSignedRootCertificate walks the cross-signed chain to the root.
func (m *MockCertificateAuthority) XSignedRootCertificate(issuerCN string, cert *x509.Certificate) (*x509.Certificate, error) {
	args := m.Called(issuerCN, cert)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*x509.Certificate), args.Error(1)
}

// XSignedIntermediateCertificates returns intermediates in the cross-signed chain.
func (m *MockCertificateAuthority) XSignedIntermediateCertificates(issuerCN string, cert *x509.Certificate) ([]*x509.Certificate, error) {
	args := m.Called(issuerCN, cert)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*x509.Certificate), args.Error(1)
}

// CrossSignedPEM returns every cross-signed certificate for the subject.
func (m *MockCertificateAuthority) CrossSignedPEM(attrs *types.KeyAttributes) ([]byte, error) {
	args := m.Called(attrs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

// ========================================================================
// Attestation (TPM)
// ========================================================================

// ImportAttestation stores a TPM attestation blob.
func (m *MockCertificateAuthority) ImportAttestation(ctx context.Context, akAttrs *types.KeyAttributes, blobType string, data []byte) error {
	args := m.Called(akAttrs, blobType, data)
	return args.Error(0)
}

// ImportAttestationKeyCertificate stores a DER-encoded AK certificate.
func (m *MockCertificateAuthority) ImportAttestationKeyCertificate(ctx context.Context, attrs *types.KeyAttributes, akDER []byte) error {
	args := m.Called(attrs, akDER)
	return args.Error(0)
}

// ImportAttestationEventLog stores a TPM event log blob.
func (m *MockCertificateAuthority) ImportAttestationEventLog(ctx context.Context, akAttrs *types.KeyAttributes, eventLog []byte) error {
	args := m.Called(akAttrs, eventLog)
	return args.Error(0)
}

// ImportAttestationPCRs stores a TPM PCR snapshot blob.
func (m *MockCertificateAuthority) ImportAttestationPCRs(ctx context.Context, akAttrs *types.KeyAttributes, pcrs []byte) error {
	args := m.Called(akAttrs, pcrs)
	return args.Error(0)
}

// ImportAttestationQuote stores a TPM quote blob.
func (m *MockCertificateAuthority) ImportAttestationQuote(ctx context.Context, akAttrs *types.KeyAttributes, quote []byte) error {
	args := m.Called(akAttrs, quote)
	return args.Error(0)
}

// ImportLocalAttestation imports a complete local attestation.
func (m *MockCertificateAuthority) ImportLocalAttestation(ctx context.Context, akAttrs *types.KeyAttributes, quote *tpm2.Quote) error {
	args := m.Called(akAttrs, quote)
	return args.Error(0)
}

// VerifyAttestationQuote verifies a previously-stored quote blob.
func (m *MockCertificateAuthority) VerifyAttestationQuote(akAttrs *types.KeyAttributes, quote []byte) error {
	args := m.Called(akAttrs, quote)
	return args.Error(0)
}

// VerifyAttestationEventLog verifies a previously-stored event log blob.
func (m *MockCertificateAuthority) VerifyAttestationEventLog(akAttrs *types.KeyAttributes, eventLog []byte) error {
	args := m.Called(akAttrs, eventLog)
	return args.Error(0)
}

// VerifyAttestationPCRs verifies a previously-stored PCR snapshot blob.
func (m *MockCertificateAuthority) VerifyAttestationPCRs(akAttrs *types.KeyAttributes, pcrs []byte) error {
	args := m.Called(akAttrs, pcrs)
	return args.Error(0)
}

// ========================================================================
// TCG Enrollment Verification
// ========================================================================

// VerifyTCG_CSR_IDevIDBytes verifies a packed TCG-CSR-IDEVID.
func (m *MockCertificateAuthority) VerifyTCG_CSR_IDevIDBytes(packedCSR []byte, sigAlg x509.SignatureAlgorithm) ([]byte, []byte, []byte, error) {
	args := m.Called(packedCSR, sigAlg)
	var credentialBlob, encryptedSecret, plainSecret []byte
	if args.Get(0) != nil {
		credentialBlob = args.Get(0).([]byte)
	}
	if args.Get(1) != nil {
		encryptedSecret = args.Get(1).([]byte)
	}
	if args.Get(2) != nil {
		plainSecret = args.Get(2).([]byte)
	}
	return credentialBlob, encryptedSecret, plainSecret, args.Error(3)
}

// ========================================================================
// Configuration & Metadata
// ========================================================================

// CAKeyAttributes returns the KeyAttributes for the CA's signing key.
func (m *MockCertificateAuthority) CAKeyAttributes(storeType types.StoreType) (*types.KeyAttributes, error) {
	args := m.Called(storeType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*types.KeyAttributes), args.Error(1)
}

// CASigner returns a crypto.Signer filtered by store type/algorithm.
func (m *MockCertificateAuthority) CASigner(ctx context.Context, storeType types.StoreType, algo x509.PublicKeyAlgorithm) (crypto.Signer, error) {
	args := m.Called(storeType, algo)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(crypto.Signer), args.Error(1)
}

// CAConfig returns the flat CAConfig supplied at construction time.
func (m *MockCertificateAuthority) CAConfig() ca.CAConfig {
	args := m.Called()
	return args.Get(0).(ca.CAConfig)
}

// DefaultKeyAlgorithm returns the CA's default public-key algorithm.
func (m *MockCertificateAuthority) DefaultKeyAlgorithm() x509.PublicKeyAlgorithm {
	args := m.Called()
	return args.Get(0).(x509.PublicKeyAlgorithm)
}

// DefaultSignatureAlgorithm returns the CA's default signature algorithm.
func (m *MockCertificateAuthority) DefaultSignatureAlgorithm() x509.SignatureAlgorithm {
	args := m.Called()
	return args.Get(0).(x509.SignatureAlgorithm)
}

// DefaultValidityPeriod returns the default validity period in days.
func (m *MockCertificateAuthority) DefaultValidityPeriod() int {
	args := m.Called()
	return args.Int(0)
}

// Hash returns the CA's signing hash function.
func (m *MockCertificateAuthority) Hash() crypto.Hash {
	args := m.Called()
	return args.Get(0).(crypto.Hash)
}

// IssuingIdentity returns the issuing identity.
func (m *MockCertificateAuthority) IssuingIdentity() ca.Identity {
	args := m.Called()
	if args.Get(0) == nil {
		return ca.Identity{}
	}
	return args.Get(0).(ca.Identity)
}

// IsAutoImportingIssuerCAs reports whether AIA auto-import is enabled.
func (m *MockCertificateAuthority) IsAutoImportingIssuerCAs() bool {
	args := m.Called()
	return args.Bool(0)
}

// ========================================================================
// Extended Revocation & Filtered Bundle
// ========================================================================

// CABundleFiltered returns a CA bundle filtered by store type and algorithm.
func (m *MockCertificateAuthority) CABundleFiltered(storeType types.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error) {
	args := m.Called(storeType, keyAlgorithm)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

// ========================================================================
// TCGCA: TCG-specific extensions
// ========================================================================

// IssueEKCertificate issues an Endorsement Key certificate.
func (m *MockCertificateAuthority) IssueEKCertificate(ctx context.Context, request *ca.CertificateRequest, ekPubKey crypto.PublicKey) (*x509.Certificate, error) {
	args := m.Called(request, ekPubKey)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*x509.Certificate), args.Error(1)
}

// IssueAKCertificate issues an Attestation Key certificate.
func (m *MockCertificateAuthority) IssueAKCertificate(ctx context.Context, request *ca.CertificateRequest, pubKey crypto.PublicKey) (*x509.Certificate, error) {
	args := m.Called(request, pubKey)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*x509.Certificate), args.Error(1)
}

// SignTCGCSRIDevID verifies and signs a TCG-CSR-IDEVID for enrollment.
func (m *MockCertificateAuthority) SignTCGCSRIDevID(ctx context.Context, tcgCSR *tpm2.TCG_CSR_IDEVID, request *ca.CertificateRequest) ([]byte, []byte, error) {
	args := m.Called(tcgCSR, request)
	var iakDER, idevidDER []byte
	if args.Get(0) != nil {
		iakDER = args.Get(0).([]byte)
	}
	if args.Get(1) != nil {
		idevidDER = args.Get(1).([]byte)
	}
	return iakDER, idevidDER, args.Error(2)
}

// EnrollDevice performs complete TCG enrollment.
func (m *MockCertificateAuthority) EnrollDevice(ctx context.Context, packedCSR []byte, request *ca.CertificateRequest) (*ca.TCGEnrollmentResult, error) {
	args := m.Called(packedCSR, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ca.TCGEnrollmentResult), args.Error(1)
}

// SetTPM configures the TPM instance for enrollment operations.
func (m *MockCertificateAuthority) SetTPM(tpm tpm2.TrustedPlatformModule) {
	m.Called(tpm)
}

// VerifyQuote verifies a TPM quote signature and nonce.
func (m *MockCertificateAuthority) VerifyQuote(attrs *types.KeyAttributes, quote *tpm2.Quote, nonce []byte) error {
	args := m.Called(attrs, quote, nonce)
	return args.Error(0)
}

// ImportEndorsementKeyCertificate imports an EK certificate.
func (m *MockCertificateAuthority) ImportEndorsementKeyCertificate(cert *x509.Certificate) error {
	args := m.Called(cert)
	return args.Error(0)
}

// EndorsementKeyCertificate retrieves an EK certificate by CN.
func (m *MockCertificateAuthority) EndorsementKeyCertificate(cn string) (*x509.Certificate, error) {
	args := m.Called(cn)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*x509.Certificate), args.Error(1)
}

// IssueLAKCertificate issues a Local Attestation Key certificate (go-xkms#715).
func (m *MockCertificateAuthority) IssueLAKCertificate(ctx context.Context, request *ca.CertificateRequest, evidence *ca.LAKCertificationEvidence) (*x509.Certificate, error) {
	args := m.Called(request, evidence)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*x509.Certificate), args.Error(1)
}
