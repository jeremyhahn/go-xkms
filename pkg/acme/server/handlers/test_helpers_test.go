//go:build codec_json

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package handlers

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jeremyhahn/go-objstore/pkg/local"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/require"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// TestKey holds a test keypair and its JWK representation
type TestKey struct {
	PrivateKey crypto.Signer
	PublicKey  crypto.PublicKey
	JWK        *jose.JSONWebKey
}

// MockCA is a minimal mock Certificate Authority for testing.
// It implements ca.TCGCA.
type MockCA struct{}

// Compile-time assertion.
var _ ca.TCGCA = (*MockCA)(nil)

// crypto.Signer interface

func (m *MockCA) Public() crypto.PublicKey {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return key.Public()
}

func (m *MockCA) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return []byte("mock-signature"), nil
}

// Lifecycle

func (m *MockCA) Init() error         { return nil }
func (m *MockCA) Load() error         { return nil }
func (m *MockCA) IsInitialized() bool { return true }

// CSR / Issuance

func (m *MockCA) SignCSR(_ []byte, _ *ca.SignOptions) (*x509.Certificate, error) {
	return &x509.Certificate{}, nil
}

func (m *MockCA) CreateCSR(_ *ca.CertificateRequest) ([]byte, error) {
	return []byte("mock-csr-pem"), nil
}

func (m *MockCA) IssueCertificate(_ *ca.CertificateRequest) (*ca.IssuedCertificate, error) {
	return &ca.IssuedCertificate{}, nil
}

func (m *MockCA) IssueCertificateWithProfile(_ *ca.CertificateRequest, _ string) (*ca.IssuedCertificate, error) {
	return &ca.IssuedCertificate{}, nil
}

// Trust Chain

func (m *MockCA) CACertificate() (*x509.Certificate, error) { return &x509.Certificate{}, nil }
func (m *MockCA) CABundle() ([]byte, error)                 { return []byte("mock-bundle"), nil }

func (m *MockCA) Verify(_ *x509.Certificate, _ ...crypto.Signer) ([][]*x509.Certificate, error) {
	return [][]*x509.Certificate{}, nil
}

func (m *MockCA) TrustedRoot() (*x509.Certificate, error)         { return &x509.Certificate{}, nil }
func (m *MockCA) TrustedIntermediate() (*x509.Certificate, error) { return nil, nil }

// Revocation

func (m *MockCA) Revoke(_ *big.Int, _ int) error                           { return nil }
func (m *MockCA) RevokeCert(_ *x509.Certificate, _ ca.RevokeOptions) error { return nil }
func (m *MockCA) IsRevoked(_ *big.Int) (bool, error)                       { return false, nil }
func (m *MockCA) GenerateCRL() ([]byte, error)                             { return []byte("mock-crl-data"), nil }

// TLS

func (m *MockCA) TLSCertificate(_ *types.KeyAttributes) (tls.Certificate, error) {
	return tls.Certificate{}, nil
}
func (m *MockCA) TLSConfig(_ *types.KeyAttributes) (*tls.Config, error) { return &tls.Config{}, nil }
func (m *MockCA) QuantumSafeTLSConfig(_ *types.KeyAttributes) (*tls.Config, error) {
	return &tls.Config{}, nil
}
func (m *MockCA) TLSBundle(_ *types.KeyAttributes) ([]byte, error) {
	return []byte("mock-tls-bundle"), nil
}
func (m *MockCA) TLSBundleWithCrossSigner(_ *types.KeyAttributes, _ crypto.Signer) ([]byte, error) {
	return []byte("mock-tls-bundle-xsigner"), nil
}
func (m *MockCA) TLSConfigWithXSigner(_ *types.KeyAttributes, _ crypto.Signer) (*tls.Config, error) {
	return &tls.Config{}, nil
}

// Trust Pool Builders

func (m *MockCA) TrustedRootCertPool(_ *x509.Certificate) (*x509.CertPool, error) {
	return x509.NewCertPool(), nil
}
func (m *MockCA) TrustedIntermediateCertPool(_ *x509.Certificate) (*x509.CertPool, error) {
	return x509.NewCertPool(), nil
}
func (m *MockCA) TrustedRootCertPoolWithXSigner(_ *x509.Certificate, _ crypto.Signer) (*x509.CertPool, error) {
	return x509.NewCertPool(), nil
}
func (m *MockCA) TrustedIntermediateCertPoolWithXSigner(_ *x509.Certificate, _ crypto.Signer) (*x509.CertPool, error) {
	return x509.NewCertPool(), nil
}
func (m *MockCA) CABundleCertPool() (*x509.CertPool, error) { return x509.NewCertPool(), nil }
func (m *MockCA) OSTrustStore() (*x509.CertPool, error)     { return x509.NewCertPool(), nil }

// Storage Access

func (m *MockCA) KeyStore() xkms.Backend         { return nil }
func (m *MockCA) CertStore() certstore.CertStore { return nil }

// Configuration

func (m *MockCA) Config() *ca.Identity { return nil }
func (m *MockCA) Identity() string     { return "Mock CA" }

// Signing Identity Accessors

func (m *MockCA) Signer() (crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return key, nil
}
func (m *MockCA) PrivateKey(_ *types.KeyAttributes) (crypto.PrivateKey, error) { return nil, nil }
func (m *MockCA) PubKey(_ *types.KeyAttributes) (crypto.PublicKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return key.Public(), nil
}
func (m *MockCA) SignedBlob(_ []byte) ([]byte, error) { return []byte("mock-signed-blob"), nil }

// Certificate Retrieval & Import

func (m *MockCA) Issued(_ string) (bool, error)                            { return false, nil }
func (m *MockCA) Exists(_ string, _ x509.PublicKeyAlgorithm) (bool, error) { return false, nil }
func (m *MockCA) Certificate(_ *types.KeyAttributes) (*x509.Certificate, error) {
	return &x509.Certificate{}, nil
}
func (m *MockCA) CertificatePEM(_ string) ([]byte, error)       { return []byte("mock-cert-pem"), nil }
func (m *MockCA) ImportCertificate(_ *x509.Certificate) error   { return nil }
func (m *MockCA) ImportCertificatePEM(_ string, _ []byte) error { return nil }
func (m *MockCA) PEM(_ *types.KeyAttributes) ([]byte, error)    { return []byte("mock-pem"), nil }

// Object Store Helpers

func (m *MockCA) Blob(_ []byte) ([]byte, error)       { return []byte("mock-blob"), nil }
func (m *MockCA) ImportBlob(_ []byte, _ []byte) error { return nil }

// Trust Chain Extensions

func (m *MockCA) ImportDistributionCRLs(_ *x509.Certificate) error { return nil }
func (m *MockCA) ImportIssuingCAs(_ *x509.Certificate) error       { return nil }
func (m *MockCA) ParseBundle(_ []byte) ([]*x509.Certificate, error) {
	return []*x509.Certificate{}, nil
}
func (m *MockCA) RootCertificate(_ *x509.Certificate) (*x509.Certificate, error) {
	return &x509.Certificate{}, nil
}

// Cross-Signing

func (m *MockCA) ImportXSignedCertificate(_ string, _ *x509.Certificate) error { return nil }
func (m *MockCA) XSignedCertificate(_ string, _ *types.KeyAttributes) (*x509.Certificate, error) {
	return &x509.Certificate{}, nil
}
func (m *MockCA) XSignedRootCertificate(_ string, _ *x509.Certificate) (*x509.Certificate, error) {
	return &x509.Certificate{}, nil
}
func (m *MockCA) XSignedIntermediateCertificates(_ string, _ *x509.Certificate) ([]*x509.Certificate, error) {
	return []*x509.Certificate{}, nil
}
func (m *MockCA) CrossSignedPEM(_ *types.KeyAttributes) ([]byte, error) { return []byte{}, nil }

// Attestation (TPM)

func (m *MockCA) ImportAttestation(_ *types.KeyAttributes, _ string, _ []byte) error     { return nil }
func (m *MockCA) ImportAttestationKeyCertificate(_ *types.KeyAttributes, _ []byte) error { return nil }
func (m *MockCA) ImportAttestationEventLog(_ *types.KeyAttributes, _ []byte) error       { return nil }
func (m *MockCA) ImportAttestationPCRs(_ *types.KeyAttributes, _ []byte) error           { return nil }
func (m *MockCA) ImportAttestationQuote(_ *types.KeyAttributes, _ []byte) error          { return nil }
func (m *MockCA) ImportLocalAttestation(_ *types.KeyAttributes, _ *tpm2.Quote) error     { return nil }
func (m *MockCA) VerifyAttestationQuote(_ *types.KeyAttributes, _ []byte) error          { return nil }
func (m *MockCA) VerifyAttestationEventLog(_ *types.KeyAttributes, _ []byte) error       { return nil }
func (m *MockCA) VerifyAttestationPCRs(_ *types.KeyAttributes, _ []byte) error           { return nil }

// TCG Enrollment Verification

func (m *MockCA) VerifyTCG_CSR_IDevIDBytes(_ []byte, _ x509.SignatureAlgorithm) ([]byte, []byte, []byte, error) {
	return []byte("mock-credential-blob"), []byte("mock-encrypted-secret"), []byte("mock-secret"), nil
}

// Configuration & Metadata

func (m *MockCA) CAKeyAttributes(_ types.StoreType) (*types.KeyAttributes, error) {
	return &types.KeyAttributes{CN: "Mock CA"}, nil
}
func (m *MockCA) CASigner(_ types.StoreType, _ x509.PublicKeyAlgorithm) (crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return key, nil
}
func (m *MockCA) CAConfig() ca.CAConfig {
	return ca.CAConfig{
		DefaultCertValidityDays: 365,
	}
}
func (m *MockCA) DefaultKeyAlgorithm() x509.PublicKeyAlgorithm       { return x509.ECDSA }
func (m *MockCA) DefaultSignatureAlgorithm() x509.SignatureAlgorithm { return x509.ECDSAWithSHA256 }
func (m *MockCA) DefaultValidityPeriod() int                         { return 365 }
func (m *MockCA) Hash() crypto.Hash                                  { return crypto.SHA256 }
func (m *MockCA) IssuingIdentity() ca.Identity                       { return ca.Identity{} }
func (m *MockCA) IsAutoImportingIssuerCAs() bool                     { return false }

// Extended Revocation & Filtered Bundle

func (m *MockCA) CABundleFiltered(_ types.StoreType, _ x509.PublicKeyAlgorithm) ([]byte, error) {
	return []byte("mock-bundle"), nil
}

// TCGCA extensions

func (m *MockCA) IssueEKCertificate(_ *ca.CertificateRequest, _ crypto.PublicKey) (*x509.Certificate, error) {
	return &x509.Certificate{}, nil
}
func (m *MockCA) IssueAKCertificate(_ *ca.CertificateRequest, _ crypto.PublicKey) (*x509.Certificate, error) {
	return &x509.Certificate{}, nil
}
func (m *MockCA) SignTCGCSRIDevID(_ *tpm2.TCG_CSR_IDEVID, _ *ca.CertificateRequest) ([]byte, []byte, error) {
	return []byte("mock-iak"), []byte("mock-idevid"), nil
}
func (m *MockCA) EnrollDevice(_ []byte, _ *ca.CertificateRequest) (*ca.TCGEnrollmentResult, error) {
	return &ca.TCGEnrollmentResult{}, nil
}
func (m *MockCA) SetTPM(_ tpm2.TrustedPlatformModule)                               {}
func (m *MockCA) VerifyQuote(_ *types.KeyAttributes, _ *tpm2.Quote, _ []byte) error { return nil }
func (m *MockCA) ImportEndorsementKeyCertificate(_ *x509.Certificate) error         { return nil }
func (m *MockCA) EndorsementKeyCertificate(_ string) (*x509.Certificate, error) {
	return &x509.Certificate{}, nil
}

// setupTestService creates a test ACME REST service with a temporary storage backend
func setupTestService(t *testing.T) (*RestService, string, func()) {
	tmpDir, err := os.MkdirTemp("", "acme-handler-test-*")
	require.NoError(t, err)

	store := local.New()
	err = store.Configure(map[string]string{"path": tmpDir})
	require.NoError(t, err)

	factory, err := objstore.NewFactory(store)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError, // Reduce noise in tests
	}))

	params := &Params{
		BaseRESTURI:    "https://acme.test.example.com",
		CA:             &MockCA{},
		CAAIdentities:  []string{"acme.test.example.com"},
		ChallengeMap:   make(map[string]common.ChallengeVerifierFunc),
		Logger:         logger,
		StorageFactory: factory,
		TermsOfService: "https://acme.test.example.com/tos",
	}

	service, err := NewRestService(params)
	require.NoError(t, err)

	cleanup := func() {
		_ = os.RemoveAll(tmpDir)
	}

	return service.(*RestService), tmpDir, cleanup
}

// generateTestKey creates a test ECDSA key pair and its JWK representation
func generateTestKey(t *testing.T) *TestKey {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwk := &jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     "",
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}

	return &TestKey{
		PrivateKey: privateKey,
		PublicKey:  privateKey.Public(),
		JWK:        jwk,
	}
}

// createJWSRequest creates a signed JWS request for testing
func createJWSRequest(t *testing.T, service *RestService, key *TestKey, url string, payload interface{}, useKID bool, accountID uint64) *http.Request {
	// Get a valid nonce
	nonce, err := common.GenerateNonce(nonceSize)
	require.NoError(t, err)
	service.nonceStore.Add(nonce)

	// Marshal payload
	var payloadBytes []byte
	if payload != nil {
		payloadBytes, err = json.Marshal(payload)
		require.NoError(t, err)
	} else {
		// For POST-as-GET, use empty string payload, not nil
		payloadBytes = []byte("")
	}

	// Create signer options
	signerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: nonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
		},
	}

	if useKID {
		// Use KID for existing account
		signerOpts.ExtraHeaders["kid"] = fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, accountID)
	} else {
		// Use JWK for new account - embed the public key
		signerOpts.EmbedJWK = true
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key.PrivateKey,
	}, signerOpts)
	require.NoError(t, err)

	// Sign the payload
	jws, err := signer.Sign(payloadBytes)
	require.NoError(t, err)

	// Serialize to full format (not compact, since ACME uses full JSON serialization)
	serialized := jws.FullSerialize()

	// Create HTTP request with JWS body
	req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(serialized))
	req.Header.Set("Content-Type", "application/jose+json")

	return req
}

// staticNonceSource provides a static nonce for testing
type staticNonceSource struct {
	nonce string
}

func (s *staticNonceSource) Nonce() (string, error) {
	return s.nonce, nil
}

// createTestAccount creates and saves a test account
func createTestAccount(t *testing.T, service *RestService, key *TestKey) *entities.ACMEAccount {
	ctx := context.Background()

	// Get account DAO
	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	// Serialize public key
	pubKeyPEM, err := xkmssdk.EncodePublicKeyPEM(key.PublicKey)
	require.NoError(t, err)

	// Generate account ID
	accountID, err := AccountIDFromPublicKey(key.PublicKey)
	require.NoError(t, err)

	// Create account
	account := &entities.ACMEAccount{
		ID:                   accountID,
		Status:               common.StatusValid,
		Contact:              []string{"mailto:test@example.com"},
		TermsOfServiceAgreed: true,
		Key:                  string(pubKeyPEM),
		CreatedAt:            time.Now(),
		Orders:               fmt.Sprintf("%s/acme/account/%d/orders", service.baseRESTURI, accountID),
		URL:                  fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, accountID),
	}

	// Save account
	err = accountDAO.Save(ctx, account)
	require.NoError(t, err)

	return account
}

// createTestOrderSimple creates and saves a simple test order for an account
func createTestOrderSimple(t *testing.T, service *RestService, accountID uint64) *entities.ACMEOrder {
	ctx := context.Background()

	// Get order DAO
	orderDAO, err := service.storageFactory.OrderDAO(accountID)
	require.NoError(t, err)

	// Generate order ID
	orderID, err := GenerateID()
	require.NoError(t, err)

	// Create order
	order := &entities.ACMEOrder{
		ID:     orderID,
		Status: common.StatusPending,
		Identifiers: []entities.ACMEIdentifier{
			{Type: "dns", Value: "example.com"},
		},
		Expires:        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		Authorizations: []string{fmt.Sprintf("%s/acme/authz/1", service.baseRESTURI)},
		Finalize:       fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, orderID),
		AccountID:      accountID,
	}

	// Set the URL
	order.URL = fmt.Sprintf("%s/acme/orders/%d", service.baseRESTURI, order.ID)

	// Save order
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	return order
}

// parseErrorResponse parses an ACME error from an HTTP response
func parseErrorResponse(t *testing.T, resp *httptest.ResponseRecorder) *entities.Error {
	var acmeError entities.Error
	err := json.NewDecoder(resp.Body).Decode(&acmeError)
	require.NoError(t, err)
	return &acmeError
}

// assertErrorType checks that the response contains an ACME error of the expected type
func assertErrorType(t *testing.T, resp *httptest.ResponseRecorder, expectedType string, expectedStatus int) {
	require.Equal(t, expectedStatus, resp.Code, "HTTP status code mismatch")
	require.Equal(t, "application/problem+json", resp.Header().Get("Content-Type"), "Content-Type should be application/problem+json")

	acmeError := parseErrorResponse(t, resp)
	// Error type should be the full URN
	expectedFullType := "urn:ietf:params:acme:error:" + expectedType
	require.Equal(t, expectedFullType, acmeError.Type, "Error type mismatch")
}

// createInvalidJWSRequest creates an HTTP request with invalid JWS (for testing error handling)
func createInvalidJWSRequest(t *testing.T, url string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString("invalid-jws"))
	req.Header.Set("Content-Type", "application/jose+json")
	return req
}

// compile-time checks to silence unused warnings
var (
	_ = createTestOrderForHandler
	_ = createTestOrder
)

// createTestOrderForHandler creates and saves a simple test order for an account (alias for createTestOrderSimple)
func createTestOrderForHandler(t *testing.T, service *RestService, accountID uint64) *entities.ACMEOrder {
	return createTestOrderSimple(t, service, accountID)
}

// createTestOrder creates and saves a test order with specific identifiers
func createTestOrder(t *testing.T, service *RestService, account *entities.ACMEAccount, identifiers []entities.ACMEIdentifier) *entities.ACMEOrder {
	ctx := context.Background()

	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)

	order := &entities.ACMEOrder{
		Status:      common.StatusPending,
		Expires:     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		Identifiers: identifiers,
		AccountID:   account.ID,
	}

	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	// Update order with URLs
	order.URL = fmt.Sprintf("%s/acme/order/%d", service.baseRESTURI, order.ID)
	order.Finalize = fmt.Sprintf("%s/acme/finalize/%d", service.baseRESTURI, order.ID)

	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	return order
}

// createTestAuthorization creates and saves a test authorization with specific challenges
func createTestAuthorization(t *testing.T, service *RestService, account *entities.ACMEAccount, order *entities.ACMEOrder, identifier entities.ACMEIdentifier, challengeTypes []string) *entities.ACMEAuthorization {
	ctx := context.Background()

	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)

	// Generate authorization ID
	authzID, err := GenerateID()
	require.NoError(t, err)

	authz := &entities.ACMEAuthorization{
		ID:         authzID,
		Identifier: identifier,
		Status:     common.StatusPending,
		Expires:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		Wildcard:   false,
		AccountID:  account.ID,
		OrderID:    order.ID,
	}

	// Create challenges
	challenges := make([]entities.ACMEChallenge, 0, len(challengeTypes))
	for _, challengeType := range challengeTypes {
		// Generate challenge ID
		challengeID, err := GenerateID()
		require.NoError(t, err)

		challenge := entities.ACMEChallenge{
			ID:              challengeID,
			Type:            challengeType,
			Status:          common.StatusPending,
			Token:           fmt.Sprintf("test-token-%d", challengeID),
			AccountID:       account.ID,
			AuthorizationID: 0, // Will be set after authorization is saved
		}
		challenges = append(challenges, challenge)
	}

	authz.Challenges = challenges

	err = authzDAO.Save(ctx, authz)
	require.NoError(t, err)

	// Update challenges with authorization ID and URL
	for i := range authz.Challenges {
		authz.Challenges[i].AuthorizationID = authz.ID
		authz.Challenges[i].URL = fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[i].ID)
	}

	// Update authorization with URL
	authz.URL = fmt.Sprintf("%s/acme/authz/%d", service.baseRESTURI, authz.ID)

	err = authzDAO.Save(ctx, authz)
	require.NoError(t, err)

	// Update order with authorization URL
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)

	order.Authorizations = append(order.Authorizations, authz.URL)
	err = orderDAO.Save(ctx, order)
	require.NoError(t, err)

	return authz
}

// publicKeyToJOSEAlgorithm converts a public key to its corresponding JOSE signature algorithm
func publicKeyToJOSEAlgorithm(key interface{}) (jose.SignatureAlgorithm, error) {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		case elliptic.P521():
			return jose.ES512, nil
		default:
			return "", caerrors.MalformedError("unsupported ECDSA curve: %s", k.Curve.Params().Name)
		}
	case ecdsa.PublicKey:
		return publicKeyToJOSEAlgorithm(&k)
	case *rsa.PublicKey, rsa.PublicKey:
		return jose.RS256, nil
	case ed25519.PublicKey:
		return jose.EdDSA, nil
	default:
		return "", caerrors.MalformedError("unsupported key type: %T", key)
	}
}

// keyToID converts a key to a unique identifier string
func keyToID(key interface{}) (string, error) {
	jsonBytes, err := json.Marshal(key)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(jsonBytes)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// keyToString converts a key to a string identifier, ignoring errors
func keyToString(key interface{}) string {
	id, _ := keyToID(key)
	return id
}

// parseNextLinkHeaderFromRequest parses the next link from the Link header
func parseNextLinkHeaderFromRequest(req *http.Request) (int, error) {
	linkHeader := req.Header.Get("Link")
	if linkHeader == "" {
		return 0, caerrors.NotFoundError("next link not found in header")
	}

	// Parse multiple links separated by comma
	links := strings.Split(linkHeader, ",")
	for _, link := range links {
		link = strings.TrimSpace(link)

		// Check if this is a "next" rel
		if !strings.Contains(link, `rel="next"`) {
			continue
		}

		// Extract URL from angle brackets
		start := strings.Index(link, "<")
		end := strings.Index(link, ">")
		if start == -1 || end == -1 || start >= end {
			return 0, caerrors.MalformedError("invalid URL format in Link header")
		}

		urlStr := link[start+1 : end]

		// Parse the URL
		parsedURL, err := url.Parse(urlStr)
		if err != nil {
			return 0, caerrors.MalformedError("invalid URL in Link header: %v", err)
		}

		// Extract the last path segment as ID
		pathParts := strings.Split(strings.TrimSuffix(parsedURL.Path, "/"), "/")
		if len(pathParts) == 0 {
			return 0, caerrors.MalformedError("invalid ID in URL path")
		}

		idStr := pathParts[len(pathParts)-1]
		id, err := strconv.Atoi(idStr)
		if err != nil {
			return 0, caerrors.MalformedError("invalid ID in URL: %v", err)
		}

		return id, nil
	}

	return 0, caerrors.NotFoundError("next link not found in header")
}
