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

//go:build local || integration

package integration

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-objstore/pkg/local"
	"github.com/jeremyhahn/go-xkms/pkg/acme/ca"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/require"
)

const (
	// TestNonceSize is the size of nonces used in tests
	TestNonceSize = 16

	// TestBaseURL is the base URL for the test ACME server
	TestBaseURL = "https://acme.test.example.com"

	// TestTOSURL is the terms of service URL for tests
	TestTOSURL = "https://acme.test.example.com/tos"
)

// TestServer represents a running test ACME server instance
type TestServer struct {
	Service        *handlers.RestService
	Server         *httptest.Server
	BaseURL        string
	TempDir        string
	KeyStore       xkmssdk.ServiceBackend // go-xkms KeyStore for key management
	Cleanup        func()
	storageFactory storage.Factory // storage factory for direct storage access in tests
}

// NewTestServer creates and starts an ACME server for integration testing.
// It uses in-memory storage (go-objstore local backend) and returns the server
// instance and URL for making requests. Uses a REAL CA, not mocks.
func NewTestServer(t *testing.T) *TestServer {
	// Reset any previous facade state to ensure clean test isolation
	xkmssdk.ServiceReset()

	// Create temporary directory for local storage
	tmpDir, err := os.MkdirTemp("", "acme-integration-test-*")
	require.NoError(t, err)

	// Create local storage backend for ACME objects
	store := local.New()
	err = store.Configure(map[string]string{"path": tmpDir})
	require.NoError(t, err)

	// Create storage factory for ACME storage
	factory, err := objstore.NewFactory(store)
	require.NoError(t, err)

	// Create go-xkms KeyStore with pkcs8 backend for key management
	keyStorage, err := xkmssdk.NewMemoryBackend()
	require.NoError(t, err)
	certStorage, err := xkmssdk.NewMemoryBackend()
	require.NoError(t, err)

	softwareBackend, err := xkmssdk.NewPKCS8Backend(&xkmssdk.PKCS8BackendConfig{
		KeyStorage: keyStorage,
	})
	require.NoError(t, err)

	keyStore, err := xkmssdk.NewServiceBackend(&xkmssdk.ServiceBackendConfig{
		Backend:     softwareBackend,
		CertStorage: certStorage,
	})
	require.NoError(t, err)

	// Initialize the XKMSFacade with the software backend
	// This is CRITICAL - the CA uses the facade to access keystores
	err = xkmssdk.ServiceInitialize(&xkmssdk.ServiceConfig{
		Backends: map[string]xkmssdk.ServiceBackend{
			"software": keyStore,
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	// Create cert adapter and certstore for CA
	certAdapter := xkmssdk.NewStorageCertAdapter(certStorage)
	certStore, err := xkmssdk.NewCertStore(&xkmssdk.CertStoreConfig{
		CertStorage: certAdapter,
	})
	require.NoError(t, err)

	// Create blob store using go-objstore for CA
	blobStore := local.New()
	err = blobStore.Configure(map[string]string{"path": tmpDir + "/blobs"})
	require.NoError(t, err)

	// Create REAL CA configuration - software backend only
	caConfig := ca.Config{
		HomeDir: tmpDir,
		Identity: []ca.Identity{
			{
				Subject: ca.Subject{
					CommonName:   "Test Root CA",
					Organization: "Test Organization",
					Country:      "US",
				},
				Valid:        10,
				KeyAlgorithm: x509.ECDSA,
				ECCCurve:     "P256",
				KeystoreType: "software",
				IsRoot:       true,
			},
			{
				Subject: ca.Subject{
					CommonName:   "Test Intermediate CA",
					Organization: "Test Organization",
					Country:      "US",
				},
				Valid:        5,
				KeyAlgorithm: x509.ECDSA,
				ECCCurve:     "P256",
				KeystoreType: "software",
				ParentCA:     "Test Root CA",
			},
		},
		SelectedCA:                1,
		DefaultValidityPeriod:     365,
		DefaultKeyAlgorithm:       x509.ECDSA,
		DefaultSignatureAlgorithm: x509.ECDSAWithSHA256,
		DefaultHash:               crypto.SHA256,
		LazyInitialization:        false,
	}

	// Create REAL CA instance
	realCA, err := ca.New(caConfig, certStore, blobStore)
	require.NoError(t, err)

	// Create logger (error level to reduce test noise)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	// Create HTTP test server first to get dynamic URL
	router := mux.NewRouter()
	server := httptest.NewServer(router)

	// Create challenge map with verifiers for testing
	// These auto-succeed for integration tests - real E2E tests run in Docker
	challengeMap := make(map[string]common.ChallengeVerifierFunc)
	challengeMap["http-01"] = func(resolver *net.Resolver, caIntf common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}
	challengeMap["dns-01"] = func(resolver *net.Resolver, caIntf common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}
	challengeMap["enroll-01"] = func(resolver *net.Resolver, caIntf common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}
	challengeMap["endorse-01"] = func(resolver *net.Resolver, caIntf common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}
	challengeMap["device-attest-01"] = func(resolver *net.Resolver, caIntf common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}

	// Create service parameters with REAL CA
	params := &handlers.Params{
		BaseRESTURI:    server.URL,
		CA:             realCA,
		CAAIdentities:  []string{"acme.test.example.com"},
		ChallengeMap:   challengeMap,
		Logger:         logger,
		StorageFactory: factory,
		TermsOfService: server.URL + "/tos",
	}

	// Create REST service
	service, err := handlers.NewRestService(params)
	require.NoError(t, err)

	// Register ACME endpoints
	router.HandleFunc("/acme/directory", service.DirectoryHandler)
	router.HandleFunc("/acme/new-nonce", service.NewNonceHandler)
	router.HandleFunc("/acme/new-account", service.NewAccountHandler)
	router.HandleFunc("/acme/new-order", service.NewOrderHandler)
	router.HandleFunc("/acme/account/{id:[0-9]+}", service.AccountHandler)
	router.HandleFunc("/acme/account/{id:[0-9]+}/orders", service.OrdersListHandler)
	router.HandleFunc("/acme/order/{id:[0-9]+}", service.OrderHandler)
	router.HandleFunc("/acme/order/{id:[0-9]+}/finalize", service.OrderFinalizeHandler)
	router.HandleFunc("/acme/authz/{id:[0-9]+}", service.AuthorizationHandler)
	router.HandleFunc("/acme/challenge/{id:[0-9]+}", service.ChallengeHandler)
	router.HandleFunc("/acme/cert/{id:[0-9]+}", service.CertificateHandler)
	router.HandleFunc("/acme/revoke-cert", service.RevokeCertHandler)
	router.HandleFunc("/acme/key-change", service.KeyChangeHandler)
	router.HandleFunc("/acme/ca-bundle", service.CABundleHandler)

	cleanup := func() {
		server.Close()
		keyStore.Close()
		xkmssdk.ServiceReset()
		os.RemoveAll(tmpDir)
	}

	return &TestServer{
		Service:        service.(*handlers.RestService),
		Server:         server,
		BaseURL:        server.URL,
		TempDir:        tmpDir,
		KeyStore:       keyStore,
		Cleanup:        cleanup,
		storageFactory: factory,
	}
}

// GetNonce fetches a fresh nonce from the real ACME server
func GetNonce(t *testing.T, serverURL string) string {
	resp, err := http.Head(serverURL + "/acme/new-nonce")
	require.NoError(t, err)
	defer resp.Body.Close()

	nonce := resp.Header.Get("Replay-Nonce")
	require.NotEmpty(t, nonce, "Server must return a Replay-Nonce header")

	return nonce
}

// staticNonceSource provides a static nonce for JWS signing
type staticNonceSource struct {
	nonce string
}

func (s *staticNonceSource) Nonce() (string, error) {
	return s.nonce, nil
}

// CreateJWS creates a signed JWS message using go-jose.
// This function uses a crypto.Signer to sign the payload.
//
// Parameters:
//   - key: The signer to use (must implement crypto.Signer)
//   - nonce: The replay nonce from the server
//   - url: The URL being requested
//   - payload: The payload to sign (will be JSON marshaled)
//   - useKID: If true, use KID in header; if false, embed JWK
//   - kidURL: The KID URL (account URL) if useKID is true
func CreateJWS(t *testing.T, key crypto.Signer, nonce, url string, payload interface{}, useKID bool, kidURL string) string {
	// Marshal payload
	var payloadBytes []byte
	var err error

	if payload != nil {
		payloadBytes, err = json.Marshal(payload)
		require.NoError(t, err)
	} else {
		// For POST-as-GET, use empty string payload
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
		signerOpts.ExtraHeaders["kid"] = kidURL
	} else {
		// Use JWK for new account - embed the public key
		signerOpts.EmbedJWK = true
	}

	// Determine the appropriate signing algorithm based on key type
	var alg jose.SignatureAlgorithm
	switch key.Public().(type) {
	case *ecdsa.PublicKey:
		alg = jose.ES256
	default:
		t.Fatalf("Unsupported key type: %T", key)
	}

	// Create signer
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: alg,
		Key:       key,
	}, signerOpts)
	require.NoError(t, err)

	// Sign the payload
	jws, err := signer.Sign(payloadBytes)
	require.NoError(t, err)

	// Serialize to full JSON format (ACME uses full serialization)
	serialized := jws.FullSerialize()

	return serialized
}

// CreateTestAccount creates a new ACME account using the real server.
// It generates a new key using go-xkms, creates the account,
// and returns the signer and account URL.
func CreateTestAccount(t *testing.T, serverURL string, email string) (crypto.Signer, string) {
	// Generate ECDSA key using go-xkms
	attrs := &xkmssdk.KeyAttributes{
		CN:           email,
		KeyType:      xkmssdk.KeyTypeTLS,
		StoreType:    xkmssdk.StoreSoftware,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &xkmssdk.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	// For testing, use the pkcs8 backend directly to get concrete key types (not opaque wrappers)
	// This is necessary because go-jose requires concrete types like *ecdsa.PrivateKey
	keyStorage, err := xkmssdk.NewMemoryBackend()
	require.NoError(t, err)
	backend, err := xkmssdk.NewPKCS8Backend(&xkmssdk.PKCS8BackendConfig{KeyStorage: keyStorage})
	require.NoError(t, err)
	defer backend.Close()

	// Generate key using backend directly - returns concrete *ecdsa.PrivateKey
	privateKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Type assert to *ecdsa.PrivateKey for go-jose compatibility
	ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
	require.True(t, ok, "Generated key must be *ecdsa.PrivateKey, got %T", privateKey)

	// ECDSA keys implement crypto.Signer
	signer := crypto.Signer(ecdsaKey)

	// Get a fresh nonce
	nonce := GetNonce(t, serverURL)

	// Create account payload
	accountPayload := map[string]interface{}{
		"termsOfServiceAgreed": true,
		"contact":              []string{"mailto:" + email},
	}

	// Create JWS for new account (uses embedded JWK, not KID)
	jwsBody := CreateJWS(t, signer, nonce, serverURL+"/acme/new-account", accountPayload, false, "")

	// Send request to server
	resp, err := http.Post(
		serverURL+"/acme/new-account",
		"application/jose+json",
		bytes.NewReader([]byte(jwsBody)),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Check response
	require.True(t, resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK,
		"Expected 200 or 201, got %d", resp.StatusCode)

	// Get account URL from Location header
	accountURL := resp.Header.Get("Location")
	require.NotEmpty(t, accountURL, "Server must return Location header with account URL")

	return signer, accountURL
}

// CreateTestOrder creates a new certificate order for the given domain.
// It requires an existing account (signer and account URL).
// Returns the order URL and authorization URLs.
func CreateTestOrder(t *testing.T, serverURL string, accountSigner crypto.Signer, accountURL, domain string) (string, []string) {
	// Get a fresh nonce
	nonce := GetNonce(t, serverURL)

	// Create order payload
	orderPayload := map[string]interface{}{
		"identifiers": []map[string]string{
			{
				"type":  "dns",
				"value": domain,
			},
		},
	}

	// Create JWS for new order (uses KID from existing account)
	jwsBody := CreateJWS(t, accountSigner, nonce, serverURL+"/acme/new-order", orderPayload, true, accountURL)

	// Send request to server
	resp, err := http.Post(
		serverURL+"/acme/new-order",
		"application/jose+json",
		bytes.NewReader([]byte(jwsBody)),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Check response
	require.Equal(t, http.StatusCreated, resp.StatusCode, "Expected 201 Created")

	// Get order URL from Location header
	orderURL := resp.Header.Get("Location")
	require.NotEmpty(t, orderURL, "Server must return Location header with order URL")

	// Parse response body to get authorizations
	var order entities.ACMEOrder
	err = json.NewDecoder(resp.Body).Decode(&order)
	require.NoError(t, err)

	return orderURL, order.Authorizations
}

// GenerateTestKey generates a new ECDSA P-256 key pair for testing.
// Returns a crypto.Signer that can be used directly with go-jose.
func GenerateTestKey(t *testing.T) crypto.Signer {
	attrs := &xkmssdk.KeyAttributes{
		CN:           "test-key",
		KeyType:      xkmssdk.KeyTypeTLS,
		StoreType:    xkmssdk.StoreSoftware,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &xkmssdk.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	// Get the global test server's keystore (or create a temporary one if not available)
	var keyStore xkmssdk.ServiceBackend
	if testServer != nil && testServer.KeyStore != nil {
		keyStore = testServer.KeyStore
	} else {
		// Create temporary keystore for this function
		keyStorage, err := xkmssdk.NewMemoryBackend()
		require.NoError(t, err)
		certStorage, err := xkmssdk.NewMemoryBackend()
		require.NoError(t, err)
		backend, err := xkmssdk.NewPKCS8Backend(&xkmssdk.PKCS8BackendConfig{KeyStorage: keyStorage})
		require.NoError(t, err)
		keyStore, err = xkmssdk.NewServiceBackend(&xkmssdk.ServiceBackendConfig{
			Backend:     backend,
			CertStorage: certStorage,
		})
		require.NoError(t, err)
		defer keyStore.Close()
	}

	privateKey, err := keyStore.GenerateECDSA(attrs)
	require.NoError(t, err)

	signer, ok := privateKey.(crypto.Signer)
	require.True(t, ok, "Generated key must implement crypto.Signer")

	return signer
}

// ComputeKeyAuthorization computes the key authorization for a challenge.
// Format: token.base64url(SHA256(JWK))
// This uses the server's JWKThumbprint implementation directly to ensure consistency.
func ComputeKeyAuthorization(t *testing.T, token string, publicKey crypto.PublicKey) string {
	thumbprint, err := handlers.JWKThumbprint(publicKey)
	require.NoError(t, err)
	return fmt.Sprintf("%s.%s", token, thumbprint)
}

// AccountIDFromPublicKey generates a deterministic account ID from a public key.
// This uses the server's implementation directly to ensure consistency.
func AccountIDFromPublicKey(t *testing.T, pubKey crypto.PublicKey) uint64 {
	id, err := handlers.AccountIDFromPublicKey(pubKey)
	require.NoError(t, err)
	return id
}

// Backward compatibility wrappers for existing tests

var (
	// testServerURL is the global server URL used by existing integration tests
	TestServerURL string

	// testServer is the global server instance used by existing integration tests
	testServer *TestServer
)

// NewACMEServer creates a new test ACME server (backward compatibility wrapper)
func NewACMEServer(t *testing.T) *TestServer {
	server := NewTestServer(t)
	testServer = server
	TestServerURL = server.BaseURL
	return server
}

// Stop stops the test server
func (ts *TestServer) Stop() {
	if ts.Cleanup != nil {
		ts.Cleanup()
	}
}

// StorageFactory returns the ACME storage factory for direct storage access in tests.
// This is useful for integration tests that need to manipulate storage directly.
func (ts *TestServer) StorageFactory() storage.Factory {
	return ts.storageFactory
}

// getNonce fetches a nonce from the global test server (backward compatibility)
func getNonce(t *testing.T) string {
	return GetNonce(t, TestServerURL)
}

// createJWS creates a JWS using the global test server (backward compatibility)
func createJWS(t *testing.T, key crypto.Signer, nonce, url string, payload interface{}, useKID bool, kidURL string) string {
	return CreateJWS(t, key, nonce, url, payload, useKID, kidURL)
}

// createTestAccount creates an account on the global test server (backward compatibility)
func createTestAccount(t *testing.T, email string) (crypto.Signer, string) {
	return CreateTestAccount(t, TestServerURL, email)
}

// createTestOrder creates an order on the global test server (backward compatibility)
func createTestOrder(t *testing.T, accountSigner crypto.Signer, accountURL, domain string) (string, []string) {
	return CreateTestOrder(t, TestServerURL, accountSigner, accountURL, domain)
}

// computeJWKThumbprint computes JWK thumbprint (backward compatibility wrapper)
// This uses the server's implementation directly to ensure consistency.
func computeJWKThumbprint(publicKey crypto.PublicKey) (string, error) {
	return handlers.JWKThumbprint(publicKey)
}

// EncodePublicKeyPEM encodes a public key to PEM format using go-xkms
func EncodePublicKeyPEM(t *testing.T, pubKey crypto.PublicKey) []byte {
	pemBytes, err := xkmssdk.EncodePublicKeyPEM(pubKey)
	require.NoError(t, err)
	return pemBytes
}

// DecodePublicKeyPEM decodes a PEM-encoded public key using go-xkms
func DecodePublicKeyPEM(t *testing.T, pemBytes []byte) crypto.PublicKey {
	pubKey, err := xkmssdk.DecodePublicKeyPEM(pemBytes)
	require.NoError(t, err)
	return pubKey
}

// WaitForChallengeValidation polls a challenge URL until it's validated or times out
func WaitForChallengeValidation(t *testing.T, serverURL string, accountSigner crypto.Signer, accountURL, challengeURL string, timeout time.Duration) entities.ACMEChallenge {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		// Get fresh nonce
		nonce := GetNonce(t, serverURL)

		// Create POST-as-GET request (nil payload)
		jwsBody := CreateJWS(t, accountSigner, nonce, challengeURL, nil, true, accountURL)

		// Send request
		resp, err := http.Post(
			challengeURL,
			"application/jose+json",
			bytes.NewReader([]byte(jwsBody)),
		)
		require.NoError(t, err)

		// Parse response
		var challenge entities.ACMEChallenge
		err = json.NewDecoder(resp.Body).Decode(&challenge)
		resp.Body.Close()
		require.NoError(t, err)

		// Check status
		if challenge.Status == common.StatusValid {
			return challenge
		}

		if challenge.Status == common.StatusInvalid {
			t.Fatalf("Challenge validation failed: %v", challenge.Error)
		}

		// Wait before retrying
		time.Sleep(500 * time.Millisecond)
	}

	t.Fatal("Timeout waiting for challenge validation")
	return entities.ACMEChallenge{}
}

// FetchOrder fetches an order from the server using POST-as-GET
func FetchOrder(t *testing.T, serverURL string, accountSigner crypto.Signer, accountURL, orderURL string) entities.ACMEOrder {
	// Get fresh nonce
	nonce := GetNonce(t, serverURL)

	// Create POST-as-GET request (nil payload)
	jwsBody := CreateJWS(t, accountSigner, nonce, orderURL, nil, true, accountURL)

	// Send request
	resp, err := http.Post(
		orderURL,
		"application/jose+json",
		bytes.NewReader([]byte(jwsBody)),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Logf("FetchOrder failed: status=%d, body=%s, url=%s", resp.StatusCode, string(bodyBytes), orderURL)
	}
	require.Equal(t, http.StatusOK, resp.StatusCode, "Expected 200 OK")

	// Parse response
	var order entities.ACMEOrder
	err = json.NewDecoder(resp.Body).Decode(&order)
	require.NoError(t, err)

	return order
}

// ParseErrorResponse parses an ACME error from an HTTP response
func ParseErrorResponse(t *testing.T, resp *http.Response) *entities.Error {
	var acmeError entities.Error
	err := json.NewDecoder(resp.Body).Decode(&acmeError)
	require.NoError(t, err)
	return &acmeError
}

// AssertACMEError verifies that an HTTP response contains an ACME error of the expected type
func AssertACMEError(t *testing.T, resp *http.Response, expectedType string, expectedStatus int) {
	require.Equal(t, expectedStatus, resp.StatusCode, "HTTP status code mismatch")
	require.Equal(t, "application/problem+json", resp.Header.Get("Content-Type"),
		"Content-Type should be application/problem+json")

	acmeError := ParseErrorResponse(t, resp)
	expectedFullType := "urn:ietf:params:acme:error:" + expectedType
	require.Equal(t, expectedFullType, acmeError.Type, "Error type mismatch")
}
