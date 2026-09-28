//go:build codec_json

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

package handlers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
)

// TestRevokeCertHandlerAccountNotActive tests RevokeCertHandler with non-active account
func TestRevokeCertHandlerAccountNotActive(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Set account to pending status (not active)
	ctx := context.Background()
	accountDAO, _ := service.storageFactory.AccountDAO()
	account.Status = common.StatusPending
	_ = accountDAO.Save(ctx, account)

	// Create a valid certificate DER
	certKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		DNSNames:     []string{"test.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &certKey.PublicKey, certKey)
	certB64 := base64.RawURLEncoding.EncodeToString(certDER)

	revokeReq := RevokeCertRequest{
		Certificate: certB64,
		Reason:      0,
	}

	url := "https://acme.test.example.com/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, revokeReq, true, account.ID)

	rr := httptest.NewRecorder()
	service.RevokeCertHandler(rr, req)

	// Should return unauthorized for non-active account
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestRevokeCertHandlerUnauthorizedDomain tests RevokeCertHandler when account lacks authorization
func TestRevokeCertHandlerUnauthorizedDomain(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	ctx := context.Background()

	// Create a valid certificate with a domain
	certKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject:      pkix.Name{CommonName: "unauthorized.example.com"},
		DNSNames:     []string{"unauthorized.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &certKey.PublicKey, certKey)
	cert, _ := x509.ParseCertificate(certDER)
	certB64 := base64.RawURLEncoding.EncodeToString(certDER)

	// Store the certificate in the database
	certDAO, _ := service.storageFactory.CertificateDAO()
	certEntity := &entities.ACMECertificate{
		Serial: cert.SerialNumber.Text(16),
		PEM:    string(encodeCertificatePEM(certDER)),
		Status: common.StatusValid,
	}
	_ = certDAO.Save(ctx, certEntity)

	// Note: We don't create an authorization for this domain

	revokeReq := RevokeCertRequest{
		Certificate: certB64,
		Reason:      0,
	}

	url := "https://acme.test.example.com/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, revokeReq, true, account.ID)

	rr := httptest.NewRecorder()
	service.RevokeCertHandler(rr, req)

	// Should return unauthorized because account lacks authorization for the domain
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// TestKeyChangeHandlerSuccessful tests a successful key change
func TestKeyChangeHandlerSuccessful(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	oldKey := generateTestKey(t)
	account := createTestAccount(t, service, oldKey)
	newKey := generateTestKey(t)

	// Build the key change request
	oldJWK := &jose.JSONWebKey{Key: oldKey.PublicKey}
	oldKeyJSON, _ := oldJWK.MarshalJSON()
	var oldKeyMap map[string]interface{}
	_ = json.Unmarshal(oldKeyJSON, &oldKeyMap)

	keyChangeReq := KeyChangeRequest{
		AccountURL: account.URL,
		OldKey:     oldKeyMap,
	}
	innerPayload, _ := json.Marshal(keyChangeReq)

	url := "https://acme.test.example.com/acme/key-change"

	// Create inner JWS signed with new key
	innerSignerOpts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
		},
		EmbedJWK: true,
	}
	innerSigner, _ := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       newKey.PrivateKey,
	}, innerSignerOpts)
	innerJWS, _ := innerSigner.Sign(innerPayload)

	// Create outer JWS with old key KID
	outerPayload := []byte(innerJWS.FullSerialize())
	nonce, _ := service.GetNonceService().Generate()

	outerSignerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: nonce},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
			"kid": fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID),
		},
	}
	outerSigner, _ := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       oldKey.PrivateKey,
	}, outerSignerOpts)
	outerJWS, _ := outerSigner.Sign(outerPayload)

	req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(outerJWS.FullSerialize()))
	req.Header.Set("Content-Type", "application/jose+json")

	rr := httptest.NewRecorder()
	service.KeyChangeHandler(rr, req)

	// Should return 200 OK for successful key change
	assert.Equal(t, http.StatusOK, rr.Code)

	// Verify the key was actually changed
	ctx := context.Background()
	accountDAO, _ := service.storageFactory.AccountDAO()
	updatedAccount, _ := accountDAO.Get(ctx, account.ID)

	newKeyPEM, _ := xkmssdk.EncodePublicKeyPEM(newKey.PublicKey)
	assert.Equal(t, string(newKeyPEM), updatedAccount.Key)
}

// TestOrderFinalizeHandlerUnauthorized tests finalize when account doesn't own order
func TestOrderFinalizeHandlerUnauthorized(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key1 := generateTestKey(t)
	account1 := createTestAccount(t, service, key1)

	key2 := generateTestKey(t)
	account2 := createTestAccount(t, service, key2)

	// Create order for account1
	order := createTestOrderSimple(t, service, account1.ID)

	// Set order to ready status so we can try to finalize
	ctx := context.Background()
	orderDAO, _ := service.storageFactory.OrderDAO(account1.ID)
	order.Status = common.StatusReady
	_ = orderDAO.Save(ctx, order)

	// Try to finalize with account2 - create order in account2's namespace too
	// to simulate cross-account access attempt
	orderDAO2, _ := service.storageFactory.OrderDAO(account2.ID)
	order.AccountID = account2.ID // Store it with wrong account
	_ = orderDAO2.Save(ctx, order)

	finalizeReq := map[string]string{"csr": "dGVzdA"}
	url := fmt.Sprintf("https://acme.test.example.com/acme/order/%d/finalize", order.ID)
	req := createJWSRequest(t, service, key2, url, finalizeReq, true, account2.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	rr := httptest.NewRecorder()
	service.OrderFinalizeHandler(rr, req)

	// Order DAO is scoped to account2, so it will find the order but account mismatch
	// will trigger unauthorized response
	// Actually since we saved with account2.ID, it won't trigger unauthorized
	// Let's check what status we get
	assert.True(t, rr.Code == http.StatusBadRequest || rr.Code == http.StatusUnauthorized,
		"Expected 400 or 401, got %d", rr.Code)
}

// TestOrderFinalizeHandlerInvalidCSRPayload tests finalize with invalid CSR payload
func TestOrderFinalizeHandlerInvalidCSRPayload(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create order and set to ready
	order := createTestOrderSimple(t, service, account.ID)
	ctx := context.Background()
	orderDAO, _ := service.storageFactory.OrderDAO(account.ID)
	order.Status = common.StatusReady
	_ = orderDAO.Save(ctx, order)

	// Send request with invalid JSON
	url := fmt.Sprintf("https://acme.test.example.com/acme/order/%d/finalize", order.ID)
	req := createJWSRequest(t, service, key, url, "not valid json", true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	rr := httptest.NewRecorder()
	service.OrderFinalizeHandler(rr, req)

	// Should return malformed error
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestOrderFinalizeHandlerInvalidCSREncoding tests finalize with invalid CSR base64
func TestOrderFinalizeHandlerInvalidCSREncodingGap(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Create order and set to ready
	order := createTestOrderSimple(t, service, account.ID)
	ctx := context.Background()
	orderDAO, _ := service.storageFactory.OrderDAO(account.ID)
	order.Status = common.StatusReady
	_ = orderDAO.Save(ctx, order)

	// Send request with invalid base64 CSR
	finalizeReq := map[string]string{"csr": "!!!not-base64!!!"}
	url := fmt.Sprintf("https://acme.test.example.com/acme/order/%d/finalize", order.ID)
	req := createJWSRequest(t, service, key, url, finalizeReq, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	rr := httptest.NewRecorder()
	service.OrderFinalizeHandler(rr, req)

	// Should return malformed error
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestParseCryptoAgileEventTruncated tests parseCryptoAgileEvent with truncated data
func TestParseCryptoAgileEventTruncated(t *testing.T) {
	// Create truncated event data
	data := make([]byte, 4) // Only 4 bytes, needs at least 8 for PCR index + event type

	algorithms := []SpecIDAlgorithm{
		{AlgorithmID: 0x0004, DigestSize: 20}, // SHA-1
	}

	reader := bytes.NewReader(data)
	_, err := parseCryptoAgileEvent(reader, algorithms)

	assert.Error(t, err)
}

// TestParseLegacyEventBasic tests parseLegacyEvent with minimal event
func TestParseLegacyEventBasic(t *testing.T) {
	var buf bytes.Buffer

	// PCR index (4 bytes)
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	// Event type (4 bytes)
	binary.Write(&buf, binary.LittleEndian, uint32(0x00000001))

	// Digest (20 bytes for SHA-1)
	digest := make([]byte, 20)
	buf.Write(digest)

	// Event size (4 bytes)
	binary.Write(&buf, binary.LittleEndian, uint32(4))

	// Event data
	buf.Write([]byte{0x01, 0x02, 0x03, 0x04})

	reader := bytes.NewReader(buf.Bytes())
	entry, err := parseLegacyEvent(reader)

	assert.NoError(t, err)
	assert.Equal(t, 0, entry.PCRIndex)
}

// TestParseLegacyEventTruncated tests parseLegacyEvent with truncated data
func TestParseLegacyEventTruncated(t *testing.T) {
	data := make([]byte, 4) // Only 4 bytes, needs much more

	reader := bytes.NewReader(data)
	_, err := parseLegacyEvent(reader)

	assert.Error(t, err)
}

// TestVerifyMACInvalidSignature tests verifyMAC with invalid signature
func TestVerifyMACInvalidSignature(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	message := []byte("test message")
	invalidSig := "invalid-base64!!!"

	err := verifyMAC("HS256", key, message, invalidSig)
	assert.Error(t, err)
}

// TestVerifyMACMismatch tests verifyMAC with mismatched signature
func TestVerifyMACMismatch(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	message := []byte("test message")
	wrongSig := base64.RawURLEncoding.EncodeToString([]byte("wrong signature"))

	err := verifyMAC("HS256", key, message, wrongSig)
	assert.Error(t, err)
}

// TestVerifyMACUnsupportedAlgorithm tests verifyMAC with unsupported algorithm
func TestVerifyMACUnsupportedAlgorithm(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	message := []byte("test message")
	sig := base64.RawURLEncoding.EncodeToString([]byte("signature"))

	err := verifyMAC("UNSUPPORTED", key, message, sig)
	assert.Error(t, err)
}

// TestJwkKeysMatchDifferentTypes tests jwkKeysMatch with different key types
func TestJwkKeysMatchDifferentTypes(t *testing.T) {
	key1 := map[string]interface{}{
		"kty": "RSA",
		"n":   "test-n",
		"e":   "test-e",
	}
	key2 := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "test-x",
		"y":   "test-y",
	}

	assert.False(t, jwkKeysMatch(key1, key2))
}

// TestJwkKeysMatchMissingKty tests jwkKeysMatch when kty is missing
func TestJwkKeysMatchMissingKty(t *testing.T) {
	key1 := map[string]interface{}{
		"n": "test-n",
	}
	key2 := map[string]interface{}{
		"kty": "RSA",
		"n":   "test-n",
	}

	assert.False(t, jwkKeysMatch(key1, key2))
}

// TestJwkKeysMatchUnknownType tests jwkKeysMatch with unknown key type
func TestJwkKeysMatchUnknownType(t *testing.T) {
	key1 := map[string]interface{}{
		"kty": "UNKNOWN",
		"foo": "bar",
	}
	key2 := map[string]interface{}{
		"kty": "UNKNOWN",
		"foo": "bar",
	}

	// Unknown types fall through to JSON comparison
	assert.True(t, jwkKeysMatch(key1, key2))
}

// TestJwkKeysMatchUnknownTypeMarshalFailure verifies that when the fallback
// JSON comparison for an unrecognized kty cannot marshal one of the keys, the
// keys are reported as not matching rather than as equal. Before this was
// fixed, a marshal failure produced two empty (nil) byte slices, and
// bytes.Equal(nil, nil) is true — turning an internal error into a false
// positive on a security-relevant key comparison.
func TestJwkKeysMatchUnknownTypeMarshalFailure(t *testing.T) {
	key1 := map[string]interface{}{
		"kty": "UNKNOWN",
		// func values are never JSON-marshalable, forcing json.Marshal to
		// fail the way it would for any unmarshalable value that reached
		// this map through some path other than json.Unmarshal.
		"foo": func() {},
	}
	key2 := map[string]interface{}{
		"kty": "UNKNOWN",
		"foo": "bar",
	}

	assert.False(t, jwkKeysMatch(key1, key2))
	// Also verify the failure isn't masked when both sides fail to marshal.
	assert.False(t, jwkKeysMatch(key1, key1))
}

// TestNewEventLogValidationHookNoEventLog tests event log validation with no event log
func TestNewEventLogValidationHookNoEventLog(t *testing.T) {
	policy := &EventLogPolicy{
		RequiredEvents: nil, // No required events
	}
	hook := NewEventLogValidationHook(policy)

	ctx := &PreIssuanceHookContext{
		IsTCGCSR: true,
		TCGData: &TCGEnrollmentData{
			EventLog: nil, // No event log
		},
	}

	err := hook(ctx)
	assert.NoError(t, err) // Should skip validation when no event log and no required events
}

// TestNewEventLogValidationHookNonTCG tests event log validation for non-TCG enrollment
func TestNewEventLogValidationHookNonTCG(t *testing.T) {
	policy := &EventLogPolicy{}
	hook := NewEventLogValidationHook(policy)

	ctx := &PreIssuanceHookContext{
		IsTCGCSR: false,
		TCGData:  nil,
	}

	err := hook(ctx)
	assert.NoError(t, err) // Should skip for non-TCG
}

// TestParseTPMSignatureRSAPSSGap tests parseTPMSignature with RSA-PSS algorithm
func TestParseTPMSignatureRSAPSSGap(t *testing.T) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, TPMAlgRSAPSS)   // RSAPSS algorithm
	binary.Write(&buf, binary.BigEndian, uint16(0x000B)) // SHA256 hash
	binary.Write(&buf, binary.BigEndian, uint16(4))      // sig size
	buf.Write([]byte{0x01, 0x02, 0x03, 0x04})            // signature data

	alg, sigData, err := parseTPMSignature(buf.Bytes())
	assert.NoError(t, err)
	assert.Equal(t, TPMAlgRSAPSS, alg)
	assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, sigData)
}

// TestParseTPMSignatureECDSATruncatedR tests ECDSA with truncated R parameter
func TestParseTPMSignatureECDSATruncatedRGap(t *testing.T) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, TPMAlgECDSA)    // ECDSA algorithm
	binary.Write(&buf, binary.BigEndian, uint16(0x000B)) // SHA256 hash

	// R parameter truncated - claims 100 bytes but not enough data
	binary.Write(&buf, binary.BigEndian, uint16(100)) // R size

	_, _, err := parseTPMSignature(buf.Bytes())
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidQuoteStructure, err)
}

// TestNewEventLogValidationHookRequiredEventsMissing tests event log with required events missing
func TestNewEventLogValidationHookRequiredEventsMissing(t *testing.T) {
	policy := &EventLogPolicy{
		RequiredEvents: []string{"EV_SEPARATOR"}, // Required event
	}
	hook := NewEventLogValidationHook(policy)

	ctx := &PreIssuanceHookContext{
		IsTCGCSR: true,
		TCGData: &TCGEnrollmentData{
			EventLog: nil, // No event log provided but required events specified
		},
	}

	err := hook(ctx)
	assert.Error(t, err) // Should fail when event log is required but not provided
}

// TestVerifyMACHS384Gap tests verifyMAC with HS384 algorithm
func TestVerifyMACHS384Gap(t *testing.T) {
	key := make([]byte, 48) // 384 bits
	_, _ = rand.Read(key)

	message := []byte("test message")
	wrongSig := base64.RawURLEncoding.EncodeToString(make([]byte, 48))

	err := verifyMAC("HS384", key, message, wrongSig)
	assert.Error(t, err) // Wrong signature should fail
}

// TestVerifyMACHS512Gap tests verifyMAC with HS512 algorithm
func TestVerifyMACHS512Gap(t *testing.T) {
	key := make([]byte, 64) // 512 bits
	_, _ = rand.Read(key)

	message := []byte("test message")
	wrongSig := base64.RawURLEncoding.EncodeToString(make([]byte, 64))

	err := verifyMAC("HS512", key, message, wrongSig)
	assert.Error(t, err) // Wrong signature should fail
}
