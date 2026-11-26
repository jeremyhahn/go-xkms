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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/stretchr/testify/assert"
)

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

// TestVerifyMACMismatch tests verifyMAC with mismatched signature
func TestVerifyMACMismatch(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	message := []byte("test message")
	wrongSig := base64.RawURLEncoding.EncodeToString([]byte("wrong signature"))

	err := verifyMAC("HS256", key, message, wrongSig)
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
