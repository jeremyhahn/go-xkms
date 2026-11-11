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
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server"
	"github.com/stretchr/testify/assert"
)

// TestEncodeJSONWithLoggerEncodingError tests encodeJSONWithLogger with unencodable value
func TestEncodeJSONWithLoggerEncodingError(t *testing.T) {
	rr := httptest.NewRecorder()

	// Create a channel which cannot be JSON encoded
	unencodable := make(chan int)

	// Should log error but not panic
	encodeJSONWithLogger(rr, unencodable, nil)
}

// TestRevokeCertHandlerDeactivatedAccount tests RevokeCertHandler with deactivated account
func TestRevokeCertHandlerDeactivatedAccount(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// Deactivate account
	ctx := context.Background()
	accountDAO, _ := service.storageFactory.AccountDAO()
	account.Status = common.StatusDeactivated
	_ = accountDAO.Save(ctx, account)

	// Try to revoke
	revokeReq := RevokeCertRequest{
		Certificate: "dGVzdA",
		Reason:      0,
	}

	url := "https://acme.test.example.com/acme/revoke-cert"
	req := createJWSRequest(t, service, key, url, revokeReq, true, account.ID)

	rr := httptest.NewRecorder()
	service.RevokeCertHandler(rr, req)

	// Should return bad request (parseKID fails for deactivated accounts)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestParseTPMSignatureInvalidECDSA tests parseTPMSignature with truncated ECDSA signature
func TestParseTPMSignatureInvalidECDSA(t *testing.T) {
	// Create truncated ECDSA signature
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, TPMAlgECDSA)    // sig algorithm
	binary.Write(&buf, binary.BigEndian, uint16(0x0004)) // hash
	// Missing R and S data
	_, _, err := parseTPMSignature(buf.Bytes())
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidQuoteStructure, err)
}

// TestKeyChangeHandlerInvalidInnerPayload tests key change with invalid inner payload
func TestKeyChangeHandlerInvalidInnerPayload(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	newKey := generateTestKey(t)
	url := "https://acme.test.example.com/acme/key-change"

	// Create inner JWS with invalid JSON payload
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
	innerJWS, _ := innerSigner.Sign([]byte("not valid json"))

	// Create outer JWS
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
		Key:       key.PrivateKey,
	}, outerSignerOpts)
	outerJWS, _ := outerSigner.Sign(outerPayload)

	req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(outerJWS.FullSerialize()))
	req.Header.Set("Content-Type", "application/jose+json")

	rr := httptest.NewRecorder()
	service.KeyChangeHandler(rr, req)

	// Should return malformed error (invalid inner payload)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// Helper to suppress unused variable warnings
var _ = server.AllowedJOSEAlgorithms
