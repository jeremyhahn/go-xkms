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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash"

	"github.com/go-jose/go-jose/v4"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
)

var (
	// ErrInvalidExternalAccountBinding is returned when the external account binding is malformed
	ErrInvalidExternalAccountBinding = errors.New("handlers: invalid external account binding")

	// ErrExternalAccountBindingVerificationFailed is returned when MAC verification fails
	ErrExternalAccountBindingVerificationFailed = errors.New("handlers: external account binding verification failed")

	// ErrUnsupportedMACAlgorithm is returned for unsupported MAC algorithms
	ErrUnsupportedMACAlgorithm = errors.New("handlers: unsupported MAC algorithm")

	// ErrExternalAccountBindingKeyMismatch is returned when the payload doesn't match the account key
	ErrExternalAccountBindingKeyMismatch = errors.New("handlers: external account binding key mismatch")

	// ErrExternalAccountBindingURLMismatch is returned when the URL in the binding doesn't match
	ErrExternalAccountBindingURLMismatch = errors.New("handlers: external account binding URL mismatch")

	// ErrExternalAccountBindingNoncePresent is returned when nonce is present in EAB protected header
	// Per RFC 8555 Section 7.3.4: The JWS protected header MUST NOT include nonce
	ErrExternalAccountBindingNoncePresent = errors.New("handlers: external account binding must not include nonce")
)

// ExternalAccountBindingVerifier verifies external account binding JWS per RFC 8555 Section 7.3.4.
type ExternalAccountBindingVerifier struct {
	eabDAO        qrdbsdk.GenericDAO[*entities.ExternalAccountBinding]
	newAccountURL string
}

// NewExternalAccountBindingVerifier creates a new verifier instance.
func NewExternalAccountBindingVerifier(
	eabDAO qrdbsdk.GenericDAO[*entities.ExternalAccountBinding],
	newAccountURL string,
) *ExternalAccountBindingVerifier {
	return &ExternalAccountBindingVerifier{
		eabDAO:        eabDAO,
		newAccountURL: newAccountURL,
	}
}

// Verify verifies an external account binding JWS and returns the binding entity.
// Per RFC 8555 Section 7.3.4, the verification steps are:
// 1. Verify that the value of the field is a well-formed JWS
// 2. Verify that the JWS protected field meets the criteria (alg is symmetric, kid matches, url matches)
// 3. Verify that the "kid" field of the JWS protected header is set to the key identifier
// 4. Verify that the value of the JWS payload is the JWK representing the account key
// 5. Verify the signature using the MAC key corresponding to the key identifier
func (v *ExternalAccountBindingVerifier) Verify(
	ctx context.Context,
	eabJWS interface{},
	accountJWK *jose.JSONWebKey,
) (*entities.ExternalAccountBinding, error) {
	// Convert the interface{} to the expected structure
	eabData, err := json.Marshal(eabJWS)
	if err != nil {
		return nil, caerrors.SerializationFailureError("failed to marshal EAB JWS: %v", err)
	}

	var jws entities.ExternalAccountBindingJWS
	if err := json.Unmarshal(eabData, &jws); err != nil {
		return nil, caerrors.SerializationFailureError("failed to unmarshal EAB JWS: %v", err)
	}

	// Step 1 & 2: Parse and verify the protected header
	protectedBytes, err := base64.RawURLEncoding.DecodeString(jws.Protected)
	if err != nil {
		return nil, caerrors.MalformedError("failed to decode protected header: %v", err)
	}

	var header entities.ExternalAccountBindingProtectedHeader
	if err := json.Unmarshal(protectedBytes, &header); err != nil {
		return nil, caerrors.SerializationFailureError("failed to unmarshal protected header: %v", err)
	}

	// Per RFC 8555 Section 7.3.4: The JWS protected field MUST NOT include nonce
	if header.Nonce != "" {
		return nil, caerrors.MalformedError("external account binding must not include nonce")
	}

	// Verify the algorithm is symmetric (HS256, HS384, or HS512)
	if !isSymmetricAlgorithm(header.Alg) {
		return nil, caerrors.MalformedError(
			"algorithm must be symmetric (HS256, HS384, HS512), got %s", header.Alg)
	}

	// Verify the URL matches the newAccount URL
	if header.URL != v.newAccountURL {
		return nil, caerrors.UnauthorizedError(
			"EAB URL mismatch: expected %s, got %s", v.newAccountURL, header.URL)
	}

	// Step 3: Look up the binding by key identifier
	binding, err := v.eabDAO.Get(ctx, entities.StringToEntityID(header.KID))
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			return nil, caerrors.NotFoundError("EAB key identifier %s not found", header.KID)
		}
		return nil, caerrors.StorageFailureError("failed to retrieve binding: %v", err)
	}

	// Verify binding is usable
	if !binding.CanBeUsed() {
		if binding.IsExpired() {
			return nil, storage.ErrExternalAccountBindingExpired
		}
		if binding.Status == entities.EABStatusUsed {
			return nil, storage.ErrExternalAccountBindingUsed
		}
		if binding.Status == entities.EABStatusRevoked {
			return nil, storage.ErrExternalAccountBindingRevoked
		}
		return nil, caerrors.UnauthorizedError("binding status is %s", binding.Status)
	}

	// Verify the algorithm matches the binding's configured algorithm
	if binding.MACAlgorithm != "" && binding.MACAlgorithm != header.Alg {
		return nil, caerrors.MalformedError(
			"algorithm mismatch: expected %s, got %s", binding.MACAlgorithm, header.Alg)
	}

	// Step 4: Verify the payload is the account JWK
	payloadBytes, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		return nil, caerrors.MalformedError("failed to decode payload: %v", err)
	}

	// Verify the payload matches the account JWK
	accountJWKBytes, err := json.Marshal(accountJWK)
	if err != nil {
		return nil, caerrors.SerializationFailureError("failed to marshal account JWK: %v", err)
	}

	// Normalize both JWKs for comparison (unmarshal and remarshal to ensure consistent ordering)
	var payloadJWK, expectedJWK map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payloadJWK); err != nil {
		return nil, caerrors.SerializationFailureError("failed to unmarshal payload JWK: %v", err)
	}
	if err := json.Unmarshal(accountJWKBytes, &expectedJWK); err != nil {
		return nil, caerrors.SerializationFailureError("failed to unmarshal expected JWK: %v", err)
	}

	// Compare the JWK key material (not including optional fields like "use", "alg")
	if !jwkKeysMatch(payloadJWK, expectedJWK) {
		return nil, caerrors.UnauthorizedError("external account binding key mismatch")
	}

	// Step 5: Verify the MAC signature
	macKey, err := base64.RawURLEncoding.DecodeString(binding.MACKey)
	if err != nil {
		return nil, caerrors.MalformedError("failed to decode MAC key: %v", err)
	}

	signatureInput := jws.Protected + "." + jws.Payload
	if err := verifyMAC(header.Alg, macKey, []byte(signatureInput), jws.Signature); err != nil {
		return nil, caerrors.VerificationFailureError("EAB MAC verification failed: %v", err)
	}

	return binding, nil
}

// isSymmetricAlgorithm returns true if the algorithm is a symmetric MAC algorithm.
func isSymmetricAlgorithm(alg string) bool {
	switch alg {
	case "HS256", "HS384", "HS512":
		return true
	default:
		return false
	}
}

// verifyMAC verifies a MAC signature using the specified algorithm.
func verifyMAC(alg string, key []byte, message []byte, signatureB64 string) error {
	var h func() hash.Hash
	switch alg {
	case "HS256":
		h = sha256.New
	case "HS384":
		h = sha512.New384
	case "HS512":
		h = sha512.New
	default:
		return caerrors.MalformedError("unsupported algorithm: %s", alg)
	}

	mac := hmac.New(h, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)

	signature, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return caerrors.MalformedError("failed to decode signature: %v", err)
	}

	if !hmac.Equal(expectedMAC, signature) {
		return caerrors.VerificationFailureError("MAC verification failed")
	}

	return nil
}

// jwkKeysMatch compares two JWKs to ensure they represent the same key.
// It compares the essential key material fields (kty, n, e for RSA; crv, x, y for EC; etc.)
func jwkKeysMatch(a, b map[string]interface{}) bool {
	// Key type must match
	aKty, aOk := a["kty"].(string)
	bKty, bOk := b["kty"].(string)
	if !aOk || !bOk || aKty != bKty {
		return false
	}

	switch aKty {
	case "RSA":
		// Compare n (modulus) and e (exponent)
		return a["n"] == b["n"] && a["e"] == b["e"]
	case "EC":
		// Compare crv (curve), x, and y
		return a["crv"] == b["crv"] && a["x"] == b["x"] && a["y"] == b["y"]
	case "OKP":
		// Compare crv and x for Ed25519
		return a["crv"] == b["crv"] && a["x"] == b["x"]
	default:
		// For unknown types, do a full comparison
		aBytes, _ := json.Marshal(a)
		bBytes, _ := json.Marshal(b)
		return string(aBytes) == string(bBytes)
	}
}

// CreateExternalAccountBinding creates a new external account binding with a generated MAC key.
// This is a helper function for CA administrators to provision enterprise account bindings.
func CreateExternalAccountBinding(kid, externalAccountID, algorithm string) (*entities.ExternalAccountBinding, error) {
	// Default algorithm is HS256 per RFC 8555
	if algorithm == "" {
		algorithm = "HS256"
	}

	if !isSymmetricAlgorithm(algorithm) {
		return nil, caerrors.MalformedError("unsupported MAC algorithm: %s", algorithm)
	}

	// Generate MAC key of appropriate size
	var keySize int
	switch algorithm {
	case "HS256":
		keySize = 32 // 256 bits
	case "HS384":
		keySize = 48 // 384 bits
	case "HS512":
		keySize = 64 // 512 bits
	}

	macKey := make([]byte, keySize)
	if _, err := rand.Read(macKey); err != nil {
		return nil, caerrors.KeyGenerationFailureError("failed to generate MAC key: %v", err)
	}

	return &entities.ExternalAccountBinding{
		ID:                kid,
		MACKey:            base64.RawURLEncoding.EncodeToString(macKey),
		MACAlgorithm:      algorithm,
		ExternalAccountID: externalAccountID,
		Status:            entities.EABStatusActive,
	}, nil
}
