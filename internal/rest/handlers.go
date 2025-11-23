// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package rest

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/encoding"
	"github.com/jeremyhahn/go-keychain/pkg/health"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/jeremyhahn/go-keychain/pkg/verification"
)

// HandlerContext holds dependencies for REST handlers.
type HandlerContext struct {
	// Version is the API version
	Version string
	// HealthChecker manages health check probes
	HealthChecker HealthChecker
}

// HealthChecker defines the interface for health checking.
type HealthChecker interface {
	Live(ctx context.Context) health.CheckResult
	Ready(ctx context.Context) []health.CheckResult
	Startup(ctx context.Context) health.CheckResult
}

// NewHandlerContext creates a new handler context.
// The handlers use the global keychain facade for backend management.
func NewHandlerContext(version string) *HandlerContext {
	return &HandlerContext{
		Version: version,
	}
}

// SetHealthChecker sets the health checker for the handler context.
func (h *HandlerContext) SetHealthChecker(checker HealthChecker) {
	h.HealthChecker = checker
}

// HealthHandler handles GET /health requests.
func (h *HandlerContext) HealthHandler(w http.ResponseWriter, r *http.Request) {
	resp := HealthResponse{
		Status:  "healthy",
		Version: h.Version,
	}
	writeJSON(w, resp, http.StatusOK)
}

// ListBackendsHandler handles GET /api/v1/backends requests.
func (h *HandlerContext) ListBackendsHandler(w http.ResponseWriter, r *http.Request) {
	backendNames := keychain.Backends()

	backends := make([]BackendInfo, 0, len(backendNames))
	for _, name := range backendNames {
		ks, err := keychain.Backend(name)
		if err != nil {
			continue // Skip backends that can't be retrieved
		}

		backend := ks.Backend()
		caps := backend.Capabilities()

		backends = append(backends, BackendInfo{
			ID:             name,
			Type:           string(backend.Type()),
			HardwareBacked: caps.HardwareBacked,
			Capabilities:   caps,
		})
	}

	resp := ListBackendsResponse{
		Backends: backends,
	}
	writeJSON(w, resp, http.StatusOK)
}

// GetBackendHandler handles GET /api/v1/backends/{id} requests.
func (h *HandlerContext) GetBackendHandler(w http.ResponseWriter, r *http.Request) {
	backendID := chi.URLParam(r, "id")
	if backendID == "" {
		writeError(w, ErrInvalidBackend, http.StatusBadRequest)
		return
	}

	ks, err := keychain.Backend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	backend := ks.Backend()
	caps := backend.Capabilities()

	info := BackendInfo{
		ID:             backendID,
		Type:           string(backend.Type()),
		HardwareBacked: caps.HardwareBacked,
		Capabilities:   caps,
	}

	writeJSON(w, info, http.StatusOK)
}

// GenerateKeyHandler handles POST /api/v1/keys requests.
func (h *HandlerContext) GenerateKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req GenerateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.KeyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	// Validate KeyID for security (prevent path traversal, injection)
	if err := ValidateKeyID(req.KeyID); err != nil {
		writeError(w, fmt.Errorf("invalid key ID: %w", err), http.StatusBadRequest)
		return
	}

	if req.Backend == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	// Validate backend name
	if err := ValidateBackendName(req.Backend); err != nil {
		writeError(w, fmt.Errorf("invalid backend: %w", err), http.StatusBadRequest)
		return
	}

	if req.KeyType == "" {
		writeError(w, ErrInvalidKeyType, http.StatusBadRequest)
		return
	}

	// Get the backend (this also validates it exists)
	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Parse key algorithm
	// Support both direct algorithm names (aes-256-gcm) and simple types (aes)
	keyType := strings.ToLower(req.KeyType)
	var keyAlgorithm x509.PublicKeyAlgorithm
	var symmetricAlgorithm types.SymmetricAlgorithm

	// Check if it's a simple "aes" request and use algorithm if provided
	if keyType == "aes" {
		if req.Algorithm == "" {
			// Default to AES-256-GCM if no algorithm specified
			symmetricAlgorithm = types.SymmetricAES256GCM
		} else {
			symmetricAlgorithm = types.SymmetricAlgorithm(strings.ToLower(req.Algorithm))
		}
	} else {
		// Try parsing as asymmetric algorithm
		keyAlgorithm, _ = types.ParseKeyAlgorithm(req.KeyType)
		if keyAlgorithm == x509.UnknownPublicKeyAlgorithm {
			// Try as symmetric algorithm
			symmetricAlgorithm = types.SymmetricAlgorithm(strings.ToLower(req.KeyType))
		}
	}

	// Build key attributes
	attrs := &types.KeyAttributes{
		CN:                 req.KeyID,
		KeyType:            types.KeyTypeSigning, // Default to signing
		StoreType:          types.StorePKCS8,     // Will be updated based on backend
		KeyAlgorithm:       keyAlgorithm,
		SymmetricAlgorithm: symmetricAlgorithm,
	}

	// Set hash algorithm if provided
	if req.Hash != "" {
		attrs.Hash = types.ParseHash(req.Hash)
		if attrs.Hash == 0 {
			attrs.Hash = crypto.SHA256 // Default if unknown
		}
	} else {
		attrs.Hash = crypto.SHA256 // Default
	}

	// Set algorithm-specific attributes
	var privKey crypto.PrivateKey
	var isSymmetric bool

	if symmetricAlgorithm != "" {
		// Symmetric key generation
		isSymmetric = true
		attrs.KeyType = types.KeyTypeEncryption

		// Get key size from algorithm
		var keySize int
		switch symmetricAlgorithm {
		case types.SymmetricAES128GCM:
			keySize = 128
		case types.SymmetricAES192GCM:
			keySize = 192
		case types.SymmetricAES256GCM:
			keySize = 256
		default:
			keySize = 256 // Default
		}

		attrs.AESAttributes = &types.AESAttributes{
			KeySize: keySize,
		}

		// Check if backend supports symmetric operations
		symBackend, ok := ks.Backend().(types.SymmetricBackend)
		if !ok {
			writeError(w, fmt.Errorf("backend does not support symmetric key generation"), http.StatusBadRequest)
			return
		}

		_, err = symBackend.GenerateSymmetricKey(attrs)
	} else {
		// Asymmetric key generation
		switch keyAlgorithm {
		case x509.RSA:
			keySize := req.KeySize
			if keySize == 0 {
				keySize = 2048 // Default RSA key size
			}
			attrs.RSAAttributes = &types.RSAAttributes{
				KeySize: keySize,
			}
			privKey, err = ks.GenerateRSA(attrs)

		case x509.ECDSA:
			curve := req.Curve
			if curve == "" {
				curve = "P256" // Default ECDSA curve
			}
			parsedCurve, _ := types.ParseCurve(curve)
			attrs.ECCAttributes = &types.ECCAttributes{
				Curve: parsedCurve,
			}
			privKey, err = ks.GenerateECDSA(attrs)

		case x509.Ed25519:
			privKey, err = ks.GenerateEd25519(attrs)

		default:
			writeError(w, ErrInvalidKeyType, http.StatusBadRequest)
			return
		}
	}

	if err != nil {
		log.Printf("Failed to generate key: %v", err)
		handleError(w, err)
		return
	}

	// Build response
	resp := GenerateKeyResponse{
		KeyID:   req.KeyID,
		KeyType: req.KeyType,
		Message: fmt.Sprintf("Key %s generated successfully", req.KeyID),
	}

	// Add public key PEM for asymmetric keys only
	if !isSymmetric && privKey != nil {
		pubKey := getPublicKey(privKey)
		if pubKey != nil {
			pubKeyPEM, err := encoding.EncodePublicKeyPEM(pubKey)
			if err != nil {
				log.Printf("Failed to encode public key: %v", err)
			} else {
				resp.PublicKeyPEM = string(pubKeyPEM)
			}
		}
	}

	writeJSON(w, resp, http.StatusCreated)
}

// ListKeysHandler handles GET /api/v1/keys requests.
func (h *HandlerContext) ListKeysHandler(w http.ResponseWriter, r *http.Request) {
	backendID := r.URL.Query().Get("backend")
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	ks, err := keychain.Backend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// List keys from backend
	keyAttrs, err := ks.ListKeys()
	if err != nil {
		log.Printf("Failed to list keys: %v", err)
		handleError(w, err)
		return
	}

	// Convert to KeyInfo
	keys := make([]KeyInfo, 0, len(keyAttrs))
	for _, attr := range keyAttrs {
		keyInfo := KeyInfo{
			KeyID:     attr.CN,
			KeyType:   string(attr.KeyType),
			Algorithm: getAlgorithmString(attr),
			Backend:   backendID,
		}

		// Try to get public key
		privKey, err := ks.GetKey(attr)
		if err == nil {
			pubKey := getPublicKey(privKey)
			if pubKey != nil {
				pubKeyPEM, err := encoding.EncodePublicKeyPEM(pubKey)
				if err == nil {
					keyInfo.PublicKeyPEM = string(pubKeyPEM)
				}
			}
		}

		keys = append(keys, keyInfo)
	}

	resp := ListKeysResponse{
		Keys: keys,
	}
	writeJSON(w, resp, http.StatusOK)
}

// GetKeyHandler handles GET /api/v1/keys/{id} requests.
func (h *HandlerContext) GetKeyHandler(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	backendID := r.URL.Query().Get("backend")
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	ks, err := keychain.Backend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// List all keys and find the matching one
	keyAttrs, err := ks.ListKeys()
	if err != nil {
		log.Printf("Failed to list keys: %v", err)
		handleError(w, err)
		return
	}

	// Find the key
	var targetAttr *types.KeyAttributes
	for _, attr := range keyAttrs {
		if attr.CN == keyID {
			targetAttr = attr
			break
		}
	}

	if targetAttr == nil {
		writeError(w, backend.ErrKeyNotFound, http.StatusNotFound)
		return
	}

	// Get the key
	privKey, err := ks.GetKey(targetAttr)
	if err != nil {
		log.Printf("Failed to get key: %v", err)
		handleError(w, err)
		return
	}

	// Build response
	resp := GetKeyResponse{
		KeyInfo: KeyInfo{
			KeyID:     targetAttr.CN,
			KeyType:   string(targetAttr.KeyType),
			Algorithm: getAlgorithmString(targetAttr),
			Backend:   backendID,
		},
	}

	// Add public key
	pubKey := getPublicKey(privKey)
	if pubKey != nil {
		pubKeyPEM, err := encoding.EncodePublicKeyPEM(pubKey)
		if err == nil {
			resp.PublicKeyPEM = string(pubKeyPEM)
		}
	}

	writeJSON(w, resp, http.StatusOK)
}

// SignHandler handles POST /api/v1/keys/{id}/sign requests.
func (h *HandlerContext) SignHandler(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	backendID := r.URL.Query().Get("backend")
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	ks, err := keychain.Backend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Find the key
	keyAttrs, err := ks.ListKeys()
	if err != nil {
		log.Printf("Failed to list keys: %v", err)
		handleError(w, err)
		return
	}

	var targetAttr *types.KeyAttributes
	for _, attr := range keyAttrs {
		if attr.CN == keyID {
			targetAttr = attr
			break
		}
	}

	if targetAttr == nil {
		writeError(w, backend.ErrKeyNotFound, http.StatusNotFound)
		return
	}

	// Get signer
	signer, err := ks.Signer(targetAttr)
	if err != nil {
		log.Printf("Failed to get signer: %v", err)
		handleError(w, err)
		return
	}

	// Unmarshal data
	var data []byte
	if err := json.Unmarshal(req.Data, &data); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	// Parse hash algorithm
	hashAlg := crypto.SHA256
	if req.Hash != "" {
		hashAlg = types.ParseHash(req.Hash)
		if hashAlg == 0 {
			hashAlg = crypto.SHA256 // Default if unknown
		}
	}

	// Sign the data
	cryptoHash := hashAlg
	hasher := cryptoHash.New()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	signature, err := signer.Sign(nil, digest, cryptoHash)
	if err != nil {
		log.Printf("Failed to sign data: %v", err)
		handleError(w, err)
		return
	}

	// Build response
	resp := SignResponse{
		Signature: signature,
		Algorithm: getAlgorithmString(targetAttr),
	}
	writeJSON(w, resp, http.StatusOK)
}

// VerifyHandler handles POST /api/v1/keys/{id}/verify requests.
func (h *HandlerContext) VerifyHandler(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	backendID := r.URL.Query().Get("backend")
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	ks, err := keychain.Backend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Find the key
	keyAttrs, err := ks.ListKeys()
	if err != nil {
		log.Printf("Failed to list keys: %v", err)
		handleError(w, err)
		return
	}

	var targetAttr *types.KeyAttributes
	for _, attr := range keyAttrs {
		if attr.CN == keyID {
			targetAttr = attr
			break
		}
	}

	if targetAttr == nil {
		writeError(w, backend.ErrKeyNotFound, http.StatusNotFound)
		return
	}

	// Get the key
	privKey, err := ks.GetKey(targetAttr)
	if err != nil {
		log.Printf("Failed to get key: %v", err)
		handleError(w, err)
		return
	}

	// Unmarshal data and signature
	var data []byte
	if err := json.Unmarshal(req.Data, &data); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	var signature []byte
	if err := json.Unmarshal(req.Signature, &signature); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	// Parse hash algorithm
	hashAlg := crypto.SHA256
	if req.Hash != "" {
		hashAlg = types.ParseHash(req.Hash)
		if hashAlg == 0 {
			hashAlg = crypto.SHA256 // Default if unknown
		}
	}

	// Get public key
	pubKey := getPublicKey(privKey)
	if pubKey == nil {
		writeError(w, ErrInternalError, http.StatusInternalServerError)
		return
	}

	// Verify signature
	cryptoHash := hashAlg
	hasher := cryptoHash.New()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	verifier := verification.NewVerifier(nil) // No checksum provider for REST API
	err = verifier.Verify(pubKey, cryptoHash, digest, signature, nil)

	resp := VerifyResponse{
		Valid: err == nil,
	}
	if err == nil {
		resp.Message = "Signature is valid"
	} else {
		resp.Message = "Signature is invalid"
	}

	writeJSON(w, resp, http.StatusOK)
}

// DeleteKeyHandler handles DELETE /api/v1/keys/{id} requests.
func (h *HandlerContext) DeleteKeyHandler(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	backendID := r.URL.Query().Get("backend")
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	ks, err := keychain.Backend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Find the key
	keyAttrs, err := ks.ListKeys()
	if err != nil {
		log.Printf("Failed to list keys: %v", err)
		handleError(w, err)
		return
	}

	var targetAttr *types.KeyAttributes
	for _, attr := range keyAttrs {
		if attr.CN == keyID {
			targetAttr = attr
			break
		}
	}

	if targetAttr == nil {
		writeError(w, backend.ErrKeyNotFound, http.StatusNotFound)
		return
	}

	// Delete the key
	if err := ks.DeleteKey(targetAttr); err != nil {
		log.Printf("Failed to delete key: %v", err)
		handleError(w, err)
		return
	}

	resp := DeleteKeyResponse{
		Success: true,
		Message: fmt.Sprintf("Key %s deleted successfully", keyID),
	}
	writeJSON(w, resp, http.StatusOK)
}

// RotateKeyHandler handles POST /api/v1/keys/{id}/rotate requests.
func (h *HandlerContext) RotateKeyHandler(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	backendID := r.URL.Query().Get("backend")
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	ks, err := keychain.Backend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Find the key
	keyAttrs, err := ks.ListKeys()
	if err != nil {
		log.Printf("Failed to list keys: %v", err)
		handleError(w, err)
		return
	}

	var targetAttr *types.KeyAttributes
	for _, attr := range keyAttrs {
		if attr.CN == keyID {
			targetAttr = attr
			break
		}
	}

	if targetAttr == nil {
		writeError(w, backend.ErrKeyNotFound, http.StatusNotFound)
		return
	}

	// Rotate the key
	newKey, err := ks.RotateKey(targetAttr)
	if err != nil {
		log.Printf("Failed to rotate key: %v", err)
		handleError(w, err)
		return
	}

	// Build response
	resp := RotateKeyResponse{
		KeyID:   keyID,
		KeyType: string(targetAttr.KeyType),
		Message: fmt.Sprintf("Key %s rotated successfully", keyID),
	}

	// Add public key
	pubKey := getPublicKey(newKey)
	if pubKey != nil {
		pubKeyPEM, err := encoding.EncodePublicKeyPEM(pubKey)
		if err == nil {
			resp.PublicKeyPEM = string(pubKeyPEM)
		}
	}

	writeJSON(w, resp, http.StatusOK)
}

// EncryptHandler handles POST /api/v1/keys/{id}/encrypt requests.
func (h *HandlerContext) EncryptHandler(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	backendID := r.URL.Query().Get("backend")
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	var req EncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	ks, err := keychain.Backend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Find the key
	keyAttrs, err := ks.ListKeys()
	if err != nil {
		log.Printf("Failed to list keys: %v", err)
		handleError(w, err)
		return
	}

	var targetAttr *types.KeyAttributes
	for _, attr := range keyAttrs {
		if attr.CN == keyID {
			targetAttr = attr
			break
		}
	}

	if targetAttr == nil {
		writeError(w, backend.ErrKeyNotFound, http.StatusNotFound)
		return
	}

	// Get the backend and check if it supports symmetric encryption
	symBackend, ok := ks.Backend().(types.SymmetricBackend)
	if !ok {
		writeError(w, fmt.Errorf("backend does not support symmetric encryption"), http.StatusBadRequest)
		return
	}

	// Get symmetric encrypter
	encrypter, err := symBackend.SymmetricEncrypter(targetAttr)
	if err != nil {
		log.Printf("Failed to get symmetric encrypter: %v", err)
		handleError(w, err)
		return
	}

	// Unmarshal plaintext
	var plaintext []byte
	if err := json.Unmarshal(req.Plaintext, &plaintext); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	// Unmarshal additional data if provided
	var aad []byte
	if len(req.AdditionalData) > 0 {
		if err := json.Unmarshal(req.AdditionalData, &aad); err != nil {
			writeError(w, ErrInvalidRequest, http.StatusBadRequest)
			return
		}
	}

	// Encrypt the data
	encryptOpts := &types.EncryptOptions{
		AdditionalData: aad,
	}
	encrypted, err := encrypter.Encrypt(plaintext, encryptOpts)
	if err != nil {
		log.Printf("Failed to encrypt data: %v", err)
		handleError(w, err)
		return
	}

	// Build response
	resp := EncryptResponse{
		Ciphertext: encrypted.Ciphertext,
		Nonce:      encrypted.Nonce,
		Tag:        encrypted.Tag,
	}
	writeJSON(w, resp, http.StatusOK)
}

// DecryptHandler handles POST /api/v1/keys/{id}/decrypt requests.
func (h *HandlerContext) DecryptHandler(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	backendID := r.URL.Query().Get("backend")
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	var req DecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	ks, err := keychain.Backend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Find the key
	keyAttrs, err := ks.ListKeys()
	if err != nil {
		log.Printf("Failed to list keys: %v", err)
		handleError(w, err)
		return
	}

	var targetAttr *types.KeyAttributes
	for _, attr := range keyAttrs {
		if attr.CN == keyID {
			targetAttr = attr
			break
		}
	}

	if targetAttr == nil {
		writeError(w, backend.ErrKeyNotFound, http.StatusNotFound)
		return
	}

	// Unmarshal ciphertext
	var ciphertext []byte
	if err := json.Unmarshal(req.Ciphertext, &ciphertext); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	// Check if this is symmetric decryption (nonce and tag present)
	var plaintext []byte
	if len(req.Nonce) > 0 && len(req.Tag) > 0 {
		// Symmetric decryption path
		symBackend, ok := ks.Backend().(types.SymmetricBackend)
		if !ok {
			writeError(w, fmt.Errorf("backend does not support symmetric decryption"), http.StatusBadRequest)
			return
		}

		// Get symmetric encrypter
		encrypter, err := symBackend.SymmetricEncrypter(targetAttr)
		if err != nil {
			log.Printf("Failed to get symmetric encrypter: %v", err)
			handleError(w, err)
			return
		}

		// Unmarshal nonce and tag
		var nonce []byte
		if err := json.Unmarshal(req.Nonce, &nonce); err != nil {
			writeError(w, ErrInvalidRequest, http.StatusBadRequest)
			return
		}

		var tag []byte
		if err := json.Unmarshal(req.Tag, &tag); err != nil {
			writeError(w, ErrInvalidRequest, http.StatusBadRequest)
			return
		}

		// Unmarshal additional data if provided
		var aad []byte
		if len(req.AdditionalData) > 0 {
			if err := json.Unmarshal(req.AdditionalData, &aad); err != nil {
				writeError(w, ErrInvalidRequest, http.StatusBadRequest)
				return
			}
		}

		// Build encrypted data structure
		encryptedData := &types.EncryptedData{
			Ciphertext: ciphertext,
			Nonce:      nonce,
			Tag:        tag,
			Algorithm:  getAlgorithmString(targetAttr),
		}

		// Decrypt the data
		decryptOpts := &types.DecryptOptions{
			AdditionalData: aad,
		}
		plaintext, err = encrypter.Decrypt(encryptedData, decryptOpts)
		if err != nil {
			log.Printf("Failed to decrypt data: %v", err)
			handleError(w, err)
			return
		}
	} else {
		// Asymmetric decryption path
		decrypter, err := ks.Decrypter(targetAttr)
		if err != nil {
			log.Printf("Failed to get decrypter: %v", err)
			handleError(w, err)
			return
		}

		// Decrypt the data
		plaintext, err = decrypter.Decrypt(nil, ciphertext, nil)
		if err != nil {
			log.Printf("Failed to decrypt data: %v", err)
			handleError(w, err)
			return
		}
	}

	// Build response
	resp := DecryptResponse{
		Plaintext: plaintext,
	}
	writeJSON(w, resp, http.StatusOK)
}

// SaveCertHandler handles POST /api/v1/certs requests.
func (h *HandlerContext) SaveCertHandler(w http.ResponseWriter, r *http.Request) {
	var req SaveCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	keyID := r.URL.Query().Get("key_id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	backendID := r.URL.Query().Get("backend")
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	ks, err := keychain.Backend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Parse certificate PEM
	cert, err := encoding.DecodeCertificatePEM([]byte(req.CertificatePEM))
	if err != nil {
		log.Printf("Failed to parse certificate: %v", err)
		writeError(w, fmt.Errorf("invalid certificate PEM: %w", err), http.StatusBadRequest)
		return
	}

	// Save certificate
	if err := ks.SaveCert(keyID, cert); err != nil {
		log.Printf("Failed to save certificate: %v", err)
		handleError(w, err)
		return
	}

	resp := SuccessResponse{
		Success: true,
		Message: fmt.Sprintf("Certificate for key %s saved successfully", keyID),
	}
	writeJSON(w, resp, http.StatusCreated)
}

// GetCertHandler handles GET /api/v1/certs/{id} requests.
func (h *HandlerContext) GetCertHandler(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	backendID := r.URL.Query().Get("backend")
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	ks, err := keychain.Backend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Get certificate
	cert, err := ks.GetCert(keyID)
	if err != nil {
		log.Printf("Failed to get certificate: %v", err)
		handleError(w, err)
		return
	}

	// Encode to PEM
	certPEM, err := encoding.EncodeCertificatePEM(cert)
	if err != nil {
		log.Printf("Failed to encode certificate: %v", err)
		writeError(w, ErrInternalError, http.StatusInternalServerError)
		return
	}

	resp := GetCertResponse{
		KeyID:          keyID,
		CertificatePEM: string(certPEM),
	}
	writeJSON(w, resp, http.StatusOK)
}

// DeleteCertHandler handles DELETE /api/v1/certs/{id} requests.
func (h *HandlerContext) DeleteCertHandler(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	backendID := r.URL.Query().Get("backend")
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	ks, err := keychain.Backend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Delete certificate
	if err := ks.DeleteCert(keyID); err != nil {
		log.Printf("Failed to delete certificate: %v", err)
		handleError(w, err)
		return
	}

	resp := SuccessResponse{
		Success: true,
		Message: fmt.Sprintf("Certificate for key %s deleted successfully", keyID),
	}
	writeJSON(w, resp, http.StatusOK)
}

// ListCertsHandler handles GET /api/v1/certs requests.
func (h *HandlerContext) ListCertsHandler(w http.ResponseWriter, r *http.Request) {
	backendID := r.URL.Query().Get("backend")
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	ks, err := keychain.Backend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// List certificates
	certs, err := ks.ListCerts()
	if err != nil {
		log.Printf("Failed to list certificates: %v", err)
		handleError(w, err)
		return
	}

	resp := ListCertsResponse{
		Certificates: certs,
	}
	writeJSON(w, resp, http.StatusOK)
}

// CertExistsHandler handles HEAD /api/v1/certs/{id} requests.
func (h *HandlerContext) CertExistsHandler(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	backendID := r.URL.Query().Get("backend")
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	ks, err := keychain.Backend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Check if certificate exists
	exists, err := ks.CertExists(keyID)
	if err != nil {
		log.Printf("Failed to check certificate existence: %v", err)
		handleError(w, err)
		return
	}

	if exists {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
}

// SaveCertChainHandler handles POST /api/v1/certs/{id}/chain requests.
func (h *HandlerContext) SaveCertChainHandler(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	backendID := r.URL.Query().Get("backend")
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	var req SaveCertChainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	ks, err := keychain.Backend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Parse certificate chain
	chain := make([]*x509.Certificate, 0, len(req.CertChainPEM))
	for i, certPEM := range req.CertChainPEM {
		cert, err := encoding.DecodeCertificatePEM([]byte(certPEM))
		if err != nil {
			log.Printf("Failed to parse certificate at index %d: %v", i, err)
			writeError(w, fmt.Errorf("invalid certificate PEM at index %d: %w", i, err), http.StatusBadRequest)
			return
		}
		chain = append(chain, cert)
	}

	// Save certificate chain
	if err := ks.SaveCertChain(keyID, chain); err != nil {
		log.Printf("Failed to save certificate chain: %v", err)
		handleError(w, err)
		return
	}

	resp := SuccessResponse{
		Success: true,
		Message: fmt.Sprintf("Certificate chain for key %s saved successfully", keyID),
	}
	writeJSON(w, resp, http.StatusCreated)
}

// GetCertChainHandler handles GET /api/v1/certs/{id}/chain requests.
func (h *HandlerContext) GetCertChainHandler(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	backendID := r.URL.Query().Get("backend")
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	ks, err := keychain.Backend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Get certificate chain
	chain, err := ks.GetCertChain(keyID)
	if err != nil {
		log.Printf("Failed to get certificate chain: %v", err)
		handleError(w, err)
		return
	}

	// Encode to PEM
	chainPEM := make([]string, 0, len(chain))
	for i, cert := range chain {
		certPEM, err := encoding.EncodeCertificatePEM(cert)
		if err != nil {
			log.Printf("Failed to encode certificate at index %d: %v", i, err)
			writeError(w, ErrInternalError, http.StatusInternalServerError)
			return
		}
		chainPEM = append(chainPEM, string(certPEM))
	}

	resp := GetCertChainResponse{
		KeyID:        keyID,
		CertChainPEM: chainPEM,
	}
	writeJSON(w, resp, http.StatusOK)
}

// GetTLSCertificateHandler handles GET /api/v1/tls/{id} requests.
func (h *HandlerContext) GetTLSCertificateHandler(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	backendID := r.URL.Query().Get("backend")
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	ks, err := keychain.Backend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Find the key
	keyAttrs, err := ks.ListKeys()
	if err != nil {
		log.Printf("Failed to list keys: %v", err)
		handleError(w, err)
		return
	}

	var targetAttr *types.KeyAttributes
	for _, attr := range keyAttrs {
		if attr.CN == keyID {
			targetAttr = attr
			break
		}
	}

	if targetAttr == nil {
		writeError(w, backend.ErrKeyNotFound, http.StatusNotFound)
		return
	}

	// Get TLS certificate
	tlsCert, err := ks.GetTLSCertificate(keyID, targetAttr)
	if err != nil {
		log.Printf("Failed to get TLS certificate: %v", err)
		handleError(w, err)
		return
	}

	// Encode certificate to PEM
	certPEM, err := encoding.EncodeCertificatePEM(tlsCert.Leaf)
	if err != nil {
		log.Printf("Failed to encode certificate: %v", err)
		writeError(w, ErrInternalError, http.StatusInternalServerError)
		return
	}

	// Build response (without private key for security)
	resp := GetTLSCertificateResponse{
		KeyID:          keyID,
		CertificatePEM: string(certPEM),
	}

	// Add chain if present
	if len(tlsCert.Certificate) > 1 {
		chainPEM := make([]string, 0, len(tlsCert.Certificate)-1)
		for _, certDER := range tlsCert.Certificate[1:] {
			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				log.Printf("Failed to parse certificate in chain: %v", err)
				continue
			}
			certPEM, err := encoding.EncodeCertificatePEM(cert)
			if err != nil {
				log.Printf("Failed to encode certificate in chain: %v", err)
				continue
			}
			chainPEM = append(chainPEM, string(certPEM))
		}
		if len(chainPEM) > 0 {
			resp.ChainPEM = chainPEM
		}
	}

	writeJSON(w, resp, http.StatusOK)
}

// GetImportParametersHandler handles POST /api/v1/keys/import-params requests.
func (h *HandlerContext) GetImportParametersHandler(w http.ResponseWriter, r *http.Request) {
	var req GetImportParametersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Backend == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	// Validate backend name
	if err := ValidateBackendName(req.Backend); err != nil {
		writeError(w, fmt.Errorf("invalid backend: %w", err), http.StatusBadRequest)
		return
	}

	if req.KeyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	// Validate KeyID for security
	if err := ValidateKeyID(req.KeyID); err != nil {
		writeError(w, fmt.Errorf("invalid key ID: %w", err), http.StatusBadRequest)
		return
	}

	if req.KeyType == "" {
		writeError(w, ErrInvalidKeyType, http.StatusBadRequest)
		return
	}
	if req.Algorithm == "" {
		writeError(w, fmt.Errorf("missing wrapping algorithm"), http.StatusBadRequest)
		return
	}

	// Get the backend
	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Check if backend supports import/export
	importExportBackend, ok := ks.Backend().(backend.ImportExportBackend)
	if !ok {
		writeError(w, fmt.Errorf("backend does not support import/export operations"), http.StatusBadRequest)
		return
	}

	// Build key attributes
	attrs := buildKeyAttributes(req.KeyID, req.KeyType, req.KeySize, req.Curve, req.Hash, req.AESKeySize)

	// Parse wrapping algorithm
	wrappingAlg := backend.WrappingAlgorithm(req.Algorithm)

	// Get import parameters
	params, err := importExportBackend.GetImportParameters(attrs, wrappingAlg)
	if err != nil {
		log.Printf("Failed to get import parameters: %v", err)
		handleError(w, err)
		return
	}

	// Encode wrapping public key to PEM
	wrappingKeyPEM, err := encoding.EncodePublicKeyPEM(params.WrappingPublicKey)
	if err != nil {
		log.Printf("Failed to encode wrapping public key: %v", err)
		writeError(w, ErrInternalError, http.StatusInternalServerError)
		return
	}

	// Build response
	resp := GetImportParametersResponse{
		WrappingPublicKeyPEM: string(wrappingKeyPEM),
		Algorithm:            string(params.Algorithm),
	}

	// Add import token if present
	if params.ImportToken != nil {
		resp.ImportToken = json.RawMessage(params.ImportToken)
	}

	// Add expiration time if set
	if !params.ExpiresAt.IsZero() {
		resp.ExpiresAt = params.ExpiresAt.Format(time.RFC3339)
	}

	writeJSON(w, resp, http.StatusOK)
}

// WrapKeyHandler handles POST /api/v1/keys/wrap requests.
func (h *HandlerContext) WrapKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req WrapKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	// Validate required fields
	if len(req.KeyMaterial) == 0 {
		writeError(w, fmt.Errorf("missing key material"), http.StatusBadRequest)
		return
	}
	if req.WrappingPublicKeyPEM == "" {
		writeError(w, fmt.Errorf("missing wrapping public key"), http.StatusBadRequest)
		return
	}
	if req.Algorithm == "" {
		writeError(w, fmt.Errorf("missing wrapping algorithm"), http.StatusBadRequest)
		return
	}

	// Decode wrapping public key from PEM
	wrappingKey, err := encoding.DecodePublicKeyPEM([]byte(req.WrappingPublicKeyPEM))
	if err != nil {
		log.Printf("Failed to decode wrapping public key: %v", err)
		writeError(w, fmt.Errorf("invalid wrapping public key: %w", err), http.StatusBadRequest)
		return
	}

	// Unmarshal key material
	var keyMaterial []byte
	if err := json.Unmarshal(req.KeyMaterial, &keyMaterial); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	// Build import parameters
	params := &backend.ImportParameters{
		WrappingPublicKey: wrappingKey,
		Algorithm:         backend.WrappingAlgorithm(req.Algorithm),
	}

	// Add import token if provided
	if len(req.ImportToken) > 0 {
		var importToken []byte
		if err := json.Unmarshal(req.ImportToken, &importToken); err != nil {
			writeError(w, ErrInvalidRequest, http.StatusBadRequest)
			return
		}
		params.ImportToken = importToken
	}

	// Wrap the key material
	// Note: WrapKey is typically a utility function that can be called on any backend
	// For now, we'll get a backend that supports import/export and use it
	var importExportBackend backend.ImportExportBackend
	for _, backendName := range keychain.Backends() {
		ks, err := keychain.Backend(backendName)
		if err != nil {
			continue
		}
		if ieb, ok := ks.Backend().(backend.ImportExportBackend); ok {
			importExportBackend = ieb
			break
		}
	}

	if importExportBackend == nil {
		writeError(w, fmt.Errorf("no backend supports import/export operations"), http.StatusBadRequest)
		return
	}

	wrapped, err := importExportBackend.WrapKey(keyMaterial, params)
	if err != nil {
		log.Printf("Failed to wrap key: %v", err)
		handleError(w, err)
		return
	}

	// Build response
	resp := WrapKeyResponse{
		WrappedKey: json.RawMessage(wrapped.WrappedKey),
		Algorithm:  string(wrapped.Algorithm),
	}

	// Add import token if present
	if wrapped.ImportToken != nil {
		resp.ImportToken = json.RawMessage(wrapped.ImportToken)
	}

	writeJSON(w, resp, http.StatusOK)
}

// UnwrapKeyHandler handles POST /api/v1/keys/unwrap requests.
func (h *HandlerContext) UnwrapKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req UnwrapKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	// Validate required fields
	if len(req.WrappedKey) == 0 {
		writeError(w, fmt.Errorf("missing wrapped key"), http.StatusBadRequest)
		return
	}
	if req.WrappingPublicKeyPEM == "" {
		writeError(w, fmt.Errorf("missing wrapping public key"), http.StatusBadRequest)
		return
	}
	if req.Algorithm == "" {
		writeError(w, fmt.Errorf("missing wrapping algorithm"), http.StatusBadRequest)
		return
	}

	// Decode wrapping public key from PEM
	wrappingKey, err := encoding.DecodePublicKeyPEM([]byte(req.WrappingPublicKeyPEM))
	if err != nil {
		log.Printf("Failed to decode wrapping public key: %v", err)
		writeError(w, fmt.Errorf("invalid wrapping public key: %w", err), http.StatusBadRequest)
		return
	}

	// Unmarshal wrapped key
	var wrappedKeyBytes []byte
	if err := json.Unmarshal(req.WrappedKey, &wrappedKeyBytes); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	// Build wrapped key material
	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: wrappedKeyBytes,
		Algorithm:  backend.WrappingAlgorithm(req.Algorithm),
	}

	// Add import token if provided
	if len(req.ImportToken) > 0 {
		var importToken []byte
		if err := json.Unmarshal(req.ImportToken, &importToken); err != nil {
			writeError(w, ErrInvalidRequest, http.StatusBadRequest)
			return
		}
		wrapped.ImportToken = importToken
	}

	// Build import parameters
	params := &backend.ImportParameters{
		WrappingPublicKey: wrappingKey,
		Algorithm:         backend.WrappingAlgorithm(req.Algorithm),
	}

	if len(req.ImportToken) > 0 {
		var importToken []byte
		if err := json.Unmarshal(req.ImportToken, &importToken); err != nil {
			writeError(w, ErrInvalidRequest, http.StatusBadRequest)
			return
		}
		params.ImportToken = importToken
	}

	// Unwrap the key material
	var importExportBackend backend.ImportExportBackend
	for _, backendName := range keychain.Backends() {
		ks, err := keychain.Backend(backendName)
		if err != nil {
			continue
		}
		if ieb, ok := ks.Backend().(backend.ImportExportBackend); ok {
			importExportBackend = ieb
			break
		}
	}

	if importExportBackend == nil {
		writeError(w, fmt.Errorf("no backend supports import/export operations"), http.StatusBadRequest)
		return
	}

	keyMaterial, err := importExportBackend.UnwrapKey(wrapped, params)
	if err != nil {
		log.Printf("Failed to unwrap key: %v", err)
		handleError(w, err)
		return
	}

	// Build response
	resp := UnwrapKeyResponse{
		KeyMaterial: json.RawMessage(keyMaterial),
	}

	writeJSON(w, resp, http.StatusOK)
}

// ImportKeyHandler handles POST /api/v1/keys/import requests.
func (h *HandlerContext) ImportKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req ImportKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Backend == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	// Validate backend name
	if err := ValidateBackendName(req.Backend); err != nil {
		writeError(w, fmt.Errorf("invalid backend: %w", err), http.StatusBadRequest)
		return
	}

	if req.KeyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	// Validate KeyID for security
	if err := ValidateKeyID(req.KeyID); err != nil {
		writeError(w, fmt.Errorf("invalid key ID: %w", err), http.StatusBadRequest)
		return
	}

	if req.KeyType == "" {
		writeError(w, ErrInvalidKeyType, http.StatusBadRequest)
		return
	}
	if len(req.WrappedKey) == 0 {
		writeError(w, fmt.Errorf("missing wrapped key"), http.StatusBadRequest)
		return
	}
	if req.Algorithm == "" {
		writeError(w, fmt.Errorf("missing wrapping algorithm"), http.StatusBadRequest)
		return
	}

	// Get the backend
	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Check if backend supports import/export
	importExportBackend, ok := ks.Backend().(backend.ImportExportBackend)
	if !ok {
		writeError(w, fmt.Errorf("backend does not support import/export operations"), http.StatusBadRequest)
		return
	}

	// Build key attributes
	attrs := buildKeyAttributes(req.KeyID, req.KeyType, req.KeySize, req.Curve, req.Hash, req.AESKeySize)

	// Unmarshal wrapped key
	var wrappedKeyBytes []byte
	if err := json.Unmarshal(req.WrappedKey, &wrappedKeyBytes); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	// Build wrapped key material
	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: wrappedKeyBytes,
		Algorithm:  backend.WrappingAlgorithm(req.Algorithm),
	}

	// Add import token if provided
	if len(req.ImportToken) > 0 {
		var importToken []byte
		if err := json.Unmarshal(req.ImportToken, &importToken); err != nil {
			writeError(w, ErrInvalidRequest, http.StatusBadRequest)
			return
		}
		wrapped.ImportToken = importToken
	}

	// Import the key
	if err := importExportBackend.ImportKey(attrs, wrapped); err != nil {
		log.Printf("Failed to import key: %v", err)
		handleError(w, err)
		return
	}

	// Build response
	resp := ImportKeyResponse{
		Success: true,
		KeyID:   req.KeyID,
		Message: fmt.Sprintf("Key %s imported successfully", req.KeyID),
	}

	// Try to get public key for asymmetric keys
	if req.KeyType != "aes" {
		privKey, err := ks.GetKey(attrs)
		if err == nil {
			pubKey := getPublicKey(privKey)
			if pubKey != nil {
				pubKeyPEM, err := encoding.EncodePublicKeyPEM(pubKey)
				if err == nil {
					resp.PublicKeyPEM = string(pubKeyPEM)
				}
			}
		}
	}

	writeJSON(w, resp, http.StatusCreated)
}

// ExportKeyHandler handles POST /api/v1/keys/{id}/export requests.
func (h *HandlerContext) ExportKeyHandler(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	backendID := r.URL.Query().Get("backend")
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	var req ExportKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	// Validate wrapping algorithm
	if req.Algorithm == "" {
		writeError(w, fmt.Errorf("missing wrapping algorithm"), http.StatusBadRequest)
		return
	}

	ks, err := keychain.Backend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Check if backend supports import/export
	importExportBackend, ok := ks.Backend().(backend.ImportExportBackend)
	if !ok {
		writeError(w, fmt.Errorf("backend does not support import/export operations"), http.StatusBadRequest)
		return
	}

	// Find the key
	keyAttrs, err := ks.ListKeys()
	if err != nil {
		log.Printf("Failed to list keys: %v", err)
		handleError(w, err)
		return
	}

	var targetAttr *types.KeyAttributes
	for _, attr := range keyAttrs {
		if attr.CN == keyID {
			targetAttr = attr
			break
		}
	}

	if targetAttr == nil {
		writeError(w, backend.ErrKeyNotFound, http.StatusNotFound)
		return
	}

	// Parse wrapping algorithm
	wrappingAlg := backend.WrappingAlgorithm(req.Algorithm)

	// Export the key
	wrapped, err := importExportBackend.ExportKey(targetAttr, wrappingAlg)
	if err != nil {
		log.Printf("Failed to export key: %v", err)
		handleError(w, err)
		return
	}

	// Build response
	resp := ExportKeyResponse{
		KeyID:      keyID,
		WrappedKey: json.RawMessage(wrapped.WrappedKey),
		Algorithm:  string(wrapped.Algorithm),
	}

	// Add import token if present
	if wrapped.ImportToken != nil {
		resp.ImportToken = json.RawMessage(wrapped.ImportToken)
	}

	writeJSON(w, resp, http.StatusOK)
}

// CopyKeyHandler handles POST /api/v1/keys/copy requests.
func (h *HandlerContext) CopyKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req CopyKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.SourceBackend == "" {
		writeError(w, fmt.Errorf("missing source_backend"), http.StatusBadRequest)
		return
	}
	if req.SourceKeyID == "" {
		writeError(w, fmt.Errorf("missing source_key_id"), http.StatusBadRequest)
		return
	}
	if req.DestBackend == "" {
		writeError(w, fmt.Errorf("missing dest_backend"), http.StatusBadRequest)
		return
	}
	if req.DestKeyID == "" {
		writeError(w, fmt.Errorf("missing dest_key_id"), http.StatusBadRequest)
		return
	}
	if req.KeyType == "" {
		writeError(w, fmt.Errorf("missing key_type"), http.StatusBadRequest)
		return
	}
	if req.Algorithm == "" {
		writeError(w, fmt.Errorf("missing wrapping algorithm"), http.StatusBadRequest)
		return
	}

	// Get source backend
	sourceKS, err := keychain.Backend(req.SourceBackend)
	if err != nil {
		writeError(w, fmt.Errorf("source backend not found: %w", err), http.StatusNotFound)
		return
	}

	// Check if source backend supports import/export
	sourceBackend, ok := sourceKS.Backend().(backend.ImportExportBackend)
	if !ok {
		writeError(w, fmt.Errorf("source backend does not support export operations"), http.StatusBadRequest)
		return
	}

	// Get destination backend
	destKS, err := keychain.Backend(req.DestBackend)
	if err != nil {
		writeError(w, fmt.Errorf("destination backend not found: %w", err), http.StatusNotFound)
		return
	}

	// Check if destination backend supports import/export
	destBackend, ok := destKS.Backend().(backend.ImportExportBackend)
	if !ok {
		writeError(w, fmt.Errorf("destination backend does not support import operations"), http.StatusBadRequest)
		return
	}

	// Find the source key
	sourceKeyAttrs, err := sourceKS.ListKeys()
	if err != nil {
		log.Printf("Failed to list keys from source backend: %v", err)
		handleError(w, err)
		return
	}

	var sourceAttr *types.KeyAttributes
	for _, attr := range sourceKeyAttrs {
		if attr.CN == req.SourceKeyID {
			sourceAttr = attr
			break
		}
	}

	if sourceAttr == nil {
		writeError(w, fmt.Errorf("source key not found: %s", req.SourceKeyID), http.StatusNotFound)
		return
	}

	// Parse wrapping algorithm
	wrappingAlg := backend.WrappingAlgorithm(req.Algorithm)

	// Export the key from source backend
	wrapped, err := sourceBackend.ExportKey(sourceAttr, wrappingAlg)
	if err != nil {
		log.Printf("Failed to export key from source backend: %v", err)
		handleError(w, err)
		return
	}

	// Build destination key attributes
	destAttrs := buildKeyAttributes(req.DestKeyID, req.KeyType, req.KeySize, req.Curve, req.Hash, req.AESKeySize)

	// Import the key to destination backend
	if err := destBackend.ImportKey(destAttrs, wrapped); err != nil {
		log.Printf("Failed to import key to destination backend: %v", err)
		handleError(w, err)
		return
	}

	// Build response
	resp := CopyKeyResponse{
		Success: true,
		Message: fmt.Sprintf("Key copied successfully from %s/%s to %s/%s",
			req.SourceBackend, req.SourceKeyID, req.DestBackend, req.DestKeyID),
	}

	writeJSON(w, resp, http.StatusOK)
}

// buildKeyAttributes is a helper function to build key attributes from REST request parameters.
func buildKeyAttributes(keyID, keyType string, keySize int, curve, hash string, aesKeySize int) *types.KeyAttributes {
	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StorePKCS8,
		Hash:      crypto.SHA256,
	}

	// Parse key type and set appropriate attributes
	keyTypeLower := strings.ToLower(keyType)

	switch keyTypeLower {
	case "rsa":
		attrs.KeyAlgorithm = x509.RSA
		if keySize == 0 {
			keySize = 2048
		}
		attrs.RSAAttributes = &types.RSAAttributes{
			KeySize: keySize,
		}
	case "ecdsa":
		attrs.KeyAlgorithm = x509.ECDSA
		if curve == "" {
			curve = "P256"
		}
		parsedCurve2, _ := types.ParseCurve(curve)
		attrs.ECCAttributes = &types.ECCAttributes{
			Curve: parsedCurve2,
		}
	case "ed25519":
		attrs.KeyAlgorithm = x509.Ed25519
	case "aes":
		attrs.KeyType = types.KeyTypeEncryption
		if aesKeySize == 0 {
			aesKeySize = 256
		}
		var symAlg types.SymmetricAlgorithm
		switch aesKeySize {
		case 128:
			symAlg = types.SymmetricAES128GCM
		case 192:
			symAlg = types.SymmetricAES192GCM
		case 256:
			symAlg = types.SymmetricAES256GCM
		default:
			symAlg = types.SymmetricAES256GCM
		}
		attrs.SymmetricAlgorithm = symAlg
		attrs.AESAttributes = &types.AESAttributes{
			KeySize: aesKeySize,
		}
	}

	// Set hash algorithm if provided
	if hash != "" {
		attrs.Hash = types.ParseHash(hash)
		if attrs.Hash == 0 {
			attrs.Hash = crypto.SHA256
		}
	}

	return attrs
}

// getPublicKey extracts the public key from a private key.
func getPublicKey(privKey crypto.PrivateKey) crypto.PublicKey {
	switch k := privKey.(type) {
	case interface{ Public() crypto.PublicKey }:
		return k.Public()
	default:
		return nil
	}
}

// getAlgorithmString returns the algorithm name as a string, handling both
// symmetric and asymmetric key types.
func getAlgorithmString(attrs *types.KeyAttributes) string {
	if attrs.SymmetricAlgorithm != "" {
		return string(attrs.SymmetricAlgorithm)
	}
	if attrs.KeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
		return attrs.KeyAlgorithm.String()
	}
	return ""
}
