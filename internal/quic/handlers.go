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

package quic

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"

	"github.com/jeremyhahn/go-keychain/pkg/adapters/logger"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// HealthResponse represents a health check response
type HealthResponse struct {
	Status string `json:"status"`
}

// BackendInfo represents information about a backend
type BackendInfo struct {
	ID             string                   `json:"id"`
	Type           string                   `json:"type"`
	HardwareBacked bool                     `json:"hardware_backed"`
	Capabilities   types.Capabilities `json:"capabilities"`
}

// ListBackendsResponse represents the backends list response
type ListBackendsResponse struct {
	Backends []BackendInfo `json:"backends"`
}

// GenerateKeyRequest represents a key generation request
type GenerateKeyRequest struct {
	KeyID      string `json:"key_id"`
	Backend    string `json:"backend"`
	KeyType    string `json:"key_type"`
	KeySize    int    `json:"key_size,omitempty"`
	Curve      string `json:"curve,omitempty"`
	Algorithm  string `json:"algorithm,omitempty"`  // For symmetric keys (e.g., "aes-128-gcm", "aes-256-gcm")
	Exportable bool   `json:"exportable,omitempty"` // Whether the key can be exported
}

// KeyResponse represents a key response
type KeyResponse struct {
	KeyID        string `json:"key_id"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	Backend      string `json:"backend,omitempty"`
}

// ListKeysResponse represents the keys list response
type ListKeysResponse struct {
	Keys []KeyInfo `json:"keys"`
}

// KeyInfo represents basic key information
type KeyInfo struct {
	KeyID   string `json:"key_id"`
	Backend string `json:"backend,omitempty"`
}

// SignRequest represents a signing request
type SignRequest struct {
	Data []byte `json:"data"`
	Hash string `json:"hash"`
}

// SignResponse represents a signing response
type SignResponse struct {
	Signature interface{} `json:"signature"`
}

// VerifyRequest represents a verification request
type VerifyRequest struct {
	Data      []byte      `json:"data"`
	Signature interface{} `json:"signature"`
	Hash      string      `json:"hash"`
}

// VerifyResponse represents a verification response
type VerifyResponse struct {
	Valid bool `json:"valid"`
}

// DeleteResponse represents a deletion response
type DeleteResponse struct {
	Success bool `json:"success"`
}

// EncryptRequest represents an encryption request (symmetric encryption)
type EncryptRequest struct {
	Plaintext      []byte `json:"plaintext"`
	AdditionalData []byte `json:"additional_data,omitempty"`
	Algorithm      string `json:"algorithm,omitempty"` // Symmetric algorithm (e.g., "aes256-gcm")
}

// EncryptResponse represents an encryption response
type EncryptResponse struct {
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
	Tag        []byte `json:"tag"`
}

// DecryptRequest represents a decryption request
type DecryptRequest struct {
	Ciphertext     []byte `json:"ciphertext"`
	AdditionalData []byte `json:"additional_data,omitempty"` // Optional AAD for symmetric decryption
	Nonce          []byte `json:"nonce,omitempty"`           // Required for symmetric decryption
	Tag            []byte `json:"tag,omitempty"`             // Required for symmetric decryption (GCM)
	Algorithm      string `json:"algorithm,omitempty"`       // Symmetric algorithm (e.g., "aes256-gcm")
}

// DecryptResponse represents a decryption response
type DecryptResponse struct {
	Plaintext []byte `json:"plaintext"`
}

// CertRequest represents a certificate save request
type CertRequest struct {
	KeyID   string `json:"key_id"`
	CertPEM string `json:"cert_pem"`
}

// CertResponse represents a certificate response
type CertResponse struct {
	KeyID   string `json:"key_id"`
	CertPEM string `json:"cert_pem"`
}

// ListCertsResponse represents the certificates list response
type ListCertsResponse struct {
	KeyIDs []string `json:"key_ids"`
}

// CertChainRequest represents a certificate chain save request
type CertChainRequest struct {
	ChainPEMs []string `json:"chain_pems"`
}

// CertChainResponse represents a certificate chain response
type CertChainResponse struct {
	KeyID     string   `json:"key_id"`
	ChainPEMs []string `json:"chain_pems"`
}

// TLSCertificateResponse represents a TLS certificate response
type TLSCertificateResponse struct {
	CertPEM        string   `json:"cert_pem"`
	ChainPEMs      []string `json:"chain_pems,omitempty"`
	PrivateKeyType string   `json:"private_key_type"`
}

// GetImportParametersRequest represents a request to get import parameters
type GetImportParametersRequest struct {
	Backend    string `json:"backend"`
	KeyID      string `json:"key_id"`
	KeyType    string `json:"key_type"`
	KeySize    int    `json:"key_size,omitempty"`
	Curve      string `json:"curve,omitempty"`
	Hash       string `json:"hash,omitempty"`
	AESKeySize int    `json:"aes_key_size,omitempty"`
	Algorithm  string `json:"algorithm"` // Wrapping algorithm
}

// GetImportParametersResponse represents the import parameters response
type GetImportParametersResponse struct {
	WrappingPublicKeyPEM string  `json:"wrapping_public_key_pem"`
	ImportToken          []byte  `json:"import_token,omitempty"`
	Algorithm            string  `json:"algorithm"`
	ExpiresAt            *string `json:"expires_at,omitempty"` // ISO 8601 format
	KeySpec              string  `json:"key_spec,omitempty"`
}

// WrapKeyRequest represents a request to wrap key material
type WrapKeyRequest struct {
	KeyMaterial          []byte `json:"key_material"`
	WrappingPublicKeyPEM string `json:"wrapping_public_key_pem"`
	ImportToken          []byte `json:"import_token,omitempty"`
	Algorithm            string `json:"algorithm"`
}

// WrapKeyResponse represents the wrapped key response
type WrapKeyResponse struct {
	WrappedKey  []byte            `json:"wrapped_key"`
	Algorithm   string            `json:"algorithm"`
	ImportToken []byte            `json:"import_token,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// ImportKeyRequest represents a request to import key material
type ImportKeyRequest struct {
	WrappedKey  []byte            `json:"wrapped_key"`
	Algorithm   string            `json:"algorithm"`
	ImportToken []byte            `json:"import_token,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// ExportKeyRequest represents a request to export a key
type ExportKeyRequest struct {
	Algorithm string `json:"algorithm"`
}

// ExportKeyResponse represents the export key response
type ExportKeyResponse struct {
	WrappedKey  []byte            `json:"wrapped_key"`
	Algorithm   string            `json:"algorithm"`
	ImportToken []byte            `json:"import_token,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// AsymmetricEncryptRequest represents an asymmetric encryption request (RSA)
type AsymmetricEncryptRequest struct {
	Plaintext []byte `json:"plaintext"`
}

// CopyKeyRequest represents a request to copy a key from one backend to another
type CopyKeyRequest struct {
	SourceBackend string `json:"source_backend"` // Source backend name
	SourceKeyID   string `json:"source_key_id"`
	DestBackend   string `json:"dest_backend"` // Destination backend name
	DestKeyID     string `json:"dest_key_id"`
	KeyType       string `json:"key_type"`  // "rsa", "ecdsa", "ed25519", "symmetric"
	Algorithm     string `json:"algorithm"` // Wrapping algorithm
	KeySize       int    `json:"key_size,omitempty"`
	Curve         string `json:"curve,omitempty"`
	Hash          string `json:"hash,omitempty"`
	AESKeySize    int    `json:"aes_key_size,omitempty"`
}

// CopyKeyResponse represents the response for copying a key
type CopyKeyResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	s.sendJSON(w, http.StatusOK, HealthResponse{Status: "healthy"})
}

// handleListBackends handles backend listing
func (s *Server) handleListBackends(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	backendNames := keychain.Backends()

	backends := make([]BackendInfo, 0, len(backendNames))
	for _, name := range backendNames {
		ks, err := keychain.Backend(name)
		if err != nil {
			continue // Skip backends that can't be retrieved
		}

		backendImpl := ks.Backend()
		caps := backendImpl.Capabilities()

		backends = append(backends, BackendInfo{
			ID:             name,
			Type:           string(backendImpl.Type()),
			HardwareBacked: caps.HardwareBacked,
			Capabilities:   caps,
		})
	}

	s.sendJSON(w, http.StatusOK, ListBackendsResponse{Backends: backends})
}

// handleBackendOperations handles operations on specific backends
func (s *Server) handleBackendOperations(w http.ResponseWriter, r *http.Request) {
	// Extract backend ID from path: /api/v1/backends/{backendID}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/backends/")
	backendID := strings.TrimSuffix(path, "/")

	if backendID == "" {
		s.sendError(w, http.StatusBadRequest, "backend_id is required")
		return
	}

	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Get the backend
	ks, err := keychain.Backend(backendID)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", backendID))
		return
	}

	backendImpl := ks.Backend()
	caps := backendImpl.Capabilities()

	info := BackendInfo{
		ID:             backendID,
		Type:           string(backendImpl.Type()),
		HardwareBacked: caps.HardwareBacked,
		Capabilities:   caps,
	}

	s.sendJSON(w, http.StatusOK, info)
}

// handleKeys handles key listing and creation
func (s *Server) handleKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListKeys(w, r)
	case http.MethodPost:
		s.handleGenerateKey(w, r)
	default:
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleListKeys handles listing keys
func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	backendParam := r.URL.Query().Get("backend")

	// Get the keystore for the specified backend
	ks, err := s.getKeystoreForBackend(backendParam)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", backendParam))
		return
	}

	// List keys from keystore
	attrs, err := ks.ListKeys()
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list keys: %v", err))
		return
	}

	keys := make([]KeyInfo, 0, len(attrs))
	for _, attr := range attrs {
		// Filter by backend if specified
		if backendParam != "" && string(attr.StoreType) != backendParam {
			continue
		}

		keys = append(keys, KeyInfo{
			KeyID:   attr.CN,
			Backend: string(attr.StoreType),
		})
	}

	s.sendJSON(w, http.StatusOK, ListKeysResponse{Keys: keys})
}

// handleGenerateKey handles key generation
func (s *Server) handleGenerateKey(w http.ResponseWriter, r *http.Request) {
	var req GenerateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	if req.KeyID == "" {
		s.sendError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	if req.Backend == "" {
		s.sendError(w, http.StatusBadRequest, "backend is required")
		return
	}

	// Get the keystore for the specified backend
	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", req.Backend))
		return
	}

	// Create key attributes
	attrs := &types.KeyAttributes{
		CN:         req.KeyID,
		KeyType:    types.KeyTypeSigning, // Default to signing
		Exportable: req.Exportable,
	}

	storeType := types.ParseStoreType(req.Backend)
	if storeType == types.StoreUnknown {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid backend: %s", req.Backend))
		return
	}
	attrs.StoreType = storeType

	// Generate key based on type
	var privKey interface{}

	// Use Algorithm field if provided, otherwise fall back to KeyType for backward compatibility
	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = req.KeyType
	}

	switch {
	case types.AlgorithmRSA.Equals(algorithm):
		attrs.RSAAttributes = &types.RSAAttributes{
			KeySize: req.KeySize,
		}
		if attrs.RSAAttributes.KeySize == 0 {
			attrs.RSAAttributes.KeySize = types.RSAKeySize2048
		}
		privKey, err = ks.GenerateRSA(attrs)

	case types.AlgorithmECDSA.Equals(algorithm):
		attrs.ECCAttributes = &types.ECCAttributes{}
		if req.Curve != "" {
			curve, curveErr := types.ParseCurve(req.Curve)
			if curveErr != nil {
				s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid curve: %s", req.Curve))
				return
			}
			attrs.ECCAttributes.Curve = curve
		} else {
			attrs.ECCAttributes.Curve, _ = types.ParseCurve(string(types.CurveP256))
		}
		privKey, err = ks.GenerateECDSA(attrs)

	case types.AlgorithmEd25519.Equals(algorithm):
		privKey, err = ks.GenerateEd25519(attrs)

	case types.AlgorithmSymmetric.Equals(algorithm):
		// For AES keys, check if backend supports symmetric operations
		symBackend, ok := ks.Backend().(types.SymmetricBackend)
		if !ok {
			s.sendError(w, http.StatusBadRequest, "backend does not support symmetric encryption")
			return
		}

		// Parse algorithm or use defaults based on key size
		if req.Algorithm != "" {
			attrs.SymmetricAlgorithm = types.SymmetricAlgorithm(req.Algorithm)
			if !attrs.SymmetricAlgorithm.IsValid() {
				s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid algorithm: %s", req.Algorithm))
				return
			}
		} else {
			// Default to AES-256-GCM if no algorithm specified
			keySize := req.KeySize
			if keySize == 0 {
				keySize = 256
			}
			switch keySize {
			case 128:
				attrs.SymmetricAlgorithm = types.SymmetricAES128GCM
			case 192:
				attrs.SymmetricAlgorithm = types.SymmetricAES192GCM
			case 256:
				attrs.SymmetricAlgorithm = types.SymmetricAES256GCM
			default:
				s.sendError(w, http.StatusBadRequest, fmt.Sprintf("unsupported AES key size: %d", keySize))
				return
			}
		}

		// Set correct key type for symmetric keys
		attrs.KeyType = types.KeyTypeSecret

		// Generate the symmetric key
		_, err = symBackend.GenerateSymmetricKey(attrs)
		// For symmetric keys, we don't return the key material
		privKey = nil

	default:
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("unsupported algorithm: %s", algorithm))
		return
	}

	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to generate key: %v", err))
		return
	}

	// Extract public key PEM
	var pubKeyPEM string
	if privKey != nil {
		pubKey, err := extractPublicKey(privKey)
		if err == nil {
			pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
			if err == nil {
				pemBlock := &pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: pubKeyBytes,
				}
				pubKeyPEM = string(pem.EncodeToMemory(pemBlock))
			}
		}
	}

	s.sendJSON(w, http.StatusCreated, KeyResponse{
		KeyID:        req.KeyID,
		PublicKeyPEM: pubKeyPEM,
	})
}

// handleKeyOperations handles operations on specific keys
func (s *Server) handleKeyOperations(w http.ResponseWriter, r *http.Request) {
	// Extract key ID from path: /api/v1/keys/{keyID}/...
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/keys/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		s.sendError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	keyID := parts[0]
	backendParam := r.URL.Query().Get("backend")

	// Determine operation
	var operation string
	if len(parts) > 1 {
		operation = parts[1]
	}

	switch operation {
	case "sign":
		s.handleSign(w, r, keyID, backendParam)
	case "verify":
		s.handleVerify(w, r, keyID, backendParam)
	case "rotate":
		s.handleRotateKey(w, r, keyID, backendParam)
	case "encrypt":
		s.handleEncrypt(w, r, keyID, backendParam)
	case "decrypt":
		s.handleDecrypt(w, r, keyID, backendParam)
	case "asymmetric-encrypt", "encrypt-asym":
		s.handleAsymmetricEncrypt(w, r, keyID, backendParam)
	case "import-parameters":
		s.handleGetImportParameters(w, r, keyID, backendParam)
	case "wrap":
		s.handleWrapKey(w, r, keyID, backendParam)
	case "import":
		s.handleImportKey(w, r, keyID, backendParam)
	case "export":
		s.handleExportKey(w, r, keyID, backendParam)
	case "":
		// No operation - handle key get/delete
		switch r.Method {
		case http.MethodGet:
			s.handleGetKey(w, r, keyID, backendParam)
		case http.MethodDelete:
			s.handleDeleteKey(w, r, keyID, backendParam)
		default:
			s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	default:
		s.sendError(w, http.StatusNotFound, "operation not found")
	}
}

// getKeystoreForBackend returns the keystore for the specified backend, or the default keystore if empty
func (s *Server) getKeystoreForBackend(backendParam string) (keychain.KeyStore, error) {
	if backendParam != "" {
		return keychain.Backend(backendParam)
	}
	return s.keystore, nil
}

// findKeyByID finds a key's attributes by its ID (CN) in the keystore
// Returns the full key attributes needed for operations like GetKey, Sign, etc.
func (s *Server) findKeyByID(ks keychain.KeyStore, keyID string) (*types.KeyAttributes, error) {
	keys, err := ks.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	for _, attr := range keys {
		if attr.CN == keyID {
			return attr, nil
		}
	}

	return nil, fmt.Errorf("key not found: %s", keyID)
}

// handleGetKey handles retrieving a key
func (s *Server) handleGetKey(w http.ResponseWriter, r *http.Request, keyID, backendParam string) {
	ks, err := s.getKeystoreForBackend(backendParam)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", backendParam))
		return
	}

	// Find the key's full attributes
	attrs, err := s.findKeyByID(ks, keyID)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("key not found: %v", err))
		return
	}

	privKey, err := ks.GetKey(attrs)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("key not found: %v", err))
		return
	}

	// Extract public key PEM
	var pubKeyPEM string
	pubKey, err := extractPublicKey(privKey)
	if err == nil {
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
		if err == nil {
			pemBlock := &pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: pubKeyBytes,
			}
			pubKeyPEM = string(pem.EncodeToMemory(pemBlock))
		}
	}

	s.sendJSON(w, http.StatusOK, KeyResponse{
		KeyID:        keyID,
		PublicKeyPEM: pubKeyPEM,
		Backend:      backendParam,
	})
}

// handleDeleteKey handles deleting a key
func (s *Server) handleDeleteKey(w http.ResponseWriter, r *http.Request, keyID, backendParam string) {
	ks, err := s.getKeystoreForBackend(backendParam)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", backendParam))
		return
	}

	// Find the key's full attributes
	attrs, err := s.findKeyByID(ks, keyID)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("key not found: %v", err))
		return
	}

	if err := ks.DeleteKey(attrs); err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("failed to delete key: %v", err))
		return
	}

	s.sendJSON(w, http.StatusOK, DeleteResponse{Success: true})
}

// handleSign handles signing data
func (s *Server) handleSign(w http.ResponseWriter, r *http.Request, keyID, backendParam string) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ks, err := s.getKeystoreForBackend(backendParam)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", backendParam))
		return
	}

	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	// Find the key's full attributes
	attrs, err := s.findKeyByID(ks, keyID)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("key not found: %v", err))
		return
	}

	signer, err := ks.Signer(attrs)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get signer: %v", err))
		return
	}

	var signature []byte

	// Ed25519 signs the raw message, not a hash
	if attrs.KeyAlgorithm == x509.Ed25519 {
		// Ed25519 uses crypto.Hash(0) to indicate no pre-hashing
		signature, err = signer.Sign(rand.Reader, req.Data, crypto.Hash(0))
		if err != nil {
			s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to sign: %v", err))
			return
		}
	} else {
		// RSA and ECDSA use hashed data
		hash, err := parseHashAlgorithm(req.Hash)
		if err != nil {
			s.sendError(w, http.StatusBadRequest, err.Error())
			return
		}

		hasher := hash.New()
		hasher.Write(req.Data)
		digest := hasher.Sum(nil)

		// Sign the digest
		signature, err = signer.Sign(rand.Reader, digest, hash)
		if err != nil {
			s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to sign: %v", err))
			return
		}
	}

	s.sendJSON(w, http.StatusOK, SignResponse{Signature: signature})
}

// handleVerify handles verifying a signature
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request, keyID, backendParam string) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ks, err := s.getKeystoreForBackend(backendParam)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", backendParam))
		return
	}

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	// Find the key's full attributes
	attrs, err := s.findKeyByID(ks, keyID)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("key not found: %v", err))
		return
	}

	// Get the key
	privKey, err := ks.GetKey(attrs)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("key not found: %v", err))
		return
	}

	pubKey, err := extractPublicKey(privKey)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to extract public key: %v", err))
		return
	}

	// Convert signature to bytes
	var sigBytes []byte
	switch sig := req.Signature.(type) {
	case []byte:
		sigBytes = sig
	case string:
		// Try base64 decoding first (JSON encodes []byte as base64)
		decoded, err := base64.StdEncoding.DecodeString(sig)
		if err != nil {
			// If not base64, use raw bytes
			sigBytes = []byte(sig)
		} else {
			sigBytes = decoded
		}
	case []interface{}:
		sigBytes = make([]byte, len(sig))
		for i, v := range sig {
			if b, ok := v.(float64); ok {
				sigBytes[i] = byte(b)
			}
		}
	default:
		// Try to marshal and unmarshal
		sigJSON, _ := json.Marshal(req.Signature)
		_ = json.Unmarshal(sigJSON, &sigBytes) // Best-effort unmarshal
	}

	var valid bool

	// Ed25519 verifies the raw message, not a hash
	if attrs.KeyAlgorithm == x509.Ed25519 {
		valid, err = verifySignature(pubKey, req.Data, sigBytes, crypto.Hash(0))
		if err != nil {
			s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to verify: %v", err))
			return
		}
	} else {
		// RSA and ECDSA verify against hashed data
		hash, err := parseHashAlgorithm(req.Hash)
		if err != nil {
			s.sendError(w, http.StatusBadRequest, err.Error())
			return
		}

		hasher := hash.New()
		hasher.Write(req.Data)
		digest := hasher.Sum(nil)

		valid, err = verifySignature(pubKey, digest, sigBytes, hash)
		if err != nil {
			s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to verify: %v", err))
			return
		}
	}

	s.sendJSON(w, http.StatusOK, VerifyResponse{Valid: valid})
}

// handleRotateKey handles key rotation
func (s *Server) handleRotateKey(w http.ResponseWriter, r *http.Request, keyID, backendParam string) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ks, err := s.getKeystoreForBackend(backendParam)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", backendParam))
		return
	}

	// Find the key's full attributes
	attrs, err := s.findKeyByID(ks, keyID)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("key not found: %v", err))
		return
	}

	privKey, err := ks.RotateKey(attrs)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to rotate key: %v", err))
		return
	}

	// Extract public key PEM
	var pubKeyPEM string
	if privKey != nil {
		pubKey, err := extractPublicKey(privKey)
		if err == nil {
			pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
			if err == nil {
				pemBlock := &pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: pubKeyBytes,
				}
				pubKeyPEM = string(pem.EncodeToMemory(pemBlock))
			}
		}
	}

	s.sendJSON(w, http.StatusOK, KeyResponse{
		KeyID:        keyID,
		PublicKeyPEM: pubKeyPEM,
		Backend:      backendParam,
	})
}

// handleEncrypt handles symmetric encryption
func (s *Server) handleEncrypt(w http.ResponseWriter, r *http.Request, keyID, backendParam string) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Default to symmetric backend for encryption operations
	if backendParam == "" {
		backendParam = "symmetric"
	}

	ks, err := s.getKeystoreForBackend(backendParam)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", backendParam))
		return
	}

	var req EncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	// Find the key's full attributes (includes algorithm, key type, etc.)
	attrs, err := s.findKeyByID(ks, keyID)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("key not found: %v", err))
		return
	}

	// Check if backend supports symmetric operations
	symBackend, ok := ks.Backend().(types.SymmetricBackend)
	if !ok {
		s.sendError(w, http.StatusBadRequest, "backend does not support symmetric encryption")
		return
	}

	// Get the symmetric encrypter
	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get encrypter: %v", err))
		return
	}

	// Prepare encryption options
	encryptOpts := &types.EncryptOptions{}
	if len(req.AdditionalData) > 0 {
		encryptOpts.AdditionalData = req.AdditionalData
	}

	// Encrypt the plaintext
	encrypted, err := encrypter.Encrypt(req.Plaintext, encryptOpts)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to encrypt: %v", err))
		return
	}

	s.sendJSON(w, http.StatusOK, EncryptResponse{
		Ciphertext: encrypted.Ciphertext,
		Nonce:      encrypted.Nonce,
		Tag:        encrypted.Tag,
	})
}

// handleDecrypt handles decryption (both asymmetric RSA and symmetric AES)
func (s *Server) handleDecrypt(w http.ResponseWriter, r *http.Request, keyID, backendParam string) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req DecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	// Find the key - search in specified backend or both if not specified
	var ks keychain.KeyStore
	var attrs *types.KeyAttributes
	var err error

	if backendParam != "" {
		ks, err = s.getKeystoreForBackend(backendParam)
		if err != nil {
			s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", backendParam))
			return
		}
		attrs, err = s.findKeyByID(ks, keyID)
		if err != nil {
			s.sendError(w, http.StatusNotFound, fmt.Sprintf("key not found: %v", err))
			return
		}
	} else {
		// No backend specified, search symmetric first, then software
		ks, err = s.getKeystoreForBackend("symmetric")
		if err == nil {
			attrs, err = s.findKeyByID(ks, keyID)
		}
		if err != nil {
			ks, err = s.getKeystoreForBackend("software")
			if err != nil {
				s.sendError(w, http.StatusNotFound, "backend not found")
				return
			}
			attrs, err = s.findKeyByID(ks, keyID)
			if err != nil {
				s.sendError(w, http.StatusNotFound, fmt.Sprintf("key not found: %v", err))
				return
			}
		}
	}

	// Check if this is a symmetric key based on key attributes
	if attrs.IsSymmetric() {
		// Symmetric decryption
		symBackend, ok := ks.Backend().(types.SymmetricBackend)
		if !ok {
			s.sendError(w, http.StatusBadRequest, "backend does not support symmetric decryption")
			return
		}

		encrypter, err := symBackend.SymmetricEncrypter(attrs)
		if err != nil {
			s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get encrypter: %v", err))
			return
		}

		// Prepare encrypted data
		encrypted := &types.EncryptedData{
			Ciphertext: req.Ciphertext,
			Nonce:      req.Nonce,
			Tag:        req.Tag,
		}

		// Prepare decryption options
		decryptOpts := &types.DecryptOptions{}
		if len(req.AdditionalData) > 0 {
			decryptOpts.AdditionalData = req.AdditionalData
		}

		plaintext, err := encrypter.Decrypt(encrypted, decryptOpts)
		if err != nil {
			s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to decrypt: %v", err))
			return
		}

		s.sendJSON(w, http.StatusOK, DecryptResponse{Plaintext: plaintext})
	} else {
		// Asymmetric decryption (RSA-OAEP with SHA256)
		decrypter, err := ks.Decrypter(attrs)
		if err != nil {
			s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get decrypter: %v", err))
			return
		}

		// Use RSA-OAEP options matching the encryption (SHA256)
		opts := &rsa.OAEPOptions{
			Hash: crypto.SHA256,
		}
		plaintext, err := decrypter.Decrypt(rand.Reader, req.Ciphertext, opts)
		if err != nil {
			s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to decrypt: %v", err))
			return
		}

		s.sendJSON(w, http.StatusOK, DecryptResponse{Plaintext: plaintext})
	}
}

// handleCerts handles certificate listing and creation
func (s *Server) handleCerts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListCerts(w, r)
	case http.MethodPost:
		s.handleSaveCert(w, r)
	default:
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleListCerts handles listing certificates
func (s *Server) handleListCerts(w http.ResponseWriter, r *http.Request) {
	keyIDs, err := s.keystore.ListCerts()
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list certificates: %v", err))
		return
	}

	s.sendJSON(w, http.StatusOK, ListCertsResponse{KeyIDs: keyIDs})
}

// handleSaveCert handles saving a certificate
func (s *Server) handleSaveCert(w http.ResponseWriter, r *http.Request) {
	var req CertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	if req.KeyID == "" {
		s.sendError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	if req.CertPEM == "" {
		s.sendError(w, http.StatusBadRequest, "cert_pem is required")
		return
	}

	// Parse PEM certificate
	block, _ := pem.Decode([]byte(req.CertPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		s.sendError(w, http.StatusBadRequest, "invalid certificate PEM")
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("failed to parse certificate: %v", err))
		return
	}

	if err := s.keystore.SaveCert(req.KeyID, cert); err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save certificate: %v", err))
		return
	}

	s.sendJSON(w, http.StatusCreated, DeleteResponse{Success: true})
}

// handleCertOperations handles operations on specific certificates
func (s *Server) handleCertOperations(w http.ResponseWriter, r *http.Request) {
	// Extract cert ID from path: /api/v1/certs/{certID}/...
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/certs/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		s.sendError(w, http.StatusBadRequest, "cert_id is required")
		return
	}

	certID := parts[0]

	// Determine operation
	var operation string
	if len(parts) > 1 {
		operation = parts[1]
	}

	switch operation {
	case "chain":
		s.handleCertChainOperations(w, r, certID)
	case "":
		// No operation - handle cert get/delete/exists
		switch r.Method {
		case http.MethodGet:
			s.handleGetCert(w, r, certID)
		case http.MethodDelete:
			s.handleDeleteCert(w, r, certID)
		case http.MethodHead:
			s.handleCertExists(w, r, certID)
		default:
			s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	default:
		s.sendError(w, http.StatusNotFound, "operation not found")
	}
}

// handleGetCert handles retrieving a certificate
func (s *Server) handleGetCert(w http.ResponseWriter, r *http.Request, certID string) {
	cert, err := s.keystore.GetCert(certID)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("certificate not found: %v", err))
		return
	}

	// Encode to PEM
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	certPEM := string(pem.EncodeToMemory(pemBlock))

	s.sendJSON(w, http.StatusOK, CertResponse{
		KeyID:   certID,
		CertPEM: certPEM,
	})
}

// handleDeleteCert handles deleting a certificate
func (s *Server) handleDeleteCert(w http.ResponseWriter, r *http.Request, certID string) {
	if err := s.keystore.DeleteCert(certID); err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("failed to delete certificate: %v", err))
		return
	}

	s.sendJSON(w, http.StatusOK, DeleteResponse{Success: true})
}

// handleCertExists handles checking if a certificate exists
func (s *Server) handleCertExists(w http.ResponseWriter, r *http.Request, certID string) {
	exists, err := s.keystore.CertExists(certID)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to check certificate: %v", err))
		return
	}

	if exists {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
}

// handleCertChainOperations handles certificate chain operations
func (s *Server) handleCertChainOperations(w http.ResponseWriter, r *http.Request, certID string) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetCertChain(w, r, certID)
	case http.MethodPost:
		s.handleSaveCertChain(w, r, certID)
	default:
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleSaveCertChain handles saving a certificate chain
func (s *Server) handleSaveCertChain(w http.ResponseWriter, r *http.Request, certID string) {
	var req CertChainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	if len(req.ChainPEMs) == 0 {
		s.sendError(w, http.StatusBadRequest, "chain_pems is required")
		return
	}

	// Parse all certificates
	chain := make([]*x509.Certificate, 0, len(req.ChainPEMs))
	for i, pemStr := range req.ChainPEMs {
		block, _ := pem.Decode([]byte(pemStr))
		if block == nil || block.Type != "CERTIFICATE" {
			s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid certificate PEM at index %d", i))
			return
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			s.sendError(w, http.StatusBadRequest, fmt.Sprintf("failed to parse certificate at index %d: %v", i, err))
			return
		}

		chain = append(chain, cert)
	}

	if err := s.keystore.SaveCertChain(certID, chain); err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save certificate chain: %v", err))
		return
	}

	s.sendJSON(w, http.StatusCreated, DeleteResponse{Success: true})
}

// handleGetCertChain handles retrieving a certificate chain
func (s *Server) handleGetCertChain(w http.ResponseWriter, r *http.Request, certID string) {
	chain, err := s.keystore.GetCertChain(certID)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("certificate chain not found: %v", err))
		return
	}

	// Encode all certificates to PEM
	chainPEMs := make([]string, len(chain))
	for i, cert := range chain {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		chainPEMs[i] = string(pem.EncodeToMemory(pemBlock))
	}

	s.sendJSON(w, http.StatusOK, CertChainResponse{
		KeyID:     certID,
		ChainPEMs: chainPEMs,
	})
}

// handleTLSCertificate handles getting a TLS certificate
func (s *Server) handleTLSCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Extract cert ID from path: /api/v1/tls/{certID}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/tls/")
	certID := path

	if certID == "" {
		s.sendError(w, http.StatusBadRequest, "cert_id is required")
		return
	}

	backendParam := r.URL.Query().Get("backend")

	attrs := &types.KeyAttributes{
		CN: certID,
	}

	if backendParam != "" {
		storeType := types.ParseStoreType(backendParam)
		if storeType == types.StoreUnknown {
			s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid backend: %s", backendParam))
			return
		}
		attrs.StoreType = storeType
	}

	tlsCert, err := s.keystore.GetTLSCertificate(certID, attrs)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("TLS certificate not found: %v", err))
		return
	}

	// Convert certificate to PEM
	var certPEM string
	if len(tlsCert.Certificate) > 0 {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: tlsCert.Certificate[0],
		}
		certPEM = string(pem.EncodeToMemory(pemBlock))
	}

	// Convert chain to PEM
	chainPEMs := make([]string, 0, len(tlsCert.Certificate)-1)
	for i := 1; i < len(tlsCert.Certificate); i++ {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: tlsCert.Certificate[i],
		}
		chainPEMs = append(chainPEMs, string(pem.EncodeToMemory(pemBlock)))
	}

	// Determine private key type
	var keyType string
	if tlsCert.PrivateKey != nil {
		keyType = fmt.Sprintf("%T", tlsCert.PrivateKey)
	}

	s.sendJSON(w, http.StatusOK, TLSCertificateResponse{
		CertPEM:        certPEM,
		ChainPEMs:      chainPEMs,
		PrivateKeyType: keyType,
	})
}

// sendJSON sends a JSON response
func (s *Server) sendJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		s.logger.Error("Error encoding response", logger.Error(err))
	}
}

// sendError sends an error response
func (s *Server) sendError(w http.ResponseWriter, status int, message string) {
	s.logger.Warn("QUIC request error",
		logger.Int("status", status),
		logger.String("error", message))
	s.sendJSON(w, status, ErrorResponse{
		Error:   http.StatusText(status),
		Message: message,
	})
}

// handleGetImportParameters handles getting import parameters for key import
func (s *Server) handleGetImportParameters(w http.ResponseWriter, r *http.Request, keyID, backendParam string) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req GetImportParametersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	attrs := &types.KeyAttributes{
		CN: keyID,
	}

	if backendParam != "" {
		storeType := types.ParseStoreType(backendParam)
		if storeType == types.StoreUnknown {
			s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid backend: %s", backendParam))
			return
		}
		attrs.StoreType = storeType
	}

	// Get the correct keystore for the backend
	ks, err := s.getKeystoreForBackend(backendParam)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", backendParam))
		return
	}

	// Check if backend supports import/export
	importExportBackend, ok := ks.Backend().(backend.ImportExportBackend)
	if !ok {
		s.sendError(w, http.StatusBadRequest, "backend does not support import/export operations")
		return
	}

	// Parse wrapping algorithm
	algorithm := backend.WrappingAlgorithm(req.Algorithm)

	// Get import parameters
	params, err := importExportBackend.GetImportParameters(attrs, algorithm)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get import parameters: %v", err))
		return
	}

	// Encode public key to PEM
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(params.WrappingPublicKey)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to marshal public key: %v", err))
		return
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}
	pubKeyPEM := string(pem.EncodeToMemory(pemBlock))

	resp := GetImportParametersResponse{
		WrappingPublicKeyPEM: pubKeyPEM,
		ImportToken:          params.ImportToken,
		Algorithm:            string(params.Algorithm),
		KeySpec:              params.KeySpec,
	}

	// Add expiration time if present
	if params.ExpiresAt != nil {
		expiresAt := params.ExpiresAt.Format("2006-01-02T15:04:05Z07:00")
		resp.ExpiresAt = &expiresAt
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// handleGetImportParams handles POST /api/v1/keys/import-params requests
// This is the global endpoint (no key ID in path) that takes all params from request body
func (s *Server) handleGetImportParams(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req GetImportParametersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	// Validate required fields
	if req.Backend == "" {
		s.sendError(w, http.StatusBadRequest, "backend is required")
		return
	}
	if req.KeyID == "" {
		s.sendError(w, http.StatusBadRequest, "key_id is required")
		return
	}
	if req.KeyType == "" {
		s.sendError(w, http.StatusBadRequest, "key_type is required")
		return
	}
	if req.Algorithm == "" {
		s.sendError(w, http.StatusBadRequest, "algorithm is required")
		return
	}

	// Get the correct keystore for the backend
	ks, err := s.getKeystoreForBackend(req.Backend)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", req.Backend))
		return
	}

	// Check if backend supports import/export
	importExportBackend, ok := ks.Backend().(backend.ImportExportBackend)
	if !ok {
		s.sendError(w, http.StatusBadRequest, "backend does not support import/export operations")
		return
	}

	// Build key attributes from request
	attrs := &types.KeyAttributes{
		CN: req.KeyID,
	}

	// Set store type
	storeType := types.ParseStoreType(req.Backend)
	if storeType != types.StoreUnknown {
		attrs.StoreType = storeType
	}

	// Set key type based on the request
	switch req.KeyType {
	case "rsa", "RSA":
		attrs.KeyType = types.KeyTypeTLS
		attrs.KeyAlgorithm = x509.RSA
		keySize := req.KeySize
		if keySize == 0 {
			keySize = 2048
		}
		attrs.RSAAttributes = &types.RSAAttributes{
			KeySize: keySize,
		}
	case "ecdsa", "ECDSA":
		attrs.KeyType = types.KeyTypeTLS
		attrs.KeyAlgorithm = x509.ECDSA
		curve := req.Curve
		if curve == "" {
			curve = "P-256"
		}
		parsedCurve, err := types.ParseCurve(curve)
		if err != nil {
			s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid curve: %v", err))
			return
		}
		attrs.ECCAttributes = &types.ECCAttributes{
			Curve: parsedCurve,
		}
	case "ed25519", "Ed25519":
		attrs.KeyType = types.KeyTypeTLS
		attrs.KeyAlgorithm = x509.Ed25519
	case "signing":
		attrs.KeyType = types.KeyTypeTLS
	case "encryption":
		attrs.KeyType = types.KeyTypeEncryption
	case "aes", "AES", "symmetric":
		attrs.KeyType = types.KeyTypeSecret
		keySize := req.AESKeySize
		if keySize == 0 && req.KeySize > 0 {
			keySize = req.KeySize
		}
		if keySize == 128 {
			attrs.SymmetricAlgorithm = types.SymmetricAES128GCM
		} else if keySize == 192 {
			attrs.SymmetricAlgorithm = types.SymmetricAES192GCM
		} else {
			attrs.SymmetricAlgorithm = types.SymmetricAES256GCM
		}
	default:
		// For unknown types, try to determine from other fields
		attrs.KeyType = types.KeyTypeTLS
	}

	// Parse wrapping algorithm
	algorithm := backend.WrappingAlgorithm(req.Algorithm)

	// Get import parameters
	params, err := importExportBackend.GetImportParameters(attrs, algorithm)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get import parameters: %v", err))
		return
	}

	// Encode public key to PEM
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(params.WrappingPublicKey)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to marshal public key: %v", err))
		return
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}
	pubKeyPEM := string(pem.EncodeToMemory(pemBlock))

	resp := GetImportParametersResponse{
		WrappingPublicKeyPEM: pubKeyPEM,
		ImportToken:          params.ImportToken,
		Algorithm:            string(params.Algorithm),
		KeySpec:              params.KeySpec,
	}

	// Add expiration time if present
	if params.ExpiresAt != nil {
		expiresAt := params.ExpiresAt.Format("2006-01-02T15:04:05Z07:00")
		resp.ExpiresAt = &expiresAt
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// handleWrapKey handles wrapping key material for secure transport
func (s *Server) handleWrapKey(w http.ResponseWriter, r *http.Request, keyID, backendParam string) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req WrapKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	// Get the correct keystore for the backend
	ks, err := s.getKeystoreForBackend(backendParam)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", backendParam))
		return
	}

	// Check if backend supports import/export
	importExportBackend, ok := ks.Backend().(backend.ImportExportBackend)
	if !ok {
		s.sendError(w, http.StatusBadRequest, "backend does not support import/export operations")
		return
	}

	// Parse wrapping public key from PEM
	block, _ := pem.Decode([]byte(req.WrappingPublicKeyPEM))
	if block == nil {
		s.sendError(w, http.StatusBadRequest, "invalid wrapping public key PEM")
		return
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("failed to parse public key: %v", err))
		return
	}

	// Build import parameters
	params := &backend.ImportParameters{
		WrappingPublicKey: pubKey,
		ImportToken:       req.ImportToken,
		Algorithm:         backend.WrappingAlgorithm(req.Algorithm),
	}

	// Wrap the key material
	wrapped, err := importExportBackend.WrapKey(req.KeyMaterial, params)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to wrap key: %v", err))
		return
	}

	s.sendJSON(w, http.StatusOK, WrapKeyResponse{
		WrappedKey:  wrapped.WrappedKey,
		Algorithm:   string(wrapped.Algorithm),
		ImportToken: wrapped.ImportToken,
		Metadata:    wrapped.Metadata,
	})
}

// handleImportKey handles importing externally generated key material
func (s *Server) handleImportKey(w http.ResponseWriter, r *http.Request, keyID, backendParam string) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req ImportKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	attrs := &types.KeyAttributes{
		CN: keyID,
	}

	if backendParam != "" {
		storeType := types.ParseStoreType(backendParam)
		if storeType == types.StoreUnknown {
			s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid backend: %s", backendParam))
			return
		}
		attrs.StoreType = storeType
	}

	// Get the correct keystore for the backend
	ks, err := s.getKeystoreForBackend(backendParam)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", backendParam))
		return
	}

	// Check if backend supports import/export
	importExportBackend, ok := ks.Backend().(backend.ImportExportBackend)
	if !ok {
		s.sendError(w, http.StatusBadRequest, "backend does not support import/export operations")
		return
	}

	// Build wrapped key material
	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  req.WrappedKey,
		Algorithm:   backend.WrappingAlgorithm(req.Algorithm),
		ImportToken: req.ImportToken,
		Metadata:    req.Metadata,
	}

	// Import the key
	if err := importExportBackend.ImportKey(attrs, wrapped); err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to import key: %v", err))
		return
	}

	s.sendJSON(w, http.StatusOK, DeleteResponse{Success: true})
}

// handleExportKey handles exporting a key in wrapped form
func (s *Server) handleExportKey(w http.ResponseWriter, r *http.Request, keyID, backendParam string) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req ExportKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	// Get the correct keystore for the backend
	ks, err := s.getKeystoreForBackend(backendParam)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", backendParam))
		return
	}

	// Find the key's full attributes (includes exportable flag, algorithm, etc.)
	attrs, err := s.findKeyByID(ks, keyID)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("key not found: %v", err))
		return
	}

	if backendParam != "" {
		storeType := types.ParseStoreType(backendParam)
		if storeType == types.StoreUnknown {
			s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid backend: %s", backendParam))
			return
		}
		attrs.StoreType = storeType
	}

	// Check if backend supports import/export
	importExportBackend, ok := ks.Backend().(backend.ImportExportBackend)
	if !ok {
		s.sendError(w, http.StatusBadRequest, "backend does not support import/export operations")
		return
	}

	// Parse wrapping algorithm
	algorithm := backend.WrappingAlgorithm(req.Algorithm)

	// Export the key
	wrapped, err := importExportBackend.ExportKey(attrs, algorithm)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to export key: %v", err))
		return
	}

	s.sendJSON(w, http.StatusOK, ExportKeyResponse{
		WrappedKey:  wrapped.WrappedKey,
		Algorithm:   string(wrapped.Algorithm),
		ImportToken: wrapped.ImportToken,
		Metadata:    wrapped.Metadata,
	})
}

// handleAsymmetricEncrypt handles asymmetric (RSA) encryption
func (s *Server) handleAsymmetricEncrypt(w http.ResponseWriter, r *http.Request, keyID, backendParam string) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req AsymmetricEncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	// Get the correct keystore for the backend
	ks, err := s.getKeystoreForBackend(backendParam)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", backendParam))
		return
	}

	// Find the key's full attributes
	attrs, err := s.findKeyByID(ks, keyID)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("key not found: %v", err))
		return
	}

	// Get the key
	privKey, err := ks.GetKey(attrs)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("key not found: %v", err))
		return
	}

	// Extract public key for encryption
	pubKey, err := extractPublicKey(privKey)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to extract public key: %v", err))
		return
	}

	// Encrypt with RSA-OAEP
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		s.sendError(w, http.StatusBadRequest, "key is not an RSA key")
		return
	}

	hash := crypto.SHA256
	ciphertext, err := rsa.EncryptOAEP(hash.New(), rand.Reader, rsaPubKey, req.Plaintext, nil)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to encrypt: %v", err))
		return
	}

	s.sendJSON(w, http.StatusOK, EncryptResponse{
		Ciphertext: ciphertext,
		Nonce:      nil, // Not used for asymmetric encryption
		Tag:        nil, // Not used for asymmetric encryption
	})
}

// handleCopyKey handles copying a key from one backend to another
func (s *Server) handleCopyKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req CopyKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	// Validate required fields
	if req.SourceBackend == "" {
		s.sendError(w, http.StatusBadRequest, "source_backend is required")
		return
	}
	if req.SourceKeyID == "" {
		s.sendError(w, http.StatusBadRequest, "source_key_id is required")
		return
	}
	if req.DestBackend == "" {
		s.sendError(w, http.StatusBadRequest, "dest_backend is required")
		return
	}
	if req.DestKeyID == "" {
		s.sendError(w, http.StatusBadRequest, "dest_key_id is required")
		return
	}
	if req.Algorithm == "" {
		s.sendError(w, http.StatusBadRequest, "algorithm is required")
		return
	}

	// Get source and destination backends
	sourceKS, err := keychain.Backend(req.SourceBackend)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("source backend not found: %v", err))
		return
	}
	sourceBackend, ok := sourceKS.Backend().(backend.ImportExportBackend)
	if !ok {
		s.sendError(w, http.StatusBadRequest, "source backend does not support import/export operations")
		return
	}

	destKS, err := keychain.Backend(req.DestBackend)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("destination backend not found: %v", err))
		return
	}
	destBackend, ok := destKS.Backend().(backend.ImportExportBackend)
	if !ok {
		s.sendError(w, http.StatusBadRequest, "destination backend does not support import/export operations")
		return
	}

	// Build source key attributes
	sourceAttrs := &types.KeyAttributes{
		CN: req.SourceKeyID,
	}
	if req.SourceBackend != "" {
		storeType := types.ParseStoreType(req.SourceBackend)
		if storeType == types.StoreUnknown {
			s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid source backend: %s", req.SourceBackend))
			return
		}
		sourceAttrs.StoreType = storeType
	}

	// Build destination key attributes
	destAttrs := &types.KeyAttributes{
		CN: req.DestKeyID,
	}
	if req.DestBackend != "" {
		storeType := types.ParseStoreType(req.DestBackend)
		if storeType == types.StoreUnknown {
			s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid destination backend: %s", req.DestBackend))
			return
		}
		destAttrs.StoreType = storeType
	}

	// Parse wrapping algorithm
	algorithm := backend.WrappingAlgorithm(req.Algorithm)

	// Export from source backend
	wrapped, err := sourceBackend.ExportKey(sourceAttrs, algorithm)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to export key: %v", err))
		return
	}

	// Import to destination backend
	if err := destBackend.ImportKey(destAttrs, wrapped); err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to import key: %v", err))
		return
	}

	s.sendJSON(w, http.StatusOK, CopyKeyResponse{
		Success: true,
		Message: fmt.Sprintf("Key copied from %s/%s to %s/%s successfully",
			req.SourceBackend, req.SourceKeyID, req.DestBackend, req.DestKeyID),
	})
}
