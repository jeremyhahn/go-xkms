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

package quic

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// HealthResponse represents a health check response
type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version,omitempty"`
}

// BackendInfo represents information about a backend
type BackendInfo struct {
	ID             string             `json:"id"`
	Type           string             `json:"type"`
	HardwareBacked bool               `json:"hardware_backed"`
	Capabilities   types.Capabilities `json:"capabilities"`
}

// ListBackendsResponse represents the backends list response
type ListBackendsResponse struct {
	Backends   []BackendInfo           `json:"backends"`
	Pagination *transport.PageResponse `json:"pagination,omitempty"`
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
	Sensitive  bool   `json:"sensitive,omitempty"`  // CKA_SENSITIVE: plaintext is never released
}

// KeyResponse represents a key response
type KeyResponse struct {
	KeyID        string `json:"key_id"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	Backend      string `json:"backend,omitempty"`
}

// RotateKeyResponse represents a key rotation response
type RotateKeyResponse struct {
	Success      bool   `json:"success"`
	KeyID        string `json:"key_id"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	Backend      string `json:"backend,omitempty"`
	Message      string `json:"message,omitempty"`
}

// ListKeysResponse represents the keys list response
type ListKeysResponse struct {
	Keys       []KeyInfo               `json:"keys"`
	Pagination *transport.PageResponse `json:"pagination,omitempty"`
}

// KeyInfo represents basic key information
type KeyInfo struct {
	KeyID   string `json:"key_id"`
	Backend string `json:"backend,omitempty"`
}

// SignRequest represents a signing request.
//
// Every field below is forwarded verbatim to transport.SignRequest; see that
// type for the authoritative semantics. This struct exists only to give the
// QUIC wire its own JSON shape (the key ID and backend travel in the path and
// query string rather than the body), not to reinterpret any parameter.
type SignRequest struct {
	Data []byte `json:"data"`
	Hash string `json:"hash"`
	// DataIsDigest states that Data is already the digest and must not be
	// hashed again, while Hash still names which digest produced it.
	// RSASSA-PSS needs both facts at once, so they are separate fields.
	DataIsDigest bool `json:"data_is_digest,omitempty"`
	// Padding selects the RSA signature padding scheme: "" or "pkcs1v15"
	// (default, PKCS#1 v1.5) or "pss" (RSASSA-PSS).
	Padding string `json:"padding,omitempty"`
	// SaltLength is the RSA-PSS salt length in bytes. Zero selects
	// rsa.PSSSaltLengthAuto. Ignored unless Padding is "pss".
	SaltLength int `json:"salt_length,omitempty"`
	// PreHash selects the pre-hashed EdDSA variant (Ed25519ph) per RFC 8032
	// Table 73. Only meaningful for Ed25519 keys.
	PreHash bool `json:"pre_hash,omitempty"`
	// Context is the optional EdDSA context string (Ed25519ctx).
	Context []byte `json:"context,omitempty"`
}

// SignResponse represents a signing response
type SignResponse struct {
	Signature interface{} `json:"signature"`
	// Algorithm names the key algorithm that produced the signature, as
	// reported by the service layer.
	Algorithm string `json:"algorithm,omitempty"`
}

// VerifyRequest represents a verification request. Its parameters mirror
// SignRequest's and must match those used to produce Signature.
type VerifyRequest struct {
	Data      []byte      `json:"data"`
	Signature interface{} `json:"signature"`
	Hash      string      `json:"hash"`
	// DataIsDigest states that Data is already the digest. See
	// SignRequest.DataIsDigest.
	DataIsDigest bool `json:"data_is_digest,omitempty"`
	// Padding selects the RSA signature padding scheme. See
	// SignRequest.Padding.
	Padding string `json:"padding,omitempty"`
	// SaltLength is the RSA-PSS salt length in bytes the signature is
	// expected to use. Zero selects rsa.PSSSaltLengthAuto (auto-detect).
	SaltLength int `json:"salt_length,omitempty"`
	// PreHash selects the pre-hashed EdDSA variant. See SignRequest.PreHash.
	PreHash bool `json:"pre_hash,omitempty"`
	// Context is the optional EdDSA context string. See SignRequest.Context.
	Context []byte `json:"context,omitempty"`
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
	// Nonce optionally supplies the AEAD nonce to use. If empty, the backend
	// generates a random one and returns it in EncryptResponse.Nonce. Only
	// meaningful for the default AEAD mode; AES-CBC uses IV instead.
	Nonce []byte `json:"nonce,omitempty"`
	// Mode selects the cipher mode of operation: "" (default AEAD, AES-GCM or
	// ChaCha20-Poly1305), "cbc" (unpadded AES-CBC; Plaintext must already be a
	// whole number of AES blocks), or "cbc-pad" (AES-CBC with PKCS#7 padding).
	Mode string `json:"mode,omitempty"`
	// IV supplies the AES-CBC initialization vector, exactly 16 bytes. Ignored
	// for the default AEAD mode. If empty with a CBC Mode, a random IV is
	// generated and returned in EncryptResponse.IV.
	IV []byte `json:"iv,omitempty"`
	// TagSize is the AEAD authentication tag length in bytes; 0 selects the
	// cipher's full-length tag. AES-GCM admits 12-16 bytes per NIST
	// SP 800-38D section 5.2.1.2.
	TagSize int `json:"tag_size,omitempty"`
}

// EncryptResponse represents an encryption response
type EncryptResponse struct {
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
	Tag        []byte `json:"tag"`
	// IV is the AES-CBC initialization vector used for encryption. Populated
	// only when the request's Mode was "cbc" or "cbc-pad".
	IV []byte `json:"iv,omitempty"`
}

// DecryptRequest represents a decryption request
type DecryptRequest struct {
	Ciphertext     []byte `json:"ciphertext"`
	AdditionalData []byte `json:"additional_data,omitempty"` // Optional AAD for symmetric decryption
	Nonce          []byte `json:"nonce,omitempty"`           // Required for symmetric decryption
	Tag            []byte `json:"tag,omitempty"`             // Required for symmetric decryption (GCM)
	Algorithm      string `json:"algorithm,omitempty"`       // Symmetric algorithm (e.g., "aes256-gcm")
	// Mode selects the cipher mode of operation. See EncryptRequest.Mode;
	// must match the Mode used to produce Ciphertext.
	Mode string `json:"mode,omitempty"`
	// IV is the AES-CBC initialization vector used at encryption time,
	// exactly 16 bytes. Required when Mode is "cbc" or "cbc-pad".
	IV []byte `json:"iv,omitempty"`
	// TagSize is the AEAD authentication tag length in bytes that Tag
	// carries; 0 selects the cipher's full-length tag. It must equal the
	// TagSize used to encrypt.
	TagSize int `json:"tag_size,omitempty"`
	// Padding selects the RSA decryption scheme for an asymmetric key:
	// "" or "pkcs1v15" (default), or "oaep". This handler used to force
	// OAEP-SHA-256 unconditionally, so a PKCS#1 v1.5 ciphertext could not be
	// decrypted here at all and an OAEP ciphertext under any other digest
	// failed with an error that read like corruption.
	Padding string `json:"padding,omitempty"`
	// Hash names the OAEP digest (e.g. "SHA-256"). Ignored unless Padding is
	// "oaep"; empty selects SHA-256, which is what the encrypt half of this
	// service produces for an unnamed digest. RFC 8017's own default of SHA-1
	// is refused when named explicitly -- see xkms.ResolveOAEPHash.
	Hash string `json:"hash,omitempty"`
	// Label is the optional OAEP label. Ignored unless Padding is "oaep".
	Label []byte `json:"label,omitempty"`
}

// DecryptResponse represents a decryption response
type DecryptResponse struct {
	Plaintext []byte `json:"plaintext"`
}

// CertRequest represents a certificate save request
type CertRequest struct {
	KeyID          string `json:"key_id"`
	CertPEM        string `json:"cert_pem"`
	CertificatePEM string `json:"certificate_pem"` // Alternative field name for SDK compatibility
}

// CertResponse represents a certificate response
type CertResponse struct {
	KeyID          string `json:"key_id"`
	CertificatePEM string `json:"certificate_pem"`
}

// ListCertsResponse represents the certificates list response
type ListCertsResponse struct {
	KeyIDs     []string                `json:"key_ids"`
	Pagination *transport.PageResponse `json:"pagination,omitempty"`
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

// UnwrapKeyRequest represents a request to unwrap key material
type UnwrapKeyRequest struct {
	WrappedKey           []byte            `json:"wrapped_key"`
	WrappingPublicKeyPEM string            `json:"wrapping_public_key_pem"`
	ImportToken          []byte            `json:"import_token,omitempty"`
	Algorithm            string            `json:"algorithm"`
	Metadata             map[string]string `json:"metadata,omitempty"`
}

// UnwrapKeyResponse represents the unwrapped key response
type UnwrapKeyResponse struct {
	KeyMaterial []byte `json:"key_material"`
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
	// Hash names the RSA-OAEP digest (e.g. "SHA-384"). Empty selects
	// SHA-256. The digest is part of the ciphertext's construction, so a
	// caller that asks for one hash and gets another produces a blob its
	// intended recipient cannot open.
	Hash string `json:"hash,omitempty"`
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

	s.sendJSON(w, http.StatusOK, HealthResponse{Status: "healthy", Version: s.version})
}

// handleListBackends handles backend listing
func (s *Server) handleListBackends(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, auth.ResourceBackends, auth.ActionList) {
		return
	}

	backendNames := s.backendNames()

	backends := make([]BackendInfo, 0, len(backendNames))
	for _, name := range backendNames {
		ks, err := s.lookupBackend(name)
		if err != nil {
			continue // Skip backends that can't be retrieved
		}

		backendImpl := ks.KeyProvider()
		caps := backendImpl.Capabilities()

		backends = append(backends, BackendInfo{
			ID:             name,
			Type:           string(backendImpl.Type()),
			HardwareBacked: caps.HardwareBacked,
			Capabilities:   caps,
		})
	}

	pr := transport.PageRequestFromQuery(r)
	paginatedBackends, pageResp := transport.ApplyPagination(backends, pr)

	s.sendJSON(w, http.StatusOK, ListBackendsResponse{
		Backends:   paginatedBackends,
		Pagination: &pageResp,
	})
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

	if !s.authorize(w, r, auth.ResourceBackends, auth.ActionRead) {
		return
	}

	// Get the backend
	ks, err := s.lookupBackend(backendID)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", backendID))
		return
	}

	backendImpl := ks.KeyProvider()
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
	if !s.authorize(w, r, auth.ResourceKeys, auth.ActionList) {
		return
	}

	backendParam := r.URL.Query().Get("backend")

	// Get the keystore for the specified backend
	ks, err := s.getKeystoreForBackend(backendParam)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", backendParam))
		return
	}

	// List keys from keystore
	attrs, err := ks.ListKeys(r.Context())
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list keys: %v", err))
		return
	}

	// Drop anything the resolved backend reports that does not belong to it.
	//
	// The comparison is against the backend's own store type, not against the
	// name it is registered under. Those are only the same string for a backend
	// whose configuration name happens to match its type: a pkcs11 backend
	// registered as "prod-hsm" matched nothing, so every key it held was
	// filtered out and the list came back empty.
	storeType := types.StoreType(ks.KeyProvider().Type())

	keys := make([]KeyInfo, 0, len(attrs))
	for _, attr := range attrs {
		if attr.StoreType != "" && attr.StoreType != storeType {
			continue
		}

		keys = append(keys, KeyInfo{
			KeyID:   attr.CN,
			Backend: string(attr.StoreType),
		})
	}

	pr := transport.PageRequestFromQuery(r)
	paginatedKeys, pageResp := transport.ApplyPagination(keys, pr)

	s.sendJSON(w, http.StatusOK, ListKeysResponse{
		Keys:       paginatedKeys,
		Pagination: &pageResp,
	})
}

// handleGenerateKey handles key generation
func (s *Server) handleGenerateKey(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ResourceKeys, auth.ActionCreate) {
		return
	}

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
	ks, err := s.lookupBackend(req.Backend)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", req.Backend))
		return
	}

	// Parse key type from request (e.g., "tls", "signing", "encryption")
	keyType := types.ParseKeyType(req.KeyType)
	// Default to KeyTypeSigning if the parsed key type is invalid
	// (e.g., when req.KeyType is an algorithm name like "rsa", "ecdsa", "ed25519")
	if keyType == 0 {
		keyType = types.KeyTypeSigning
	}

	// Create key attributes
	attrs := &types.KeyAttributes{
		CN:         req.KeyID,
		KeyType:    keyType,
		Exportable: req.Exportable,
		Sensitive:  req.Sensitive,
	}

	// The store type comes from the resolved backend, not from parsing its
	// registered name. Those are only the same string for a backend whose
	// configuration name happens to match its type: a pkcs11 backend registered
	// as "prod-hsm" parsed to StoreUnknown and was refused with 400, even
	// though lookupBackend had just resolved it. This is the same conflation
	// handleListKeys made when filtering.
	attrs.StoreType = types.StoreType(ks.KeyProvider().Type())

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
		privKey, err = ks.GenerateRSA(r.Context(), attrs)

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
		privKey, err = ks.GenerateECDSA(r.Context(), attrs)

	case types.AlgorithmEd25519.Equals(algorithm):
		privKey, err = ks.GenerateEd25519(r.Context(), attrs)

	case symmetricAlgorithm(algorithm) != "":
		// For AES keys, check if backend supports symmetric operations
		symBackend, ok := ks.KeyProvider().(types.SymmetricKeyProvider)
		if !ok {
			s.sendError(w, http.StatusBadRequest, "backend does not support symmetric encryption")
			return
		}

		attrs.SymmetricAlgorithm = symmetricAlgorithm(algorithm)

		// A bare "symmetric" or "secret" names no cipher, so the key size
		// selects one. A request that named its cipher outright keeps it: the
		// size is already implied by the name, and overriding it here would
		// generate a key the caller did not ask for.
		if types.AlgorithmSymmetric.Equals(algorithm) || types.KeyTypeStringSecret.Equals(algorithm) {
			switch req.KeySize {
			case 128:
				attrs.SymmetricAlgorithm = types.SymmetricAES128GCM
			case 192:
				attrs.SymmetricAlgorithm = types.SymmetricAES192GCM
			case 256, 0:
				attrs.SymmetricAlgorithm = types.SymmetricAES256GCM
			default:
				s.sendError(w, http.StatusBadRequest, fmt.Sprintf("unsupported AES key size: %d", req.KeySize))
				return
			}
		}

		// Set correct key type for symmetric keys
		attrs.KeyType = types.KeyTypeSecret

		// Generate the symmetric key
		_, err = symBackend.GenerateSymmetricKey(r.Context(), attrs)
		// For symmetric keys, we don't return the key material
		privKey = nil

	default:
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("unsupported algorithm: %s", algorithm))
		return
	}

	if err != nil {
		s.sendServiceError(r.Context(), w, err, http.StatusInternalServerError, fmt.Sprintf("failed to generate key: %v", err))
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

// symmetricAlgorithm resolves an algorithm name to the symmetric cipher it
// selects, or "" when the name is not a symmetric one.
//
// It mirrors the service layer's own parsing (xkms's parseSymmetricAlgorithm,
// which is unexported): every spelling types.ParseAEADAlgorithm accepts, plus
// the two bare names that mean "a symmetric key, you pick the cipher". This
// transport used to match the literal "symmetric" and nothing else, so a
// request naming its cipher outright -- "aes-256-gcm", "chacha20-poly1305" --
// was refused as an unsupported algorithm even though the service accepts it.
func symmetricAlgorithm(algorithm string) types.SymmetricAlgorithm {
	if sym := types.ParseAEADAlgorithm(algorithm).ToSymmetricAlgorithm(); sym != "" {
		return sym
	}
	if types.AlgorithmSymmetric.Equals(algorithm) || types.KeyTypeStringSecret.Equals(algorithm) {
		return types.SymmetricAES256GCM
	}
	return ""
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

	// Determine operation - handle multi-part operations like "versions/enable"
	var operation string
	if len(parts) > 1 {
		operation = strings.Join(parts[1:], "/")
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
	case "unwrap":
		s.handleUnwrapKey(w, r, keyID, backendParam)
	case "import":
		s.handleImportKey(w, r, keyID, backendParam)
	case "export":
		s.handleExportKey(w, r, keyID, backendParam)
	case "export-material":
		s.handleExportKeyMaterial(w, r, keyID, backendParam)
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
func (s *Server) getKeystoreForBackend(backendParam string) (xkms.Backend, error) {
	if backendParam != "" {
		return s.lookupBackend(backendParam)
	}
	return s.keystore, nil
}

// findKeyByID finds a key's attributes by its ID (CN) in the keystore
// Returns the full key attributes needed for operations like GetKey, Sign, etc.
func (s *Server) findKeyByID(ctx context.Context, ks xkms.Backend, keyID string) (*types.KeyAttributes, error) {
	keys, err := ks.ListKeys(ctx)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to list keys", Err: err}
	}

	for _, attr := range keys {
		if attr.CN == keyID {
			return attr, nil
		}
	}

	return nil, &errs.Message{Msg: fmt.Sprintf("key not found: %s", keyID)}
}

// handleGetKey handles retrieving a key
func (s *Server) handleGetKey(w http.ResponseWriter, r *http.Request, keyID, backendParam string) {
	if !s.authorize(w, r, auth.ResourceKeys, auth.ActionGet) {
		return
	}

	ks, err := s.getKeystoreForBackend(backendParam)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", backendParam))
		return
	}

	// Find the key's full attributes
	attrs, err := s.findKeyByID(r.Context(), ks, keyID)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("key not found: %v", err))
		return
	}

	privKey, err := ks.GetKey(r.Context(), attrs)
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
	if !s.authorize(w, r, auth.ResourceKeys, auth.ActionDelete) {
		return
	}

	ks, err := s.getKeystoreForBackend(backendParam)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", backendParam))
		return
	}

	// Find the key's full attributes
	attrs, err := s.findKeyByID(r.Context(), ks, keyID)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("key not found: %v", err))
		return
	}

	if err := ks.DeleteKey(r.Context(), attrs); err != nil {
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

	if !s.authorize(w, r, auth.ResourceKeys, auth.ActionSign) {
		return
	}

	// The backend is validated here rather than left to the service so a
	// misspelled backend still yields 404 rather than the service's own
	// lookup error, preserving this transport's established status mapping.
	if _, err := s.getKeystoreForBackend(backendParam); err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", backendParam))
		return
	}

	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	// The signing itself belongs to the service layer, which owns padding
	// selection (PKCS#1 v1.5 vs PSS), the salt length, the "already a digest"
	// contract, and the per-algorithm rules for Ed25519 and ECDSA. This
	// handler used to call signer.Sign directly with the bare crypto.Hash as
	// opts, which is PKCS#1 v1.5 for an RSA key: a caller asking for PSS got
	// a valid signature under the scheme it did not ask for, and no error.
	resp, err := s.xkmsService.Sign(r.Context(), &transport.SignRequest{
		Backend:      backendParam,
		KeyID:        keyID,
		Data:         req.Data,
		Hash:         req.Hash,
		DataIsDigest: req.DataIsDigest,
		Padding:      req.Padding,
		SaltLength:   req.SaltLength,
		PreHash:      req.PreHash,
		Context:      req.Context,
		TenantID:     callerTenantID(r.Context()),
	})
	if err != nil {
		s.sendKeyOpError(r.Context(), w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, SignResponse{
		Signature: resp.Signature,
		Algorithm: resp.Algorithm,
	})
}

// handleVerify handles verifying a signature
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request, keyID, backendParam string) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, auth.ResourceKeys, auth.ActionVerify) {
		return
	}

	if _, err := s.getKeystoreForBackend(backendParam); err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", backendParam))
		return
	}

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	sigBytes, err := decodeSignature(req.Signature)
	if err != nil {
		s.sendError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Verification mirrors Sign: the service layer owns padding, salt length
	// and the per-algorithm rules, so a PSS signature is verified as PSS
	// rather than being rejected by a hard-wired PKCS#1 v1.5 check.
	resp, err := s.xkmsService.Verify(r.Context(), &transport.VerifyRequest{
		Backend:      backendParam,
		KeyID:        keyID,
		Data:         req.Data,
		Signature:    sigBytes,
		Hash:         req.Hash,
		DataIsDigest: req.DataIsDigest,
		Padding:      req.Padding,
		SaltLength:   req.SaltLength,
		PreHash:      req.PreHash,
		Context:      req.Context,
		TenantID:     callerTenantID(r.Context()),
	})
	if err != nil {
		s.sendKeyOpError(r.Context(), w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, VerifyResponse{Valid: resp.Valid})
}

// handleRotateKey handles key rotation
func (s *Server) handleRotateKey(w http.ResponseWriter, r *http.Request, keyID, backendParam string) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, auth.ResourceKeys, auth.ActionRotate) {
		return
	}

	ks, err := s.getKeystoreForBackend(backendParam)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", backendParam))
		return
	}

	// Find the key's full attributes
	attrs, err := s.findKeyByID(r.Context(), ks, keyID)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("key not found: %v", err))
		return
	}

	privKey, err := ks.RotateKey(r.Context(), attrs)
	if err != nil {
		s.sendServiceError(r.Context(), w, err, http.StatusInternalServerError, fmt.Sprintf("failed to rotate key: %v", err))
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

	s.sendJSON(w, http.StatusOK, RotateKeyResponse{
		Success:      true,
		KeyID:        keyID,
		PublicKeyPEM: pubKeyPEM,
		Backend:      backendParam,
		Message:      fmt.Sprintf("Key %s rotated successfully", keyID),
	})
}

// handleEncrypt handles symmetric encryption
func (s *Server) handleEncrypt(w http.ResponseWriter, r *http.Request, keyID, backendParam string) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, auth.ResourceKeys, auth.ActionEncrypt) {
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

	// Two preconditions are checked here rather than left to the service
	// because this transport reports them with its own status codes: a
	// missing key is 404, and a backend with no symmetric support is 400.
	// The service answers both with a coarser sentinel (it falls back to
	// asymmetric encryption for the latter), so the checks stay local. They
	// decide status codes only -- no crypto parameter is interpreted here.
	if _, err := s.findKeyByID(r.Context(), ks, keyID); err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("key not found: %v", err))
		return
	}

	if _, ok := ks.KeyProvider().(types.SymmetricKeyProvider); !ok {
		s.sendError(w, http.StatusBadRequest, "backend does not support symmetric encryption")
		return
	}

	resp, err := s.xkmsService.Encrypt(r.Context(), &transport.EncryptRequest{
		Backend:        backendParam,
		KeyID:          keyID,
		Plaintext:      req.Plaintext,
		AdditionalData: req.AdditionalData,
		Nonce:          req.Nonce,
		Mode:           req.Mode,
		IV:             req.IV,
		TagSize:        req.TagSize,
		TenantID:       callerTenantID(r.Context()),
	})
	if err != nil {
		s.sendKeyOpError(r.Context(), w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, EncryptResponse{
		Ciphertext: resp.Ciphertext,
		Nonce:      resp.Nonce,
		Tag:        resp.Tag,
		IV:         resp.IV,
	})
}

// handleDecrypt handles decryption (both asymmetric RSA and symmetric AES)
func (s *Server) handleDecrypt(w http.ResponseWriter, r *http.Request, keyID, backendParam string) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, auth.ResourceKeys, auth.ActionDecrypt) {
		return
	}

	var req DecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	// Resolve which backend holds the key before delegating. The service takes
	// a backend by name and does not search, so this transport's established
	// "try symmetric, then software" discovery for an unspecified backend has
	// to happen here.
	backendName, attrs, err := s.resolveDecryptBackend(r.Context(), keyID, backendParam)
	if err != nil {
		s.sendError(w, http.StatusNotFound, err.Error())
		return
	}

	// A symmetric key in a backend with no symmetric support is 400 on this
	// transport. The service falls back to asymmetric decryption instead and
	// reports the eventual failure as 500, so the check stays local.
	if attrs.IsSymmetric() {
		ks, ksErr := s.getKeystoreForBackend(backendName)
		if ksErr != nil {
			s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", backendName))
			return
		}
		if _, ok := ks.KeyProvider().(types.SymmetricKeyProvider); !ok {
			s.sendError(w, http.StatusBadRequest, "backend does not support symmetric decryption")
			return
		}
	}

	// Decryption belongs to the service layer, which owns the symmetric /
	// asymmetric split and the RSA padding selection. This handler used to
	// hard-wire rsa.OAEPOptions{Hash: crypto.SHA256} for every asymmetric key,
	// so a PKCS#1 v1.5 ciphertext could not be decrypted here at all, and an
	// OAEP ciphertext built under any other digest -- or with a label --
	// failed with an error that read like corruption.
	resp, err := s.xkmsService.Decrypt(r.Context(), &transport.DecryptRequest{
		Backend:        backendName,
		KeyID:          keyID,
		Ciphertext:     req.Ciphertext,
		Nonce:          req.Nonce,
		Tag:            req.Tag,
		AdditionalData: req.AdditionalData,
		Mode:           req.Mode,
		IV:             req.IV,
		TagSize:        req.TagSize,
		Padding:        req.Padding,
		Hash:           req.Hash,
		Label:          req.Label,
		TenantID:       callerTenantID(r.Context()),
	})
	if err != nil {
		s.sendKeyOpError(r.Context(), w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, DecryptResponse{Plaintext: resp.Plaintext})
}

// resolveDecryptBackend names the backend that holds keyID for a decrypt
// request and returns the key's attributes. An explicit backendParam is used
// as-is once it is known to exist; otherwise the "symmetric" and then
// "software" backends are searched, which is this transport's established
// discovery order.
func (s *Server) resolveDecryptBackend(ctx context.Context, keyID, backendParam string) (string, *types.KeyAttributes, error) {
	if backendParam != "" {
		ks, err := s.getKeystoreForBackend(backendParam)
		if err != nil {
			return "", nil, &errs.Message{Msg: fmt.Sprintf("backend not found: %s", backendParam)}
		}
		attrs, err := s.findKeyByID(ctx, ks, keyID)
		if err != nil {
			return "", nil, &errs.Wrapped{Msg: "key not found", Err: err}
		}
		return backendParam, attrs, nil
	}

	var lookupErr error
	for _, candidate := range []string{"symmetric", "software"} {
		ks, err := s.getKeystoreForBackend(candidate)
		if err != nil {
			continue
		}
		attrs, err := s.findKeyByID(ctx, ks, keyID)
		if err != nil {
			lookupErr = err
			continue
		}
		return candidate, attrs, nil
	}
	if lookupErr == nil {
		// Neither discovery backend is configured at all.
		return "", nil, &errs.Message{Msg: "backend not found"}
	}
	return "", nil, &errs.Wrapped{Msg: "key not found", Err: lookupErr}
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
	if !s.authorize(w, r, auth.ResourceCerts, auth.ActionList) {
		return
	}

	keyIDs, err := s.keystore.ListCerts(r.Context())
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list certificates: %v", err))
		return
	}

	pr := transport.PageRequestFromQuery(r)
	paginatedIDs, pageResp := transport.ApplyPagination(keyIDs, pr)

	s.sendJSON(w, http.StatusOK, ListCertsResponse{
		KeyIDs:     paginatedIDs,
		Pagination: &pageResp,
	})
}

// handleSaveCert handles saving a certificate
func (s *Server) handleSaveCert(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, auth.ResourceCerts, auth.ActionGenerate) {
		return
	}

	var req CertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	// Support key_id from query parameter (SDK compatibility)
	keyID := r.URL.Query().Get("key_id")
	if keyID == "" {
		keyID = req.KeyID
	}
	if keyID == "" {
		s.sendError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	// Support both cert_pem and certificate_pem field names
	certPEM := req.CertPEM
	if certPEM == "" {
		certPEM = req.CertificatePEM
	}
	if certPEM == "" {
		s.sendError(w, http.StatusBadRequest, "cert_pem or certificate_pem is required")
		return
	}
	req.KeyID = keyID
	req.CertPEM = certPEM

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

	if err := s.keystore.SaveCert(r.Context(), req.KeyID, cert); err != nil {
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
	if !s.authorize(w, r, auth.ResourceCerts, auth.ActionRead) {
		return
	}

	cert, err := s.keystore.GetCert(r.Context(), certID)
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
		KeyID:          certID,
		CertificatePEM: certPEM,
	})
}

// handleDeleteCert handles deleting a certificate
func (s *Server) handleDeleteCert(w http.ResponseWriter, r *http.Request, certID string) {
	if !s.authorize(w, r, auth.ResourceCerts, auth.ActionRevoke) {
		return
	}

	if err := s.keystore.DeleteCert(r.Context(), certID); err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("failed to delete certificate: %v", err))
		return
	}

	s.sendJSON(w, http.StatusOK, DeleteResponse{Success: true})
}

// handleCertExists handles checking if a certificate exists
func (s *Server) handleCertExists(w http.ResponseWriter, r *http.Request, certID string) {
	if !s.authorize(w, r, auth.ResourceCerts, auth.ActionRead) {
		return
	}

	exists, err := s.keystore.CertExists(r.Context(), certID)
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
	if !s.authorize(w, r, auth.ResourceCerts, auth.ActionGenerate) {
		return
	}

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

	if err := s.keystore.SaveCertChain(r.Context(), certID, chain); err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save certificate chain: %v", err))
		return
	}

	s.sendJSON(w, http.StatusCreated, DeleteResponse{Success: true})
}

// handleGetCertChain handles retrieving a certificate chain
func (s *Server) handleGetCertChain(w http.ResponseWriter, r *http.Request, certID string) {
	if !s.authorize(w, r, auth.ResourceCerts, auth.ActionRead) {
		return
	}

	chain, err := s.keystore.GetCertChain(r.Context(), certID)
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

	if !s.authorize(w, r, auth.ResourceCerts, auth.ActionRead) {
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

	tlsCert, err := s.keystore.GetTLSCertificate(r.Context(), certID, attrs)
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
		s.logger.Error("Error encoding response", slog.String("error", err.Error()))
	}
}

// sendError sends an error response
func (s *Server) sendError(w http.ResponseWriter, status int, message string) {
	s.logger.Warn("QUIC request error",
		slog.Int("status", status),
		slog.String("error", message))
	s.sendJSON(w, status, ErrorResponse{
		Error:   message,
		Message: message,
	})
}

// handleGetImportParameters handles getting import parameters for key import
func (s *Server) handleGetImportParameters(w http.ResponseWriter, r *http.Request, keyID, backendParam string) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, auth.ResourceKeys, auth.ActionImport) {
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
	importExportBackend, ok := ks.KeyProvider().(backend.ImportExportBackend)
	if !ok {
		s.sendError(w, http.StatusBadRequest, "backend does not support import/export operations")
		return
	}

	// Parse wrapping algorithm
	algorithm := backend.WrappingAlgorithm(req.Algorithm)

	// Get import parameters
	params, err := importExportBackend.GetImportParameters(r.Context(), attrs, algorithm)
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

	if !s.authorize(w, r, auth.ResourceKeys, auth.ActionImport) {
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
	importExportBackend, ok := ks.KeyProvider().(backend.ImportExportBackend)
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
		switch keySize {
		case 128:
			attrs.SymmetricAlgorithm = types.SymmetricAES128GCM
		case 192:
			attrs.SymmetricAlgorithm = types.SymmetricAES192GCM
		default:
			attrs.SymmetricAlgorithm = types.SymmetricAES256GCM
		}
	default:
		// For unknown types, try to determine from other fields
		attrs.KeyType = types.KeyTypeTLS
	}

	// Parse wrapping algorithm
	algorithm := backend.WrappingAlgorithm(req.Algorithm)

	// Get import parameters
	params, err := importExportBackend.GetImportParameters(r.Context(), attrs, algorithm)
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

	if !s.authorize(w, r, auth.ResourceKeys, auth.ActionWrap) {
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
	importExportBackend, ok := ks.KeyProvider().(backend.ImportExportBackend)
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
	wrapped, err := importExportBackend.WrapKey(r.Context(), req.KeyMaterial, params)
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

// handleUnwrapKey handles unwrapping key material
func (s *Server) handleUnwrapKey(w http.ResponseWriter, r *http.Request, keyID, backendParam string) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, auth.ResourceKeys, auth.ActionUnwrap) {
		return
	}

	var req UnwrapKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	if len(req.WrappedKey) == 0 {
		s.sendError(w, http.StatusBadRequest, "wrapped_key is required")
		return
	}
	if req.Algorithm == "" {
		s.sendError(w, http.StatusBadRequest, "algorithm is required")
		return
	}

	// Get the correct keystore for the backend
	ks, err := s.getKeystoreForBackend(backendParam)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", backendParam))
		return
	}

	// Check if backend supports import/export
	importExportBackend, ok := ks.KeyProvider().(backend.ImportExportBackend)
	if !ok {
		s.sendError(w, http.StatusBadRequest, "backend does not support import/export operations")
		return
	}

	// The wrapping public key is optional on an unwrap.
	//
	// Unwrapping uses the private half, which lives in the backend; the public
	// half is an input to the wrap, not to its reverse. The service layer's
	// UnwrapKey does not populate ImportParameters.WrappingPublicKey at all, so
	// requiring it here rejected, with 400, requests the service accepts. It is
	// still forwarded when supplied, for a backend that chooses to check it,
	// but a malformed value is refused rather than passed on.
	var pubKey crypto.PublicKey
	if req.WrappingPublicKeyPEM != "" {
		block, _ := pem.Decode([]byte(req.WrappingPublicKeyPEM))
		if block == nil {
			s.sendError(w, http.StatusBadRequest, "invalid wrapping public key PEM")
			return
		}

		pubKey, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			s.sendError(w, http.StatusBadRequest, fmt.Sprintf("failed to parse public key: %v", err))
			return
		}
	}

	// Build wrapped key material
	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  req.WrappedKey,
		Algorithm:   backend.WrappingAlgorithm(req.Algorithm),
		ImportToken: req.ImportToken,
		Metadata:    req.Metadata,
	}

	// Build import parameters
	params := &backend.ImportParameters{
		WrappingPublicKey: pubKey,
		ImportToken:       req.ImportToken,
		Algorithm:         backend.WrappingAlgorithm(req.Algorithm),
	}

	// Unwrap the key material
	keyMaterial, err := importExportBackend.UnwrapKey(r.Context(), wrapped, params)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to unwrap key: %v", err))
		return
	}

	s.sendJSON(w, http.StatusOK, UnwrapKeyResponse{
		KeyMaterial: keyMaterial,
	})
}

// handleImportKey handles importing externally generated key material
func (s *Server) handleImportKey(w http.ResponseWriter, r *http.Request, keyID, backendParam string) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !s.authorize(w, r, auth.ResourceKeys, auth.ActionImport) {
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
	importExportBackend, ok := ks.KeyProvider().(backend.ImportExportBackend)
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
	if err := importExportBackend.ImportKey(r.Context(), attrs, wrapped); err != nil {
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

	if !s.authorize(w, r, auth.ResourceKeys, auth.ActionExport) {
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
	attrs, err := s.findKeyByID(r.Context(), ks, keyID)
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
	importExportBackend, ok := ks.KeyProvider().(backend.ImportExportBackend)
	if !ok {
		s.sendError(w, http.StatusBadRequest, "backend does not support import/export operations")
		return
	}

	// Parse wrapping algorithm
	algorithm := backend.WrappingAlgorithm(req.Algorithm)

	// Export the key
	wrapped, err := importExportBackend.ExportKey(r.Context(), attrs, algorithm)
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

	if !s.authorize(w, r, auth.ResourceKeys, auth.ActionEncrypt) {
		return
	}

	var req AsymmetricEncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
		return
	}

	// Validate the backend and the key locally so a misspelled backend and a
	// missing key keep this transport's 404, then let the service layer own
	// the OAEP construction itself: the digest selection, its weak-hash
	// refusal, and the RSA key-type check.
	//
	// The key-type check is deliberately NOT repeated here. It has to be made
	// against the resolved public key, not against KeyAttributes.KeyAlgorithm,
	// and duplicating that resolution is exactly the divergence this routing
	// removes. The service reports it as xkms.ErrEncryptionFailed, which maps
	// to 500 -- the same answer the gRPC transport gives for the same
	// condition (pkg/api/grpc/errors_keyops.go maps it to codes.Internal).
	ks, err := s.getKeystoreForBackend(backendParam)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("backend not found: %s", backendParam))
		return
	}

	if _, err := s.findKeyByID(r.Context(), ks, keyID); err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("key not found: %v", err))
		return
	}

	resp, err := s.xkmsService.EncryptAsym(r.Context(), &transport.EncryptAsymRequest{
		Backend:   backendParam,
		KeyID:     keyID,
		Plaintext: req.Plaintext,
		Hash:      req.Hash,
		TenantID:  callerTenantID(r.Context()),
	})
	if err != nil {
		s.sendKeyOpError(r.Context(), w, err)
		return
	}

	s.sendJSON(w, http.StatusOK, EncryptResponse{
		Ciphertext: resp.Ciphertext,
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

	if !s.authorize(w, r, auth.ResourceKeys, auth.ActionCreate) {
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
	sourceKS, err := s.lookupBackend(req.SourceBackend)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("source backend not found: %v", err))
		return
	}
	sourceBackend, ok := sourceKS.KeyProvider().(backend.ImportExportBackend)
	if !ok {
		s.sendError(w, http.StatusBadRequest, "source backend does not support import/export operations")
		return
	}

	destKS, err := s.lookupBackend(req.DestBackend)
	if err != nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("destination backend not found: %v", err))
		return
	}
	destBackend, ok := destKS.KeyProvider().(backend.ImportExportBackend)
	if !ok {
		s.sendError(w, http.StatusBadRequest, "destination backend does not support import/export operations")
		return
	}

	// Find the source key by listing keys from the source backend
	sourceKeyAttrs, err := sourceKS.ListKeys(r.Context())
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list keys from source backend: %v", err))
		return
	}

	var sourceAttrs *types.KeyAttributes
	for _, attr := range sourceKeyAttrs {
		if attr.CN == req.SourceKeyID {
			sourceAttrs = attr
			break
		}
	}

	if sourceAttrs == nil {
		s.sendError(w, http.StatusNotFound, fmt.Sprintf("source key not found: %s", req.SourceKeyID))
		return
	}

	// Build destination key attributes - copy from source but with new ID
	destAttrs := &types.KeyAttributes{
		CN:                 req.DestKeyID,
		KeyType:            sourceAttrs.KeyType,
		KeyAlgorithm:       sourceAttrs.KeyAlgorithm,
		Hash:               sourceAttrs.Hash,
		Partition:          sourceAttrs.Partition,
		RSAAttributes:      sourceAttrs.RSAAttributes,
		ECCAttributes:      sourceAttrs.ECCAttributes,
		SymmetricAlgorithm: sourceAttrs.SymmetricAlgorithm,
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
	wrapped, err := sourceBackend.ExportKey(r.Context(), sourceAttrs, algorithm)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to export key: %v", err))
		return
	}

	// Import to destination backend
	if err := destBackend.ImportKey(r.Context(), destAttrs, wrapped); err != nil {
		s.sendError(w, http.StatusInternalServerError, fmt.Sprintf("failed to import key: %v", err))
		return
	}

	s.sendJSON(w, http.StatusOK, CopyKeyResponse{
		Success: true,
		Message: fmt.Sprintf("Key copied from %s/%s to %s/%s successfully",
			req.SourceBackend, req.SourceKeyID, req.DestBackend, req.DestKeyID),
	})
}
