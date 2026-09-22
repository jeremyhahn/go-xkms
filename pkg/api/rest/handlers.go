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

package rest

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/go-chi/chi/v5"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/encoding"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/validation"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// HandlerContext holds dependencies for REST handlers.
type HandlerContext struct {
	// Version is the API version
	Version string
	// HealthChecker manages health check probes
	HealthChecker HealthChecker
	// Barrier is the optional barrier for seal/unseal lifecycle management
	Barrier *seal.Barrier
	// PINManager is the optional PIN backend for SO/User PIN operations
	PINManager qrdbsdk.PINBackend
	// xkmsService is the injected XKMS service; replaces package-singleton lookups.
	xkmsService *xkms.XKMSService
}

// HealthChecker defines the interface for health checking.
type HealthChecker interface {
	Live(ctx context.Context) qrdbsdk.HealthCheckResult
	Ready(ctx context.Context) []qrdbsdk.HealthCheckResult
	Startup(ctx context.Context) qrdbsdk.HealthCheckResult
}

// NewHandlerContext creates a new handler context.
// Callers must call SetXKMSService to wire the injected service before use.
func NewHandlerContext(version string) *HandlerContext {
	return &HandlerContext{
		Version: version,
	}
}

// SetHealthChecker sets the health checker for the handler context.
func (h *HandlerContext) SetHealthChecker(checker HealthChecker) {
	h.HealthChecker = checker
}

// SetBarrier sets the barrier for the handler context.
func (h *HandlerContext) SetBarrier(barrier *seal.Barrier) {
	h.Barrier = barrier
}

// SetPINManager sets the PIN backend for the handler context.
func (h *HandlerContext) SetPINManager(manager qrdbsdk.PINBackend) {
	h.PINManager = manager
}

// SetXKMSService sets the injected XKMS service on the handler context.
func (h *HandlerContext) SetXKMSService(svc *xkms.XKMSService) {
	h.xkmsService = svc
}

// lookupBackend returns the named backend from the injected service.
// Returns xkms.ErrNotInitialized when the service has not been wired.
func (h *HandlerContext) lookupBackend(name string) (xkms.Backend, error) {
	if h.xkmsService == nil {
		return nil, xkms.ErrNotInitialized
	}
	return h.xkmsService.LookupBackend(name)
}

// lookupTenantBackend returns the named backend viewed through the tenant of
// the authenticated caller. It is what every path that resolves a key by
// COMMON NAME must use, because a common name is unique only within a tenant:
// findKeyAttributes scans whatever backend it is handed, so handing it an
// unscoped one lets the scan match another tenant's key.
//
// Before go-xkms#221 the key-by-CN handlers here called lookupBackend, and a
// caller holding no key of that name at all resolved -- and then decrypted or
// encrypted with -- the first key any tenant happened to have stored under it.
//
// It delegates to XKMSService.LookupTenantBackend, the same helper the gRPC and
// MCP transports use, so all three agree on what a tenant is rather than each
// deciding for itself.
func (h *HandlerContext) lookupTenantBackend(ctx context.Context, name string) (xkms.Backend, error) {
	if h.xkmsService == nil {
		return nil, xkms.ErrNotInitialized
	}
	return h.xkmsService.LookupTenantBackend(name, callerTenantID(ctx))
}

// findKeyAttributes resolves a key's attributes by common name within a single
// backend. It exists so the handlers that must keep this transport's 404 for a
// missing key resolve it one way, rather than each repeating the list-and-scan
// loop with its own idea of what "not found" means.
func (h *HandlerContext) findKeyAttributes(ctx context.Context, ks xkms.Backend, keyID string) (*types.KeyAttributes, error) {
	attrs, err := ks.ListKeys(ctx)
	if err != nil {
		return nil, err
	}
	for _, attr := range attrs {
		if attr.CN == keyID {
			return attr, nil
		}
	}
	return nil, backend.ErrKeyNotFound
}

// backendNames returns the names of all registered backends.
// Returns nil when the service has not been wired.
func (h *HandlerContext) backendNames() []string {
	if h.xkmsService == nil {
		return nil
	}
	return h.xkmsService.BackendNames()
}

// sealWithBackend seals data using the named backend.
// Returns xkms.ErrNotInitialized when the service has not been wired.
func (h *HandlerContext) sealWithBackend(ctx context.Context, backendName string, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	if h.xkmsService == nil {
		return nil, xkms.ErrNotInitialized
	}
	return h.xkmsService.SealWithBackend(ctx, backendName, data, opts)
}

// unsealWithBackend unseals data using the named backend.
// Returns xkms.ErrNotInitialized when the service has not been wired.
func (h *HandlerContext) unsealWithBackend(ctx context.Context, backendName string, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if h.xkmsService == nil {
		return nil, xkms.ErrNotInitialized
	}
	return h.xkmsService.UnsealWithBackend(ctx, backendName, sealed, opts)
}

// canSeal returns true if the named backend supports sealing operations.
// Returns false when the service has not been wired.
func (h *HandlerContext) canSeal(backendName ...string) bool {
	if h.xkmsService == nil {
		return false
	}
	return h.xkmsService.CanSealDirect(backendName...)
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
	backendNames := h.backendNames()

	backends := make([]BackendInfo, 0, len(backendNames))
	for _, name := range backendNames {
		ks, err := h.lookupBackend(name)
		if err != nil {
			continue // Skip backends that can't be retrieved
		}

		backend := ks.KeyProvider()
		caps := backend.Capabilities()

		backends = append(backends, BackendInfo{
			ID:             name,
			Type:           string(backend.Type()),
			HardwareBacked: caps.HardwareBacked,
			Capabilities:   caps,
		})
	}

	pageReq := parsePageRequest(r)
	paged, pageResp := applyPagination(backends, pageReq)

	resp := ListBackendsResponse{
		Backends:   paged,
		Pagination: pageResp,
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

	ks, err := h.lookupBackend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	backend := ks.KeyProvider()
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
		writeError(w, &errs.Wrapped{Msg: "invalid key ID", Err: err}, http.StatusBadRequest)
		return
	}

	if req.Backend == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	// Validate backend name
	if err := validation.ValidateBackendName(req.Backend); err != nil {
		writeError(w, &errs.Wrapped{Msg: "invalid backend", Err: err}, http.StatusBadRequest)
		return
	}

	if req.KeyType == "" {
		writeError(w, ErrInvalidKeyType, http.StatusBadRequest)
		return
	}
	if req.Algorithm == "" {
		writeError(w, ErrMissingAlgorithm, http.StatusBadRequest)
		return
	}

	// Get the backend (this also validates it exists)
	ks, err := h.lookupBackend(req.Backend)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Parse key algorithm.
	// Support both direct algorithm names (aes-256-gcm) and simple types (aes).
	algorithmStr := req.Algorithm
	keyType := strings.ToLower(algorithmStr)
	var keyAlgorithm x509.PublicKeyAlgorithm
	var symmetricAlgorithm types.SymmetricAlgorithm

	// The literal "symmetric" algorithm names no specific cipher: default to
	// AES-256-GCM.
	if keyType == "symmetric" {
		symmetricAlgorithm = types.SymmetricAES256GCM
	} else {
		// Try parsing as asymmetric algorithm
		keyAlgorithm, _ = types.ParseKeyAlgorithm(algorithmStr)
		if keyAlgorithm == x509.UnknownPublicKeyAlgorithm {
			// Try as symmetric algorithm
			symmetricAlgorithm = types.SymmetricAlgorithm(keyType)
		}
	}

	// Parse key purpose type from request (e.g., "tls", "signing", "encryption")
	keyPurposeType := types.ParseKeyType(req.KeyType)
	// Default to KeyTypeSigning if the parsed key purpose type is invalid
	// (e.g., when req.KeyType is an algorithm name like "rsa", "ecdsa", "ed25519")
	if keyPurposeType == 0 {
		keyPurposeType = types.KeyTypeSigning
	}

	// Build key attributes
	attrs := &types.KeyAttributes{
		CN:                 req.KeyID,
		KeyType:            keyPurposeType,
		StoreType:          types.StoreSoftware, // Will be updated based on backend
		KeyAlgorithm:       keyAlgorithm,
		SymmetricAlgorithm: symmetricAlgorithm,
		Exportable:         req.Exportable,
		Sensitive:          req.Sensitive,
		Partition:          types.Partition(req.Partition),
	}

	// Resolve the hash algorithm. An absent name selects SHA-256; a name the
	// caller did supply that does not resolve is a client error, never a
	// substitution — a key created under a digest the caller did not choose is
	// indistinguishable, in the response, from the one it asked for.
	hashAlg, hashErr := resolveHashForHandler(req.Hash)
	if hashErr != nil {
		mapKeyOpError(w, hashErr)
		return
	}
	attrs.Hash = hashAlg

	// Set algorithm-specific attributes
	var privKey crypto.PrivateKey
	var isSymmetric bool

	if symmetricAlgorithm != "" {
		// Symmetric key generation
		isSymmetric = true
		attrs.KeyType = types.KeyTypeSecret // Symmetric keys use KeyTypeSecret

		// Check if backend supports symmetric operations
		symBackend, ok := ks.KeyProvider().(types.SymmetricKeyProvider)
		if !ok {
			writeError(w, &errs.Message{Msg: "backend does not support symmetric key generation"}, http.StatusBadRequest)
			return
		}

		_, err = symBackend.GenerateSymmetricKey(r.Context(), attrs)
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
			privKey, err = ks.GenerateRSA(r.Context(), attrs)

		case x509.ECDSA:
			curve := req.Curve
			if curve == "" {
				curve = "P256" // Default ECDSA curve
			}
			// ParseCurve's error names the curve the caller actually sent.
			// Discarding it left Curve nil, and the backend's own nil guard
			// then reported "curve is required" -- blaming the caller for
			// omitting a field they had supplied, with the offending value
			// gone (go-xkms#153).
			parsedCurve, curveErr := types.ParseCurve(curve)
			if curveErr != nil {
				writeError(w, curveErr, http.StatusBadRequest)
				return
			}
			attrs.ECCAttributes = &types.ECCAttributes{
				Curve: parsedCurve,
			}
			privKey, err = ks.GenerateECDSA(r.Context(), attrs)

		case x509.Ed25519:
			privKey, err = ks.GenerateEd25519(r.Context(), attrs)

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

	ks, err := h.lookupBackend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// List keys from backend
	keyAttrs, err := ks.ListKeys(r.Context())
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
			KeyType:   attr.KeyType.String(),
			Algorithm: attr.AlgorithmString(),
			Backend:   backendID,
		}

		// Try to get public key
		privKey, err := ks.GetKey(r.Context(), attr)
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

	pageReq := parsePageRequest(r)
	paged, pageResp := applyPagination(keys, pageReq)

	resp := ListKeysResponse{
		Keys:       paged,
		Pagination: pageResp,
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

	ks, err := h.lookupBackend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// List all keys and find the matching one
	keyAttrs, err := ks.ListKeys(r.Context())
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
	privKey, err := ks.GetKey(r.Context(), targetAttr)
	if err != nil {
		log.Printf("Failed to get key: %v", err)
		handleError(w, err)
		return
	}

	// Build response
	resp := GetKeyResponse{
		KeyInfo: KeyInfo{
			KeyID:     targetAttr.CN,
			KeyType:   targetAttr.KeyType.String(),
			Algorithm: targetAttr.AlgorithmString(),
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
// backendFromRequest resolves the target backend for a crypto request from
// either the "backend" URL query parameter or the decoded request body's
// backend field. The query parameter wins when both are present. Every crypto
// *Request DTO advertises a body "backend" field, so accepting it keeps these
// handlers consistent with GenerateKey (which reads the body) and avoids a
// confusing 400 for clients that follow the DTO instead of the query string.
func backendFromRequest(r *http.Request, bodyBackend string) string {
	if q := r.URL.Query().Get("backend"); q != "" {
		return q
	}
	return bodyBackend
}

func (h *HandlerContext) SignHandler(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	backendID := backendFromRequest(r, req.Backend)
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	// The signing itself belongs to the service layer, which owns padding
	// selection (PKCS#1 v1.5 vs PSS), the "no hashing" contract for a
	// caller-supplied digest, and the per-algorithm rules for Ed25519 and
	// ECDSA. Reimplementing any of that here would let the transports drift
	// apart from each other and from the PKCS#11 module.
	resp, err := h.xkmsService.Sign(r.Context(), &transport.SignRequest{
		Backend:      backendID,
		KeyID:        keyID,
		Data:         req.Data,
		Hash:         req.Hash,
		Padding:      req.Padding,
		SaltLength:   req.SaltLength,
		DataIsDigest: req.DataIsDigest,
		TenantID:     callerTenantID(r.Context()),
	})
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, SignResponse{
		Signature: resp.Signature,
		Algorithm: resp.Algorithm,
	}, http.StatusOK)
}

// VerifyHandler handles POST /api/v1/keys/{id}/verify requests.
func (h *HandlerContext) VerifyHandler(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	backendID := backendFromRequest(r, req.Backend)
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	resp, err := h.xkmsService.Verify(r.Context(), &transport.VerifyRequest{
		Backend:      backendID,
		KeyID:        keyID,
		Data:         req.Data,
		Signature:    req.Signature,
		Hash:         req.Hash,
		Padding:      req.Padding,
		SaltLength:   req.SaltLength,
		DataIsDigest: req.DataIsDigest,
		TenantID:     callerTenantID(r.Context()),
	})
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	// The message is synthesized here rather than forwarded: the verifier's
	// own error text ("crypto/rsa: verification error") tells a client nothing
	// actionable and leaks implementation detail.
	message := "Signature is invalid"
	if resp.Valid {
		message = "signature is valid"
	}

	writeJSON(w, VerifyResponse{Valid: resp.Valid, Message: message}, http.StatusOK)
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

	ks, err := h.lookupBackend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Find the key
	keyAttrs, err := ks.ListKeys(r.Context())
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
	if err := ks.DeleteKey(r.Context(), targetAttr); err != nil {
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

	ks, err := h.lookupBackend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Find the key
	keyAttrs, err := ks.ListKeys(r.Context())
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
	newKey, err := ks.RotateKey(r.Context(), targetAttr)
	if err != nil {
		log.Printf("Failed to rotate key: %v", err)
		handleError(w, err)
		return
	}

	// Build response
	resp := RotateKeyResponse{
		Success: true,
		KeyID:   keyID,
		KeyType: targetAttr.KeyType.String(),
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

	var req EncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	backendID := backendFromRequest(r, req.Backend)
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	resp, err := h.xkmsService.Encrypt(r.Context(), &transport.EncryptRequest{
		Backend:        backendID,
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
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, EncryptResponse{
		Ciphertext: resp.Ciphertext,
		Nonce:      resp.Nonce,
		Tag:        resp.Tag,
		IV:         resp.IV,
	}, http.StatusOK)
}

// DecryptHandler handles POST /api/v1/keys/{id}/decrypt requests.
func (h *HandlerContext) DecryptHandler(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	var req DecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	backendID := backendFromRequest(r, req.Backend)
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	ks, err := h.lookupTenantBackend(r.Context(), backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Resolve the key locally so a missing key keeps this transport's 404, and
	// so a symmetric key in a backend with no symmetric support keeps its 400.
	// The service falls back to asymmetric decryption in that case and reports
	// the eventual failure as 500.
	targetAttr, err := h.findKeyAttributes(r.Context(), ks, keyID)
	if err != nil {
		if errors.Is(err, backend.ErrKeyNotFound) {
			writeError(w, backend.ErrKeyNotFound, http.StatusNotFound)
			return
		}
		log.Printf("Failed to list keys: %v", err)
		handleError(w, err)
		return
	}

	if targetAttr.IsSymmetric() {
		if _, ok := ks.KeyProvider().(types.SymmetricKeyProvider); !ok {
			writeError(w, &errs.Message{Msg: "backend does not support symmetric decryption"}, http.StatusBadRequest)
			return
		}
	}

	// Decryption belongs to the service layer, which owns the symmetric /
	// asymmetric split and the RSA padding selection. This handler used to
	// hard-wire rsa.OAEPOptions{Hash: crypto.SHA256} for every asymmetric key
	// while EncryptHandler delegated to a service that produces PKCS#1 v1.5,
	// so a REST encrypt could never be reversed by a REST decrypt. The two
	// halves now resolve their padding through one definition.
	resp, err := h.xkmsService.Decrypt(r.Context(), &transport.DecryptRequest{
		Backend:        backendID,
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
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, DecryptResponse{Plaintext: resp.Plaintext}, http.StatusOK)
}

// EncryptAsymHandler handles POST /api/v1/keys/{id}/encrypt-asym requests.
// This performs RSA-OAEP asymmetric encryption using the public key.
func (h *HandlerContext) EncryptAsymHandler(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	var req EncryptAsymRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	backendID := backendFromRequest(r, req.Backend)
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	// Validate the backend and the key locally so a misspelled backend and a
	// missing key keep this transport's 404, then let the service layer own the
	// OAEP construction itself: the digest selection, its weak-hash refusal,
	// its refusal of hash "NONE", and the RSA key-type check.
	//
	// The digest used to be resolved here and handed straight to hashFunc.New().
	// xkms.ResolveOAEPHash answers crypto.Hash(0) for the name "NONE" -- a
	// legal, non-error answer meaning "no digest" -- and crypto.Hash(0).New()
	// panics, so a request naming that hash crashed the handler goroutine
	// rather than being refused. The service has always rejected it.
	ks, err := h.lookupTenantBackend(r.Context(), backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	if _, err := h.findKeyAttributes(r.Context(), ks, keyID); err != nil {
		if errors.Is(err, backend.ErrKeyNotFound) {
			writeError(w, backend.ErrKeyNotFound, http.StatusNotFound)
			return
		}
		log.Printf("Failed to list keys: %v", err)
		handleError(w, err)
		return
	}

	resp, err := h.xkmsService.EncryptAsym(r.Context(), &transport.EncryptAsymRequest{
		Backend:   backendID,
		KeyID:     keyID,
		Plaintext: req.Plaintext,
		Hash:      req.Hash,
		Label:     req.Label,
		TenantID:  callerTenantID(r.Context()),
	})
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, EncryptAsymResponse{Ciphertext: resp.Ciphertext}, http.StatusOK)
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

	ks, err := h.lookupBackend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Parse certificate PEM
	cert, err := encoding.DecodeCertificatePEM([]byte(req.CertificatePEM))
	if err != nil {
		log.Printf("Failed to parse certificate: %v", err)
		writeError(w, &errs.Wrapped{Msg: "invalid certificate PEM", Err: err}, http.StatusBadRequest)
		return
	}

	// Save certificate
	if err := ks.SaveCert(r.Context(), keyID, cert); err != nil {
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

	ks, err := h.lookupBackend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Get certificate
	cert, err := ks.GetCert(r.Context(), keyID)
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

	ks, err := h.lookupBackend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Delete certificate
	if err := ks.DeleteCert(r.Context(), keyID); err != nil {
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

	ks, err := h.lookupBackend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// List certificates
	certIDs, err := ks.ListCerts(r.Context())
	if err != nil {
		log.Printf("Failed to list certificates: %v", err)
		handleError(w, err)
		return
	}

	// Convert to CertificateInfo objects
	certs := make([]CertificateInfo, len(certIDs))
	for i, keyID := range certIDs {
		certs[i] = CertificateInfo{
			KeyID: keyID,
		}
	}

	pageReq := parsePageRequest(r)
	paged, pageResp := applyPagination(certs, pageReq)

	resp := ListCertsResponse{
		Certificates: paged,
		Pagination:   pageResp,
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

	ks, err := h.lookupBackend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Check if certificate exists
	exists, err := ks.CertExists(r.Context(), keyID)
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

	ks, err := h.lookupBackend(backendID)
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
			writeError(w, &errs.Wrapped{Msg: fmt.Sprintf("invalid certificate PEM at index %d", i), Err: err}, http.StatusBadRequest)
			return
		}
		chain = append(chain, cert)
	}

	// Save certificate chain
	if err := ks.SaveCertChain(r.Context(), keyID, chain); err != nil {
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

	ks, err := h.lookupBackend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Get certificate chain
	chain, err := ks.GetCertChain(r.Context(), keyID)
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

	ks, err := h.lookupBackend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Find the key
	keyAttrs, err := ks.ListKeys(r.Context())
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
	tlsCert, err := ks.GetTLSCertificate(r.Context(), keyID, targetAttr)
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
	if err := validation.ValidateBackendName(req.Backend); err != nil {
		writeError(w, &errs.Wrapped{Msg: "invalid backend", Err: err}, http.StatusBadRequest)
		return
	}

	if req.KeyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	// Validate KeyID for security
	if err := ValidateKeyID(req.KeyID); err != nil {
		writeError(w, &errs.Wrapped{Msg: "invalid key ID", Err: err}, http.StatusBadRequest)
		return
	}

	if req.KeyType == "" {
		writeError(w, ErrInvalidKeyType, http.StatusBadRequest)
		return
	}
	if req.Algorithm == "" {
		writeError(w, &errs.Message{Msg: "missing wrapping algorithm"}, http.StatusBadRequest)
		return
	}

	// Get the backend
	ks, err := h.lookupBackend(req.Backend)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Check if the backend supports the import half of the ceremony. This
	// asserts backend.ImportBackend, not the full ImportExportBackend union: a
	// backend that cannot export (AWS KMS, by hardware design) must still be
	// reachable here, since GetImportParameters is unrelated to whether the
	// same backend can later export a key.
	importBackend, ok := ks.KeyProvider().(backend.ImportBackend)
	if !ok {
		writeError(w, backend.ErrImportNotSupported, http.StatusNotImplemented)
		return
	}

	// Build key attributes
	attrs, hashErr := buildKeyAttributes(req.KeyID, req.KeyType, req.KeySize, req.Curve, req.Hash, req.AESKeySize)
	if hashErr != nil {
		mapKeyOpError(w, hashErr)
		return
	}

	// Parse wrapping algorithm
	wrappingAlg := backend.WrappingAlgorithm(req.Algorithm)

	// Get import parameters
	params, err := importBackend.GetImportParameters(r.Context(), attrs, wrappingAlg)
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
		KeySpec:              params.KeySpec,
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

// resolveImportBackend resolves the named backend and asserts that it
// implements backend.ImportBackend. It writes the mapped error response and
// reports false when resolution fails, so callers only need to return.
//
// The backend is always named explicitly by the caller and is never inferred:
// wrapping is backend specific (AWS KMS, GCP KMS and PKCS#11 each define their
// own wrapping semantics and import tokens), so material wrapped by one
// backend cannot be unwrapped or imported by another.
//
// This asserts backend.ImportBackend, not the full ImportExportBackend union.
// WrapKey and UnwrapKey are both half of the import ceremony -- wrapping
// material to hand to ImportKey, and unwrapping material previously produced
// by WrapKey -- so a backend that cannot export (AWS KMS, by hardware design)
// must still be reachable through this resolver.
func (h *HandlerContext) resolveImportBackend(w http.ResponseWriter, name string) (backend.ImportBackend, bool) {
	if err := validation.ValidateBackendName(name); err != nil {
		writeError(w, &errs.Wrapped{Msg: "invalid backend", Err: err}, http.StatusBadRequest)
		return nil, false
	}

	ks, err := h.lookupBackend(name)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return nil, false
	}

	importBackend, ok := ks.KeyProvider().(backend.ImportBackend)
	if !ok {
		writeError(w, backend.ErrImportNotSupported, http.StatusNotImplemented)
		return nil, false
	}
	return importBackend, true
}

// WrapKeyHandler handles POST /api/v1/keys/wrap requests. The request must
// name the backend whose wrapping semantics are used; an empty backend is
// rejected with 400 rather than silently resolved, matching ImportKeyHandler.
func (h *HandlerContext) WrapKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req WrapKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Backend == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}
	if len(req.KeyMaterial) == 0 {
		writeError(w, &errs.Message{Msg: "missing key material"}, http.StatusBadRequest)
		return
	}
	if req.WrappingPublicKeyPEM == "" {
		writeError(w, &errs.Message{Msg: "missing wrapping public key"}, http.StatusBadRequest)
		return
	}
	if req.Algorithm == "" {
		writeError(w, &errs.Message{Msg: "missing wrapping algorithm"}, http.StatusBadRequest)
		return
	}

	// Decode wrapping public key from PEM
	wrappingKey, err := encoding.DecodePublicKeyPEM([]byte(req.WrappingPublicKeyPEM))
	if err != nil {
		log.Printf("Failed to decode wrapping public key: %v", err)
		writeError(w, &errs.Wrapped{Msg: "invalid wrapping public key", Err: err}, http.StatusBadRequest)
		return
	}

	// Build import parameters
	params := &backend.ImportParameters{
		WrappingPublicKey: wrappingKey,
		Algorithm:         backend.WrappingAlgorithm(req.Algorithm),
		ImportToken:       req.ImportToken,
		KeySpec:           req.KeySpec,
	}

	// Wrap the key material with the caller-named backend.
	importBackend, ok := h.resolveImportBackend(w, req.Backend)
	if !ok {
		return
	}

	wrapped, err := importBackend.WrapKey(r.Context(), req.KeyMaterial, params)
	if err != nil {
		log.Printf("Failed to wrap key: %v", err)
		handleError(w, err)
		return
	}

	// Build response
	resp := WrapKeyResponse{
		WrappedKey:  wrapped.WrappedKey,
		Algorithm:   string(wrapped.Algorithm),
		ImportToken: wrapped.ImportToken,
		Metadata:    wrapped.Metadata,
	}

	writeJSON(w, resp, http.StatusOK)
}

// UnwrapKeyHandler handles POST /api/v1/keys/unwrap requests. The request must
// name the backend that performs the unwrap -- it has to be the same backend
// that produced the wrapped material -- so an empty backend is rejected with
// 400 rather than silently resolved, matching ImportKeyHandler.
func (h *HandlerContext) UnwrapKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req UnwrapKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Backend == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}
	if len(req.WrappedKey) == 0 {
		writeError(w, &errs.Message{Msg: "missing wrapped key"}, http.StatusBadRequest)
		return
	}
	if req.WrappingPublicKeyPEM == "" {
		writeError(w, &errs.Message{Msg: "missing wrapping public key"}, http.StatusBadRequest)
		return
	}
	if req.Algorithm == "" {
		writeError(w, &errs.Message{Msg: "missing wrapping algorithm"}, http.StatusBadRequest)
		return
	}

	// Decode wrapping public key from PEM
	wrappingKey, err := encoding.DecodePublicKeyPEM([]byte(req.WrappingPublicKeyPEM))
	if err != nil {
		log.Printf("Failed to decode wrapping public key: %v", err)
		writeError(w, &errs.Wrapped{Msg: "invalid wrapping public key", Err: err}, http.StatusBadRequest)
		return
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
		WrappingPublicKey: wrappingKey,
		Algorithm:         backend.WrappingAlgorithm(req.Algorithm),
		ImportToken:       req.ImportToken,
		KeySpec:           req.KeySpec,
	}

	// Unwrap the key material with the caller-named backend.
	importBackend, ok := h.resolveImportBackend(w, req.Backend)
	if !ok {
		return
	}

	keyMaterial, err := importBackend.UnwrapKey(r.Context(), wrapped, params)
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
	if err := validation.ValidateBackendName(req.Backend); err != nil {
		writeError(w, &errs.Wrapped{Msg: "invalid backend", Err: err}, http.StatusBadRequest)
		return
	}

	if req.KeyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return
	}

	// Validate KeyID for security
	if err := ValidateKeyID(req.KeyID); err != nil {
		writeError(w, &errs.Wrapped{Msg: "invalid key ID", Err: err}, http.StatusBadRequest)
		return
	}

	if req.KeyType == "" {
		writeError(w, ErrInvalidKeyType, http.StatusBadRequest)
		return
	}
	if len(req.WrappedKey) == 0 {
		writeError(w, &errs.Message{Msg: "missing wrapped key"}, http.StatusBadRequest)
		return
	}
	if req.Algorithm == "" {
		writeError(w, &errs.Message{Msg: "missing wrapping algorithm"}, http.StatusBadRequest)
		return
	}

	// Get the backend
	ks, err := h.lookupBackend(req.Backend)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Check if the backend supports the import half of the ceremony. Asserts
	// backend.ImportBackend, not the full ImportExportBackend union: a
	// backend that genuinely cannot export (AWS KMS, by hardware design)
	// must not be blocked from importing because of that unrelated
	// limitation. Before this assertion was split, a missing export method
	// on any backend failed this check and every import through this
	// handler returned "backend does not support import/export operations"
	// regardless of whether import itself worked.
	importBackend, ok := ks.KeyProvider().(backend.ImportBackend)
	if !ok {
		writeError(w, backend.ErrImportNotSupported, http.StatusNotImplemented)
		return
	}

	// Build key attributes
	attrs, hashErr := buildKeyAttributes(req.KeyID, req.KeyType, req.KeySize, req.Curve, req.Hash, req.AESKeySize)
	if hashErr != nil {
		mapKeyOpError(w, hashErr)
		return
	}

	// Build wrapped key material
	// The request decides whether the key may leave again; the write-once
	// defaults apply only when it says nothing. This path never set the
	// flag, so every symmetric key imported over REST was stored
	// non-exportable while the same import over gRPC or MCP was exportable.
	xkms.ApplyImportExportability(attrs, req.Exportable, req.Sensitive)
	attrs.Partition = types.Partition(req.Partition)

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  req.WrappedKey,
		Algorithm:   backend.WrappingAlgorithm(req.Algorithm),
		ImportToken: req.ImportToken,
		Metadata:    req.Metadata,
	}

	// Import the key
	if err := importBackend.ImportKey(r.Context(), attrs, wrapped); err != nil {
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
	if req.KeyType != "symmetric" {
		privKey, err := ks.GetKey(r.Context(), attrs)
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
		writeError(w, &errs.Message{Msg: "missing wrapping algorithm"}, http.StatusBadRequest)
		return
	}

	ks, err := h.lookupBackend(backendID)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Check if the backend supports the export half of the ceremony. Asserts
	// backend.ExportBackend, not the full ImportExportBackend union, for the
	// same reason ImportKeyHandler asserts backend.ImportBackend: export and
	// import are independent capabilities, and a backend that only supports
	// one must not be unreachable for it because of the other.
	exportBackend, ok := ks.KeyProvider().(backend.ExportBackend)
	if !ok {
		writeError(w, backend.ErrExportNotSupported, http.StatusNotImplemented)
		return
	}

	// Find the key
	keyAttrs, err := ks.ListKeys(r.Context())
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
	wrapped, err := exportBackend.ExportKey(r.Context(), targetAttr, wrappingAlg)
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
		writeError(w, &errs.Message{Msg: "missing source_backend"}, http.StatusBadRequest)
		return
	}
	if req.SourceKeyID == "" {
		writeError(w, &errs.Message{Msg: "missing source_key_id"}, http.StatusBadRequest)
		return
	}
	if req.DestBackend == "" {
		writeError(w, &errs.Message{Msg: "missing dest_backend"}, http.StatusBadRequest)
		return
	}
	if req.DestKeyID == "" {
		writeError(w, &errs.Message{Msg: "missing dest_key_id"}, http.StatusBadRequest)
		return
	}
	if req.KeyType == "" {
		writeError(w, &errs.Message{Msg: "missing key_type"}, http.StatusBadRequest)
		return
	}
	if req.Algorithm == "" {
		writeError(w, &errs.Message{Msg: "missing wrapping algorithm"}, http.StatusBadRequest)
		return
	}

	// Get source backend
	sourceKS, err := h.lookupBackend(req.SourceBackend)
	if err != nil {
		writeError(w, &errs.Wrapped{Msg: "source backend not found", Err: err}, http.StatusNotFound)
		return
	}

	// Check if source backend supports export. This asserts
	// backend.ExportBackend rather than the full ImportExportBackend union:
	// the source backend below is only ever asked to ExportKey, so a backend
	// that cannot import (but can export) must not be refused here for a
	// capability this handler never calls on it.
	sourceBackend, ok := sourceKS.KeyProvider().(backend.ExportBackend)
	if !ok {
		writeError(w, backend.ErrExportNotSupported, http.StatusNotImplemented)
		return
	}

	// Get destination backend
	destKS, err := h.lookupBackend(req.DestBackend)
	if err != nil {
		writeError(w, &errs.Wrapped{Msg: "destination backend not found", Err: err}, http.StatusNotFound)
		return
	}

	// Check if destination backend supports import. This asserts
	// backend.ImportBackend rather than the full ImportExportBackend union:
	// the destination backend below is only ever asked to ImportKey, so AWS
	// KMS -- which genuinely cannot export but does support import -- is a
	// valid destination for CopyKey even though it would never be a valid
	// source.
	destBackend, ok := destKS.KeyProvider().(backend.ImportBackend)
	if !ok {
		writeError(w, backend.ErrImportNotSupported, http.StatusNotImplemented)
		return
	}

	// Find the source key
	sourceKeyAttrs, err := sourceKS.ListKeys(r.Context())
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
		writeError(w, &errs.Message{Msg: fmt.Sprintf("source key not found: %s", req.SourceKeyID)}, http.StatusNotFound)
		return
	}

	// Parse wrapping algorithm
	wrappingAlg := backend.WrappingAlgorithm(req.Algorithm)

	// Export the key from source backend
	wrapped, err := sourceBackend.ExportKey(r.Context(), sourceAttr, wrappingAlg)
	if err != nil {
		log.Printf("Failed to export key from source backend: %v", err)
		handleError(w, err)
		return
	}

	// Build destination key attributes
	destAttrs, hashErr := buildKeyAttributes(req.DestKeyID, req.KeyType, req.KeySize, req.Curve, req.Hash, req.AESKeySize)
	if hashErr != nil {
		mapKeyOpError(w, hashErr)
		return
	}

	// Import the key to destination backend
	if err := destBackend.ImportKey(r.Context(), destAttrs, wrapped); err != nil {
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

// SealHandler handles POST /api/v1/seal requests.
// This endpoint seals (encrypts) data using a backend's sealing mechanism.
// Sealing may include hardware-backed protection (TPM, HSM) or policy-based access control.
func (h *HandlerContext) SealHandler(w http.ResponseWriter, r *http.Request) {
	var req SealRequest
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
	if err := validation.ValidateBackendName(req.Backend); err != nil {
		writeError(w, &errs.Wrapped{Msg: "invalid backend", Err: err}, http.StatusBadRequest)
		return
	}

	if len(req.Data) == 0 {
		writeError(w, ErrMissingData, http.StatusBadRequest)
		return
	}

	// Validate KeyID if provided
	if req.KeyID != "" {
		if err := ValidateKeyID(req.KeyID); err != nil {
			writeError(w, &errs.Wrapped{Msg: "invalid key ID", Err: err}, http.StatusBadRequest)
			return
		}
	}

	// Build seal options
	opts := &types.SealOptions{
		AAD: req.AAD,
	}

	// If key ID is provided, look up the key to get its actual attributes
	if req.KeyID != "" {
		// Get the backend to look up the key
		ks, err := h.lookupBackend(req.Backend)
		if err != nil {
			writeError(w, ErrBackendNotFound, http.StatusNotFound)
			return
		}

		// Find the key by CN to get its full attributes
		keyAttrs, err := ks.ListKeys(r.Context())
		if err != nil {
			log.Printf("Failed to list keys: %v", err)
			handleError(w, err)
			return
		}

		var targetAttr *types.KeyAttributes
		for _, attr := range keyAttrs {
			if attr.CN == req.KeyID {
				targetAttr = attr
				break
			}
		}

		if targetAttr == nil {
			writeError(w, backend.ErrKeyNotFound, http.StatusNotFound)
			return
		}

		opts.KeyAttributes = targetAttr
	}

	// Seal the data using the xkms service
	sealed, err := h.sealWithBackend(r.Context(), req.Backend, req.Data, opts)
	if err != nil {
		log.Printf("Failed to seal data: %v", err)
		handleError(w, err)
		return
	}

	// Build response
	resp := SealResponse{
		Backend:    string(sealed.Backend),
		Ciphertext: sealed.Ciphertext,
		Nonce:      sealed.Nonce,
		Tag:        sealed.Tag,
		Metadata:   sealed.Metadata,
	}

	writeJSON(w, resp, http.StatusOK)
}

// UnsealHandler handles POST /api/v1/unseal requests.
// This endpoint unseals (decrypts) data that was previously sealed.
// The sealed data must have been created by the same backend type.
func (h *HandlerContext) UnsealHandler(w http.ResponseWriter, r *http.Request) {
	var req UnsealRequest
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
	if err := validation.ValidateBackendName(req.Backend); err != nil {
		writeError(w, &errs.Wrapped{Msg: "invalid backend", Err: err}, http.StatusBadRequest)
		return
	}

	if len(req.Ciphertext) == 0 {
		writeError(w, ErrMissingCiphertext, http.StatusBadRequest)
		return
	}

	// Validate KeyID if provided
	if req.KeyID != "" {
		if err := ValidateKeyID(req.KeyID); err != nil {
			writeError(w, &errs.Wrapped{Msg: "invalid key ID", Err: err}, http.StatusBadRequest)
			return
		}
	}

	// Get backend to determine backend type
	ks, err := h.lookupBackend(req.Backend)
	if err != nil {
		writeError(w, ErrBackendNotFound, http.StatusNotFound)
		return
	}

	// Build sealed data structure
	sealed := &types.SealedData{
		Backend:    ks.KeyProvider().Type(),
		Ciphertext: req.Ciphertext,
		Nonce:      req.Nonce,
		Tag:        req.Tag,
		Metadata:   req.Metadata,
	}

	// Build unseal options
	opts := &types.UnsealOptions{
		AAD: req.AAD,
	}

	// If key ID is provided, look up the key to get its actual attributes
	if req.KeyID != "" {
		// Find the key by CN to get its full attributes
		keyAttrs, err := ks.ListKeys(r.Context())
		if err != nil {
			log.Printf("Failed to list keys: %v", err)
			handleError(w, err)
			return
		}

		var targetAttr *types.KeyAttributes
		for _, attr := range keyAttrs {
			if attr.CN == req.KeyID {
				targetAttr = attr
				break
			}
		}

		if targetAttr == nil {
			writeError(w, backend.ErrKeyNotFound, http.StatusNotFound)
			return
		}

		opts.KeyAttributes = targetAttr
		sealed.KeyID = targetAttr.ID() // Use storage format to match what Seal stores
	}

	// Unseal the data using the xkms service
	plaintext, err := h.unsealWithBackend(r.Context(), req.Backend, sealed, opts)
	if err != nil {
		log.Printf("Failed to unseal data: %v", err)
		handleError(w, err)
		return
	}

	// Build response
	resp := UnsealResponse{
		Plaintext: plaintext,
	}

	writeJSON(w, resp, http.StatusOK)
}

// CanSealHandler handles GET /api/v1/seal/capability requests.
// This endpoint checks whether a backend supports sealing operations.
func (h *HandlerContext) CanSealHandler(w http.ResponseWriter, r *http.Request) {
	backendName := r.URL.Query().Get("backend")

	// If no backend specified, check default backend
	if backendName == "" {
		canSeal := h.canSeal()
		resp := CanSealResponse{
			CanSeal: canSeal,
		}
		writeJSON(w, resp, http.StatusOK)
		return
	}

	// Validate backend name
	if err := validation.ValidateBackendName(backendName); err != nil {
		writeError(w, &errs.Wrapped{Msg: "invalid backend", Err: err}, http.StatusBadRequest)
		return
	}

	// Check if the specified backend supports sealing
	canSeal := h.canSeal(backendName)

	resp := CanSealResponse{
		CanSeal: canSeal,
		Backend: backendName,
	}

	writeJSON(w, resp, http.StatusOK)
}

// buildKeyAttributes is a helper function to build key attributes from REST request parameters.
//
// The hash name is resolved by xkms.ResolveHash, so an unresolvable name is an
// error the caller sees rather than a silent SHA-256 substitution.
func buildKeyAttributes(keyID, keyType string, keySize int, curve, hash string, aesKeySize int) (*types.KeyAttributes, error) {
	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreSoftware,
		Hash:      crypto.SHA256,
	}

	// Parse key type and set appropriate attributes
	switch {
	case types.AlgorithmRSA.Equals(keyType):
		attrs.KeyAlgorithm = x509.RSA
		if keySize == 0 {
			keySize = types.RSAKeySize2048
		}
		attrs.RSAAttributes = &types.RSAAttributes{
			KeySize: keySize,
		}
	case types.AlgorithmECDSA.Equals(keyType):
		attrs.KeyAlgorithm = x509.ECDSA
		if curve == "" {
			curve = string(types.CurveP256)
		}
		// This function already returns an error; dropping ParseCurve's meant an
		// unrecognised curve surfaced later as the backend's "curve is
		// required" (go-xkms#153).
		parsedCurve, curveErr := types.ParseCurve(curve)
		if curveErr != nil {
			return nil, curveErr
		}
		attrs.ECCAttributes = &types.ECCAttributes{
			Curve: parsedCurve,
		}
	case types.AlgorithmEd25519.Equals(keyType):
		attrs.KeyAlgorithm = x509.Ed25519
	case types.AlgorithmSymmetric.Equals(keyType):
		attrs.KeyType = types.KeyTypeSecret // Symmetric keys use KeyTypeSecret
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
	}

	// Set hash algorithm if provided
	if hash != "" {
		h, err := resolveHashForHandler(hash)
		if err != nil {
			return nil, err
		}
		attrs.Hash = h
	}

	return attrs, nil
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

// callerTenantID returns the tenant the authenticated caller belongs to, or the
// empty string for a system-level or unauthenticated request.
//
// Every key operation must carry this through to the service layer: the service
// resolves a tenant-scoped view of the backend from it, and a key ID is only
// unique within a tenant. Omitting it runs the operation against the unscoped
// backend, where a lookup by common name can reach another tenant's key.
func callerTenantID(ctx context.Context) string {
	if identity := auth.GetIdentity(ctx); identity != nil {
		return identity.TenantID
	}
	return ""
}

// resolveHashForHandler resolves a caller-supplied hash name for a REST handler.
//
// It rejects the "NONE" sentinel that xkms.ResolveHash maps to crypto.Hash(0).
// That value means "the caller supplied a pre-built digest; do not hash", which
// the handlers in this file never do — and crypto.Hash(0).New() panics, so the
// sentinel must fail closed here rather than reaching a hasher.
func resolveHashForHandler(hash string) (crypto.Hash, error) {
	h, err := xkms.ResolveHash(hash)
	if err != nil {
		return 0, err
	}
	if h == 0 {
		return 0, xkms.ErrInvalidHashFunction
	}
	return h, nil
}
