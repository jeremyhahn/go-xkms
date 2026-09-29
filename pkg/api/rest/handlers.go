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
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/go-chi/chi/v5"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/encoding"
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

	pageReq, err := transport.PageRequestFromQuery(r)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}
	paged, pageResp := transport.ApplyPagination(backends, pageReq)

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
//
// Generation belongs to the service layer, which owns backend resolution,
// the algorithm and key-purpose vocabularies, the symmetric/asymmetric
// split, curve and RSA-size validation (including the 2048-bit floor,
// go-xkms#1204), and the exportability contract
// (pkg/xkms/servicer_key.go's buildKeyAttributes). This handler used to
// reimplement all of that so it could drift from gRPC, MCP and the embedded
// transport's own copies (go-xkms#1214).
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

	// Validate backend name. This stays here, ahead of the service call,
	// because xkms.ErrBackendNameValidation is not one of mapKeyOpError's
	// mapped sentinels: a malformed name must fail closed as 400 rather than
	// fall through to mapKeyOpError's 500 catch-all.
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

	resp, err := h.xkmsService.GenerateKey(r.Context(), &transport.GenerateKeyRequest{
		KeyID:      req.KeyID,
		Backend:    req.Backend,
		KeyType:    req.KeyType,
		KeySize:    req.KeySize,
		Curve:      req.Curve,
		Hash:       req.Hash,
		Algorithm:  req.Algorithm,
		Exportable: req.Exportable,
		Sensitive:  req.Sensitive,
		Partition:  req.Partition,
		TPMPolicy:  req.TPMPolicy,
		TenantID:   callerTenantID(r.Context()),
	})
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, GenerateKeyResponse{
		KeyID:        resp.KeyID,
		KeyType:      req.KeyType,
		PublicKeyPEM: resp.PublicKeyPEM,
		Message:      fmt.Sprintf("Key %s generated successfully", resp.KeyID),
	}, http.StatusCreated)
}

// ListKeysHandler handles GET /api/v1/keys requests.
//
// The listing belongs to the service layer, which confines it to the caller's
// tenant: a tenant sees only its own keys, and the pagination total counts
// only those. This handler used to list the unscoped backend itself, so any
// tenant could enumerate every other tenant's keys (go-xkms#1218).
func (h *HandlerContext) ListKeysHandler(w http.ResponseWriter, r *http.Request) {
	backendID := r.URL.Query().Get("backend")
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	pageReq, err := transport.PageRequestFromQuery(r)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}

	if h.xkmsService == nil {
		mapKeyOpError(w, xkms.ErrNotInitialized)
		return
	}

	listed, err := h.xkmsService.ListKeys(r.Context(), backendID, transport.WithPageRequest(pageReq))
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	keys := make([]KeyInfo, 0, len(listed.Keys))
	for _, key := range listed.Keys {
		keys = append(keys, keyInfoFromTransport(key))
	}

	writeJSON(w, ListKeysResponse{
		Keys:       keys,
		Pagination: listed.PageResponse,
	}, http.StatusOK)
}

// GetKeyHandler handles GET /api/v1/keys/{id} requests.
//
// The lookup belongs to the service layer, which confines it to the caller's
// tenant. Another tenant's key is a 404 identical to the one a key no tenant
// holds produces, so the response does not reveal that it exists. This
// handler used to scan the unscoped backend, and returned any tenant's key to
// any caller that named it (go-xkms#1218).
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

	if h.xkmsService == nil {
		mapKeyOpError(w, xkms.ErrNotInitialized)
		return
	}

	resp, err := h.xkmsService.GetKey(r.Context(), backendID, keyID)
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	info := keyInfoFromTransport(resp.KeyInfo)
	info.PublicKeyPEM = resp.PublicKeyPEM
	writeJSON(w, GetKeyResponse{KeyInfo: info}, http.StatusOK)
}

// keyInfoFromTransport renders the service layer's KeyInfo as this
// transport's wire shape.
func keyInfoFromTransport(key transport.KeyInfo) KeyInfo {
	return KeyInfo{
		KeyID:        key.KeyID,
		KeyType:      key.KeyType,
		Algorithm:    key.Algorithm,
		Backend:      key.Backend,
		PublicKeyPEM: key.PublicKeyPEM,
	}
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
//
// Deletion belongs to the service layer, which resolves the key within the
// caller's tenant: another tenant's key is a 404 identical to a genuine miss.
// This handler used to resolve the key over the unscoped backend, and deleted
// any tenant's key for any caller that named it (go-xkms#1218).
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

	if h.xkmsService == nil {
		mapKeyOpError(w, xkms.ErrNotInitialized)
		return
	}

	if err := h.xkmsService.DeleteKey(r.Context(), backendID, keyID); err != nil {
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, DeleteKeyResponse{
		Success: true,
		Message: fmt.Sprintf("Key %s deleted successfully", keyID),
	}, http.StatusOK)
}

// RotateKeyHandler handles POST /api/v1/keys/{id}/rotate requests.
//
// Rotation belongs to the service layer, which resolves the key within the
// caller's tenant: another tenant's key is a 404 identical to a genuine miss.
// This handler used to resolve the key over the unscoped backend, and
// replaced any tenant's key for any caller that named it (go-xkms#1218).
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

	if h.xkmsService == nil {
		mapKeyOpError(w, xkms.ErrNotInitialized)
		return
	}

	resp, err := h.xkmsService.RotateKey(r.Context(), &transport.RotateKeyRequest{
		Backend:  backendID,
		KeyID:    keyID,
		TenantID: callerTenantID(r.Context()),
	})
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, RotateKeyResponse{
		Success:      true,
		KeyID:        resp.KeyID,
		KeyType:      resp.KeyType,
		PublicKeyPEM: resp.PublicKeyPEM,
		Message:      fmt.Sprintf("Key %s rotated successfully", resp.KeyID),
	}, http.StatusOK)
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
		Ciphertext:   resp.Ciphertext,
		Nonce:        resp.Nonce,
		Tag:          resp.Tag,
		IV:           resp.IV,
		GCMNonceMode: resp.GCMNonceMode,
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
		GCMNonceMode:   req.GCMNonceMode,
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

// The certificate handlers below are thin adapters over the XKMSService
// certificate methods, which confine every read, write, listing and delete to
// the caller's tenant namespace. A certificate another tenant holds, or one
// the platform holds, answers exactly as one nobody stored, and a key ID that
// names another namespace ("tenant-b/web") is refused as malformed. These
// handlers used to call the unscoped backend directly, so any tenant could
// read, overwrite, list or delete every tenant's certificates and the
// platform's (go-xkms#1228).

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

	if h.xkmsService == nil {
		mapKeyOpError(w, xkms.ErrNotInitialized)
		return
	}

	if err := h.xkmsService.SaveCertificate(r.Context(), &transport.SaveCertificateRequest{
		Backend:        backendID,
		KeyID:          keyID,
		CertificatePEM: req.CertificatePEM,
		TenantID:       callerTenantID(r.Context()),
	}); err != nil {
		mapKeyOpError(w, err)
		return
	}

	resp := SuccessResponse{
		Success: true,
		Message: fmt.Sprintf("Certificate for key %s saved successfully", keyID),
	}
	writeJSON(w, resp, http.StatusCreated)
}

// certRequestTarget reads the key ID path parameter and the backend query
// parameter every by-ID certificate handler requires, writing the 400 for
// whichever is missing. It reports false when the handler must stop.
func (h *HandlerContext) certRequestTarget(w http.ResponseWriter, r *http.Request) (keyID, backendID string, ok bool) {
	keyID = chi.URLParam(r, "id")
	if keyID == "" {
		writeError(w, ErrMissingKeyID, http.StatusBadRequest)
		return "", "", false
	}

	backendID = r.URL.Query().Get("backend")
	if backendID == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return "", "", false
	}

	if h.xkmsService == nil {
		mapKeyOpError(w, xkms.ErrNotInitialized)
		return "", "", false
	}
	return keyID, backendID, true
}

// GetCertHandler handles GET /api/v1/certs/{id} requests.
func (h *HandlerContext) GetCertHandler(w http.ResponseWriter, r *http.Request) {
	keyID, backendID, ok := h.certRequestTarget(w, r)
	if !ok {
		return
	}

	resp, err := h.xkmsService.GetCertificate(r.Context(), backendID, keyID)
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, GetCertResponse{
		KeyID:          resp.KeyID,
		CertificatePEM: resp.CertificatePEM,
	}, http.StatusOK)
}

// DeleteCertHandler handles DELETE /api/v1/certs/{id} requests.
func (h *HandlerContext) DeleteCertHandler(w http.ResponseWriter, r *http.Request) {
	keyID, backendID, ok := h.certRequestTarget(w, r)
	if !ok {
		return
	}

	if err := h.xkmsService.DeleteCertificate(r.Context(), backendID, keyID); err != nil {
		mapKeyOpError(w, err)
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

	pageReq, err := transport.PageRequestFromQuery(r)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}

	if h.xkmsService == nil {
		mapKeyOpError(w, xkms.ErrNotInitialized)
		return
	}

	listed, err := h.xkmsService.ListCertificates(r.Context(), backendID, transport.WithPageRequest(pageReq))
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	certs := make([]CertificateInfo, 0, len(listed.Certificates))
	for _, cert := range listed.Certificates {
		certs = append(certs, CertificateInfo{
			KeyID:          cert.KeyID,
			Subject:        cert.Subject,
			Issuer:         cert.Issuer,
			NotBefore:      cert.NotBefore,
			NotAfter:       cert.NotAfter,
			SerialNumber:   cert.SerialNumber,
			CertificatePEM: cert.CertificatePEM,
		})
	}

	writeJSON(w, ListCertsResponse{
		Certificates: certs,
		Pagination:   listed.PageResponse,
	}, http.StatusOK)
}

// CertExistsHandler handles HEAD /api/v1/certs/{id} requests.
func (h *HandlerContext) CertExistsHandler(w http.ResponseWriter, r *http.Request) {
	keyID, backendID, ok := h.certRequestTarget(w, r)
	if !ok {
		return
	}

	exists, err := h.xkmsService.CertificateExists(r.Context(), backendID, keyID)
	if err != nil {
		mapKeyOpError(w, err)
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
	keyID, backendID, ok := h.certRequestTarget(w, r)
	if !ok {
		return
	}

	var req SaveCertChainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if err := h.xkmsService.SaveCertificateChain(r.Context(), &transport.SaveCertificateChainRequest{
		Backend:  backendID,
		KeyID:    keyID,
		ChainPEM: req.CertChainPEM,
		TenantID: callerTenantID(r.Context()),
	}); err != nil {
		mapKeyOpError(w, err)
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
	keyID, backendID, ok := h.certRequestTarget(w, r)
	if !ok {
		return
	}

	resp, err := h.xkmsService.GetCertificateChain(r.Context(), backendID, keyID)
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, GetCertChainResponse{
		KeyID:        resp.KeyID,
		CertChainPEM: resp.ChainPEM,
	}, http.StatusOK)
}

// GetTLSCertificateHandler handles GET /api/v1/tls/{id} requests. The bundle
// is the leaf and chain stored in the caller's certificate namespace; the
// private key never travels on this response (go-xkms#627).
func (h *HandlerContext) GetTLSCertificateHandler(w http.ResponseWriter, r *http.Request) {
	keyID, backendID, ok := h.certRequestTarget(w, r)
	if !ok {
		return
	}

	resp, err := h.xkmsService.GetTLSCertificate(r.Context(), backendID, keyID)
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, resp, http.StatusOK)
}

// GetImportParametersHandler handles POST /api/v1/keys/import-params requests.
//
// The ceremony belongs to the service layer, which owns backend resolution
// (tenant-scoped, per-direction capability assertion), the key-template
// vocabulary and the RSA floor (go-xkms#1204). This handler used to assert
// backend.ImportBackend and build its own key attributes, reachable only
// through the untenanted backend map -- reimplementing what
// XKMSService.GetImportParameters already does, and bypassing tenant scoping
// in the process (go-xkms#1216).
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

	// Validate backend name. This stays here, ahead of the service call, for
	// the same reason GenerateKeyHandler keeps it: a malformed name must fail
	// closed as 400 rather than fall through to mapKeyOpError's 500 catch-all.
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

	resp, err := h.xkmsService.GetImportParameters(r.Context(), &transport.GetImportParametersRequest{
		Backend:   req.Backend,
		KeyID:     req.KeyID,
		Algorithm: req.Algorithm,
		KeyType:   req.KeyType,
		KeySize:   req.KeySize,
		Curve:     req.Curve,
		TenantID:  callerTenantID(r.Context()),
	})
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	// The service returns the wrapping public key as DER (transport is
	// backend-agnostic); this transport's wire response carries PEM, as it
	// always has.
	wrappingKeyPEM := pem.EncodeToMemory(&pem.Block{Type: encoding.PEMTypePublicKey, Bytes: resp.WrappingPublicKey})

	out := GetImportParametersResponse{
		WrappingPublicKeyPEM: string(wrappingKeyPEM),
		Algorithm:            resp.Algorithm,
		KeySpec:              resp.KeySpec,
		ExpiresAt:            resp.ExpiresAt,
	}

	// Add import token if present
	if resp.ImportToken != nil {
		out.ImportToken = json.RawMessage(resp.ImportToken)
	}

	writeJSON(w, out, http.StatusOK)
}

// WrapKeyHandler handles POST /api/v1/keys/wrap requests. The request must
// name the backend whose wrapping semantics are used; an empty backend is
// rejected with 400 rather than silently resolved, matching ImportKeyHandler.
//
// WrapKey belongs to the service layer, which resolves the named backend's
// import capability (backend.ImportBackend, never the full union -- see
// go-xkms#1216) the same way ImportKey does, and carries KeySpec and Metadata
// through both directions.
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

	// Validate backend name ahead of the service call, matching
	// GetImportParametersHandler and ImportKeyHandler: a malformed name fails
	// closed as 400 rather than falling through to mapKeyOpError's 500
	// catch-all.
	if err := validation.ValidateBackendName(req.Backend); err != nil {
		writeError(w, &errs.Wrapped{Msg: "invalid backend", Err: err}, http.StatusBadRequest)
		return
	}

	// Decode wrapping public key from PEM
	wrappingKey, err := encoding.DecodePublicKeyPEM([]byte(req.WrappingPublicKeyPEM))
	if err != nil {
		log.Printf("Failed to decode wrapping public key: %v", err)
		writeError(w, &errs.Wrapped{Msg: "invalid wrapping public key", Err: err}, http.StatusBadRequest)
		return
	}
	wrappingKeyDER, err := encoding.EncodePublicKeyPKIX(wrappingKey)
	if err != nil {
		writeError(w, &errs.Wrapped{Msg: "invalid wrapping public key", Err: err}, http.StatusBadRequest)
		return
	}

	resp, err := h.xkmsService.WrapKey(r.Context(), &transport.WrapKeyRequest{
		Backend:           req.Backend,
		KeyMaterial:       req.KeyMaterial,
		Algorithm:         req.Algorithm,
		WrappingPublicKey: wrappingKeyDER,
		ImportToken:       req.ImportToken,
		KeySpec:           req.KeySpec,
		TenantID:          callerTenantID(r.Context()),
	})
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, WrapKeyResponse{
		WrappedKey:  resp.WrappedKeyMaterial,
		Algorithm:   resp.Algorithm,
		ImportToken: resp.ImportToken,
		Metadata:    resp.Metadata,
	}, http.StatusOK)
}

// UnwrapKeyHandler handles POST /api/v1/keys/unwrap requests. The request must
// name the backend that performs the unwrap -- it has to be the same backend
// that produced the wrapped material -- so an empty backend is rejected with
// 400 rather than silently resolved, matching ImportKeyHandler.
//
// UnwrapKey belongs to the service layer for the same reason WrapKeyHandler
// does; see its doc comment.
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

	// Validate backend name ahead of the service call; see WrapKeyHandler.
	if err := validation.ValidateBackendName(req.Backend); err != nil {
		writeError(w, &errs.Wrapped{Msg: "invalid backend", Err: err}, http.StatusBadRequest)
		return
	}

	// Decode wrapping public key from PEM
	wrappingKey, err := encoding.DecodePublicKeyPEM([]byte(req.WrappingPublicKeyPEM))
	if err != nil {
		log.Printf("Failed to decode wrapping public key: %v", err)
		writeError(w, &errs.Wrapped{Msg: "invalid wrapping public key", Err: err}, http.StatusBadRequest)
		return
	}
	wrappingKeyDER, err := encoding.EncodePublicKeyPKIX(wrappingKey)
	if err != nil {
		writeError(w, &errs.Wrapped{Msg: "invalid wrapping public key", Err: err}, http.StatusBadRequest)
		return
	}

	resp, err := h.xkmsService.UnwrapKey(r.Context(), &transport.UnwrapKeyRequest{
		Backend:            req.Backend,
		WrappedKeyMaterial: req.WrappedKey,
		Algorithm:          req.Algorithm,
		ImportToken:        req.ImportToken,
		WrappingPublicKey:  wrappingKeyDER,
		KeySpec:            req.KeySpec,
		Metadata:           req.Metadata,
		TenantID:           callerTenantID(r.Context()),
	})
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, UnwrapKeyResponse{
		KeyMaterial: json.RawMessage(resp.KeyMaterial),
	}, http.StatusOK)
}

// ImportKeyHandler handles POST /api/v1/keys/import requests.
//
// Import belongs to the service layer, which owns backend resolution
// (tenant-scoped, per-direction capability assertion -- backend.ImportBackend,
// never the full ImportExportBackend union, so a backend that genuinely
// cannot export, AWS KMS by hardware design, is never blocked from importing
// because of that unrelated limitation), the key-template vocabulary, the RSA
// floor (go-xkms#1204) and the exportability write-once default. This handler
// used to reimplement all of that reachable only through the untenanted
// backend map (go-xkms#1216).
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

	resp, err := h.xkmsService.ImportKey(r.Context(), &transport.ImportKeyRequest{
		Backend:            req.Backend,
		KeyID:              req.KeyID,
		KeyType:            req.KeyType,
		KeySize:            req.KeySize,
		Curve:              req.Curve,
		Hash:               req.Hash,
		AESKeySize:         req.AESKeySize,
		WrappedKeyMaterial: req.WrappedKey,
		Algorithm:          req.Algorithm,
		ImportToken:        req.ImportToken,
		Partition:          req.Partition,
		Metadata:           req.Metadata,
		Exportable:         req.Exportable,
		Sensitive:          req.Sensitive,
		TenantID:           callerTenantID(r.Context()),
	})
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, ImportKeyResponse{
		Success:      resp.Success,
		KeyID:        resp.KeyID,
		Message:      fmt.Sprintf("Key %s imported successfully", resp.KeyID),
		PublicKeyPEM: resp.PublicKeyPEM,
	}, http.StatusCreated)
}

// ExportKeyHandler handles POST /api/v1/keys/{id}/export requests.
//
// Export belongs to the service layer, which resolves the key within the
// caller's tenant: another tenant's key is a 404 identical to a genuine miss.
// This handler used to resolve the key over the unscoped backend, and handed
// any tenant's wrapped key material to any caller that named it
// (go-xkms#1218).
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

	if req.Algorithm == "" {
		writeError(w, &errs.Message{Msg: "missing wrapping algorithm"}, http.StatusBadRequest)
		return
	}

	if h.xkmsService == nil {
		mapKeyOpError(w, xkms.ErrNotInitialized)
		return
	}

	resp, err := h.xkmsService.ExportKey(r.Context(), &transport.ExportKeyRequest{
		Backend:   backendID,
		KeyID:     keyID,
		Algorithm: req.Algorithm,
		TenantID:  callerTenantID(r.Context()),
	})
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, ExportKeyResponse{
		KeyID:       resp.KeyID,
		WrappedKey:  resp.WrappedKeyMaterial,
		Algorithm:   resp.Algorithm,
		ImportToken: resp.ImportToken,
	}, http.StatusOK)
}

// CopyKeyHandler handles POST /api/v1/keys/copy requests.
//
// The copy belongs to the service layer, which resolves the source key within
// the caller's tenant, imports the copy into the caller's tenant in the
// destination backend, and wraps the material for the destination's own
// import parameters. The copy takes its algorithm, size, curve, hash and
// partition from the source key: a copy is the same key under a new name, so
// there is nothing for the request to describe. This handler used to resolve
// the source over the unscoped backend (so any tenant could copy any other
// tenant's key), built the destination's attributes from request fields that
// could disagree with the material being imported, and wrapped the material
// under a token only the source backend could open (go-xkms#1218).
func (h *HandlerContext) CopyKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req CopyKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	switch {
	case req.SourceBackend == "":
		writeError(w, &errs.Message{Msg: "missing source_backend"}, http.StatusBadRequest)
		return
	case req.SourceKeyID == "":
		writeError(w, &errs.Message{Msg: "missing source_key_id"}, http.StatusBadRequest)
		return
	case req.DestBackend == "":
		writeError(w, &errs.Message{Msg: "missing dest_backend"}, http.StatusBadRequest)
		return
	case req.DestKeyID == "":
		writeError(w, &errs.Message{Msg: "missing dest_key_id"}, http.StatusBadRequest)
		return
	case req.Algorithm == "":
		writeError(w, &errs.Message{Msg: "missing wrapping algorithm"}, http.StatusBadRequest)
		return
	}

	if h.xkmsService == nil {
		mapKeyOpError(w, xkms.ErrNotInitialized)
		return
	}

	if _, err := h.xkmsService.CopyKey(r.Context(), &transport.CopyKeyRequest{
		SourceBackend: req.SourceBackend,
		SourceKeyID:   req.SourceKeyID,
		DestBackend:   req.DestBackend,
		DestKeyID:     req.DestKeyID,
		Algorithm:     req.Algorithm,
		TenantID:      callerTenantID(r.Context()),
	}); err != nil {
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, CopyKeyResponse{
		Success: true,
		Message: fmt.Sprintf("Key copied successfully from %s/%s to %s/%s",
			req.SourceBackend, req.SourceKeyID, req.DestBackend, req.DestKeyID),
	}, http.StatusOK)
}

// SealHandler handles POST /api/v1/seal requests.
// This endpoint seals (encrypts) data using a backend's sealing mechanism.
// Sealing may include hardware-backed protection (TPM, HSM) or policy-based access control.
//
// The seal belongs to the service layer, which resolves the sealing key --
// the named one, or the caller's default sealing key when none is named --
// within the caller's tenant. Another tenant's key is a 404 identical to the
// one a key no tenant holds produces. This handler used to resolve the key
// over the unscoped backend and sealed under any tenant's key of that name
// (go-xkms#1228).
func (h *HandlerContext) SealHandler(w http.ResponseWriter, r *http.Request) {
	var req SealRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.Backend == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	if len(req.Data) == 0 {
		writeError(w, ErrMissingData, http.StatusBadRequest)
		return
	}

	if h.xkmsService == nil {
		mapKeyOpError(w, xkms.ErrNotInitialized)
		return
	}

	sealed, err := h.xkmsService.Seal(r.Context(), &transport.SealRequest{
		Backend:   req.Backend,
		KeyID:     req.KeyID,
		Data:      req.Data,
		AAD:       req.AAD,
		Password:  req.Password,
		TPMPolicy: req.TPMPolicy,
		TenantID:  callerTenantID(r.Context()),
	})
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, SealResponse{
		Backend:    sealed.Backend,
		Ciphertext: sealed.Ciphertext,
		Nonce:      sealed.Nonce,
		Tag:        sealed.Tag,
		Metadata:   sealed.Metadata,
		TPMPublic:  sealed.TPMPublic,
		TPMPrivate: sealed.TPMPrivate,
		WrappedDEK: sealed.WrappedDEK,
		KeyID:      sealed.KeyID,
	}, http.StatusOK)
}

// UnsealHandler handles POST /api/v1/unseal requests.
// This endpoint unseals (decrypts) data that was previously sealed.
// The sealed data must have been created by the same backend type.
//
// As with SealHandler, the key is resolved within the caller's tenant by the
// service, so a blob sealed under another tenant's key -- named, or that
// tenant's default sealing key -- does not unseal here. This handler used to
// resolve the key over the unscoped backend, so a tenant that held another
// tenant's blob and knew its key's name recovered the plaintext
// (go-xkms#1228).
func (h *HandlerContext) UnsealHandler(w http.ResponseWriter, r *http.Request) {
	var req UnsealRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, ErrInvalidRequest, http.StatusBadRequest)
		return
	}

	if req.Backend == "" {
		writeError(w, ErrMissingBackend, http.StatusBadRequest)
		return
	}

	if len(req.Ciphertext) == 0 && (len(req.TPMPublic) == 0 || len(req.TPMPrivate) == 0) {
		writeError(w, ErrMissingCiphertext, http.StatusBadRequest)
		return
	}

	if h.xkmsService == nil {
		mapKeyOpError(w, xkms.ErrNotInitialized)
		return
	}

	resp, err := h.xkmsService.Unseal(r.Context(), &transport.UnsealRequest{
		Backend:    req.Backend,
		KeyID:      req.KeyID,
		Ciphertext: req.Ciphertext,
		Nonce:      req.Nonce,
		Tag:        req.Tag,
		AAD:        req.AAD,
		Metadata:   req.Metadata,
		TPMPublic:  req.TPMPublic,
		TPMPrivate: req.TPMPrivate,
		WrappedDEK: req.WrappedDEK,
		Password:   req.Password,
		TenantID:   callerTenantID(r.Context()),
	})
	if err != nil {
		mapKeyOpError(w, err)
		return
	}

	writeJSON(w, UnsealResponse{Plaintext: resp.Plaintext}, http.StatusOK)
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
