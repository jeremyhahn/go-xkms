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

package xkms

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/metrics"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/validation"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// unwrapSymmetricAlgorithms maps the requested symmetric key size in bits to
// the symmetric algorithm used for a key created by UnwrapKeyByID. A zero size
// selects the AES-256-GCM default.
var unwrapSymmetricAlgorithms = map[int]types.SymmetricAlgorithm{
	0:   types.SymmetricAES256GCM,
	128: types.SymmetricAES128GCM,
	192: types.SymmetricAES192GCM,
	256: types.SymmetricAES256GCM,
}

// =========================================================================
// KeyServicer Implementation
// =========================================================================

// GenerateKey generates a new cryptographic key based on the request parameters.
// It resolves the backend, constructs key attributes from the request, and
// delegates to the appropriate generation method (RSA, ECDSA, Ed25519, or symmetric).
func (s *XKMSService) GenerateKey(ctx context.Context, req *transport.GenerateKeyRequest) (resp *transport.GenerateKeyResponse, err error) {
	start := time.Now()
	backendName := ""
	if req != nil {
		backendName = s.metricsBackendName(req.Backend)
	}
	defer func() { recordServiceOp(metrics.OpGenerate, backendName, start, err) }()

	if req == nil {
		return nil, ErrNilConfig
	}
	if req.KeyID == "" {
		return nil, ErrInvalidKeyID
	}
	if req.Algorithm == "" {
		return nil, ErrMissingAlgorithm
	}

	b, err := s.resolveTenantBackend(backendName, req.TenantID)
	if err != nil {
		return nil, err
	}

	attrs, err := buildKeyAttributes(req, backendName, b.Type())
	if err != nil {
		return nil, err
	}

	var privKey crypto.PrivateKey

	// Symmetric key generation
	if attrs.SymmetricAlgorithm != "" {
		symProvider, ok := b.KeyProvider().(types.SymmetricKeyProvider)
		if !ok {
			return nil, &ErrBackendUnsupported{
				Sentinel: ErrOperationNotSupported,
				Backend:  backendName,
				Detail:   "does not support symmetric key generation",
			}
		}
		_, symErr := symProvider.GenerateSymmetricKey(ctx, attrs)
		if symErr != nil {
			return nil, &ErrOperationWrap{Sentinel: ErrOperationFailed, Err: symErr}
		}
		incrementKeysTotal(backendName)
		return &transport.GenerateKeyResponse{
			KeyID:   req.KeyID,
			KeyType: req.KeyType,
		}, nil
	}

	// Asymmetric key generation
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		privKey, err = b.GenerateRSA(ctx, attrs)
	case x509.ECDSA:
		privKey, err = b.GenerateECDSA(ctx, attrs)
	case x509.Ed25519:
		privKey, err = b.GenerateEd25519(ctx, attrs)
	default:
		return nil, &ErrValidation{Sentinel: ErrUnsupportedKeyAlgorithm, Detail: req.Algorithm}
	}
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrOperationFailed, Err: err}
	}

	pubPEM, err := pubKeyPEM(privKey)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "encode public key", Err: err}
	}

	incrementKeysTotal(backendName)

	return &transport.GenerateKeyResponse{
		KeyID:        req.KeyID,
		KeyType:      req.KeyType,
		PublicKeyPEM: pubPEM,
	}, nil
}

// ListKeys lists all keys in the specified backend, or across all backends
// if the backend name is empty.
//
// The list options are honoured: the response carries the requested page and
// the pagination metadata describing it. They used to be accepted and ignored,
// so every caller that asked for a page received the entire key list with a
// zero-valued PageResponse claiming it was page 0 of 0 -- which for a token
// holding thousands of keys is both the wrong answer and the expensive one.
//
// When no options are given the full list is returned, as before.
func (s *XKMSService) ListKeys(ctx context.Context, backendName string, opts ...transport.ListOption) (resp *transport.ListKeysResponse, err error) {
	start := time.Now()
	metricsBackend := backendName
	if metricsBackend == "" {
		metricsBackend = metricsAllBackends
	}
	defer func() { recordServiceOp(metrics.OpList, metricsBackend, start, err) }()

	s.mu.RLock()
	defer s.mu.RUnlock()

	var allKeys []transport.KeyInfo

	if backendName != "" {
		if err := validation.ValidateBackendName(backendName); err != nil {
			return nil, &ErrBackendNameValidation{Err: err}
		}
		b, ok := s.backends[backendName]
		if !ok {
			return nil, &ErrBackendLookup{Sentinel: ErrBackendNotFound, Name: validation.SanitizeForLog(backendName)}
		}
		keys, err := b.ListKeys(ctx)
		if err != nil {
			return nil, &ErrOperationWrap{Sentinel: ErrOperationFailed, Err: err}
		}
		allKeys = attrsToKeyInfoList(keys, backendName)
	} else {
		// Backends are visited in name order. Ranging the map directly gave a
		// different concatenation on each call, and a page boundary drawn
		// across an order that changes between requests silently skips and
		// repeats keys as the caller walks the pages.
		names := make([]string, 0, len(s.backends))
		for name := range s.backends {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			keys, err := s.backends[name].ListKeys(ctx)
			if err != nil {
				continue
			}
			allKeys = append(allKeys, attrsToKeyInfoList(keys, name)...)
		}
	}

	page, pagination := transport.ApplyPagination(allKeys, transport.BuildPageRequest(opts...))

	return &transport.ListKeysResponse{Keys: page, PageResponse: pagination}, nil
}

// GetKey retrieves key information for a specific key in a backend.
func (s *XKMSService) GetKey(ctx context.Context, backendName, keyID string) (resp *transport.GetKeyResponse, err error) {
	start := time.Now()
	metricsBackend := s.metricsBackendName(backendName)
	defer func() { recordServiceOp(metrics.OpGet, metricsBackend, start, err) }()

	if keyID == "" {
		return nil, ErrInvalidKeyID
	}

	b, resolvedName, err := s.resolveBackendWithName(backendName)
	if err != nil {
		return nil, err
	}

	keyAttrs, err := findKeyAttrs(ctx, b, keyID)
	if err != nil {
		return nil, err
	}

	resp = &transport.GetKeyResponse{
		KeyInfo: transport.KeyInfo{
			KeyID:     keyAttrs.CN,
			Backend:   resolvedName,
			KeyType:   keyAttrs.KeyType.String(),
			Algorithm: algorithmString(keyAttrs),
		},
	}

	// Try to extract and encode the public key
	privKey, keyErr := b.GetKey(ctx, keyAttrs)
	if keyErr == nil {
		if pemStr, pemErr := pubKeyPEM(privKey); pemErr == nil {
			resp.PublicKeyPEM = pemStr
		}
	}

	return resp, nil
}

// DeleteKey deletes a key from the specified backend.
func (s *XKMSService) DeleteKey(ctx context.Context, backendName, keyID string) (err error) {
	start := time.Now()
	metricsBackend := s.metricsBackendName(backendName)
	defer func() { recordServiceOp(metrics.OpDelete, metricsBackend, start, err) }()

	if keyID == "" {
		return ErrInvalidKeyID
	}

	b, resolvedName, err := s.resolveBackendWithName(backendName)
	if err != nil {
		return err
	}

	keyAttrs, err := findKeyAttrs(ctx, b, keyID)
	if err != nil {
		return err
	}

	if err = b.DeleteKey(ctx, keyAttrs); err != nil {
		return err
	}

	decrementKeysTotal(resolvedName)
	return nil
}

// ImportKey imports externally generated key material into a backend using
// the BYOK (Bring Your Own Key) protocol.
func (s *XKMSService) ImportKey(ctx context.Context, req *transport.ImportKeyRequest) (resp *transport.ImportKeyResponse, err error) {
	start := time.Now()
	metricsBackend := ""
	if req != nil {
		metricsBackend = s.metricsBackendName(req.Backend)
	}
	defer func() { recordServiceOp(metrics.OpImport, metricsBackend, start, err) }()

	if req == nil {
		return nil, ErrNilConfig
	}
	if req.KeyID == "" {
		return nil, ErrInvalidKeyID
	}

	backendName := req.Backend
	if backendName == "" {
		backendName = s.defaultBackendName()
	}

	b, err := s.resolveTenantBackend(backendName, req.TenantID)
	if err != nil {
		return nil, err
	}

	importExport, ok := importExportFor(b)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrOperationNotSupported,
			Backend:  backendName,
			Detail:   "does not support import/export operations",
		}
	}

	attrs, err := buildImportKeyAttributes(req, backendName, b.Type())
	if err != nil {
		return nil, err
	}

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  req.WrappedKeyMaterial,
		Algorithm:   backend.WrappingAlgorithm(req.Algorithm),
		ImportToken: req.ImportToken,
		Metadata:    req.Metadata,
	}

	if err = importExport.ImportKey(ctx, attrs, wrapped); err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrOperationFailed, Err: err}
	}

	incrementKeysTotal(backendName)

	return &transport.ImportKeyResponse{
		Success: true,
		KeyID:   req.KeyID,
	}, nil
}

// ExportKey exports a key in wrapped form for secure transport.
func (s *XKMSService) ExportKey(ctx context.Context, req *transport.ExportKeyRequest) (resp *transport.ExportKeyResponse, err error) {
	start := time.Now()
	metricsBackend := ""
	if req != nil {
		metricsBackend = s.metricsBackendName(req.Backend)
	}
	defer func() { recordServiceOp(metrics.OpExport, metricsBackend, start, err) }()

	if req == nil {
		return nil, ErrNilConfig
	}
	if req.KeyID == "" {
		return nil, ErrInvalidKeyID
	}

	backendName := req.Backend
	if backendName == "" {
		backendName = s.defaultBackendName()
	}

	b, err := s.resolveTenantBackend(backendName, req.TenantID)
	if err != nil {
		return nil, err
	}

	importExport, ok := importExportFor(b)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrOperationNotSupported,
			Backend:  backendName,
			Detail:   "does not support import/export operations",
		}
	}

	keyAttrs, err := findKeyAttrs(ctx, b, req.KeyID)
	if err != nil {
		return nil, err
	}

	algorithm := backend.WrappingAlgorithm(req.Algorithm)
	wrapped, err := importExport.ExportKey(ctx, keyAttrs, algorithm)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrOperationFailed, Err: err}
	}

	// The import token names the wrapping key the backend wrapped under, and
	// the metadata describes the blob; both travel with it to ImportKey. A
	// response that dropped them returned material nothing could import.
	return &transport.ExportKeyResponse{
		KeyID:              req.KeyID,
		WrappedKeyMaterial: wrapped.WrappedKey,
		Algorithm:          string(wrapped.Algorithm),
		ImportToken:        wrapped.ImportToken,
		Metadata:           wrapped.Metadata,
	}, nil
}

// RotateKey replaces an existing key with a newly generated key of the same type.
func (s *XKMSService) RotateKey(ctx context.Context, req *transport.RotateKeyRequest) (resp *transport.RotateKeyResponse, err error) {
	start := time.Now()
	metricsBackend := ""
	if req != nil {
		metricsBackend = s.metricsBackendName(req.Backend)
	}
	defer func() { recordServiceOp(metrics.OpRotate, metricsBackend, start, err) }()

	if req == nil {
		return nil, ErrNilConfig
	}
	if req.KeyID == "" {
		return nil, ErrInvalidKeyID
	}

	backendName := req.Backend
	if backendName == "" {
		backendName = s.defaultBackendName()
	}

	b, err := s.resolveTenantBackend(backendName, req.TenantID)
	if err != nil {
		return nil, err
	}

	keyAttrs, err := findKeyAttrs(ctx, b, req.KeyID)
	if err != nil {
		return nil, err
	}

	privKey, err := b.RotateKey(ctx, keyAttrs)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrOperationFailed, Err: err}
	}

	pubPEM, _ := pubKeyPEM(privKey)

	return &transport.RotateKeyResponse{
		Success:      true,
		KeyID:        req.KeyID,
		PublicKeyPEM: pubPEM,
	}, nil
}

// GetImportParameters retrieves the parameters needed to import a key into a backend.
func (s *XKMSService) GetImportParameters(ctx context.Context, req *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	if req == nil {
		return nil, ErrNilConfig
	}

	backendName := req.Backend
	if backendName == "" {
		backendName = s.defaultBackendName()
	}

	b, err := s.resolveTenantBackend(backendName, req.TenantID)
	if err != nil {
		return nil, err
	}

	importExport, ok := importExportFor(b)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrOperationNotSupported,
			Backend:  backendName,
			Detail:   "does not support import/export operations",
		}
	}

	// The request's key template decides which kind of key the ceremony is
	// for, and the backend answers with a matching KeySpec -- "RSA_2048",
	// "AES_256" -- which an AWS-KMS-style import then carries back into
	// WrapKey. Only the common name used to be passed, so every ceremony was
	// negotiated for a key of unknown kind however precisely the caller had
	// described it. The template is optional here because a caller that has
	// not chosen a key kind yet can still ask for a wrapping key.
	attrs := &types.KeyAttributes{
		CN:        req.KeyID,
		Backend:   backendName,
		StoreType: b.Type(),
	}
	if req.KeyType != "" {
		if err := applyKeyTemplate(attrs, "key type", req.KeyType, req.KeySize, req.Curve); err != nil {
			return nil, err
		}
	}

	algorithm := backend.WrappingAlgorithm(req.Algorithm)
	params, err := importExport.GetImportParameters(ctx, attrs, algorithm)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrOperationFailed, Err: err}
	}

	// Marshal the wrapping public key to DER
	wrappingPubKeyBytes, err := x509.MarshalPKIXPublicKey(params.WrappingPublicKey)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "marshal wrapping public key", Err: err}
	}

	resp := &transport.GetImportParametersResponse{
		WrappingPublicKey: wrappingPubKeyBytes,
		ImportToken:       params.ImportToken,
		Algorithm:         string(params.Algorithm),
		KeySpec:           params.KeySpec,
	}

	if params.ExpiresAt != nil {
		resp.ExpiresAt = params.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")
	}

	return resp, nil
}

// CopyKey copies a key from one backend to another using secure key wrapping.
func (s *XKMSService) CopyKey(ctx context.Context, req *transport.CopyKeyRequest) (*transport.CopyKeyResponse, error) {
	if req == nil {
		return nil, ErrNilConfig
	}
	if req.SourceKeyID == "" || req.DestKeyID == "" {
		return nil, ErrInvalidKeyID
	}

	sourceBackend := req.SourceBackend
	if sourceBackend == "" {
		sourceBackend = s.defaultBackendName()
	}
	destBackend := req.DestBackend
	if destBackend == "" {
		destBackend = s.defaultBackendName()
	}

	srcB, err := s.resolveTenantBackend(sourceBackend, req.TenantID)
	if err != nil {
		return nil, &ErrCopyKeyBackend{Role: "source", Err: err}
	}
	dstB, err := s.resolveTenantBackend(destBackend, req.TenantID)
	if err != nil {
		return nil, &ErrCopyKeyBackend{Role: "destination", Err: err}
	}

	srcImportExport, ok := importExportFor(srcB)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrOperationNotSupported,
			Detail:   "source backend does not support export operations",
		}
	}
	dstImportExport, ok := importExportFor(dstB)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrOperationNotSupported,
			Detail:   "destination backend does not support import operations",
		}
	}

	srcAttrs, err := findKeyAttrs(ctx, srcB, req.SourceKeyID)
	if err != nil {
		return nil, &ErrCopyKeyBackend{Role: "source key", Err: err}
	}

	// The destination describes the same key under a new name: the store type
	// is the destination backend's, exactly as an import into it would derive
	// it, and the digest and partition travel with the material so the copy is
	// addressed the way the source was. The tenant is deliberately not set
	// here -- dstB is the caller's tenant-scoped view and its ImportKey stamps
	// it, which is the one place the stamping belongs (go-xkms#222).
	dstAttrs := &types.KeyAttributes{
		CN:                 req.DestKeyID,
		KeyAlgorithm:       srcAttrs.KeyAlgorithm,
		KeyType:            srcAttrs.KeyType,
		Backend:            destBackend,
		StoreType:          dstB.Type(),
		Hash:               srcAttrs.Hash,
		Partition:          srcAttrs.Partition,
		RSAAttributes:      srcAttrs.RSAAttributes,
		ECCAttributes:      srcAttrs.ECCAttributes,
		SymmetricAlgorithm: srcAttrs.SymmetricAlgorithm,
	}

	algorithm := backend.WrappingAlgorithmRSAES_OAEP_SHA_256
	if req.Algorithm != "" {
		algorithm = backend.WrappingAlgorithm(req.Algorithm)
	}

	// The material is wrapped for the DESTINATION's own wrapping key, not one
	// the source mints for itself. dstImportExport.GetImportParameters is the
	// same ceremony step an external BYOK import would call first; the
	// resulting ImportParameters -- and, critically, the ImportToken that
	// names them inside the destination's own state -- come from the
	// destination and only the destination. ExportKeyTo then wraps under
	// those parameters directly, so the token ImportKey receives always names
	// something the destination itself minted. This used to call ExportKey,
	// which wraps under a key the EXPORTING backend mints for itself and
	// names by ITS OWN token -- meaningless to any other backend instance's
	// ImportKey, which looks the token up in its own state and finds nothing
	// (go-xkms#154, go-xkms#222).
	dstParams, err := dstImportExport.GetImportParameters(ctx, dstAttrs, algorithm)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "get destination import parameters", Err: err}
	}

	wrappedKey, err := srcImportExport.ExportKeyTo(ctx, srcAttrs, dstParams)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "export key", Err: err}
	}

	if err := dstImportExport.ImportKey(ctx, dstAttrs, wrappedKey); err != nil {
		return nil, &ErrKeyOperation{Operation: "import key", Err: err}
	}

	return &transport.CopyKeyResponse{
		Success: true,
		KeyID:   req.DestKeyID,
	}, nil
}

// ExportKeyMaterial exports raw symmetric key bytes for extractable keys.
//
// SECURITY WARNING: this returns plaintext key material with no cryptographic
// protection. It only succeeds for symmetric keys created with exportable=true
// on a backend implementing backend.ImportExportBackend; asymmetric keys and
// hardware-resident keys are rejected by the backend. Use ExportKey for secure
// key transport between backends.
func (s *XKMSService) ExportKeyMaterial(ctx context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.KeyID == "" {
		return nil, requiredField("key_id")
	}
	if req.Backend == "" {
		return nil, requiredField("backend")
	}

	b, err := s.resolveTenantBackend(req.Backend, req.TenantID)
	if err != nil {
		return nil, roleLookupError("backend", req.Backend, err)
	}

	importExport, ok := importExportFor(b)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrOperationNotSupported,
			Backend:  req.Backend,
			Detail:   "does not support import/export operations",
		}
	}

	attrs, err := findKeyAttrs(ctx, b, req.KeyID)
	if err != nil {
		return nil, roleLookupError("key", req.KeyID, err)
	}

	// A sensitive key's plaintext is never released, whatever the caller says.
	//
	// This is decided here rather than in each backend because it is an
	// authorization question about the key, not a capability question about the
	// store: every ImportExportBackend can physically produce the bytes, and one
	// that forgot the check would silently become the way around it. The
	// backends keep their own Exportable check as a second line.
	//
	// It matters most for a PKCS#11 caller. That module holds CKA_SENSITIVE in
	// its own object store so it can answer C_GetAttributeValue locally, and
	// that store is client-side state. attrs.Sensitive comes from the backend's
	// record, fixed when the key was created, so clearing the client's copy
	// changes nothing here.
	if attrs.Sensitive {
		return nil, &ErrOperationWrap{
			Sentinel: ErrExportKeyMaterialFailed,
			Err:      ErrKeySensitive,
		}
	}

	keyMaterial, err := importExport.ExportKeyMaterial(ctx, attrs)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrExportKeyMaterialFailed, Err: err}
	}

	// The response's KeyMaterial is caller-owned: a caller seals and wipes it
	// (the PKCS#11 module does), and over the embedded transport that caller
	// is in-process, so handing back the backend's own slice would let the
	// wipe zero the backend's stored key. Copy once here, at the ownership
	// boundary, instead of trusting every backend to return a fresh slice.
	owned := make([]byte, len(keyMaterial))
	copy(owned, keyMaterial)

	// KeySize is documented as bits, and types.SymmetricAlgorithm.KeySize()
	// already returns bits (128/192/256), so it is reported verbatim.
	return &transport.ExportKeyMaterialResponse{
		KeyMaterial: owned,
		KeyType:     string(attrs.SymmetricAlgorithm),
		KeySize:     attrs.SymmetricAlgorithm.KeySize(),
	}, nil
}

// WrapKey wraps key material for secure transport using the specified parameters.
func (s *XKMSService) WrapKey(ctx context.Context, req *transport.WrapKeyRequest) (*transport.WrapKeyResponse, error) {
	if req == nil {
		return nil, ErrNilConfig
	}

	backendName := req.Backend
	if backendName == "" {
		backendName = s.defaultBackendName()
	}

	b, err := s.resolveTenantBackend(backendName, req.TenantID)
	if err != nil {
		return nil, err
	}

	importExport, ok := importExportFor(b)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrOperationNotSupported,
			Backend:  backendName,
			Detail:   "does not support import/export operations",
		}
	}

	// Parse the wrapping public key
	wrappingPubKey, err := x509.ParsePKIXPublicKey(req.WrappingPublicKey)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "parse wrapping public key", Err: err}
	}

	// KeySpec comes back from GetImportParameters and names the kind of key
	// the ceremony is for. A backend whose wrapping is key-spec aware -- AWS
	// KMS most visibly -- needs it to wrap for the right target, so dropping
	// it made this method unusable for those ceremonies and forced the gRPC
	// transport to keep building its own parameters.
	params := &backend.ImportParameters{
		WrappingPublicKey: wrappingPubKey,
		ImportToken:       req.ImportToken,
		Algorithm:         backend.WrappingAlgorithm(req.Algorithm),
		KeySpec:           req.KeySpec,
	}

	wrapped, err := importExport.WrapKey(ctx, req.KeyMaterial, params)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrOperationFailed, Err: err}
	}

	// The backend's import token and metadata travel with the blob to
	// ImportKey, so they are returned rather than discarded.
	return &transport.WrapKeyResponse{
		WrappedKeyMaterial: wrapped.WrappedKey,
		Algorithm:          string(wrapped.Algorithm),
		ImportToken:        wrapped.ImportToken,
		Metadata:           wrapped.Metadata,
	}, nil
}

// UnwrapKey unwraps key material that was previously wrapped.
func (s *XKMSService) UnwrapKey(ctx context.Context, req *transport.UnwrapKeyRequest) (*transport.UnwrapKeyResponse, error) {
	if req == nil {
		return nil, ErrNilConfig
	}

	backendName := req.Backend
	if backendName == "" {
		backendName = s.defaultBackendName()
	}

	b, err := s.resolveTenantBackend(backendName, req.TenantID)
	if err != nil {
		return nil, err
	}

	importExport, ok := importExportFor(b)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrOperationNotSupported,
			Backend:  backendName,
			Detail:   "does not support import/export operations",
		}
	}

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  req.WrappedKeyMaterial,
		Algorithm:   backend.WrappingAlgorithm(req.Algorithm),
		ImportToken: req.ImportToken,
		Metadata:    req.Metadata,
	}

	params := &backend.ImportParameters{
		Algorithm:   backend.WrappingAlgorithm(req.Algorithm),
		ImportToken: req.ImportToken,
		KeySpec:     req.KeySpec,
	}

	// A backend holding more than one wrapping key pair selects the matching
	// private key from the public key the material was wrapped under, so the
	// request may name it. It is optional: backends that key their ceremony
	// entirely off the import token do not need it.
	if len(req.WrappingPublicKey) > 0 {
		wrappingPubKey, parseErr := x509.ParsePKIXPublicKey(req.WrappingPublicKey)
		if parseErr != nil {
			return nil, &ErrKeyOperation{Operation: "parse wrapping public key", Err: parseErr}
		}
		params.WrappingPublicKey = wrappingPubKey
	}

	keyMaterial, err := importExport.UnwrapKey(ctx, wrapped, params)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrOperationFailed, Err: err}
	}

	return &transport.UnwrapKeyResponse{
		KeyMaterial: keyMaterial,
	}, nil
}

// WrapKeyByID wraps a server-side target key with a server-side wrapping key,
// both identified by key ID and backend. This is the service-layer primitive
// behind PKCS#11 C_WrapKey.
//
// The target is named either by req.TargetKeyID -- a backend-resident key,
// which must be extractable and whose raw material is exported here -- or by
// req.TargetKeyMaterial, plaintext the caller already holds. See
// wrapTargetKeyMaterial for why both forms exist and why they must converge
// here rather than in the caller. Either way the material is encrypted
// directly under the wrapping key named by req.WrappingKeyID via
// wrapKeyMaterial (servicer_wrapkey.go), so both produce the same framing and
// UnwrapKeyByID reverses both. This is deliberately independent of
// backend.ImportExportBackend.GetImportParameters/WrapKey, which serve a
// different feature (the key-IMPORT ceremony: bringing externally generated
// material into a backend) and always wrap under a freshly generated
// ephemeral key pair -- never the caller's own designated wrapping key, and
// never a symmetric one, since that ceremony's ImportParameters models only
// an RSA wrapping public key. Only the target backend needs
// backend.ImportExportBackend now, for ExportKeyMaterial.
func (s *XKMSService) WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.WrappingKeyID == "" {
		return nil, requiredField("wrapping_key_id")
	}
	if req.WrappingKeyBackend == "" {
		return nil, requiredField("wrapping_key_backend")
	}
	if req.Algorithm == "" {
		return nil, requiredField("algorithm")
	}

	keyMaterial, err := s.wrapTargetKeyMaterial(ctx, req)
	if err != nil {
		return nil, err
	}
	// The plaintext of the key being wrapped is the most sensitive value this
	// call touches, and every path below it can fail. Deferring the wipe is
	// what covers the failure paths too.
	defer secure.Wipe(keyMaterial)

	wrappingBackend, err := s.resolveTenantBackend(req.WrappingKeyBackend, req.TenantID)
	if err != nil {
		return nil, roleLookupError("wrapping key backend", req.WrappingKeyBackend, err)
	}

	wrappingAttrs, err := findKeyAttrs(ctx, wrappingBackend, req.WrappingKeyID)
	if err != nil {
		return nil, roleLookupError("wrapping key", req.WrappingKeyID, err)
	}

	wrapped, err := wrapKeyMaterial(ctx, wrappingBackend, wrappingAttrs, req.Algorithm, wrapParams{
		iv:        req.IV,
		aad:       req.AAD,
		tagBits:   req.TagBits,
		oaepLabel: req.OAEPLabel,
	}, keyMaterial)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "wrap key", KeyID: req.TargetKeyID, Err: err}
	}

	return &transport.WrapKeyByIDResponse{
		WrappedKey: wrapped,
		Algorithm:  req.Algorithm,
	}, nil
}

// wrapTargetKeyMaterial resolves the plaintext a WrapKeyByID request names.
//
// A request identifies its target one of two ways, and exactly one must be
// used. TargetKeyID names a key resident in a backend, whose material is
// exported here; TargetKeyMaterial carries the plaintext directly, for a
// PKCS#11 C_WrapKey whose target was imported with C_CreateObject and CKA_VALUE
// and so exists only in the caller's own object store.
//
// The second form exists so both cases run through the one wrap implementation
// in servicer_wrapkey.go. A caller that encrypted such a key itself produced a
// blob framed differently from the one UnwrapKeyByID parses -- no nonce prefix
// for AES-GCM, no IV prefix for AES-CBC, and no possible blob at all for
// AES-KW, which is not an encryption mechanism -- so the wrap succeeded and the
// key was unrecoverable. It grants no capability the API lacked: a caller with
// plaintext and a wrapping key could already reach the same ciphertext through
// Encrypt.
//
// Whichever form the request took, the returned slice belongs to the caller
// and must be wiped once the wrap is done: the request-carried plaintext is
// copied rather than aliased, so that wiping it cannot reach back into a
// request the caller still holds.
func (s *XKMSService) wrapTargetKeyMaterial(ctx context.Context, req *transport.WrapKeyByIDRequest) ([]byte, error) {
	if req.TargetKeyID != "" && len(req.TargetKeyMaterial) > 0 {
		return nil, &ErrValidation{
			Sentinel: ErrInvalidKeyAttributes,
			Detail:   "target_key_id and target_key_material are mutually exclusive",
		}
	}

	if len(req.TargetKeyMaterial) > 0 {
		owned := make([]byte, len(req.TargetKeyMaterial))
		copy(owned, req.TargetKeyMaterial)
		return owned, nil
	}

	if req.TargetKeyID == "" {
		return nil, requiredField("target_key_id")
	}
	if req.TargetKeyBackend == "" {
		return nil, requiredField("target_key_backend")
	}

	targetBackend, err := s.resolveTenantBackend(req.TargetKeyBackend, req.TenantID)
	if err != nil {
		return nil, roleLookupError("target key backend", req.TargetKeyBackend, err)
	}

	targetImportExport, ok := importExportFor(targetBackend)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrOperationNotSupported,
			Backend:  req.TargetKeyBackend,
			Detail:   "target key backend does not support import/export operations",
		}
	}

	targetAttrs, err := findKeyAttrs(ctx, targetBackend, req.TargetKeyID)
	if err != nil {
		return nil, roleLookupError("target key", req.TargetKeyID, err)
	}

	// Only symmetric keys created with Exportable=true can be released here.
	keyMaterial, err := targetImportExport.ExportKeyMaterial(ctx, targetAttrs)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrExportKeyMaterialFailed, Detail: "target key", Err: err}
	}
	return keyMaterial, nil
}

// UnwrapKeyByID unwraps key material with a server-side unwrapping key and
// imports the result as a new key. This is the service-layer primitive behind
// PKCS#11 C_UnwrapKey.
//
// The unwrapping key named by req.UnwrappingKeyID is used directly via
// unwrapKeyMaterial (servicer_wrapkey.go) -- never a freshly generated
// ephemeral key, and never routed through
// backend.ImportExportBackend.GetImportParameters/UnwrapKey, the unrelated
// key-IMPORT ceremony (see the WrapKeyByID doc comment for why the two must
// not be conflated). The recovered plaintext material is then imported into
// the target backend using the key template carried in the request, exactly
// as before.
func (s *XKMSService) UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if len(req.WrappedKey) == 0 {
		return nil, requiredField("wrapped_key")
	}
	if req.UnwrappingKeyID == "" {
		return nil, requiredField("unwrapping_key_id")
	}
	if req.UnwrappingKeyBackend == "" {
		return nil, requiredField("unwrapping_key_backend")
	}
	if req.Algorithm == "" {
		return nil, requiredField("algorithm")
	}
	if req.TargetKeyID == "" {
		return nil, requiredField("target_key_id")
	}
	if req.TargetKeyBackend == "" {
		return nil, requiredField("target_key_backend")
	}

	unwrappingBackend, err := s.resolveTenantBackend(req.UnwrappingKeyBackend, req.TenantID)
	if err != nil {
		return nil, roleLookupError("unwrapping key backend", req.UnwrappingKeyBackend, err)
	}

	// Confirm the destination can accept an import before looking up keys or
	// decrypting. Import capability is a property of the backend, not of any
	// particular key, so a request that could never succeed is refused with
	// that specific reason rather than with whichever key lookup or
	// decryption happened to fail first. The unwrapping backend is still
	// resolved first, above: it is the subject of the operation, so its
	// errors take precedence.
	targetBackend, err := s.resolveTenantBackend(req.TargetKeyBackend, req.TenantID)
	if err != nil {
		return nil, roleLookupError("target key backend", req.TargetKeyBackend, err)
	}

	targetImportExport, ok := importExportFor(targetBackend)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrOperationNotSupported,
			Backend:  req.TargetKeyBackend,
			Detail:   "target key backend does not support import/export operations",
		}
	}

	unwrappingAttrs, err := findKeyAttrs(ctx, unwrappingBackend, req.UnwrappingKeyID)
	if err != nil {
		return nil, roleLookupError("unwrapping key", req.UnwrappingKeyID, err)
	}

	keyMaterial, err := unwrapKeyMaterial(ctx, unwrappingBackend, unwrappingAttrs, req.Algorithm, wrapParams{
		iv:        req.IV,
		aad:       req.AAD,
		tagBits:   req.TagBits,
		oaepLabel: req.OAEPLabel,
	}, req.WrappedKey)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "unwrap key", KeyID: req.TargetKeyID, Err: err}
	}
	// The recovered plaintext outlives nothing beyond the import below, so it
	// is wiped on the way out rather than left for the garbage collector.
	defer secure.Wipe(keyMaterial)

	targetAttrs, err := unwrapTargetAttributes(req, len(keyMaterial), targetBackend.Type())
	if err != nil {
		return nil, err
	}

	// The recovered material is re-wrapped under the target backend's own
	// import key and fed through its normal import ceremony, rather than
	// handed over in the clear.
	//
	// ImportKey's contract is that the material arrives wrapped with parameters
	// from GetImportParameters, and every backend enforces it. That is not an
	// obstacle to route around: for a TPM, an HSM or a cloud KMS the ceremony
	// is the whole reason plaintext key material never crosses the boundary.
	// Re-wrapping keeps C_UnwrapKey working the same way on all of them.
	if err := importKeyMaterial(ctx, targetImportExport, targetAttrs, keyMaterial); err != nil {
		return nil, &ErrKeyOperation{Operation: "import unwrapped key", KeyID: req.TargetKeyID, Err: err}
	}

	return &transport.UnwrapKeyByIDResponse{
		KeyID:   req.TargetKeyID,
		Backend: req.TargetKeyBackend,
		Success: true,
		Message: "key " + req.TargetKeyID + " successfully unwrapped and imported into backend " + req.TargetKeyBackend,
	}, nil
}

// importKeyMaterial stores recovered key material in a backend by running it
// through that backend's own import ceremony.
//
// The material is wrapped under a public key the backend generates for this
// purpose and only the backend can unwrap, so it is never handed over in the
// clear. RSA-OAEP with SHA-256 is the wrapping algorithm: SHA-1 is refused
// project-wide, and the hybrid RSA+AES variants exist for material too large
// for a single RSA block, which a key being unwrapped here is not.
func importKeyMaterial(ctx context.Context, target ImportExporter, attrs *types.KeyAttributes, material []byte) error {
	const algorithm = backend.WrappingAlgorithmRSAES_OAEP_SHA_256

	params, err := target.GetImportParameters(ctx, attrs, algorithm)
	if err != nil {
		return &ErrKeyOperation{Operation: "obtain import parameters", KeyID: attrs.CN, Err: err}
	}

	wrapped, err := target.WrapKey(ctx, material, params)
	if err != nil {
		return &ErrKeyOperation{Operation: "wrap key material for import", KeyID: attrs.CN, Err: err}
	}

	return target.ImportKey(ctx, attrs, wrapped)
}

// unwrapTargetAttributes builds the key attributes for the key an
// UnwrapKeyByID request creates, from the request's key template.
//
// storeType is the resolved target backend's own Type(), not
// types.StoreType(req.TargetKeyBackend): the target key backend is a
// registry name, and casting it straight to StoreType named the wrong thing
// for any backend registered under a name that is not itself a store-type
// keyword (go-xkms#312) -- unlike the ParseStoreType(name) sites elsewhere in
// this file, this one did not even normalise case or reject an unknown
// keyword first.
func unwrapTargetAttributes(req *transport.UnwrapKeyByIDRequest, materialLen int, storeType types.StoreType) (*types.KeyAttributes, error) {
	attrs := &types.KeyAttributes{
		CN:         req.TargetKeyID,
		Backend:    req.TargetKeyBackend,
		StoreType:  storeType,
		Partition:  types.Partition(req.TargetPartition),
		Exportable: req.TargetExportable,
	}

	keyType := req.TargetKeyType
	if keyType == "" {
		if req.TargetKeySize <= 0 {
			return nil, requiredField("target_key_type")
		}
		// A bare key size is only meaningful for symmetric material.
		keyType = string(types.AlgorithmSymmetric)
	}

	keySize := req.TargetKeySize
	if keySize == 0 && isSymmetricKeyTypeName(keyType) {
		// PKCS#11 v3.2 §5.18.6 does not require the unwrap template to carry
		// CKA_VALUE_LEN: the recovered material's own length settles the key
		// size, and a caller unwrapping a key it did not create has no reason
		// to know that length in advance. Demanding it made C_UnwrapKey fail
		// for every template that legitimately omitted it.
		keySize = materialLen * 8
	}

	if err := applyKeyTemplate(attrs, "target key type", keyType, keySize, req.TargetCurve); err != nil {
		return nil, err
	}

	return attrs, nil
}

// =========================================================================
// Internal helpers (unique to servicer_key.go)
// =========================================================================

// errAlgorithmNotAsymmetric reports that a name does not name one of the
// asymmetric algorithms this service creates.
//
// It never reaches a caller of the service: applyAsymmetricAlgorithm's own
// callers translate it into the validation sentinel their vocabulary uses,
// because the same condition is an unsupported ALGORITHM to GenerateKey and an
// unsupported KEY TYPE to the import ceremony, and the transports map those two
// sentinels to different wire errors.
var errAlgorithmNotAsymmetric = errors.New("keystore: not an asymmetric algorithm")

// applyAsymmetricAlgorithm sets the algorithm-bearing attributes named by an
// algorithm string, a key size in bits and a curve name.
//
// The names come from types.ParseKeyAlgorithmString, so "rsa", "ecdsa" (also
// "ec" and "ecc") and "ed25519" all resolve and the service speaks one
// algorithm vocabulary. A zero key size selects RSA-2048 and an empty curve
// selects P-256, the documented defaults for an unspecified parameter.
//
// A curve that is present but unsupported is an error rather than a
// substitution. GenerateKey used to answer an unparseable curve with a P-256
// key and report success, so a caller that asked for P-384 and got a P-256 key
// had no way to tell -- a dropped parameter is not a default.
//
// Any other algorithm name returns errAlgorithmNotAsymmetric. The attributes
// are left untouched whenever an error is returned.
func applyAsymmetricAlgorithm(attrs *types.KeyAttributes, algorithm string, keySize int, curve string) error {
	switch types.ParseKeyAlgorithmString(algorithm) {
	case types.AlgorithmRSA:
		if keySize == 0 {
			keySize = types.RSAKeySize2048
		}
		attrs.KeyAlgorithm = x509.RSA
		attrs.RSAAttributes = &types.RSAAttributes{KeySize: keySize}
		return nil

	case types.AlgorithmECDSA:
		if curve == "" {
			curve = string(types.CurveP256)
		}
		parsed := parseCurveString(curve)
		if parsed == nil {
			return &ErrValidation{Sentinel: ErrInvalidCurve, Detail: "invalid curve: " + curve}
		}
		attrs.KeyAlgorithm = x509.ECDSA
		attrs.ECCAttributes = &types.ECCAttributes{Curve: parsed}
		return nil

	case types.AlgorithmEd25519:
		attrs.KeyAlgorithm = x509.Ed25519
		return nil

	default:
		return errAlgorithmNotAsymmetric
	}
}

// isSymmetricKeyTypeName reports whether a key-type string names symmetric
// material.
func isSymmetricKeyTypeName(keyType string) bool {
	return types.AlgorithmSymmetric.Equals(keyType) || types.AlgorithmAES.Equals(keyType)
}

// applyKeyTemplate sets the algorithm-bearing attributes for the key an import
// ceremony creates. ImportKey, GetImportParameters and UnwrapKeyByID all name
// their key the same way -- a key-type string plus an optional size and curve --
// so all three resolve it here and cannot drift apart.
//
// The key-type string names the ALGORITHM in these requests ("rsa", "ecdsa",
// "ed25519", "symmetric"/"aes"), not the key's purpose: the wire carries one
// field for it, and the purpose follows from it (KeyTypeSecret for symmetric
// material, KeyTypeSigning for asymmetric). A name that resolves to neither is
// rejected.
//
// The asymmetric case used to fall through to types.ParseCLIKeyType instead,
// which assigns a purpose and no algorithm at all. types.KeyAttributes.ID()
// then ended in "unknown", storing the key under an identifier nothing else
// constructs: an Ed25519 import succeeded and was reported as RSA by ListKeys
// from that point on, and every later operation missed it. An RSA import failed
// outright, its attributes claiming no algorithm at all.
//
// field is how the caller's own request spells this parameter ("key type",
// "target key type"), so the refusal names the field the caller sent rather
// than a name only this function uses.
func applyKeyTemplate(attrs *types.KeyAttributes, field, keyType string, keySize int, curve string) error {
	if isSymmetricKeyTypeName(keyType) {
		symmetric, ok := unwrapSymmetricAlgorithms[keySize]
		if !ok {
			return &ErrValidation{
				Sentinel: ErrInvalidKeyAttributes,
				Detail:   fmt.Sprintf("invalid key size for symmetric key: %d (must be 128, 192, or 256)", keySize),
			}
		}
		attrs.KeyType = types.KeyTypeSecret
		attrs.SymmetricAlgorithm = symmetric
		return nil
	}

	if err := applyAsymmetricAlgorithm(attrs, keyType, keySize, curve); err != nil {
		if errors.Is(err, errAlgorithmNotAsymmetric) {
			return &ErrValidation{Sentinel: ErrInvalidKeyType, Detail: "unsupported " + field + ": " + keyType}
		}
		return err
	}
	attrs.KeyType = types.KeyTypeSigning
	return nil
}

// resolveKeyHash resolves the digest a request designates for the key it
// creates.
//
// It is ResolveHash with the "NONE" sentinel refused. NONE means "the caller
// has already produced the exact bytes to sign", which is a property of one
// operation and says nothing about a key; recording it would leave
// types.KeyAttributes.Hash at crypto.Hash(0), whose New method panics wherever
// the attribute is later used. An empty name selects the SHA-256 default,
// matching ResolveHash and the transports that already set this attribute.
func resolveKeyHash(hash string) (crypto.Hash, error) {
	h, err := ResolveHash(hash)
	if err != nil {
		return 0, err
	}
	if h == 0 {
		return 0, &ErrValidation{
			Sentinel: ErrInvalidHashFunction,
			Detail:   `hash "NONE" names no digest and cannot be a key attribute`,
		}
	}
	return h, nil
}

// guardKeyID refuses a key ID that the storage identifier cannot round trip.
//
// It sits here, where the caller's key ID first becomes a CN and therefore an
// identifier segment, because that is a boundary EVERY method crosses. The
// transport validators cover the transports that call them — REST does; MCP's
// handleGenerateKey checks only that key_id is non-empty — so a guard in each
// handler leaves the next handler to be discovered the same way (#169). The
// per-handler refusal added for MCP import in #63 was deliberately narrow and
// this is what generalises it.
//
// KeyAttributes.ID() joins its fields with ':' and parseStorageKeyID
// disambiguates by segment count, so a separator inside the CN shifts every
// field after it: "a:b" is stored as "software:tls:a:b:rsa" and read back with
// CN == "b". The operation reports success, list_keys shows a key the caller
// did not ask for, and get_key and sign cannot reach it under the name it was
// created with.
func guardKeyID(keyID string) error {
	if err := validation.ValidateKeyID(keyID); err != nil {
		return &ErrKeyIDValidation{Err: err}
	}
	return nil
}

// buildKeyAttributes constructs a types.KeyAttributes from a GenerateKeyRequest.
//
// The key's purpose is read with types.ParseKeyType, the vocabulary the
// transports already use for the same field. It used to be read with
// types.ParseCLIKeyType, which knows six of the thirteen names: a request for a
// "ca", "attestation", "idevid" or "storage" key silently became a signing key
// here while the same string became the named purpose in every transport that
// built its own attributes. The purpose is part of types.KeyAttributes.ID(), so
// the two paths stored the same request's key in two different places.
//
// storeType is the resolved backend's own Type(), not derived from
// backendName here: a backend registered under a non-keyword name (e.g.
// "token-a") is a legal registration, and StoreType must still name its real
// kind rather than the ParseStoreType(backendName) "unknown" that used to
// reach ID() for one (go-xkms#312).
func buildKeyAttributes(req *transport.GenerateKeyRequest, backendName string, storeType types.StoreType) (*types.KeyAttributes, error) {
	if err := guardKeyID(req.KeyID); err != nil {
		return nil, err
	}

	attrs := &types.KeyAttributes{
		CN:        req.KeyID,
		Backend:   backendName,
		StoreType: storeType,
		Partition: types.Partition(req.Partition),
	}

	// The request's hash was accepted and then discarded, so a caller that
	// asked for an SHA-384 key received one whose attributes named no digest
	// at all.
	hash, err := resolveKeyHash(req.Hash)
	if err != nil {
		return nil, err
	}
	attrs.Hash = hash

	attrs.KeyType = types.ParseKeyType(req.KeyType)
	// Default to signing key type if not specified or not a purpose name.
	if attrs.KeyType == 0 {
		attrs.KeyType = types.KeyTypeSigning
	}

	// Algorithm is required (enforced by GenerateKey before this is called);
	// KeyType is a purpose, never a fallback algorithm name.
	algorithm := req.Algorithm

	// Exportability is set before the symmetric branch returns, not after the
	// asymmetric parsing. It used to be assigned only at the end of this
	// function, which the symmetric early return skipped, so every symmetric
	// key generated through this API was stored non-exportable no matter what
	// the request asked for.
	//
	// The request is the authority. PKCS#11 v3.2 Table 30 makes a secret key
	// CKA_EXTRACTABLE by default, so the PKCS#11 module sends Exportable=true
	// unless the application's template says CK_FALSE; dropping the field made
	// C_GetAttributeValue(CKA_VALUE) fail on a key whose own attributes said it
	// was readable.
	attrs.Exportable = req.Exportable

	// Sensitivity is recorded alongside exportability and for the same reason:
	// it has to be assigned before the symmetric branch returns, because that
	// branch is the one that matters. CKA_SENSITIVE only ever withholds the
	// plaintext of a secret key, and secret keys leave this function early.
	attrs.Sensitive = req.Sensitive

	// Check for symmetric algorithms first
	if symAlgo := ParseSymmetricAlgorithm(algorithm); symAlgo != "" {
		attrs.SymmetricAlgorithm = symAlgo
		attrs.KeyType = types.KeyTypeSecret
		return attrs, nil
	}

	if err := applyAsymmetricAlgorithm(attrs, algorithm, req.KeySize, req.Curve); err != nil {
		if errors.Is(err, errAlgorithmNotAsymmetric) {
			return nil, &ErrValidation{Sentinel: ErrUnsupportedKeyAlgorithm, Detail: algorithm}
		}
		return nil, err
	}

	return attrs, nil
}

// buildImportKeyAttributes constructs key attributes from an ImportKeyRequest.
//
// req.KeyType names the algorithm, and applyKeyTemplate resolves it, so an
// import describes its key exactly as UnwrapKeyByID and GetImportParameters
// describe theirs. Only the symmetric case used to be handled here; an
// asymmetric request produced attributes carrying a purpose and no algorithm,
// which either failed the backend's key-type check (RSA) or stored the key
// under an identifier no other code path constructs (ECDSA, Ed25519). See
// applyKeyTemplate for what that cost.
//
// A symmetric request cannot be answered by the generic key-type mapping
// because types.KeyAttributes.IsSymmetric is defined as SymmetricAlgorithm !=
// "" and every backend's ImportKey dispatches on it. Without the symmetric
// branch, an AES import reached the asymmetric path and its raw key bytes were
// handed to x509.ParsePKCS8PrivateKey, so ImportKey could not import a secret
// key at all -- through any transport, for any caller.
//
// The size is taken from KeySize with AESKeySize as the fallback. Both name the
// same quantity, but only KeySize survives every transport -- the gRPC
// ImportKeyRequest message has key_size and no aes_key_size field -- so reading
// AESKeySize first would make the same call behave differently over gRPC than
// over the unix socket. A zero size selects the AES-256 default, exactly as it
// does for UnwrapKeyByID, which shares the unwrapSymmetricAlgorithms table.
//
// Exportability is set here for symmetric material rather than taken from the
// request because ImportKeyRequest carries no field for it. PKCS#11 v3.2 §4.9
// Table 30 makes a secret key CKA_EXTRACTABLE by default, and an imported key
// that the backend will not release afterwards cannot be read back with
// C_GetAttributeValue(CKA_VALUE) or wrapped as a C_WrapKey target. Callers that
// must keep a key unextractable do not import it: the PKCS#11 module refuses to
// send CKA_EXTRACTABLE=CK_FALSE material here and keeps such a key local
// instead (see Module.CreateObject), so this default never widens a protection
// an application actually asked for. Asymmetric private keys stay
// non-exportable, which is what every backend's ExportKeyMaterial requires of
// them anyway.
//
// storeType is the resolved backend's own Type(), for the same reason
// buildKeyAttributes takes it rather than deriving it from backendName
// (go-xkms#312).
func buildImportKeyAttributes(req *transport.ImportKeyRequest, backendName string, storeType types.StoreType) (*types.KeyAttributes, error) {
	if req.KeyType == "" {
		// There is no honest default. The algorithm cannot be recovered from
		// the wrapped material at this layer, and guessing one stores the key
		// under an identifier that does not describe it.
		return nil, requiredField("key_type")
	}

	if err := guardKeyID(req.KeyID); err != nil {
		return nil, err
	}

	attrs := &types.KeyAttributes{
		CN:        req.KeyID,
		Backend:   backendName,
		StoreType: storeType,
		Partition: types.Partition(req.Partition),
	}

	hash, err := resolveKeyHash(req.Hash)
	if err != nil {
		return nil, err
	}
	attrs.Hash = hash

	keySize := req.KeySize
	if keySize == 0 && isSymmetricKeyTypeName(req.KeyType) {
		keySize = req.AESKeySize
	}

	if err := applyKeyTemplate(attrs, "key type", req.KeyType, keySize, req.Curve); err != nil {
		return nil, err
	}

	ApplyImportExportability(attrs, req.Exportable, req.Sensitive)

	return attrs, nil
}

// ApplyImportExportability records an import request's exportability choice
// on the key attributes the backend will store. The symmetric metadata record
// is write-once for Exportable, so the choice made here is the key's for its
// whole lifetime.
//
// An unset choice (nil) keeps the default every import path applied before
// the request could express one: true for symmetric material, because
// PKCS#11 v3.2 Table 30 makes a secret key CKA_EXTRACTABLE by default and a
// symmetric key the backend will not release can neither be read back nor
// wrapped; false for asymmetric material, as GenerateKeyRequest's zero value
// is. An explicit choice wins for either kind of material. Sensitive is
// carried as given; it is independent of Exportable, as it is on generate.
//
// The gRPC service and the REST handler build their import attributes
// themselves and call this so the three paths cannot drift on the one flag
// that cannot be corrected after the fact.
func ApplyImportExportability(attrs *types.KeyAttributes, exportable *bool, sensitive bool) {
	if exportable != nil {
		attrs.Exportable = *exportable
	} else {
		attrs.Exportable = attrs.IsSymmetric()
	}
	attrs.Sensitive = sensitive
}

// parseCurveString converts a curve name string to an elliptic.Curve, or nil
// when the name is not one of the supported NIST curves. It delegates to
// types.ParseCurve so the project has one curve-name table.
func parseCurveString(curve string) elliptic.Curve {
	parsed, err := types.ParseCurve(curve)
	if err != nil {
		return nil
	}
	return parsed
}

// ParseSymmetricAlgorithm attempts to parse an algorithm string as a symmetric algorithm.
// Returns empty string if the algorithm is not a recognized symmetric algorithm.
//
// It is exported because the gRPC and QUIC transports each carried a private
// copy of this mapping, which is how the same algorithm name could resolve
// differently depending on which socket the request arrived on.
func ParseSymmetricAlgorithm(algo string) types.SymmetricAlgorithm {
	lower := strings.ToLower(algo)
	switch {
	case strings.Contains(lower, "aes") || strings.Contains(lower, "chacha"):
		parsed := types.ParseAEADAlgorithm(algo)
		if parsed != "" {
			return parsed.ToSymmetricAlgorithm()
		}
	case lower == "symmetric" || lower == "secret":
		return types.SymmetricAES256GCM
	}
	return ""
}

// attrsToKeyInfoList converts a slice of KeyAttributes to transport.KeyInfo slice.
func attrsToKeyInfoList(attrs []*types.KeyAttributes, backendName string) []transport.KeyInfo {
	keys := make([]transport.KeyInfo, 0, len(attrs))
	for _, attr := range attrs {
		keys = append(keys, transport.KeyInfo{
			KeyID:     attr.CN,
			Backend:   backendName,
			KeyType:   attr.KeyType.String(),
			Algorithm: algorithmString(attr),
		})
	}
	return keys
}
