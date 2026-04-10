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
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/validation"
)

// =========================================================================
// KeyServicer Implementation
// =========================================================================

// GenerateKey generates a new cryptographic key based on the request parameters.
// It resolves the backend, constructs key attributes from the request, and
// delegates to the appropriate generation method (RSA, ECDSA, Ed25519, or symmetric).
func (s *XKMSService) GenerateKey(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
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

	b, err := s.resolveBackend(backendName)
	if err != nil {
		return nil, err
	}

	attrs, err := buildKeyAttributes(req, backendName)
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
		_, symErr := symProvider.GenerateSymmetricKey(attrs)
		if symErr != nil {
			return nil, &ErrOperationWrap{Sentinel: ErrOperationFailed, Err: symErr}
		}
		return &transport.GenerateKeyResponse{
			KeyID:   req.KeyID,
			KeyType: req.KeyType,
		}, nil
	}

	// Asymmetric key generation
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		privKey, err = b.GenerateRSA(attrs)
	case x509.ECDSA:
		privKey, err = b.GenerateECDSA(attrs)
	case x509.Ed25519:
		privKey, err = b.GenerateEd25519(attrs)
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

	return &transport.GenerateKeyResponse{
		KeyID:        req.KeyID,
		KeyType:      req.KeyType,
		PublicKeyPEM: pubPEM,
	}, nil
}

// ListKeys lists all keys in the specified backend, or across all backends
// if the backend name is empty.
func (s *XKMSService) ListKeys(ctx context.Context, backendName string, opts ...transport.ListOption) (*transport.ListKeysResponse, error) {
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
		keys, err := b.ListKeys()
		if err != nil {
			return nil, &ErrOperationWrap{Sentinel: ErrOperationFailed, Err: err}
		}
		allKeys = attrsToKeyInfoList(keys, backendName)
	} else {
		for name, b := range s.backends {
			keys, err := b.ListKeys()
			if err != nil {
				continue
			}
			allKeys = append(allKeys, attrsToKeyInfoList(keys, name)...)
		}
	}

	return &transport.ListKeysResponse{Keys: allKeys}, nil
}

// GetKey retrieves key information for a specific key in a backend.
func (s *XKMSService) GetKey(ctx context.Context, backendName, keyID string) (*transport.GetKeyResponse, error) {
	if keyID == "" {
		return nil, ErrInvalidKeyID
	}

	b, resolvedName, err := s.resolveBackendWithName(backendName)
	if err != nil {
		return nil, err
	}

	keyAttrs, err := findKeyAttrs(b, keyID)
	if err != nil {
		return nil, err
	}

	resp := &transport.GetKeyResponse{
		KeyInfo: transport.KeyInfo{
			KeyID:     keyAttrs.CN,
			Backend:   resolvedName,
			KeyType:   keyAttrs.KeyType.String(),
			Algorithm: algorithmString(keyAttrs),
		},
	}

	// Try to extract and encode the public key
	privKey, keyErr := b.GetKey(keyAttrs)
	if keyErr == nil {
		if pemStr, pemErr := pubKeyPEM(privKey); pemErr == nil {
			resp.PublicKeyPEM = pemStr
		}
	}

	return resp, nil
}

// DeleteKey deletes a key from the specified backend.
func (s *XKMSService) DeleteKey(ctx context.Context, backendName, keyID string) error {
	if keyID == "" {
		return ErrInvalidKeyID
	}

	b, _, err := s.resolveBackendWithName(backendName)
	if err != nil {
		return err
	}

	keyAttrs, err := findKeyAttrs(b, keyID)
	if err != nil {
		return err
	}

	return b.DeleteKey(keyAttrs)
}

// ImportKey imports externally generated key material into a backend using
// the BYOK (Bring Your Own Key) protocol.
func (s *XKMSService) ImportKey(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
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

	b, err := s.resolveBackend(backendName)
	if err != nil {
		return nil, err
	}

	importExport, ok := b.KeyProvider().(backend.ImportExportBackend)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrOperationNotSupported,
			Backend:  backendName,
			Detail:   "does not support import/export operations",
		}
	}

	attrs := buildImportKeyAttributes(req, backendName)

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  req.WrappedKeyMaterial,
		Algorithm:   backend.WrappingAlgorithm(req.Algorithm),
		ImportToken: req.ImportToken,
	}

	if err := importExport.ImportKey(attrs, wrapped); err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrOperationFailed, Err: err}
	}

	return &transport.ImportKeyResponse{
		Success: true,
		KeyID:   req.KeyID,
	}, nil
}

// ExportKey exports a key in wrapped form for secure transport.
func (s *XKMSService) ExportKey(ctx context.Context, req *transport.ExportKeyRequest) (*transport.ExportKeyResponse, error) {
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

	b, err := s.resolveBackend(backendName)
	if err != nil {
		return nil, err
	}

	importExport, ok := b.KeyProvider().(backend.ImportExportBackend)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrOperationNotSupported,
			Backend:  backendName,
			Detail:   "does not support import/export operations",
		}
	}

	keyAttrs, err := findKeyAttrs(b, req.KeyID)
	if err != nil {
		return nil, err
	}

	algorithm := backend.WrappingAlgorithm(req.Algorithm)
	wrapped, err := importExport.ExportKey(keyAttrs, algorithm)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrOperationFailed, Err: err}
	}

	return &transport.ExportKeyResponse{
		KeyID:              req.KeyID,
		WrappedKeyMaterial: wrapped.WrappedKey,
		Algorithm:          string(wrapped.Algorithm),
	}, nil
}

// RotateKey replaces an existing key with a newly generated key of the same type.
func (s *XKMSService) RotateKey(ctx context.Context, req *transport.RotateKeyRequest) (*transport.RotateKeyResponse, error) {
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

	b, err := s.resolveBackend(backendName)
	if err != nil {
		return nil, err
	}

	keyAttrs, err := findKeyAttrs(b, req.KeyID)
	if err != nil {
		return nil, err
	}

	privKey, err := b.RotateKey(keyAttrs)
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

	b, err := s.resolveBackend(backendName)
	if err != nil {
		return nil, err
	}

	importExport, ok := b.KeyProvider().(backend.ImportExportBackend)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrOperationNotSupported,
			Backend:  backendName,
			Detail:   "does not support import/export operations",
		}
	}

	attrs := &types.KeyAttributes{
		CN: req.KeyID,
	}

	algorithm := backend.WrappingAlgorithm(req.Algorithm)
	params, err := importExport.GetImportParameters(attrs, algorithm)
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

	srcB, err := s.resolveBackend(sourceBackend)
	if err != nil {
		return nil, &ErrCopyKeyBackend{Role: "source", Err: err}
	}
	dstB, err := s.resolveBackend(destBackend)
	if err != nil {
		return nil, &ErrCopyKeyBackend{Role: "destination", Err: err}
	}

	srcImportExport, ok := srcB.KeyProvider().(backend.ImportExportBackend)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrOperationNotSupported,
			Detail:   "source backend does not support export operations",
		}
	}
	dstImportExport, ok := dstB.KeyProvider().(backend.ImportExportBackend)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrOperationNotSupported,
			Detail:   "destination backend does not support import operations",
		}
	}

	srcAttrs, err := findKeyAttrs(srcB, req.SourceKeyID)
	if err != nil {
		return nil, &ErrCopyKeyBackend{Role: "source key", Err: err}
	}

	dstAttrs := &types.KeyAttributes{
		CN:                 req.DestKeyID,
		KeyAlgorithm:       srcAttrs.KeyAlgorithm,
		KeyType:            srcAttrs.KeyType,
		RSAAttributes:      srcAttrs.RSAAttributes,
		ECCAttributes:      srcAttrs.ECCAttributes,
		SymmetricAlgorithm: srcAttrs.SymmetricAlgorithm,
	}

	algorithm := backend.WrappingAlgorithmRSAES_OAEP_SHA_256
	if req.Algorithm != "" {
		algorithm = backend.WrappingAlgorithm(req.Algorithm)
	}

	importParams, err := dstImportExport.GetImportParameters(dstAttrs, algorithm)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "get import parameters", Err: err}
	}

	wrappedKey, err := srcImportExport.ExportKey(srcAttrs, algorithm)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "export key", Err: err}
	}
	wrappedKey.ImportToken = importParams.ImportToken

	if err := dstImportExport.ImportKey(dstAttrs, wrappedKey); err != nil {
		return nil, &ErrKeyOperation{Operation: "import key", Err: err}
	}

	return &transport.CopyKeyResponse{
		Success: true,
		KeyID:   req.DestKeyID,
	}, nil
}

// ExportKeyMaterial exports raw symmetric key bytes.
// This operation is not yet supported.
func (s *XKMSService) ExportKeyMaterial(ctx context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	return nil, ErrOperationNotSupported
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

	b, err := s.resolveBackend(backendName)
	if err != nil {
		return nil, err
	}

	importExport, ok := b.KeyProvider().(backend.ImportExportBackend)
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

	params := &backend.ImportParameters{
		WrappingPublicKey: wrappingPubKey,
		ImportToken:       req.ImportToken,
		Algorithm:         backend.WrappingAlgorithm(req.Algorithm),
	}

	wrapped, err := importExport.WrapKey(req.KeyMaterial, params)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrOperationFailed, Err: err}
	}

	return &transport.WrapKeyResponse{
		WrappedKeyMaterial: wrapped.WrappedKey,
		Algorithm:          string(wrapped.Algorithm),
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

	b, err := s.resolveBackend(backendName)
	if err != nil {
		return nil, err
	}

	importExport, ok := b.KeyProvider().(backend.ImportExportBackend)
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
	}

	params := &backend.ImportParameters{
		Algorithm:   backend.WrappingAlgorithm(req.Algorithm),
		ImportToken: req.ImportToken,
	}

	keyMaterial, err := importExport.UnwrapKey(wrapped, params)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrOperationFailed, Err: err}
	}

	return &transport.UnwrapKeyResponse{
		KeyMaterial: keyMaterial,
	}, nil
}

// WrapKeyByID wraps a key using another key, both identified by their IDs.
// This operation is not yet supported.
func (s *XKMSService) WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	return nil, ErrOperationNotSupported
}

// UnwrapKeyByID unwraps key material and imports it as a new key.
// This operation is not yet supported.
func (s *XKMSService) UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	return nil, ErrOperationNotSupported
}

// =========================================================================
// Internal helpers (unique to servicer_key.go)
// =========================================================================

// buildKeyAttributes constructs a types.KeyAttributes from a GenerateKeyRequest.
func buildKeyAttributes(req *transport.GenerateKeyRequest, backendName string) (*types.KeyAttributes, error) {
	attrs := &types.KeyAttributes{
		CN:        req.KeyID,
		StoreType: types.ParseStoreType(backendName),
	}

	// Parse key type
	if req.KeyType != "" {
		kt := types.ParseCLIKeyType(req.KeyType)
		if kt != "" {
			attrs.KeyType = kt.ToKeyType()
		}
	}
	// Default to signing key type if not specified
	if attrs.KeyType == 0 {
		attrs.KeyType = types.KeyTypeSigning
	}

	// Determine algorithm
	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = req.KeyType
	}

	// Check for symmetric algorithms first
	symAlgo := parseSymmetricAlgorithm(algorithm)
	if symAlgo != "" {
		attrs.SymmetricAlgorithm = symAlgo
		attrs.KeyType = types.KeyTypeSecret
		return attrs, nil
	}

	// Asymmetric algorithm parsing
	if types.AlgorithmRSA.Equals(algorithm) {
		attrs.KeyAlgorithm = x509.RSA
		keySize := req.KeySize
		if keySize == 0 {
			keySize = types.RSAKeySize2048
		}
		attrs.RSAAttributes = &types.RSAAttributes{KeySize: keySize}
	} else if types.AlgorithmECDSA.Equals(algorithm) || strings.EqualFold(algorithm, "ec") || strings.EqualFold(algorithm, "ecc") {
		attrs.KeyAlgorithm = x509.ECDSA
		curve := parseCurveString(req.Curve)
		if curve == nil {
			curve = elliptic.P256()
		}
		attrs.ECCAttributes = &types.ECCAttributes{Curve: curve}
	} else if types.AlgorithmEd25519.Equals(algorithm) {
		attrs.KeyAlgorithm = x509.Ed25519
	} else if algorithm != "" {
		return nil, &ErrValidation{Sentinel: ErrUnsupportedKeyAlgorithm, Detail: algorithm}
	} else {
		// No algorithm specified, default to ECDSA P-256
		attrs.KeyAlgorithm = x509.ECDSA
		attrs.ECCAttributes = &types.ECCAttributes{Curve: elliptic.P256()}
	}

	if req.Exportable {
		attrs.Exportable = true
	}

	return attrs, nil
}

// buildImportKeyAttributes constructs key attributes from an ImportKeyRequest.
func buildImportKeyAttributes(req *transport.ImportKeyRequest, backendName string) *types.KeyAttributes {
	attrs := &types.KeyAttributes{
		CN:        req.KeyID,
		StoreType: types.ParseStoreType(backendName),
	}

	if req.KeyType != "" {
		kt := types.ParseCLIKeyType(req.KeyType)
		if kt != "" {
			attrs.KeyType = kt.ToKeyType()
		}
	}
	if attrs.KeyType == 0 {
		attrs.KeyType = types.KeyTypeSigning
	}

	return attrs
}

// parseCurveString converts a curve name string to an elliptic.Curve.
func parseCurveString(curve string) elliptic.Curve {
	ec := types.ParseEllipticCurve(curve)
	switch ec {
	case types.CurveP224:
		return elliptic.P224()
	case types.CurveP256:
		return elliptic.P256()
	case types.CurveP384:
		return elliptic.P384()
	case types.CurveP521:
		return elliptic.P521()
	default:
		return nil
	}
}

// parseSymmetricAlgorithm attempts to parse an algorithm string as a symmetric algorithm.
// Returns empty string if the algorithm is not a recognized symmetric algorithm.
func parseSymmetricAlgorithm(algo string) types.SymmetricAlgorithm {
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
