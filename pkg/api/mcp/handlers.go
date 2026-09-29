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

package mcp

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/encoding"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// tenantBackend returns the named backend viewed through the authenticated
// caller's tenant, so a key resolved against it can only be one the caller
// owns.
//
// Every lookup on this transport identifies a key by its common name, which is
// unique only within a tenant. Against an unscoped backend such a lookup
// matches whichever tenant's key is listed first: one tenant could export
// another tenant's wrapped key material, unseal under its key, or delete it.
// The system tenant is not a scope and still sees every key -- see
// xkms.ScopeBackendToTenant.
func (s *Server) tenantBackend(ctx context.Context, backendName string) (xkms.Backend, error) {
	return s.xkmsService.LookupTenantBackend(backendName, callerTenantID(ctx))
}

// keyByCN returns the attributes of the key whose common name is keyID, out of
// the keys ks lists. It is the one place a key ID is matched against a common
// name, so the tenant scope carried by ks is the only thing that decides which
// tenant's key a caller can name.
func keyByCN(ctx context.Context, ks xkms.Backend, keyID string) (*types.KeyAttributes, error) {
	keys, err := ks.ListKeys(ctx)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to list keys", Err: err}
	}

	for _, attr := range keys {
		if attr.CN == keyID {
			return attr, nil
		}
	}

	// Wraps xkms.ErrKeyNotFound, not a bare *errs.Message, so a caller up the
	// stack that runs this through mapKeyOpError (requireKey does) resolves
	// it via keyOpSentinelCodes to sdkssh.JSONRPCCodeNotFound instead of
	// falling through to ErrCodeInternalError (go-xkms#814).
	return nil, &errs.Wrapped{Msg: fmt.Sprintf("key not found: %s", keyID), Err: xkms.ErrKeyNotFound}
}

// findKeyByCN searches the default keystore for a key by its common name,
// within the caller's tenant, and returns the full attributes.
func (s *Server) findKeyByCN(ctx context.Context, keyID string) (*types.KeyAttributes, error) {
	ks, err := xkms.ScopeBackendToTenant(s.keystore, callerTenantID(ctx))
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to scope keystore to the caller's tenant", Err: err}
	}

	return keyByCN(ctx, ks, keyID)
}

// findKeyInBackend searches a specific backend for a key by CN, within the
// caller's tenant.
func (s *Server) findKeyInBackend(ctx context.Context, keyID string, backendName string) (*types.KeyAttributes, error) {
	ks, err := s.tenantBackend(ctx, backendName)
	if err != nil {
		return nil, &errs.Wrapped{Msg: fmt.Sprintf("failed to get backend %s", backendName), Err: err}
	}

	return keyByCN(ctx, ks, keyID)
}

// requireKey confirms keyID names a key that exists, in the named backend when
// one is given and in the default backend otherwise.
//
// The crypto handlers resolve the key again inside the service layer, which is
// where the operation itself belongs. This lookup exists solely so a missing
// key is reported with this transport's own wording -- the same phrase every
// other method here uses -- rather than the service's. It interprets no crypto
// parameter.
func (s *Server) requireKey(ctx context.Context, keyID, backendName string) error {
	var err error
	if backendName != "" {
		_, err = s.findKeyInBackend(ctx, keyID, backendName)
	} else {
		_, err = s.findKeyByCN(ctx, keyID)
	}
	// Routed through mapKeyOpError, not a bare *errs.Wrapped, so every
	// caller of requireKey (handleSign, handleVerify, ...) reports a missing
	// key as sdkssh.JSONRPCCodeNotFound instead of ErrCodeInternalError
	// (go-xkms#814): requireKey's callers all return this error unchanged,
	// so it has to already be a *KeyOpError by the time it leaves here.
	return mapKeyOpError(err)
}

// handleHealth handles the health check method
func (s *Server) handleHealth(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return HealthResult{Status: "healthy"}, nil
}

// handleListBackends handles the listBackends method
func (s *Server) handleListBackends(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	backendNames := s.xkmsService.BackendNames()

	backends := make([]BackendInfo, 0, len(backendNames))
	for _, name := range backendNames {
		ks, err := s.xkmsService.LookupBackend(name)
		if err != nil {
			continue
		}

		provider := ks.KeyProvider()
		caps := provider.Capabilities()

		backends = append(backends, BackendInfo{
			ID:             name,
			Type:           string(provider.Type()),
			HardwareBacked: caps.HardwareBacked,
			Capabilities:   caps,
		})
	}

	// Apply pagination if params are provided
	var pr transport.PageRequest
	if len(req.Params) > 0 {
		if err := decodeParams(req, &pr); err != nil {
			return nil, err
		}
	}
	if err := transport.ValidatePageRequest(pr); err != nil {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: err}
	}
	paginatedBackends, pageResp := transport.ApplyPagination(backends, pr)

	return ListBackendsResult{
		Backends:   paginatedBackends,
		Pagination: &pageResp,
	}, nil
}

// handleGetBackend handles the xkms.getBackend method. It delegates to
// XKMSService.GetBackend, the same transport.XKMSServicer method the
// embedded transport calls directly, so the wire shape this handler returns
// is exactly transport.BackendInfo rather than a second, hand-built
// projection of it.
func (s *Server) handleGetBackend(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params GetBackendParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if params.Backend == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "backend is required"}}
	}

	info, err := s.xkmsService.GetBackend(ctx, params.Backend)
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return info, nil
}

// symmetricBackendName is the backend this transport has always fallen back to
// for a symmetric key generated without an explicit backend.
const symmetricBackendName = "symmetric"

// generateBackendName resolves the backend a generate request is served by.
//
// An explicit backend always wins. A symmetric request that names none keeps
// this transport's historical fallback to the "symmetric" backend; everything
// else defers to the service layer's own default. Choosing a name is request
// normalisation, not key work: nothing here interprets a crypto parameter.
func generateBackendName(params *GenerateKeyParams) string {
	if params.Backend != "" {
		return params.Backend
	}
	if types.AlgorithmSymmetric.Equals(params.KeyType) || types.AlgorithmSymmetric.Equals(params.Algorithm) {
		return symmetricBackendName
	}
	return ""
}

// handleGenerateKey handles the generateKey method.
//
// Generation belongs to the service layer, which owns backend resolution, the
// algorithm and key-purpose vocabularies, the symmetric/asymmetric split and
// the exportability contract. This handler used to resolve params.Backend only
// far enough to stamp KeyAttributes.StoreType and then generate with
// s.keystore, the process default backend: a key the caller asked a named
// backend to create was written to the default one carrying attributes that
// named a different store. Both halves were invisible from the response, which
// reported success and a public key either way, and the key was unusable
// afterwards -- sign, which does resolve the named backend, could not find it.
func (s *Server) handleGenerateKey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params GenerateKeyParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.KeyID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "key_id is required"}}
	}
	if params.Algorithm == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "algorithm is required"}}
	}

	// A named curve is validated here rather than left to the service, which
	// silently substitutes P-256 for anything it cannot parse
	// (pkg/xkms/servicer_key.go, buildKeyAttributes). A caller that asks for a
	// curve by name and receives a key on a different one has had a parameter
	// dropped, not defaulted, so the name is rejected at the boundary. This
	// interprets no crypto: the attributes are still built by the service.
	if params.Curve != "" {
		if _, curveErr := types.ParseCurve(params.Curve); curveErr != nil {
			return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: fmt.Sprintf("invalid curve: %s", params.Curve)}}
		}
	}

	resp, err := s.xkmsService.GenerateKey(ctx, &transport.GenerateKeyRequest{
		KeyID:      params.KeyID,
		Backend:    generateBackendName(&params),
		KeyType:    params.KeyType,
		KeySize:    params.KeySize,
		Curve:      params.Curve,
		Algorithm:  params.Algorithm,
		Exportable: params.Exportable,
		Sensitive:  params.Sensitive,
		TenantID:   callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return GenerateKeyResult{
		KeyID:        resp.KeyID,
		PublicKeyPEM: resp.PublicKeyPEM,
	}, nil
}

// handleGetKey handles the getKey method.
//
// The lookup belongs to the service layer, which resolves the request's
// backend and searches only that one. This handler used to find the key with
// findKeyByCN -- which scans the default keystore and ignores params.Backend
// entirely -- and then read the material out of s.keystore, the default
// backend, while echoing the requested backend name back in the response. A
// caller naming a second backend was answered with the default backend's key
// under the second backend's label whenever both held the same key ID, and a
// key resident only in the named backend was reported missing.
func (s *Server) handleGetKey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params GetKeyParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.KeyID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "key_id is required"}}
	}

	resp, err := s.xkmsService.GetKey(ctx, params.Backend, params.KeyID)
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	// The backend is reported as the service resolved it, not as the request
	// spelled it, so an empty request field names the backend actually read.
	return GetKeyResult{
		KeyID:        resp.KeyID,
		PublicKeyPEM: resp.PublicKeyPEM,
		Backend:      resp.Backend,
	}, nil
}

// handleDeleteKey handles the deleteKey method
func (s *Server) handleDeleteKey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params DeleteKeyParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.KeyID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "key_id is required"}}
	}

	// Get the backend - try to find key in specified backend or search all backends
	backendName := params.Backend
	var attrs *types.KeyAttributes
	var err error

	if backendName != "" {
		// Search in specified backend
		attrs, err = s.findKeyInBackend(ctx, params.KeyID, backendName)
	} else {
		// Try software backend first, then symmetric
		attrs, err = s.findKeyInBackend(ctx, params.KeyID, "software")
		if err != nil {
			attrs, err = s.findKeyInBackend(ctx, params.KeyID, "symmetric")
			if err == nil {
				backendName = "symmetric"
			}
		} else {
			backendName = "software"
		}
	}

	if err != nil {
		return nil, mapKeyOpError(err)
	}

	// Get the correct keystore
	ks := s.keystore
	if backendName != "" {
		ks, err = s.tenantBackend(ctx, backendName)
		if err != nil {
			return nil, mapKeyOpError(err)
		}
	}

	if err := ks.DeleteKey(ctx, attrs); err != nil {
		return nil, mapKeyOpError(err)
	}

	return map[string]interface{}{
		"success": true,
	}, nil
}

// handleListKeys handles the listKeys method.
// When params include a backend name, only keys from that backend are returned.
// When no backend is specified, keys from all registered backends are returned.
// The response format matches the REST API's ListKeysHandler for cross-protocol parity.
func (s *Server) handleListKeys(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	// Parse optional params for backend filtering
	var params ListKeysParams
	if len(req.Params) > 0 {
		if err := decodeParams(req, &params); err != nil {
			return nil, err
		}
	}

	// Collect keys from the requested backend(s)
	var keys []KeyInfo

	if params.Backend != "" {
		// Single-backend listing
		backendKeys, err := s.listKeysFromBackend(ctx, params.Backend)
		if err != nil {
			return nil, mapKeyOpError(err)
		}
		keys = backendKeys
	} else {
		// All-backends listing
		keys = make([]KeyInfo, 0)
		for _, backendName := range s.xkmsService.BackendNames() {
			backendKeys, err := s.listKeysFromBackend(ctx, backendName)
			if err != nil {
				// Skip backends that fail to list keys (e.g., not initialized)
				continue
			}
			keys = append(keys, backendKeys...)
		}
	}

	// Apply pagination
	var pr transport.PageRequest
	if len(req.Params) > 0 {
		if err := decodeParams(req, &pr); err != nil {
			return nil, err
		}
	}
	if err := transport.ValidatePageRequest(pr); err != nil {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: err}
	}
	paginatedKeys, pageResp := transport.ApplyPagination(keys, pr)

	return ListKeysResult{
		Keys:       paginatedKeys,
		Pagination: &pageResp,
	}, nil
}

// listKeysFromBackend lists keys from a single backend, converting each
// KeyAttributes into the rich KeyInfo format that matches the REST API.
func (s *Server) listKeysFromBackend(ctx context.Context, backendName string) ([]KeyInfo, error) {
	ks, err := s.tenantBackend(ctx, backendName)
	if err != nil {
		return nil, &errs.Wrapped{Msg: fmt.Sprintf("failed to get backend %s", backendName), Err: err}
	}

	keyAttrs, err := ks.ListKeys(ctx)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to list keys", Err: err}
	}

	keys := make([]KeyInfo, 0, len(keyAttrs))
	for _, attr := range keyAttrs {
		keyInfo := KeyInfo{
			KeyID:     attr.CN,
			KeyType:   attr.KeyType.String(),
			Algorithm: attr.AlgorithmString(),
			Backend:   backendName,
		}

		// Try to get the public key PEM for asymmetric keys
		privKey, err := ks.GetKey(ctx, attr)
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

	return keys, nil
}

// handleSign handles the sign method
func (s *Server) handleSign(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params SignParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.KeyID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "key_id is required"}}
	}

	// The key is resolved here so a missing key keeps this transport's
	// "failed to find key" wording, which is its uniform vocabulary for the
	// condition across every method. This decides error reporting only; the
	// signing below still resolves the key through the service.
	if err := s.requireKey(ctx, params.KeyID, params.Backend); err != nil {
		return nil, err
	}

	// The signing itself belongs to the service layer, which owns padding
	// selection (PKCS#1 v1.5 vs PSS), the salt length, the "already a digest"
	// contract, and the per-algorithm rules for Ed25519 and ECDSA. This
	// handler used to call signer.Sign directly with the bare crypto.Hash as
	// opts, which is PKCS#1 v1.5 for an RSA key: a caller asking for PSS got
	// a valid signature under the scheme it did not ask for, and no error.
	//
	// It also resolved the key in params.Backend but then signed with
	// s.keystore, the default backend -- so a request naming a second backend
	// was answered by the wrong key whenever both held the same key ID.
	resp, err := s.xkmsService.Sign(ctx, &transport.SignRequest{
		Backend:      params.Backend,
		KeyID:        params.KeyID,
		Data:         params.Data,
		Hash:         params.Hash,
		DataIsDigest: params.DataIsDigest,
		Padding:      params.Padding,
		SaltLength:   params.SaltLength,
		PreHash:      params.PreHash,
		Context:      params.Context,
		TenantID:     callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return SignResult{
		Signature: resp.Signature,
		Algorithm: resp.Algorithm,
	}, nil
}

// handleVerify handles the verify method
func (s *Server) handleVerify(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params VerifyParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.KeyID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "key_id is required"}}
	}

	if err := s.requireKey(ctx, params.KeyID, params.Backend); err != nil {
		return nil, err
	}

	sigBytes, err := decodeSignature(params.Signature)
	if err != nil {
		return nil, err
	}

	// Verification mirrors Sign: the service layer owns padding, salt length
	// and the per-algorithm rules, so a PSS signature is verified as PSS
	// rather than being rejected by a hard-wired PKCS#1 v1.5 check.
	resp, err := s.xkmsService.Verify(ctx, &transport.VerifyRequest{
		Backend:      params.Backend,
		KeyID:        params.KeyID,
		Data:         params.Data,
		Signature:    sigBytes,
		Hash:         params.Hash,
		DataIsDigest: params.DataIsDigest,
		Padding:      params.Padding,
		SaltLength:   params.SaltLength,
		PreHash:      params.PreHash,
		Context:      params.Context,
		TenantID:     callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return VerifyResult{
		Valid: resp.Valid,
	}, nil
}

// handleRotateKey handles the rotateKey method.
//
// Rotation belongs to the service layer, which resolves the request's backend
// and rotates the key it holds. This handler used to read the key's attributes
// out of the default keystore with findKeyByCN, overwrite their StoreType from
// params.Backend, and then rotate with s.keystore -- the default backend -- so
// a request naming a second backend rotated the default backend's key, or
// failed outright looking for an identifier the default store cannot contain
// because KeyAttributes.ID() encodes the store type it had just been given.
func (s *Server) handleRotateKey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params RotateKeyParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.KeyID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "key_id is required"}}
	}

	resp, err := s.xkmsService.RotateKey(ctx, &transport.RotateKeyRequest{
		KeyID:    params.KeyID,
		Backend:  params.Backend,
		TenantID: callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return RotateKeyResult{
		KeyID:        resp.KeyID,
		PublicKeyPEM: resp.PublicKeyPEM,
	}, nil
}

// handleDecrypt handles the decrypt method
func (s *Server) handleDecrypt(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params DecryptParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.KeyID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "key_id is required"}}
	}

	// Get the backend and find the key
	backendName := params.Backend
	var attrs *types.KeyAttributes
	var err error

	if backendName != "" {
		// Backend specified, look up key in that backend
		attrs, err = s.findKeyInBackend(ctx, params.KeyID, backendName)
		if err != nil {
			return nil, mapKeyOpError(err)
		}
	} else {
		// No backend specified, search both symmetric and software backends
		attrs, err = s.findKeyInBackend(ctx, params.KeyID, "symmetric")
		if err != nil {
			attrs, err = s.findKeyInBackend(ctx, params.KeyID, "software")
			if err != nil {
				return nil, mapKeyOpError(err)
			}
			backendName = "software"
		} else {
			backendName = "symmetric"
		}
	}

	ks, ksErr := s.xkmsService.LookupBackend(backendName)
	if ksErr != nil {
		return nil, mapKeyOpError(ksErr)
	}

	// A symmetric key in a backend with no symmetric support is a caller-facing
	// configuration error on this transport. The service falls back to
	// asymmetric decryption instead and reports the eventual failure as an
	// internal fault, so the check stays local to preserve the message.
	if attrs.IsSymmetric() {
		if _, ok := ks.KeyProvider().(types.SymmetricKeyProvider); !ok {
			return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: fmt.Sprintf("backend %s does not support symmetric operations", backendName)}}
		}
	}

	// Decryption belongs to the service layer, which owns the symmetric /
	// asymmetric split and the RSA padding selection. This handler used to
	// hard-wire rsa.OAEPOptions{Hash: crypto.SHA256} for every asymmetric key,
	// so a PKCS#1 v1.5 ciphertext could not be decrypted here at all, and an
	// OAEP ciphertext built under any other digest -- or with a label --
	// failed with an error that read like corruption.
	resp, err := s.xkmsService.Decrypt(ctx, &transport.DecryptRequest{
		Backend:        backendName,
		KeyID:          params.KeyID,
		Ciphertext:     params.Ciphertext,
		Nonce:          params.Nonce,
		Tag:            params.Tag,
		AdditionalData: params.AdditionalData,
		GCMNonceMode:   params.GCMNonceMode,
		Mode:           params.Mode,
		IV:             params.IV,
		TagSize:        params.TagSize,
		Padding:        params.Padding,
		Hash:           params.Hash,
		Label:          params.Label,
		TenantID:       callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return DecryptResult{
		Plaintext: resp.Plaintext,
	}, nil
}

// handleEncrypt handles the encrypt method
func (s *Server) handleEncrypt(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params EncryptParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.KeyID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "key_id is required"}}
	}

	if len(params.Plaintext) == 0 {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "plaintext is required"}}
	}

	// Get the correct backend for symmetric operations
	backendName := params.Backend
	if backendName == "" {
		backendName = "symmetric" // Default to symmetric backend
	}

	// Two preconditions are checked here rather than left to the service
	// because this transport reports them with its own messages: a missing key
	// and a backend with no symmetric support. The service answers the latter
	// by falling back to asymmetric encryption, so the check stays local. They
	// decide error reporting only -- no crypto parameter is interpreted here.
	if _, err := s.findKeyInBackend(ctx, params.KeyID, backendName); err != nil {
		return nil, mapKeyOpError(err)
	}

	ks, ksErr := s.xkmsService.LookupBackend(backendName)
	if ksErr != nil {
		return nil, mapKeyOpError(ksErr)
	}

	if _, ok := ks.KeyProvider().(types.SymmetricKeyProvider); !ok {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: fmt.Sprintf("backend %s does not support symmetric operations", backendName)}}
	}

	resp, err := s.xkmsService.Encrypt(ctx, &transport.EncryptRequest{
		Backend:        backendName,
		KeyID:          params.KeyID,
		Plaintext:      params.Plaintext,
		AdditionalData: params.AdditionalData,
		Nonce:          params.Nonce,
		Mode:           params.Mode,
		IV:             params.IV,
		TagSize:        params.TagSize,
		TenantID:       callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return EncryptResult{
		Ciphertext:   resp.Ciphertext,
		Nonce:        resp.Nonce,
		Tag:          resp.Tag,
		IV:           resp.IV,
		GCMNonceMode: resp.GCMNonceMode,
	}, nil
}

// The certificate methods below are thin adapters over the XKMSService
// certificate methods, which confine every read, write, listing and delete to
// the caller's tenant namespace. A certificate another tenant holds, or one
// the platform holds, answers exactly as one nobody stored, and a key ID that
// names another namespace ("tenant-b/web") is refused as malformed. These
// methods used to call the unscoped default keystore directly, so any tenant
// could read, overwrite, list or delete every tenant's certificates and the
// platform's (go-xkms#1228).

// requireKeyID refuses an empty key ID with the Invalid params every
// certificate method reports for it.
func requireKeyID(keyID string) error {
	if keyID == "" {
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "key_id is required"}}
	}
	return nil
}

// handleSaveCert handles the saveCert method
func (s *Server) handleSaveCert(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params SaveCertParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if err := requireKeyID(params.KeyID); err != nil {
		return nil, err
	}

	if params.CertPEM == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "cert_pem is required"}}
	}

	if err := s.xkmsService.SaveCertificate(ctx, &transport.SaveCertificateRequest{
		KeyID:          params.KeyID,
		CertificatePEM: params.CertPEM,
		TenantID:       callerTenantID(ctx),
	}); err != nil {
		return nil, mapKeyOpError(err)
	}

	return map[string]interface{}{
		"success": true,
	}, nil
}

// handleGetCert handles the getCert method
func (s *Server) handleGetCert(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params GetCertParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if err := requireKeyID(params.KeyID); err != nil {
		return nil, err
	}

	resp, err := s.xkmsService.GetCertificate(ctx, "", params.KeyID)
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return GetCertResult{
		KeyID:   resp.KeyID,
		CertPEM: resp.CertificatePEM,
	}, nil
}

// handleDeleteCert handles the deleteCert method
func (s *Server) handleDeleteCert(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params DeleteCertParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if err := requireKeyID(params.KeyID); err != nil {
		return nil, err
	}

	if err := s.xkmsService.DeleteCertificate(ctx, "", params.KeyID); err != nil {
		return nil, mapKeyOpError(err)
	}

	return map[string]interface{}{
		"success": true,
	}, nil
}

// handleListCerts handles the listCerts method
func (s *Server) handleListCerts(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	// Pagination params are optional.
	var pr transport.PageRequest
	if len(req.Params) > 0 {
		if err := decodeParams(req, &pr); err != nil {
			return nil, err
		}
	}
	if err := transport.ValidatePageRequest(pr); err != nil {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: err}
	}

	listed, err := s.xkmsService.ListCertificates(ctx, "", transport.WithPageRequest(pr))
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	keyIDs := make([]string, 0, len(listed.Certificates))
	for _, cert := range listed.Certificates {
		keyIDs = append(keyIDs, cert.KeyID)
	}

	return ListCertsResult{
		KeyIDs:     keyIDs,
		Pagination: &listed.PageResponse,
	}, nil
}

// handleCertExists handles the certExists method
func (s *Server) handleCertExists(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params CertExistsParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if err := requireKeyID(params.KeyID); err != nil {
		return nil, err
	}

	exists, err := s.xkmsService.CertificateExists(ctx, "", params.KeyID)
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return CertExistsResult{
		Exists: exists,
	}, nil
}

// handleSaveCertChain handles the saveCertChain method
func (s *Server) handleSaveCertChain(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params SaveCertChainParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if err := requireKeyID(params.KeyID); err != nil {
		return nil, err
	}

	if len(params.ChainPEMs) == 0 {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "chain_pems is required"}}
	}

	if err := s.xkmsService.SaveCertificateChain(ctx, &transport.SaveCertificateChainRequest{
		KeyID:    params.KeyID,
		ChainPEM: params.ChainPEMs,
		TenantID: callerTenantID(ctx),
	}); err != nil {
		return nil, mapKeyOpError(err)
	}

	return map[string]interface{}{
		"success": true,
	}, nil
}

// handleGetCertChain handles the getCertChain method
func (s *Server) handleGetCertChain(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params GetCertChainParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if err := requireKeyID(params.KeyID); err != nil {
		return nil, err
	}

	resp, err := s.xkmsService.GetCertificateChain(ctx, "", params.KeyID)
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return GetCertChainResult{
		KeyID:     resp.KeyID,
		ChainPEMs: resp.ChainPEM,
	}, nil
}

// handleGetTLSCertificate handles the getTLSCertificate method. The bundle is
// the leaf and chain stored in the caller's certificate namespace, in the
// named backend or the default one; the private key never travels on this
// response (go-xkms#627).
func (s *Server) handleGetTLSCertificate(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params GetTLSCertificateParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if err := requireKeyID(params.KeyID); err != nil {
		return nil, err
	}

	// Refuse a backend the service does not resolve before the lookup, so
	// the refusal names the backend rather than the certificate.
	if err := s.refuseUnknownBackend(params.Backend); err != nil {
		return nil, err
	}

	resp, err := s.xkmsService.GetTLSCertificate(ctx, params.Backend, params.KeyID)
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return *resp, nil
}

// handleGetImportParameters handles getting import parameters for key import
func (s *Server) handleGetImportParameters(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params GetImportParametersParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.KeyID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "key_id is required"}}
	}

	if err := s.refuseUnknownBackend(params.Backend); err != nil {
		return nil, err
	}

	tenantID, err := tenantForRequest(ctx, params.TenantID)
	if err != nil {
		return nil, err
	}

	// The service resolves the backend through the caller's tenant and
	// builds the attributes the backend mints its parameters for, from the
	// same key-type vocabulary the import takes, so the spec the backend
	// names here is the one the import will check the material against.
	// This handler used to build a common name and nothing else, so the
	// backend could only ever answer key_spec UNKNOWN.
	resp, err := s.xkmsService.GetImportParameters(ctx, &transport.GetImportParametersRequest{
		Backend:   params.Backend,
		KeyID:     params.KeyID,
		Algorithm: params.Algorithm,
		KeyType:   params.KeyType,
		KeySize:   params.KeySize,
		Curve:     params.Curve,
		TenantID:  tenantID,
	})
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	result := GetImportParametersResult{
		WrappingPublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: resp.WrappingPublicKey})),
		ImportToken:          resp.ImportToken,
		Algorithm:            resp.Algorithm,
		KeySpec:              resp.KeySpec,
	}
	if resp.ExpiresAt != "" {
		expiresAt := resp.ExpiresAt
		result.ExpiresAt = &expiresAt
	}

	return result, nil
}

// handleWrapKey handles wrapping key material for a subsequent import.
//
// WrapKey belongs to the service layer, which resolves the named backend's
// import capability (backend.ImportBackend, never the full
// ImportExportBackend union -- see go-xkms#1216) the same way
// handleImportKeyMaterial does, and carries KeySpec and Metadata through both
// directions. An empty backend selects the caller's tenant-scoped default,
// exactly as the former direct lookup through s.keystore did.
func (s *Server) handleWrapKey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params WrapKeyParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	// Parse wrapping public key from PEM
	block, _ := pem.Decode([]byte(params.WrappingPublicKeyPEM))
	if block == nil {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "invalid wrapping public key PEM"}}
	}

	resp, err := s.xkmsService.WrapKey(ctx, &transport.WrapKeyRequest{
		Backend:           params.Backend,
		KeyMaterial:       params.KeyMaterial,
		Algorithm:         params.Algorithm,
		WrappingPublicKey: block.Bytes,
		ImportToken:       params.ImportToken,
		KeySpec:           params.KeySpec,
		TenantID:          callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return WrapKeyResult{
		WrappedKey:  resp.WrappedKeyMaterial,
		Algorithm:   resp.Algorithm,
		ImportToken: resp.ImportToken,
		Metadata:    resp.Metadata,
	}, nil
}

// handleUnwrapKey handles unwrapping key material. UnwrapKey belongs to the
// service layer for the same reason handleWrapKey does; see its doc comment.
func (s *Server) handleUnwrapKey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params UnwrapKeyParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if len(params.WrappedKey) == 0 {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "wrapped_key is required"}}
	}
	if params.WrappingPublicKey == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "wrapping_public_key is required"}}
	}
	if params.Algorithm == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "algorithm is required"}}
	}

	// Parse wrapping public key from PEM
	block, _ := pem.Decode([]byte(params.WrappingPublicKey))
	if block == nil {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "invalid wrapping public key PEM"}}
	}

	resp, err := s.xkmsService.UnwrapKey(ctx, &transport.UnwrapKeyRequest{
		Backend:            params.Backend,
		WrappedKeyMaterial: params.WrappedKey,
		Algorithm:          params.Algorithm,
		ImportToken:        params.ImportToken,
		WrappingPublicKey:  block.Bytes,
		KeySpec:            params.KeySpec,
		Metadata:           params.Metadata,
		TenantID:           callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return UnwrapKeyResult{
		KeyMaterial: resp.KeyMaterial,
	}, nil
}

// handleImportKeyMaterial handles importing externally generated key material.
//
// The import belongs to the service layer, which owns backend resolution and
// the algorithm vocabulary and builds the key attributes for all three
// transports from one place. This handler used to build the attributes itself
// -- a common name, and a store type when the request named a backend -- and
// call ImportKey on s.keystore, the process default backend. Those attributes
// describe no algorithm, so the key was stored under an identifier ending in
// "unknown" that nothing else constructs, and the backend's own check of the
// material against its declared type had nothing to check it against.
//
// The algorithm now arrives in ImportKeyParams.KeyType and the service resolves
// it, exactly as it does for the gRPC and REST imports.
//
// The import runs under the caller's own tenant: the service writes it through
// the tenant-scoped backend, so a tenant's key lands in the tenant's own
// namespace and an untenanted caller's in the untenanted one, with no fallback
// between them. This transport withheld the tenant while an imported key
// persisted no metadata record it could be read back from (go-xkms#162); both
// key providers have persisted the tenant since go-xkms#163, so withholding it
// only sent a tenant's import where that tenant's own reads could not find it
// (go-xkms#222).
func (s *Server) handleImportKeyMaterial(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params ImportKeyParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.KeyID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "key_id is required"}}
	}

	// The backend name is refused here, through the service's own lookup,
	// so the refusal is classifiable before the import is attempted.
	if err := s.refuseUnknownBackend(params.Backend); err != nil {
		return nil, err
	}

	tenantID, err := tenantForRequest(ctx, params.TenantID)
	if err != nil {
		return nil, err
	}

	if _, err := s.xkmsService.ImportKey(ctx, &transport.ImportKeyRequest{
		Backend:            params.Backend,
		KeyID:              params.KeyID,
		KeyType:            params.KeyType,
		KeySize:            params.KeySize,
		Curve:              params.Curve,
		WrappedKeyMaterial: params.WrappedKey,
		Algorithm:          params.Algorithm,
		ImportToken:        params.ImportToken,
		Metadata:           params.Metadata,
		// Forwarded since go-xkms#159. The params struct could not represent
		// these three, so a symmetric import over MCP failed on a zero key
		// size and any requested digest or partition was silently discarded.
		AESKeySize: params.AESKeySize,
		Hash:       params.Hash,
		Partition:  params.Partition,
		Exportable: params.Exportable,
		Sensitive:  params.Sensitive,
		TenantID:   tenantID,
	}); err != nil {
		return nil, mapKeyOpError(err)
	}

	return map[string]interface{}{
		"success": true,
	}, nil
}

// handleExportKey handles exporting a key in wrapped form
func (s *Server) handleExportKey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params ExportKeyParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.KeyID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "key_id is required"}}
	}

	// Default to software backend for export operations
	backendName := params.Backend
	if backendName == "" {
		backendName = "software"
	}

	// Look up the key in the correct backend
	attrs, err := s.findKeyInBackend(ctx, params.KeyID, backendName)
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	// Get the correct keystore
	ks, err := s.tenantBackend(ctx, backendName)
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	// The resolved backend is authoritative for both fields: Backend is the
	// name the caller addressed it by, and StoreType is what that backend
	// reports itself to be via Type(), not a guess parsed from the name
	// (go-xkms#312). This replaces the old ParseStoreType(backendName) gate,
	// which silently left StoreType unchanged for any backend named
	// something other than a store-type keyword -- exactly the "token-a"
	// shape this transport must support.
	attrs.Backend = backendName
	attrs.StoreType = ks.Type()

	// Check if the backend supports the export half of the ceremony. Asserts
	// backend.ExportBackend, not the full ImportExportBackend union, so a
	// backend that only supports import (AWS KMS, by hardware design) does
	// not report the same undifferentiated refusal as one that supports
	// neither direction.
	exportBackend, ok := ks.KeyProvider().(backend.ExportBackend)
	if !ok {
		return nil, &KeyOpError{Code: ErrCodeMethodNotFound, Err: backend.ErrExportNotSupported}
	}

	// Parse wrapping algorithm
	algorithm := backend.WrappingAlgorithm(params.Algorithm)

	// Export the key
	wrapped, err := exportBackend.ExportKey(ctx, attrs, algorithm)
	if err != nil {
		return nil, mapImportExportError("failed to export key", err)
	}

	return ExportKeyResult{
		WrappedKey:  wrapped.WrappedKey,
		Algorithm:   string(wrapped.Algorithm),
		ImportToken: wrapped.ImportToken,
		Metadata:    wrapped.Metadata,
	}, nil
}

// ErrTenantIDNotAccepted is returned when request params carry a tenant_id.
//
// The tenant an operation runs under is the authenticated caller's own, never
// a value the caller names: a key ID is only unique within a tenant, so a
// caller-supplied tenant would let any caller address another tenant's keys.
// The field is refused rather than ignored, because a caller that believes it
// is acting on one tenant and is quietly served another has no way to tell.
var ErrTenantIDNotAccepted = errors.New("tenant_id is not accepted in the request params; the tenant is taken from the authenticated identity")

// ErrInvalidBackend is the sentinel behind every "invalid backend: <name>"
// refusal on this transport, so a caller can classify the refusal with
// errors.Is rather than by matching the message text (#176).
var ErrInvalidBackend = errors.New("invalid backend")

// InvalidBackendError is the refusal for a backend name the service does not
// resolve. It is ErrInvalidBackend to errors.Is, and it unwraps to the
// service's own error, so a caller can also tell a name that failed
// validation (xkms.ErrBackendNameValidation) from one that is not registered
// (xkms.ErrBackendNotFound).
type InvalidBackendError struct {
	// Name is the backend name as the request carried it.
	Name string
	// Cause is the service's refusal.
	Cause error
}

// Error implements the error interface.
func (e *InvalidBackendError) Error() string {
	return "invalid backend: " + e.Name + ": " + e.Cause.Error()
}

// Unwrap returns the service's refusal.
func (e *InvalidBackendError) Unwrap() error { return e.Cause }

// Is reports ErrInvalidBackend as this error's identity.
func (e *InvalidBackendError) Is(target error) bool { return target == ErrInvalidBackend }

// refuseUnknownBackend returns nil when name is empty (the default backend)
// or names a backend the service resolves, and otherwise the one refusal
// every handler returns: an InvalidBackendError carried as a KeyOpError with
// the JSON-RPC invalid-params code, since the fault is in the request.
//
// The name is resolved through the service's LookupBackend, the mechanism
// every other handler uses, rather than types.ParseStoreType: a backend name
// is a registry key, not a store-type keyword, and a configured name such as
// "token-a" that is not a keyword is a valid backend the transport must not
// refuse on its own.
func (s *Server) refuseUnknownBackend(name string) error {
	if name == "" {
		return nil
	}
	if _, err := s.xkmsService.LookupBackend(name); err != nil {
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: &InvalidBackendError{Name: name, Cause: err}}
	}
	return nil
}

// tenantForRequest returns the tenant the operation must run under, which is
// the one carried by the authenticated identity. It refuses a request that
// supplied a tenant of its own.
//
// This mirrors the gRPC transport, where the tenant has only ever come from
// callerTenantID and the wire format has no field for the caller to set.
func tenantForRequest(ctx context.Context, supplied string) (string, error) {
	if supplied != "" {
		return "", &KeyOpError{Code: ErrCodeInvalidParams, Err: ErrTenantIDNotAccepted}
	}
	return callerTenantID(ctx), nil
}

// handleAttestKey handles requesting a hardware attestation statement proving a
// key was generated in, and never left, a hardware security boundary (TPM 2.0,
// PKCS#11 HSM). The transport decodes the wire params directly into
// transport.AttestKeyRequest and returns transport.AttestKeyResponse unchanged,
// so the JSON field names are defined exactly once, in pkg/api/transport.
// All business logic — backend resolution, capability assertion, key lookup —
// is delegated to the xkms service layer; this handler performs no key
// operations of its own.
func (s *Server) handleAttestKey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.AttestKeyRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	tenantID, err := tenantForRequest(ctx, params.TenantID)
	if err != nil {
		return nil, err
	}
	params.TenantID = tenantID

	resp, err := s.xkmsService.AttestKey(ctx, &params)
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return resp, nil
}

// handleDeriveKeyECDH handles ECDH key agreement against a peer public key,
// combined with a KDF to produce a derived symmetric key. Delegates entirely to
// the xkms service layer, which resolves the backend, asserts it implements
// types.KeyAgreementProvider, and performs the derivation.
func (s *Server) handleDeriveKeyECDH(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.DeriveKeyECDHRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	tenantID, err := tenantForRequest(ctx, params.TenantID)
	if err != nil {
		return nil, err
	}
	params.TenantID = tenantID

	resp, err := s.xkmsService.DeriveKeyECDH(ctx, &params)
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return resp, nil
}

// handleDeriveKey handles the xkms.deriveKey method: general (non-ECDH) key
// derivation -- HKDF, SP 800-108 counter/feedback, PBKDF2 -- over
// caller-supplied input key material or a backend-held key. Distinct from
// xkms.deriveKeyECDH (handleDeriveKeyECDH), which performs an ECDH key
// agreement before deriving. Delegates entirely to the xkms service layer,
// which owns the KDF adapter dispatch and parameter assembly
// (pkg/xkms/servicer_crypto.go).
func (s *Server) handleDeriveKey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.DeriveKeyRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.Algorithm == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "algorithm is required"}}
	}

	tenantID, err := tenantForRequest(ctx, params.TenantID)
	if err != nil {
		return nil, err
	}
	params.TenantID = tenantID

	resp, err := s.xkmsService.DeriveKey(ctx, &params)
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return resp, nil
}

// handleExportKeyMaterial handles exporting raw symmetric key bytes for
// extractable keys.
//
// SECURITY WARNING: This method returns plaintext key material without any
// cryptographic protection. It only succeeds for symmetric keys created with
// exportable=true on a backend implementing backend.ImportExportBackend; use
// xkms.exportKey (handleExportKey) for secure key transport between backends.
func (s *Server) handleExportKeyMaterial(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.ExportKeyMaterialRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	tenantID, err := tenantForRequest(ctx, params.TenantID)
	if err != nil {
		return nil, err
	}
	params.TenantID = tenantID

	resp, err := s.xkmsService.ExportKeyMaterial(ctx, &params)
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return resp, nil
}

// handleWrapKeyByID handles wrapping a server-side target key with a
// server-side wrapping key, both identified by key ID and backend. This is the
// JSON-RPC surface for PKCS#11 C_WrapKey semantics. Distinct from xkms.wrapKey
// (handleWrapKey), which wraps caller-supplied key material against a
// caller-supplied PEM public key.
func (s *Server) handleWrapKeyByID(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.WrapKeyByIDRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	tenantID, err := tenantForRequest(ctx, params.TenantID)
	if err != nil {
		return nil, err
	}
	params.TenantID = tenantID

	resp, err := s.xkmsService.WrapKeyByID(ctx, &params)
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return resp, nil
}

// handleUnwrapKeyByID handles unwrapping key material with a server-side
// unwrapping key and importing the result as a new key, identified by key ID
// and backend. This is the JSON-RPC surface for PKCS#11 C_UnwrapKey semantics.
// Distinct from xkms.unwrapKey (handleUnwrapKey), which unwraps caller-supplied
// wrapped material against a caller-supplied PEM public key.
func (s *Server) handleUnwrapKeyByID(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.UnwrapKeyByIDRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	tenantID, err := tenantForRequest(ctx, params.TenantID)
	if err != nil {
		return nil, err
	}
	params.TenantID = tenantID

	resp, err := s.xkmsService.UnwrapKeyByID(ctx, &params)
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return resp, nil
}

// handleAsymmetricEncrypt handles asymmetric (RSA) encryption
func (s *Server) handleAsymmetricEncrypt(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params AsymmetricEncryptParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.KeyID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "key_id is required"}}
	}

	if err := s.refuseUnknownBackend(params.Backend); err != nil {
		return nil, err
	}

	// The key is resolved here, in the backend the request names, so a
	// missing key keeps this transport's "failed to find key" report rather
	// than the service's own wording.
	if err := s.requireKey(ctx, params.KeyID, params.Backend); err != nil {
		return nil, err
	}

	// The OAEP construction belongs to the service layer, which owns the
	// digest selection, its weak-hash refusal and the RSA key-type check. The
	// digest used to be a constant here and the request's hash was not carried
	// at all, so a caller could not choose one.
	resp, err := s.xkmsService.EncryptAsym(ctx, &transport.EncryptAsymRequest{
		Backend:   params.Backend,
		KeyID:     params.KeyID,
		Plaintext: params.Plaintext,
		Hash:      params.Hash,
		TenantID:  callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return AsymmetricEncryptResult{
		Ciphertext: resp.Ciphertext,
	}, nil
}

// handleAsymmetricDecrypt handles asymmetric (RSA) decryption
func (s *Server) handleAsymmetricDecrypt(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params AsymmetricDecryptParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.KeyID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "key_id is required"}}
	}

	if err := s.refuseUnknownBackend(params.Backend); err != nil {
		return nil, err
	}

	if err := s.requireKey(ctx, params.KeyID, params.Backend); err != nil {
		return nil, err
	}

	// The padding scheme and its digest used to be constants here. They are
	// now the caller's to choose, defaulting to the OAEP-SHA-256 this method's
	// counterpart (xkms.asymmetricEncrypt) produces, so the previous
	// behaviour is what an unchanged caller still gets.
	padding := params.Padding
	if padding == "" {
		padding = "oaep"
	}
	hash := params.Hash
	if hash == "" && strings.EqualFold(padding, "oaep") {
		hash = "SHA-256"
	}

	resp, err := s.xkmsService.Decrypt(ctx, &transport.DecryptRequest{
		Backend:    params.Backend,
		KeyID:      params.KeyID,
		Ciphertext: params.Ciphertext,
		Padding:    padding,
		Hash:       hash,
		Label:      params.Label,
		TenantID:   callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return AsymmetricDecryptResult{
		Plaintext: resp.Plaintext,
	}, nil
}

// handleCopyKey handles copying a key from one backend to another
func (s *Server) handleCopyKey(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params CopyKeyParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	// Validate required fields
	if params.SourceBackend == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "source_backend is required"}}
	}
	if params.SourceKeyID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "source_key_id is required"}}
	}
	if params.DestBackend == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "dest_backend is required"}}
	}
	if params.DestKeyID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "dest_key_id is required"}}
	}
	if params.Algorithm == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "algorithm is required"}}
	}

	// The copy is the service's, not this handler's. It resolves the source
	// key's stored attributes -- exportability included -- from the backend's
	// own listing, so what the key IS decides whether it may leave, never what
	// a request claims about it. This handler used to build the source
	// attributes by hand with CN and store type only, which left Exportable
	// at its zero value and refused every copy at the export step (#155), and
	// a request field for it would have let a caller assert exportability of
	// a key that has none.
	// Tenant scoping rides on the request like every other delegating
	// handler here: the service resolves both backends through
	// resolveTenantBackend with this value, so a caller in one tenant cannot
	// name a key ID that resolves in another tenant's store. Both ends are the
	// caller's own tenant -- there are no cross-tenant copies on this
	// transport, so a request naming a tenant of its own is refused rather
	// than acted on (go-xkms#222).
	tenantID, err := tenantForRequest(ctx, params.TenantID)
	if err != nil {
		return nil, err
	}

	resp, err := s.xkmsService.CopyKey(ctx, &transport.CopyKeyRequest{
		SourceBackend: params.SourceBackend,
		SourceKeyID:   params.SourceKeyID,
		DestBackend:   params.DestBackend,
		DestKeyID:     params.DestKeyID,
		Algorithm:     params.Algorithm,
		TenantID:      tenantID,
	})
	if err != nil {
		return nil, mapKeyOpError(err)
	}
	if !resp.Success {
		// The service reports failure through its error; a nil error with
		// Success false is a contract violation and must not read as success.
		return nil, &KeyOpError{Code: ErrCodeInternalError, Err: ErrCopyKeyIncomplete}
	}

	return CopyKeyResult{
		Success: true,
		Message: fmt.Sprintf("Key copied from %s/%s to %s/%s successfully",
			params.SourceBackend, params.SourceKeyID, params.DestBackend, resp.KeyID),
	}, nil
}

// handleSeal handles the seal method for sealing data with a backend.
//
// The seal belongs to the service layer, which resolves the sealing key --
// the named one, or the caller's default sealing key when none is named --
// within the caller's tenant (go-xkms#1228).
func (s *Server) handleSeal(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params SealParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if len(params.Data) == 0 {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "data is required"}}
	}

	sealed, err := s.xkmsService.Seal(ctx, &transport.SealRequest{
		Backend:  params.Backend,
		KeyID:    params.KeyID,
		Data:     params.Data,
		AAD:      params.AAD,
		TenantID: callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	// Convert metadata from map[string][]byte to map[string]string for JSON serialization
	var metadata map[string]string
	if sealed.Metadata != nil {
		metadata = make(map[string]string, len(sealed.Metadata))
		for k, v := range sealed.Metadata {
			metadata[k] = base64.StdEncoding.EncodeToString(v)
		}
	}

	return SealResult{
		Backend:    sealed.Backend,
		Ciphertext: sealed.Ciphertext,
		Nonce:      sealed.Nonce,
		Tag:        sealed.Tag,
		Metadata:   metadata,
		KeyID:      sealed.KeyID,
		WrappedDEK: sealed.WrappedDEK,
	}, nil
}

// handleUnseal handles the unseal method for unsealing data with a backend.
//
// As with handleSeal, the key is resolved within the caller's tenant by the
// service, so a blob sealed under another tenant's key -- named, or that
// tenant's default sealing key -- does not unseal here (go-xkms#1228).
func (s *Server) handleUnseal(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params UnsealParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if len(params.Ciphertext) == 0 {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "ciphertext is required"}}
	}

	resp, err := s.xkmsService.Unseal(ctx, &transport.UnsealRequest{
		Backend:    params.Backend,
		KeyID:      params.KeyID,
		Ciphertext: params.Ciphertext,
		Nonce:      params.Nonce,
		Tag:        params.Tag,
		AAD:        params.AAD,
		TenantID:   callerTenantID(ctx),
	})
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return UnsealResult{
		Plaintext: resp.Plaintext,
	}, nil
}

// handleCanSeal handles the canSeal method to check if a backend supports sealing
func (s *Server) handleCanSeal(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params CanSealParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	// Check sealing capability
	var canSeal bool
	if params.Backend != "" {
		canSeal = s.xkmsService.CanSealDirect(params.Backend)
	} else {
		canSeal = s.xkmsService.CanSealDirect()
	}

	return CanSealResult{
		CanSeal: canSeal,
	}, nil
}
