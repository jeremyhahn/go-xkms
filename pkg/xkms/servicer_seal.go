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
	"crypto/elliptic"
	"crypto/x509"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// sealingKeyCNPrefix is the well-known prefix for auto-generated sealing keys.
// A deterministic CN is used so the same key is reused across seal operations
// on the same backend.
const sealingKeyCNPrefix = "xkms-sealing-key"

// defaultSealingKeyAttributes builds KeyAttributes for an auto-generated
// sealing key on the given backend. The CN is deterministic so the same
// key is reused across seal/unseal operations.
//
// The attributes carry no tenant. Seal and Unseal hand them to a backend
// resolved through the caller's tenant, and a tenant-scoped backend stamps
// its tenant on every key it generates, loads or seals under -- so each
// tenant's default sealing key is its own key, stored under its own
// identifier, and a platform-scoped caller's is the untenanted one
// (go-xkms#1228).
func defaultSealingKeyAttributes(backendType types.BackendType) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:           fmt.Sprintf("%s-%s", sealingKeyCNPrefix, backendType),
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
		KeyType:   types.KeyTypeEncryption,
		StoreType: backendTypeToStoreType(backendType),
	}
}

// ensureSealingKey guarantees the default sealing key exists in b. It first
// attempts to load the key via GetKey; if the key does not exist it generates
// a new one. b is the caller's tenant view of the backend, so the key is
// loaded from, and generated into, the caller's tenant.
func ensureSealingKey(ctx context.Context, b Backend, attrs *types.KeyAttributes) error {
	if _, err := b.GetKey(ctx, attrs); err != nil {
		if _, genErr := b.GenerateECDSA(ctx, attrs); genErr != nil {
			return &ErrSealOperation{
				Operation: "auto-generate sealing key",
				Err:       genErr,
			}
		}
	}
	return nil
}

// sealingKey resolves the key a seal or unseal runs under, within b -- the
// caller's tenant view of the backend.
//
// A key ID names a key the way every other key operation names one: the
// reference is parsed (a malformed one is ErrKeyIDParse) and its key name is
// resolved against the keys b lists, which for a tenant caller are that
// tenant's keys only. Another tenant's key is the same ErrKeyNotFound a key
// no tenant holds produces, so the answer does not reveal that it exists.
// The transports used to resolve the name over the unscoped backend, which
// sealed under -- and unsealed with -- any tenant's key of that name.
//
// Without a key ID a key-based backend uses the default sealing key; see
// defaultSealingKeyAttributes. TPM 2.0 seals a keyed-hash object of its own
// rather than under a key; see tpmSealedObject. tpmPolicy names the TPM policy
// a TPM2 sealed object is bound to, and any other backend refuses one.
func sealingKey(ctx context.Context, b Backend, keyID, tpmPolicy string) (*types.KeyAttributes, error) {
	kp := b.KeyProvider()
	if kp != nil && kp.Type() == types.BackendTypeTPM2 {
		return tpmSealedObject(keyID, tpmPolicy)
	}
	if tpmPolicy != "" {
		return nil, &ErrValidation{Sentinel: ErrTPMPolicyNotSupported, Detail: "tpm_policy is only valid on a TPM2 backend"}
	}
	if keyID != "" {
		parsed, err := ParseKeyIDToAttributes(keyID)
		if err != nil {
			return nil, &ErrKeyIDParse{Err: err}
		}
		return findKeyAttrs(ctx, b, parsed.CN)
	}
	if kp == nil {
		return nil, nil
	}
	return defaultSealingKeyAttributes(kp.Type()), nil
}

// tpmSealedObject returns the attributes of the TPM2 sealed object a seal
// creates, or an unseal authorizes: the object keyID names, or the backend's
// default sealed object when keyID is empty. It is created under the storage
// parent of the scope the tenant view selects, bound to tpmPolicy -- a named
// policy of that scope, "platform" for the built-in platform policy, or empty
// for none, leaving its password as its only authorization.
func tpmSealedObject(keyID, tpmPolicy string) (*types.KeyAttributes, error) {
	cn := fmt.Sprintf("%s-%s", sealingKeyCNPrefix, types.BackendTypeTPM2)
	if keyID != "" {
		parsed, err := ParseKeyIDToAttributes(keyID)
		if err != nil {
			return nil, &ErrKeyIDParse{Err: err}
		}
		cn = parsed.CN
	}
	return &types.KeyAttributes{
		CN:        cn,
		StoreType: types.StoreTPM2,
		TPMPolicy: tpmPolicy,
	}, nil
}

// Seal encrypts/protects data using the specified backend's sealing mechanism.
// If req.Backend is empty, the default backend is used.
//
// The backend is viewed through req.TenantID, the caller's tenant, which each
// transport fills from the authenticated identity: the sealing key is found
// within that tenant (see sealingKey), and when no KeyID is provided on a
// key-based backend the tenant's own default sealing key is generated on
// first use and reused after that. A platform-scoped caller seals on the
// unscoped backend.
//
// Implements the SealServicer interface.
func (s *XKMSService) Seal(ctx context.Context, req *transport.SealRequest) (*transport.SealResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	if len(req.Data) == 0 {
		return nil, ErrNilData
	}

	b, err := s.resolveTenantBackend(req.Backend, req.TenantID)
	if err != nil {
		return nil, err
	}

	attrs, err := sealingKey(ctx, b, req.KeyID, req.TPMPolicy)
	if err != nil {
		return nil, err
	}
	if attrs != nil && req.KeyID == "" && attrs.StoreType != types.StoreTPM2 {
		if sealErr := ensureSealingKey(ctx, b, attrs); sealErr != nil {
			return nil, sealErr
		}
	}

	opts := &types.SealOptions{
		AAD:           req.AAD,
		KeyAttributes: attrs,
	}

	// Map password for TPM sealed object authentication.
	if req.Password != "" {
		pw, pwErr := types.NewPasswordFromString(req.Password)
		if pwErr != nil {
			return nil, pwErr
		}
		opts.Password = pw
	}

	sealed, err := b.Seal(ctx, req.Data, opts)
	if err != nil {
		return nil, &ErrSealOperation{Operation: "seal", Err: err}
	}

	return &transport.SealResponse{
		Backend:    string(sealed.Backend),
		Ciphertext: sealed.Ciphertext,
		Nonce:      sealed.Nonce,
		Tag:        sealed.Tag,
		TPMPublic:  sealed.TPMPublic,
		TPMPrivate: sealed.TPMPrivate,
		WrappedDEK: sealed.WrappedDEK,
		KeyID:      sealed.KeyID,
		Metadata:   sealed.Metadata,
	}, nil
}

// Unseal decrypts/recovers data that was previously sealed.
// If req.Backend is empty, the default backend is used.
//
// The key is resolved within req.TenantID exactly as Seal resolves it, so a
// blob sealed under another tenant's key -- named or default -- does not
// unseal for this caller.
//
// Implements the SealServicer interface.
func (s *XKMSService) Unseal(ctx context.Context, req *transport.UnsealRequest) (*transport.UnsealResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	// Accept either ciphertext (software/cloud backends) or TPM public+private
	// blobs (TPM2 backend). At least one form of sealed data must be present.
	if len(req.Ciphertext) == 0 && (len(req.TPMPublic) == 0 || len(req.TPMPrivate) == 0) {
		return nil, ErrInvalidSealedData
	}

	b, err := s.resolveTenantBackend(req.Backend, req.TenantID)
	if err != nil {
		return nil, err
	}

	attrs, err := sealingKey(ctx, b, req.KeyID, "")
	if err != nil {
		return nil, err
	}

	sealed := &types.SealedData{
		Backend:    b.KeyProvider().Type(),
		Ciphertext: req.Ciphertext,
		Nonce:      req.Nonce,
		Tag:        req.Tag,
		TPMPublic:  req.TPMPublic,
		TPMPrivate: req.TPMPrivate,
		WrappedDEK: req.WrappedDEK,
		Metadata:   req.Metadata,
	}

	opts := &types.UnsealOptions{
		AAD:           req.AAD,
		KeyAttributes: attrs,
	}

	// Map password for TPM sealed object authentication.
	if req.Password != "" {
		pw, pwErr := types.NewPasswordFromString(req.Password)
		if pwErr != nil {
			return nil, pwErr
		}
		opts.Password = pw
	}

	plaintext, err := b.Unseal(ctx, sealed, opts)
	if err != nil {
		return nil, &ErrSealOperation{Operation: "unseal", Err: err}
	}

	return &transport.UnsealResponse{
		Plaintext: plaintext,
	}, nil
}

// CanSeal checks whether the specified backend supports sealing operations.
// If backendName is empty, the default backend is checked.
// Implements the SealServicer interface.
func (s *XKMSService) CanSeal(ctx context.Context, backendName string) (*transport.CanSealResponse, error) {
	b, err := s.resolveBackend(backendName)
	if err != nil {
		return nil, err
	}

	resolvedName := backendName
	if resolvedName == "" {
		resolvedName = s.defaultBackend
	}

	return &transport.CanSealResponse{
		CanSeal: b.CanSeal(),
		Backend: resolvedName,
	}, nil
}
