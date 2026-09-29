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
	"strings"

	"github.com/google/go-tpm/tpm2"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// sealingKeyCNPrefix is the well-known prefix for auto-generated sealing keys.
// A deterministic CN is used so the same key is reused across seal operations
// on the same backend.
const sealingKeyCNPrefix = "xkms-sealing-key"

// pcrHashAlgMap maps lowercase hash algorithm strings to TPM algorithm IDs.
var pcrHashAlgMap = map[string]tpm2.TPMIAlgHash{
	"sha1":   tpm2.TPMAlgSHA1,
	"sha256": tpm2.TPMAlgSHA256,
	"sha384": tpm2.TPMAlgSHA384,
	"sha512": tpm2.TPMAlgSHA512,
}

// parsePCRHashAlg converts a hash algorithm string to a TPM algorithm ID.
// Returns TPMAlgSHA256 when alg is empty (default).
// Returns an ErrPCRHashAlgParse error for unrecognized algorithms.
func parsePCRHashAlg(alg string) (tpm2.TPMIAlgHash, error) {
	if alg == "" {
		return tpm2.TPMAlgSHA256, nil
	}
	hashAlg, ok := pcrHashAlgMap[strings.ToLower(alg)]
	if !ok {
		return 0, &ErrPCRHashAlgParse{
			Algorithm: alg,
			Err:       ErrInvalidHashFunction,
		}
	}
	return hashAlg, nil
}

// buildPCRSelection converts a slice of PCR indices and a hash algorithm
// into a TPMLPCRSelection suitable for use in TPM seal policies.
func buildPCRSelection(pcrs []int, hashAlg tpm2.TPMIAlgHash) (tpm2.TPMLPCRSelection, error) {
	upcrs := make([]uint, 0, len(pcrs))
	for _, pcr := range pcrs {
		if pcr < 0 || pcr > 23 {
			return tpm2.TPMLPCRSelection{}, ErrInvalidPCRIndex
		}
		upcrs = append(upcrs, uint(pcr))
	}
	return tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      hashAlg,
				PCRSelect: tpm2.PCClientCompatible.PCRs(upcrs...),
			},
		},
	}, nil
}

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
// defaultSealingKeyAttributes. TPM 2.0 seals under its storage root and needs
// no key, so the answer is nil.
func sealingKey(ctx context.Context, b Backend, keyID string) (*types.KeyAttributes, error) {
	if keyID != "" {
		parsed, err := ParseKeyIDToAttributes(keyID)
		if err != nil {
			return nil, &ErrKeyIDParse{Err: err}
		}
		return findKeyAttrs(ctx, b, parsed.CN)
	}
	kp := b.KeyProvider()
	if kp == nil || kp.Type() == types.BackendTypeTPM2 {
		return nil, nil
	}
	return defaultSealingKeyAttributes(kp.Type()), nil
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

	attrs, err := sealingKey(ctx, b, req.KeyID)
	if err != nil {
		return nil, err
	}
	if attrs != nil && req.KeyID == "" {
		if sealErr := ensureSealingKey(ctx, b, attrs); sealErr != nil {
			return nil, sealErr
		}
	}

	opts := &types.SealOptions{
		AAD:           req.AAD,
		KeyAttributes: attrs,
	}

	// Map PCR selection to TPM seal policy.
	if len(req.PCRs) > 0 {
		hashAlg, hashErr := parsePCRHashAlg(req.PCRHashAlg)
		if hashErr != nil {
			return nil, hashErr
		}
		pcrSelection, pcrErr := buildPCRSelection(req.PCRs, hashAlg)
		if pcrErr != nil {
			return nil, pcrErr
		}
		opts.TPMPolicy = &types.TPMSealPolicy{
			PCRSelection: pcrSelection,
			HashAlg:      hashAlg,
		}
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

	attrs, err := sealingKey(ctx, b, req.KeyID)
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
