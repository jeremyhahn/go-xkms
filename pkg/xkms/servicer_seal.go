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

// ensureSealingKey guarantees a sealing key exists in the backend. It first
// attempts to load the key via GetKey; if the key does not exist it generates
// a new one. This is a no-op for TPM2 backends which handle sealing keys
// internally via the SRK.
func ensureSealingKey(kp types.KeyProvider, attrs *types.KeyAttributes) error {
	if _, err := kp.GetKey(attrs); err != nil {
		if _, genErr := kp.GenerateKey(attrs); genErr != nil {
			return &ErrSealOperation{
				Operation: "auto-generate sealing key",
				Err:       genErr,
			}
		}
	}
	return nil
}

// Seal encrypts/protects data using the specified backend's sealing mechanism.
// If req.Backend is empty, the default backend is used.
//
// When no KeyID is provided and the backend is not TPM2, a dedicated sealing
// key is auto-generated (or reused if it already exists) so that the caller
// does not need to manage sealing keys explicitly.
//
// Implements the SealServicer interface.
func (s *XKMSService) Seal(ctx context.Context, req *transport.SealRequest) (*transport.SealResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	if len(req.Data) == 0 {
		return nil, ErrNilData
	}

	b, err := s.resolveBackend(req.Backend)
	if err != nil {
		return nil, err
	}

	opts := &types.SealOptions{
		AAD: req.AAD,
	}

	if req.KeyID != "" {
		attrs, parseErr := ParseKeyIDToAttributes(req.KeyID)
		if parseErr != nil {
			return nil, &ErrKeyIDParse{Err: parseErr}
		}
		opts.KeyAttributes = attrs
	}

	// Auto-generate a sealing key for backends that require KeyAttributes
	// (software, PKCS#11) when the caller did not provide a KeyID.
	// TPM2 handles this internally via defaultSealKeyAttributes().
	if opts.KeyAttributes == nil {
		kp := b.KeyProvider()
		if kp != nil && kp.Type() != types.BackendTypeTPM2 {
			attrs := defaultSealingKeyAttributes(kp.Type())
			if sealErr := ensureSealingKey(kp, attrs); sealErr != nil {
				return nil, sealErr
			}
			opts.KeyAttributes = attrs
		}
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
		opts.Password = types.NewPasswordFromString(req.Password)
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
// When no KeyID is provided and the backend is not TPM2, the well-known
// auto-generated sealing key CN is used to locate the sealing key.
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

	b, err := s.resolveBackend(req.Backend)
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
		AAD: req.AAD,
	}

	if req.KeyID != "" {
		attrs, parseErr := ParseKeyIDToAttributes(req.KeyID)
		if parseErr != nil {
			// KeyID may use the legacy ID() format (storeType:keyType:CN:algo)
			// which is not parseable by ParseKeyID. For non-TPM2 backends, fall
			// through to auto-resolve using the well-known sealing key. For TPM2
			// or if the KeyID is clearly invalid (e.g. empty keyname), return error.
			kp := b.KeyProvider()
			if kp == nil || kp.Type() == types.BackendTypeTPM2 {
				return nil, &ErrKeyIDParse{Err: parseErr}
			}
			// Fall through — auto-resolve will use defaultSealingKeyAttributes
		} else {
			opts.KeyAttributes = attrs
		}
	}

	// Auto-resolve sealing key for software/PKCS11 backends when no KeyID
	// was provided (or legacy KeyID parse failed). Use the well-known sealing
	// key CN so it matches the key that was auto-generated during Seal().
	if opts.KeyAttributes == nil {
		kp := b.KeyProvider()
		if kp != nil && kp.Type() != types.BackendTypeTPM2 {
			opts.KeyAttributes = defaultSealingKeyAttributes(kp.Type())
		}
	}

	// Map password for TPM sealed object authentication.
	if req.Password != "" {
		opts.Password = types.NewPasswordFromString(req.Password)
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
