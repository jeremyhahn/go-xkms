// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package software

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/google/go-tpm/tpm2"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// tpm2DuplicateMetaKey matches the tpm2 backend's WrappedKeyMaterial
// metadata marker for a duplication blob.
const tpm2DuplicateMetaKey = "tpm2_duplicate_blob"

// exportTPM2Duplicate wraps an asymmetric private key as a TCG duplication
// blob for the TPM storage parent named in dstParams.ImportToken (its
// marshaled TPMT_PUBLIC), so the destination TPM's TPM2_Import accepts it.
// The seed, KDFa, outer wrap and integrity HMAC are go-tpm's
// tpm2.ImportEncapsulationKey and tpm2.CreateDuplicate, the same helpers the
// tpm2 backend's WrapKey uses; this file only builds the public and
// sensitive areas of the key. Symmetric keys are refused: the tpm2 backend
// imports signing and decryption keys only.
func (b *SoftwareBackend) exportTPM2Duplicate(ctx context.Context, attrs *types.KeyAttributes, dstParams *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if attrs.IsSymmetric() {
		return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: "TPM2_DUPLICATE carries asymmetric keys only"}
	}
	if len(dstParams.ImportToken) == 0 {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "TPM2_DUPLICATE import parameters carry no parent public area"}
	}
	parent, err := tpm2.Unmarshal[tpm2.TPMTPublic](dstParams.ImportToken)
	if err != nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("parse TPM2 parent public area: %v", err)}
	}
	encKey, err := tpm2.ImportEncapsulationKey(parent)
	if err != nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("TPM2 parent encapsulation key: %v", err)}
	}

	privateKey, err := b.pkcs8Backend.GetKey(ctx, attrs)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get private key", Err: err}
	}
	public, sensitive, err := tpm2DuplicateAreas(privateKey, attrs.KeyType)
	if err != nil {
		return nil, err
	}
	name, err := tpm2.ObjectName(public)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "compute TPM2 object name", Err: err}
	}
	duplicate, encSecret, err := tpm2.CreateDuplicate(rand.Reader, encKey, name.Buffer, tpm2.Marshal(*sensitive))
	if err != nil {
		return nil, &errs.Wrapped{Msg: "create TPM2 duplication blob", Err: err}
	}
	encoded, err := json.Marshal(backend.TPM2DuplicationBlob{
		Public:    tpm2.Marshal(*public),
		Duplicate: duplicate,
		EncSecret: encSecret,
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "encode TPM2 duplication blob", Err: err}
	}
	return &backend.WrappedKeyMaterial{
		WrappedKey:  encoded,
		Algorithm:   backend.WrappingAlgorithmTPM2Duplicate,
		ImportToken: dstParams.ImportToken,
		Metadata:    map[string]string{tpm2DuplicateMetaKey: "1"},
	}, nil
}

// tpm2DuplicateAreas builds the importable public and sensitive areas of an
// RSA or ECDSA private key: a user-auth key with FixedTPM and FixedParent
// clear (TPM2_Import refuses either set) and null schemes, so the TPM uses
// the scheme each Sign or Decrypt call names. The object attributes follow
// the key's purpose (tpm2DuplicateAttributes).
func tpm2DuplicateAreas(privateKey any, keyType types.KeyType) (*tpm2.TPMTPublic, *tpm2.TPMTSensitive, error) {
	attrs, err := tpm2DuplicateAttributes(keyType)
	if err != nil {
		return nil, nil, err
	}
	obfuscation := make([]byte, sha256.Size)
	if _, err := rand.Read(obfuscation); err != nil {
		return nil, nil, &errs.Wrapped{Msg: "read obfuscation value", Err: err}
	}

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		if len(key.Primes) != 2 {
			return nil, nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: "TPM2_DUPLICATE needs a two-prime RSA key"}
		}
		bits := key.N.BitLen()
		exponent := uint32(key.E)
		if key.E == 65537 {
			exponent = 0 // TPM 2.0 encodes the default exponent as zero
		}
		public := &tpm2.TPMTPublic{
			Type:             tpm2.TPMAlgRSA,
			NameAlg:          tpm2.TPMAlgSHA256,
			ObjectAttributes: attrs,
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
				Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
				Scheme:    tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull},
				KeyBits:   tpm2.TPMKeyBits(bits),
				Exponent:  exponent,
			}),
			Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: key.N.FillBytes(make([]byte, (bits+7)/8))}),
		}
		sensitive := &tpm2.TPMTSensitive{
			SensitiveType: tpm2.TPMAlgRSA,
			SeedValue:     tpm2.TPM2BDigest{Buffer: obfuscation},
			Sensitive: tpm2.NewTPMUSensitiveComposite(tpm2.TPMAlgRSA, &tpm2.TPM2BPrivateKeyRSA{
				Buffer: key.Primes[0].FillBytes(make([]byte, (bits+15)/16)),
			}),
		}
		return public, sensitive, nil

	case *ecdsa.PrivateKey:
		curveID, err := tpm2ECCCurve(key.Curve)
		if err != nil {
			return nil, nil, err
		}
		size := (key.Curve.Params().BitSize + 7) / 8
		// Bytes is the fixed-length big-endian private scalar (size bytes for
		// the NIST curves tpm2ECCCurve admits); the D field is deprecated.
		scalar, err := key.Bytes()
		if err != nil {
			return nil, nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("TPM2_DUPLICATE private scalar: %v", err)}
		}
		public := &tpm2.TPMTPublic{
			Type:             tpm2.TPMAlgECC,
			NameAlg:          tpm2.TPMAlgSHA256,
			ObjectAttributes: attrs,
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
				Scheme:    tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull},
				CurveID:   curveID,
				KDF:       tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
			}),
			Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: key.X.FillBytes(make([]byte, size))},
				Y: tpm2.TPM2BECCParameter{Buffer: key.Y.FillBytes(make([]byte, size))},
			}),
		}
		sensitive := &tpm2.TPMTSensitive{
			SensitiveType: tpm2.TPMAlgECC,
			SeedValue:     tpm2.TPM2BDigest{Buffer: obfuscation},
			Sensitive: tpm2.NewTPMUSensitiveComposite(tpm2.TPMAlgECC, &tpm2.TPM2BECCParameter{
				Buffer: scalar,
			}),
		}
		return public, sensitive, nil

	default:
		return nil, nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("TPM2_DUPLICATE does not carry %T keys", privateKey)}
	}
}

// tpm2ECCCurve maps a NIST curve to its TPM 2.0 curve identifier.
// tpm2DuplicateAttributes maps a key purpose to the TPM object attributes of
// its duplicate: encryption keys get Decrypt (RSA decrypt, ECDH), signing
// purposes get SignEncrypt, and a purpose a TPM asymmetric object cannot
// honour (HMAC, secret, storage, an unset type, ...) is refused rather than
// guessed.
func tpm2DuplicateAttributes(keyType types.KeyType) (tpm2.TPMAObject, error) {
	attrs := tpm2.TPMAObject{UserWithAuth: true, NoDA: true}
	switch keyType {
	case types.KeyTypeEncryption:
		attrs.Decrypt = true
	case types.KeyTypeSigning, types.KeyTypeTLS, types.KeyTypeCA,
		types.KeyTypeAttestation, types.KeyTypeIDevID, types.KeyTypeLDevID:
		attrs.SignEncrypt = true
	default:
		return tpm2.TPMAObject{}, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("TPM2_DUPLICATE does not carry keys of purpose %v", keyType)}
	}
	return attrs, nil
}

func tpm2ECCCurve(curve elliptic.Curve) (tpm2.TPMECCCurve, error) {
	switch curve {
	case elliptic.P256():
		return tpm2.TPMECCNistP256, nil
	case elliptic.P384():
		return tpm2.TPMECCNistP384, nil
	case elliptic.P521():
		return tpm2.TPMECCNistP521, nil
	}
	return 0, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("TPM2_DUPLICATE does not carry curve %s", curve.Params().Name)}
}
