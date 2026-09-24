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

package tpm2

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Ensure Backend implements backend.ImportExportBackend at compile time.
var _ backend.ImportExportBackend = (*Backend)(nil)

// tpmDuplicateMetaKey is the WrappedKeyMaterial.Metadata key under which the
// serialized TPM duplication blob is carried.
const tpmDuplicateMetaKey = "tpm2_duplicate_blob"

// duplicationBlob is the wire representation of a TPM2 duplication produced by
// WrapKey and consumed by UnwrapKey/ImportKey.
//
// The TPM import/export contract for hardware backends does not use the
// RSA-OAEP / AES-KWP wrapping families: a TPM imports externally supplied
// sensitive material via the TCG duplication protocol. WrapKey therefore
// builds a duplicable sealed-keyedhash object whose secret is the supplied
// key material, encrypts it to the parent (SRK) public key with
// TPM2_CreateDuplicate, and serializes the three resulting fields here.
// UnwrapKey/ImportKey feed them back into TPM2_Import under the SRK.
type duplicationBlob struct {
	// Public is the marshaled TPMTPublic of the duplicated sealed object.
	Public []byte `json:"public"`

	// Duplicate is the outer-wrapped private area (the duplication blob).
	Duplicate []byte `json:"duplicate"`

	// EncSecret is the seed protected by the SRK's asymmetric algorithm.
	EncSecret []byte `json:"enc_secret"`
}

// importExportAlgorithm is the wrapping-algorithm label reported by the TPM2
// backend's import/export surface. It denotes the TCG duplication protocol
// (labeled encapsulation under the parent storage key), not an RSA family.
const importExportAlgorithm = backend.WrappingAlgorithm("TPM2_DUPLICATE")

// srkPublicContents reads the public area of this backend's own storage
// parent (b.srkAttrs -- the Platform SRK, see NewBackend) and returns its
// TPMTPublic together with its Name, used to build the labeled-encapsulation
// key for duplication and to authorize Import.
//
// This deliberately reads b.srkAttrs.TPMAttributes.Handle via ReadHandle
// rather than calling b.tpm.SRKPublic(), which is pinned to the TCG-standard
// Shared SRK (TPM2.SSRKPublic) regardless of which key this backend actually
// uses as its parent. Reading the wrong key here would encapsulate WrapKey's
// duplication seed to a public key different from the parent ImportKey and
// UnwrapKey authorize against, and the TPM rejects the resulting mismatch.
func (b *Backend) srkPublicContents() (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	if b.srkAttrs == nil || b.srkAttrs.TPMAttributes == nil {
		return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, &errs.Detail{Err: ErrUnsupportedOperation, Detail: "backend has no storage parent attributes"}
	}
	name, pub, err := b.tpm.ReadHandle(b.srkAttrs.TPMAttributes.Handle)
	if err != nil {
		return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, &errs.Detail{Err: ErrUnsupportedOperation, Detail: fmt.Sprintf("failed to read SRK public: %v", err)}
	}
	return name, pub, nil
}

// GetImportParameters returns the parameters required to wrap key material for
// import into the TPM. The wrapping key is the SRK public area; WrapKey uses
// it to build the duplication blob. The marshaled SRK TPMTPublic is carried in
// ImportToken so WrapKey can reconstruct the encapsulation key without a second
// TPM round trip.
func (b *Backend) GetImportParameters(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrNotInitialized
	}
	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}
	if algorithm != importExportAlgorithm {
		return nil, &errs.Detail{Err: ErrUnsupportedOperation, Detail: fmt.Sprintf("TPM2 import requires algorithm %s, got %s", importExportAlgorithm, algorithm)}
	}

	name, pub, err := b.srkPublicContents()
	if err != nil {
		return nil, err
	}

	// Convert the SRK public area to a crypto.PublicKey for the contract's
	// WrappingPublicKey field. ParsePublicKey expects the bare TPMTPublic
	// marshaling (no length prefix), matching the production read path.
	pubKey, err := b.tpm.ParsePublicKey(tpm2.Marshal(pub))
	if err != nil {
		return nil, &errs.Detail{Err: ErrUnsupportedOperation, Detail: fmt.Sprintf("failed to parse SRK public key: %v", err)}
	}

	return &backend.ImportParameters{
		WrappingPublicKey: pubKey,
		ImportToken:       name.Buffer,
		Algorithm:         importExportAlgorithm,
		KeySpec:           "TPM2_KEYEDHASH",
	}, nil
}

// WrapKey wraps key material into a TPM2 duplication blob bound to the SRK.
//
// It builds a duplicable sealed-keyedhash object holding keyMaterial, computes
// its Name, and calls TPM2_CreateDuplicate against the SRK encapsulation key.
// The resulting public area, duplication blob, and encrypted seed are returned
// in WrappedKeyMaterial. This operation is performed locally: the TPM is only
// read for the SRK public area.
func (b *Backend) WrapKey(ctx context.Context, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrNotInitialized
	}
	if len(keyMaterial) == 0 {
		return nil, &errs.Detail{Err: ErrInvalidKeyAttributes, Detail: "key material is empty"}
	}
	if params == nil {
		return nil, &errs.Detail{Err: ErrInvalidKeyAttributes, Detail: "import parameters are nil"}
	}
	if params.Algorithm != importExportAlgorithm {
		return nil, &errs.Detail{Err: ErrUnsupportedOperation, Detail: params.Algorithm.String()}
	}

	_, srkPub, err := b.srkPublicContents()
	if err != nil {
		return nil, err
	}

	encKey, err := tpm2.ImportEncapsulationKey(&srkPub)
	if err != nil {
		return nil, &errs.Detail{Err: ErrUnsupportedOperation, Detail: fmt.Sprintf("failed to build SRK encapsulation key: %v", err)}
	}

	// Build the duplicable sealed object that holds the key material as its
	// keyedhash secret, then compute its Name (required to seed the outer
	// duplication HMAC).
	public, sensitive, err := b.buildSealedDuplicate(keyMaterial)
	if err != nil {
		return nil, err
	}
	name, err := tpm2.ObjectName(public)
	if err != nil {
		return nil, &errs.Detail{Err: ErrUnsupportedOperation, Detail: fmt.Sprintf("failed to compute object name: %v", err)}
	}

	duplicate, encSecret, err := tpm2.CreateDuplicate(b.tpm.RandomSource(), encKey, name.Buffer, sensitive)
	if err != nil {
		return nil, &errs.Detail{Err: ErrUnsupportedOperation, Detail: fmt.Sprintf("failed to create duplication blob: %v", err)}
	}

	blob := duplicationBlob{
		Public:    tpm2.Marshal(*public),
		Duplicate: duplicate,
		EncSecret: encSecret,
	}
	encoded, err := json.Marshal(blob)
	if err != nil {
		return nil, &errs.Detail{Err: ErrUnsupportedOperation, Detail: fmt.Sprintf("failed to encode duplication blob: %v", err)}
	}

	return &backend.WrappedKeyMaterial{
		WrappedKey: encoded,
		Algorithm:  importExportAlgorithm,
		Metadata:   map[string]string{tpmDuplicateMetaKey: "1"},
	}, nil
}

// UnwrapKey recovers key material from a TPM2 duplication blob by importing it
// under the SRK and unsealing the resulting object.
//
// TPM2_Import decrypts the duplication blob under the SRK to yield the object's
// private area; the object is then loaded and unsealed to recover the original
// key material. All transient handles are flushed before returning.
func (b *Backend) UnwrapKey(ctx context.Context, wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrNotInitialized
	}
	if wrapped == nil || len(wrapped.WrappedKey) == 0 {
		return nil, &errs.Detail{Err: ErrInvalidKeyAttributes, Detail: "wrapped key material is empty"}
	}

	public, outPrivate, err := b.importDuplicate(wrapped.WrappedKey)
	if err != nil {
		return nil, err
	}

	return b.loadAndUnseal(public, outPrivate)
}

// ImportKey imports externally generated key material into the TPM and persists
// the resulting object's blobs under the supplied attributes' CN.
//
// The duplication blob is imported under the SRK; the imported public and
// private areas are saved to the key backend so the object is durably
// available for subsequent load/unseal operations.
func (b *Backend) ImportKey(ctx context.Context, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrNotInitialized
	}
	if attrs == nil {
		return ErrInvalidKeyAttributes
	}
	if wrapped == nil || len(wrapped.WrappedKey) == 0 {
		return &errs.Detail{Err: ErrInvalidKeyAttributes, Detail: "wrapped key material is empty"}
	}

	public, outPrivate, err := b.importDuplicate(wrapped.WrappedKey)
	if err != nil {
		return err
	}

	if attrs.Parent == nil {
		attrs.Parent = b.srkAttrs
	}
	attrs.StoreType = types.StoreTPM2

	publicBlob := tpm2.New2B(*public)
	if err := b.tpm.SaveKeyPair(attrs, outPrivate, publicBlob, b.keyBackend, true); err != nil {
		return &errs.Detail{Err: ErrUnsupportedOperation, Detail: fmt.Sprintf("failed to persist imported key: %v", err)}
	}
	return nil
}

// ExportKey is not supported: TPM2 storage objects created by this backend are
// fixedTPM/fixedParent and therefore non-duplicable. Use a duplicable object
// produced via WrapKey for cross-node transport instead.
func (b *Backend) ExportKey(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}
	if !attrs.Exportable {
		return nil, backend.ErrKeyNotExportable
	}
	return nil, &errs.Detail{Err: backend.ErrExportNotSupported, Detail: "TPM2 keys are hardware-bound and cannot be exported"}
}

// ExportKeyTo is not supported for the same reason ExportKey is not: this
// backend's storage objects are fixedTPM/fixedParent and non-duplicable, so
// there is no plaintext to wrap for a destination's parameters in the first
// place, let alone a TPM2 primitive that would wrap it under an externally
// supplied public key rather than a loaded TPM object.
func (b *Backend) ExportKeyTo(ctx context.Context, attrs *types.KeyAttributes, dstParams *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}
	if dstParams == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "destination import parameters cannot be nil"}
	}
	return nil, &errs.Detail{Err: backend.ErrExportToUnsupported, Detail: "TPM2 keys are hardware-bound and cannot be re-wrapped for a foreign destination"}
}

// ExportKeyMaterial is not supported: TPM2 keys never release plaintext private
// material outside the hardware boundary.
func (b *Backend) ExportKeyMaterial(ctx context.Context, attrs *types.KeyAttributes) ([]byte, error) {
	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}
	return nil, &errs.Detail{Err: backend.ErrExportNotSupported, Detail: "TPM2 keys cannot release raw material"}
}

// buildSealedDuplicate constructs the duplicable sealed-keyedhash object whose
// keyedhash secret is keyMaterial. It returns the object's public area and the
// marshaled TPMTSensitive that TPM2_CreateDuplicate wraps.
//
// The object is duplicable: FixedTPM and FixedParent are false, which is
// required for the duplication/import protocol. The unique field is the
// canonical KEYEDHASH unique = H_nameAlg(obfuscation || secret) per TCG Part 1.
func (b *Backend) buildSealedDuplicate(keyMaterial []byte) (*tpm2.TPMTPublic, []byte, error) {
	obfuscation := make([]byte, sha256.Size)
	if _, err := b.tpm.RandomSource().Read(obfuscation); err != nil {
		return nil, nil, &errs.Detail{Err: ErrUnsupportedOperation, Detail: fmt.Sprintf("failed to read obfuscation: %v", err)}
	}

	uniqueHash := sha256.New()
	uniqueHash.Write(obfuscation)
	uniqueHash.Write(keyMaterial)

	public := &tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			UserWithAuth: true,
			NoDA:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{}),
		Unique:     tpm2.NewTPMUPublicID(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BDigest{Buffer: uniqueHash.Sum(nil)}),
	}

	sensitive := tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgKeyedHash,
		SeedValue:     tpm2.TPM2BDigest{Buffer: obfuscation},
		Sensitive: tpm2.NewTPMUSensitiveComposite(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BSensitiveData{
			Buffer: keyMaterial,
		}),
	}

	return public, tpm2.Marshal(sensitive), nil
}

// importDuplicate decodes a duplication blob and runs TPM2_Import under the SRK,
// returning the imported object's public area and private blob. The caller owns
// the returned private blob and must load/persist it as appropriate.
func (b *Backend) importDuplicate(encoded []byte) (*tpm2.TPMTPublic, tpm2.TPM2BPrivate, error) {
	var blob duplicationBlob
	if err := json.Unmarshal(encoded, &blob); err != nil {
		return nil, tpm2.TPM2BPrivate{}, &errs.Detail{Err: ErrInvalidKeyAttributes, Detail: fmt.Sprintf("failed to decode duplication blob: %v", err)}
	}

	public, err := tpm2.Unmarshal[tpm2.TPMTPublic](blob.Public)
	if err != nil {
		return nil, tpm2.TPM2BPrivate{}, &errs.Detail{Err: ErrInvalidKeyAttributes, Detail: fmt.Sprintf("failed to parse duplicated public: %v", err)}
	}

	srkName, _, err := b.srkPublicContents()
	if err != nil {
		return nil, tpm2.TPM2BPrivate{}, err
	}

	// Authorize the SRK parent for Import. The imported object's parent is the
	// SRK, so a session built from the SRK attributes satisfies its policy.
	importAttrs := &types.KeyAttributes{
		CN:        "tpm2-import",
		StoreType: types.StoreTPM2,
		Parent:    b.srkAttrs,
	}
	session, closer, err := b.tpm.CreateSession(importAttrs)
	if err != nil {
		return nil, tpm2.TPM2BPrivate{}, &errs.Detail{Err: ErrSessionCreationFailed, Detail: fmt.Sprintf("%v", err)}
	}
	defer func() { _ = closer() }()

	imp, err := tpm2.Import{
		ParentHandle: tpm2.AuthHandle{
			Handle: b.srkAttrs.TPMAttributes.Handle,
			Name:   srkName,
			Auth:   session,
		},
		ObjectPublic: tpm2.New2B(*public),
		Duplicate:    tpm2.TPM2BPrivate{Buffer: blob.Duplicate},
		InSymSeed:    tpm2.TPM2BEncryptedSecret{Buffer: blob.EncSecret},
	}.Execute(b.tpm.Transport())
	if err != nil {
		return nil, tpm2.TPM2BPrivate{}, &errs.Detail{Err: ErrUnsupportedOperation, Detail: fmt.Sprintf("TPM2_Import failed: %v", err)}
	}

	return public, imp.OutPrivate, nil
}

// loadAndUnseal loads an imported keyedhash object under the SRK and unseals it,
// returning the recovered key material. All transient handles are flushed.
func (b *Backend) loadAndUnseal(public *tpm2.TPMTPublic, outPrivate tpm2.TPM2BPrivate) ([]byte, error) {
	srkName, _, err := b.srkPublicContents()
	if err != nil {
		return nil, err
	}

	loadAttrs := &types.KeyAttributes{
		CN:        "tpm2-import",
		StoreType: types.StoreTPM2,
		Parent:    b.srkAttrs,
	}
	loadSession, loadCloser, err := b.tpm.CreateSession(loadAttrs)
	if err != nil {
		return nil, &errs.Detail{Err: ErrSessionCreationFailed, Detail: fmt.Sprintf("%v", err)}
	}

	loadResp, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: b.srkAttrs.TPMAttributes.Handle,
			Name:   srkName,
			Auth:   loadSession,
		},
		InPublic:  tpm2.New2B(*public),
		InPrivate: outPrivate,
	}.Execute(b.tpm.Transport())
	_ = loadCloser()
	if err != nil {
		return nil, &errs.Detail{Err: ErrUnsupportedOperation, Detail: fmt.Sprintf("failed to load imported object: %v", err)}
	}
	defer b.tpm.Flush(loadResp.ObjectHandle)

	unseal, err := tpm2.Unseal{
		ItemHandle: tpm2.NamedHandle{
			Handle: loadResp.ObjectHandle,
			Name:   loadResp.Name,
		},
	}.Execute(b.tpm.Transport())
	if err != nil {
		return nil, &errs.Detail{Err: ErrUnsupportedOperation, Detail: fmt.Sprintf("failed to unseal imported object: %v", err)}
	}

	return unseal.OutData.Buffer, nil
}
