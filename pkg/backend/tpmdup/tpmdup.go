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

// Package tpmdup builds TCG TPM2_Duplicate blobs (TPM 2.0 Part 1, 23.3) for a
// destination TPM's Storage Root Key without a TPM: it needs only the SRK's
// marshaled TPMT_PUBLIC. The TPM 2.0 backend's WrapKey and any non-TPM source
// exporting to a TPM 2.0 destination share it, so both produce the blob the
// TPM 2.0 backend's ImportKey accepts.
package tpmdup

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// Algorithm is the wrapping algorithm a TPM 2.0 destination imports with.
const Algorithm = backend.WrappingAlgorithmTPM2Duplicate

// MetadataKey marks WrappedKeyMaterial.Metadata of a duplication blob.
const MetadataKey = "tpm2_duplicate_blob"

// ErrWrap is returned (wrapped) when a duplication blob cannot be built.
var ErrWrap = errors.New("tpmdup: cannot build duplication blob")

// Blob is the JSON envelope of a duplication: the three TPM2_Import inputs.
type Blob struct {
	// Public is the marshaled TPMTPublic of the duplicated sealed object.
	Public []byte `json:"public"`

	// Duplicate is the outer-wrapped private area (the duplication blob).
	Duplicate []byte `json:"duplicate"`

	// EncSecret is the seed protected by the SRK's asymmetric algorithm.
	EncSecret []byte `json:"enc_secret"`
}

// Wrap seals keyMaterial as a duplicable keyedhash object and duplicates it
// to the SRK whose marshaled TPMT_PUBLIC is srkPublic, drawing the
// obfuscation value and the duplication seed from rand.
func Wrap(rand io.Reader, srkPublic []byte, keyMaterial []byte) (*backend.WrappedKeyMaterial, error) {
	if len(keyMaterial) == 0 {
		return nil, &errs.Detail{Err: ErrWrap, Detail: "key material is empty"}
	}
	srkPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](srkPublic)
	if err != nil {
		return nil, &errs.Detail{Err: ErrWrap, Detail: fmt.Sprintf("failed to parse SRK public area: %v", err)}
	}
	encKey, err := tpm2.ImportEncapsulationKey(srkPub)
	if err != nil {
		return nil, &errs.Detail{Err: ErrWrap, Detail: fmt.Sprintf("failed to build SRK encapsulation key: %v", err)}
	}

	// Build the duplicable sealed object that holds the key material as its
	// keyedhash secret, then compute its Name (required to seed the outer
	// duplication HMAC).
	public, sensitive, err := sealedObject(rand, keyMaterial)
	if err != nil {
		return nil, err
	}
	name, err := tpm2.ObjectName(public)
	if err != nil {
		return nil, &errs.Detail{Err: ErrWrap, Detail: fmt.Sprintf("failed to compute object name: %v", err)}
	}

	duplicate, encSecret, err := tpm2.CreateDuplicate(rand, encKey, name.Buffer, sensitive)
	if err != nil {
		return nil, &errs.Detail{Err: ErrWrap, Detail: fmt.Sprintf("failed to create duplication blob: %v", err)}
	}

	encoded, err := json.Marshal(Blob{
		Public:    tpm2.Marshal(*public),
		Duplicate: duplicate,
		EncSecret: encSecret,
	})
	if err != nil {
		return nil, &errs.Detail{Err: ErrWrap, Detail: fmt.Sprintf("failed to encode duplication blob: %v", err)}
	}

	return &backend.WrappedKeyMaterial{
		WrappedKey: encoded,
		Algorithm:  Algorithm,
		Metadata:   map[string]string{MetadataKey: "1"},
	}, nil
}

// sealedObject returns the public area and marshaled sensitive area of a
// keyedhash sealed object holding keyMaterial.
func sealedObject(rand io.Reader, keyMaterial []byte) (*tpm2.TPMTPublic, []byte, error) {
	obfuscation := make([]byte, sha256.Size)
	if _, err := io.ReadFull(rand, obfuscation); err != nil {
		return nil, nil, &errs.Detail{Err: ErrWrap, Detail: fmt.Sprintf("failed to read obfuscation: %v", err)}
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
