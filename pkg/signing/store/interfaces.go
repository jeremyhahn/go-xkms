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

// Package store persists crypto.Signer key material and per-blob signature
// records on behalf of any xkms backend. It has no TPM (or other hardware)
// dependency: it reads and writes through the generic storage.Backend
// interface, the same one every backend already uses for certificate
// storage (pkg/xkms/keystore.go New wires SignerStore from the same
// storage.Backend as CertStorage), so it applies uniformly to every backend
// behind xkms.Backend -- TPM2, PKCS#11, cloud KMS, software, phone -- not
// only to TPM2. See docs/signing/architecture.md.
package store

import (
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// SignerOpts identifies the signing key and, when persisting or retrieving a
// signature record, the blob it was signed under.
type SignerOpts struct {
	// KeyAttributes specifies the signing key.
	KeyAttributes *types.KeyAttributes

	// BlobCN is the common name for the persisted signature/digest record.
	// Empty means "no blob CN" -- the record is keyed by KeyAttributes.CN
	// alone (see signatureKey).
	BlobCN string
}

// SignerStorer provides crypto.Signer storage and per-blob signature
// persistence operations.
type SignerStorer interface {
	// Get retrieves a crypto.Signer from storage.
	Get(attrs *types.KeyAttributes) (interface{}, error)

	// Save stores a crypto.Signer to storage.
	Save(attrs *types.KeyAttributes, signer interface{}) error

	// Delete removes a crypto.Signer from storage.
	Delete(attrs *types.KeyAttributes) error

	// SaveSignature persists the digest and signature produced for a signed
	// blob, keyed by opts.KeyAttributes.CN and opts.BlobCN.
	SaveSignature(opts *SignerOpts, signature, digest []byte) error

	// GetSignature retrieves the digest and signature persisted by a prior
	// SaveSignature call for the same key attributes and blob CN. Returns
	// ErrSignatureNotFound if no record exists.
	GetSignature(opts *SignerOpts) (digest, signature []byte, err error)

	// Checksum implements types.ChecksumProvider: it looks up the digest
	// persisted for opts.KeyAttributes.CN and opts.BlobCN, so a SignerStorer
	// can be used directly as the checksum source for a
	// types.SimpleVerifier performing IntegrityCheck.
	Checksum(opts *types.VerifyOpts) ([]byte, error)
}
