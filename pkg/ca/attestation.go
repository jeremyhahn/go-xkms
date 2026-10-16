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

// Package ca provides TPM attestation import and verification operations
// for the TrustedCA certificate authority. These methods persist quotes,
// event logs and PCR snapshots to the object store along with a CA-produced
// signature that can be re-checked by VerifyAttestationQuote,
// VerifyAttestationEventLog and VerifyAttestationPCRs.
//
// # Storage Layout
//
// Attestation blobs live under the object store prefix "attestation/{cn}/{type}"
// with three sibling entries per blob:
//
//   - "<prefix>/data"      raw blob bytes as presented
//   - "<prefix>/digest"    SHA-256 digest of the blob
//   - "<prefix>/signature" CA signature over the digest
//
// The AK certificate itself is persisted under
// "attestation/{cn}/ak-cert.der" and its digest/signature alongside.
package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Attestation blob-type identifiers.
const (
	AttestBlobQuote    = "quote"
	AttestBlobEventLog = "eventlog"
	AttestBlobPCRs     = "pcrs"
	AttestBlobRoot     = "attestation"
)

// Attestation errors that supplement the base revocation/certificate errors.
var (
	// ErrInvalidAttestationBlobType indicates an unrecognised blob type
	// identifier was supplied to ImportAttestation or VerifyAttestation*.
	ErrInvalidAttestationBlobType = &errs.Message{Msg: "ca: invalid attestation blob type"}

	// ErrInvalidNonce indicates the nonce supplied to VerifyQuote did not
	// match the nonce returned by the TPM.
	ErrInvalidNonce = &errs.Message{Msg: "ca: invalid nonce in quote"}

	// ErrInvalidRequest indicates required parameters (KeyAttributes, data,
	// etc.) were missing or empty on an attestation call.
	ErrInvalidRequest = &errs.Message{Msg: "ca: invalid request"}
)

// ImportAttestation stores a TPM attestation blob (quote, event log or PCRs)
// together with a CA-produced signature that VerifyAttestation* can use to
// detect tampering. The blob type must be one of the AttestBlob* constants.
//
// Requires the object store to be configured.
//
// Thread-safe: Yes
func (ca *CA) ImportAttestation(ctx context.Context, akAttrs *types.KeyAttributes, blobType string, data []byte) error {
	if akAttrs == nil {
		return ErrInvalidRequest
	}
	if len(data) == 0 {
		return ErrInvalidRequest
	}
	if ca.objectStore == nil {
		return ErrObjectStoreRequired
	}

	blobKey, err := ca.attestationBlobKey(akAttrs.CN, blobType)
	if err != nil {
		return err
	}

	digest := sha256.Sum256(data)

	signer, err := ca.Signer(ctx)
	if err != nil {
		return &errs.Detail{Err: ErrSigningFailed, Detail: fmt.Sprintf("failed to get CA signer: %v", err)}
	}
	hashFunc := ca.getSigningHashFunc()
	signature, err := signer.Sign(nil, digest[:], hashFunc)
	if err != nil {
		return &errs.Detail{Err: ErrSigningFailed, Detail: fmt.Sprintf("failed to sign attestation data: %v", err)}
	}

	dataKey := fmt.Sprintf("%s/%s/data", AttestBlobRoot, blobKey)
	sigKey := fmt.Sprintf("%s/%s/signature", AttestBlobRoot, blobKey)
	digestKey := fmt.Sprintf("%s/%s/digest", AttestBlobRoot, blobKey)

	if err := ca.objectStore.Set([]byte(dataKey), data); err != nil {
		return &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("failed to store attestation data: %v", err)}
	}
	if err := ca.objectStore.Set([]byte(sigKey), signature); err != nil {
		return &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("failed to store attestation signature: %v", err)}
	}
	if err := ca.objectStore.Set([]byte(digestKey), digest[:]); err != nil {
		return &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("failed to store attestation digest: %v", err)}
	}
	return nil
}

// ImportAttestationKeyCertificate stores a DER-encoded Attestation Key
// certificate in the object store and also imports it into the standard
// certificate store so it participates in chain building operations.
//
// Thread-safe: Yes
func (ca *CA) ImportAttestationKeyCertificate(ctx context.Context, attrs *types.KeyAttributes, akDER []byte) error {
	if attrs == nil {
		return ErrInvalidRequest
	}
	if len(akDER) == 0 {
		return ErrInvalidCertificate
	}
	if ca.objectStore == nil {
		return ErrObjectStoreRequired
	}

	cert, err := x509.ParseCertificate(akDER)
	if err != nil {
		return &errs.Detail{Err: ErrInvalidCertificate, Detail: fmt.Sprintf("failed to parse AK certificate: %v", err)}
	}

	certKey := fmt.Sprintf("%s/%s/ak-cert.der", AttestBlobRoot, attrs.CN)
	if err := ca.objectStore.Set([]byte(certKey), akDER); err != nil {
		return &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("failed to store AK certificate: %v", err)}
	}

	digest := sha256.Sum256(akDER)
	digestKey := fmt.Sprintf("%s/%s/ak-cert.digest", AttestBlobRoot, attrs.CN)
	if err := ca.objectStore.Set([]byte(digestKey), digest[:]); err != nil {
		return &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("failed to store AK certificate digest: %v", err)}
	}

	signer, err := ca.Signer(ctx)
	if err != nil {
		return &errs.Detail{Err: ErrSigningFailed, Detail: fmt.Sprintf("failed to get CA signer: %v", err)}
	}
	hashFunc := ca.getSigningHashFunc()
	signature, err := signer.Sign(nil, digest[:], hashFunc)
	if err != nil {
		return &errs.Detail{Err: ErrSigningFailed, Detail: fmt.Sprintf("failed to sign AK certificate: %v", err)}
	}
	sigKey := fmt.Sprintf("%s/%s/ak-cert.sig", AttestBlobRoot, attrs.CN)
	if err := ca.objectStore.Set([]byte(sigKey), signature); err != nil {
		return &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("failed to store AK certificate signature: %v", err)}
	}

	return ca.ImportCertificate(ctx, cert)
}

// ImportAttestationEventLog is a convenience wrapper around ImportAttestation
// for event-log blobs.
func (ca *CA) ImportAttestationEventLog(ctx context.Context, akAttrs *types.KeyAttributes, eventLog []byte) error {
	return ca.ImportAttestation(ctx, akAttrs, AttestBlobEventLog, eventLog)
}

// ImportAttestationPCRs is a convenience wrapper around ImportAttestation
// for PCR-snapshot blobs.
func (ca *CA) ImportAttestationPCRs(ctx context.Context, akAttrs *types.KeyAttributes, pcrs []byte) error {
	return ca.ImportAttestation(ctx, akAttrs, AttestBlobPCRs, pcrs)
}

// ImportAttestationQuote is a convenience wrapper around ImportAttestation
// for quote blobs.
func (ca *CA) ImportAttestationQuote(ctx context.Context, akAttrs *types.KeyAttributes, quote []byte) error {
	return ca.ImportAttestation(ctx, akAttrs, AttestBlobQuote, quote)
}

// ImportLocalAttestation imports every component of a complete TPM quote
// (quote, optional event log, PCRs) in a single call. Missing event logs are
// accepted gracefully because some platforms (QEMU/OVMF + swtpm) do not
// surface a valid event log to the kernel.
//
// Thread-safe: Yes
func (ca *CA) ImportLocalAttestation(ctx context.Context, akAttrs *types.KeyAttributes, quote *tpm2.Quote) error {
	if quote == nil {
		return ErrInvalidRequest
	}
	if err := ca.ImportAttestationQuote(ctx, akAttrs, quote.Quoted); err != nil {
		return &errs.Wrapped{Msg: "failed to import quote", Err: err}
	}
	if len(quote.EventLog) > 0 {
		if err := ca.ImportAttestationEventLog(ctx, akAttrs, quote.EventLog); err != nil {
			return &errs.Wrapped{Msg: "failed to import event log", Err: err}
		}
	}
	if err := ca.ImportAttestationPCRs(ctx, akAttrs, quote.PCRs); err != nil {
		return &errs.Wrapped{Msg: "failed to import PCRs", Err: err}
	}
	return nil
}

// VerifyAttestationQuote verifies a previously imported quote blob by
// recomputing its digest, comparing against the stored digest, and
// re-verifying the CA's signature over that digest.
//
// Thread-safe: Yes
func (ca *CA) VerifyAttestationQuote(akAttrs *types.KeyAttributes, quote []byte) error {
	return ca.verifyStoredAttestation(akAttrs, AttestBlobQuote, quote)
}

// VerifyAttestationEventLog verifies a previously imported event log blob.
// See VerifyAttestationQuote for the verification semantics.
func (ca *CA) VerifyAttestationEventLog(akAttrs *types.KeyAttributes, eventLog []byte) error {
	return ca.verifyStoredAttestation(akAttrs, AttestBlobEventLog, eventLog)
}

// VerifyAttestationPCRs verifies a previously imported PCR snapshot.
// See VerifyAttestationQuote for the verification semantics.
func (ca *CA) VerifyAttestationPCRs(akAttrs *types.KeyAttributes, pcrs []byte) error {
	return ca.verifyStoredAttestation(akAttrs, AttestBlobPCRs, pcrs)
}

// verifyStoredAttestation is the shared engine behind the three
// VerifyAttestation* methods.
func (ca *CA) verifyStoredAttestation(akAttrs *types.KeyAttributes, blobType string, data []byte) error {
	if akAttrs == nil {
		return ErrInvalidRequest
	}
	if ca.objectStore == nil {
		return ErrObjectStoreRequired
	}

	blobKey, err := ca.attestationBlobKey(akAttrs.CN, blobType)
	if err != nil {
		return err
	}

	digestKey := fmt.Sprintf("%s/%s/digest", AttestBlobRoot, blobKey)
	storedDigest, err := ca.getObject(digestKey)
	if err != nil {
		return &errs.Detail{Err: ErrCertificateNotFound, Detail: fmt.Sprintf("attestation digest not found: %v", err)}
	}

	newDigest := sha256.Sum256(data)
	if !bytes.Equal(storedDigest, newDigest[:]) {
		return &errs.Detail{Err: ErrInvalidSignature, Detail: "attestation data mismatch"}
	}

	sigKey := fmt.Sprintf("%s/%s/signature", AttestBlobRoot, blobKey)
	storedSig, err := ca.getObject(sigKey)
	if err != nil {
		return &errs.Detail{Err: ErrCertificateNotFound, Detail: fmt.Sprintf("attestation signature not found: %v", err)}
	}

	caPublic := ca.Public()
	return verifyCASignature(caPublic, newDigest[:], storedSig)
}

// verifyCASignature applies the correct signature-verification algorithm
// based on the CA's public-key type.
func verifyCASignature(pub crypto.PublicKey, digest, signature []byte) error {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		// Prefer RSA-PSS (the default used by ImportAttestation's signer.Sign
		// path); fall back to PKCS1v15 to remain compatible with historical
		// entries.
		pssOpts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		}
		if err := rsa.VerifyPSS(key, crypto.SHA256, digest, signature, pssOpts); err == nil {
			return nil
		}
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest, signature); err != nil {
			return ErrInvalidSignature
		}
		return nil
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest, signature) {
			return ErrInvalidSignature
		}
		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(key, digest, signature) {
			return ErrInvalidSignature
		}
		return nil
	default:
		return &errs.Detail{Err: ErrInvalidSignature, Detail: fmt.Sprintf("unsupported CA key type %T", pub)}
	}
}

// getSigningHashFunc returns the appropriate hash algorithm to use when
// signing attestation digests given the CA's current key type. Ed25519
// signs unhashed messages so hash==0 is returned.
func (ca *CA) getSigningHashFunc() crypto.Hash {
	switch ca.Public().(type) {
	case ed25519.PublicKey:
		return crypto.Hash(0)
	default:
		return crypto.SHA256
	}
}

// attestationBlobKey constructs the path component used under
// "attestation/" for the given CN and blob type.
func (ca *CA) attestationBlobKey(cn, blobType string) (string, error) {
	switch blobType {
	case AttestBlobQuote, AttestBlobEventLog, AttestBlobPCRs:
		// ok
	default:
		return "", ErrInvalidAttestationBlobType
	}

	safeCN := strings.ReplaceAll(cn, " ", "-")
	safeCN = strings.ReplaceAll(safeCN, "/", "-")
	if safeCN == "" {
		h := sha256.Sum256([]byte("default-attestation-key"))
		safeCN = hex.EncodeToString(h[:8])
	}
	return fmt.Sprintf("%s/%s", safeCN, blobType), nil
}

// readBlobData returns the raw bytes stored under key in the object store.
