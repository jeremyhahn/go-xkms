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

package store

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cespare/xxhash/v2"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// SignerStore implements SignerStorer using a go-qrdb GenericDAO for
// signer persistence and a separate DAO for signature storage.
// The storage.Backend interface is compatible with external object storage
// libraries like go-objstore.
type SignerStore struct {
	logger *slog.Logger
	dao    qrdbsdk.GenericDAO[*SignerEntry]
	sigDAO qrdbsdk.GenericDAO[*SignatureEntry]
	idGen  *signerEntryIDGenerator
}

// Compile-time interface compliance checks: SignerStore satisfies
// SignerStorer, and its Checksum method alone satisfies types.ChecksumProvider
// so it can be handed directly to a types.SimpleVerifier performing
// IntegrityCheck.
var (
	_ SignerStorer           = (*SignerStore)(nil)
	_ types.ChecksumProvider = (*SignerStore)(nil)
)

// NewSignerStore creates a new signer store using the storage.Backend interface.
// The backend can be any implementation of storage.Backend, including custom
// adapters that wrap external storage libraries like go-objstore.
func NewSignerStore(logger *slog.Logger, backend storage.Backend) SignerStorer {
	kvStore, err := kvadapter.New(backend)
	if err != nil {
		// Backend should never be nil when called correctly. If it is, fall
		// back to a no-op store that returns errors. In practice this path
		// should not be hit since callers validate inputs.
		if logger != nil {
			logger.Error("failed to create KVStore adapter for signer store", slog.String("error", err.Error()))
		}
		return &SignerStore{logger: logger}
	}

	idGen := &signerEntryIDGenerator{}

	signerDAO, daoErr := qrdbsdk.NewDAO(
		kvStore,
		"signers",
		func() *SignerEntry { return &SignerEntry{} },
		qrdbsdk.WithIDGenerator(idGen),
	)
	if daoErr != nil {
		if logger != nil {
			logger.Error("failed to create signer DAO", slog.String("error", daoErr.Error()))
		}
		return &SignerStore{logger: logger}
	}

	sigDAO, sigErr := qrdbsdk.NewDAO(
		kvStore,
		"signatures",
		func() *SignatureEntry { return &SignatureEntry{} },
		qrdbsdk.WithIDGenerator(idGen),
	)
	if sigErr != nil {
		if logger != nil {
			logger.Error("failed to create signature DAO", slog.String("error", sigErr.Error()))
		}
		return &SignerStore{logger: logger, dao: signerDAO}
	}

	return &SignerStore{
		logger: logger,
		dao:    signerDAO,
		sigDAO: sigDAO,
		idGen:  idGen,
	}
}

// computeSignerID computes the deterministic entity ID for a CN.
func computeSignerID(cn string) uint64 {
	return xxhash.Sum64String(cn)
}

// decodePEM decodes a PEM block. It is a local, minimal copy of
// pkg/tpm2/store's DecodePEM: duplicated rather than imported, since
// importing pkg/tpm2/store for one three-line helper would reintroduce the
// TPM2 package dependency this package exists to avoid.
func decodePEM(data []byte) (*pem.Block, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, &errs.Message{Msg: "failed to decode PEM block"}
	}
	return block, nil
}

// Get retrieves a crypto.Signer from storage.
func (s *SignerStore) Get(attrs *types.KeyAttributes) (interface{}, error) {
	if s.dao == nil {
		return nil, ErrSignerStoreNotInitialized
	}

	entryID := computeSignerID(attrs.CN)
	entry, err := s.dao.Get(context.Background(), entryID)
	if err != nil {
		if qrdbsdk.IsDAONotFound(err) {
			return nil, &ErrSignerNotFound{CN: attrs.CN}
		}
		return nil, &ErrSignerGet{CN: attrs.CN, Cause: err}
	}

	// Decode PEM
	block, pemErr := decodePEM(entry.KeyPEM)
	if pemErr != nil {
		return nil, &ErrSignerPEMDecode{CN: attrs.CN, Cause: pemErr}
	}

	// Parse private key based on algorithm.
	return parsePrivateKey(attrs, block)
}

// Save stores a crypto.Signer to storage.
func (s *SignerStore) Save(attrs *types.KeyAttributes, signer interface{}) error {
	if s.dao == nil {
		return ErrSignerStoreNotInitialized
	}

	if signer == nil {
		return &ErrSignerNil{CN: attrs.CN}
	}

	// Extract the private key from the signer.
	privateKey, err := extractPrivateKey(attrs.CN, signer)
	if err != nil {
		return err
	}

	// Marshal to PKCS8 format.
	keyData, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return &ErrSignerMarshal{CN: attrs.CN, Cause: err}
	}

	// Encode to PEM.
	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyData,
	}
	pemData := pem.EncodeToMemory(pemBlock)

	// Create entry with deterministic ID.
	entry := &SignerEntry{
		CN:        attrs.CN,
		KeyPEM:    pemData,
		Algorithm: attrs.KeyAlgorithm.String(),
	}
	entry.SetEntityID(computeSignerID(attrs.CN))

	if err := s.dao.Save(context.Background(), entry); err != nil {
		return &ErrSignerSave{CN: attrs.CN, Cause: err}
	}

	if s.logger != nil {
		s.logger.Debug("saved signer", slog.String("cn", attrs.CN))
	}

	return nil
}

// Delete removes a crypto.Signer from storage.
func (s *SignerStore) Delete(attrs *types.KeyAttributes) error {
	if s.dao == nil {
		return ErrSignerStoreNotInitialized
	}

	entryID := computeSignerID(attrs.CN)

	stub := &SignerEntry{}
	stub.SetEntityID(entryID)
	if err := s.dao.Delete(context.Background(), stub); err != nil {
		// DAO Delete is idempotent for the underlying kvstore, but we check
		// for real errors. Not-found is not an error for delete operations.
		if !qrdbsdk.IsDAONotFound(err) {
			return &ErrSignerDelete{CN: attrs.CN, Cause: err}
		}
		if s.logger != nil {
			s.logger.Debug("signer not found for deletion", slog.String("cn", attrs.CN))
		}
	}

	if s.logger != nil {
		s.logger.Debug("deleted signer", slog.String("cn", attrs.CN))
	}

	return nil
}

// signatureKey computes the storage key for a persisted signature record,
// combining the signing key's CN with the optional blob CN. GetSignature and
// Checksum must compute this identically to SaveSignature to read back what
// it wrote.
func signatureKey(cn, blobCN string) string {
	if blobCN != "" {
		return fmt.Sprintf("%s.%s.sig", cn, blobCN)
	}
	return fmt.Sprintf("%s.sig", cn)
}

// SaveSignature stores a signature and digest for auditing/verification purposes.
func (s *SignerStore) SaveSignature(opts *SignerOpts, signature, digest []byte) error {
	if opts == nil || opts.KeyAttributes == nil {
		return ErrInvalidSignerOpts
	}

	if s.sigDAO == nil {
		return ErrSignerStoreNotInitialized
	}

	key := signatureKey(opts.KeyAttributes.CN, opts.BlobCN)

	// Store signature and digest together.
	data := fmt.Sprintf("digest=%x\nsignature=%x\n", digest, signature)

	entry := &SignatureEntry{
		Key:  key,
		Data: data,
	}
	entry.SetEntityID(computeSignerID(key))

	if err := s.sigDAO.Save(context.Background(), entry); err != nil {
		return &ErrSignatureSave{Key: key, Cause: err}
	}

	if s.logger != nil {
		s.logger.Debug("saved signature", slog.String("key", key))
	}

	return nil
}

// GetSignature retrieves the digest and signature persisted by a prior
// SaveSignature call for the same key attributes and blob CN.
func (s *SignerStore) GetSignature(opts *SignerOpts) (digest, signature []byte, err error) {
	if opts == nil || opts.KeyAttributes == nil {
		return nil, nil, ErrInvalidSignerOpts
	}

	if s.sigDAO == nil {
		return nil, nil, ErrSignerStoreNotInitialized
	}

	key := signatureKey(opts.KeyAttributes.CN, opts.BlobCN)
	entryID := computeSignerID(key)

	entry, getErr := s.sigDAO.Get(context.Background(), entryID)
	if getErr != nil {
		if qrdbsdk.IsDAONotFound(getErr) {
			return nil, nil, &ErrSignatureNotFound{Key: key}
		}
		return nil, nil, &ErrSignatureGet{Key: key, Cause: getErr}
	}

	digest, signature, parseErr := parseSignatureData(entry.Data)
	if parseErr != nil {
		return nil, nil, &ErrSignatureParse{Key: key, Cause: parseErr}
	}

	if s.logger != nil {
		s.logger.Debug("read signature", slog.String("key", key))
	}

	return digest, signature, nil
}

// Checksum implements types.ChecksumProvider. It retrieves the digest
// persisted for opts.KeyAttributes.CN and opts.BlobCN, so a SignerStore can
// serve as the checksum source for a types.SimpleVerifier performing
// IntegrityCheck.
func (s *SignerStore) Checksum(opts *types.VerifyOpts) ([]byte, error) {
	if opts == nil || opts.KeyAttributes == nil {
		return nil, ErrInvalidSignerOpts
	}

	digest, _, err := s.GetSignature(&SignerOpts{
		KeyAttributes: opts.KeyAttributes,
		BlobCN:        opts.BlobCN,
	})
	if err != nil {
		return nil, err
	}

	return digest, nil
}

// parseSignatureData decodes the "digest=<hex>\nsignature=<hex>\n" record
// SaveSignature writes back into its digest and signature components.
func parseSignatureData(data string) (digest, signature []byte, err error) {
	for _, line := range strings.Split(strings.TrimRight(data, "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "digest="):
			digest, err = hex.DecodeString(strings.TrimPrefix(line, "digest="))
			if err != nil {
				return nil, nil, err
			}
		case strings.HasPrefix(line, "signature="):
			signature, err = hex.DecodeString(strings.TrimPrefix(line, "signature="))
			if err != nil {
				return nil, nil, err
			}
		}
	}

	if digest == nil || signature == nil {
		return nil, nil, ErrMalformedSignatureData
	}

	return digest, signature, nil
}

// parsePrivateKey parses a PEM-decoded private key block based on the key algorithm.
func parsePrivateKey(attrs *types.KeyAttributes, block *pem.Block) (crypto.Signer, error) {
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return parseRSAKey(attrs.CN, block)
	case x509.ECDSA:
		return parseECDSAKey(attrs.CN, block)
	case x509.Ed25519:
		return parseEd25519Key(attrs.CN, block)
	default:
		return nil, &ErrUnsupportedAlgorithm{CN: attrs.CN, Algorithm: attrs.KeyAlgorithm}
	}
}

// parseRSAKey parses an RSA private key from a PEM block.
func parseRSAKey(cn string, block *pem.Block) (*rsa.PrivateKey, error) {
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS1 format as fallback.
		rsaKey, rsaErr := x509.ParsePKCS1PrivateKey(block.Bytes)
		if rsaErr != nil {
			return nil, &ErrSignerKeyParse{CN: cn, Algorithm: "RSA", Cause: rsaErr, FallbackCause: err}
		}
		return rsaKey, nil
	}

	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, &ErrSignerKeyTypeMismatch{CN: cn, Expected: "RSA", Actual: fmt.Sprintf("%T", privateKey)}
	}
	return rsaKey, nil
}

// parseECDSAKey parses an ECDSA private key from a PEM block.
func parseECDSAKey(cn string, block *pem.Block) (*ecdsa.PrivateKey, error) {
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try EC format as fallback.
		ecKey, ecErr := x509.ParseECPrivateKey(block.Bytes)
		if ecErr != nil {
			return nil, &ErrSignerKeyParse{CN: cn, Algorithm: "ECDSA", Cause: ecErr, FallbackCause: err}
		}
		return ecKey, nil
	}

	ecKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, &ErrSignerKeyTypeMismatch{CN: cn, Expected: "ECDSA", Actual: fmt.Sprintf("%T", privateKey)}
	}
	return ecKey, nil
}

// parseEd25519Key parses an Ed25519 private key from a PEM block.
func parseEd25519Key(cn string, block *pem.Block) (ed25519.PrivateKey, error) {
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, &ErrSignerKeyParse{CN: cn, Algorithm: "Ed25519", Cause: err}
	}

	ed25519Key, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, &ErrSignerKeyTypeMismatch{CN: cn, Expected: "Ed25519", Actual: fmt.Sprintf("%T", privateKey)}
	}
	return ed25519Key, nil
}

// extractPrivateKey extracts the private key material from a signer value.
func extractPrivateKey(cn string, signer interface{}) (interface{}, error) {
	switch v := signer.(type) {
	case *rsa.PrivateKey:
		return v, nil
	case *ecdsa.PrivateKey:
		return v, nil
	case ed25519.PrivateKey:
		return v, nil
	case crypto.Signer:
		return extractFromCryptoSigner(cn, v)
	default:
		return nil, &ErrUnsupportedSignerType{CN: cn, Type: fmt.Sprintf("%T", signer)}
	}
}

// extractFromCryptoSigner extracts the private key from a crypto.Signer interface.
func extractFromCryptoSigner(cn string, signer crypto.Signer) (interface{}, error) {
	switch signer.Public().(type) {
	case *rsa.PublicKey:
		if rsaKey, ok := signer.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, &ErrSignerExtract{CN: cn, Algorithm: "RSA"}
	case *ecdsa.PublicKey:
		if ecKey, ok := signer.(*ecdsa.PrivateKey); ok {
			return ecKey, nil
		}
		return nil, &ErrSignerExtract{CN: cn, Algorithm: "ECDSA"}
	case ed25519.PublicKey:
		if edKey, ok := signer.(ed25519.PrivateKey); ok {
			return edKey, nil
		}
		return nil, &ErrSignerExtract{CN: cn, Algorithm: "Ed25519"}
	default:
		return nil, &ErrUnsupportedPublicKeyType{CN: cn, Type: fmt.Sprintf("%T", signer.Public())}
	}
}
