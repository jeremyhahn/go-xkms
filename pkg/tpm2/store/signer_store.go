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
	"encoding/pem"
	"fmt"
	"log/slog"

	"github.com/cespare/xxhash/v2"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
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
	block, pemErr := DecodePEM(entry.KeyPEM)
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

// SaveSignature stores a signature and digest for auditing/verification purposes.
func (s *SignerStore) SaveSignature(opts *SignerOpts, signature, digest []byte) error {
	if opts == nil || opts.KeyAttributes == nil {
		return ErrInvalidSignerOpts
	}

	if s.sigDAO == nil {
		return ErrSignerStoreNotInitialized
	}

	// Create a unique key for the signature using CN and blob CN if available.
	var key string
	if opts.BlobCN != nil && *opts.BlobCN != "" {
		key = fmt.Sprintf("%s.%s.sig", opts.KeyAttributes.CN, *opts.BlobCN)
	} else {
		key = fmt.Sprintf("%s.sig", opts.KeyAttributes.CN)
	}

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
