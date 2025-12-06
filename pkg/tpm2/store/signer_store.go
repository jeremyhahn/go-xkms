// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package store

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

const (
	// FSEXT_SIGNER is the file extension for stored signers
	FSEXT_SIGNER = ".signer"
)

// SignerStore implements SignerStorer using storage.Backend
//
// Deprecated: Use ObjStoreSignerAdapter instead, which provides direct integration
// with go-objstore for multi-backend support (S3, Azure, GCS, filesystem).
// Use NewStorageFactory or NewObjStoreSignerAdapter to create new signer stores.
type SignerStore struct {
	logger  Logger
	storage storage.Backend
}

// NewSignerStore creates a new signer store using the storage.Backend interface
//
// Deprecated: Use NewObjStoreSignerAdapter or NewStorageFactory instead for
// direct go-objstore integration with multi-backend support.
func NewSignerStore(logger Logger, backend storage.Backend) SignerStorer {
	return &SignerStore{
		logger:  logger,
		storage: backend,
	}
}

// Get retrieves a crypto.Signer from storage
func (s *SignerStore) Get(attrs *types.KeyAttributes) (interface{}, error) {
	key := attrs.CN + FSEXT_SIGNER
	data, err := s.storage.Get(key)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, fmt.Errorf("signer not found for %s: %w", attrs.CN, err)
		}
		return nil, fmt.Errorf("failed to get signer %s: %w", key, err)
	}

	// Decode PEM
	block, err := DecodePEM(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PEM for %s: %w", attrs.CN, err)
	}

	// Parse private key based on algorithm
	var signer crypto.Signer
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS1 format as fallback
			rsaKey, rsaErr := x509.ParsePKCS1PrivateKey(block.Bytes)
			if rsaErr != nil {
				return nil, fmt.Errorf("failed to parse RSA private key for %s: %w (pkcs8: %v)", attrs.CN, rsaErr, err)
			}
			signer = rsaKey
		} else {
			rsaKey, ok := privateKey.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("key is not an RSA private key for %s", attrs.CN)
			}
			signer = rsaKey
		}

	case x509.ECDSA:
		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			// Try EC format as fallback
			ecKey, ecErr := x509.ParseECPrivateKey(block.Bytes)
			if ecErr != nil {
				return nil, fmt.Errorf("failed to parse ECDSA private key for %s: %w (pkcs8: %v)", attrs.CN, ecErr, err)
			}
			signer = ecKey
		} else {
			ecKey, ok := privateKey.(*ecdsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("key is not an ECDSA private key for %s", attrs.CN)
			}
			signer = ecKey
		}

	case x509.Ed25519:
		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Ed25519 private key for %s: %w", attrs.CN, err)
		}
		ed25519Key, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an Ed25519 private key for %s", attrs.CN)
		}
		signer = ed25519Key

	default:
		return nil, fmt.Errorf("unsupported key algorithm for %s: %v", attrs.CN, attrs.KeyAlgorithm)
	}

	return signer, nil
}

// Save stores a crypto.Signer to storage
func (s *SignerStore) Save(attrs *types.KeyAttributes, signer interface{}) error {
	if signer == nil {
		return fmt.Errorf("signer is nil for %s", attrs.CN)
	}

	// Extract the private key from the signer
	var privateKey interface{}
	switch v := signer.(type) {
	case *rsa.PrivateKey:
		privateKey = v
	case *ecdsa.PrivateKey:
		privateKey = v
	case ed25519.PrivateKey:
		privateKey = v
	case crypto.Signer:
		// Try to extract the underlying key if it's wrapped
		switch key := v.Public().(type) {
		case *rsa.PublicKey:
			if rsaKey, ok := v.(*rsa.PrivateKey); ok {
				privateKey = rsaKey
			} else {
				return fmt.Errorf("unable to extract RSA private key from signer for %s", attrs.CN)
			}
		case *ecdsa.PublicKey:
			if ecKey, ok := v.(*ecdsa.PrivateKey); ok {
				privateKey = ecKey
			} else {
				return fmt.Errorf("unable to extract ECDSA private key from signer for %s", attrs.CN)
			}
		case ed25519.PublicKey:
			if edKey, ok := v.(ed25519.PrivateKey); ok {
				privateKey = edKey
			} else {
				return fmt.Errorf("unable to extract Ed25519 private key from signer for %s", attrs.CN)
			}
		default:
			return fmt.Errorf("unsupported public key type for %s: %T", attrs.CN, key)
		}
	default:
		return fmt.Errorf("unsupported signer type for %s: %T", attrs.CN, signer)
	}

	// Marshal to PKCS8 format
	keyData, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key for %s: %w", attrs.CN, err)
	}

	// Encode to PEM
	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyData,
	}
	pemData := pem.EncodeToMemory(pemBlock)

	// Store in backend
	key := attrs.CN + FSEXT_SIGNER
	if err := s.storage.Put(key, pemData, storage.DefaultOptions()); err != nil {
		return fmt.Errorf("failed to save signer %s: %w", key, err)
	}

	if s.logger != nil {
		s.logger.Debugf("Saved signer for %s", attrs.CN)
	}

	return nil
}

// Delete removes a crypto.Signer from storage
func (s *SignerStore) Delete(attrs *types.KeyAttributes) error {
	key := attrs.CN + FSEXT_SIGNER
	if err := s.storage.Delete(key); err != nil {
		if err != storage.ErrNotFound {
			return fmt.Errorf("failed to delete signer %s: %w", key, err)
		}
		// Not found is not an error for delete
		if s.logger != nil {
			s.logger.Debugf("Signer not found for deletion: %s", key)
		}
	}

	if s.logger != nil {
		s.logger.Debugf("Deleted signer for %s", attrs.CN)
	}

	return nil
}

// SaveSignature stores a signature and digest for auditing/verification purposes
func (s *SignerStore) SaveSignature(opts *SignerOpts, signature, digest []byte) error {
	if opts == nil || opts.KeyAttributes == nil {
		return ErrInvalidSignerOpts
	}

	// Create a unique key for the signature using CN and blob CN if available
	var key string
	if opts.BlobCN != nil && *opts.BlobCN != "" {
		key = fmt.Sprintf("%s.%s.sig", opts.KeyAttributes.CN, *opts.BlobCN)
	} else {
		key = fmt.Sprintf("%s.sig", opts.KeyAttributes.CN)
	}

	// Store signature and digest together
	data := fmt.Sprintf("digest=%x\nsignature=%x\n", digest, signature)

	if err := s.storage.Put(key, []byte(data), storage.DefaultOptions()); err != nil {
		return fmt.Errorf("failed to save signature %s: %w", key, err)
	}

	if s.logger != nil {
		s.logger.Debugf("Saved signature for %s", key)
	}

	return nil
}
