// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC

package store

import (
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestSignerOpts_HashFunc(t *testing.T) {
	t.Run("with key attributes", func(t *testing.T) {
		opts := &SignerOpts{
			KeyAttributes: &types.KeyAttributes{
				Hash: crypto.SHA256,
			},
		}

		result := opts.HashFunc()
		assert.Equal(t, crypto.SHA256, result)
	})

	t.Run("with SHA384", func(t *testing.T) {
		opts := &SignerOpts{
			KeyAttributes: &types.KeyAttributes{
				Hash: crypto.SHA384,
			},
		}

		result := opts.HashFunc()
		assert.Equal(t, crypto.SHA384, result)
	})

	t.Run("with SHA512", func(t *testing.T) {
		opts := &SignerOpts{
			KeyAttributes: &types.KeyAttributes{
				Hash: crypto.SHA512,
			},
		}

		result := opts.HashFunc()
		assert.Equal(t, crypto.SHA512, result)
	})

	t.Run("without key attributes", func(t *testing.T) {
		opts := &SignerOpts{}

		result := opts.HashFunc()
		assert.Equal(t, crypto.Hash(0), result)
	})

	t.Run("with nil key attributes", func(t *testing.T) {
		opts := &SignerOpts{
			KeyAttributes: nil,
		}

		result := opts.HashFunc()
		assert.Equal(t, crypto.Hash(0), result)
	})
}

func TestSignerOpts_FullConfiguration(t *testing.T) {
	blobCN := "test-blob"
	opts := &SignerOpts{
		KeyAttributes: &types.KeyAttributes{
			CN:                 "test-key",
			KeyAlgorithm:       x509.RSA,
			KeyType:            types.KeyTypeCA,
			Hash:               crypto.SHA256,
			SignatureAlgorithm: x509.SHA256WithRSAPSS,
		},
		Backend: nil,
		BlobCN:  &blobCN,
	}

	// Verify HashFunc works with full configuration
	assert.Equal(t, crypto.SHA256, opts.HashFunc())

	// Verify fields are accessible
	assert.Equal(t, "test-key", opts.KeyAttributes.CN)
	assert.Equal(t, "test-blob", *opts.BlobCN)
}

func TestFSExtensionConstants(t *testing.T) {
	// Verify the file extension constants
	assert.Equal(t, ".blob", FSEXT_PRIVATE_BLOB)
	assert.Equal(t, ".pub", FSEXT_PUBLIC_BLOB)
	assert.Equal(t, ".ctx", FSEXT_TPM_CONTEXT)
}

func TestErrorConstants(t *testing.T) {
	// Verify error constants are properly defined
	assert.NotNil(t, ErrCertNotFound)
	assert.NotNil(t, ErrCorruptCopy)
	assert.NotNil(t, ErrInvalidParentAttributes)
	assert.NotNil(t, ErrAlreadyInitialized)
	assert.NotNil(t, ErrInvalidKeyedHashSecret)
	assert.NotNil(t, ErrInvalidHashFunction)
	assert.NotNil(t, ErrInvalidSignerOpts)
	assert.NotNil(t, ErrInvalidKeyAttributes)
	assert.NotNil(t, ErrInvalidKeyAlgorithm)
	assert.NotNil(t, ErrUnsupportedKeyAlgorithm)
	assert.NotNil(t, ErrPasswordRequired)

	// Verify error messages
	assert.Contains(t, ErrCertNotFound.Error(), "certificate not found")
	assert.Contains(t, ErrCorruptCopy.Error(), "corrupt copy")
	assert.Contains(t, ErrInvalidParentAttributes.Error(), "invalid parent")
	assert.Contains(t, ErrAlreadyInitialized.Error(), "already initialized")
	assert.Contains(t, ErrInvalidKeyedHashSecret.Error(), "keyed hash secret")
	assert.Contains(t, ErrInvalidHashFunction.Error(), "hash function")
	assert.Contains(t, ErrInvalidSignerOpts.Error(), "signer options")
	assert.Contains(t, ErrInvalidKeyAttributes.Error(), "key attributes")
	assert.Contains(t, ErrInvalidKeyAlgorithm.Error(), "key algorithm")
	assert.Contains(t, ErrUnsupportedKeyAlgorithm.Error(), "unsupported")
	assert.Contains(t, ErrPasswordRequired.Error(), "password required")
}
