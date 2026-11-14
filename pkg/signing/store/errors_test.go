// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC

package store

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
)

// =============================================================================
// SignerErrors Tests
// =============================================================================
func TestErrSignerMarshal_Error(t *testing.T) {
	cause := errors.New("marshal error")
	err := &ErrSignerMarshal{CN: "my-key", Cause: cause}
	assert.Contains(t, err.Error(), "marshal private key")
	assert.Contains(t, err.Error(), "my-key")
	assert.ErrorIs(t, err, cause)
}

func TestErrSignerStoreNotInitialized(t *testing.T) {
	// Test that uninitialized store returns proper errors.
	store := &SignerStore{}

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.RSA,
	}

	_, err := store.Get(attrs)
	assert.ErrorIs(t, err, ErrSignerStoreNotInitialized)

	err = store.Save(attrs, nil)
	assert.ErrorIs(t, err, ErrSignerStoreNotInitialized)

	err = store.Delete(attrs)
	assert.ErrorIs(t, err, ErrSignerStoreNotInitialized)

	opts := &SignerOpts{KeyAttributes: attrs}
	err = store.SaveSignature(opts, []byte("sig"), []byte("digest"))
	assert.ErrorIs(t, err, ErrSignerStoreNotInitialized)

	_, _, err = store.GetSignature(opts)
	assert.ErrorIs(t, err, ErrSignerStoreNotInitialized)

	_, err = store.Checksum(&types.VerifyOpts{KeyAttributes: attrs, BlobCN: "blob"})
	assert.ErrorIs(t, err, ErrSignerStoreNotInitialized)
}
