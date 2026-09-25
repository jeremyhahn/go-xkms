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
func TestErrSignerNotFound_Error(t *testing.T) {
	err := &ErrSignerNotFound{CN: "my-key"}
	assert.Contains(t, err.Error(), "signer not found")
	assert.Contains(t, err.Error(), "my-key")
}

func TestErrSignerGet_Error(t *testing.T) {
	cause := errors.New("io error")
	err := &ErrSignerGet{CN: "my-key", Cause: cause}
	assert.Contains(t, err.Error(), "failed to get signer")
	assert.Contains(t, err.Error(), "my-key")
	assert.ErrorIs(t, err, cause)
}

func TestErrSignerPEMDecode_Error(t *testing.T) {
	cause := errors.New("bad pem")
	err := &ErrSignerPEMDecode{CN: "my-key", Cause: cause}
	assert.Contains(t, err.Error(), "decode PEM")
	assert.Contains(t, err.Error(), "my-key")
	assert.ErrorIs(t, err, cause)
}

func TestErrSignerKeyParse_Error(t *testing.T) {
	t.Run("without fallback cause", func(t *testing.T) {
		cause := errors.New("parse error")
		err := &ErrSignerKeyParse{CN: "my-key", Algorithm: "RSA", Cause: cause}
		assert.Contains(t, err.Error(), "parse RSA")
		assert.Contains(t, err.Error(), "my-key")
		assert.NotContains(t, err.Error(), "pkcs8:")
		assert.ErrorIs(t, err, cause)
	})

	t.Run("with fallback cause", func(t *testing.T) {
		cause := errors.New("pkcs1 error")
		fallback := errors.New("pkcs8 error")
		err := &ErrSignerKeyParse{CN: "my-key", Algorithm: "RSA", Cause: cause, FallbackCause: fallback}
		assert.Contains(t, err.Error(), "parse RSA")
		assert.Contains(t, err.Error(), "pkcs8:")
		assert.ErrorIs(t, err, cause)
	})
}

func TestErrSignerKeyTypeMismatch_Error(t *testing.T) {
	err := &ErrSignerKeyTypeMismatch{CN: "my-key", Expected: "RSA", Actual: "ECDSA"}
	assert.Contains(t, err.Error(), "not an RSA")
	assert.Contains(t, err.Error(), "my-key")
}

func TestErrSignerNil_Error(t *testing.T) {
	err := &ErrSignerNil{CN: "my-key"}
	assert.Contains(t, err.Error(), "signer is nil")
	assert.Contains(t, err.Error(), "my-key")
}

func TestErrSignerMarshal_Error(t *testing.T) {
	cause := errors.New("marshal error")
	err := &ErrSignerMarshal{CN: "my-key", Cause: cause}
	assert.Contains(t, err.Error(), "marshal private key")
	assert.Contains(t, err.Error(), "my-key")
	assert.ErrorIs(t, err, cause)
}

func TestErrSignerSave_Error(t *testing.T) {
	cause := errors.New("save error")
	err := &ErrSignerSave{CN: "my-key", Cause: cause}
	assert.Contains(t, err.Error(), "failed to save signer")
	assert.Contains(t, err.Error(), "my-key")
	assert.ErrorIs(t, err, cause)
}

func TestErrSignerDelete_Error(t *testing.T) {
	cause := errors.New("delete error")
	err := &ErrSignerDelete{CN: "my-key", Cause: cause}
	assert.Contains(t, err.Error(), "failed to delete signer")
	assert.Contains(t, err.Error(), "my-key")
	assert.ErrorIs(t, err, cause)
}

func TestErrSignatureSave_Error(t *testing.T) {
	cause := errors.New("save error")
	err := &ErrSignatureSave{Key: "test.sig", Cause: cause}
	assert.Contains(t, err.Error(), "failed to save signature")
	assert.Contains(t, err.Error(), "test.sig")
	assert.ErrorIs(t, err, cause)
}

func TestErrUnsupportedAlgorithm_Error(t *testing.T) {
	err := &ErrUnsupportedAlgorithm{CN: "my-key", Algorithm: x509.DSA}
	assert.Contains(t, err.Error(), "unsupported key algorithm")
	assert.Contains(t, err.Error(), "my-key")
}

func TestErrUnsupportedSignerType_Error(t *testing.T) {
	err := &ErrUnsupportedSignerType{CN: "my-key", Type: "string"}
	assert.Contains(t, err.Error(), "unsupported signer type")
	assert.Contains(t, err.Error(), "my-key")
}

func TestErrSignerExtract_Error(t *testing.T) {
	err := &ErrSignerExtract{CN: "my-key", Algorithm: "RSA"}
	assert.Contains(t, err.Error(), "unable to extract RSA")
	assert.Contains(t, err.Error(), "my-key")
}

func TestErrUnsupportedPublicKeyType_Error(t *testing.T) {
	err := &ErrUnsupportedPublicKeyType{CN: "my-key", Type: "string"}
	assert.Contains(t, err.Error(), "unsupported public key type")
	assert.Contains(t, err.Error(), "my-key")
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
