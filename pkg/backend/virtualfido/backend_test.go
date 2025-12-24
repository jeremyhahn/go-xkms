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

package virtualfido

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/bulwarkid/virtual-fido/fido_client"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBackend(t *testing.T) {
	t.Run("creates backend with defaults", func(t *testing.T) {
		cfg := &Config{}
		backend, err := NewBackend(cfg)
		require.NoError(t, err)
		require.NotNil(t, backend)
		defer func() { _ = backend.Close() }()

		assert.Equal(t, BackendTypeVirtualFIDO, backend.Type())
		assert.NotEmpty(t, backend.SerialNumber())
		assert.Equal(t, DefaultManufacturer, backend.Manufacturer())
		assert.Equal(t, DefaultProduct, backend.Product())
	})

	t.Run("returns error for nil config", func(t *testing.T) {
		backend, err := NewBackend(nil)
		assert.Error(t, err)
		assert.Nil(t, backend)
		assert.True(t, errors.Is(err, ErrConfigNil))
	})

	t.Run("returns error for invalid PIN", func(t *testing.T) {
		cfg := &Config{PIN: "12"} // Too short
		backend, err := NewBackend(cfg)
		assert.Error(t, err)
		assert.Nil(t, backend)
	})

	t.Run("returns error for invalid PUK", func(t *testing.T) {
		cfg := &Config{PUK: "1234567"} // Not 8 chars
		backend, err := NewBackend(cfg)
		assert.Error(t, err)
		assert.Nil(t, backend)
	})

	t.Run("returns error for invalid management key", func(t *testing.T) {
		cfg := &Config{ManagementKey: []byte{1, 2, 3}} // Not 24 bytes
		backend, err := NewBackend(cfg)
		assert.Error(t, err)
		assert.Nil(t, backend)
	})
}

func TestBackendType(t *testing.T) {
	backend := createTestBackend(t)
	defer func() { _ = backend.Close() }()

	assert.Equal(t, BackendTypeVirtualFIDO, backend.Type())
}

func TestBackendCapabilities(t *testing.T) {
	backend := createTestBackend(t)
	defer func() { _ = backend.Close() }()

	caps := backend.Capabilities()

	assert.True(t, caps.Keys)
	assert.True(t, caps.Signing)
	assert.True(t, caps.Decryption)
	assert.True(t, caps.KeyRotation)
	assert.True(t, caps.SymmetricEncryption)
	assert.True(t, caps.Import)
	assert.True(t, caps.Export)
	assert.True(t, caps.KeyAgreement)
	assert.True(t, caps.ECIES)
	assert.False(t, caps.HardwareBacked)
	assert.False(t, caps.Sealing)
}

func TestGenerateKey(t *testing.T) {
	t.Run("generates RSA key", func(t *testing.T) {
		backend := createTestBackend(t)
		defer func() { _ = backend.Close() }()

		attrs := &types.KeyAttributes{
			CN:           "test-rsa",
			KeyAlgorithm: x509.RSA,
			Hash:         crypto.SHA256,
		}

		key, err := backend.GenerateKey(attrs)
		require.NoError(t, err)
		require.NotNil(t, key)

		rsaKey, ok := key.(*rsa.PrivateKey)
		require.True(t, ok)
		assert.GreaterOrEqual(t, rsaKey.N.BitLen(), 2048)
	})

	t.Run("generates ECDSA key", func(t *testing.T) {
		backend := createTestBackend(t)
		defer func() { _ = backend.Close() }()

		attrs := &types.KeyAttributes{
			CN:           "test-ecdsa",
			KeyAlgorithm: x509.ECDSA,
			Hash:         crypto.SHA256,
		}

		key, err := backend.GenerateKey(attrs)
		require.NoError(t, err)
		require.NotNil(t, key)

		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		require.True(t, ok)
		assert.Equal(t, 256, ecdsaKey.Curve.Params().BitSize)
	})

	t.Run("generates Ed25519 key", func(t *testing.T) {
		backend := createTestBackend(t)
		defer func() { _ = backend.Close() }()

		attrs := &types.KeyAttributes{
			CN:           "test-ed25519",
			KeyAlgorithm: x509.Ed25519,
		}

		key, err := backend.GenerateKey(attrs)
		require.NoError(t, err)
		require.NotNil(t, key)

		edKey, ok := key.(ed25519.PrivateKey)
		require.True(t, ok)
		assert.Len(t, edKey, ed25519.PrivateKeySize)
	})

	t.Run("fails on closed backend", func(t *testing.T) {
		backend := createTestBackend(t)
		_ = backend.Close()

		attrs := &types.KeyAttributes{
			CN:           "test",
			KeyAlgorithm: x509.ECDSA,
		}

		key, err := backend.GenerateKey(attrs)
		assert.Error(t, err)
		assert.Nil(t, key)
		assert.True(t, errors.Is(err, ErrBackendClosed))
	})

	t.Run("fails for unsupported algorithm", func(t *testing.T) {
		backend := createTestBackend(t)
		defer func() { _ = backend.Close() }()

		attrs := &types.KeyAttributes{
			CN:           "test",
			KeyAlgorithm: x509.DSA, // Not supported
		}

		key, err := backend.GenerateKey(attrs)
		assert.Error(t, err)
		assert.Nil(t, key)
	})
}

func TestGetKey(t *testing.T) {
	t.Run("retrieves existing key", func(t *testing.T) {
		backend := createTestBackend(t)
		defer func() { _ = backend.Close() }()

		attrs := &types.KeyAttributes{
			CN:           "test",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      types.KeyTypeSigning,
		}

		origKey, err := backend.GenerateKey(attrs)
		require.NoError(t, err)

		retrievedKey, err := backend.GetKey(attrs)
		require.NoError(t, err)

		origECDSA := origKey.(*ecdsa.PrivateKey)
		retrievedECDSA := retrievedKey.(*ecdsa.PrivateKey)
		assert.True(t, origECDSA.Equal(retrievedECDSA))
	})

	t.Run("returns error for non-existent key", func(t *testing.T) {
		backend := createTestBackend(t)
		defer func() { _ = backend.Close() }()

		attrs := &types.KeyAttributes{
			CN:           "non-existent",
			KeyAlgorithm: x509.ECDSA,
		}

		key, err := backend.GetKey(attrs)
		assert.Error(t, err)
		assert.Nil(t, key)
		assert.True(t, errors.Is(err, ErrKeyNotFound))
	})

	t.Run("fails on closed backend", func(t *testing.T) {
		backend := createTestBackend(t)
		_ = backend.Close()

		attrs := &types.KeyAttributes{CN: "test"}
		key, err := backend.GetKey(attrs)
		assert.Error(t, err)
		assert.Nil(t, key)
		assert.True(t, errors.Is(err, ErrBackendClosed))
	})
}

func TestDeleteKey(t *testing.T) {
	t.Run("deletes existing key", func(t *testing.T) {
		backend := createTestBackend(t)
		defer func() { _ = backend.Close() }()

		attrs := &types.KeyAttributes{
			CN:           "test",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      types.KeyTypeSigning,
		}

		_, err := backend.GenerateKey(attrs)
		require.NoError(t, err)

		err = backend.DeleteKey(attrs)
		require.NoError(t, err)

		// Verify it's gone
		key, err := backend.GetKey(attrs)
		assert.Error(t, err)
		assert.Nil(t, key)
	})

	t.Run("returns error for non-existent key", func(t *testing.T) {
		backend := createTestBackend(t)
		defer func() { _ = backend.Close() }()

		attrs := &types.KeyAttributes{CN: "non-existent"}
		err := backend.DeleteKey(attrs)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrKeyNotFound))
	})
}

func TestListKeys(t *testing.T) {
	t.Run("returns empty list initially", func(t *testing.T) {
		backend := createTestBackend(t)
		defer func() { _ = backend.Close() }()

		keys, err := backend.ListKeys()
		require.NoError(t, err)
		assert.Empty(t, keys)
	})

	t.Run("returns all generated keys", func(t *testing.T) {
		backend := createTestBackend(t)
		defer func() { _ = backend.Close() }()

		// Generate a key
		_, err := backend.GenerateKey(&types.KeyAttributes{
			CN:           "key1",
			KeyAlgorithm: x509.ECDSA,
		})
		require.NoError(t, err)

		keys, err := backend.ListKeys()
		require.NoError(t, err)
		assert.Len(t, keys, 1)
		assert.Equal(t, StoreTypeVirtualFIDO, keys[0].StoreType)
	})
}

func TestSigner(t *testing.T) {
	t.Run("returns working signer", func(t *testing.T) {
		backend := createTestBackend(t)
		defer func() { _ = backend.Close() }()

		attrs := &types.KeyAttributes{
			CN:           "test",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      types.KeyTypeSigning,
			Hash:         crypto.SHA256,
		}

		privKey, err := backend.GenerateKey(attrs)
		require.NoError(t, err)

		signer, err := backend.Signer(attrs)
		require.NoError(t, err)
		require.NotNil(t, signer)

		// Sign
		message := []byte("test message")
		digest := sha256.Sum256(message)
		signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		require.NoError(t, err)

		// Verify
		ecdsaKey := privKey.(*ecdsa.PrivateKey)
		valid := ecdsa.VerifyASN1(&ecdsaKey.PublicKey, digest[:], signature)
		assert.True(t, valid)
	})

	t.Run("returns error for non-existent key", func(t *testing.T) {
		backend := createTestBackend(t)
		defer func() { _ = backend.Close() }()

		attrs := &types.KeyAttributes{CN: "non-existent"}
		signer, err := backend.Signer(attrs)
		assert.Error(t, err)
		assert.Nil(t, signer)
	})
}

func TestDecrypter(t *testing.T) {
	t.Run("returns working decrypter for RSA", func(t *testing.T) {
		backend := createTestBackend(t)
		defer func() { _ = backend.Close() }()

		attrs := &types.KeyAttributes{
			CN:           "test",
			KeyAlgorithm: x509.RSA,
			KeyType:      types.KeyTypeEncryption,
		}

		privKey, err := backend.GenerateKey(attrs)
		require.NoError(t, err)

		decrypter, err := backend.Decrypter(attrs)
		require.NoError(t, err)

		rsaKey := privKey.(*rsa.PrivateKey)
		message := []byte("secret message")
		ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &rsaKey.PublicKey, message)
		require.NoError(t, err)

		plaintext, err := decrypter.Decrypt(rand.Reader, ciphertext, nil)
		require.NoError(t, err)
		assert.Equal(t, message, plaintext)
	})

	t.Run("returns error for ECDSA key", func(t *testing.T) {
		backend := createTestBackend(t)
		defer func() { _ = backend.Close() }()

		attrs := &types.KeyAttributes{
			CN:           "test",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      types.KeyTypeEncryption,
		}

		_, err := backend.GenerateKey(attrs)
		require.NoError(t, err)

		decrypter, err := backend.Decrypter(attrs)
		assert.Error(t, err)
		assert.Nil(t, decrypter)
	})
}

func TestRotateKey(t *testing.T) {
	t.Run("rotates key successfully", func(t *testing.T) {
		backend := createTestBackend(t)
		defer func() { _ = backend.Close() }()

		attrs := &types.KeyAttributes{
			CN:           "test",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      types.KeyTypeSigning,
		}

		origKey, err := backend.GenerateKey(attrs)
		require.NoError(t, err)

		err = backend.RotateKey(attrs)
		require.NoError(t, err)

		newKey, err := backend.GetKey(attrs)
		require.NoError(t, err)

		origECDSA := origKey.(*ecdsa.PrivateKey)
		newECDSA := newKey.(*ecdsa.PrivateKey)
		assert.False(t, origECDSA.Equal(newECDSA), "rotated key should be different")
	})

	t.Run("returns error for non-existent key", func(t *testing.T) {
		backend := createTestBackend(t)
		defer func() { _ = backend.Close() }()

		attrs := &types.KeyAttributes{CN: "non-existent"}
		err := backend.RotateKey(attrs)
		assert.Error(t, err)
	})
}

func TestDeriveSharedSecret(t *testing.T) {
	t.Run("derives shared secret", func(t *testing.T) {
		backend := createTestBackend(t)
		defer func() { _ = backend.Close() }()

		attrs := &types.KeyAttributes{
			CN:           "test",
			KeyAlgorithm: x509.ECDSA,
			Hash:         crypto.SHA256,
		}

		ourKey, err := backend.GenerateKey(attrs)
		require.NoError(t, err)
		ourECDSA := ourKey.(*ecdsa.PrivateKey)

		// Generate peer key
		peerKey, err := ecdsa.GenerateKey(ourECDSA.Curve, rand.Reader)
		require.NoError(t, err)

		// Derive from our side
		secret1, err := backend.DeriveSharedSecret(attrs, &peerKey.PublicKey)
		require.NoError(t, err)

		// Derive from peer side
		peerECDH, _ := peerKey.ECDH()
		ourPubECDH, _ := ourECDSA.PublicKey.ECDH()
		secret2, err := peerECDH.ECDH(ourPubECDH)
		require.NoError(t, err)

		assert.Equal(t, secret1, secret2)
	})

	t.Run("fails for RSA key", func(t *testing.T) {
		backend := createTestBackend(t)
		defer func() { _ = backend.Close() }()

		attrs := &types.KeyAttributes{
			CN:           "test",
			KeyAlgorithm: x509.RSA,
		}

		_, err := backend.GenerateKey(attrs)
		require.NoError(t, err)

		_, err = backend.DeriveSharedSecret(attrs, nil)
		assert.Error(t, err)
	})
}

func TestPINOperations(t *testing.T) {
	t.Run("verify PIN success", func(t *testing.T) {
		cfg := &Config{PIN: "123456"}
		backend, err := NewBackend(cfg)
		require.NoError(t, err)
		defer func() { _ = backend.Close() }()

		err = backend.VerifyPIN("123456")
		assert.NoError(t, err)
	})

	t.Run("verify PIN failure decrements retries", func(t *testing.T) {
		cfg := &Config{PIN: "123456", PINRetries: 3}
		backend, err := NewBackend(cfg)
		require.NoError(t, err)
		defer func() { _ = backend.Close() }()

		pinRetries, _, _ := backend.GetRetryCount()
		assert.Equal(t, 3, pinRetries)

		err = backend.VerifyPIN("wrong")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrPINInvalid))

		pinRetries, _, _ = backend.GetRetryCount()
		assert.Equal(t, 2, pinRetries)
	})

	t.Run("set PIN", func(t *testing.T) {
		cfg := &Config{PIN: "123456"}
		backend, err := NewBackend(cfg)
		require.NoError(t, err)
		defer func() { _ = backend.Close() }()

		err = backend.SetPIN("123456", "654321")
		assert.NoError(t, err)

		err = backend.VerifyPIN("654321")
		assert.NoError(t, err)
	})

	t.Run("set PIN fails with wrong old PIN", func(t *testing.T) {
		cfg := &Config{PIN: "123456"}
		backend, err := NewBackend(cfg)
		require.NoError(t, err)
		defer func() { _ = backend.Close() }()

		err = backend.SetPIN("wrong", "654321")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrPINInvalid))
	})
}

func TestPUKOperations(t *testing.T) {
	t.Run("unblock PIN with PUK", func(t *testing.T) {
		cfg := &Config{PIN: "123456", PUK: "12345678", PINRetries: 3}
		backend, err := NewBackend(cfg)
		require.NoError(t, err)
		defer func() { _ = backend.Close() }()

		// Exhaust PIN retries
		for i := 0; i < 3; i++ {
			_ = backend.VerifyPIN("wrong")
		}

		// PIN should be blocked
		err = backend.VerifyPIN("123456")
		assert.True(t, errors.Is(err, ErrPINBlocked))

		// Unblock with PUK
		err = backend.UnblockPIN("12345678", "newpin12")
		assert.NoError(t, err)

		// New PIN should work
		err = backend.VerifyPIN("newpin12")
		assert.NoError(t, err)
	})

	t.Run("unblock fails with wrong PUK", func(t *testing.T) {
		cfg := &Config{PIN: "123456", PUK: "12345678"}
		backend, err := NewBackend(cfg)
		require.NoError(t, err)
		defer func() { _ = backend.Close() }()

		err = backend.UnblockPIN("wrong-pk", "newpin12")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrPUKInvalid))
	})
}

func TestResetDevice(t *testing.T) {
	backend := createTestBackend(t)
	defer func() { _ = backend.Close() }()

	// Generate a key
	_, err := backend.GenerateKey(&types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.ECDSA,
	})
	require.NoError(t, err)

	// Reset
	err = backend.ResetDevice()
	require.NoError(t, err)

	// Keys should be gone
	keys, _ := backend.ListKeys()
	assert.Empty(t, keys)

	// Default PIN should work
	err = backend.VerifyPIN(DefaultPIN)
	assert.NoError(t, err)
}

func TestClose(t *testing.T) {
	t.Run("close is idempotent", func(t *testing.T) {
		backend := createTestBackend(t)

		err := backend.Close()
		assert.NoError(t, err)

		err = backend.Close()
		assert.NoError(t, err)
	})

	t.Run("operations fail after close", func(t *testing.T) {
		backend := createTestBackend(t)
		_ = backend.Close()

		_, err := backend.ListKeys()
		assert.True(t, errors.Is(err, ErrBackendClosed))
	})
}

func TestFIDOClient(t *testing.T) {
	backend := createTestBackend(t)
	defer func() { _ = backend.Close() }()

	fidoClient := backend.FIDOClient()
	assert.NotNil(t, fidoClient)
}

func TestVirtualSignerPublic(t *testing.T) {
	backend := createTestBackend(t)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.ECDSA,
		KeyType:      types.KeyTypeSigning,
	}

	privKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)

	signer, err := backend.Signer(attrs)
	require.NoError(t, err)

	ecdsaKey := privKey.(*ecdsa.PrivateKey)
	assert.Equal(t, ecdsaKey.Public(), signer.Public())
}

func TestVirtualDecrypterPublic(t *testing.T) {
	backend := createTestBackend(t)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeEncryption,
	}

	privKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)

	decrypter, err := backend.Decrypter(attrs)
	require.NoError(t, err)

	rsaKey := privKey.(*rsa.PrivateKey)
	assert.Equal(t, rsaKey.Public(), decrypter.Public())
}

func TestSignerSignAfterClose(t *testing.T) {
	backend := createTestBackend(t)

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.ECDSA,
		KeyType:      types.KeyTypeSigning,
	}

	_, err := backend.GenerateKey(attrs)
	require.NoError(t, err)

	signer, err := backend.Signer(attrs)
	require.NoError(t, err)

	_ = backend.Close()

	// Sign should fail after close
	digest := sha256.Sum256([]byte("test"))
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrBackendClosed))
}

func TestDecrypterDecryptAfterClose(t *testing.T) {
	backend := createTestBackend(t)

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeEncryption,
	}

	privKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)

	decrypter, err := backend.Decrypter(attrs)
	require.NoError(t, err)

	rsaKey := privKey.(*rsa.PrivateKey)
	ciphertext, _ := rsa.EncryptPKCS1v15(rand.Reader, &rsaKey.PublicKey, []byte("test"))

	_ = backend.Close()

	// Decrypt should fail after close
	_, err = decrypter.Decrypt(rand.Reader, ciphertext, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrBackendClosed))
}

func TestCurveFromHash(t *testing.T) {
	backend := createTestBackend(t)
	defer func() { _ = backend.Close() }()

	// SHA256 -> P-256
	attrs := &types.KeyAttributes{
		CN:           "sha256",
		KeyAlgorithm: x509.ECDSA,
		Hash:         crypto.SHA256,
	}
	privKey, _ := backend.GenerateKey(attrs)
	ecdsaKey := privKey.(*ecdsa.PrivateKey)
	assert.Equal(t, 256, ecdsaKey.Curve.Params().BitSize)
}

func TestAutoApprover(t *testing.T) {
	approver := &autoApprover{}
	// Test that it always returns true
	assert.True(t, approver.ApproveClientAction(fido_client.ClientActionFIDOMakeCredential, fido_client.ClientActionRequestParams{}))
	assert.True(t, approver.ApproveClientAction(fido_client.ClientActionFIDOGetAssertion, fido_client.ClientActionRequestParams{}))
}

func TestDeriveSharedSecretWithECDHPublicKey(t *testing.T) {
	backend := createTestBackend(t)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.ECDSA,
		Hash:         crypto.SHA256,
	}

	ourKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)
	ourECDSA := ourKey.(*ecdsa.PrivateKey)

	// Generate peer key and convert to ecdh.PublicKey
	peerKey, err := ecdsa.GenerateKey(ourECDSA.Curve, rand.Reader)
	require.NoError(t, err)
	peerECDH, _ := peerKey.PublicKey.ECDH()

	// Derive using ecdh.PublicKey directly
	secret, err := backend.DeriveSharedSecret(attrs, peerECDH)
	require.NoError(t, err)
	assert.NotEmpty(t, secret)
}

func TestSlotAllocationForMultipleKeys(t *testing.T) {
	backend := createTestBackend(t)
	defer func() { _ = backend.Close() }()

	// Generate signing key - should use SlotSignature
	_, err := backend.GenerateKey(&types.KeyAttributes{
		CN:           "sig1",
		KeyAlgorithm: x509.ECDSA,
		KeyType:      types.KeyTypeSigning,
	})
	require.NoError(t, err)

	// Generate another signing key - SlotSignature is full, should use SlotAuthentication
	_, err = backend.GenerateKey(&types.KeyAttributes{
		CN:           "sig2",
		KeyAlgorithm: x509.ECDSA,
		KeyType:      types.KeyTypeSigning,
	})
	require.NoError(t, err)

	// Generate encryption key - SlotKeyManagement
	_, err = backend.GenerateKey(&types.KeyAttributes{
		CN:           "enc1",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeEncryption,
	})
	require.NoError(t, err)

	keys, _ := backend.ListKeys()
	assert.Len(t, keys, 3)
}

func TestGetRetryCountAfterClose(t *testing.T) {
	backend := createTestBackend(t)
	_ = backend.Close()

	_, _, err := backend.GetRetryCount()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrBackendClosed))
}

func createTestBackend(t *testing.T) *Backend {
	t.Helper()
	cfg := &Config{SerialNumber: "TEST-" + t.Name()}
	backend, err := NewBackend(cfg)
	require.NoError(t, err)
	return backend
}
