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

//go:build integration

package virtualfido_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"hash"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend/virtualfido"
	"github.com/jeremyhahn/go-keychain/pkg/fido2"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBackendCreation tests the creation of a VirtualFIDO backend.
func TestBackendCreation(t *testing.T) {
	t.Run("creates backend with default config", func(t *testing.T) {
		cfg := &virtualfido.Config{}
		backend, err := virtualfido.NewBackend(cfg)
		require.NoError(t, err)
		require.NotNil(t, backend)
		defer backend.Close()

		// Verify backend type
		assert.Equal(t, virtualfido.BackendTypeVirtualFIDO, backend.Type())

		// Verify serial number was generated
		assert.NotEmpty(t, backend.SerialNumber())
		assert.True(t, len(backend.SerialNumber()) >= 6)

		// Verify defaults
		assert.Equal(t, virtualfido.DefaultManufacturer, backend.Manufacturer())
		assert.Equal(t, virtualfido.DefaultProduct, backend.Product())
	})

	t.Run("creates backend with custom config", func(t *testing.T) {
		cfg := &virtualfido.Config{
			SerialNumber: "CUSTOM001",
			Manufacturer: "TestManufacturer",
			Product:      "TestProduct",
			PIN:          "654321",
			PUK:          "87654321",
		}
		backend, err := virtualfido.NewBackend(cfg)
		require.NoError(t, err)
		require.NotNil(t, backend)
		defer backend.Close()

		assert.Equal(t, "CUSTOM001", backend.SerialNumber())
		assert.Equal(t, "TestManufacturer", backend.Manufacturer())
		assert.Equal(t, "TestProduct", backend.Product())
	})

	t.Run("fails with nil config", func(t *testing.T) {
		backend, err := virtualfido.NewBackend(nil)
		assert.Error(t, err)
		assert.Nil(t, backend)
		assert.True(t, errors.Is(err, virtualfido.ErrConfigNil))
	})

	t.Run("fails with invalid PIN length", func(t *testing.T) {
		cfg := &virtualfido.Config{
			PIN: "12", // Too short (min 4)
		}
		backend, err := virtualfido.NewBackend(cfg)
		assert.Error(t, err)
		assert.Nil(t, backend)
	})

	t.Run("fails with invalid PUK length", func(t *testing.T) {
		cfg := &virtualfido.Config{
			PUK: "1234567", // Wrong length (must be 8)
		}
		backend, err := virtualfido.NewBackend(cfg)
		assert.Error(t, err)
		assert.Nil(t, backend)
	})
}

// TestBackendCapabilities tests the capabilities reported by the backend.
func TestBackendCapabilities(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()

	caps := backend.Capabilities()

	assert.True(t, caps.Keys, "should support keys")
	assert.True(t, caps.Signing, "should support signing")
	assert.True(t, caps.Decryption, "should support decryption")
	assert.True(t, caps.KeyRotation, "should support key rotation")
	assert.True(t, caps.SymmetricEncryption, "should support symmetric encryption")
	assert.True(t, caps.Import, "should support import")
	assert.True(t, caps.Export, "should support export")
	assert.True(t, caps.KeyAgreement, "should support key agreement (ECDH)")
	assert.True(t, caps.ECIES, "should support ECIES")
	assert.False(t, caps.HardwareBacked, "should not be hardware backed")
	assert.False(t, caps.Sealing, "should not support sealing")
}

// TestRSAKeyGeneration tests RSA key generation and signing.
func TestRSAKeyGeneration(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()

	t.Run("generates RSA key and signs", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-rsa-key",
			KeyAlgorithm: x509.RSA,
			KeyType:      types.KeyTypeSigning,
			Hash:         crypto.SHA256,
		}

		// Generate key
		privKey, err := backend.GenerateKey(attrs)
		require.NoError(t, err)
		require.NotNil(t, privKey)

		// Verify it's an RSA key
		rsaKey, ok := privKey.(*rsa.PrivateKey)
		require.True(t, ok, "expected RSA private key")
		assert.GreaterOrEqual(t, rsaKey.N.BitLen(), 2048, "RSA key should be at least 2048 bits")

		// Get signer
		signer, err := backend.Signer(attrs)
		require.NoError(t, err)
		require.NotNil(t, signer)

		// Sign some data
		message := []byte("test message for RSA signing")
		digest := sha256.Sum256(message)
		signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		require.NoError(t, err)
		require.NotEmpty(t, signature)

		// Verify signature
		err = rsa.VerifyPKCS1v15(&rsaKey.PublicKey, crypto.SHA256, digest[:], signature)
		assert.NoError(t, err, "signature verification should succeed")
	})

	t.Run("generates larger RSA key with SHA384", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "test-rsa-key-4096",
			KeyAlgorithm: x509.RSA,
			KeyType:      types.KeyTypeSigning,
			Hash:         crypto.SHA384,
		}

		privKey, err := backend.GenerateKey(attrs)
		require.NoError(t, err)

		rsaKey, ok := privKey.(*rsa.PrivateKey)
		require.True(t, ok)
		assert.GreaterOrEqual(t, rsaKey.N.BitLen(), 4096, "RSA key should be 4096 bits for SHA384")
	})
}

// TestECDSAKeyGeneration tests ECDSA key generation and signing.
func TestECDSAKeyGeneration(t *testing.T) {
	testCases := []struct {
		name      string
		hash      crypto.Hash
		curveBits int
	}{
		{"P256 with SHA256", crypto.SHA256, 256},
		{"P384 with SHA384", crypto.SHA384, 384},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Each subtest gets its own backend to avoid slot allocation conflicts
			backend := createTestBackend(t)
			defer backend.Close()

			attrs := &types.KeyAttributes{
				CN:           "test-ecdsa-" + tc.name,
				KeyAlgorithm: x509.ECDSA,
				KeyType:      types.KeyTypeSigning,
				Hash:         tc.hash,
			}

			// Generate key
			privKey, err := backend.GenerateKey(attrs)
			require.NoError(t, err)
			require.NotNil(t, privKey)

			// Verify it's an ECDSA key
			ecdsaKey, ok := privKey.(*ecdsa.PrivateKey)
			require.True(t, ok, "expected ECDSA private key")
			assert.Equal(t, tc.curveBits, ecdsaKey.Curve.Params().BitSize)

			// Get signer
			signer, err := backend.Signer(attrs)
			require.NoError(t, err)

			// Sign some data using the appropriate hash for the curve
			message := []byte("test message for ECDSA signing")
			var digest []byte
			var hashFunc hash.Hash
			if tc.hash == crypto.SHA384 {
				hashFunc = sha512.New384()
			} else {
				hashFunc = sha256.New()
			}
			hashFunc.Write(message)
			digest = hashFunc.Sum(nil)

			signature, err := signer.Sign(rand.Reader, digest, tc.hash)
			require.NoError(t, err)
			require.NotEmpty(t, signature)

			// Verify signature
			valid := ecdsa.VerifyASN1(&ecdsaKey.PublicKey, digest, signature)
			assert.True(t, valid, "ECDSA signature verification should succeed")
		})
	}
}

// TestEd25519KeyGeneration tests Ed25519 key generation and signing.
func TestEd25519KeyGeneration(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()

	attrs := &types.KeyAttributes{
		CN:           "test-ed25519-key",
		KeyAlgorithm: x509.Ed25519,
		KeyType:      types.KeyTypeSigning,
	}

	// Generate key
	privKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)
	require.NotNil(t, privKey)

	// Verify it's an Ed25519 key
	edKey, ok := privKey.(ed25519.PrivateKey)
	require.True(t, ok, "expected Ed25519 private key")
	assert.Len(t, edKey, ed25519.PrivateKeySize)

	// Get signer
	signer, err := backend.Signer(attrs)
	require.NoError(t, err)

	// Sign some data (Ed25519 signs the message directly, not a digest)
	message := []byte("test message for Ed25519 signing")
	signature, err := signer.Sign(rand.Reader, message, crypto.Hash(0))
	require.NoError(t, err)
	require.Len(t, signature, ed25519.SignatureSize)

	// Verify signature
	pubKey := edKey.Public().(ed25519.PublicKey)
	valid := ed25519.Verify(pubKey, message, signature)
	assert.True(t, valid, "Ed25519 signature verification should succeed")
}

// TestKeyRetrieval tests key retrieval operations.
func TestKeyRetrieval(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()

	// Generate a key first
	attrs := &types.KeyAttributes{
		CN:           "test-key-retrieval",
		KeyAlgorithm: x509.ECDSA,
		KeyType:      types.KeyTypeSigning,
		Hash:         crypto.SHA256,
	}

	origKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)

	t.Run("retrieves existing key", func(t *testing.T) {
		retrievedKey, err := backend.GetKey(attrs)
		require.NoError(t, err)
		require.NotNil(t, retrievedKey)

		// Should be the same key
		origECDSA := origKey.(*ecdsa.PrivateKey)
		retrievedECDSA := retrievedKey.(*ecdsa.PrivateKey)
		assert.True(t, origECDSA.Equal(retrievedECDSA), "retrieved key should match original")
	})

	t.Run("returns error for non-existent key", func(t *testing.T) {
		nonExistentAttrs := &types.KeyAttributes{
			CN:           "non-existent-key",
			KeyAlgorithm: x509.ECDSA,
		}
		key, err := backend.GetKey(nonExistentAttrs)
		assert.Error(t, err)
		assert.Nil(t, key)
		assert.True(t, errors.Is(err, virtualfido.ErrKeyNotFound))
	})
}

// TestKeyListing tests the ListKeys operation.
func TestKeyListing(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()

	// Initially should be empty
	keys, err := backend.ListKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)

	// Generate some keys
	keyTypes := []struct {
		cn        string
		algorithm x509.PublicKeyAlgorithm
	}{
		{"key-rsa", x509.RSA},
		{"key-ecdsa", x509.ECDSA},
		{"key-ed25519", x509.Ed25519},
	}

	for _, kt := range keyTypes {
		_, err := backend.GenerateKey(&types.KeyAttributes{
			CN:           kt.cn,
			KeyAlgorithm: kt.algorithm,
			Hash:         crypto.SHA256,
		})
		require.NoError(t, err)
	}

	// List keys
	keys, err = backend.ListKeys()
	require.NoError(t, err)
	assert.Len(t, keys, 3, "should have 3 keys")

	// Verify all keys have correct store type
	for _, key := range keys {
		assert.Equal(t, virtualfido.StoreTypeVirtualFIDO, key.StoreType)
	}
}

// TestKeyDeletion tests key deletion.
func TestKeyDeletion(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()

	attrs := &types.KeyAttributes{
		CN:           "test-key-delete",
		KeyAlgorithm: x509.ECDSA,
		KeyType:      types.KeyTypeSigning,
		Hash:         crypto.SHA256,
	}

	// Generate key
	_, err := backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Verify it exists
	key, err := backend.GetKey(attrs)
	require.NoError(t, err)
	require.NotNil(t, key)

	// Delete the key
	err = backend.DeleteKey(attrs)
	require.NoError(t, err)

	// Verify it's gone
	key, err = backend.GetKey(attrs)
	assert.Error(t, err)
	assert.Nil(t, key)
	assert.True(t, errors.Is(err, virtualfido.ErrKeyNotFound))

	// Deleting again should fail
	err = backend.DeleteKey(attrs)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, virtualfido.ErrKeyNotFound))
}

// TestKeyRotation tests key rotation.
func TestKeyRotation(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()

	attrs := &types.KeyAttributes{
		CN:           "test-key-rotate",
		KeyAlgorithm: x509.ECDSA,
		KeyType:      types.KeyTypeSigning,
		Hash:         crypto.SHA256,
	}

	// Generate initial key
	origKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)

	origECDSA := origKey.(*ecdsa.PrivateKey)
	origPubKeyBytes, _ := x509.MarshalPKIXPublicKey(&origECDSA.PublicKey)

	// Rotate the key
	err = backend.RotateKey(attrs)
	require.NoError(t, err)

	// Get the new key
	newKey, err := backend.GetKey(attrs)
	require.NoError(t, err)

	newECDSA := newKey.(*ecdsa.PrivateKey)
	newPubKeyBytes, _ := x509.MarshalPKIXPublicKey(&newECDSA.PublicKey)

	// Keys should be different
	assert.NotEqual(t, origPubKeyBytes, newPubKeyBytes, "rotated key should be different")

	// New key should still work for signing
	signer, err := backend.Signer(attrs)
	require.NoError(t, err)

	message := []byte("test after rotation")
	digest := sha256.Sum256(message)
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)

	valid := ecdsa.VerifyASN1(&newECDSA.PublicKey, digest[:], signature)
	assert.True(t, valid)
}

// TestRSADecryption tests RSA decryption operations.
func TestRSADecryption(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()

	attrs := &types.KeyAttributes{
		CN:           "test-rsa-decrypt",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeEncryption,
		Hash:         crypto.SHA256,
	}

	// Generate key
	privKey, err := backend.GenerateKey(attrs)
	require.NoError(t, err)

	rsaKey := privKey.(*rsa.PrivateKey)

	// Encrypt some data with the public key
	message := []byte("secret message for RSA decryption test")
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &rsaKey.PublicKey, message)
	require.NoError(t, err)

	// Get decrypter
	decrypter, err := backend.Decrypter(attrs)
	require.NoError(t, err)

	// Decrypt
	plaintext, err := decrypter.Decrypt(rand.Reader, ciphertext, nil)
	require.NoError(t, err)
	assert.Equal(t, message, plaintext)
}

// TestECDHKeyAgreement tests ECDH key agreement.
func TestECDHKeyAgreement(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()

	// Generate our key
	ourAttrs := &types.KeyAttributes{
		CN:           "test-ecdh-our-key",
		KeyAlgorithm: x509.ECDSA,
		KeyType:      types.KeyTypeEncryption,
		Hash:         crypto.SHA256,
	}

	ourPrivKey, err := backend.GenerateKey(ourAttrs)
	require.NoError(t, err)
	ourECDSA := ourPrivKey.(*ecdsa.PrivateKey)

	// Generate peer key (using standard library, simulating external party)
	peerPrivKey, err := ecdsa.GenerateKey(ourECDSA.Curve, rand.Reader)
	require.NoError(t, err)

	// Derive shared secret using our backend
	sharedSecret1, err := backend.DeriveSharedSecret(ourAttrs, &peerPrivKey.PublicKey)
	require.NoError(t, err)
	require.NotEmpty(t, sharedSecret1)

	// Derive shared secret from peer's side (using standard library)
	peerECDH, err := peerPrivKey.ECDH()
	require.NoError(t, err)
	ourPubECDH, err := ourECDSA.PublicKey.ECDH()
	require.NoError(t, err)
	sharedSecret2, err := peerECDH.ECDH(ourPubECDH)
	require.NoError(t, err)

	// Both sides should derive the same shared secret
	assert.Equal(t, sharedSecret1, sharedSecret2, "ECDH shared secrets should match")
}

// TestPINManagement tests PIN operations.
func TestPINManagement(t *testing.T) {
	cfg := &virtualfido.Config{
		PIN:        "123456",
		PINRetries: 3,
	}
	backend, err := virtualfido.NewBackend(cfg)
	require.NoError(t, err)
	defer backend.Close()

	t.Run("verify correct PIN", func(t *testing.T) {
		err := backend.VerifyPIN("123456")
		assert.NoError(t, err)
	})

	t.Run("reject incorrect PIN and decrement retries", func(t *testing.T) {
		pinRetries, _, _ := backend.GetRetryCount()
		assert.Equal(t, 3, pinRetries)

		err := backend.VerifyPIN("wrong-pin")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, virtualfido.ErrPINInvalid))

		pinRetries, _, _ = backend.GetRetryCount()
		assert.Equal(t, 2, pinRetries, "PIN retries should be decremented")
	})

	t.Run("set new PIN", func(t *testing.T) {
		err := backend.SetPIN("123456", "654321")
		assert.NoError(t, err)

		// Old PIN should no longer work
		err = backend.VerifyPIN("123456")
		assert.Error(t, err)

		// New PIN should work
		err = backend.VerifyPIN("654321")
		assert.NoError(t, err)
	})

	t.Run("reject set PIN with wrong old PIN", func(t *testing.T) {
		err := backend.SetPIN("wrong-old-pin", "newpin1")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, virtualfido.ErrPINInvalid))
	})
}

// TestPUKManagement tests PUK operations.
func TestPUKManagement(t *testing.T) {
	cfg := &virtualfido.Config{
		PIN:        "123456",
		PUK:        "12345678",
		PINRetries: 3,
		PUKRetries: 3,
	}
	backend, err := virtualfido.NewBackend(cfg)
	require.NoError(t, err)
	defer backend.Close()

	// Exhaust PIN retries
	for i := 0; i < 3; i++ {
		backend.VerifyPIN("wrong-pin")
	}

	// PIN should now be blocked
	err = backend.VerifyPIN("123456")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, virtualfido.ErrPINBlocked))

	t.Run("unblock PIN with correct PUK", func(t *testing.T) {
		err := backend.UnblockPIN("12345678", "newpin12")
		assert.NoError(t, err)

		// New PIN should work
		err = backend.VerifyPIN("newpin12")
		assert.NoError(t, err)

		// Retries should be restored
		pinRetries, _, _ := backend.GetRetryCount()
		assert.Equal(t, 3, pinRetries)
	})

	t.Run("reject unblock with wrong PUK", func(t *testing.T) {
		// First block PIN again
		for i := 0; i < 3; i++ {
			backend.VerifyPIN("wrong-pin")
		}

		err := backend.UnblockPIN("wrong-puk", "newpin34")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, virtualfido.ErrPUKInvalid))
	})
}

// TestDeviceReset tests device factory reset.
func TestDeviceReset(t *testing.T) {
	cfg := &virtualfido.Config{
		PIN: "654321",
		PUK: "87654321",
	}
	backend, err := virtualfido.NewBackend(cfg)
	require.NoError(t, err)
	defer backend.Close()

	// Generate some keys
	for i := 0; i < 3; i++ {
		_, err := backend.GenerateKey(&types.KeyAttributes{
			CN:           "test-key",
			KeyAlgorithm: x509.ECDSA,
			Hash:         crypto.SHA256,
		})
		require.NoError(t, err)
	}

	// Verify keys exist
	keys, err := backend.ListKeys()
	require.NoError(t, err)
	require.NotEmpty(t, keys)

	// Reset device
	err = backend.ResetDevice()
	require.NoError(t, err)

	// Keys should be gone
	keys, err = backend.ListKeys()
	require.NoError(t, err)
	assert.Empty(t, keys, "all keys should be deleted after reset")

	// Default PIN should work again
	err = backend.VerifyPIN(virtualfido.DefaultPIN)
	assert.NoError(t, err)
}

// TestBackendClosure tests that operations fail after backend is closed.
func TestBackendClosure(t *testing.T) {
	backend := createTestBackend(t)

	// Generate a key before closing
	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
		Hash:         crypto.SHA256,
	}
	_, err := backend.GenerateKey(attrs)
	require.NoError(t, err)

	// Close the backend
	err = backend.Close()
	require.NoError(t, err)

	// All operations should now fail
	t.Run("GenerateKey fails after close", func(t *testing.T) {
		_, err := backend.GenerateKey(attrs)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, virtualfido.ErrBackendClosed))
	})

	t.Run("GetKey fails after close", func(t *testing.T) {
		_, err := backend.GetKey(attrs)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, virtualfido.ErrBackendClosed))
	})

	t.Run("DeleteKey fails after close", func(t *testing.T) {
		err := backend.DeleteKey(attrs)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, virtualfido.ErrBackendClosed))
	})

	t.Run("ListKeys fails after close", func(t *testing.T) {
		_, err := backend.ListKeys()
		assert.Error(t, err)
		assert.True(t, errors.Is(err, virtualfido.ErrBackendClosed))
	})

	t.Run("VerifyPIN fails after close", func(t *testing.T) {
		err := backend.VerifyPIN("123456")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, virtualfido.ErrBackendClosed))
	})

	// Double close should be safe
	t.Run("double close is safe", func(t *testing.T) {
		err := backend.Close()
		assert.NoError(t, err)
	})
}

// TestVirtualFIDO2Device tests the virtual FIDO2 device operations.
func TestVirtualFIDO2Device(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()

	t.Run("creates virtual device", func(t *testing.T) {
		fidoClient := backend.FIDOClient()
		require.NotNil(t, fidoClient)

		cfg := &fido2.VirtualDeviceConfig{
			SerialNumber: "TEST001",
			Manufacturer: "TestMfg",
			Product:      "TestDevice",
			FIDOClient:   fidoClient,
		}

		device, err := fido2.NewVirtualFIDO2Device(cfg)
		require.NoError(t, err)
		require.NotNil(t, device)
		defer device.Close()

		// Verify device properties
		assert.Equal(t, fido2.VirtualFIDOPathPrefix+"TEST001", device.Path())
		assert.Equal(t, "TestMfg", device.Manufacturer())
		assert.Equal(t, "TestDevice", device.Product())
		assert.Equal(t, "TEST001", device.SerialNumber())
		assert.Equal(t, uint16(fido2.VirtualFIDOVendorID), device.VendorID())
		assert.Equal(t, uint16(fido2.VirtualFIDOProductID), device.ProductID())
	})

	t.Run("device requires FIDOClient", func(t *testing.T) {
		cfg := &fido2.VirtualDeviceConfig{
			SerialNumber: "TEST002",
			// FIDOClient is nil
		}

		device, err := fido2.NewVirtualFIDO2Device(cfg)
		assert.Error(t, err)
		assert.Nil(t, device)
	})
}

// TestVirtualDeviceEnumerator tests the virtual device enumerator.
func TestVirtualDeviceEnumerator(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()

	enumerator := fido2.NewVirtualDeviceEnumerator()
	require.NotNil(t, enumerator)
	defer enumerator.Close()

	// Create and register a device
	device, err := fido2.NewVirtualFIDO2Device(&fido2.VirtualDeviceConfig{
		SerialNumber: "ENUM001",
		FIDOClient:   backend.FIDOClient(),
	})
	require.NoError(t, err)

	t.Run("register device", func(t *testing.T) {
		err := enumerator.RegisterDevice(device)
		assert.NoError(t, err)
		assert.Equal(t, 1, enumerator.DeviceCount())
	})

	t.Run("enumerate devices", func(t *testing.T) {
		devices, err := enumerator.Enumerate(0, 0)
		require.NoError(t, err)
		assert.Len(t, devices, 1)
		assert.Equal(t, device.Path(), devices[0].Path())
	})

	t.Run("enumerate by vendor ID", func(t *testing.T) {
		devices, err := enumerator.Enumerate(fido2.VirtualFIDOVendorID, 0)
		require.NoError(t, err)
		assert.Len(t, devices, 1)

		// Non-matching vendor ID should return empty
		devices, err = enumerator.Enumerate(0x1234, 0)
		require.NoError(t, err)
		assert.Empty(t, devices)
	})

	t.Run("open device by path", func(t *testing.T) {
		opened, err := enumerator.Open(device.Path())
		require.NoError(t, err)
		assert.Equal(t, device.Path(), opened.Path())
	})

	t.Run("open non-existent device fails", func(t *testing.T) {
		opened, err := enumerator.Open("virtualfido://nonexistent")
		assert.Error(t, err)
		assert.Nil(t, opened)
	})

	t.Run("unregister device", func(t *testing.T) {
		err := enumerator.UnregisterDevice(device.Path())
		assert.NoError(t, err)
		assert.Equal(t, 0, enumerator.DeviceCount())
	})

	t.Run("unregister non-existent device fails", func(t *testing.T) {
		err := enumerator.UnregisterDevice("virtualfido://nonexistent")
		assert.Error(t, err)
	})
}

// TestCombinedEnumerator tests the combined enumerator.
func TestCombinedEnumerator(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()

	enum1 := fido2.NewVirtualDeviceEnumerator()
	enum2 := fido2.NewVirtualDeviceEnumerator()
	defer enum1.Close()
	defer enum2.Close()

	// Register devices in different enumerators
	device1, _ := fido2.NewVirtualFIDO2Device(&fido2.VirtualDeviceConfig{
		SerialNumber: "DEV001",
		FIDOClient:   backend.FIDOClient(),
	})
	device2, _ := fido2.NewVirtualFIDO2Device(&fido2.VirtualDeviceConfig{
		SerialNumber: "DEV002",
		FIDOClient:   backend.FIDOClient(),
	})

	enum1.RegisterDevice(device1)
	enum2.RegisterDevice(device2)

	combined := fido2.NewCombinedEnumerator(enum1, enum2)

	t.Run("enumerate across all enumerators", func(t *testing.T) {
		devices, err := combined.Enumerate(0, 0)
		require.NoError(t, err)
		assert.Len(t, devices, 2)
	})

	t.Run("open device from either enumerator", func(t *testing.T) {
		opened1, err := combined.Open(device1.Path())
		require.NoError(t, err)
		assert.Equal(t, device1.Path(), opened1.Path())

		opened2, err := combined.Open(device2.Path())
		require.NoError(t, err)
		assert.Equal(t, device2.Path(), opened2.Path())
	})
}

// TestConcurrentOperations tests thread safety.
func TestConcurrentOperations(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()

	const numGoroutines = 10
	const numOpsPerGoroutine = 5

	var wg sync.WaitGroup
	errChan := make(chan error, numGoroutines*numOpsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			for j := 0; j < numOpsPerGoroutine; j++ {
				attrs := &types.KeyAttributes{
					CN:           "concurrent-key",
					KeyAlgorithm: x509.ECDSA,
					Hash:         crypto.SHA256,
				}

				// Mix of operations
				switch j % 3 {
				case 0:
					if _, err := backend.GenerateKey(attrs); err != nil {
						errChan <- err
					}
				case 1:
					if _, err := backend.ListKeys(); err != nil {
						errChan <- err
					}
				case 2:
					if err := backend.VerifyPIN(virtualfido.DefaultPIN); err != nil {
						errChan <- err
					}
				}
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	assert.Empty(t, errs, "no errors should occur during concurrent operations")
}

// TestPIVSlotAllocation tests automatic PIV slot allocation.
func TestPIVSlotAllocation(t *testing.T) {
	backend := createTestBackend(t)
	defer backend.Close()

	t.Run("signing key uses signature slot", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "sig-key",
			KeyAlgorithm: x509.ECDSA,
			KeyType:      types.KeyTypeSigning,
			Hash:         crypto.SHA256,
		}
		_, err := backend.GenerateKey(attrs)
		require.NoError(t, err)

		keys, _ := backend.ListKeys()
		require.Len(t, keys, 1)
		// The CN should be the slot name
		assert.Contains(t, keys[0].CN, "Signature")
	})

	t.Run("encryption key uses key management slot", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "enc-key",
			KeyAlgorithm: x509.RSA,
			KeyType:      types.KeyTypeEncryption,
			Hash:         crypto.SHA256,
		}
		_, err := backend.GenerateKey(attrs)
		require.NoError(t, err)

		keys, _ := backend.ListKeys()
		found := false
		for _, k := range keys {
			if k.KeyAlgorithm == x509.RSA {
				assert.Contains(t, k.CN, "Key Management")
				found = true
			}
		}
		assert.True(t, found)
	})
}

// TestRetryCounters tests the retry counter functionality.
func TestRetryCounters(t *testing.T) {
	cfg := &virtualfido.Config{
		PIN:        "123456",
		PUK:        "12345678",
		PINRetries: 5,
		PUKRetries: 4,
	}
	backend, err := virtualfido.NewBackend(cfg)
	require.NoError(t, err)
	defer backend.Close()

	t.Run("initial retry counts", func(t *testing.T) {
		pinRetries, pukRetries, err := backend.GetRetryCount()
		require.NoError(t, err)
		assert.Equal(t, 5, pinRetries)
		assert.Equal(t, 4, pukRetries)
	})

	t.Run("retries decrease on failure", func(t *testing.T) {
		backend.VerifyPIN("wrong")
		backend.VerifyPIN("wrong")

		pinRetries, pukRetries, err := backend.GetRetryCount()
		require.NoError(t, err)
		assert.Equal(t, 3, pinRetries)
		assert.Equal(t, 4, pukRetries)
	})

	t.Run("retries reset on success", func(t *testing.T) {
		err := backend.VerifyPIN("123456")
		require.NoError(t, err)

		pinRetries, _, err := backend.GetRetryCount()
		require.NoError(t, err)
		assert.Equal(t, 5, pinRetries)
	})
}

// createTestBackend is a helper function that creates a test backend.
func createTestBackend(t *testing.T) *virtualfido.Backend {
	t.Helper()

	cfg := &virtualfido.Config{
		SerialNumber: "TEST-" + t.Name(),
	}
	backend, err := virtualfido.NewBackend(cfg)
	require.NoError(t, err)
	return backend
}
