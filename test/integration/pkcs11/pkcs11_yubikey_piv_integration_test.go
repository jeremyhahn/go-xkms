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

//go:build yubikey && pkcs11

package integration

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend/yubikey"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	pkcs11lib "github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// YubiKey PIV Slot Information
// ===========================
// YubiKey PIV supports the following standard PIV slots:
//   - 9a (Authentication): General authentication, requires PIN
//   - 9c (Digital Signature): Used for digital signatures, always requires PIN
//   - 9d (Key Management): Used for encryption/decryption, requires PIN
//   - 9e (Card Authentication): No PIN required for operations
//   - 82-95 (Retired Key Management): 20 additional slots for key storage
//
// IMPORTANT: YubiKey PIV requirements for key generation:
//   1. Slots must be EMPTY before key generation
//   2. Management key authentication is required (default: 010203...hex)
//   3. Keys must be generated on-device (no key import)
//
// To prepare YubiKey for testing:
//   - Delete existing keys: yubico-piv-tool -a delete-certificate -s 9a
//   - Or reset PIV app: yubico-piv-tool -a reset (WARNING: erases all keys!)
//   - Check status: yubico-piv-tool -a status
//
// These tests work with the YubiKey in its default PIV configuration.
// Tests will skip gracefully if slots are not empty.

const (
	PIV_SLOT_AUTHENTICATION = 0x9a
	PIV_SLOT_SIGNATURE      = 0x9c
	PIV_SLOT_KEY_MANAGEMENT = 0x9d
	PIV_SLOT_CARD_AUTH      = 0x9e
	PIV_SLOT_RETIRED_1      = 0x82
)

// getYubiKeyPIVConfig returns YubiKey PIV-specific configuration
func getYubiKeyPIVConfig(t *testing.T) (*yubikey.Config, bool) {
	// Check for YubiKey PKCS#11 library
	yubikeyLib := os.Getenv("YUBIKEY_PKCS11_LIBRARY")
	if yubikeyLib == "" {
		yubikeyLib = "/usr/lib/x86_64-linux-gnu/libykcs11.so"
		if _, err := os.Stat(yubikeyLib); os.IsNotExist(err) {
			candidates := []string{
				"/usr/lib/libykcs11.so",
				"/usr/local/lib/libykcs11.so",
				"/usr/local/lib/libykcs11.dylib",
			}

			found := false
			for _, path := range candidates {
				if _, err := os.Stat(path); err == nil {
					yubikeyLib = path
					found = true
					break
				}
			}

			if !found {
				t.Log("YubiKey PKCS#11 library not found")
				return nil, false
			}
		}
	}

	t.Logf("Using YubiKey PKCS#11 library: %s", yubikeyLib)

	pin := os.Getenv("YUBIKEY_PIN")
	if pin == "" {
		pin = "123456" // Default YubiKey PIV PIN
	}

	t.Logf("Using YubiKey PIN: %s", pin)

	// Discover the actual token label from the YubiKey
	p := pkcs11lib.New(yubikeyLib)
	if p == nil {
		t.Log("Failed to load PKCS#11 library")
		return nil, false
	}

	err := p.Initialize()
	if err != nil {
		t.Logf("Failed to initialize PKCS#11: %v", err)
		return nil, false
	}
	defer p.Finalize()
	defer p.Destroy()

	slots, err := p.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		t.Logf("No PKCS#11 slots found: %v", err)
		return nil, false
	}

	tokenInfo, err := p.GetTokenInfo(slots[0])
	if err != nil {
		t.Logf("Failed to get token info: %v", err)
		return nil, false
	}

	tokenLabel := tokenInfo.Label
	t.Logf("Discovered YubiKey token label: %s", tokenLabel)

	keyStorage := storage.New()
	certStorage := storage.New()

	// Use slot 0x9a (PIV Authentication) for YubiKey PIV operations
	slot := uint(0x9a)

	config := &yubikey.Config{
		Library:       yubikeyLib,
		TokenLabel:    tokenLabel,
		PIN:           pin,
		Slot:          &slot,
		ManagementKey: yubikey.DefaultMgmtKey,
		KeyStorage:    keyStorage,
		CertStorage:   certStorage,
	}

	return config, true
}

// cleanupSlot deletes any existing key from a PKCS#11 slot
func cleanupSlot(t *testing.T, ykBackend *yubikey.Backend, cn string) {
	attrs := &types.KeyAttributes{
		CN: cn,
	}
	// Try to delete - ignore errors if key doesn't exist
	_ = ykBackend.DeleteKey(attrs)
}

// TestYubiKeyPIV_BackendInfo verifies YubiKey PIV backend information
func TestYubiKeyPIV_BackendInfo(t *testing.T) {
	config, ok := getYubiKeyPIVConfig(t)
	if !ok {
		t.Fatal("YubiKey not available")
	}

	ykBackend, err := yubikey.NewBackend(config)
	require.NoError(t, err, "Failed to create YubiKey backend")
	defer ykBackend.Close()

	// YubiKey PIV tokens are pre-initialized - initialize the backend
	err = ykBackend.Initialize()
	require.NoError(t, err, "Failed to initialize YubiKey backend")

	t.Run("Type", func(t *testing.T) {
		backendType := ykBackend.Type()
		assert.Equal(t, types.BackendType("yubikey"), backendType)
		t.Logf("✓ Backend type: %s", backendType)
	})

	t.Run("Capabilities", func(t *testing.T) {
		caps := ykBackend.Capabilities()
		require.NotNil(t, caps)

		assert.True(t, caps.Keys, "YubiKey should support keys")
		assert.True(t, caps.HardwareBacked, "YubiKey is hardware-backed")
		assert.True(t, caps.Signing, "YubiKey should support signing")

		t.Log("✓ YubiKey capabilities verified")
	})

	t.Run("FirmwareVersion", func(t *testing.T) {
		fwVer := ykBackend.GetFirmwareVersion()
		require.NotNil(t, fwVer)
		t.Logf("✓ YubiKey firmware version: %d.%d.%d", fwVer.Major, fwVer.Minor, fwVer.Patch)

		// Check feature support
		t.Logf("  RSA 3072 support: %v", ykBackend.SupportsRSA3072())
		t.Logf("  RSA 4096 support: %v", ykBackend.SupportsRSA4096())
		t.Logf("  Ed25519 support: %v", ykBackend.SupportsEd25519())
		t.Logf("  X25519 support: %v", ykBackend.SupportsX25519())
		t.Logf("  AES support: %v", ykBackend.SupportsAES())
	})
}

// TestYubiKeyPIV_RSA tests RSA operations with YubiKey PIV
func TestYubiKeyPIV_RSA(t *testing.T) {
	config, ok := getYubiKeyPIVConfig(t)
	if !ok {
		t.Fatal("YubiKey not available")
	}

	ykBackend, err := yubikey.NewBackend(config)
	require.NoError(t, err, "Failed to create YubiKey backend")
	defer ykBackend.Close()

	// YubiKey PIV tokens are pre-initialized
	err = ykBackend.Initialize()
	require.NoError(t, err, "Failed to initialize YubiKey")

	t.Run("GenerateAndSign_RSA2048", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "yubikey-piv-rsa-2048-test",
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Clean up any existing key from previous runs
		cleanupSlot(t, ykBackend, attrs.CN)
		defer cleanupSlot(t, ykBackend, attrs.CN)

		key, err := ykBackend.GenerateRSA(attrs)
		if err != nil {
			t.Logf("Key generation failed: %v", err)
			t.Fatal("YubiKey PIV slot may be in use or require manual configuration")
			return
		}

		signer, ok := key.(crypto.Signer)
		require.True(t, ok, "Key should implement crypto.Signer")

		// Verify key properties
		rsaPub, ok := signer.Public().(*rsa.PublicKey)
		require.True(t, ok, "Public key should be RSA")
		assert.Equal(t, 2048, rsaPub.N.BitLen(), "Key size should be 2048 bits")

		// Test signing
		testData := []byte("YubiKey PIV RSA 2048 signing test")
		hashed := sha256.Sum256(testData)

		signature, err := signer.Sign(nil, hashed[:], crypto.SHA256)
		require.NoError(t, err, "Failed to sign data")
		assert.NotEmpty(t, signature, "Signature should not be empty")

		// Verify signature
		err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hashed[:], signature)
		require.NoError(t, err, "Signature verification failed")

		t.Log("✓ RSA 2048 key generation and signing successful")
	})

	t.Run("GenerateAndSign_RSA2048_PSS", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "yubikey-piv-rsa-2048-pss-test",
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
		}

		// Clean up any existing key from previous runs
		cleanupSlot(t, ykBackend, attrs.CN)
		defer cleanupSlot(t, ykBackend, attrs.CN)

		key, err := ykBackend.GenerateRSA(attrs)
		if err != nil {
			t.Logf("Key generation failed: %v", err)
			t.Fatal("YubiKey PIV slot may be in use or require manual configuration")
			return
		}

		signer, ok := key.(crypto.Signer)
		require.True(t, ok, "Key should implement crypto.Signer")

		// Verify key properties
		rsaPub, ok := signer.Public().(*rsa.PublicKey)
		require.True(t, ok, "Public key should be RSA")
		assert.Equal(t, 2048, rsaPub.N.BitLen(), "Key size should be 2048 bits")

		// Test signing with RSA-PSS
		testData := []byte("YubiKey PIV RSA 2048 PSS signing test")
		h := sha256.New()
		h.Write(testData)
		digest := h.Sum(nil)

		// crypto11 doesn't support PSSSaltLengthAuto, use PSSSaltLengthEqualsHash
		pssOpts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		}

		signature, err := signer.Sign(rand.Reader, digest, pssOpts)
		require.NoError(t, err, "Failed to sign data with PSS")
		assert.NotEmpty(t, signature, "Signature should not be empty")

		// Verify PSS signature
		err = rsa.VerifyPSS(rsaPub, crypto.SHA256, digest, signature, pssOpts)
		require.NoError(t, err, "PSS signature verification failed")

		t.Log("✓ RSA 2048 PSS signing successful")
	})

	t.Run("GenerateAndSign_RSA3072", func(t *testing.T) {
		if !ykBackend.SupportsRSA3072() {
			fwVer := ykBackend.GetFirmwareVersion()
			t.Fatalf("RSA 3072 requires firmware 5.7+, have %d.%d", fwVer.Major, fwVer.Minor)
		}

		attrs := &types.KeyAttributes{
			CN:           "yubikey-piv-rsa-3072-test",
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 3072,
			},
		}

		cleanupSlot(t, ykBackend, attrs.CN)
		defer cleanupSlot(t, ykBackend, attrs.CN)

		key, err := ykBackend.GenerateRSA(attrs)
		if err != nil {
			t.Logf("Key generation failed: %v", err)
			t.Fatal("YubiKey PIV slot may be in use or require manual configuration")
			return
		}

		signer, ok := key.(crypto.Signer)
		require.True(t, ok, "Key should implement crypto.Signer")

		rsaPub, ok := signer.Public().(*rsa.PublicKey)
		require.True(t, ok, "Public key should be RSA")
		assert.Equal(t, 3072, rsaPub.N.BitLen(), "Key size should be 3072 bits")

		// Test signing
		testData := []byte("YubiKey PIV RSA 3072 signing test")
		hashed := sha256.Sum256(testData)

		signature, err := signer.Sign(nil, hashed[:], crypto.SHA256)
		require.NoError(t, err, "Failed to sign data")
		assert.NotEmpty(t, signature, "Signature should not be empty")

		err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hashed[:], signature)
		require.NoError(t, err, "Signature verification failed")

		t.Log("✓ RSA 3072 key generation and signing successful")
	})

	t.Run("GenerateAndSign_RSA3072_PSS", func(t *testing.T) {
		if !ykBackend.SupportsRSA3072() {
			fwVer := ykBackend.GetFirmwareVersion()
			t.Fatalf("RSA 3072 requires firmware 5.7+, have %d.%d", fwVer.Major, fwVer.Minor)
		}

		attrs := &types.KeyAttributes{
			CN:           "yubikey-piv-rsa-3072-pss-test",
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 3072,
			},
		}

		cleanupSlot(t, ykBackend, attrs.CN)
		defer cleanupSlot(t, ykBackend, attrs.CN)

		key, err := ykBackend.GenerateRSA(attrs)
		if err != nil {
			t.Logf("Key generation failed: %v", err)
			t.Fatal("YubiKey PIV slot may be in use or require manual configuration")
			return
		}

		signer, ok := key.(crypto.Signer)
		require.True(t, ok, "Key should implement crypto.Signer")

		rsaPub, ok := signer.Public().(*rsa.PublicKey)
		require.True(t, ok, "Public key should be RSA")
		assert.Equal(t, 3072, rsaPub.N.BitLen(), "Key size should be 3072 bits")

		// Test signing with RSA-PSS
		testData := []byte("YubiKey PIV RSA 3072 PSS signing test")
		h := sha256.New()
		h.Write(testData)
		digest := h.Sum(nil)

		// crypto11 doesn't support PSSSaltLengthAuto, use PSSSaltLengthEqualsHash
		pssOpts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		}

		signature, err := signer.Sign(rand.Reader, digest, pssOpts)
		require.NoError(t, err, "Failed to sign data with PSS")
		assert.NotEmpty(t, signature, "Signature should not be empty")

		err = rsa.VerifyPSS(rsaPub, crypto.SHA256, digest, signature, pssOpts)
		require.NoError(t, err, "PSS signature verification failed")

		t.Log("✓ RSA 3072 PSS signing successful")
	})

	t.Run("GenerateAndSign_RSA4096", func(t *testing.T) {
		if !ykBackend.SupportsRSA4096() {
			fwVer := ykBackend.GetFirmwareVersion()
			t.Fatalf("RSA 4096 requires firmware 5.7+, have %d.%d", fwVer.Major, fwVer.Minor)
		}

		attrs := &types.KeyAttributes{
			CN:           "yubikey-piv-rsa-4096-test",
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 4096,
			},
		}

		cleanupSlot(t, ykBackend, attrs.CN)
		defer cleanupSlot(t, ykBackend, attrs.CN)

		key, err := ykBackend.GenerateRSA(attrs)
		if err != nil {
			t.Logf("Key generation failed: %v", err)
			t.Fatal("YubiKey PIV slot may be in use or require manual configuration")
			return
		}

		signer, ok := key.(crypto.Signer)
		require.True(t, ok, "Key should implement crypto.Signer")

		rsaPub, ok := signer.Public().(*rsa.PublicKey)
		require.True(t, ok, "Public key should be RSA")
		assert.Equal(t, 4096, rsaPub.N.BitLen(), "Key size should be 4096 bits")

		// Test signing
		testData := []byte("YubiKey PIV RSA 4096 signing test")
		hashed := sha256.Sum256(testData)

		signature, err := signer.Sign(nil, hashed[:], crypto.SHA256)
		require.NoError(t, err, "Failed to sign data")
		assert.NotEmpty(t, signature, "Signature should not be empty")

		err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hashed[:], signature)
		require.NoError(t, err, "Signature verification failed")

		t.Log("✓ RSA 4096 key generation and signing successful")
	})

	t.Run("GenerateAndSign_RSA4096_PSS", func(t *testing.T) {
		if !ykBackend.SupportsRSA4096() {
			fwVer := ykBackend.GetFirmwareVersion()
			t.Fatalf("RSA 4096 requires firmware 5.7+, have %d.%d", fwVer.Major, fwVer.Minor)
		}

		attrs := &types.KeyAttributes{
			CN:           "yubikey-piv-rsa-4096-pss-test",
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 4096,
			},
		}

		cleanupSlot(t, ykBackend, attrs.CN)
		defer cleanupSlot(t, ykBackend, attrs.CN)

		key, err := ykBackend.GenerateRSA(attrs)
		if err != nil {
			t.Logf("Key generation failed: %v", err)
			t.Fatal("YubiKey PIV slot may be in use or require manual configuration")
			return
		}

		signer, ok := key.(crypto.Signer)
		require.True(t, ok, "Key should implement crypto.Signer")

		rsaPub, ok := signer.Public().(*rsa.PublicKey)
		require.True(t, ok, "Public key should be RSA")
		assert.Equal(t, 4096, rsaPub.N.BitLen(), "Key size should be 4096 bits")

		// Test signing with RSA-PSS
		testData := []byte("YubiKey PIV RSA 4096 PSS signing test")
		h := sha256.New()
		h.Write(testData)
		digest := h.Sum(nil)

		// crypto11 doesn't support PSSSaltLengthAuto, use PSSSaltLengthEqualsHash
		pssOpts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		}

		signature, err := signer.Sign(rand.Reader, digest, pssOpts)
		require.NoError(t, err, "Failed to sign data with PSS")
		assert.NotEmpty(t, signature, "Signature should not be empty")

		err = rsa.VerifyPSS(rsaPub, crypto.SHA256, digest, signature, pssOpts)
		require.NoError(t, err, "PSS signature verification failed")

		t.Log("✓ RSA 4096 PSS signing successful")
	})
}

// TestYubiKeyPIV_ECDSA tests ECDSA operations with YubiKey PIV
func TestYubiKeyPIV_ECDSA(t *testing.T) {
	config, ok := getYubiKeyPIVConfig(t)
	if !ok {
		t.Fatal("YubiKey not available")
	}

	ykBackend, err := yubikey.NewBackend(config)
	require.NoError(t, err, "Failed to create YubiKey backend")
	defer ykBackend.Close()

	// YubiKey PIV tokens are pre-initialized
	err = ykBackend.Initialize()
	require.NoError(t, err, "Failed to initialize YubiKey")

	t.Run("GenerateAndSign_P256", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "yubikey-piv-ecdsa-p256-test",
			KeyAlgorithm: x509.ECDSA,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		// Clean up any existing key from previous runs
		cleanupSlot(t, ykBackend, attrs.CN)
		defer cleanupSlot(t, ykBackend, attrs.CN)

		key, err := ykBackend.GenerateECDSA(attrs)
		if err != nil {
			t.Logf("Key generation failed: %v", err)
			t.Fatal("YubiKey PIV slot may be in use or require manual configuration")
			return
		}

		signer, ok := key.(crypto.Signer)
		require.True(t, ok, "Key should implement crypto.Signer")

		// Verify key properties
		ecdsaPub, ok := signer.Public().(*ecdsa.PublicKey)
		require.True(t, ok, "Public key should be ECDSA")
		assert.Equal(t, elliptic.P256(), ecdsaPub.Curve, "Curve should be P-256")

		// Test signing
		testData := []byte("YubiKey PIV ECDSA P-256 signing test")
		hashed := sha256.Sum256(testData)

		signature, err := signer.Sign(nil, hashed[:], crypto.SHA256)
		require.NoError(t, err, "Failed to sign data")
		assert.NotEmpty(t, signature, "Signature should not be empty")

		// Verify signature using ECDSA
		valid := ecdsa.VerifyASN1(ecdsaPub, hashed[:], signature)
		require.True(t, valid, "ECDSA signature verification failed")

		t.Log("✓ ECDSA P-256 key generation and signing successful")
	})

	t.Run("GenerateAndSign_P384", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "yubikey-piv-ecdsa-p384-test",
			KeyAlgorithm: x509.ECDSA,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P384(),
			},
		}

		// Clean up any existing key from previous runs
		cleanupSlot(t, ykBackend, attrs.CN)
		defer cleanupSlot(t, ykBackend, attrs.CN)

		key, err := ykBackend.GenerateECDSA(attrs)
		if err != nil {
			t.Logf("Key generation failed: %v", err)
			t.Fatal("YubiKey PIV slot may be in use or require manual configuration")
			return
		}

		signer, ok := key.(crypto.Signer)
		require.True(t, ok, "Key should implement crypto.Signer")

		// Verify key properties
		ecdsaPub, ok := signer.Public().(*ecdsa.PublicKey)
		require.True(t, ok, "Public key should be ECDSA")
		assert.Equal(t, elliptic.P384(), ecdsaPub.Curve, "Curve should be P-384")

		// Test signing
		testData := []byte("YubiKey PIV ECDSA P-384 signing test")
		hashed := sha256.Sum256(testData)

		signature, err := signer.Sign(nil, hashed[:], crypto.SHA256)
		require.NoError(t, err, "Failed to sign data")
		assert.NotEmpty(t, signature, "Signature should not be empty")

		// Verify signature using ECDSA
		valid := ecdsa.VerifyASN1(ecdsaPub, hashed[:], signature)
		require.True(t, valid, "ECDSA signature verification failed")

		t.Log("✓ ECDSA P-384 key generation and signing successful")
	})
}

// TestYubiKeyPIV_KeyRetrieval tests key retrieval operations
func TestYubiKeyPIV_KeyRetrieval(t *testing.T) {
	config, ok := getYubiKeyPIVConfig(t)
	if !ok {
		t.Fatal("YubiKey not available")
	}

	ykBackend, err := yubikey.NewBackend(config)
	require.NoError(t, err, "Failed to create YubiKey backend")
	defer ykBackend.Close()

	// YubiKey PIV tokens are pre-initialized
	// Use Login() to create context for pre-initialized tokens
	err = ykBackend.Initialize()
	require.NoError(t, err, "Failed to login to YubiKey")

	attrs := &types.KeyAttributes{
		CN:           "yubikey-piv-retrieval-test",
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	// Clean up any existing key from previous runs
	cleanupSlot(t, ykBackend, attrs.CN)

	// Ensure cleanup after test
	defer cleanupSlot(t, ykBackend, attrs.CN)

	// Generate key
	_, err = ykBackend.GenerateRSA(attrs)
	if err != nil {
		t.Logf("Key generation failed: %v", err)
		t.Fatal("YubiKey PIV slot may be in use")
		return
	}

	// Retrieve key
	_, err = ykBackend.GetKey(attrs)
	require.NoError(t, err, "Failed to retrieve key")

	t.Log("✓ Key retrieval successful")
}

// TestYubiKeyPIV_RandomGeneration tests hardware RNG
func TestYubiKeyPIV_RandomGeneration(t *testing.T) {
	config, ok := getYubiKeyPIVConfig(t)
	if !ok {
		t.Fatal("YubiKey not available")
	}

	ykBackend, err := yubikey.NewBackend(config)
	require.NoError(t, err, "Failed to create YubiKey backend")
	defer ykBackend.Close()

	err = ykBackend.Initialize()
	require.NoError(t, err, "Failed to initialize YubiKey")

	t.Run("GenerateRandom_32bytes", func(t *testing.T) {
		random, err := ykBackend.GenerateRandom(32)
		require.NoError(t, err, "Failed to generate random bytes")
		assert.Len(t, random, 32, "Should generate 32 bytes")

		// Check that bytes are not all zeros
		allZeros := true
		for _, b := range random {
			if b != 0 {
				allZeros = false
				break
			}
		}
		assert.False(t, allZeros, "Random bytes should not be all zeros")

		t.Logf("✓ Generated 32 random bytes from YubiKey hardware RNG")
	})

	t.Run("GenerateRandom_256bytes", func(t *testing.T) {
		random, err := ykBackend.GenerateRandom(256)
		require.NoError(t, err, "Failed to generate random bytes")
		assert.Len(t, random, 256, "Should generate 256 bytes")

		t.Logf("✓ Generated 256 random bytes from YubiKey hardware RNG")
	})

	t.Run("GenerateRandom_Uniqueness", func(t *testing.T) {
		random1, err := ykBackend.GenerateRandom(64)
		require.NoError(t, err, "Failed to generate first random bytes")

		random2, err := ykBackend.GenerateRandom(64)
		require.NoError(t, err, "Failed to generate second random bytes")

		// Verify they're different
		assert.NotEqual(t, random1, random2, "Consecutive random generations should produce different values")

		t.Logf("✓ YubiKey RNG produces unique values")
	})

	t.Run("GenerateRandom_MaxSize", func(t *testing.T) {
		// Test maximum recommended size
		random, err := ykBackend.GenerateRandom(1024)
		require.NoError(t, err, "Failed to generate 1024 random bytes")
		assert.Len(t, random, 1024, "Should generate 1024 bytes")

		t.Logf("✓ Generated 1024 random bytes (max recommended size)")
	})

	t.Run("GenerateRandom_ExceedsMax", func(t *testing.T) {
		// Should fail for sizes > 1024
		_, err := ykBackend.GenerateRandom(2048)
		assert.Error(t, err, "Should fail for size > 1024")
		assert.Contains(t, err.Error(), "exceeds maximum", "Error should mention size limit")

		t.Logf("✓ Properly rejects oversized RNG requests")
	})

	t.Run("GenerateRandom_InvalidLength", func(t *testing.T) {
		_, err := ykBackend.GenerateRandom(0)
		assert.Error(t, err, "Should fail for zero length")

		_, err = ykBackend.GenerateRandom(-1)
		assert.Error(t, err, "Should fail for negative length")

		t.Logf("✓ Properly validates RNG length parameter")
	})
}

// TestYubiKeyPIV_Documentation documents YubiKey PIV usage
func TestYubiKeyPIV_Documentation(t *testing.T) {
	t.Log("=== YubiKey PIV Integration Guide ===")
	t.Log("")
	t.Log("YubiKey PIV Slots:")
	t.Logf("  0x9a - Authentication (requires PIN)")
	t.Logf("  0x9c - Digital Signature (always requires PIN)")
	t.Logf("  0x9d - Key Management (requires PIN)")
	t.Logf("  0x9e - Card Authentication (no PIN required)")
	t.Logf("  0x82-0x95 - Retired Key Management (20 slots)")
	t.Log("")
	t.Log("YubiKey PIV Requirements:")
	t.Log("  - Keys must be generated on-device (no key import)")
	t.Log("  - Slots must be empty before key generation")
	t.Log("  - Some operations require management key (default: 010203...)")
	t.Log("  - Default PIN: 123456")
	t.Log("  - Default PUK: 12345678")
	t.Log("")
	t.Log("Slot Management:")
	t.Log("  - Use 'yubico-piv-tool' for advanced slot management")
	t.Log("  - Reset PIV app: yubico-piv-tool -a reset")
	t.Log("  - List certs: yubico-piv-tool -a status")
	t.Log("  - Delete cert: yubico-piv-tool -a delete-certificate -s 9a")
	t.Log("")
	t.Log("For manual YubiKey PIV key generation using specific slots,")
	t.Log("use the yubico-piv-tool command-line utility or Yubico Manager.")
}
