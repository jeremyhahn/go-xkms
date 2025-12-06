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
	"crypto/x509/pkix"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	pkcs11lib "github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// getYubiKeyConfig returns configuration for YubiKey PKCS#11
func getYubiKeyConfig(t *testing.T) (*pkcs11.Config, bool) {
	// Check for YubiKey PKCS#11 library
	yubikeyLib := os.Getenv("YUBIKEY_PKCS11_LIBRARY")
	if yubikeyLib == "" {
		// Default to standard Linux location
		yubikeyLib = "/usr/lib/x86_64-linux-gnu/libykcs11.so"

		// If not found, try other common locations
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
				return nil, false
			}
		}
	}

	t.Logf("Using YubiKey PKCS#11 library: %s", yubikeyLib)

	// Get PIN from environment or use default
	pin := os.Getenv("YUBIKEY_PIN")
	if pin == "" {
		pin = "123456" // Default YubiKey PIV PIN
	}

	t.Logf("Using YubiKey PIN: %s", pin)

	// Get SO PIN from environment or use default
	// Note: YubiKey PIV doesn't use SO PIN in the traditional sense
	// The Management Key is used instead, but we'll set a value for compatibility
	soPin := os.Getenv("YUBIKEY_SO_PIN")
	if soPin == "" {
		soPin = "010203040506070801020304050607080102030405060708" // Default YubiKey Management Key
	}

	// Discover the actual token label from the YubiKey
	// YubiKey PIV tokens have labels like "YubiKey PIV #SERIALNUMBER"
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

	// Create storage backends
	keyStorage := storage.New()
	certStorage := storage.New()

	config := &pkcs11.Config{
		Library:     yubikeyLib,
		TokenLabel:  tokenLabel,
		PIN:         pin,
		SOPIN:       soPin,
		KeyStorage:  keyStorage,
		CertStorage: certStorage,
	}

	return config, true
}

// TestYubiKeyPKCS11Integration performs comprehensive integration tests for YubiKey PKCS#11
func TestYubiKeyPKCS11Integration(t *testing.T) {
	config, available := getYubiKeyConfig(t)
	if !available {
		t.Skip("YubiKey PKCS#11 library not found. Install Yubico PIV Tool or set YUBIKEY_PKCS11_LIBRARY environment variable.")
	}

	// Create PKCS11 backend
	yubikey, err := pkcs11.NewBackend(config)
	if err != nil {
		t.Skipf("Failed to create YubiKey PKCS#11 backend: %v (YubiKey may not be connected)", err)
	}
	defer yubikey.Close()

	// Initialize (login to the YubiKey)
	err = yubikey.Initialize(config.SOPIN, config.PIN)
	if err != nil && err != pkcs11.ErrAlreadyInitialized {
		t.Skipf("Failed to initialize YubiKey PKCS#11 backend: %v", err)
	}

	t.Log("=== YubiKey PKCS#11 Integration Tests ===")

	// ========================================
	// Key Generation Tests
	// ========================================
	t.Run("KeyGeneration", func(t *testing.T) {
		t.Run("RSA-2048", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "yubikey-test-rsa-2048",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			key, err := yubikey.GenerateRSA(attrs)
			require.NoError(t, err, "Failed to generate RSA-2048 key on YubiKey")
			require.NotNil(t, key)

			// Verify it's a crypto.Signer
			signer, ok := key.(crypto.Signer)
			require.True(t, ok, "Key must implement crypto.Signer")

			// Verify public key
			rsaPub, ok := signer.Public().(*rsa.PublicKey)
			require.True(t, ok, "Expected RSA public key")
			assert.Equal(t, 2048, rsaPub.N.BitLen(), "Key size should be 2048 bits")

			t.Logf("✓ Generated RSA-2048 key on YubiKey: %d bits", rsaPub.N.BitLen())

			// Clean up
			err = yubikey.DeleteKey(attrs)
			assert.NoError(t, err, "Failed to delete test key")
		})

		t.Run("ECDSA-P256", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "yubikey-test-ecdsa-p256",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P256(),
				},
			}

			key, err := yubikey.GenerateECDSA(attrs)
			require.NoError(t, err, "Failed to generate ECDSA-P256 key on YubiKey")
			require.NotNil(t, key)

			// Verify it's a crypto.Signer
			signer, ok := key.(crypto.Signer)
			require.True(t, ok, "Key must implement crypto.Signer")

			// Verify public key
			ecdsaPub, ok := signer.Public().(*ecdsa.PublicKey)
			require.True(t, ok, "Expected ECDSA public key")
			assert.Equal(t, elliptic.P256(), ecdsaPub.Curve, "Curve should be P-256")

			t.Logf("✓ Generated ECDSA-P256 key on YubiKey")

			// Clean up
			err = yubikey.DeleteKey(attrs)
			assert.NoError(t, err, "Failed to delete test key")
		})

		t.Run("ECDSA-P384", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "yubikey-test-ecdsa-p384",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P384(),
				},
			}

			key, err := yubikey.GenerateECDSA(attrs)
			require.NoError(t, err, "Failed to generate ECDSA-P384 key on YubiKey")
			require.NotNil(t, key)

			// Verify it's a crypto.Signer
			signer, ok := key.(crypto.Signer)
			require.True(t, ok, "Key must implement crypto.Signer")

			// Verify public key
			ecdsaPub, ok := signer.Public().(*ecdsa.PublicKey)
			require.True(t, ok, "Expected ECDSA public key")
			assert.Equal(t, elliptic.P384(), ecdsaPub.Curve, "Curve should be P-384")

			t.Logf("✓ Generated ECDSA-P384 key on YubiKey")

			// Clean up
			err = yubikey.DeleteKey(attrs)
			assert.NoError(t, err, "Failed to delete test key")
		})
	})

	// ========================================
	// Signing Tests
	// ========================================
	t.Run("Signing", func(t *testing.T) {
		t.Run("RSA-2048-Sign-Verify", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "yubikey-signing-rsa-2048",
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Generate key
			key, err := yubikey.GenerateRSA(attrs)
			require.NoError(t, err)
			defer yubikey.DeleteKey(attrs)

			signer, ok := key.(crypto.Signer)
			require.True(t, ok)

			// Sign data
			message := []byte("YubiKey PKCS#11 signing test")
			digest := sha256.Sum256(message)

			signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
			require.NoError(t, err, "Failed to sign with YubiKey")
			require.NotEmpty(t, signature)

			// Verify signature
			rsaPub := signer.Public().(*rsa.PublicKey)
			err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], signature)
			assert.NoError(t, err, "Signature verification failed")

			t.Logf("✓ RSA-2048 signing and verification on YubiKey successful")
		})

		t.Run("RSA-2048-PSS-Sign-Verify", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "yubikey-signing-rsa-2048-pss",
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Generate key
			key, err := yubikey.GenerateRSA(attrs)
			require.NoError(t, err)
			defer yubikey.DeleteKey(attrs)

			signer, ok := key.(crypto.Signer)
			require.True(t, ok)

			// Sign data with RSA-PSS
			message := []byte("YubiKey PKCS#11 RSA-PSS signing test")
			h := sha256.New()
			h.Write(message)
			digest := h.Sum(nil)

			// crypto11 doesn't support PSSSaltLengthAuto, use PSSSaltLengthEqualsHash
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       crypto.SHA256,
			}

			signature, err := signer.Sign(rand.Reader, digest, pssOpts)
			require.NoError(t, err, "Failed to sign with YubiKey using RSA-PSS")
			require.NotEmpty(t, signature)

			// Verify PSS signature
			rsaPub := signer.Public().(*rsa.PublicKey)
			err = rsa.VerifyPSS(rsaPub, crypto.SHA256, digest, signature, pssOpts)
			assert.NoError(t, err, "RSA-PSS signature verification failed")

			t.Logf("✓ RSA-2048 PSS signing and verification on YubiKey successful")
		})

		t.Run("ECDSA-P256-Sign-Verify", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "yubikey-signing-ecdsa-p256",
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P256(),
				},
			}

			// Generate key
			key, err := yubikey.GenerateECDSA(attrs)
			require.NoError(t, err)
			defer yubikey.DeleteKey(attrs)

			signer, ok := key.(crypto.Signer)
			require.True(t, ok)

			// Sign data
			message := []byte("YubiKey PKCS#11 ECDSA signing test")
			digest := sha256.Sum256(message)

			signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
			require.NoError(t, err, "Failed to sign with YubiKey")
			require.NotEmpty(t, signature)

			// Verify signature
			ecdsaPub := signer.Public().(*ecdsa.PublicKey)
			valid := ecdsa.VerifyASN1(ecdsaPub, digest[:], signature)
			assert.True(t, valid, "ECDSA signature verification failed")

			t.Logf("✓ ECDSA-P256 signing and verification on YubiKey successful")
		})
	})

	// ========================================
	// Key Retrieval Tests
	// ========================================
	t.Run("KeyRetrieval", func(t *testing.T) {
		t.Run("GetKey-AfterGeneration", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "yubikey-retrieval-test",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Generate key
			originalKey, err := yubikey.GenerateRSA(attrs)
			require.NoError(t, err)
			defer yubikey.DeleteKey(attrs)

			// Retrieve the same key
			retrievedKey, err := yubikey.GetKey(attrs)
			require.NoError(t, err)
			require.NotNil(t, retrievedKey)

			// Verify both keys have the same public key
			originalPub := originalKey.(crypto.Signer).Public().(*rsa.PublicKey)
			retrievedPub := retrievedKey.(crypto.Signer).Public().(*rsa.PublicKey)

			assert.Equal(t, originalPub.N, retrievedPub.N, "Public keys should match")
			assert.Equal(t, originalPub.E, retrievedPub.E, "Public exponents should match")

			t.Log("✓ Key retrieval from YubiKey successful")
		})

		t.Run("KeyExists", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "yubikey-exists-test",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Key should not exist - GetKey should return error
			_, err := yubikey.GetKey(attrs)
			assert.Error(t, err, "Key should not exist yet")

			// Generate key
			_, err = yubikey.GenerateRSA(attrs)
			require.NoError(t, err)
			defer yubikey.DeleteKey(attrs)

			// Key should now exist - GetKey should succeed
			key, err := yubikey.GetKey(attrs)
			require.NoError(t, err)
			assert.NotNil(t, key, "Key should exist after generation")

			t.Log("✓ YubiKey key existence check successful")
		})
	})

	// ========================================
	// Certificate Operations
	// ========================================
	t.Run("CertificateOperations", func(t *testing.T) {
		t.Run("GenerateSelfSignedCert", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "yubikey-cert-test",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Generate key
			key, err := yubikey.GenerateRSA(attrs)
			require.NoError(t, err)
			defer yubikey.DeleteKey(attrs)

			signer := key.(crypto.Signer)
			publicKey := signer.Public()

			// Create self-signed certificate
			template := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject: pkix.Name{
					CommonName:   "YubiKey Test Certificate",
					Organization: []string{"Test Org"},
				},
				NotBefore:             time.Now(),
				NotAfter:              time.Now().Add(24 * time.Hour),
				KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true,
			}

			certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, signer)
			require.NoError(t, err, "Failed to create self-signed certificate with YubiKey")
			require.NotEmpty(t, certDER)

			// Parse certificate
			cert, err := x509.ParseCertificate(certDER)
			require.NoError(t, err)
			assert.Equal(t, "YubiKey Test Certificate", cert.Subject.CommonName)

			t.Log("✓ Self-signed certificate creation with YubiKey successful")
		})
	})

	// ========================================
	// Key Deletion Tests
	// ========================================
	t.Run("KeyDeletion", func(t *testing.T) {
		t.Run("DeleteKey", func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "yubikey-delete-test",
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_PKCS11,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			}

			// Generate key
			_, err := yubikey.GenerateRSA(attrs)
			require.NoError(t, err)

			// Verify key exists
			key, err := yubikey.GetKey(attrs)
			require.NoError(t, err)
			require.NotNil(t, key)

			// Delete key
			err = yubikey.DeleteKey(attrs)
			assert.NoError(t, err, "Failed to delete key from YubiKey")

			// Verify key no longer exists
			_, err = yubikey.GetKey(attrs)
			assert.Error(t, err, "Key should not exist after deletion")

			t.Log("✓ Key deletion from YubiKey successful")
		})
	})

	// ========================================
	// Backend Information Tests
	// ========================================
	t.Run("BackendInformation", func(t *testing.T) {
		t.Run("Type", func(t *testing.T) {
			backendType := yubikey.Type()
			assert.Equal(t, backend.BackendTypePKCS11, backendType)
			t.Logf("✓ Backend type: %v", backendType)
		})

		t.Run("Capabilities", func(t *testing.T) {
			caps := yubikey.Capabilities()
			assert.True(t, caps.Keys, "Should support key operations")
			assert.True(t, caps.HardwareBacked, "Should be hardware-backed")
			assert.True(t, caps.Signing, "Should support signing")

			t.Logf("✓ YubiKey capabilities verified")
		})
	})
}

// TestYubiKeyRNG tests the YubiKey's random number generation capabilities via crypto/rand
// Note: Direct RNG access via Backend.Random() is not implemented.
// YubiKey RNG is accessed through crypto/rand tests instead.
func TestYubiKeyRNG(t *testing.T) {
	t.Skip("YubiKey RNG tests are in test/integration/crypto/rand_yubikey_integration_test.go")
}

// TestYubiKeyStressTest performs stress testing on the YubiKey
func TestYubiKeyStressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	config, available := getYubiKeyConfig(t)
	if !available {
		t.Skip("YubiKey PKCS#11 library not found")
	}

	yubikey, err := pkcs11.NewBackend(config)
	if err != nil {
		t.Skipf("Failed to create YubiKey PKCS#11 backend: %v", err)
	}
	defer yubikey.Close()

	err = yubikey.Initialize(config.SOPIN, config.PIN)
	if err != nil && err != pkcs11.ErrAlreadyInitialized {
		t.Skipf("Failed to initialize YubiKey: %v", err)
	}

	t.Run("MultipleSignOperations", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "yubikey-stress-test",
			KeyType:      backend.KEY_TYPE_SIGNING,
			StoreType:    backend.STORE_PKCS11,
			KeyAlgorithm: x509.ECDSA,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		// Generate key
		key, err := yubikey.GenerateECDSA(attrs)
		require.NoError(t, err)
		defer yubikey.DeleteKey(attrs)

		signer := key.(crypto.Signer)

		// Perform 100 signing operations
		numOps := 100
		for i := 0; i < numOps; i++ {
			message := []byte("Stress test message " + string(rune(i)))
			digest := sha256.Sum256(message)

			signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
			require.NoError(t, err, "Sign operation %d failed", i)
			require.NotEmpty(t, signature)

			// Verify signature
			ecdsaPub := signer.Public().(*ecdsa.PublicKey)
			valid := ecdsa.VerifyASN1(ecdsaPub, digest[:], signature)
			assert.True(t, valid, "Verification failed for operation %d", i)
		}

		t.Logf("✓ Successfully performed %d signing operations on YubiKey", numOps)
	})
}
