//go:build integration && tpm2

package integration

import (
	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	tpm2lib "github.com/jeremyhahn/go-keychain/pkg/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// provisionTPMIfNeeded ensures TPM is provisioned with SRK
func provisionTPMIfNeeded(t *testing.T, tpmInstance tpm2lib.TrustedPlatformModule) *types.KeyAttributes {
	t.Helper()

	srkAttrs, err := tpmInstance.SSRKAttributes()
	if err != nil {
		t.Log("SRK not found, provisioning TPM...")
		if err := tpmInstance.Provision(nil); err != nil {
			t.Fatalf("Failed to provision TPM: %v", err)
		}
		srkAttrs, err = tpmInstance.SSRKAttributes()
		if err != nil {
			t.Fatalf("Failed to get SRK attributes after provisioning: %v", err)
		}
	}
	return srkAttrs
}

// TestIntegration_RSAEncryptDecrypt tests RSA encryption and decryption roundtrip
func TestIntegration_RSAEncryptDecrypt(t *testing.T) {
	tpmInstance, cleanup := setupTPM2(t)
	defer cleanup()

	srkAttrs := provisionTPMIfNeeded(t, tpmInstance)

	testCases := []struct {
		name       string
		message    string
		shouldFail bool
	}{
		{
			name:       "Short Message",
			message:    "Hello, TPM!",
			shouldFail: false,
		},
		{
			name:       "Medium Message",
			message:    "This is a longer test message for RSA encryption",
			shouldFail: false,
		},
		{
			name:       "Empty Message",
			message:    "",
			shouldFail: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create RSA key for encryption/decryption
			keyAttrs := &types.KeyAttributes{
				CN:           "rsa-encrypt-test-" + tc.name,
				KeyAlgorithm: x509.RSA,
				KeyType:      types.KeyTypeEncryption,
				Parent:       srkAttrs,
				Password:     types.NewClearPassword(nil),
				StoreType:    types.StoreTPM2,
				TPMAttributes: &types.TPMAttributes{
					Hierarchy: tpm2.TPMRHOwner,
				},
			}

			// Create RSA key with encryption capability
			rsaPub, err := tpmInstance.CreateRSA(keyAttrs, nil, false)
			if err != nil {
				if tc.shouldFail {
					t.Logf("Expected failure: %v", err)
					return
				}
				t.Fatalf("Failed to create RSA key: %v", err)
			}

			if tc.shouldFail {
				t.Fatal("Expected operation to fail, but it succeeded")
			}

			// Verify RSA public key
			if rsaPub == nil {
				t.Fatal("CreateRSA returned nil public key")
			}
			if rsaPub.N == nil {
				t.Fatal("RSA public key modulus is nil")
			}

			keySize := rsaPub.N.BitLen()
			t.Logf("Created %d-bit RSA key", keySize)

			// Get the key handle and name from attributes
			keyHandle := keyAttrs.TPMAttributes.Handle.(tpm2.TPMHandle)
			keyName := keyAttrs.TPMAttributes.Name.(tpm2.TPM2BName)

			// Encrypt the message using TPM
			plaintext := []byte(tc.message)
			ciphertext, err := tpmInstance.RSAEncrypt(keyHandle, keyName, plaintext)
			if err != nil {
				t.Fatalf("RSA encryption failed: %v", err)
			}

			// Verify ciphertext is different from plaintext (unless empty)
			if len(plaintext) > 0 && bytes.Equal(ciphertext, plaintext) {
				t.Error("Ciphertext should be different from plaintext")
			}

			// Verify ciphertext is not empty
			if len(ciphertext) == 0 && len(plaintext) > 0 {
				t.Error("Ciphertext is empty but plaintext was not")
			}

			// Decrypt the ciphertext using TPM
			decrypted, err := tpmInstance.RSADecrypt(keyHandle, keyName, ciphertext)
			if err != nil {
				t.Fatalf("RSA decryption failed: %v", err)
			}

			// Verify decrypted data matches original plaintext
			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("Decrypted data does not match original:\nExpected: %q\nGot: %q",
					plaintext, decrypted)
			}

			t.Logf("Successfully encrypted and decrypted %d bytes using %d-bit RSA key",
				len(plaintext), keySize)

			tpmInstance.Flush(keyHandle)
		})
	}
}

// TestIntegration_RSAEncryptDecrypt_InvalidInput tests error cases
func TestIntegration_RSAEncryptDecrypt_InvalidInput(t *testing.T) {
	tpmInstance, cleanup := setupTPM2(t)
	defer cleanup()

	provisionTPMIfNeeded(t, tpmInstance)

	testCases := []struct {
		name        string
		handle      tpm2.TPMHandle
		data        []byte
		expectError bool
	}{
		{
			name:        "Invalid Handle",
			handle:      tpm2.TPMHandle(0xDEADBEEF),
			data:        []byte("test"),
			expectError: true,
		},
		{
			name:        "Zero Handle",
			handle:      tpm2.TPMHandle(0),
			data:        []byte("test"),
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tpmInstance.RSAEncrypt(tc.handle, tpm2.TPM2BName{}, tc.data)
			if tc.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			_, err = tpmInstance.RSADecrypt(tc.handle, tpm2.TPM2BName{}, tc.data)
			if tc.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestIntegration_CreateRSA tests RSA key creation with various configurations
func TestIntegration_CreateRSA(t *testing.T) {
	tpmInstance, cleanup := setupTPM2(t)
	defer cleanup()

	srkAttrs := provisionTPMIfNeeded(t, tpmInstance)

	testCases := []struct {
		name           string
		sigAlg         x509.SignatureAlgorithm
		platformPolicy bool
	}{
		{
			name:   "RSA SSA",
			sigAlg: x509.SHA256WithRSA,
		},
		{
			name:   "RSA PSS",
			sigAlg: x509.SHA256WithRSAPSS,
		},
		{
			name:           "RSA with Platform Policy",
			sigAlg:         x509.SHA256WithRSA,
			platformPolicy: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keyAttrs := &types.KeyAttributes{
				CN:                 "integration-test-rsa-" + tc.name,
				KeyAlgorithm:       x509.RSA,
				KeyType:            types.KeyTypeCA,
				Parent:             srkAttrs,
				Password:           types.NewClearPassword(nil),
				StoreType:          types.StoreTPM2,
				SignatureAlgorithm: tc.sigAlg,
				PlatformPolicy:     tc.platformPolicy,
				TPMAttributes: &types.TPMAttributes{
					Hierarchy: tpm2.TPMRHOwner,
				},
			}

			// Create RSA key
			rsaPub, err := tpmInstance.CreateRSA(keyAttrs, nil, false)
			if err != nil {
				t.Fatalf("Failed to create RSA key: %v", err)
			}

			// Verify key was created
			if rsaPub == nil {
				t.Fatal("CreateRSA returned nil public key")
			}

			if rsaPub.N == nil {
				t.Fatal("RSA public key modulus is nil")
			}

			actualSize := rsaPub.N.BitLen()
			t.Logf("Created RSA key with %d-bit modulus", actualSize)

			// Verify key attributes were updated
			if keyAttrs.TPMAttributes == nil {
				t.Error("TPM attributes not set after key creation")
			} else {
				if keyAttrs.TPMAttributes.Handle == 0 {
					t.Error("Key handle not set")
				}
				if len(keyAttrs.TPMAttributes.Name.(tpm2.TPM2BName).Buffer) == 0 {
					t.Error("Key name not set")
				}
			}

			t.Logf("Successfully created %d-bit RSA key with %s signature algorithm",
				actualSize, tc.sigAlg.String())

			tpmInstance.Flush(keyAttrs.TPMAttributes.Handle.(tpm2.TPMHandle))
		})
	}
}

// TestIntegration_CreateRSA_ErrorCases tests error handling in RSA key creation
func TestIntegration_CreateRSA_ErrorCases(t *testing.T) {
	tpmInstance, cleanup := setupTPM2(t)
	defer cleanup()

	testCases := []struct {
		name      string
		keyAttrs  *types.KeyAttributes
		expectErr bool
	}{
		{
			name: "Nil Parent",
			keyAttrs: &types.KeyAttributes{
				CN:           "test-nil-parent",
				KeyAlgorithm: x509.RSA,
				KeyType:      types.KeyTypeCA,
				Parent:       nil,
				Password:     types.NewClearPassword(nil),
				StoreType:    types.StoreTPM2,
			},
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tpmInstance.CreateRSA(tc.keyAttrs, nil, false)
			if tc.expectErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !tc.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestIntegration_CreateECDSA tests ECDSA key creation with various curves
func TestIntegration_CreateECDSA(t *testing.T) {
	tpmInstance, cleanup := setupTPM2(t)
	defer cleanup()

	srkAttrs := provisionTPMIfNeeded(t, tpmInstance)

	testCases := []struct {
		name           string
		curve          elliptic.Curve
		platformPolicy bool
		maySkip        bool // Some TPM simulators don't support all curves
	}{
		{
			name:  "ECDSA P-256",
			curve: elliptic.P256(),
		},
		{
			name:    "ECDSA P-384",
			curve:   elliptic.P384(),
			maySkip: true, // Software TPM may not support P-384
		},
		{
			name:    "ECDSA P-521",
			curve:   elliptic.P521(),
			maySkip: true, // Software TPM may not support P-521
		},
		{
			name:           "ECDSA P-256 with Platform Policy",
			curve:          elliptic.P256(),
			platformPolicy: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keyAttrs := &types.KeyAttributes{
				CN:             "integration-test-ecdsa-" + tc.name,
				KeyAlgorithm:   x509.ECDSA,
				KeyType:        types.KeyTypeCA,
				Parent:         srkAttrs,
				Password:       types.NewClearPassword(nil),
				StoreType:      types.StoreTPM2,
				PlatformPolicy: tc.platformPolicy,
				ECCAttributes: &types.ECCAttributes{
					Curve: tc.curve,
				},
				TPMAttributes: &types.TPMAttributes{
					Hierarchy: tpm2.TPMRHOwner,
				},
			}

			// Create ECDSA key
			ecdsaPub, err := tpmInstance.CreateECDSA(keyAttrs, nil, false)
			if err != nil {
				// Check if this is a curve not supported error
				if tc.maySkip && isCurveNotSupportedError(err) {
					t.Skipf("Curve %s not supported by TPM simulator: %v", tc.curve.Params().Name, err)
					return
				}
				t.Fatalf("Failed to create ECDSA key: %v", err)
			}

			// Verify key was created
			if ecdsaPub == nil {
				t.Fatal("CreateECDSA returned nil public key")
			}

			if ecdsaPub.X == nil || ecdsaPub.Y == nil {
				t.Fatal("ECDSA public key coordinates are nil")
			}

			// Verify curve
			if ecdsaPub.Curve == nil {
				t.Fatal("ECDSA curve is nil")
			}

			expectedCurveName := tc.curve.Params().Name
			actualCurveName := ecdsaPub.Curve.Params().Name
			if actualCurveName != expectedCurveName {
				t.Errorf("Expected curve %s, got %s", expectedCurveName, actualCurveName)
			}

			// Verify key is on the curve
			if !ecdsaPub.Curve.IsOnCurve(ecdsaPub.X, ecdsaPub.Y) {
				t.Error("Public key point is not on the curve")
			}

			// Verify key attributes were updated
			if keyAttrs.TPMAttributes == nil {
				t.Error("TPM attributes not set after key creation")
			} else {
				if keyAttrs.TPMAttributes.Handle == 0 {
					t.Error("Key handle not set")
				}
				if len(keyAttrs.TPMAttributes.Name.(tpm2.TPM2BName).Buffer) == 0 {
					t.Error("Key name not set")
				}
			}

			t.Logf("Successfully created ECDSA key on curve %s", actualCurveName)

			tpmInstance.Flush(keyAttrs.TPMAttributes.Handle.(tpm2.TPMHandle))
		})
	}
}

// isCurveNotSupportedError checks if the error indicates that the curve is not supported
func isCurveNotSupportedError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// Check for common TPM error codes for unsupported curves
	return strings.Contains(errStr, "TPM_RC_CURVE") ||
		strings.Contains(errStr, "unsupported") ||
		strings.Contains(errStr, "not supported") ||
		strings.Contains(errStr, "0x03") || // TPM_RC_CURVE
		strings.Contains(errStr, "0x123") // TPM_RC_ECC_CURVE
}

// TestIntegration_CreateECDSA_ErrorCases tests error handling in ECDSA key creation
func TestIntegration_CreateECDSA_ErrorCases(t *testing.T) {
	tpmInstance, cleanup := setupTPM2(t)
	defer cleanup()

	testCases := []struct {
		name      string
		keyAttrs  *types.KeyAttributes
		expectErr bool
	}{
		{
			name: "Nil Parent",
			keyAttrs: &types.KeyAttributes{
				CN:           "test-ecdsa-nil-parent",
				KeyAlgorithm: x509.ECDSA,
				KeyType:      types.KeyTypeCA,
				Parent:       nil,
				Password:     types.NewClearPassword(nil),
				StoreType:    types.StoreTPM2,
			},
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tpmInstance.CreateECDSA(tc.keyAttrs, nil, false)
			if tc.expectErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !tc.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestIntegration_CreateSecretKey tests AES secret key creation
func TestIntegration_CreateSecretKey(t *testing.T) {
	tpmInstance, cleanup := setupTPM2(t)
	defer cleanup()

	srkAttrs := provisionTPMIfNeeded(t, tpmInstance)

	testCases := []struct {
		name           string
		platformPolicy bool
		maySkip        bool // Some TPM simulators don't support AES-256
	}{
		{
			name:           "AES 256 CFB",
			platformPolicy: false,
			maySkip:        true, // Software TPM may not support AES-256 symmetric keys
		},
		{
			name:           "AES 256 CFB with Platform Policy",
			platformPolicy: true,
			maySkip:        true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keyAttrs := &types.KeyAttributes{
				CN:             "integration-test-secretkey-" + tc.name,
				KeyAlgorithm:   0, // Use 0 instead of UnknownSignatureAlgorithm
				KeyType:        types.KeyTypeHMAC,
				Parent:         srkAttrs,
				Password:       types.NewClearPassword(nil),
				StoreType:      types.StoreTPM2,
				PlatformPolicy: tc.platformPolicy,
				TPMAttributes: &types.TPMAttributes{
					Hierarchy: tpm2.TPMRHOwner,
				},
			}

			// Create secret key
			err := tpmInstance.CreateSecretKey(keyAttrs, nil)
			if err != nil {
				// Check if this is an unsupported algorithm error
				if tc.maySkip && isSymmetricAlgorithmNotSupportedError(err) {
					t.Skipf("AES-256 symmetric keys not supported by TPM simulator: %v", err)
					return
				}
				t.Fatalf("Failed to create secret key: %v", err)
			}

			// The key should be saved to blob storage
			// We can't directly verify the key material, but we can check
			// that the operation completed successfully
			t.Logf("Successfully created secret key: %s", keyAttrs.CN)
		})
	}
}

// isSymmetricAlgorithmNotSupportedError checks if the error indicates that
// the symmetric algorithm or key size is not supported
func isSymmetricAlgorithmNotSupportedError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "TPM_RC_SYMMETRIC") ||
		strings.Contains(errStr, "unsupported symmetric") ||
		strings.Contains(errStr, "key size") ||
		strings.Contains(errStr, "0x01c") || // TPM_RC_SYMMETRIC
		strings.Contains(errStr, "parameter 2")
}

// TestIntegration_CreateSecretKey_ErrorCases tests error handling in secret key creation
func TestIntegration_CreateSecretKey_ErrorCases(t *testing.T) {
	tpmInstance, cleanup := setupTPM2(t)
	defer cleanup()

	testCases := []struct {
		name      string
		keyAttrs  *types.KeyAttributes
		expectErr bool
	}{
		{
			name: "Nil Parent",
			keyAttrs: &types.KeyAttributes{
				CN:           "test-secret-nil-parent",
				KeyAlgorithm: 0,
				KeyType:      types.KeyTypeHMAC,
				Parent:       nil,
				Password:     types.NewClearPassword(nil),
				StoreType:    types.StoreTPM2,
			},
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tpmInstance.CreateSecretKey(tc.keyAttrs, nil)
			if tc.expectErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !tc.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestIntegration_RSAEncryptDecrypt_LargeData tests encryption with data near size limits
func TestIntegration_RSAEncryptDecrypt_LargeData(t *testing.T) {
	tpmInstance, cleanup := setupTPM2(t)
	defer cleanup()

	srkAttrs := provisionTPMIfNeeded(t, tpmInstance)

	// Create an RSA key
	keyAttrs := &types.KeyAttributes{
		CN:           "rsa-large-data-test",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeEncryption,
		Parent:       srkAttrs,
		Password:     types.NewClearPassword(nil),
		StoreType:    types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	rsaPub, err := tpmInstance.CreateRSA(keyAttrs, nil, false)
	if err != nil {
		t.Fatalf("Failed to create RSA key: %v", err)
	}

	keyHandle := keyAttrs.TPMAttributes.Handle.(tpm2.TPMHandle)
	keyName := keyAttrs.TPMAttributes.Name.(tpm2.TPM2BName)

	// Test with data sizes approaching the limit
	// For RSA-OAEP with SHA-256 on a 2048-bit key:
	// Max plaintext = keySize/8 - 2*hashSize - 2 = 256 - 2*32 - 2 = 190 bytes
	testCases := []struct {
		name     string
		dataSize int
	}{
		{"Small Data", 16},
		{"Medium Data", 64},
		{"Near Max Data", 100},
		{"Max Safe Data", 150},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test data
			plaintext := make([]byte, tc.dataSize)
			for i := range plaintext {
				plaintext[i] = byte(i % 256)
			}

			// Encrypt
			ciphertext, err := tpmInstance.RSAEncrypt(keyHandle, keyName, plaintext)
			if err != nil {
				t.Fatalf("Encryption failed for %d bytes: %v", tc.dataSize, err)
			}

			// Verify ciphertext size (should be key size)
			expectedCipherSize := rsaPub.N.BitLen() / 8
			if len(ciphertext) != expectedCipherSize {
				t.Errorf("Expected ciphertext size %d, got %d",
					expectedCipherSize, len(ciphertext))
			}

			// Decrypt
			decrypted, err := tpmInstance.RSADecrypt(keyHandle, keyName, ciphertext)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Verify
			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("Decrypted data mismatch for %d bytes", tc.dataSize)
			}

			t.Logf("Successfully encrypted/decrypted %d bytes", tc.dataSize)
		})
	}

	tpmInstance.Flush(keyHandle)
}

// TestIntegration_CryptoOperations_Sequential tests sequential crypto operations
func TestIntegration_CryptoOperations_Sequential(t *testing.T) {
	// Note: TPM operations on a single connection are not thread-safe
	// This test verifies sequential operations with proper resource management

	conn := openTPM(t)
	defer conn.Close()

	tpm := transport.FromReadWriter(conn)
	executeTPMStartup(t, tpm)

	const numIterations = 3

	for i := 0; i < numIterations; i++ {
		t.Run("Iteration", func(t *testing.T) {
			// Create an RSA key for encryption (unrestricted decryption key)
			// Note: For unrestricted decryption keys, we don't specify Symmetric algorithm
			// The Symmetric field is only used for storage keys (Restricted=true)
			createPrimary := tpm2.CreatePrimary{
				PrimaryHandle: tpm2.TPMRHOwner,
				InPublic: tpm2.New2B(tpm2.TPMTPublic{
					Type:    tpm2.TPMAlgRSA,
					NameAlg: tpm2.TPMAlgSHA256,
					ObjectAttributes: tpm2.TPMAObject{
						FixedTPM:            true,
						FixedParent:         true,
						SensitiveDataOrigin: true,
						UserWithAuth:        true,
						Decrypt:             true,
					},
					Parameters: tpm2.NewTPMUPublicParms(
						tpm2.TPMAlgRSA,
						&tpm2.TPMSRSAParms{
							Scheme: tpm2.TPMTRSAScheme{
								Scheme: tpm2.TPMAlgOAEP,
								Details: tpm2.NewTPMUAsymScheme(
									tpm2.TPMAlgOAEP,
									&tpm2.TPMSEncSchemeOAEP{
										HashAlg: tpm2.TPMAlgSHA256,
									},
								),
							},
							KeyBits: 2048,
						},
					),
				}),
			}

			rsp, err := createPrimary.Execute(tpm)
			if err != nil {
				t.Fatalf("CreatePrimary failed: %v", err)
			}

			keyHandle := rsp.ObjectHandle
			keyName := rsp.Name
			defer flushHandle(t, tpm, keyHandle)

			// Perform encryption
			message := []byte("test message")
			encryptCmd := tpm2.RSAEncrypt{
				KeyHandle: keyHandle,
				Message:   tpm2.TPM2BPublicKeyRSA{Buffer: message},
				InScheme: tpm2.TPMTRSADecrypt{
					Scheme: tpm2.TPMAlgOAEP,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgOAEP,
						&tpm2.TPMSEncSchemeOAEP{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
			}

			encryptRsp, err := encryptCmd.Execute(tpm)
			if err != nil {
				t.Fatalf("RSAEncrypt failed: %v", err)
			}

			ciphertext := encryptRsp.OutData.Buffer

			// Perform decryption using NamedHandle to provide the key name
			decryptCmd := tpm2.RSADecrypt{
				KeyHandle: tpm2.NamedHandle{
					Handle: keyHandle,
					Name:   keyName,
				},
				CipherText: tpm2.TPM2BPublicKeyRSA{Buffer: ciphertext},
				InScheme: tpm2.TPMTRSADecrypt{
					Scheme: tpm2.TPMAlgOAEP,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgOAEP,
						&tpm2.TPMSEncSchemeOAEP{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
			}

			decryptRsp, err := decryptCmd.Execute(tpm)
			if err != nil {
				t.Fatalf("RSADecrypt failed: %v", err)
			}

			if !bytes.Equal(decryptRsp.Message.Buffer, message) {
				t.Errorf("Message mismatch in iteration %d", i)
			}

			t.Logf("Iteration %d: Successfully encrypted and decrypted message", i)
		})
	}
}
