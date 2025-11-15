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

package jwe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// Test RSA-OAEP encryption and decryption
func TestRSAOAEP_Encryption(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	plaintext := []byte("Hello, World! This is a test message.")

	// Test RSA-OAEP with A256GCM
	t.Run("RSA-OAEP_A256GCM", func(t *testing.T) {
		encrypter, err := NewEncrypter("RSA-OAEP", "A256GCM", &privateKey.PublicKey)
		if err != nil {
			t.Fatalf("Failed to create encrypter: %v", err)
		}

		jweString, err := encrypter.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		if jweString == "" {
			t.Fatal("Encrypted string is empty")
		}

		// Decrypt
		decrypter := NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, privateKey)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		if string(decrypted) != string(plaintext) {
			t.Errorf("Decrypted text doesn't match: got %s, want %s", decrypted, plaintext)
		}
	})

	// Test RSA-OAEP-256 with A192GCM
	t.Run("RSA-OAEP-256_A192GCM", func(t *testing.T) {
		encrypter, err := NewEncrypter("RSA-OAEP-256", "A192GCM", &privateKey.PublicKey)
		if err != nil {
			t.Fatalf("Failed to create encrypter: %v", err)
		}

		jweString, err := encrypter.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		decrypter := NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, privateKey)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		if string(decrypted) != string(plaintext) {
			t.Errorf("Decrypted text doesn't match")
		}
	})

	// Test RSA-OAEP-256 with A128GCM
	t.Run("RSA-OAEP-256_A128GCM", func(t *testing.T) {
		encrypter, err := NewEncrypter("RSA-OAEP-256", "A128GCM", &privateKey.PublicKey)
		if err != nil {
			t.Fatalf("Failed to create encrypter: %v", err)
		}

		jweString, err := encrypter.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		decrypter := NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, privateKey)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		if string(decrypted) != string(plaintext) {
			t.Errorf("Decrypted text doesn't match")
		}
	})
}

// Test ECDH-ES encryption
func TestECDHES_Encryption(t *testing.T) {
	// Generate ECDSA key pair (P-256)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	plaintext := []byte("ECDH-ES test message")

	t.Run("ECDH-ES+A256KW_A256GCM", func(t *testing.T) {
		encrypter, err := NewEncrypter("ECDH-ES+A256KW", "A256GCM", &privateKey.PublicKey)
		if err != nil {
			t.Fatalf("Failed to create encrypter: %v", err)
		}

		jweString, err := encrypter.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		decrypter := NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, privateKey)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		if string(decrypted) != string(plaintext) {
			t.Errorf("Decrypted text doesn't match")
		}
	})

	t.Run("ECDH-ES+A192KW_A192GCM", func(t *testing.T) {
		encrypter, err := NewEncrypter("ECDH-ES+A192KW", "A192GCM", &privateKey.PublicKey)
		if err != nil {
			t.Fatalf("Failed to create encrypter: %v", err)
		}

		jweString, err := encrypter.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		decrypter := NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, privateKey)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		if string(decrypted) != string(plaintext) {
			t.Errorf("Decrypted text doesn't match")
		}
	})

	t.Run("ECDH-ES+A128KW_A128GCM", func(t *testing.T) {
		encrypter, err := NewEncrypter("ECDH-ES+A128KW", "A128GCM", &privateKey.PublicKey)
		if err != nil {
			t.Fatalf("Failed to create encrypter: %v", err)
		}

		jweString, err := encrypter.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		decrypter := NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, privateKey)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		if string(decrypted) != string(plaintext) {
			t.Errorf("Decrypted text doesn't match")
		}
	})
}

// Test custom headers
func TestEncryptWithHeader(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	plaintext := []byte("Test with custom headers")

	encrypter, err := NewEncrypter("RSA-OAEP-256", "A256GCM", &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to create encrypter: %v", err)
	}

	// Encrypt with kid header
	header := map[string]interface{}{
		"kid": "test-key-123",
		"typ": "JWT",
	}

	jweString, err := encrypter.EncryptWithHeader(plaintext, header)
	if err != nil {
		t.Fatalf("Encryption with header failed: %v", err)
	}

	// Extract and verify kid
	kid, err := ExtractKID(jweString)
	if err != nil {
		t.Fatalf("Failed to extract kid: %v", err)
	}

	if kid != "test-key-123" {
		t.Errorf("Extracted kid doesn't match: got %s, want test-key-123", kid)
	}

	// Decrypt
	decrypter := NewDecrypter()
	decrypted, err := decrypter.Decrypt(jweString, privateKey)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text doesn't match")
	}
}

// Test ExtractKID function
func TestExtractKID(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	plaintext := []byte("KID extraction test")

	encrypter, err := NewEncrypter("RSA-OAEP", "A256GCM", &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to create encrypter: %v", err)
	}

	// Test with kid
	t.Run("WithKID", func(t *testing.T) {
		header := map[string]interface{}{"kid": "my-key-id"}
		jweString, err := encrypter.EncryptWithHeader(plaintext, header)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		kid, err := ExtractKID(jweString)
		if err != nil {
			t.Fatalf("ExtractKID failed: %v", err)
		}

		if kid != "my-key-id" {
			t.Errorf("Expected kid 'my-key-id', got '%s'", kid)
		}
	})

	// Test without kid
	t.Run("WithoutKID", func(t *testing.T) {
		jweString, err := encrypter.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		kid, err := ExtractKID(jweString)
		if err != nil {
			t.Fatalf("ExtractKID failed: %v", err)
		}

		if kid != "" {
			t.Errorf("Expected empty kid, got '%s'", kid)
		}
	})
}

// Test error cases
func TestEncryptionErrors(t *testing.T) {
	t.Run("NilRecipientKey", func(t *testing.T) {
		_, err := NewEncrypter("RSA-OAEP", "A256GCM", nil)
		if err == nil {
			t.Error("Expected error for nil recipient key")
		}
	})

	t.Run("InvalidKeyAlgorithm", func(t *testing.T) {
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		_, err := NewEncrypter("INVALID-ALG", "A256GCM", &privateKey.PublicKey)
		if err == nil {
			t.Error("Expected error for invalid key algorithm")
		}
	})

	t.Run("InvalidContentEncryption", func(t *testing.T) {
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		_, err := NewEncrypter("RSA-OAEP", "INVALID-ENC", &privateKey.PublicKey)
		if err == nil {
			t.Error("Expected error for invalid content encryption")
		}
	})

	t.Run("NilPlaintext", func(t *testing.T) {
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		encrypter, _ := NewEncrypter("RSA-OAEP", "A256GCM", &privateKey.PublicKey)
		_, err := encrypter.Encrypt(nil)
		if err == nil {
			t.Error("Expected error for nil plaintext")
		}
	})

	t.Run("UnsupportedKeyType", func(t *testing.T) {
		_, err := NewEncrypter("RSA-OAEP", "A256GCM", "invalid-key-type")
		if err == nil {
			t.Error("Expected error for unsupported key type")
		}
	})
}

func TestDecryptionErrors(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	t.Run("EmptyJWEString", func(t *testing.T) {
		decrypter := NewDecrypter()
		_, err := decrypter.Decrypt("", privateKey)
		if err == nil {
			t.Error("Expected error for empty JWE string")
		}
	})

	t.Run("NilPrivateKey", func(t *testing.T) {
		decrypter := NewDecrypter()
		_, err := decrypter.Decrypt("invalid.jwe.string.here.now", nil)
		if err == nil {
			t.Error("Expected error for nil private key")
		}
	})

	t.Run("InvalidJWEFormat", func(t *testing.T) {
		decrypter := NewDecrypter()
		_, err := decrypter.Decrypt("invalid-jwe-format", privateKey)
		if err == nil {
			t.Error("Expected error for invalid JWE format")
		}
	})

	t.Run("WrongKey", func(t *testing.T) {
		// Encrypt with one key
		privateKey1, _ := rsa.GenerateKey(rand.Reader, 2048)
		encrypter, _ := NewEncrypter("RSA-OAEP", "A256GCM", &privateKey1.PublicKey)
		jweString, _ := encrypter.Encrypt([]byte("test"))

		// Try to decrypt with different key
		privateKey2, _ := rsa.GenerateKey(rand.Reader, 2048)
		decrypter := NewDecrypter()
		_, err := decrypter.Decrypt(jweString, privateKey2)
		if err == nil {
			t.Error("Expected error when decrypting with wrong key")
		}
	})
}

func TestExtractKIDErrors(t *testing.T) {
	t.Run("EmptyString", func(t *testing.T) {
		_, err := ExtractKID("")
		if err == nil {
			t.Error("Expected error for empty string")
		}
	})

	t.Run("InvalidFormat", func(t *testing.T) {
		_, err := ExtractKID("invalid.format")
		if err == nil {
			t.Error("Expected error for invalid format")
		}
	})

	t.Run("InvalidBase64", func(t *testing.T) {
		_, err := ExtractKID("!!!.invalid.base64.here.now")
		if err == nil {
			t.Error("Expected error for invalid base64")
		}
	})
}

// Test symmetric key encryption (direct key agreement)
func TestDirectKeyAgreement(t *testing.T) {
	// 256-bit symmetric key for A256GCM
	symmetricKey := make([]byte, 32)
	_, err := rand.Read(symmetricKey)
	if err != nil {
		t.Fatalf("Failed to generate symmetric key: %v", err)
	}

	plaintext := []byte("Direct key agreement test")

	encrypter, err := NewEncrypter("dir", "A256GCM", symmetricKey)
	if err != nil {
		t.Fatalf("Failed to create encrypter: %v", err)
	}

	jweString, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypter := NewDecrypter()
	decrypted, err := decrypter.Decrypt(jweString, symmetricKey)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text doesn't match")
	}
}

// Test AES Key Wrap
func TestAESKeyWrap(t *testing.T) {
	// 256-bit KEK for A256KW
	kek := make([]byte, 32)
	_, err := rand.Read(kek)
	if err != nil {
		t.Fatalf("Failed to generate KEK: %v", err)
	}

	plaintext := []byte("AES Key Wrap test")

	t.Run("A256KW_A256GCM", func(t *testing.T) {
		encrypter, err := NewEncrypter("A256KW", "A256GCM", kek)
		if err != nil {
			t.Fatalf("Failed to create encrypter: %v", err)
		}

		jweString, err := encrypter.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		decrypter := NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, kek)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		if string(decrypted) != string(plaintext) {
			t.Errorf("Decrypted text doesn't match")
		}
	})

	t.Run("A128KW_A128GCM", func(t *testing.T) {
		kek128 := make([]byte, 16)
		rand.Read(kek128)

		encrypter, err := NewEncrypter("A128KW", "A128GCM", kek128)
		if err != nil {
			t.Fatalf("Failed to create encrypter: %v", err)
		}

		jweString, err := encrypter.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		decrypter := NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, kek128)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		if string(decrypted) != string(plaintext) {
			t.Errorf("Decrypted text doesn't match")
		}
	})
}

// Test AES-CBC-HMAC encryption
func TestAESCBCHMAC(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	plaintext := []byte("AES-CBC-HMAC test")

	testCases := []string{"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"}

	for _, encAlg := range testCases {
		t.Run(encAlg, func(t *testing.T) {
			encrypter, err := NewEncrypter("RSA-OAEP", encAlg, &privateKey.PublicKey)
			if err != nil {
				t.Fatalf("Failed to create encrypter: %v", err)
			}

			jweString, err := encrypter.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			decrypter := NewDecrypter()
			decrypted, err := decrypter.Decrypt(jweString, privateKey)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if string(decrypted) != string(plaintext) {
				t.Errorf("Decrypted text doesn't match")
			}
		})
	}
}

// Benchmark tests
func BenchmarkRSAEncryption(b *testing.B) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	encrypter, _ := NewEncrypter("RSA-OAEP-256", "A256GCM", &privateKey.PublicKey)
	plaintext := []byte("Benchmark test message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = encrypter.Encrypt(plaintext)
	}
}

func BenchmarkRSADecryption(b *testing.B) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	encrypter, _ := NewEncrypter("RSA-OAEP-256", "A256GCM", &privateKey.PublicKey)
	plaintext := []byte("Benchmark test message")
	jweString, _ := encrypter.Encrypt(plaintext)

	decrypter := NewDecrypter()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = decrypter.Decrypt(jweString, privateKey)
	}
}

func BenchmarkECDHESEncryption(b *testing.B) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	encrypter, _ := NewEncrypter("ECDH-ES+A256KW", "A256GCM", &privateKey.PublicKey)
	plaintext := []byte("Benchmark test message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = encrypter.Encrypt(plaintext)
	}
}

func BenchmarkECDHESDecryption(b *testing.B) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	encrypter, _ := NewEncrypter("ECDH-ES+A256KW", "A256GCM", &privateKey.PublicKey)
	plaintext := []byte("Benchmark test message")
	jweString, _ := encrypter.Encrypt(plaintext)

	decrypter := NewDecrypter()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = decrypter.Decrypt(jweString, privateKey)
	}
}

// Test all supported algorithms for coverage
func TestAllAlgorithms(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	testCases := []struct {
		name   string
		keyAlg string
		encAlg string
		key    interface{}
	}{
		{"A192KW_A192GCM", "A192KW", "A192GCM", make([]byte, 24)},
		{"A128GCMKW_A128GCM", "A128GCMKW", "A128GCM", make([]byte, 16)},
		{"A192GCMKW_A192GCM", "A192GCMKW", "A192GCM", make([]byte, 24)},
		{"A256GCMKW_A256GCM", "A256GCMKW", "A256GCM", make([]byte, 32)},
		{"dir_A128GCM", "dir", "A128GCM", make([]byte, 16)},
		{"dir_A192GCM", "dir", "A192GCM", make([]byte, 24)},
		{"RSA-OAEP_A128GCM", "RSA-OAEP", "A128GCM", &rsaKey.PublicKey},
		{"ECDH-ES_A256GCM", "ECDH-ES", "A256GCM", &ecKey.PublicKey},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			plaintext := []byte("Test all algorithms")

			// Generate random key data for symmetric keys
			if keyBytes, ok := tc.key.([]byte); ok {
				rand.Read(keyBytes)
			}

			encrypter, err := NewEncrypter(tc.keyAlg, tc.encAlg, tc.key)
			if err != nil {
				t.Fatalf("Failed to create encrypter: %v", err)
			}

			jweString, err := encrypter.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Decrypt
			var decryptKey interface{}
			switch tc.key.(type) {
			case *rsa.PublicKey:
				decryptKey = rsaKey
			case *ecdsa.PublicKey:
				decryptKey = ecKey
			default:
				decryptKey = tc.key
			}

			decrypter := NewDecrypter()
			decrypted, err := decrypter.Decrypt(jweString, decryptKey)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if string(decrypted) != string(plaintext) {
				t.Errorf("Decrypted text doesn't match")
			}
		})
	}
}

// Test EncryptWithHeader with various header combinations
func TestEncryptWithHeader_AllOptions(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	plaintext := []byte("Header test")

	tests := []struct {
		name   string
		header map[string]interface{}
	}{
		{
			"OnlyKID",
			map[string]interface{}{"kid": "test-key"},
		},
		{
			"OnlyTyp",
			map[string]interface{}{"typ": "JWT"},
		},
		{
			"OnlyCty",
			map[string]interface{}{"cty": "application/json"},
		},
		{
			"KIDAndTyp",
			map[string]interface{}{"kid": "test-key", "typ": "JWT"},
		},
		{
			"AllStandard",
			map[string]interface{}{"kid": "test-key", "typ": "JWT", "cty": "application/json"},
		},
		{
			"CustomHeader",
			map[string]interface{}{"kid": "test-key", "custom": "value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypter, _ := NewEncrypter("RSA-OAEP", "A256GCM", &privateKey.PublicKey)

			jweString, err := encrypter.EncryptWithHeader(plaintext, tt.header)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Verify headers are present
			if kid, exists := tt.header["kid"]; exists {
				extractedKid, _ := ExtractKID(jweString)
				if extractedKid != kid {
					t.Errorf("Expected kid %s, got %s", kid, extractedKid)
				}
			}

			// Decrypt
			decrypter := NewDecrypter()
			decrypted, err := decrypter.Decrypt(jweString, privateKey)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if string(decrypted) != string(plaintext) {
				t.Errorf("Decrypted text doesn't match")
			}
		})
	}
}

// Test auto-detection of AEAD algorithms based on CPU features
func TestAutoDetection_AEADAlgorithm(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	plaintext := []byte("Auto-detection test message")

	// Test auto-detection with empty algorithm string
	t.Run("AutoDetect_EmptyString", func(t *testing.T) {
		// Empty string should trigger auto-detection
		encrypter, err := NewEncrypter("RSA-OAEP-256", "", &privateKey.PublicKey)
		if err != nil {
			t.Fatalf("Failed to create encrypter with auto-detection: %v", err)
		}

		jweString, err := encrypter.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encryption with auto-detection failed: %v", err)
		}

		// Decryption should work regardless of which algorithm was selected
		decrypter := NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, privateKey)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		if string(decrypted) != string(plaintext) {
			t.Errorf("Decrypted text doesn't match original")
		}
	})

	// Test that auto-detection works with ECDH-ES
	t.Run("AutoDetect_ECDHES", func(t *testing.T) {
		ecPrivateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		encrypter, err := NewEncrypter("ECDH-ES+A256KW", "", &ecPrivateKey.PublicKey)
		if err != nil {
			t.Fatalf("Failed to create ECDH-ES encrypter with auto-detection: %v", err)
		}

		jweString, err := encrypter.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("ECDH-ES encryption with auto-detection failed: %v", err)
		}

		decrypter := NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, ecPrivateKey)
		if err != nil {
			t.Fatalf("ECDH-ES decryption failed: %v", err)
		}

		if string(decrypted) != string(plaintext) {
			t.Errorf("ECDH-ES decrypted text doesn't match")
		}
	})

	// Test that auto-detection works with direct encryption
	t.Run("AutoDetect_DirectEncryption", func(t *testing.T) {
		symmetricKey := make([]byte, 32)
		rand.Read(symmetricKey)

		encrypter, err := NewEncrypter("dir", "", symmetricKey)
		if err != nil {
			t.Fatalf("Failed to create direct encrypter with auto-detection: %v", err)
		}

		jweString, err := encrypter.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Direct encryption with auto-detection failed: %v", err)
		}

		decrypter := NewDecrypter()
		decrypted, err := decrypter.Decrypt(jweString, symmetricKey)
		if err != nil {
			t.Fatalf("Direct decryption failed: %v", err)
		}

		if string(decrypted) != string(plaintext) {
			t.Errorf("Direct encrypted text doesn't match")
		}
	})
}
