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

package symmetric

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// BenchmarkAES_GenerateKey benchmarks key generation for different AES key sizes
func BenchmarkAES_GenerateKey(b *testing.B) {
	keySizes := []struct {
		name      string
		keySize   int
		algorithm types.SymmetricAlgorithm
	}{
		{"AES-128", 128, types.SymmetricAES128GCM},
		{"AES-192", 192, types.SymmetricAES192GCM},
		{"AES-256", 256, types.SymmetricAES256GCM},
	}

	for _, ks := range keySizes {
		b.Run(ks.name, func(b *testing.B) {
			storage := storage.New()
			config := &Config{KeyStorage: storage}
			be, err := NewBackend(config)
			if err != nil {
				b.Fatalf("Failed to create backend: %v", err)
			}
			defer func() { _ = be.Close() }()

			symBackend := be

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				attrs := &types.KeyAttributes{
					CN:                 fmt.Sprintf("bench-key-%d", i),
					KeyType:            backend.KEY_TYPE_SECRET,
					StoreType:          backend.STORE_SW,
					SymmetricAlgorithm: ks.algorithm,
				}

				_, err := symBackend.GenerateSymmetricKey(attrs)
				if err != nil {
					b.Fatalf("GenerateSymmetricKey() failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkAES_Encrypt benchmarks encryption for various data sizes
func BenchmarkAES_Encrypt(b *testing.B) {
	sizes := []int{
		1024,        // 1KB
		10 * 1024,   // 10KB
		100 * 1024,  // 100KB
		1024 * 1024, // 1MB
	}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("AES256-%dKB", size/1024), func(b *testing.B) {
			storage := storage.New()
			config := &Config{KeyStorage: storage}
			be, err := NewBackend(config)
			if err != nil {
				b.Fatalf("Failed to create backend: %v", err)
			}
			defer func() { _ = be.Close() }()

			symBackend := be

			attrs := &types.KeyAttributes{
				CN:                 "bench-encrypt-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_SW,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			}

			_, err = symBackend.GenerateSymmetricKey(attrs)
			if err != nil {
				b.Fatalf("GenerateSymmetricKey() failed: %v", err)
			}

			encrypter, err := symBackend.SymmetricEncrypter(attrs)
			if err != nil {
				b.Fatalf("SymmetricEncrypter() failed: %v", err)
			}

			plaintext := make([]byte, size)
			if _, err := rand.Read(plaintext); err != nil {
				b.Fatalf("Failed to generate test data: %v", err)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, err := encrypter.Encrypt(plaintext, nil)
				if err != nil {
					b.Fatalf("Encrypt() failed: %v", err)
				}
			}

			b.SetBytes(int64(size))
		})
	}
}

// BenchmarkAES_Decrypt benchmarks decryption for various data sizes
func BenchmarkAES_Decrypt(b *testing.B) {
	sizes := []int{
		1024,        // 1KB
		10 * 1024,   // 10KB
		100 * 1024,  // 100KB
		1024 * 1024, // 1MB
	}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("AES256-%dKB", size/1024), func(b *testing.B) {
			storage := storage.New()
			config := &Config{KeyStorage: storage}
			be, err := NewBackend(config)
			if err != nil {
				b.Fatalf("Failed to create backend: %v", err)
			}
			defer func() { _ = be.Close() }()

			symBackend := be

			attrs := &types.KeyAttributes{
				CN:                 "bench-decrypt-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_SW,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			}

			_, err = symBackend.GenerateSymmetricKey(attrs)
			if err != nil {
				b.Fatalf("GenerateSymmetricKey() failed: %v", err)
			}

			encrypter, err := symBackend.SymmetricEncrypter(attrs)
			if err != nil {
				b.Fatalf("SymmetricEncrypter() failed: %v", err)
			}

			plaintext := make([]byte, size)
			if _, err := rand.Read(plaintext); err != nil {
				b.Fatalf("Failed to generate test data: %v", err)
			}

			encrypted, err := encrypter.Encrypt(plaintext, nil)
			if err != nil {
				b.Fatalf("Encrypt() failed: %v", err)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, err := encrypter.Decrypt(encrypted, nil)
				if err != nil {
					b.Fatalf("Decrypt() failed: %v", err)
				}
			}

			b.SetBytes(int64(size))
		})
	}
}

// BenchmarkAES_EncryptWithAAD benchmarks encryption with additional authenticated data
func BenchmarkAES_EncryptWithAAD(b *testing.B) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	be, err := NewBackend(config)
	if err != nil {
		b.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = be.Close() }()

	symBackend := be

	attrs := &types.KeyAttributes{
		CN:                 "bench-aad-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		b.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		b.Fatalf("SymmetricEncrypter() failed: %v", err)
	}

	plaintext := make([]byte, 1024)
	if _, err := rand.Read(plaintext); err != nil {
		b.Fatalf("Failed to generate test data: %v", err)
	}

	aad := []byte("additional-authenticated-data")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := encrypter.Encrypt(plaintext, &types.EncryptOptions{
			AdditionalData: aad,
		})
		if err != nil {
			b.Fatalf("Encrypt() failed: %v", err)
		}
	}

	b.SetBytes(int64(len(plaintext)))
}

// BenchmarkAES_ConcurrentEncrypt benchmarks concurrent encryption operations
func BenchmarkAES_ConcurrentEncrypt(b *testing.B) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	be, err := NewBackend(config)
	if err != nil {
		b.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = be.Close() }()

	symBackend := be

	attrs := &types.KeyAttributes{
		CN:                 "bench-concurrent-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		b.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		b.Fatalf("SymmetricEncrypter() failed: %v", err)
	}

	plaintext := make([]byte, 1024)
	if _, err := rand.Read(plaintext); err != nil {
		b.Fatalf("Failed to generate test data: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := encrypter.Encrypt(plaintext, nil)
			if err != nil {
				b.Fatalf("Encrypt() failed: %v", err)
			}
		}
	})

	b.SetBytes(int64(len(plaintext)))
}

// BenchmarkAES_ConcurrentDecrypt benchmarks concurrent decryption operations
func BenchmarkAES_ConcurrentDecrypt(b *testing.B) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	be, err := NewBackend(config)
	if err != nil {
		b.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = be.Close() }()

	symBackend := be

	attrs := &types.KeyAttributes{
		CN:                 "bench-concurrent-decrypt-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err = symBackend.GenerateSymmetricKey(attrs)
	if err != nil {
		b.Fatalf("GenerateSymmetricKey() failed: %v", err)
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		b.Fatalf("SymmetricEncrypter() failed: %v", err)
	}

	plaintext := make([]byte, 1024)
	if _, err := rand.Read(plaintext); err != nil {
		b.Fatalf("Failed to generate test data: %v", err)
	}

	encrypted, err := encrypter.Encrypt(plaintext, nil)
	if err != nil {
		b.Fatalf("Encrypt() failed: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := encrypter.Decrypt(encrypted, nil)
			if err != nil {
				b.Fatalf("Decrypt() failed: %v", err)
			}
		}
	})

	b.SetBytes(int64(len(plaintext)))
}

// BenchmarkAES_EncryptDecryptRoundTrip benchmarks full round-trip encryption/decryption
func BenchmarkAES_EncryptDecryptRoundTrip(b *testing.B) {
	sizes := []int{
		1024,       // 1KB
		10 * 1024,  // 10KB
		100 * 1024, // 100KB
	}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("%dKB", size/1024), func(b *testing.B) {
			storage := storage.New()
			config := &Config{KeyStorage: storage}
			be, err := NewBackend(config)
			if err != nil {
				b.Fatalf("Failed to create backend: %v", err)
			}
			defer func() { _ = be.Close() }()

			symBackend := be

			attrs := &types.KeyAttributes{
				CN:                 "bench-roundtrip-key",
				KeyType:            backend.KEY_TYPE_SECRET,
				StoreType:          backend.STORE_SW,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			}

			_, err = symBackend.GenerateSymmetricKey(attrs)
			if err != nil {
				b.Fatalf("GenerateSymmetricKey() failed: %v", err)
			}

			encrypter, err := symBackend.SymmetricEncrypter(attrs)
			if err != nil {
				b.Fatalf("SymmetricEncrypter() failed: %v", err)
			}

			plaintext := make([]byte, size)
			if _, err := rand.Read(plaintext); err != nil {
				b.Fatalf("Failed to generate test data: %v", err)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				encrypted, err := encrypter.Encrypt(plaintext, nil)
				if err != nil {
					b.Fatalf("Encrypt() failed: %v", err)
				}

				_, err = encrypter.Decrypt(encrypted, nil)
				if err != nil {
					b.Fatalf("Decrypt() failed: %v", err)
				}
			}

			b.SetBytes(int64(size) * 2) // Count both encrypt and decrypt
		})
	}
}

// BenchmarkAES_PasswordProtectedKey benchmarks operations with password-protected keys
func BenchmarkAES_PasswordProtectedKey(b *testing.B) {
	storage := storage.New()
	config := &Config{KeyStorage: storage}
	be, err := NewBackend(config)
	if err != nil {
		b.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = be.Close() }()

	symBackend := be

	password := backend.StaticPassword([]byte("benchmark-password"))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		attrs := &types.KeyAttributes{
			CN:                 fmt.Sprintf("bench-protected-key-%d", i),
			KeyType:            backend.KEY_TYPE_SECRET,
			StoreType:          backend.STORE_SW,
			SymmetricAlgorithm: types.SymmetricAES256GCM,
			Password:           password,
		}

		_, err := symBackend.GenerateSymmetricKey(attrs)
		if err != nil {
			b.Fatalf("GenerateSymmetricKey() failed: %v", err)
		}

		_, err = symBackend.GetSymmetricKey(attrs)
		if err != nil {
			b.Fatalf("GetSymmetricKey() failed: %v", err)
		}
	}
}
