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

// Package main demonstrates thread-safe concurrent operations.
package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs8"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func main() {
	// Create a temporary directory
	tmpDir := filepath.Join(os.TempDir(), "keystore-concurrent")
	defer os.RemoveAll(tmpDir)

	// Initialize storage backend
	storage, err := file.New(tmpDir)
	if err != nil {
		log.Fatalf("Failed to create storage: %v", err)
	}

	// Create PKCS#8 backend
	pkcs8Backend, err := pkcs8.NewBackend(&pkcs8.Config{
		KeyStorage: storage,
	})
	if err != nil {
		log.Fatalf("Failed to create PKCS#8 backend: %v", err)
	}
	defer pkcs8Backend.Close()

	// Create keystore instance
	ks, err := keychain.New(&keychain.Config{
		Backend:     pkcs8Backend,
		CertStorage: storage,
	})
	if err != nil {
		log.Fatalf("Failed to create keystore: %v", err)
	}
	defer ks.Close()

	fmt.Println("=== Concurrent Operations Examples ===")

	// Example 1: Concurrent key generation
	fmt.Println("1. Concurrent Key Generation")
	demonstrateConcurrentGeneration(ks)

	// Example 2: Concurrent signing operations
	fmt.Println("\n2. Concurrent Signing Operations")
	demonstrateConcurrentSigning(ks)

	// Example 3: Concurrent read operations
	fmt.Println("\n3. Concurrent Read Operations")
	demonstrateConcurrentReads(ks)

	// Example 4: Mixed concurrent operations
	fmt.Println("\n4. Mixed Concurrent Operations (Read/Write)")
	demonstrateMixedOperations(ks)

	// Example 5: Load testing
	fmt.Println("\n5. Load Testing")
	demonstrateLoadTest(ks)

	fmt.Println("\n✓ All concurrent operations completed successfully!")
}

// demonstrateConcurrentGeneration shows concurrent key generation
func demonstrateConcurrentGeneration(ks keychain.KeyStore) {
	const numKeys = 10
	var wg sync.WaitGroup
	var successCount atomic.Int64
	var errorCount atomic.Int64

	fmt.Printf("   Generating %d keys concurrently...\n", numKeys)
	startTime := time.Now()

	for i := 0; i < numKeys; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			keyAttrs := &types.KeyAttributes{
				CN:           fmt.Sprintf("concurrent-key-%d", id),
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P256(),
				},
			}

			_, err := ks.GenerateECDSA(keyAttrs)
			if err != nil {
				errorCount.Add(1)
				log.Printf("Failed to generate key %d: %v", id, err)
				return
			}
			successCount.Add(1)
		}(i)
	}

	wg.Wait()
	duration := time.Since(startTime)

	fmt.Printf("   Results:\n")
	fmt.Printf("     ✓ Successful: %d keys\n", successCount.Load())
	fmt.Printf("     ✗ Failed: %d keys\n", errorCount.Load())
	fmt.Printf("     Duration: %v\n", duration)
	fmt.Printf("     Rate: %.2f keys/sec\n", float64(numKeys)/duration.Seconds())
}

// demonstrateConcurrentSigning shows concurrent signing operations
func demonstrateConcurrentSigning(ks keychain.KeyStore) {
	// Generate a key for signing
	keyAttrs := &types.KeyAttributes{
		CN:           "signing-key",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	_, err := ks.GenerateECDSA(keyAttrs)
	if err != nil {
		log.Fatalf("Failed to generate signing key: %v", err)
	}

	signer, err := ks.Signer(keyAttrs)
	if err != nil {
		log.Fatalf("Failed to get signer: %v", err)
	}

	const numSignatures = 100
	var wg sync.WaitGroup
	var successCount atomic.Int64
	var errorCount atomic.Int64

	fmt.Printf("   Performing %d concurrent signing operations...\n", numSignatures)
	startTime := time.Now()

	for i := 0; i < numSignatures; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			message := []byte(fmt.Sprintf("Message %d", id))
			hash := sha256.Sum256(message)

			_, err := signer.Sign(rand.Reader, hash[:], nil)
			if err != nil {
				errorCount.Add(1)
				log.Printf("Failed to sign message %d: %v", id, err)
				return
			}
			successCount.Add(1)
		}(i)
	}

	wg.Wait()
	duration := time.Since(startTime)

	fmt.Printf("   Results:\n")
	fmt.Printf("     ✓ Successful: %d signatures\n", successCount.Load())
	fmt.Printf("     ✗ Failed: %d signatures\n", errorCount.Load())
	fmt.Printf("     Duration: %v\n", duration)
	fmt.Printf("     Rate: %.2f signatures/sec\n", float64(numSignatures)/duration.Seconds())
}

// demonstrateConcurrentReads shows concurrent read operations
func demonstrateConcurrentReads(ks keychain.KeyStore) {
	// Generate keys for reading
	const numKeys = 5
	keyAttrs := make([]*types.KeyAttributes, numKeys)

	fmt.Printf("   Setting up %d keys for concurrent reads...\n", numKeys)
	for i := 0; i < numKeys; i++ {
		keyAttrs[i] = &types.KeyAttributes{
			CN:           fmt.Sprintf("read-key-%d", i),
			KeyType:      backend.KEY_TYPE_TLS,
			StoreType:    backend.STORE_SW,
			KeyAlgorithm: x509.ECDSA,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
		}

		_, err := ks.GenerateECDSA(keyAttrs[i])
		if err != nil {
			log.Fatalf("Failed to generate key %d: %v", i, err)
		}
	}

	const numReads = 100
	var wg sync.WaitGroup
	var successCount atomic.Int64
	var errorCount atomic.Int64

	fmt.Printf("   Performing %d concurrent read operations...\n", numReads)
	startTime := time.Now()

	for i := 0; i < numReads; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Read a random key
			keyIndex := id % numKeys
			_, err := ks.GetKey(keyAttrs[keyIndex])
			if err != nil {
				errorCount.Add(1)
				log.Printf("Failed to read key %d: %v", id, err)
				return
			}
			successCount.Add(1)
		}(i)
	}

	wg.Wait()
	duration := time.Since(startTime)

	fmt.Printf("   Results:\n")
	fmt.Printf("     ✓ Successful: %d reads\n", successCount.Load())
	fmt.Printf("     ✗ Failed: %d reads\n", errorCount.Load())
	fmt.Printf("     Duration: %v\n", duration)
	fmt.Printf("     Rate: %.2f reads/sec\n", float64(numReads)/duration.Seconds())
}

// demonstrateMixedOperations shows mixed read/write operations
func demonstrateMixedOperations(ks keychain.KeyStore) {
	const numOperations = 50
	var wg sync.WaitGroup
	var readCount atomic.Int64
	var writeCount atomic.Int64
	var deleteCount atomic.Int64
	var errorCount atomic.Int64

	fmt.Printf("   Performing %d mixed operations...\n", numOperations)
	startTime := time.Now()

	for i := 0; i < numOperations; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			keyAttrs := &types.KeyAttributes{
				CN:           fmt.Sprintf("mixed-key-%d", id),
				KeyType:      backend.KEY_TYPE_TLS,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{
					Curve: elliptic.P256(),
				},
			}

			// Perform different operations based on ID
			switch id % 3 {
			case 0: // Write
				_, err := ks.GenerateECDSA(keyAttrs)
				if err != nil {
					errorCount.Add(1)
					return
				}
				writeCount.Add(1)

			case 1: // Read (might fail if key doesn't exist)
				_, err := ks.GetKey(keyAttrs)
				if err == nil {
					readCount.Add(1)
				}

			case 2: // Delete (might fail if key doesn't exist)
				err := ks.DeleteKey(keyAttrs)
				if err == nil {
					deleteCount.Add(1)
				}
			}
		}(i)
	}

	wg.Wait()
	duration := time.Since(startTime)

	fmt.Printf("   Results:\n")
	fmt.Printf("     Writes: %d\n", writeCount.Load())
	fmt.Printf("     Reads: %d\n", readCount.Load())
	fmt.Printf("     Deletes: %d\n", deleteCount.Load())
	fmt.Printf("     Errors: %d\n", errorCount.Load())
	fmt.Printf("     Duration: %v\n", duration)
	fmt.Printf("     Rate: %.2f ops/sec\n", float64(numOperations)/duration.Seconds())
}

// demonstrateLoadTest performs a stress test
func demonstrateLoadTest(ks keychain.KeyStore) {
	const duration = 3 * time.Second
	const numWorkers = 10

	var operations atomic.Int64
	var errors atomic.Int64
	var wg sync.WaitGroup

	fmt.Printf("   Running load test for %v with %d workers...\n", duration, numWorkers)
	startTime := time.Now()
	endTime := startTime.Add(duration)

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			opCount := 0
			for time.Now().Before(endTime) {
				keyAttrs := &types.KeyAttributes{
					CN:           fmt.Sprintf("load-test-worker%d-op%d", workerID, opCount),
					KeyType:      backend.KEY_TYPE_TLS,
					StoreType:    backend.STORE_SW,
					KeyAlgorithm: x509.ECDSA,
					ECCAttributes: &types.ECCAttributes{
						Curve: elliptic.P256(),
					},
				}

				// Generate key
				_, err := ks.GenerateECDSA(keyAttrs)
				if err != nil {
					errors.Add(1)
					continue
				}

				// Sign something
				signer, err := ks.Signer(keyAttrs)
				if err == nil {
					hash := sha256.Sum256([]byte("test"))
					_, err = signer.Sign(rand.Reader, hash[:], nil)
					if err != nil {
						errors.Add(1)
					}
				}

				// Delete key
				_ = ks.DeleteKey(keyAttrs)

				operations.Add(1)
				opCount++
			}
		}(i)
	}

	wg.Wait()
	testDuration := time.Since(startTime)

	totalOps := operations.Load()
	fmt.Printf("   Results:\n")
	fmt.Printf("     Total operations: %d\n", totalOps)
	fmt.Printf("     Errors: %d\n", errors.Load())
	fmt.Printf("     Duration: %v\n", testDuration)
	fmt.Printf("     Average rate: %.2f ops/sec\n", float64(totalOps)/testDuration.Seconds())
	fmt.Printf("     Per-worker rate: %.2f ops/sec\n", float64(totalOps)/float64(numWorkers)/testDuration.Seconds())
}
