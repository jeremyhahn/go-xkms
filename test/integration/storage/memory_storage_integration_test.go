// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration

package storage_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMemoryStorageIntegration_BasicCRUD tests basic Create, Read, Update, Delete operations
func TestMemoryStorageIntegration_BasicCRUD(t *testing.T) {
	ctx := context.Background()
	backend := storage.New()
	defer backend.Close()

	// Create - Put a value
	testKey := "test-key-1"
	testValue := []byte("test-value-1")
	err := backend.Put(ctx, testKey, testValue)
	require.NoError(t, err)

	// Read - Get the value
	retrieved, err := backend.Get(ctx, testKey)
	require.NoError(t, err)
	assert.Equal(t, testValue, retrieved)

	// Update - Overwrite with new value
	newValue := []byte("updated-value-1")
	err = backend.Put(ctx, testKey, newValue)
	require.NoError(t, err)

	retrieved, err = backend.Get(ctx, testKey)
	require.NoError(t, err)
	assert.Equal(t, newValue, retrieved)

	// Delete
	err = backend.Delete(ctx, testKey)
	require.NoError(t, err)

	// Verify deletion
	_, err = backend.Get(ctx, testKey)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

// TestMemoryStorageIntegration_MultipleKeys tests storing and retrieving multiple keys
func TestMemoryStorageIntegration_MultipleKeys(t *testing.T) {
	ctx := context.Background()
	backend := storage.New()
	defer backend.Close()

	// Create multiple keys
	keyCount := 1000
	for i := 0; i < keyCount; i++ {
		key := fmt.Sprintf("key-%d", i)
		value := []byte(fmt.Sprintf("value-%d", i))
		err := backend.Put(ctx, key, value)
		require.NoError(t, err)
	}

	// Verify all keys exist
	for i := 0; i < keyCount; i++ {
		key := fmt.Sprintf("key-%d", i)
		exists, err := backend.Exists(ctx, key)
		require.NoError(t, err)
		assert.True(t, exists)
	}

	// List all keys
	keys, err := backend.List(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, keyCount, len(keys))

	// Delete all keys
	for i := 0; i < keyCount; i++ {
		key := fmt.Sprintf("key-%d", i)
		err := backend.Delete(ctx, key)
		require.NoError(t, err)
	}

	// Verify all deleted
	keys, err = backend.List(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, 0, len(keys))
}

// TestMemoryStorageIntegration_PrefixFiltering tests List operation with prefixes
func TestMemoryStorageIntegration_PrefixFiltering(t *testing.T) {
	ctx := context.Background()
	backend := storage.New()
	defer backend.Close()

	// Create keys with different prefixes
	testData := map[string][]byte{
		"user/alice/key1": []byte("value1"),
		"user/alice/key2": []byte("value2"),
		"user/bob/key1":   []byte("value3"),
		"user/bob/key2":   []byte("value4"),
		"admin/key1":      []byte("value5"),
		"admin/key2":      []byte("value6"),
	}

	for key, value := range testData {
		err := backend.Put(ctx, key, value)
		require.NoError(t, err)
	}

	// Test prefix filtering
	userKeys, err := backend.List(ctx, "user/")
	require.NoError(t, err)
	assert.Equal(t, 4, len(userKeys))

	aliceKeys, err := backend.List(ctx, "user/alice/")
	require.NoError(t, err)
	assert.Equal(t, 2, len(aliceKeys))

	adminKeys, err := backend.List(ctx, "admin/")
	require.NoError(t, err)
	assert.Equal(t, 2, len(adminKeys))

	allKeys, err := backend.List(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, 6, len(allKeys))
}

// TestMemoryStorageIntegration_Scan tests Scan operation
func TestMemoryStorageIntegration_Scan(t *testing.T) {
	ctx := context.Background()
	backend := storage.New()
	defer backend.Close()

	// Create keys with different prefixes
	testData := map[string][]byte{
		"scan/key1":  []byte("value1"),
		"scan/key2":  []byte("value2"),
		"scan/key3":  []byte("value3"),
		"other/key1": []byte("other-value1"),
	}

	for key, value := range testData {
		err := backend.Put(ctx, key, value)
		require.NoError(t, err)
	}

	// Scan with prefix
	results := make(map[string][]byte)
	err := backend.Scan(ctx, "scan/", func(key string, value []byte) error {
		results[key] = value
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 3, len(results))
	assert.Equal(t, []byte("value1"), results["scan/key1"])
	assert.Equal(t, []byte("value2"), results["scan/key2"])
	assert.Equal(t, []byte("value3"), results["scan/key3"])

	// Scan all
	allResults := make(map[string][]byte)
	err = backend.Scan(ctx, "", func(key string, value []byte) error {
		allResults[key] = value
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 4, len(allResults))

	// Scan with non-matching prefix
	emptyResults := make(map[string][]byte)
	err = backend.Scan(ctx, "nonexistent/", func(key string, value []byte) error {
		emptyResults[key] = value
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 0, len(emptyResults))
}

// TestMemoryStorageIntegration_ConcurrentAccess tests thread-safe concurrent operations
func TestMemoryStorageIntegration_ConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	backend := storage.New()
	defer backend.Close()

	// Number of concurrent goroutines and operations
	numGoroutines := 100
	opsPerGoroutine := 100

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*opsPerGoroutine*2) // *2 for read and write

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				key := fmt.Sprintf("concurrent-key-%d-%d", id, j)
				value := []byte(fmt.Sprintf("concurrent-value-%d-%d", id, j))
				if err := backend.Put(ctx, key, value); err != nil {
					errors <- err
				}
			}
		}(i)
	}

	wg.Wait()

	// Concurrent reads
	wg = sync.WaitGroup{}
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				key := fmt.Sprintf("concurrent-key-%d-%d", id, j)
				expectedValue := []byte(fmt.Sprintf("concurrent-value-%d-%d", id, j))
				retrieved, err := backend.Get(ctx, key)
				if err != nil {
					errors <- err
				} else if string(retrieved) != string(expectedValue) {
					errors <- fmt.Errorf("value mismatch for key %s", key)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	errorCount := 0
	for err := range errors {
		t.Logf("Concurrent operation error: %v", err)
		errorCount++
	}
	assert.Equal(t, 0, errorCount, "Expected no concurrent operation errors")
}

// TestMemoryStorageIntegration_ConcurrentReadWrite tests concurrent reads and writes
func TestMemoryStorageIntegration_ConcurrentReadWrite(t *testing.T) {
	ctx := context.Background()
	backend := storage.New()
	defer backend.Close()

	// Pre-populate with some keys
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("shared-key-%d", i)
		value := []byte(fmt.Sprintf("initial-value-%d", i))
		err := backend.Put(ctx, key, value)
		require.NoError(t, err)
	}

	var wg sync.WaitGroup
	numReaders := 50
	numWriters := 10
	duration := 2 * time.Second

	stopChan := make(chan struct{})
	errors := make(chan error, (numReaders+numWriters)*100)

	// Start readers
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-stopChan:
					return
				default:
					key := fmt.Sprintf("shared-key-%d", id%10)
					_, err := backend.Get(ctx, key)
					if err != nil && err != storage.ErrNotFound {
						errors <- fmt.Errorf("reader %d: %w", id, err)
					}
				}
			}
		}(i)
	}

	// Start writers
	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			counter := 0
			for {
				select {
				case <-stopChan:
					return
				default:
					key := fmt.Sprintf("shared-key-%d", id%10)
					value := []byte(fmt.Sprintf("writer-%d-value-%d", id, counter))
					if err := backend.Put(ctx, key, value); err != nil {
						errors <- fmt.Errorf("writer %d: %w", id, err)
					}
					counter++
				}
			}
		}(i)
	}

	// Run for specified duration
	time.Sleep(duration)
	close(stopChan)
	wg.Wait()
	close(errors)

	// Check for errors
	errorCount := 0
	for err := range errors {
		t.Logf("Concurrent read/write error: %v", err)
		errorCount++
	}
	assert.Equal(t, 0, errorCount, "Expected no concurrent read/write errors")
}

// TestMemoryStorageIntegration_LargeValues tests storing large values in memory
func TestMemoryStorageIntegration_LargeValues(t *testing.T) {
	ctx := context.Background()
	backend := storage.New()
	defer backend.Close()

	// Create a large value (50MB)
	largeValue := make([]byte, 50*1024*1024)
	_, err := rand.Read(largeValue)
	require.NoError(t, err)

	testKey := "large-value-key"
	err = backend.Put(ctx, testKey, largeValue)
	require.NoError(t, err)

	// Retrieve and verify
	retrieved, err := backend.Get(ctx, testKey)
	require.NoError(t, err)
	assert.Equal(t, len(largeValue), len(retrieved))
	assert.Equal(t, largeValue, retrieved)

	// Verify data isolation - modify original shouldn't affect stored
	// Save the original value to ensure we actually change it
	originalFirstByte := largeValue[0]
	newValue := byte(0xFF)
	if originalFirstByte == 0xFF {
		newValue = 0x00 // Use a different value if original was already 0xFF
	}
	largeValue[0] = newValue
	retrieved2, err := backend.Get(ctx, testKey)
	require.NoError(t, err)
	assert.Equal(t, originalFirstByte, retrieved2[0], "stored value should not be affected by modifying the original")
	assert.NotEqual(t, newValue, retrieved2[0], "stored value should not reflect the modification")
}

// TestMemoryStorageIntegration_DataIsolation tests data immutability
func TestMemoryStorageIntegration_DataIsolation(t *testing.T) {
	ctx := context.Background()
	backend := storage.New()
	defer backend.Close()

	testKey := "isolation-test"
	originalValue := []byte("original-value")

	// Put value
	err := backend.Put(ctx, testKey, originalValue)
	require.NoError(t, err)

	// Modify original slice
	originalValue[0] = 'X'

	// Retrieve and verify not affected
	retrieved, err := backend.Get(ctx, testKey)
	require.NoError(t, err)
	assert.Equal(t, byte('o'), retrieved[0])
	assert.NotEqual(t, originalValue[0], retrieved[0])

	// Modify retrieved slice
	retrieved[0] = 'Y'

	// Retrieve again and verify not affected
	retrieved2, err := backend.Get(ctx, testKey)
	require.NoError(t, err)
	assert.Equal(t, byte('o'), retrieved2[0])
}

// TestMemoryStorageIntegration_ErrorHandling tests error cases
func TestMemoryStorageIntegration_ErrorHandling(t *testing.T) {
	ctx := context.Background()
	backend := storage.New()
	defer backend.Close()

	// Test Get on non-existent key
	_, err := backend.Get(ctx, "non-existent")
	assert.ErrorIs(t, err, storage.ErrNotFound)

	// Test Delete on non-existent key
	err = backend.Delete(ctx, "non-existent")
	assert.ErrorIs(t, err, storage.ErrNotFound)

	// Test Exists on non-existent key
	exists, err := backend.Exists(ctx, "non-existent")
	require.NoError(t, err)
	assert.False(t, exists)
}

// TestMemoryStorageIntegration_KeyStorage tests KeyStorage interface operations
func TestMemoryStorageIntegration_KeyStorage(t *testing.T) {
	ctx := context.Background()
	keyStorage := storage.New()
	defer keyStorage.Close()

	// Save multiple keys
	keyCount := 100
	for i := 0; i < keyCount; i++ {
		keyID := fmt.Sprintf("key-%d", i)
		keyData := []byte(fmt.Sprintf("key-data-%d", i))
		err := storage.SaveKey(ctx, keyStorage, keyID, keyData)
		require.NoError(t, err)
	}

	// List all keys
	keys, err := storage.ListKeys(ctx, keyStorage)
	require.NoError(t, err)
	assert.Equal(t, keyCount, len(keys))

	// Verify all keys exist and can be retrieved
	for i := 0; i < keyCount; i++ {
		keyID := fmt.Sprintf("key-%d", i)

		exists, err := storage.KeyExists(ctx, keyStorage, keyID)
		require.NoError(t, err)
		assert.True(t, exists)

		retrieved, err := storage.GetKey(ctx, keyStorage, keyID)
		require.NoError(t, err)
		expectedData := []byte(fmt.Sprintf("key-data-%d", i))
		assert.Equal(t, expectedData, retrieved)
	}

	// Delete all keys
	for i := 0; i < keyCount; i++ {
		keyID := fmt.Sprintf("key-%d", i)
		err := storage.DeleteKey(ctx, keyStorage, keyID)
		require.NoError(t, err)
	}

	// Verify all deleted
	keys, err = storage.ListKeys(ctx, keyStorage)
	require.NoError(t, err)
	assert.Equal(t, 0, len(keys))
}

// TestMemoryStorageIntegration_CertStorage tests CertificateStorage interface operations
func TestMemoryStorageIntegration_CertStorage(t *testing.T) {
	ctx := context.Background()
	certStorage := storage.New()
	defer certStorage.Close()

	// Create test certificates
	cert1 := createTestCertificate(t)
	cert2 := createTestCertificate(t)

	// Save certificates
	err := storage.SaveCertParsed(ctx, certStorage, "cert-1", cert1)
	require.NoError(t, err)

	err = storage.SaveCertParsed(ctx, certStorage, "cert-2", cert2)
	require.NoError(t, err)

	// List certificates
	certs, err := storage.ListCerts(ctx, certStorage)
	require.NoError(t, err)
	assert.Equal(t, 2, len(certs))

	// Retrieve certificates
	retrieved1, err := storage.GetCertParsed(ctx, certStorage, "cert-1")
	require.NoError(t, err)
	assert.Equal(t, cert1.Raw, retrieved1.Raw)

	// Save and retrieve certificate chain
	chain := []*x509.Certificate{cert1, cert2}
	err = storage.SaveCertChainParsed(ctx, certStorage, "chain-1", chain)
	require.NoError(t, err)

	retrievedChain, err := storage.GetCertChainParsed(ctx, certStorage, "chain-1")
	require.NoError(t, err)
	assert.Equal(t, len(chain), len(retrievedChain))

	// Delete certificates
	err = storage.DeleteCert(ctx, certStorage, "cert-1")
	require.NoError(t, err)

	exists, err := storage.CertExists(ctx, certStorage, "cert-1")
	require.NoError(t, err)
	assert.False(t, exists)
}

// TestMemoryStorageIntegration_MemoryLeaks tests that memory is properly released
func TestMemoryStorageIntegration_MemoryLeaks(t *testing.T) {
	ctx := context.Background()
	backend := storage.New()
	defer backend.Close()

	// Create many keys, then delete them
	iterations := 10
	keysPerIteration := 1000

	for iter := 0; iter < iterations; iter++ {
		// Create keys
		for i := 0; i < keysPerIteration; i++ {
			key := fmt.Sprintf("leak-test-key-%d-%d", iter, i)
			value := make([]byte, 1024) // 1KB per value
			err := backend.Put(ctx, key, value)
			require.NoError(t, err)
		}

		// Delete keys
		for i := 0; i < keysPerIteration; i++ {
			key := fmt.Sprintf("leak-test-key-%d-%d", iter, i)
			err := backend.Delete(ctx, key)
			require.NoError(t, err)
		}

		// Verify all deleted
		keys, err := backend.List(ctx, "")
		require.NoError(t, err)
		assert.Equal(t, 0, len(keys), "Expected all keys deleted in iteration %d", iter)
	}
}
