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

package storage_test

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFileStorageIntegration_BasicCRUD tests basic Create, Read, Update, Delete operations
func TestFileStorageIntegration_BasicCRUD(t *testing.T) {
	tmpDir := t.TempDir()

	opts := &storage.Options{
		Path:        tmpDir,
		Permissions: 0600,
	}

	backend, err := file.New(opts.Path)
	require.NoError(t, err)
	defer backend.Close()

	// Create - Put a value
	testKey := "test-key-1"
	testValue := []byte("test-value-1")
	err = backend.Put(testKey, testValue, nil)
	require.NoError(t, err)

	// Read - Get the value
	retrieved, err := backend.Get(testKey)
	require.NoError(t, err)
	assert.Equal(t, testValue, retrieved)

	// Update - Overwrite with new value
	newValue := []byte("updated-value-1")
	err = backend.Put(testKey, newValue, nil)
	require.NoError(t, err)

	retrieved, err = backend.Get(testKey)
	require.NoError(t, err)
	assert.Equal(t, newValue, retrieved)

	// Delete
	err = backend.Delete(testKey)
	require.NoError(t, err)

	// Verify deletion
	_, err = backend.Get(testKey)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

// TestFileStorageIntegration_MultipleKeys tests storing and retrieving multiple keys
func TestFileStorageIntegration_MultipleKeys(t *testing.T) {
	tmpDir := t.TempDir()

	opts := &storage.Options{
		Path:        tmpDir,
		Permissions: 0600,
	}

	backend, err := file.New(opts.Path)
	require.NoError(t, err)
	defer backend.Close()

	// Create multiple keys
	keyCount := 100
	for i := 0; i < keyCount; i++ {
		key := fmt.Sprintf("key-%d", i)
		value := []byte(fmt.Sprintf("value-%d", i))
		err := backend.Put(key, value, nil)
		require.NoError(t, err)
	}

	// Verify all keys exist
	for i := 0; i < keyCount; i++ {
		key := fmt.Sprintf("key-%d", i)
		exists, err := backend.Exists(key)
		require.NoError(t, err)
		assert.True(t, exists)
	}

	// List all keys
	keys, err := backend.List("")
	require.NoError(t, err)
	assert.Equal(t, keyCount, len(keys))

	// Delete all keys
	for i := 0; i < keyCount; i++ {
		key := fmt.Sprintf("key-%d", i)
		err := backend.Delete(key)
		require.NoError(t, err)
	}

	// Verify all deleted
	keys, err = backend.List("")
	require.NoError(t, err)
	assert.Equal(t, 0, len(keys))
}

// TestFileStorageIntegration_NestedPaths tests storing keys with nested path structure
func TestFileStorageIntegration_NestedPaths(t *testing.T) {
	tmpDir := t.TempDir()

	opts := &storage.Options{
		Path:        tmpDir,
		Permissions: 0600,
	}

	backend, err := file.New(opts.Path)
	require.NoError(t, err)
	defer backend.Close()

	// Create keys with nested paths
	testCases := []string{
		"level1/key1",
		"level1/key2",
		"level1/level2/key3",
		"level1/level2/key4",
		"level1/level2/level3/key5",
	}

	for _, key := range testCases {
		value := []byte(fmt.Sprintf("value-for-%s", key))
		err := backend.Put(key, value, nil)
		require.NoError(t, err)
	}

	// List with prefix filter
	level1Keys, err := backend.List("level1/")
	require.NoError(t, err)
	assert.Equal(t, len(testCases), len(level1Keys))

	level2Keys, err := backend.List("level1/level2/")
	require.NoError(t, err)
	assert.Equal(t, 3, len(level2Keys))

	// Verify retrieval
	for _, key := range testCases {
		retrieved, err := backend.Get(key)
		require.NoError(t, err)
		expectedValue := []byte(fmt.Sprintf("value-for-%s", key))
		assert.Equal(t, expectedValue, retrieved)
	}
}

// TestFileStorageIntegration_ConcurrentAccess tests concurrent read/write operations
func TestFileStorageIntegration_ConcurrentAccess(t *testing.T) {
	tmpDir := t.TempDir()

	opts := &storage.Options{
		Path:        tmpDir,
		Permissions: 0600,
	}

	backend, err := file.New(opts.Path)
	require.NoError(t, err)
	defer backend.Close()

	// Number of concurrent goroutines
	numGoroutines := 50
	opsPerGoroutine := 20

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*opsPerGoroutine)

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				key := fmt.Sprintf("concurrent-key-%d-%d", id, j)
				value := []byte(fmt.Sprintf("concurrent-value-%d-%d", id, j))
				if err := backend.Put(key, value, nil); err != nil {
					errors <- err
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	errorCount := 0
	for err := range errors {
		t.Logf("Concurrent write error: %v", err)
		errorCount++
	}
	assert.Equal(t, 0, errorCount, "Expected no concurrent write errors")

	// Verify all keys exist and can be read
	wg = sync.WaitGroup{}
	readErrors := make(chan error, numGoroutines*opsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				key := fmt.Sprintf("concurrent-key-%d-%d", id, j)
				expectedValue := []byte(fmt.Sprintf("concurrent-value-%d-%d", id, j))
				retrieved, err := backend.Get(key)
				if err != nil {
					readErrors <- err
				} else if string(retrieved) != string(expectedValue) {
					readErrors <- fmt.Errorf("value mismatch for key %s", key)
				}
			}
		}(i)
	}

	wg.Wait()
	close(readErrors)

	// Check for read errors
	readErrorCount := 0
	for err := range readErrors {
		t.Logf("Concurrent read error: %v", err)
		readErrorCount++
	}
	assert.Equal(t, 0, readErrorCount, "Expected no concurrent read errors")
}

// TestFileStorageIntegration_Permissions tests file permission handling
func TestFileStorageIntegration_Permissions(t *testing.T) {
	tmpDir := t.TempDir()

	backend, err := file.New(tmpDir)
	require.NoError(t, err)
	defer backend.Close()

	testKey := "perm-test-key"
	testValue := []byte("perm-test-value")

	// Test with custom permissions passed via Put options
	customPerms := os.FileMode(0640)
	opts := &storage.Options{
		Permissions: customPerms,
	}

	err = backend.Put(testKey, testValue, opts)
	require.NoError(t, err)

	// Verify file permissions
	filePath := filepath.Join(tmpDir, testKey)
	info, err := os.Stat(filePath)
	require.NoError(t, err)

	// Check permissions (may vary based on OS umask)
	assert.Equal(t, customPerms, info.Mode().Perm())
}

// TestFileStorageIntegration_LargeValues tests storing large values
func TestFileStorageIntegration_LargeValues(t *testing.T) {
	tmpDir := t.TempDir()

	opts := &storage.Options{
		Path:        tmpDir,
		Permissions: 0600,
	}

	backend, err := file.New(opts.Path)
	require.NoError(t, err)
	defer backend.Close()

	// Create a large value (10MB)
	largeValue := make([]byte, 10*1024*1024)
	_, err = rand.Read(largeValue)
	require.NoError(t, err)

	testKey := "large-value-key"
	err = backend.Put(testKey, largeValue, nil)
	require.NoError(t, err)

	// Retrieve and verify
	retrieved, err := backend.Get(testKey)
	require.NoError(t, err)
	assert.Equal(t, len(largeValue), len(retrieved))
	assert.Equal(t, largeValue, retrieved)
}

// TestFileStorageIntegration_ErrorHandling tests error cases
func TestFileStorageIntegration_ErrorHandling(t *testing.T) {
	tmpDir := t.TempDir()

	opts := &storage.Options{
		Path:        tmpDir,
		Permissions: 0600,
	}

	backend, err := file.New(opts.Path)
	require.NoError(t, err)
	defer backend.Close()

	// Test Get on non-existent key
	_, err = backend.Get("non-existent")
	assert.ErrorIs(t, err, storage.ErrNotFound)

	// Test Delete on non-existent key
	err = backend.Delete("non-existent")
	assert.ErrorIs(t, err, storage.ErrNotFound)

	// Test Exists on non-existent key
	exists, err := backend.Exists("non-existent")
	require.NoError(t, err)
	assert.False(t, exists)
}

// TestFileStorageIntegration_KeyStorage tests KeyStorage interface operations
func TestFileStorageIntegration_KeyStorage(t *testing.T) {
	tmpDir := t.TempDir()

	keyStorage, err := file.New(tmpDir)
	require.NoError(t, err)
	defer keyStorage.Close()

	// Save a key
	keyID := "test-key-id"
	keyData := []byte("test-key-data-content")
	err = storage.SaveKey(keyStorage, keyID, keyData)
	require.NoError(t, err)

	// Get the key
	retrieved, err := storage.GetKey(keyStorage, keyID)
	require.NoError(t, err)
	assert.Equal(t, keyData, retrieved)

	// Check key exists
	exists, err := storage.KeyExists(keyStorage, keyID)
	require.NoError(t, err)
	assert.True(t, exists)

	// List keys
	keys, err := storage.ListKeys(keyStorage)
	require.NoError(t, err)
	assert.Contains(t, keys, keyID)

	// Delete key
	err = storage.DeleteKey(keyStorage, keyID)
	require.NoError(t, err)

	// Verify deletion
	exists, err = storage.KeyExists(keyStorage, keyID)
	require.NoError(t, err)
	assert.False(t, exists)
}

// TestFileStorageIntegration_CertStorage tests CertificateStorage interface operations
func TestFileStorageIntegration_CertStorage(t *testing.T) {
	tmpDir := t.TempDir()

	certStorage, err := file.New(tmpDir)
	require.NoError(t, err)
	defer certStorage.Close()

	// Create a test certificate
	cert := createTestCertificate(t)

	// Save certificate
	certID := "test-cert-id"
	err = storage.SaveCertParsed(certStorage, certID, cert)
	require.NoError(t, err)

	// Get certificate
	retrieved, err := storage.GetCertParsed(certStorage, certID)
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, retrieved.Raw)

	// Check certificate exists
	exists, err := storage.CertExists(certStorage, certID)
	require.NoError(t, err)
	assert.True(t, exists)

	// List certificates
	certs, err := storage.ListCerts(certStorage)
	require.NoError(t, err)
	assert.Contains(t, certs, certID)

	// Save certificate chain
	chainID := "test-chain-id"
	chain := []*x509.Certificate{cert, cert}
	err = storage.SaveCertChainParsed(certStorage, chainID, chain)
	require.NoError(t, err)

	// Get certificate chain
	retrievedChain, err := storage.GetCertChainParsed(certStorage, chainID)
	require.NoError(t, err)
	assert.Equal(t, len(chain), len(retrievedChain))

	// Delete certificate
	err = storage.DeleteCert(certStorage, certID)
	require.NoError(t, err)

	// Verify deletion
	exists, err = storage.CertExists(certStorage, certID)
	require.NoError(t, err)
	assert.False(t, exists)
}
