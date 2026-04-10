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

package services

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBarrierStaticPW_EncryptionEndToEnd verifies the complete barrier +
// static password flow with real filesystem I/O:
//
//  1. Initialize the barrier with a software (password) strategy
//  2. Store a password entry through the barrier-backed static password store
//  3. Read the raw file bytes from disk and assert they are NOT plaintext JSON
//  4. Read back through the store (decryption path) and assert correctness
//  5. Seal the barrier, verify operations fail
//  6. Unseal the barrier, verify passwords are accessible again
func TestBarrierStaticPW_EncryptionEndToEnd(t *testing.T) {
	configDir := t.TempDir()
	barrierPassword := "strong-test-passphrase-42"

	// ---------------------------------------------------------------
	// Step 1: Create and initialize the barrier.
	// ---------------------------------------------------------------
	svc := NewBarrierService(configDir, slog.Default())

	err := svc.Initialize(barrierPassword, "software")
	require.NoError(t, err, "barrier initialization must succeed")

	backend := svc.GetBackend()
	require.NotNil(t, backend, "GetBackend must return non-nil after initialization")

	// ---------------------------------------------------------------
	// Step 2: Create a static password store and add an entry.
	// ---------------------------------------------------------------
	store := staticpw.NewStore(backend)

	entry := &staticpw.StaticPassword{
		Name:     "TestPassword",
		Password: "secret123",
		Username: "testuser",
		URL:      "https://example.com",
		Notes:    "test entry for encryption verification",
	}

	err = store.Add(entry)
	require.NoError(t, err, "adding password entry must succeed")

	// ---------------------------------------------------------------
	// Step 3: Read the raw file bytes from disk.
	// The file storage root is configDir/barrier/ and the staticpw
	// store writes keys as "staticpw/<id>.json", so the file is at
	// configDir/barrier/staticpw/<id>.json.
	// ---------------------------------------------------------------
	expectedID := staticpw.GenerateID("TestPassword", "")
	rawFilePath := filepath.Join(configDir, "barrier", "staticpw", expectedID+".json")

	rawBytes, err := os.ReadFile(rawFilePath)
	require.NoError(t, err, "raw file must exist on disk at %s", rawFilePath)
	require.NotEmpty(t, rawBytes, "raw file must not be empty")

	// The raw bytes must NOT be valid JSON. If the barrier encryption is
	// working, the file contains a version byte followed by the AES-256-GCM
	// ciphertext, which is not parseable as JSON.
	var probe map[string]any
	jsonErr := json.Unmarshal(rawBytes, &probe)
	assert.Error(t, jsonErr, "raw file bytes must NOT be valid JSON (data must be encrypted)")

	// Additionally verify the plaintext password does not appear anywhere
	// in the raw file bytes.
	assert.NotContains(t, string(rawBytes), "secret123",
		"plaintext password must never appear in the raw on-disk file")
	assert.NotContains(t, string(rawBytes), "TestPassword",
		"plaintext entry name must never appear in the raw on-disk file")

	// ---------------------------------------------------------------
	// Step 4: Verify decryption works through the store API.
	// ---------------------------------------------------------------
	retrieved, err := store.Get("TestPassword")
	require.NoError(t, err, "reading password through store must succeed")
	require.NotNil(t, retrieved)
	assert.Equal(t, "TestPassword", retrieved.Name)
	assert.Equal(t, "secret123", retrieved.Password)
	assert.Equal(t, "testuser", retrieved.Username)
	assert.Equal(t, "https://example.com", retrieved.URL)
	assert.Equal(t, "test entry for encryption verification", retrieved.Notes)

	// Verify List also works.
	entries, err := store.List()
	require.NoError(t, err)
	require.Len(t, entries, 1, "store must contain exactly one entry")
	assert.Equal(t, "TestPassword", entries[0].Name)

	// ---------------------------------------------------------------
	// Step 5: Seal the barrier and verify operations fail.
	// ---------------------------------------------------------------
	err = svc.Seal()
	require.NoError(t, err, "sealing the barrier must succeed")
	assert.False(t, svc.IsUnsealed(), "barrier must be sealed after Seal()")

	_, err = store.List()
	require.Error(t, err, "List must fail when barrier is sealed")

	_, err = store.Get("TestPassword")
	require.Error(t, err, "Get must fail when barrier is sealed")

	// ---------------------------------------------------------------
	// Step 6: Unseal and verify passwords are accessible again.
	// ---------------------------------------------------------------
	err = svc.Unseal(barrierPassword, "software")
	require.NoError(t, err, "unseal must succeed with the correct password")
	assert.True(t, svc.IsUnsealed(), "barrier must be unsealed after Unseal()")

	// The old store still points to the previous barrier backend which is
	// now sealed. Create a new store with the freshly unsealed backend.
	newBackend := svc.GetBackend()
	require.NotNil(t, newBackend, "GetBackend must return non-nil after unseal")

	store2 := staticpw.NewStore(newBackend)

	retrieved2, err := store2.Get("TestPassword")
	require.NoError(t, err, "reading password after unseal must succeed")
	require.NotNil(t, retrieved2)
	assert.Equal(t, "TestPassword", retrieved2.Name)
	assert.Equal(t, "secret123", retrieved2.Password)
	assert.Equal(t, "testuser", retrieved2.Username)

	entries2, err := store2.List()
	require.NoError(t, err)
	require.Len(t, entries2, 1)
	assert.Equal(t, "TestPassword", entries2[0].Name)
}

// TestBarrierStaticPW_WrongPasswordCannotDecrypt verifies that unsealing with
// the wrong password does not allow reading previously stored passwords.
func TestBarrierStaticPW_WrongPasswordCannotDecrypt(t *testing.T) {
	configDir := t.TempDir()
	correctPassword := "correct-password-99"
	wrongPassword := "wrong-password-00"

	// Initialize and store a password.
	svc := NewBarrierService(configDir, slog.Default())

	err := svc.Initialize(correctPassword, "software")
	require.NoError(t, err)

	store := staticpw.NewStore(svc.GetBackend())
	err = store.Add(&staticpw.StaticPassword{
		Name:     "SecretEntry",
		Password: "very-secret",
	})
	require.NoError(t, err)

	// Seal.
	err = svc.Seal()
	require.NoError(t, err)

	// Unseal with wrong password must fail.
	err = svc.Unseal(wrongPassword, "software")
	require.Error(t, err, "unseal with wrong password must fail")
}

// TestBarrierStaticPW_MultipleEntries verifies that multiple password entries
// are all encrypted and independently retrievable after unseal.
func TestBarrierStaticPW_MultipleEntries(t *testing.T) {
	configDir := t.TempDir()
	password := "multi-entry-pw-77"

	svc := NewBarrierService(configDir, slog.Default())
	err := svc.Initialize(password, "software")
	require.NoError(t, err)

	store := staticpw.NewStore(svc.GetBackend())

	entries := []staticpw.StaticPassword{
		{Name: "GitHub", Password: "gh-token-abc", Username: "dev"},
		{Name: "AWS Console", Password: "aws-secret-xyz", Username: "admin"},
		{Name: "Database", Password: "db-pass-123", Username: "root"},
	}

	for i := range entries {
		err := store.Add(&entries[i])
		require.NoError(t, err, "adding entry %q must succeed", entries[i].Name)
	}

	// Verify all entries are stored and encrypted on disk.
	barrierDir := filepath.Join(configDir, "barrier", "staticpw")
	dirEntries, err := os.ReadDir(barrierDir)
	require.NoError(t, err)
	assert.Len(t, dirEntries, 3, "must have 3 files in staticpw directory")

	for _, de := range dirEntries {
		rawBytes, readErr := os.ReadFile(filepath.Join(barrierDir, de.Name()))
		require.NoError(t, readErr)

		var probe map[string]any
		jsonErr := json.Unmarshal(rawBytes, &probe)
		assert.Error(t, jsonErr,
			"file %s must contain encrypted data, not plaintext JSON", de.Name())
	}

	// Verify retrieval through the store.
	listed, err := store.List()
	require.NoError(t, err)
	require.Len(t, listed, 3)

	// Seal, unseal, and verify again.
	err = svc.Seal()
	require.NoError(t, err)

	err = svc.Unseal(password, "software")
	require.NoError(t, err)

	store2 := staticpw.NewStore(svc.GetBackend())
	listed2, err := store2.List()
	require.NoError(t, err)
	require.Len(t, listed2, 3)

	// Verify each entry by name.
	nameMap := make(map[string]*staticpw.StaticPassword, len(listed2))
	for _, pw := range listed2 {
		nameMap[pw.Name] = pw
	}

	for _, want := range entries {
		got, ok := nameMap[want.Name]
		require.True(t, ok, "entry %q must be present after unseal", want.Name)
		assert.Equal(t, want.Password, got.Password)
		assert.Equal(t, want.Username, got.Username)
	}
}
