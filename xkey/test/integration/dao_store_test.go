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

//go:build integration && linux

// Package xkey provides integration tests for DAO store round-trip persistence
// through the barrier encryption layer, verifying that data written through
// the barrier is encrypted on disk and correctly decrypted on retrieval.
package xkey

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	filestorage "github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
)

// barrierPassword is the test password used for software barrier initialization.
const barrierPassword = "integration-test-barrier-pw!"

// setupBarrier creates a file-backed storage backend, wraps it with a software
// barrier, initializes and unseals the barrier, and returns the unsealed barrier.
// The temporary directory and barrier are cleaned up when the test completes.
func setupBarrier(t *testing.T) (*seal.Barrier, string) {
	t.Helper()

	tmpDir := tempDir(t)
	storeDir := filepath.Join(tmpDir, "store")

	backend, err := filestorage.New(storeDir)
	require.NoError(t, err, "failed to create file storage backend")
	t.Cleanup(func() { backend.Close() })

	strategy := seal.NewSoftwareStrategy()
	t.Cleanup(func() { strategy.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	barrier, err := seal.NewBarrier(
		logger,
		backend,
		seal.BarrierConfig{
			RootKeyPath: "seal/root.key",
		},
		strategy,
	)
	require.NoError(t, err, "failed to create barrier")
	t.Cleanup(func() { barrier.Close() })

	ctx := context.Background()
	creds := seal.Credentials{Secret: barrierPassword}

	err = barrier.Initialize(ctx, creds)
	require.NoError(t, err, "failed to initialize barrier")

	// Initialize leaves the barrier unsealed; no separate Unseal needed.

	return barrier, tmpDir
}

// ---------------------------------------------------------------------------
// TeamStore DAO round-trip through barrier
// ---------------------------------------------------------------------------

// TestDAOTeamStore_RoundTrip_ThroughBarrier verifies that teams created
// through a DAOTeamStore backed by a barrier-encrypted file storage can be
// persisted, retrieved, listed, and deleted correctly.
func TestDAOTeamStore_RoundTrip_ThroughBarrier(t *testing.T) {
	barrier, _ := setupBarrier(t)
	ctx := context.Background()

	kvStore, err := kvadapter.New(barrier)
	require.NoError(t, err, "failed to create kvstore adapter")

	store, err := staticpw.NewDAOTeamStore(kvStore)
	require.NoError(t, err, "failed to create DAO team store")
	t.Cleanup(func() { store.Close() })

	// Create a team with members.
	team := &staticpw.TeamEntity{
		Name:     "platform-engineering",
		TenantID: "tenant-alpha",
		OwnerID:  "alice",
		Members:  []string{"bob", "charlie"},
	}
	err = store.Create(ctx, team)
	require.NoError(t, err, "failed to create team")

	// Verify Get returns the persisted team.
	got, err := store.Get(ctx, "platform-engineering")
	require.NoError(t, err, "failed to get team")
	assert.Equal(t, "platform-engineering", got.Name)
	assert.Equal(t, "tenant-alpha", got.TenantID)
	assert.Equal(t, "alice", got.OwnerID)
	assert.Equal(t, []string{"bob", "charlie"}, got.Members)
	assert.False(t, got.CreatedAt.IsZero(), "CreatedAt should be set")
	assert.False(t, got.UpdatedAt.IsZero(), "UpdatedAt should be set")

	// Add a member and verify membership.
	err = store.AddMember(ctx, "platform-engineering", "dave")
	require.NoError(t, err, "failed to add member")

	got, err = store.Get(ctx, "platform-engineering")
	require.NoError(t, err, "failed to get team after adding member")
	assert.Contains(t, got.Members, "dave")
	assert.Len(t, got.Members, 3)

	// Create a second team and verify list count.
	err = store.Create(ctx, &staticpw.TeamEntity{
		Name:     "security",
		TenantID: "tenant-alpha",
		OwnerID:  "eve",
	})
	require.NoError(t, err, "failed to create second team")

	teams, err := store.List(ctx)
	require.NoError(t, err, "failed to list teams")
	assert.Len(t, teams, 2)

	// Delete a team and verify it is gone.
	err = store.Delete(ctx, "security")
	require.NoError(t, err, "failed to delete team")

	_, err = store.Get(ctx, "security")
	assert.ErrorIs(t, err, staticpw.ErrTeamNotFound, "deleted team should not be found")

	teams, err = store.List(ctx)
	require.NoError(t, err, "failed to list teams after delete")
	assert.Len(t, teams, 1)
}

// TestDAOTeamStore_EncryptionVerification verifies that data persisted through
// the barrier is encrypted on disk. Raw file bytes must not contain the team
// name in plaintext.
func TestDAOTeamStore_EncryptionVerification(t *testing.T) {
	barrier, tmpDir := setupBarrier(t)
	ctx := context.Background()

	kvStore, err := kvadapter.New(barrier)
	require.NoError(t, err, "failed to create kvstore adapter")

	store, err := staticpw.NewDAOTeamStore(kvStore)
	require.NoError(t, err, "failed to create DAO team store")
	t.Cleanup(func() { store.Close() })

	// Use a distinctive name that would be easy to find in raw bytes.
	teamName := "CANARY_ENCRYPTION_CHECK_XYZ_98765"
	err = store.Create(ctx, &staticpw.TeamEntity{
		Name:     teamName,
		TenantID: "tenant-secret",
		OwnerID:  "alice",
	})
	require.NoError(t, err, "failed to create canary team")

	// Verify the team is retrievable through the barrier.
	got, err := store.Get(ctx, teamName)
	require.NoError(t, err, "failed to get canary team through barrier")
	assert.Equal(t, teamName, got.Name)

	// Walk the store directory and check that no raw file contains
	// the canary team name in plaintext.
	storeDir := filepath.Join(tmpDir, "store")
	found := false
	walkErr := filepath.Walk(storeDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		// Skip the root key file itself.
		if strings.HasSuffix(path, "root.key") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		if strings.Contains(string(data), teamName) {
			found = true
			t.Errorf("File %s contains canary team name %q in plaintext", path, teamName)
		}
		return nil
	})
	require.NoError(t, walkErr, "failed to walk store directory")

	if !found {
		t.Log("Encryption verification passed: no raw files contain the canary team name in plaintext")
	}
}

// ---------------------------------------------------------------------------
// StaticPassword store through barrier
// ---------------------------------------------------------------------------

// TestStaticPasswordStore_RoundTrip_ThroughBarrier verifies that password
// entries created through a BackendStore backed by barrier-encrypted file
// storage can be added, retrieved, listed, and deleted correctly.
func TestStaticPasswordStore_RoundTrip_ThroughBarrier(t *testing.T) {
	barrier, _ := setupBarrier(t)

	store := staticpw.NewStore(barrier)
	t.Cleanup(func() { store.Close() })

	// Add a password entry.
	pw := &staticpw.StaticPassword{
		Name:     "TestService",
		Username: "admin@example.com",
		Password: "s3cret-P@ssw0rd!",
		URL:      "https://example.com",
		Notes:    "Integration test entry",
	}
	err := store.Add(pw)
	require.NoError(t, err, "failed to add password")
	assert.NotEmpty(t, pw.ID, "password ID should be assigned")

	// Retrieve and verify.
	got, err := store.Get("TestService")
	require.NoError(t, err, "failed to get password")
	assert.Equal(t, "TestService", got.Name)
	assert.Equal(t, "admin@example.com", got.Username)
	assert.Equal(t, "s3cret-P@ssw0rd!", got.Password)
	assert.Equal(t, "https://example.com", got.URL)
	assert.Equal(t, "Integration test entry", got.Notes)
	assert.False(t, got.CreatedAt.IsZero(), "CreatedAt should be set")

	// List and verify count.
	passwords, err := store.List()
	require.NoError(t, err, "failed to list passwords")
	assert.Len(t, passwords, 1)

	// Add a second entry and verify list count.
	err = store.Add(&staticpw.StaticPassword{
		Name:     "AnotherService",
		Password: "another-secret",
	})
	require.NoError(t, err, "failed to add second password")

	passwords, err = store.List()
	require.NoError(t, err, "failed to list passwords after second add")
	assert.Len(t, passwords, 2)

	// Delete and verify gone.
	err = store.Delete("TestService")
	require.NoError(t, err, "failed to delete password")

	_, err = store.Get("TestService")
	assert.ErrorIs(t, err, staticpw.ErrPasswordNotFound, "deleted password should not be found")

	passwords, err = store.List()
	require.NoError(t, err, "failed to list passwords after delete")
	assert.Len(t, passwords, 1)
}

// TestStaticPasswordStore_EncryptionVerification verifies that password data
// is encrypted on disk when stored through the barrier.
func TestStaticPasswordStore_EncryptionVerification(t *testing.T) {
	barrier, tmpDir := setupBarrier(t)

	store := staticpw.NewStore(barrier)
	t.Cleanup(func() { store.Close() })

	// Use a distinctive password value that would be easy to find in raw bytes.
	canaryPassword := "CANARY_PASSWORD_PLAINTEXT_CHECK_54321"
	err := store.Add(&staticpw.StaticPassword{
		Name:     "EncryptionTestEntry",
		Password: canaryPassword,
	})
	require.NoError(t, err, "failed to add canary password")

	// Walk the store directory and verify the canary password does not
	// appear in any raw file on disk.
	storeDir := filepath.Join(tmpDir, "store")
	walkErr := filepath.Walk(storeDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, "root.key") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		if strings.Contains(string(data), canaryPassword) {
			t.Errorf("File %s contains canary password %q in plaintext", path, canaryPassword)
		}
		return nil
	})
	require.NoError(t, walkErr, "failed to walk store directory")
}

// ---------------------------------------------------------------------------
// Cross-store isolation
// ---------------------------------------------------------------------------

// TestCrossStoreIsolation_TeamAndPassword verifies that data written to the
// DAOTeamStore does not appear in the StaticPassword BackendStore, and vice
// versa, even though both share the same underlying barrier backend.
func TestCrossStoreIsolation_TeamAndPassword(t *testing.T) {
	barrier, _ := setupBarrier(t)
	ctx := context.Background()

	// Create a DAOTeamStore.
	kvStore, err := kvadapter.New(barrier)
	require.NoError(t, err, "failed to create kvstore adapter")

	teamStore, err := staticpw.NewDAOTeamStore(kvStore)
	require.NoError(t, err, "failed to create DAO team store")
	t.Cleanup(func() { teamStore.Close() })

	// Create a StaticPassword BackendStore.
	pwStore := staticpw.NewStore(barrier)
	t.Cleanup(func() { pwStore.Close() })

	// Write data to both stores.
	err = teamStore.Create(ctx, &staticpw.TeamEntity{
		Name:     "isolation-team",
		TenantID: "tenant-iso",
		OwnerID:  "alice",
		Members:  []string{"bob"},
	})
	require.NoError(t, err, "failed to create team for isolation test")

	err = pwStore.Add(&staticpw.StaticPassword{
		Name:     "isolation-password",
		Password: "isolated-secret-value",
	})
	require.NoError(t, err, "failed to add password for isolation test")

	// Verify team data is NOT in the password store.
	_, err = pwStore.Get("isolation-team")
	assert.ErrorIs(t, err, staticpw.ErrPasswordNotFound,
		"team name should not appear in password store")

	// Verify password data is NOT in the team store.
	_, err = teamStore.Get(ctx, "isolation-password")
	assert.ErrorIs(t, err, staticpw.ErrTeamNotFound,
		"password name should not appear in team store")

	// Verify each store still returns its own data correctly.
	team, err := teamStore.Get(ctx, "isolation-team")
	require.NoError(t, err, "team should be found in team store")
	assert.Equal(t, "isolation-team", team.Name)

	pw, err := pwStore.Get("isolation-password")
	require.NoError(t, err, "password should be found in password store")
	assert.Equal(t, "isolation-password", pw.Name)
}

// TestCrossStoreIsolation_TwoTeamStores verifies that two DAOTeamStores
// created from the same barrier share the same namespace and see each
// other's data (they are the same logical store with different handles).
func TestCrossStoreIsolation_TwoTeamStores(t *testing.T) {
	barrier, _ := setupBarrier(t)
	ctx := context.Background()

	kvStore, err := kvadapter.New(barrier)
	require.NoError(t, err, "failed to create kvstore adapter")

	store1, err := staticpw.NewDAOTeamStore(kvStore)
	require.NoError(t, err, "failed to create first DAO team store")
	t.Cleanup(func() { store1.Close() })

	store2, err := staticpw.NewDAOTeamStore(kvStore)
	require.NoError(t, err, "failed to create second DAO team store")
	t.Cleanup(func() { store2.Close() })

	// Write via store1.
	err = store1.Create(ctx, &staticpw.TeamEntity{
		Name:    "shared-team",
		OwnerID: "alice",
	})
	require.NoError(t, err, "failed to create team via store1")

	// Read via store2 to confirm shared namespace.
	got, err := store2.Get(ctx, "shared-team")
	require.NoError(t, err, "store2 should see team created by store1")
	assert.Equal(t, "shared-team", got.Name)
	assert.Equal(t, "alice", got.OwnerID)
}

// ---------------------------------------------------------------------------
// Barrier seal/unseal persistence
// ---------------------------------------------------------------------------

// TestDAOTeamStore_PersistenceAcrossSealUnseal verifies that data persisted
// through the barrier survives a seal and re-unseal cycle.
func TestDAOTeamStore_PersistenceAcrossSealUnseal(t *testing.T) {
	tmpDir := tempDir(t)
	storeDir := filepath.Join(tmpDir, "store")
	ctx := context.Background()

	backend, err := filestorage.New(storeDir)
	require.NoError(t, err, "failed to create file storage backend")
	t.Cleanup(func() { backend.Close() })

	strategy := seal.NewSoftwareStrategy()
	t.Cleanup(func() { strategy.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	creds := seal.Credentials{Secret: barrierPassword}

	barrier, err := seal.NewBarrier(
		logger,
		backend,
		seal.BarrierConfig{
			RootKeyPath: "seal/root.key",
		},
		strategy,
	)
	require.NoError(t, err, "failed to create barrier")
	t.Cleanup(func() { barrier.Close() })

	// Initialize and unseal.
	err = barrier.Initialize(ctx, creds)
	require.NoError(t, err, "failed to initialize barrier")

	// Initialize leaves the barrier unsealed; no separate Unseal needed.

	// Write data via team store.
	kvStore, err := kvadapter.New(barrier)
	require.NoError(t, err, "failed to create kvstore adapter")

	store, err := staticpw.NewDAOTeamStore(kvStore)
	require.NoError(t, err, "failed to create DAO team store")

	err = store.Create(ctx, &staticpw.TeamEntity{
		Name:     "persist-team",
		TenantID: "tenant-persist",
		OwnerID:  "alice",
		Members:  []string{"bob"},
	})
	require.NoError(t, err, "failed to create team before seal")
	store.Close()

	// Seal the barrier (clears the DEK from memory).
	err = barrier.Seal()
	require.NoError(t, err, "failed to seal barrier")

	// Re-unseal the barrier.
	err = barrier.Unseal(ctx, creds)
	require.NoError(t, err, "failed to re-unseal barrier")

	// Read the data back through a new store handle.
	kvStore2, err := kvadapter.New(barrier)
	require.NoError(t, err, "failed to create kvstore adapter after re-unseal")

	store2, err := staticpw.NewDAOTeamStore(kvStore2)
	require.NoError(t, err, "failed to create DAO team store after re-unseal")
	t.Cleanup(func() { store2.Close() })

	got, err := store2.Get(ctx, "persist-team")
	require.NoError(t, err, "team should survive seal/unseal cycle")
	assert.Equal(t, "persist-team", got.Name)
	assert.Equal(t, "tenant-persist", got.TenantID)
	assert.Equal(t, "alice", got.OwnerID)
	assert.Equal(t, []string{"bob"}, got.Members)
}
