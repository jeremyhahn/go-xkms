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

package oath

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-qrdb/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestDAOStore creates a DAOStore backed by in-memory storage for testing.
func newTestDAOStore(t *testing.T) *DAOStore {
	t.Helper()
	backend := storage.NewMemory()
	t.Cleanup(func() { backend.Close() })

	kvStore, err := kvadapter.New(backend)
	require.NoError(t, err)

	store, err := NewDAOStore(kvStore)
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	return store
}

// testCredential creates a valid TOTP credential for testing.
func testCredential(name, issuer string) *Credential {
	return &Credential{
		ID:          generateCredentialID(issuer, name+"@example.com"),
		Name:        name,
		Issuer:      issuer,
		AccountName: name + "@example.com",
		Secret:      "JBSWY3DPEHPK3PXP",
		Type:        TypeTOTP,
		Algorithm:   AlgorithmSHA1,
		Digits:      DefaultDigits,
		Period:      DefaultPeriod,
		CreatedAt:   time.Now(),
	}
}

// --- Constructor tests ---

func TestDAOStore_NewDAOStore_NilKVStore(t *testing.T) {
	store, err := NewDAOStore(nil)
	require.Error(t, err)
	var nilErr ErrNilKVStore
	require.ErrorAs(t, err, &nilErr)
	assert.Nil(t, store)
}

func TestDAOStore_ImplementsStoreInterface(t *testing.T) {
	store := newTestDAOStore(t)
	var _ Store = store
}

// --- Add tests ---

func TestDAOStore_Add_Success(t *testing.T) {
	store := newTestDAOStore(t)
	cred := testCredential("GitHub", "github.com")

	err := store.Add(cred)
	require.NoError(t, err)

	// Verify it can be retrieved.
	got, err := store.Get(cred.Name)
	require.NoError(t, err)
	assert.Equal(t, cred.Name, got.Name)
	assert.Equal(t, cred.Issuer, got.Issuer)
	assert.Equal(t, cred.Secret, got.Secret)
	assert.Equal(t, cred.Type, got.Type)
}

func TestDAOStore_Add_InvalidCredential(t *testing.T) {
	store := newTestDAOStore(t)
	cred := &Credential{Name: "", Secret: "JBSWY3DPEHPK3PXP", Type: TypeTOTP}

	err := store.Add(cred)
	require.Error(t, err)
}

func TestDAOStore_Add_DuplicateName(t *testing.T) {
	store := newTestDAOStore(t)
	cred1 := testCredential("GitHub", "github.com")
	require.NoError(t, store.Add(cred1))

	cred2 := testCredential("GitHub", "other.com")
	err := store.Add(cred2)
	require.ErrorIs(t, err, ErrCredentialExists)
}

func TestDAOStore_Add_DuplicateNameCaseInsensitive(t *testing.T) {
	store := newTestDAOStore(t)
	cred1 := testCredential("GitHub", "github.com")
	require.NoError(t, store.Add(cred1))

	cred2 := testCredential("GITHUB", "other.com")
	err := store.Add(cred2)
	require.ErrorIs(t, err, ErrCredentialExists)
}

func TestDAOStore_Add_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	err := store.Add(testCredential("GitHub", "github.com"))
	require.ErrorIs(t, err, ErrStoreClosed)
}

// --- Get tests ---

func TestDAOStore_Get_ByName(t *testing.T) {
	store := newTestDAOStore(t)
	cred := testCredential("GitHub", "github.com")
	require.NoError(t, store.Add(cred))

	got, err := store.Get("GitHub")
	require.NoError(t, err)
	assert.Equal(t, cred.Name, got.Name)
	assert.Equal(t, cred.Issuer, got.Issuer)
}

func TestDAOStore_Get_ByNameCaseInsensitive(t *testing.T) {
	store := newTestDAOStore(t)
	cred := testCredential("GitHub", "github.com")
	require.NoError(t, store.Add(cred))

	got, err := store.Get("github")
	require.NoError(t, err)
	assert.Equal(t, cred.Name, got.Name)
}

func TestDAOStore_Get_ByCredentialID(t *testing.T) {
	store := newTestDAOStore(t)
	cred := testCredential("GitHub", "github.com")
	require.NoError(t, store.Add(cred))

	got, err := store.Get(cred.ID)
	require.NoError(t, err)
	assert.Equal(t, cred.Name, got.Name)
}

func TestDAOStore_Get_NotFound(t *testing.T) {
	store := newTestDAOStore(t)

	got, err := store.Get("nonexistent")
	require.ErrorIs(t, err, ErrCredentialNotFound)
	assert.Nil(t, got)
}

func TestDAOStore_Get_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	got, err := store.Get("GitHub")
	require.ErrorIs(t, err, ErrStoreClosed)
	assert.Nil(t, got)
}

// --- List tests ---

func TestDAOStore_List_Multiple(t *testing.T) {
	store := newTestDAOStore(t)

	require.NoError(t, store.Add(testCredential("Zebra", "zebra.com")))
	require.NoError(t, store.Add(testCredential("Alpha", "alpha.com")))
	require.NoError(t, store.Add(testCredential("Middle", "middle.com")))

	creds, err := store.List()
	require.NoError(t, err)
	require.Len(t, creds, 3)

	// Sorted case-insensitively by name.
	assert.Equal(t, "Alpha", creds[0].Name)
	assert.Equal(t, "Middle", creds[1].Name)
	assert.Equal(t, "Zebra", creds[2].Name)
}

func TestDAOStore_List_Empty(t *testing.T) {
	store := newTestDAOStore(t)

	creds, err := store.List()
	require.NoError(t, err)
	assert.Empty(t, creds)
}

func TestDAOStore_List_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	creds, err := store.List()
	require.ErrorIs(t, err, ErrStoreClosed)
	assert.Nil(t, creds)
}

// --- Update tests ---

func TestDAOStore_Update_Success(t *testing.T) {
	store := newTestDAOStore(t)
	cred := testCredential("GitHub", "github.com")
	require.NoError(t, store.Add(cred))

	// Update the algorithm.
	cred.Algorithm = AlgorithmSHA256
	err := store.Update(cred)
	require.NoError(t, err)

	got, err := store.Get("GitHub")
	require.NoError(t, err)
	assert.Equal(t, AlgorithmSHA256, got.Algorithm)
}

func TestDAOStore_Update_NotFound(t *testing.T) {
	store := newTestDAOStore(t)
	cred := testCredential("Nonexistent", "example.com")

	err := store.Update(cred)
	require.ErrorIs(t, err, ErrCredentialNotFound)
}

func TestDAOStore_Update_InvalidCredential(t *testing.T) {
	store := newTestDAOStore(t)
	cred := &Credential{ID: "test", Name: "", Secret: "JBSWY3DPEHPK3PXP", Type: TypeTOTP}

	err := store.Update(cred)
	require.Error(t, err)
}

func TestDAOStore_Update_NameCollision(t *testing.T) {
	store := newTestDAOStore(t)

	cred1 := testCredential("GitHub", "github.com")
	require.NoError(t, store.Add(cred1))

	cred2 := testCredential("AWS", "aws.com")
	require.NoError(t, store.Add(cred2))

	// Try to rename AWS to GitHub.
	cred2.Name = "GitHub"
	err := store.Update(cred2)
	require.ErrorIs(t, err, ErrCredentialExists)
}

func TestDAOStore_Update_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	err := store.Update(testCredential("GitHub", "github.com"))
	require.ErrorIs(t, err, ErrStoreClosed)
}

// --- Delete tests ---

func TestDAOStore_Delete_ByName(t *testing.T) {
	store := newTestDAOStore(t)
	cred := testCredential("GitHub", "github.com")
	require.NoError(t, store.Add(cred))

	err := store.Delete("GitHub")
	require.NoError(t, err)

	// Verify it is gone.
	got, err := store.Get("GitHub")
	require.ErrorIs(t, err, ErrCredentialNotFound)
	assert.Nil(t, got)
}

func TestDAOStore_Delete_ByCredentialID(t *testing.T) {
	store := newTestDAOStore(t)
	cred := testCredential("GitHub", "github.com")
	require.NoError(t, store.Add(cred))

	err := store.Delete(cred.ID)
	require.NoError(t, err)

	got, err := store.Get(cred.Name)
	require.ErrorIs(t, err, ErrCredentialNotFound)
	assert.Nil(t, got)
}

func TestDAOStore_Delete_NotFound(t *testing.T) {
	store := newTestDAOStore(t)

	err := store.Delete("nonexistent")
	require.ErrorIs(t, err, ErrCredentialNotFound)
}

func TestDAOStore_Delete_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	err := store.Delete("GitHub")
	require.ErrorIs(t, err, ErrStoreClosed)
}

// --- Page tests ---

func TestDAOStore_Page_Pagination(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	// Add 5 credentials.
	for i := 0; i < 5; i++ {
		name := string(rune('A'+i)) + "-Service"
		cred := testCredential(name, name+".com")
		require.NoError(t, store.Add(cred))
	}

	// Page 1 with size 2.
	result, err := store.Page(ctx, dao.PageQuery{Page: 1, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result.Entities, 2)
	assert.Equal(t, 5, result.Total)
	assert.True(t, result.HasMore)
	assert.Equal(t, 1, result.Page)
	assert.Equal(t, 2, result.PageSize)

	// Page 3 (last page with 1 entry).
	result3, err := store.Page(ctx, dao.PageQuery{Page: 3, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result3.Entities, 1)
	assert.False(t, result3.HasMore)
}

func TestDAOStore_Page_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	_, err := store.Page(context.Background(), dao.PageQuery{Page: 1, PageSize: 10})
	require.ErrorIs(t, err, ErrStoreClosed)
}

// --- Close tests ---

func TestDAOStore_Close_Idempotent(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
}

// --- Concurrency tests ---

func TestDAOStore_Concurrency(t *testing.T) {
	store := newTestDAOStore(t)

	const goroutines = 30
	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	// Concurrent adds (different names to avoid collisions).
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			name := string(rune('A'+idx%26)) + "-Svc-" + string(rune('0'+idx/26))
			_ = store.Add(testCredential(name, name+".com"))
		}(i)
	}

	// Concurrent gets.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = store.Get("A-Svc-0")
		}()
	}

	// Concurrent lists.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = store.List()
		}()
	}

	wg.Wait()
}

// --- Converter round-trip tests ---

func TestDAOStore_ConverterRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	cred := &Credential{
		ID:          "github.com:user@example.com",
		Name:        "GitHub (user@example.com)",
		Issuer:      "github.com",
		AccountName: "user@example.com",
		Secret:      "JBSWY3DPEHPK3PXP",
		Type:        TypeTOTP,
		Algorithm:   AlgorithmSHA256,
		Digits:      8,
		Period:      60,
		Counter:     0,
		BackendID:   "software",
		CreatedAt:   now,
	}

	entity := credentialToEntity(cred)
	assert.Equal(t, cred.Name, entity.Name)
	assert.Equal(t, cred.Issuer, entity.Issuer)
	assert.Equal(t, cred.AccountName, entity.AccountName)
	assert.Equal(t, cred.Secret, entity.Secret)
	assert.Equal(t, cred.Type, entity.Type)
	assert.Equal(t, cred.Algorithm, entity.Algorithm)
	assert.Equal(t, cred.Digits, entity.Digits)
	assert.Equal(t, cred.Period, entity.Period)
	assert.Equal(t, cred.BackendID, entity.BackendID)

	restored := entityToCredential(entity)
	assert.Equal(t, cred.Name, restored.Name)
	assert.Equal(t, cred.Issuer, restored.Issuer)
	assert.Equal(t, cred.AccountName, restored.AccountName)
	assert.Equal(t, cred.Secret, restored.Secret)
	assert.Equal(t, cred.Type, restored.Type)
	assert.Equal(t, cred.Algorithm, restored.Algorithm)
	assert.Equal(t, cred.Digits, restored.Digits)
	assert.Equal(t, cred.Period, restored.Period)
	assert.Equal(t, cred.BackendID, restored.BackendID)

	// ID is regenerated from issuer:account.
	assert.Equal(t, generateCredentialID(cred.Issuer, cred.AccountName), restored.ID)
}

// --- Migration tests ---

func TestDAOStore_MigrateFromBackend_Success(t *testing.T) {
	// Set up legacy backend store.
	legacyBackend := storage.NewMemory()
	t.Cleanup(func() { legacyBackend.Close() })

	legacyStore, err := NewBackendStore(legacyBackend, "oath/")
	require.NoError(t, err)

	cred1 := testCredential("GitHub", "github.com")
	cred2 := testCredential("AWS", "aws.com")
	require.NoError(t, legacyStore.Add(cred1))
	require.NoError(t, legacyStore.Add(cred2))

	// Set up DAO store.
	daoStore := newTestDAOStore(t)

	// Migrate.
	ctx := context.Background()
	err = MigrateFromBackend(ctx, legacyBackend, "oath/", daoStore)
	require.NoError(t, err)

	// Verify credentials exist in DAO store.
	got1, err := daoStore.Get("GitHub")
	require.NoError(t, err)
	assert.Equal(t, "GitHub", got1.Name)

	got2, err := daoStore.Get("AWS")
	require.NoError(t, err)
	assert.Equal(t, "AWS", got2.Name)

	// Verify old keys are deleted from legacy backend.
	keys, err := legacyBackend.List(ctx, "oath/")
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestDAOStore_MigrateFromBackend_NilBackend(t *testing.T) {
	daoStore := newTestDAOStore(t)
	err := MigrateFromBackend(context.Background(), nil, "oath/", daoStore)
	require.ErrorIs(t, err, ErrNilBackend)
}

func TestDAOStore_MigrateFromBackend_NilDAOStore(t *testing.T) {
	backend := storage.NewMemory()
	t.Cleanup(func() { backend.Close() })

	err := MigrateFromBackend(context.Background(), backend, "oath/", nil)
	require.Error(t, err)
}

func TestDAOStore_MigrateFromBackend_Idempotent(t *testing.T) {
	legacyBackend := storage.NewMemory()
	t.Cleanup(func() { legacyBackend.Close() })

	legacyStore, err := NewBackendStore(legacyBackend, "oath/")
	require.NoError(t, err)

	cred := testCredential("GitHub", "github.com")
	require.NoError(t, legacyStore.Add(cred))

	daoStore := newTestDAOStore(t)
	ctx := context.Background()

	// First migration.
	require.NoError(t, MigrateFromBackend(ctx, legacyBackend, "oath/", daoStore))

	// Re-add to legacy to simulate partial migration.
	require.NoError(t, legacyStore.Add(cred))

	// Second migration should skip the duplicate.
	require.NoError(t, MigrateFromBackend(ctx, legacyBackend, "oath/", daoStore))

	// Should still have exactly one credential.
	creds, err := daoStore.List()
	require.NoError(t, err)
	assert.Len(t, creds, 1)
}
