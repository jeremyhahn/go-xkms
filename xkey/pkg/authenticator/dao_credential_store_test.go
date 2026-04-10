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

package authenticator

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-qrdb/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestDAOCredentialStore creates a DAOCredentialStore backed by in-memory storage.
func newTestDAOCredentialStore(t *testing.T) *DAOCredentialStore {
	t.Helper()
	backend := storage.NewMemory()
	t.Cleanup(func() { backend.Close() })

	kvStore, err := kvadapter.New(backend)
	require.NoError(t, err)

	store, err := NewDAOCredentialStore(kvStore)
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	return store
}

// testCredential returns a StoredCredential with all fields populated.
func testCredential(rpID string, discoverable bool) *StoredCredential {
	credID := make([]byte, 32)
	_, _ = rand.Read(credID)

	userID := make([]byte, 16)
	_, _ = rand.Read(userID)

	privKey := make([]byte, 64) // Simulated PKCS8 DER bytes
	_, _ = rand.Read(privKey)

	pubKeyCOSE := make([]byte, 77) // Simulated COSE public key
	_, _ = rand.Read(pubKeyCOSE)

	hmacKey := make([]byte, 32)
	_, _ = rand.Read(hmacKey)

	return &StoredCredential{
		CredentialID:    credID,
		RPID:            rpID,
		RPName:          rpID + " Inc.",
		UserID:          userID,
		UserName:        "alice@" + rpID,
		UserDisplayName: "Alice Smith",
		PrivateKey:      privKey,
		PublicKeyCOSE:   pubKeyCOSE,
		Algorithm:       COSEAlgES256,
		SignCount:       5,
		CreatedAt:       time.Now().Unix(),
		Discoverable:    discoverable,
		CredProtect:     CredProtectUserVerificationOptional,
		HMACSecretKey:   hmacKey,
		BackendID:       "software",
	}
}

func TestDAOCredentialStore_NewNilKVStore(t *testing.T) {
	store, err := NewDAOCredentialStore(nil)
	require.ErrorIs(t, err, ErrNilStorage)
	assert.Nil(t, store)
}

func TestDAOCredentialStore_StoreLoad_RoundTrip(t *testing.T) {
	store := newTestDAOCredentialStore(t)

	cred := testCredential("example.com", true)
	require.NoError(t, store.Store(cred))

	loaded, err := store.Load(cred.CredentialID)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	// Verify all fields survived the round-trip.
	assert.True(t, bytes.Equal(cred.CredentialID, loaded.CredentialID))
	assert.Equal(t, cred.RPID, loaded.RPID)
	assert.Equal(t, cred.RPName, loaded.RPName)
	assert.True(t, bytes.Equal(cred.UserID, loaded.UserID))
	assert.Equal(t, cred.UserName, loaded.UserName)
	assert.Equal(t, cred.UserDisplayName, loaded.UserDisplayName)
	assert.True(t, bytes.Equal(cred.PrivateKey, loaded.PrivateKey))
	assert.True(t, bytes.Equal(cred.PublicKeyCOSE, loaded.PublicKeyCOSE))
	assert.Equal(t, cred.Algorithm, loaded.Algorithm)
	assert.Equal(t, cred.SignCount, loaded.SignCount)
	assert.Equal(t, cred.CreatedAt, loaded.CreatedAt)
	assert.Equal(t, cred.Discoverable, loaded.Discoverable)
	assert.Equal(t, cred.CredProtect, loaded.CredProtect)
	assert.True(t, bytes.Equal(cred.HMACSecretKey, loaded.HMACSecretKey))
	assert.Equal(t, cred.BackendID, loaded.BackendID)
}

func TestDAOCredentialStore_Store_InvalidCredentialID(t *testing.T) {
	store := newTestDAOCredentialStore(t)

	// Nil credential.
	err := store.Store(nil)
	require.ErrorIs(t, err, ErrInvalidCredentialID)

	// Empty credential ID.
	cred := testCredential("example.com", false)
	cred.CredentialID = nil
	err = store.Store(cred)
	require.ErrorIs(t, err, ErrInvalidCredentialID)

	// Zero-length credential ID.
	cred.CredentialID = []byte{}
	err = store.Store(cred)
	require.ErrorIs(t, err, ErrInvalidCredentialID)
}

func TestDAOCredentialStore_Store_Closed(t *testing.T) {
	store := newTestDAOCredentialStore(t)
	require.NoError(t, store.Close())

	err := store.Store(testCredential("example.com", false))
	require.ErrorIs(t, err, ErrStorageClosed)
}

func TestDAOCredentialStore_Store_Upsert(t *testing.T) {
	store := newTestDAOCredentialStore(t)

	cred := testCredential("example.com", false)
	require.NoError(t, store.Store(cred))

	// Update sign count.
	cred.SignCount = 42
	require.NoError(t, store.Store(cred))

	loaded, err := store.Load(cred.CredentialID)
	require.NoError(t, err)
	assert.Equal(t, uint32(42), loaded.SignCount)

	// Count should still be 1.
	count, err := store.Count()
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestDAOCredentialStore_Load_NotFound(t *testing.T) {
	store := newTestDAOCredentialStore(t)

	loaded, err := store.Load([]byte{0xde, 0xad, 0xbe, 0xef})
	require.ErrorIs(t, err, ErrCredentialNotFound)
	assert.Nil(t, loaded)
}

func TestDAOCredentialStore_Load_InvalidCredentialID(t *testing.T) {
	store := newTestDAOCredentialStore(t)

	loaded, err := store.Load(nil)
	require.ErrorIs(t, err, ErrInvalidCredentialID)
	assert.Nil(t, loaded)

	loaded, err = store.Load([]byte{})
	require.ErrorIs(t, err, ErrInvalidCredentialID)
	assert.Nil(t, loaded)
}

func TestDAOCredentialStore_Load_Closed(t *testing.T) {
	store := newTestDAOCredentialStore(t)
	require.NoError(t, store.Close())

	loaded, err := store.Load([]byte{0x01})
	require.ErrorIs(t, err, ErrStorageClosed)
	assert.Nil(t, loaded)
}

func TestDAOCredentialStore_LoadByRPID(t *testing.T) {
	store := newTestDAOCredentialStore(t)

	// Store credentials for two different RPs.
	cred1 := testCredential("example.com", true)
	cred2 := testCredential("example.com", false)
	cred3 := testCredential("other.com", true)

	require.NoError(t, store.Store(cred1))
	require.NoError(t, store.Store(cred2))
	require.NoError(t, store.Store(cred3))

	// Load by RPID.
	result, err := store.LoadByRPID("example.com")
	require.NoError(t, err)
	assert.Len(t, result, 2)

	// All results should have the correct RPID.
	for _, cred := range result {
		assert.Equal(t, "example.com", cred.RPID)
	}

	// Load for other RP.
	result, err = store.LoadByRPID("other.com")
	require.NoError(t, err)
	assert.Len(t, result, 1)

	// Load for non-existent RP.
	result, err = store.LoadByRPID("nonexistent.com")
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestDAOCredentialStore_LoadByRPID_EmptyRPID(t *testing.T) {
	store := newTestDAOCredentialStore(t)

	result, err := store.LoadByRPID("")
	require.ErrorIs(t, err, ErrInvalidRPIDEmpty)
	assert.Nil(t, result)
}

func TestDAOCredentialStore_LoadByRPID_Closed(t *testing.T) {
	store := newTestDAOCredentialStore(t)
	require.NoError(t, store.Close())

	result, err := store.LoadByRPID("example.com")
	require.ErrorIs(t, err, ErrStorageClosed)
	assert.Nil(t, result)
}

func TestDAOCredentialStore_Delete(t *testing.T) {
	store := newTestDAOCredentialStore(t)

	cred := testCredential("example.com", false)
	require.NoError(t, store.Store(cred))

	// Delete.
	err := store.Delete(cred.CredentialID)
	require.NoError(t, err)

	// Verify gone.
	loaded, err := store.Load(cred.CredentialID)
	require.ErrorIs(t, err, ErrCredentialNotFound)
	assert.Nil(t, loaded)
}

func TestDAOCredentialStore_Delete_NotFound(t *testing.T) {
	store := newTestDAOCredentialStore(t)

	err := store.Delete([]byte{0xde, 0xad})
	require.ErrorIs(t, err, ErrCredentialNotFound)
}

func TestDAOCredentialStore_Delete_InvalidCredentialID(t *testing.T) {
	store := newTestDAOCredentialStore(t)

	err := store.Delete(nil)
	require.ErrorIs(t, err, ErrInvalidCredentialID)

	err = store.Delete([]byte{})
	require.ErrorIs(t, err, ErrInvalidCredentialID)
}

func TestDAOCredentialStore_Delete_Closed(t *testing.T) {
	store := newTestDAOCredentialStore(t)
	require.NoError(t, store.Close())

	err := store.Delete([]byte{0x01})
	require.ErrorIs(t, err, ErrStorageClosed)
}

func TestDAOCredentialStore_Count(t *testing.T) {
	store := newTestDAOCredentialStore(t)

	count, err := store.Count()
	require.NoError(t, err)
	assert.Equal(t, 0, count)

	require.NoError(t, store.Store(testCredential("a.com", false)))
	require.NoError(t, store.Store(testCredential("b.com", true)))
	require.NoError(t, store.Store(testCredential("c.com", false)))

	count, err = store.Count()
	require.NoError(t, err)
	assert.Equal(t, 3, count)
}

func TestDAOCredentialStore_Count_Closed(t *testing.T) {
	store := newTestDAOCredentialStore(t)
	require.NoError(t, store.Close())

	count, err := store.Count()
	require.ErrorIs(t, err, ErrStorageClosed)
	assert.Equal(t, 0, count)
}

func TestDAOCredentialStore_CountDiscoverable(t *testing.T) {
	store := newTestDAOCredentialStore(t)

	require.NoError(t, store.Store(testCredential("a.com", true)))
	require.NoError(t, store.Store(testCredential("b.com", false)))
	require.NoError(t, store.Store(testCredential("c.com", true)))
	require.NoError(t, store.Store(testCredential("d.com", false)))

	count, err := store.CountDiscoverable()
	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestDAOCredentialStore_CountDiscoverable_Closed(t *testing.T) {
	store := newTestDAOCredentialStore(t)
	require.NoError(t, store.Close())

	count, err := store.CountDiscoverable()
	require.ErrorIs(t, err, ErrStorageClosed)
	assert.Equal(t, 0, count)
}

func TestDAOCredentialStore_EnumerateDiscoverable(t *testing.T) {
	store := newTestDAOCredentialStore(t)

	cred1 := testCredential("a.com", true)
	cred2 := testCredential("b.com", false)
	cred3 := testCredential("c.com", true)

	require.NoError(t, store.Store(cred1))
	require.NoError(t, store.Store(cred2))
	require.NoError(t, store.Store(cred3))

	result, err := store.EnumerateDiscoverable()
	require.NoError(t, err)
	assert.Len(t, result, 2)

	for _, cred := range result {
		assert.True(t, cred.Discoverable)
	}
}

func TestDAOCredentialStore_EnumerateDiscoverable_Closed(t *testing.T) {
	store := newTestDAOCredentialStore(t)
	require.NoError(t, store.Close())

	result, err := store.EnumerateDiscoverable()
	require.ErrorIs(t, err, ErrStorageClosed)
	assert.Nil(t, result)
}

func TestDAOCredentialStore_SaveState_LoadState_RoundTrip(t *testing.T) {
	store := newTestDAOCredentialStore(t)

	// Create a state with attestation key.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	attestCert := []byte{0x30, 0x82, 0x01, 0x22} // Simulated DER cert

	original := NewAuthenticatorState()
	original.AAGUID = DefaultAAGUID
	original.PINSet = true
	original.PINHash = []byte("fake-pin-hash-16")
	original.SetPINRetries(5)
	original.SetUVRetries(2)
	original.AttestationKey = privKey
	original.AttestationCert = attestCert

	// Save state.
	require.NoError(t, store.SaveState(original))

	// Load state.
	loaded, err := store.LoadState()
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, original.AAGUID, loaded.AAGUID)
	assert.Equal(t, original.PINSet, loaded.PINSet)
	assert.True(t, bytes.Equal(original.PINHash, loaded.PINHash))
	assert.Equal(t, 5, loaded.PINRetries())
	assert.Equal(t, 2, loaded.UVRetries())
	assert.True(t, bytes.Equal(original.AttestationCert, loaded.AttestationCert))

	// Verify attestation key survived round-trip.
	require.NotNil(t, loaded.AttestationKey)

	originalDER, err := x509.MarshalPKCS8PrivateKey(original.AttestationKey)
	require.NoError(t, err)
	loadedDER, err := x509.MarshalPKCS8PrivateKey(loaded.AttestationKey)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(originalDER, loadedDER))
}

func TestDAOCredentialStore_SaveState_NilState(t *testing.T) {
	store := newTestDAOCredentialStore(t)

	err := store.SaveState(nil)
	require.ErrorIs(t, err, ErrInvalidParameter)
}

func TestDAOCredentialStore_SaveState_Closed(t *testing.T) {
	store := newTestDAOCredentialStore(t)
	require.NoError(t, store.Close())

	err := store.SaveState(NewAuthenticatorState())
	require.ErrorIs(t, err, ErrStorageClosed)
}

func TestDAOCredentialStore_LoadState_NotFound(t *testing.T) {
	store := newTestDAOCredentialStore(t)

	loaded, err := store.LoadState()
	require.ErrorIs(t, err, ErrStateNotFound)
	assert.Nil(t, loaded)
}

func TestDAOCredentialStore_LoadState_Closed(t *testing.T) {
	store := newTestDAOCredentialStore(t)
	require.NoError(t, store.Close())

	loaded, err := store.LoadState()
	require.ErrorIs(t, err, ErrStorageClosed)
	assert.Nil(t, loaded)
}

func TestDAOCredentialStore_Clear(t *testing.T) {
	store := newTestDAOCredentialStore(t)

	require.NoError(t, store.Store(testCredential("a.com", true)))
	require.NoError(t, store.Store(testCredential("b.com", false)))

	count, err := store.Count()
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	require.NoError(t, store.Clear())

	count, err = store.Count()
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestDAOCredentialStore_Clear_Closed(t *testing.T) {
	store := newTestDAOCredentialStore(t)
	require.NoError(t, store.Close())

	err := store.Clear()
	require.ErrorIs(t, err, ErrStorageClosed)
}

func TestDAOCredentialStore_ListAll(t *testing.T) {
	store := newTestDAOCredentialStore(t)

	cred1 := testCredential("a.com", true)
	cred2 := testCredential("b.com", false)

	require.NoError(t, store.Store(cred1))
	require.NoError(t, store.Store(cred2))

	ids, err := store.ListAll()
	require.NoError(t, err)
	assert.Len(t, ids, 2)

	// Verify the credential IDs are in the list.
	found1, found2 := false, false
	for _, id := range ids {
		if hex.EncodeToString(id) == hex.EncodeToString(cred1.CredentialID) {
			found1 = true
		}
		if hex.EncodeToString(id) == hex.EncodeToString(cred2.CredentialID) {
			found2 = true
		}
	}
	assert.True(t, found1, "cred1 not found in ListAll")
	assert.True(t, found2, "cred2 not found in ListAll")
}

func TestDAOCredentialStore_ListAll_Closed(t *testing.T) {
	store := newTestDAOCredentialStore(t)
	require.NoError(t, store.Close())

	ids, err := store.ListAll()
	require.ErrorIs(t, err, ErrStorageClosed)
	assert.Nil(t, ids)
}

func TestDAOCredentialStore_Page(t *testing.T) {
	store := newTestDAOCredentialStore(t)

	// Store 5 credentials.
	for i := 0; i < 5; i++ {
		require.NoError(t, store.Store(testCredential(fmt.Sprintf("rp-%02d.com", i), i%2 == 0)))
	}

	// Page with size 2.
	result, err := store.Page(context.Background(), dao.PageQuery{Page: 1, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result.Entities, 2)
	assert.Equal(t, 5, result.Total)
	assert.True(t, result.HasMore)

	// Last page.
	result3, err := store.Page(context.Background(), dao.PageQuery{Page: 3, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result3.Entities, 1)
	assert.False(t, result3.HasMore)
}

func TestDAOCredentialStore_Page_Closed(t *testing.T) {
	store := newTestDAOCredentialStore(t)
	require.NoError(t, store.Close())

	_, err := store.Page(context.Background(), dao.PageQuery{Page: 1, PageSize: 10})
	require.ErrorIs(t, err, ErrStorageClosed)
}

func TestDAOCredentialStore_Close_Idempotent(t *testing.T) {
	store := newTestDAOCredentialStore(t)
	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
}

func TestDAOCredentialStore_ImplementsInterfaces(t *testing.T) {
	store := newTestDAOCredentialStore(t)
	var _ StatefulCredentialStorage = store
	var _ CredentialStorage = store
	var _ ClearableStorage = store
	var _ ListableStorage = store
	var _ CredentialEnumerator = store
}

func TestDAOCredentialStore_EmptyOptionalFields(t *testing.T) {
	store := newTestDAOCredentialStore(t)

	// Store a credential with no optional binary fields.
	cred := &StoredCredential{
		CredentialID: []byte{0x01, 0x02, 0x03},
		RPID:         "minimal.com",
		Algorithm:    COSEAlgES256,
		CreatedAt:    time.Now().Unix(),
	}

	require.NoError(t, store.Store(cred))

	loaded, err := store.Load(cred.CredentialID)
	require.NoError(t, err)

	assert.Equal(t, "minimal.com", loaded.RPID)
	assert.Nil(t, loaded.UserID)
	assert.Nil(t, loaded.PrivateKey)
	assert.Nil(t, loaded.PublicKeyCOSE)
	assert.Nil(t, loaded.HMACSecretKey)
	assert.Equal(t, "", loaded.BackendID)
}

func TestDAOCredentialStore_Concurrency(t *testing.T) {
	store := newTestDAOCredentialStore(t)

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	// Concurrent stores.
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			_ = store.Store(testCredential(fmt.Sprintf("rp-%d.com", idx), idx%2 == 0))
		}(i)
	}

	// Concurrent loads (may not find anything).
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = store.LoadByRPID("rp-0.com")
		}()
	}

	// Concurrent counts.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = store.Count()
		}()
	}

	wg.Wait()

	// Store should be consistent after concurrent access.
	count, err := store.Count()
	require.NoError(t, err)
	assert.Equal(t, goroutines, count)
}
