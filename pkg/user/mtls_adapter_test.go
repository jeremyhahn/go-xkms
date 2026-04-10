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

package user

import (
	"context"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestMTLSAdapter(t *testing.T) (*MTLSUserStoreAdapter, *FileStore, func()) {
	t.Helper()
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	store, err := NewFileStore(backend, WithCleanupInterval(100*time.Millisecond))
	require.NoError(t, err)

	adapter := NewMTLSUserStoreAdapter(store)
	return adapter, store, func() {
		_ = store.Close()
	}
}

func TestMTLSUserStoreAdapter_GetByCertFingerprint_Success(t *testing.T) {
	adapter, store, cleanup := newTestMTLSAdapter(t)
	defer cleanup()

	ctx := context.Background()

	// Create a user and bind a certificate fingerprint.
	u, err := store.Create(ctx, "alice@example.com", "Alice", RoleOperator, "")
	require.NoError(t, err)

	fingerprint := "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"
	u.AddCertBinding(&CertBinding{
		Fingerprint: fingerprint,
		Subject:     "CN=alice",
		Issuer:      "CN=ca",
		Serial:      "123",
		NotAfter:    time.Now().Add(24 * time.Hour),
		Name:        "alice-cert",
		CreatedAt:   time.Now().UTC(),
	})
	err = store.Update(ctx, u)
	require.NoError(t, err)

	// Look up through the adapter.
	mtlsUser, err := adapter.GetByCertFingerprint(ctx, fingerprint)
	require.NoError(t, err)

	assert.Equal(t, "alice@example.com", mtlsUser.Username)
	assert.Equal(t, "Alice", mtlsUser.DisplayName)
	assert.Equal(t, string(RoleOperator), mtlsUser.Role)
	assert.True(t, mtlsUser.Enabled)
}

func TestMTLSUserStoreAdapter_GetByCertFingerprint_NotFound(t *testing.T) {
	adapter, _, cleanup := newTestMTLSAdapter(t)
	defer cleanup()

	ctx := context.Background()

	_, err := adapter.GetByCertFingerprint(ctx, "nonexistent-fingerprint")
	assert.ErrorIs(t, err, ErrCertBindingNotFound)
}

func TestMTLSUserStoreAdapter_GetByCertFingerprint_DisabledUser(t *testing.T) {
	adapter, store, cleanup := newTestMTLSAdapter(t)
	defer cleanup()

	ctx := context.Background()

	// Create a user, bind a cert, then disable them.
	u, err := store.Create(ctx, "bob@example.com", "Bob", RoleUser, "")
	require.NoError(t, err)

	fingerprint := "ff:ee:dd:cc:bb:aa:99:88:77:66:55:44:33:22:11:00"
	u.AddCertBinding(&CertBinding{
		Fingerprint: fingerprint,
		Subject:     "CN=bob",
		Issuer:      "CN=ca",
		Serial:      "456",
		NotAfter:    time.Now().Add(24 * time.Hour),
		Name:        "bob-cert",
		CreatedAt:   time.Now().UTC(),
	})
	u.Enabled = false
	err = store.Update(ctx, u)
	require.NoError(t, err)

	// The adapter itself returns the user as-is. The mTLS authenticator is
	// responsible for checking the Enabled flag and returning auth.ErrUserDisabled.
	mtlsUser, err := adapter.GetByCertFingerprint(ctx, fingerprint)
	require.NoError(t, err)
	assert.False(t, mtlsUser.Enabled)
}

func TestMTLSUserStoreAdapter_GetByCertFingerprint_EmptyFingerprint(t *testing.T) {
	adapter, _, cleanup := newTestMTLSAdapter(t)
	defer cleanup()

	ctx := context.Background()

	_, err := adapter.GetByCertFingerprint(ctx, "")
	assert.ErrorIs(t, err, ErrCertBindingNotFound)
}

func TestMTLSUserStoreAdapter_ImplementsAuthUserStore(t *testing.T) {
	adapter, _, cleanup := newTestMTLSAdapter(t)
	defer cleanup()

	// Verify the adapter satisfies the auth.UserStore interface at runtime.
	var _ auth.UserStore = adapter
}

func TestMTLSUserStoreAdapter_MultipleBindings(t *testing.T) {
	adapter, store, cleanup := newTestMTLSAdapter(t)
	defer cleanup()

	ctx := context.Background()

	// Create user with multiple certificate bindings.
	u, err := store.Create(ctx, "multi@example.com", "Multi Cert User", RoleAdmin, "")
	require.NoError(t, err)

	fp1 := "11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00"
	fp2 := "00:ff:ee:dd:cc:bb:aa:99:88:77:66:55:44:33:22:11"
	u.AddCertBinding(&CertBinding{
		Fingerprint: fp1,
		Subject:     "CN=multi-1",
		CreatedAt:   time.Now().UTC(),
	})
	u.AddCertBinding(&CertBinding{
		Fingerprint: fp2,
		Subject:     "CN=multi-2",
		CreatedAt:   time.Now().UTC(),
	})
	err = store.Update(ctx, u)
	require.NoError(t, err)

	// Both fingerprints should resolve to the same user.
	result1, err := adapter.GetByCertFingerprint(ctx, fp1)
	require.NoError(t, err)
	assert.Equal(t, "multi@example.com", result1.Username)

	result2, err := adapter.GetByCertFingerprint(ctx, fp2)
	require.NoError(t, err)
	assert.Equal(t, "multi@example.com", result2.Username)
}
