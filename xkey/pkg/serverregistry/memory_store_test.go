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

package serverregistry

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryServerRegistry_New(t *testing.T) {
	reg := NewMemoryServerRegistry()
	require.NotNil(t, reg)
	assert.NotNil(t, reg.servers)
	assert.False(t, reg.closed)
}

func TestMemoryServerRegistry_Register_Success(t *testing.T) {
	reg := NewMemoryServerRegistry()
	defer reg.Close()

	ctx := context.Background()
	entry := &ServerEntry{
		URL:           "https://xkms.example.com:8443",
		Name:          "Production XKMS",
		CAFingerprint: "SHA256:abcdef1234567890",
		Protocol:      ProtocolREST,
	}

	err := reg.Register(ctx, entry)
	require.NoError(t, err)
	assert.False(t, entry.RegisteredAt.IsZero())

	// Verify persistence.
	loaded, err := reg.Lookup(ctx, entry.URL)
	require.NoError(t, err)
	assert.Equal(t, entry.URL, loaded.URL)
	assert.Equal(t, entry.Name, loaded.Name)
	assert.Equal(t, entry.CAFingerprint, loaded.CAFingerprint)
	assert.Equal(t, entry.Protocol, loaded.Protocol)
}

func TestMemoryServerRegistry_Register_NilEntry(t *testing.T) {
	reg := NewMemoryServerRegistry()
	defer reg.Close()

	err := reg.Register(context.Background(), nil)
	require.ErrorIs(t, err, ErrNilEntry)
}

func TestMemoryServerRegistry_Register_EmptyURL(t *testing.T) {
	reg := NewMemoryServerRegistry()
	defer reg.Close()

	entry := &ServerEntry{URL: "", Name: "No URL"}
	err := reg.Register(context.Background(), entry)
	require.ErrorIs(t, err, ErrInvalidURL)
}

func TestMemoryServerRegistry_Register_Duplicate(t *testing.T) {
	reg := NewMemoryServerRegistry()
	defer reg.Close()

	ctx := context.Background()
	entry := &ServerEntry{
		URL:      "https://xkms.example.com:8443",
		Name:     "Production XKMS",
		Protocol: ProtocolREST,
	}

	require.NoError(t, reg.Register(ctx, entry))

	duplicate := &ServerEntry{
		URL:      "https://xkms.example.com:8443",
		Name:     "Duplicate",
		Protocol: ProtocolGRPC,
	}
	err := reg.Register(ctx, duplicate)
	require.ErrorIs(t, err, ErrServerExists)
}

func TestMemoryServerRegistry_Register_Closed(t *testing.T) {
	reg := NewMemoryServerRegistry()
	require.NoError(t, reg.Close())

	entry := &ServerEntry{
		URL:      "https://xkms.example.com:8443",
		Name:     "Production XKMS",
		Protocol: ProtocolREST,
	}
	err := reg.Register(context.Background(), entry)
	require.ErrorIs(t, err, ErrStoreClosed)
}

func TestMemoryServerRegistry_Lookup_Success(t *testing.T) {
	reg := NewMemoryServerRegistry()
	defer reg.Close()

	ctx := context.Background()
	entry := &ServerEntry{
		URL:           "https://xkms.example.com:8443",
		Name:          "Production XKMS",
		CAFingerprint: "SHA256:abcdef1234567890",
		Protocol:      ProtocolGRPC,
	}
	require.NoError(t, reg.Register(ctx, entry))

	loaded, err := reg.Lookup(ctx, entry.URL)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, "https://xkms.example.com:8443", loaded.URL)
	assert.Equal(t, "Production XKMS", loaded.Name)
	assert.Equal(t, "SHA256:abcdef1234567890", loaded.CAFingerprint)
	assert.Equal(t, ProtocolGRPC, loaded.Protocol)
}

func TestMemoryServerRegistry_Lookup_NotFound(t *testing.T) {
	reg := NewMemoryServerRegistry()
	defer reg.Close()

	loaded, err := reg.Lookup(context.Background(), "https://nonexistent.example.com")
	require.ErrorIs(t, err, ErrServerNotFound)
	assert.Nil(t, loaded)
}

func TestMemoryServerRegistry_Lookup_EmptyURL(t *testing.T) {
	reg := NewMemoryServerRegistry()
	defer reg.Close()

	loaded, err := reg.Lookup(context.Background(), "")
	require.ErrorIs(t, err, ErrInvalidURL)
	assert.Nil(t, loaded)
}

func TestMemoryServerRegistry_Lookup_Closed(t *testing.T) {
	reg := NewMemoryServerRegistry()
	require.NoError(t, reg.Close())

	loaded, err := reg.Lookup(context.Background(), "https://xkms.example.com:8443")
	require.ErrorIs(t, err, ErrStoreClosed)
	assert.Nil(t, loaded)
}

func TestMemoryServerRegistry_Lookup_ReturnsCopy(t *testing.T) {
	reg := NewMemoryServerRegistry()
	defer reg.Close()

	ctx := context.Background()
	entry := &ServerEntry{
		URL:      "https://xkms.example.com:8443",
		Name:     "Original",
		Protocol: ProtocolREST,
	}
	require.NoError(t, reg.Register(ctx, entry))

	loaded, err := reg.Lookup(ctx, entry.URL)
	require.NoError(t, err)

	// Mutating the returned copy should not affect the stored entry.
	loaded.Name = "Mutated"

	reloaded, err := reg.Lookup(ctx, entry.URL)
	require.NoError(t, err)
	assert.Equal(t, "Original", reloaded.Name)
}

func TestMemoryServerRegistry_Update_Success(t *testing.T) {
	reg := NewMemoryServerRegistry()
	defer reg.Close()

	ctx := context.Background()
	entry := &ServerEntry{
		URL:           "https://xkms.example.com:8443",
		Name:          "Production XKMS",
		CAFingerprint: "SHA256:original",
		Protocol:      ProtocolREST,
	}
	require.NoError(t, reg.Register(ctx, entry))

	// Update with new values.
	entry.Name = "Updated XKMS"
	entry.CAFingerprint = "SHA256:updated"
	err := reg.Update(ctx, entry)
	require.NoError(t, err)
	assert.False(t, entry.LastConnectedAt.IsZero())

	// Verify the update was persisted.
	loaded, err := reg.Lookup(ctx, entry.URL)
	require.NoError(t, err)
	assert.Equal(t, "Updated XKMS", loaded.Name)
	assert.Equal(t, "SHA256:updated", loaded.CAFingerprint)
	assert.False(t, loaded.LastConnectedAt.IsZero())
}

func TestMemoryServerRegistry_Update_NotFound(t *testing.T) {
	reg := NewMemoryServerRegistry()
	defer reg.Close()

	entry := &ServerEntry{
		URL:  "https://nonexistent.example.com",
		Name: "Ghost Server",
	}
	err := reg.Update(context.Background(), entry)
	require.ErrorIs(t, err, ErrServerNotFound)
}

func TestMemoryServerRegistry_Update_NilEntry(t *testing.T) {
	reg := NewMemoryServerRegistry()
	defer reg.Close()

	err := reg.Update(context.Background(), nil)
	require.ErrorIs(t, err, ErrNilEntry)
}

func TestMemoryServerRegistry_Update_EmptyURL(t *testing.T) {
	reg := NewMemoryServerRegistry()
	defer reg.Close()

	entry := &ServerEntry{URL: "", Name: "No URL"}
	err := reg.Update(context.Background(), entry)
	require.ErrorIs(t, err, ErrInvalidURL)
}

func TestMemoryServerRegistry_Update_Closed(t *testing.T) {
	reg := NewMemoryServerRegistry()
	require.NoError(t, reg.Close())

	entry := &ServerEntry{
		URL:      "https://xkms.example.com:8443",
		Name:     "Production XKMS",
		Protocol: ProtocolREST,
	}
	err := reg.Update(context.Background(), entry)
	require.ErrorIs(t, err, ErrStoreClosed)
}

func TestMemoryServerRegistry_Delete_Success(t *testing.T) {
	reg := NewMemoryServerRegistry()
	defer reg.Close()

	ctx := context.Background()
	entry := &ServerEntry{
		URL:      "https://xkms.example.com:8443",
		Name:     "Production XKMS",
		Protocol: ProtocolREST,
	}
	require.NoError(t, reg.Register(ctx, entry))

	err := reg.Delete(ctx, entry.URL)
	require.NoError(t, err)

	// Verify the entry is no longer loadable.
	loaded, err := reg.Lookup(ctx, entry.URL)
	require.ErrorIs(t, err, ErrServerNotFound)
	assert.Nil(t, loaded)
}

func TestMemoryServerRegistry_Delete_NotFound(t *testing.T) {
	reg := NewMemoryServerRegistry()
	defer reg.Close()

	err := reg.Delete(context.Background(), "https://nonexistent.example.com")
	require.ErrorIs(t, err, ErrServerNotFound)
}

func TestMemoryServerRegistry_Delete_EmptyURL(t *testing.T) {
	reg := NewMemoryServerRegistry()
	defer reg.Close()

	err := reg.Delete(context.Background(), "")
	require.ErrorIs(t, err, ErrInvalidURL)
}

func TestMemoryServerRegistry_Delete_Closed(t *testing.T) {
	reg := NewMemoryServerRegistry()
	require.NoError(t, reg.Close())

	err := reg.Delete(context.Background(), "https://xkms.example.com:8443")
	require.ErrorIs(t, err, ErrStoreClosed)
}

func TestMemoryServerRegistry_List_Empty(t *testing.T) {
	reg := NewMemoryServerRegistry()
	defer reg.Close()

	entries, err := reg.List(context.Background())
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestMemoryServerRegistry_List_MultipleEntries_Sorted(t *testing.T) {
	reg := NewMemoryServerRegistry()
	defer reg.Close()

	ctx := context.Background()

	// Register entries in non-alphabetical order.
	require.NoError(t, reg.Register(ctx, &ServerEntry{
		URL:      "https://charlie.example.com",
		Name:     "Charlie",
		Protocol: ProtocolMCP,
	}))
	require.NoError(t, reg.Register(ctx, &ServerEntry{
		URL:      "https://alpha.example.com",
		Name:     "Alpha",
		Protocol: ProtocolREST,
	}))
	require.NoError(t, reg.Register(ctx, &ServerEntry{
		URL:      "https://bravo.example.com",
		Name:     "Bravo",
		Protocol: ProtocolQUIC,
	}))

	entries, err := reg.List(ctx)
	require.NoError(t, err)
	require.Len(t, entries, 3)

	// Verify sorted by URL.
	assert.Equal(t, "https://alpha.example.com", entries[0].URL)
	assert.Equal(t, "https://bravo.example.com", entries[1].URL)
	assert.Equal(t, "https://charlie.example.com", entries[2].URL)
}

func TestMemoryServerRegistry_List_Closed(t *testing.T) {
	reg := NewMemoryServerRegistry()
	require.NoError(t, reg.Close())

	entries, err := reg.List(context.Background())
	require.ErrorIs(t, err, ErrStoreClosed)
	assert.Nil(t, entries)
}

func TestMemoryServerRegistry_Close_Idempotent(t *testing.T) {
	reg := NewMemoryServerRegistry()

	require.NoError(t, reg.Close())
	require.NoError(t, reg.Close())
	require.NoError(t, reg.Close())
}

func TestMemoryServerRegistry_ImplementsInterface(t *testing.T) {
	reg := NewMemoryServerRegistry()
	defer reg.Close()

	var _ ServerRegistry = reg
}

func TestMemoryServerRegistry_Concurrency(t *testing.T) {
	reg := NewMemoryServerRegistry()
	defer reg.Close()

	ctx := context.Background()

	// Seed one entry so lookups and updates have something to hit.
	require.NoError(t, reg.Register(ctx, &ServerEntry{
		URL:      "https://shared.example.com",
		Name:     "Shared",
		Protocol: ProtocolREST,
	}))

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	// Concurrent registers (different URLs to avoid ErrServerExists).
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			entry := &ServerEntry{
				URL:      "https://concurrent-" + string(rune('A'+idx%26)) + ".example.com",
				Name:     "Concurrent Server",
				Protocol: ProtocolGRPC,
			}
			_ = reg.Register(ctx, entry)
		}(i)
	}

	// Concurrent lookups.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = reg.Lookup(ctx, "https://shared.example.com")
		}()
	}

	// Concurrent lists.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = reg.List(ctx)
		}()
	}

	wg.Wait()

	// After all goroutines complete, the registry should be in a consistent state.
	loaded, err := reg.Lookup(ctx, "https://shared.example.com")
	require.NoError(t, err)
	assert.Equal(t, "Shared", loaded.Name)
}

func TestMemoryServerRegistry_RegisteredAt_SetAutomatically(t *testing.T) {
	reg := NewMemoryServerRegistry()
	defer reg.Close()

	ctx := context.Background()
	entry := &ServerEntry{
		URL:      "https://xkms.example.com:8443",
		Name:     "Production XKMS",
		Protocol: ProtocolREST,
	}

	assert.True(t, entry.RegisteredAt.IsZero())

	require.NoError(t, reg.Register(ctx, entry))
	assert.False(t, entry.RegisteredAt.IsZero())

	loaded, err := reg.Lookup(ctx, entry.URL)
	require.NoError(t, err)
	assert.False(t, loaded.RegisteredAt.IsZero())
}

func TestMemoryServerRegistry_Update_SetsLastConnectedAt(t *testing.T) {
	reg := NewMemoryServerRegistry()
	defer reg.Close()

	ctx := context.Background()
	entry := &ServerEntry{
		URL:      "https://xkms.example.com:8443",
		Name:     "Production XKMS",
		Protocol: ProtocolREST,
	}
	require.NoError(t, reg.Register(ctx, entry))

	// LastConnectedAt should be zero after registration.
	loaded, err := reg.Lookup(ctx, entry.URL)
	require.NoError(t, err)
	assert.True(t, loaded.LastConnectedAt.IsZero())

	// After update, LastConnectedAt should be set.
	require.NoError(t, reg.Update(ctx, entry))

	loaded, err = reg.Lookup(ctx, entry.URL)
	require.NoError(t, err)
	assert.False(t, loaded.LastConnectedAt.IsZero())
}
