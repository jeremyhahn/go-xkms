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

package storage

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage/qrdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// baseOnlyBackend offers the base Backend surface and nothing else. Embedding
// the INTERFACE is what makes that true: only Backend's own methods are
// promoted, so this type does not satisfy CompareAndSwapper or
// CompareAndDeleter however capable the value inside it is.
type baseOnlyBackend struct {
	Backend
}

// guardedBackend offers the two guarded interfaces and answers the capability
// question either way, so the report can be exercised independently of the
// method set. The operations delegate to the wrapped backend, so a test that
// calls them gets real behaviour.
type guardedBackend struct {
	Backend
	available bool
}

func (g *guardedBackend) GuardedWritesAvailable() bool { return g.available }

func (g *guardedBackend) CompareAndSwap(ctx context.Context, key string, expected, newValue []byte) (bool, []byte, error) {
	return g.Backend.(CompareAndSwapper).CompareAndSwap(ctx, key, expected, newValue)
}

func (g *guardedBackend) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	return g.Backend.(CompareAndDeleter).CompareAndDelete(ctx, key, expected)
}

func TestGuardedWritesAvailable_BackendWithoutAReportIsTakenAtItsWord(t *testing.T) {
	// The engine backend performs its guarded writes in this process and does
	// not implement the reporter. Defaulting it to unavailable would take the
	// capability away from every backend that never had to declare it.
	assert.True(t, GuardedWritesAvailable(NewMemory()))
}

func TestGuardedWritesAvailable_HonoursTheBackendsOwnAnswer(t *testing.T) {
	assert.False(t, GuardedWritesAvailable(&guardedBackend{Backend: NewMemory(), available: false}))
	assert.True(t, GuardedWritesAvailable(&guardedBackend{Backend: NewMemory(), available: true}))
}

// TestGuardedWritesUsable_NeedsBothHalves pins that neither half implies the
// other: a backend that reports itself able but offers no guarded methods has
// nothing to call, and one that offers them but reports itself unable would
// fail on the first write.
func TestGuardedWritesUsable_NeedsBothHalves(t *testing.T) {
	assert.True(t, GuardedWritesUsable(NewMemory()), "declares both and can run them")
	assert.False(t, GuardedWritesUsable(&baseOnlyBackend{Backend: NewMemory()}),
		"an able backend that declares no guarded methods offers nothing to call")
	assert.False(t, GuardedWritesUsable(&guardedBackend{Backend: NewMemory(), available: false}),
		"declared methods that cannot execute are not a usable capability")
}

// TestGuardedWritesAvailable_EmbeddedQRDBBackendsReportUnavailable pins the
// measurement the report is derived from: these constructors build a transport
// with no transaction service, so all three guarded writes fail at run time
// (#125). They declare the methods, which is why the method set cannot be the
// capability test.
func TestGuardedWritesAvailable_EmbeddedQRDBBackendsReportUnavailable(t *testing.T) {
	dir := t.TempDir()

	memory, err := qrdb.NewMemory()
	require.NoError(t, err)
	t.Cleanup(func() { _ = memory.Close() })

	file, err := qrdb.NewFile(filepath.Join(dir, "file"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })

	pebble, err := qrdb.NewPebble(filepath.Join(dir, "pebble"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = pebble.Close() })

	for name, backend := range map[string]Backend{"memory": memory, "file": file, "pebble": pebble} {
		t.Run(name, func(t *testing.T) {
			_, canSwap := backend.(CompareAndSwapper)
			require.True(t, canSwap, "the premise: the method is declared")

			assert.False(t, GuardedWritesAvailable(backend))
		})
	}
}

func TestPrefixBackend_ReportsTheWrappedBackendsAnswer(t *testing.T) {
	unavailable, err := NewPrefixBackend(&guardedBackend{Backend: NewMemory(), available: false}, "tenant")
	require.NoError(t, err)
	assert.False(t, GuardedWritesAvailable(unavailable),
		"a prefixed view of a backend whose guarded writes fail must not read as one whose guarded writes work")

	available, err := NewPrefixBackend(NewMemory(), "tenant")
	require.NoError(t, err)
	assert.True(t, GuardedWritesAvailable(available),
		"prefixing adds no writer, so it neither creates the capability nor removes it")
}

// TestPrefixBackend_ReportsUnavailableOverABackendWithNoGuardedMethods is the
// trap the report exists to close on this type. PrefixBackend declares
// CompareAndSwap and CompareAndDelete unconditionally and answers
// ErrCompareAndSwapUnsupported when the inner backend has neither, so its own
// method set cannot be the capability test — and a caller that trusted it
// would take a store with no guarded writes at all for an atomic one.
func TestPrefixBackend_ReportsUnavailableOverABackendWithNoGuardedMethods(t *testing.T) {
	ctx := context.Background()
	inner := &baseOnlyBackend{Backend: NewMemory()}
	prefixed, err := NewPrefixBackend(inner, "tenant")
	require.NoError(t, err)

	// The premise: PrefixBackend satisfies both interfaces whatever it wraps.
	_, canSwap := Backend(prefixed).(CompareAndSwapper)
	_, canDelete := Backend(prefixed).(CompareAndDeleter)
	require.True(t, canSwap && canDelete, "the premise of this test is that the methods are declared")

	assert.False(t, GuardedWritesAvailable(prefixed))

	// ... and the call really does fail, which is what the report is warning about.
	_, _, err = prefixed.CompareAndSwap(ctx, "k", []byte("old"), []byte("new"))
	assert.ErrorIs(t, err, ErrCompareAndSwapUnsupported)
}
