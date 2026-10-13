package types

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegisterBackendType_ValidEverywhere proves a registered type becomes a
// valid store type and parses back to itself.
// backendTypeSeq numbers the backend types the tests register.
var backendTypeSeq atomic.Uint64

// uniqueBackendType returns a backend type no earlier test, or earlier
// -count iteration, has registered. The registry is process-wide and refuses
// duplicates, so a fixed name passes only on the first run.
func uniqueBackendType(prefix string) BackendType {
	return BackendType(fmt.Sprintf("%s-%d", prefix, backendTypeSeq.Add(1)))
}

func TestRegisterBackendType_ValidEverywhere(t *testing.T) {
	bt := uniqueBackendType("types-ext-valid")
	require.False(t, StoreType(bt).IsValid())
	require.Equal(t, StoreUnknown, ParseStoreType(string(bt)))

	require.NoError(t, RegisterBackendType(bt, testBackendFactory))

	assert.True(t, IsRegisteredBackendType(bt))
	assert.False(t, IsBuiltinBackendType(bt))
	assert.True(t, StoreType(bt).IsValid())
	assert.Equal(t, StoreType(bt), ParseStoreType(" "+strings.ToUpper(string(bt))+" "))
}

// TestRegisterBackendType_Refusals proves empty, malformed, built-in and
// duplicate names are refused with typed errors.
func TestRegisterBackendType_Refusals(t *testing.T) {
	dup := uniqueBackendType("types-ext-dup")
	require.NoError(t, RegisterBackendType(dup, testBackendFactory))

	tests := []struct {
		name string
		bt   BackendType
		want error
	}{
		{"empty", "", ErrInvalidBackendTypeName},
		{"uppercase", "Fw-Backend", ErrInvalidBackendTypeName},
		{"colon breaks key id", "fw:backend", ErrInvalidBackendTypeName},
		{"builtin backend type", BackendTypeTPM2, ErrBackendTypeRegistered},
		{"builtin backend type without store", BackendTypeYubiKey, ErrBackendTypeRegistered},
		{"unknown store sentinel", BackendType(StoreUnknown), ErrBackendTypeRegistered},
		{"duplicate", dup, ErrBackendTypeRegistered},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := RegisterBackendType(tc.bt, testBackendFactory)
			require.ErrorIs(t, err, tc.want)
			var regErr *BackendTypeRegistrationError
			require.ErrorAs(t, err, &regErr)
			assert.Equal(t, tc.bt, regErr.Type)
			assert.Contains(t, err.Error(), string(tc.bt))
		})
	}
	assert.False(t, IsRegisteredBackendType("fw:backend"))
	assert.False(t, StoreType("fw:backend").IsValid())
}

// TestRegisterBackendType_ConcurrentRegistrationsAllLand proves the
// copy-on-write registry loses no entry under concurrent registration and
// admits exactly one winner for a contested name.
func TestRegisterBackendType_ConcurrentRegistrationsAllLand(t *testing.T) {
	names := make([]BackendType, 4)
	for i := range names {
		names[i] = uniqueBackendType("types-cc")
	}
	var wg sync.WaitGroup
	results := make(chan error, len(names)*2)
	for _, n := range names {
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results <- RegisterBackendType(n, testBackendFactory)
			}()
		}
	}
	wg.Wait()
	close(results)

	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
			continue
		}
		require.ErrorIs(t, err, ErrBackendTypeRegistered)
	}
	assert.Equal(t, len(names), accepted)
	for _, n := range names {
		assert.True(t, IsRegisteredBackendType(n), n)
	}
}

// testBackendFactory is a factory the registry stores; the tests never call it.
func testBackendFactory(map[string]interface{}) (KeyProvider, error) {
	return nil, nil
}

// TestRegisterBackendType_PublishesFactoryWithName proves a registration
// publishes the name and its factory together, in every lookup.
func TestRegisterBackendType_PublishesFactoryWithName(t *testing.T) {
	bt := BackendType("types-ext-factory")
	_, ok := RegisteredBackendFactory(bt)
	require.False(t, ok)

	require.NoError(t, RegisterBackendType(bt, testBackendFactory))

	factory, ok := RegisteredBackendFactory(bt)
	require.True(t, ok)
	assert.NotNil(t, factory)
	snapshot := RegisteredBackends()
	assert.NotNil(t, snapshot[bt])

	// The snapshot belongs to the caller: changing it changes no registration.
	delete(snapshot, bt)
	assert.True(t, IsRegisteredBackendType(bt))
}

// TestRegisterBackendType_RefusesNilFactory proves a name nobody can construct
// is refused and not registered.
func TestRegisterBackendType_RefusesNilFactory(t *testing.T) {
	bt := BackendType("types-ext-nofactory")
	err := RegisterBackendType(bt, nil)
	require.ErrorIs(t, err, ErrNilBackendFactory)
	var regErr *BackendTypeRegistrationError
	require.ErrorAs(t, err, &regErr)
	assert.Equal(t, bt, regErr.Type)
	assert.False(t, IsRegisteredBackendType(bt))
	assert.False(t, StoreType(bt).IsValid())
}

// TestRegisteredBackendFactory_FalseForUnknownAndBuiltIn proves only names
// registered at run time have a registered factory.
func TestRegisteredBackendFactory_FalseForUnknownAndBuiltIn(t *testing.T) {
	for _, bt := range []BackendType{"types-ext-never", BackendTypeTPM2, BackendTypeSoftware} {
		factory, ok := RegisteredBackendFactory(bt)
		assert.False(t, ok, bt)
		assert.Nil(t, factory, bt)
	}
}
