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

	require.NoError(t, RegisterBackendType(bt))

	assert.True(t, IsRegisteredBackendType(bt))
	assert.False(t, IsBuiltinBackendType(bt))
	assert.True(t, StoreType(bt).IsValid())
	assert.Equal(t, StoreType(bt), ParseStoreType(" "+strings.ToUpper(string(bt))+" "))
}

// TestRegisterBackendType_Refusals proves empty, malformed, built-in and
// duplicate names are refused with typed errors.
func TestRegisterBackendType_Refusals(t *testing.T) {
	dup := uniqueBackendType("types-ext-dup")
	require.NoError(t, RegisterBackendType(dup))

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
			err := RegisterBackendType(tc.bt)
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
				results <- RegisterBackendType(n)
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
