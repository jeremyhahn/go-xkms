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

package staticpw

import (
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpiryChecker_CheckExpired_NoExpiredEntries(t *testing.T) {
	s := NewStore(storage.New())
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{
		Name:      "valid",
		Password:  "pass",
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}))

	checker := NewExpiryChecker(s, time.Hour, nil)
	expired, err := checker.CheckExpired()
	require.NoError(t, err)
	assert.Empty(t, expired)
}

func TestExpiryChecker_CheckExpired_WithExpiredEntries(t *testing.T) {
	s := NewStore(storage.New())
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{
		Name:      "expired",
		Password:  "pass",
		ExpiresAt: time.Now().UTC().Add(-time.Hour),
	}))
	require.NoError(t, s.Add(&StaticPassword{
		Name:      "valid",
		Password:  "pass",
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}))

	checker := NewExpiryChecker(s, time.Hour, nil)
	expired, err := checker.CheckExpired()
	require.NoError(t, err)
	assert.Len(t, expired, 1)
	assert.Equal(t, "expired", expired[0].Name)
}

func TestExpiryChecker_CheckExpired_NoExpirySet(t *testing.T) {
	s := NewStore(storage.New())
	defer func() { _ = s.Close() }()

	// Entry with zero ExpiresAt should not be considered expired
	require.NoError(t, s.Add(&StaticPassword{
		Name:     "no-expiry",
		Password: "pass",
	}))

	checker := NewExpiryChecker(s, time.Hour, nil)
	expired, err := checker.CheckExpired()
	require.NoError(t, err)
	assert.Empty(t, expired)
}

func TestExpiryChecker_CheckExpired_MultipleExpired(t *testing.T) {
	s := NewStore(storage.New())
	defer func() { _ = s.Close() }()

	past := time.Now().UTC().Add(-time.Hour)
	require.NoError(t, s.Add(&StaticPassword{
		Name: "exp1", Password: "p", ExpiresAt: past,
	}))
	require.NoError(t, s.Add(&StaticPassword{
		Name: "exp2", Password: "p", ExpiresAt: past,
	}))
	require.NoError(t, s.Add(&StaticPassword{
		Name: "exp3", Password: "p", ExpiresAt: past,
	}))

	checker := NewExpiryChecker(s, time.Hour, nil)
	expired, err := checker.CheckExpired()
	require.NoError(t, err)
	assert.Len(t, expired, 3)
}

func TestExpiryChecker_CheckExpired_EmptyStore(t *testing.T) {
	s := NewStore(storage.New())
	defer func() { _ = s.Close() }()

	checker := NewExpiryChecker(s, time.Hour, nil)
	expired, err := checker.CheckExpired()
	require.NoError(t, err)
	assert.Empty(t, expired)
}

func TestExpiryChecker_CheckExpired_ExactlyNowNotExpired(t *testing.T) {
	s := NewStore(storage.New())
	defer func() { _ = s.Close() }()

	// An entry expiring exactly now should be expired (Before check)
	// We set it slightly in the past to avoid races
	require.NoError(t, s.Add(&StaticPassword{
		Name:      "just-expired",
		Password:  "pass",
		ExpiresAt: time.Now().UTC().Add(-time.Millisecond),
	}))

	checker := NewExpiryChecker(s, time.Hour, nil)
	expired, err := checker.CheckExpired()
	require.NoError(t, err)
	assert.Len(t, expired, 1)
}

func TestExpiryChecker_StartStop(t *testing.T) {
	s := NewStore(storage.New())
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{
		Name:      "expired",
		Password:  "pass",
		ExpiresAt: time.Now().UTC().Add(-time.Hour),
	}))

	var mu sync.Mutex
	var callbackCalled int
	checker := NewExpiryChecker(s, 10*time.Millisecond, func(pw *StaticPassword) {
		mu.Lock()
		callbackCalled++
		mu.Unlock()
	})

	checker.Start()
	time.Sleep(50 * time.Millisecond)
	checker.Stop()

	mu.Lock()
	calls := callbackCalled
	mu.Unlock()
	assert.Greater(t, calls, 0, "callback should have been called at least once")
}

func TestExpiryChecker_StopMultipleTimes(t *testing.T) {
	s := NewStore(storage.New())
	defer func() { _ = s.Close() }()

	checker := NewExpiryChecker(s, time.Hour, func(pw *StaticPassword) {})

	checker.Start()
	checker.Stop()
	// Should not panic
	checker.Stop()
	checker.Stop()
}

func TestExpiryChecker_CallbackReceivesCorrectEntry(t *testing.T) {
	s := NewStore(storage.New())
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{
		Name:      "expired-entry",
		Password:  "pass",
		ExpiresAt: time.Now().UTC().Add(-time.Hour),
	}))

	var mu sync.Mutex
	var receivedNames []string
	checker := NewExpiryChecker(s, 10*time.Millisecond, func(pw *StaticPassword) {
		mu.Lock()
		receivedNames = append(receivedNames, pw.Name)
		mu.Unlock()
	})

	checker.Start()
	time.Sleep(50 * time.Millisecond)
	checker.Stop()

	mu.Lock()
	defer mu.Unlock()
	assert.Contains(t, receivedNames, "expired-entry")
}

func TestExpiryChecker_CheckExpired_ClosedStore(t *testing.T) {
	s := NewStore(storage.New())
	_ = s.Close()

	checker := NewExpiryChecker(s, time.Hour, nil)
	_, err := checker.CheckExpired()
	assert.ErrorIs(t, err, ErrStoreClosed)
}

func TestExpiryChecker_MixedExpiryAndNonExpiry(t *testing.T) {
	s := NewStore(storage.New())
	defer func() { _ = s.Close() }()

	past := time.Now().UTC().Add(-time.Hour)
	future := time.Now().UTC().Add(24 * time.Hour)

	require.NoError(t, s.Add(&StaticPassword{Name: "exp", Password: "p", ExpiresAt: past}))
	require.NoError(t, s.Add(&StaticPassword{Name: "valid", Password: "p", ExpiresAt: future}))
	require.NoError(t, s.Add(&StaticPassword{Name: "no-expiry", Password: "p"}))

	checker := NewExpiryChecker(s, time.Hour, nil)
	expired, err := checker.CheckExpired()
	require.NoError(t, err)
	assert.Len(t, expired, 1)
	assert.Equal(t, "exp", expired[0].Name)
}
