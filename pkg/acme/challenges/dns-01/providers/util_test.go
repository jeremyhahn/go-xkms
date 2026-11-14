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

package providers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToFQDN(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "without dot",
			input:    "example.com",
			expected: "example.com.",
		},
		{
			name:     "with dot",
			input:    "example.com.",
			expected: "example.com.",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "subdomain without dot",
			input:    "sub.example.com",
			expected: "sub.example.com.",
		},
		{
			name:     "subdomain with dot",
			input:    "sub.example.com.",
			expected: "sub.example.com.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ToFQDN(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUnFQDN(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "with dot",
			input:    "example.com.",
			expected: "example.com",
		},
		{
			name:     "without dot",
			input:    "example.com",
			expected: "example.com",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "only dot",
			input:    ".",
			expected: "",
		},
		{
			name:     "subdomain with dot",
			input:    "sub.example.com.",
			expected: "sub.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := UnFQDN(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFindBestMatch(t *testing.T) {
	tests := []struct {
		name        string
		fqdn        string
		zones       []string
		expected    string
		expectError bool
	}{
		{
			name:     "exact match",
			fqdn:     "example.com.",
			zones:    []string{"example.com."},
			expected: "example.com.",
		},
		{
			name:     "subdomain match",
			fqdn:     "_acme-challenge.www.example.com.",
			zones:    []string{"example.com.", "other.com."},
			expected: "example.com.",
		},
		{
			name:     "longest match wins",
			fqdn:     "_acme-challenge.sub.example.com.",
			zones:    []string{"example.com.", "sub.example.com."},
			expected: "sub.example.com.",
		},
		{
			name:        "no match",
			fqdn:        "example.com.",
			zones:       []string{"other.com.", "different.org."},
			expectError: true,
		},
		{
			name:        "empty zones",
			fqdn:        "example.com.",
			zones:       []string{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FindBestMatch(tt.fqdn, tt.zones...)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestWaitFor(t *testing.T) {
	t.Run("immediate success", func(t *testing.T) {
		callCount := 0
		err := WaitFor(time.Second, 10*time.Millisecond, func() (bool, error) {
			callCount++
			return true, nil
		})
		require.NoError(t, err)
		assert.Equal(t, 1, callCount)
	})

	t.Run("eventual success", func(t *testing.T) {
		callCount := 0
		err := WaitFor(time.Second, 10*time.Millisecond, func() (bool, error) {
			callCount++
			return callCount >= 3, nil
		})
		require.NoError(t, err)
		assert.GreaterOrEqual(t, callCount, 3)
	})

	t.Run("timeout", func(t *testing.T) {
		start := time.Now()
		err := WaitFor(100*time.Millisecond, 10*time.Millisecond, func() (bool, error) {
			return false, nil
		})
		elapsed := time.Since(start)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPropagationTimeout)
		assert.GreaterOrEqual(t, elapsed, 100*time.Millisecond)
	})

	t.Run("timeout with error", func(t *testing.T) {
		testErr := errors.New("test error")
		err := WaitFor(100*time.Millisecond, 10*time.Millisecond, func() (bool, error) {
			return false, testErr
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "test error")
	})
}

func TestClearZoneCache(t *testing.T) {
	// Add something to cache
	zoneCacheMu.Lock()
	zoneCache["test.example.com."] = zoneCacheEntry{
		zone:       "example.com.",
		expiryTime: time.Now().Add(time.Hour),
	}
	zoneCacheMu.Unlock()

	// Verify it's in cache
	zoneCacheMu.RLock()
	_, exists := zoneCache["test.example.com."]
	zoneCacheMu.RUnlock()
	assert.True(t, exists)

	// Clear cache
	ClearZoneCache()

	// Verify it's gone
	zoneCacheMu.RLock()
	_, exists = zoneCache["test.example.com."]
	assert.Empty(t, zoneCache)
	zoneCacheMu.RUnlock()
	assert.False(t, exists)
}

func TestGetNameserversFromConfig(t *testing.T) {
	t.Run("nonexistent file returns defaults", func(t *testing.T) {
		servers := GetNameserversFromConfig("/nonexistent/resolv.conf")
		assert.Equal(t, DefaultNameservers, servers)
	})

	t.Run("empty path returns defaults", func(t *testing.T) {
		// This will try to read /etc/resolv.conf which may or may not exist
		servers := GetNameserversFromConfig("")
		assert.NotEmpty(t, servers)
	})
}

// Note: Testing FindZoneByFQDN, DNSQuery, and FollowCNAMEs requires
// either mocking the DNS client or having actual DNS servers available.
// These are better tested in integration tests.

func TestFindZoneByFQDN_CacheHit(t *testing.T) {
	// Clear cache first
	ClearZoneCache()

	// Add valid cache entry
	zoneCacheMu.Lock()
	zoneCache["_acme-challenge.example.com."] = zoneCacheEntry{
		zone:       "example.com.",
		expiryTime: time.Now().Add(time.Hour),
	}
	zoneCacheMu.Unlock()

	ctx := context.Background()

	// This should hit the cache and return immediately
	zone, err := FindZoneByFQDN(ctx, "_acme-challenge.example.com.", nil)
	require.NoError(t, err)
	assert.Equal(t, "example.com.", zone)

	// Clean up
	ClearZoneCache()
}
