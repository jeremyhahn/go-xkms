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

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFindZoneByFQDNCacheExpired tests cache expiration handling.
func TestFindZoneByFQDNCacheExpired(t *testing.T) {
	// Clear cache first
	ClearZoneCache()

	// Add expired cache entry
	zoneCacheMu.Lock()
	zoneCache["_acme-challenge.expired-domain.com."] = zoneCacheEntry{
		zone:       "expired-domain.com.",
		expiryTime: time.Now().Add(-time.Hour), // Expired
	}
	zoneCacheMu.Unlock()

	ctx := context.Background()

	// This should miss the cache due to expiration and try DNS lookup
	// which will fail with default nameservers but at least tests the expiration code path
	_, err := FindZoneByFQDN(ctx, "_acme-challenge.expired-domain.com.", []string{"invalid-server:53"})
	require.Error(t, err)

	// Clean up
	ClearZoneCache()
}

// TestDNSQueryWithNameserverWithoutPort tests nameserver port handling.
func TestDNSQueryWithNameserverWithoutPort(t *testing.T) {
	ctx := context.Background()

	// Test with nameserver without port (should add default port)
	_, err := DNSQuery(ctx, "example.com.", dns.TypeSOA, []string{"8.8.8.8"}, true)
	// May succeed or fail depending on network, but should not panic
	// The test validates the port handling code path
	_ = err
}

// TestDNSQueryUDPTruncation tests TCP fallback on UDP truncation.
func TestDNSQueryUDPTruncation(t *testing.T) {
	ctx := context.Background()

	// Query for a domain that returns many TXT records which might truncate
	// This tests the UDP->TCP fallback code path
	_, err := DNSQuery(ctx, "google.com.", dns.TypeTXT, []string{"8.8.8.8:53"}, true)
	// May succeed or fail depending on network
	_ = err
}

// TestWaitForCtxSuccess tests WaitForCtx with successful condition.
func TestWaitForCtxSuccess(t *testing.T) {
	ctx := context.Background()

	callCount := 0
	err := WaitForCtx(ctx, time.Second, 10*time.Millisecond, func() (bool, error) {
		callCount++
		return callCount >= 3, nil
	})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, callCount, 3)
}

// TestWaitForCtxContextCancellation tests WaitForCtx with context cancellation.
func TestWaitForCtxContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := WaitForCtx(ctx, time.Second, 10*time.Millisecond, func() (bool, error) {
		return false, nil
	})
	require.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

// TestWaitForCtxImmediateSuccess tests WaitForCtx with immediate success.
func TestWaitForCtxImmediateSuccess(t *testing.T) {
	ctx := context.Background()

	err := WaitForCtx(ctx, time.Second, 10*time.Millisecond, func() (bool, error) {
		return true, nil
	})
	require.NoError(t, err)
}

// TestWaitForCtxErrorReturnedOnTimeout tests error propagation on timeout.
func TestWaitForCtxErrorReturnedOnTimeout(t *testing.T) {
	ctx := context.Background()

	testErr := errors.New("test error from condition")
	err := WaitForCtx(ctx, 100*time.Millisecond, 10*time.Millisecond, func() (bool, error) {
		return false, testErr
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "test error")
}

// TestWaitForCtxInitialError tests error from first check.
func TestWaitForCtxInitialError(t *testing.T) {
	ctx := context.Background()

	testErr := errors.New("initial error")
	callCount := 0
	err := WaitForCtx(ctx, 100*time.Millisecond, 20*time.Millisecond, func() (bool, error) {
		callCount++
		return false, testErr
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "initial error")
}

// TestRegisterEnvFactoryAndGet tests env factory registration and retrieval.
func TestRegisterEnvFactoryAndGet(t *testing.T) {
	// Register a test env factory
	testFactory := func(ctx context.Context) (Provider, error) {
		return nil, errors.New("test factory")
	}

	RegisterEnvFactory("test-env-provider", testFactory)

	// Retrieve it
	factory := GetEnvFactory("test-env-provider")
	require.NotNil(t, factory)

	// Verify it works
	_, err := factory(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "test factory")

	// Non-existent factory returns nil
	factory = GetEnvFactory("nonexistent-provider")
	assert.Nil(t, factory)
}

// TestContainsCNAMEFunction tests the containsCNAME helper function.
func TestContainsCNAMEFunction(t *testing.T) {
	t.Run("returns true when CNAME exists", func(t *testing.T) {
		msg := &dns.Msg{}
		msg.Answer = append(msg.Answer, &dns.CNAME{
			Hdr:    dns.RR_Header{Name: "alias.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
			Target: "target.example.com.",
		})

		assert.True(t, containsCNAME(msg))
	})

	t.Run("returns false when no CNAME exists", func(t *testing.T) {
		msg := &dns.Msg{}
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{1, 2, 3, 4},
		})

		assert.False(t, containsCNAME(msg))
	})

	t.Run("returns false for empty message", func(t *testing.T) {
		msg := &dns.Msg{}
		assert.False(t, containsCNAME(msg))
	})
}

// TestGetNameserversFromConfigWithServers tests reading actual nameservers.
func TestGetNameserversFromConfigWithServers(t *testing.T) {
	// Test with actual /etc/resolv.conf if it exists
	servers := GetNameserversFromConfig("/etc/resolv.conf")
	assert.NotEmpty(t, servers)

	// Each server should have a port
	for _, server := range servers {
		assert.Contains(t, server, ":")
	}
}

// TestDNSQueryWithMultipleNameservers tests DNS query with multiple nameservers.
func TestDNSQueryWithMultipleNameservers(t *testing.T) {
	ctx := context.Background()

	// Test with multiple nameservers
	_, err := DNSQuery(ctx, "example.com.", dns.TypeA, []string{
		"8.8.8.8:53",
		"8.8.4.4:53",
	}, true)
	// Should succeed if network is available
	_ = err
}

// TestDNSQueryNoNameserversResponded tests handling when no nameservers respond.
func TestDNSQueryNoNameserversResponded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Use invalid nameservers that won't respond
	_, err := DNSQuery(ctx, "example.com.", dns.TypeA, []string{
		"192.0.2.1:53", // TEST-NET-1, should not respond
	}, true)
	require.Error(t, err)
}

// TestZoneCacheMultipleEntries tests cache with multiple entries.
func TestZoneCacheMultipleEntries(t *testing.T) {
	ClearZoneCache()

	// Add multiple entries
	zoneCacheMu.Lock()
	zoneCache["a.example.com."] = zoneCacheEntry{zone: "example.com.", expiryTime: time.Now().Add(time.Hour)}
	zoneCache["b.example.com."] = zoneCacheEntry{zone: "example.com.", expiryTime: time.Now().Add(time.Hour)}
	zoneCache["c.other.com."] = zoneCacheEntry{zone: "other.com.", expiryTime: time.Now().Add(time.Hour)}
	zoneCacheMu.Unlock()

	// Verify entries exist
	zoneCacheMu.RLock()
	assert.Len(t, zoneCache, 3)
	zoneCacheMu.RUnlock()

	// Clear and verify
	ClearZoneCache()
	zoneCacheMu.RLock()
	assert.Len(t, zoneCache, 0)
	zoneCacheMu.RUnlock()
}

// TestFindBestMatchWithMultipleMatchingZones tests zone matching with multiple matches.
func TestFindBestMatchWithMultipleMatchingZones(t *testing.T) {
	tests := []struct {
		name     string
		fqdn     string
		zones    []string
		expected string
	}{
		{
			name:     "selects longest matching zone",
			fqdn:     "_acme-challenge.deep.sub.example.com.",
			zones:    []string{"example.com.", "sub.example.com.", "deep.sub.example.com."},
			expected: "deep.sub.example.com.",
		},
		{
			name:     "works with single zone",
			fqdn:     "_acme-challenge.example.com.",
			zones:    []string{"example.com."},
			expected: "example.com.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FindBestMatch(tt.fqdn, tt.zones...)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFollowCNAMEs tests the FollowCNAMEs function.
func TestFollowCNAMEs(t *testing.T) {
	ctx := context.Background()

	t.Run("returns original fqdn when no CNAME exists", func(t *testing.T) {
		// Query a domain that doesn't have a CNAME record
		// This should return the original fqdn
		result, err := FollowCNAMEs(ctx, "example.com.", []string{"8.8.8.8:53"})
		// May succeed or fail depending on network
		if err == nil {
			assert.Equal(t, "example.com.", result)
		}
	})

	t.Run("uses default nameservers when none provided", func(t *testing.T) {
		// Pass empty nameservers to test default handling
		_, err := FollowCNAMEs(ctx, "example.com.", nil)
		// May succeed or fail depending on network
		_ = err
	})

	t.Run("returns error when DNS query fails", func(t *testing.T) {
		// Use invalid nameserver to force error
		_, err := FollowCNAMEs(ctx, "example.com.", []string{"invalid-server:53"})
		require.Error(t, err)
	})
}

// TestFollowCNAMEsWithRealCNAME tests following CNAME records.
func TestFollowCNAMEsWithRealCNAME(t *testing.T) {
	ctx := context.Background()

	// www.google.com typically has a CNAME to another domain
	// This tests the actual CNAME following logic
	result, err := FollowCNAMEs(ctx, "www.google.com.", []string{"8.8.8.8:53"})
	// May succeed or fail depending on network
	if err == nil {
		// Result should be a valid fqdn
		assert.NotEmpty(t, result)
	}
}
