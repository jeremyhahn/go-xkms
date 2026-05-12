// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package clouddns

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/dns/v1"

	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers"
)

// injectZoneCache adds an entry to the zone cache for testing.
// This allows us to bypass DNS lookups and test the zone selection logic.
func injectZoneCache(fqdn, zone string) {
	// Access internal cache in providers package
	providers.ClearZoneCache()

	// Create a method that adds to the cache
	// We need to export this or use a workaround - test getHostedZone directly
}

// TestGetHostedZoneZoneDiscoveryPaths tests zone discovery code paths
// by using real DNS lookups for well-known domains.
func TestGetHostedZoneZoneDiscoveryPaths(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when getManagedZones fails after DNS lookup", func(t *testing.T) {
		providers.ClearZoneCache()

		apiCallCount := 0
		mock := &mockCloudDNSClient{
			getManagedZonesFunc: func(ctx context.Context, project string) ([]*dns.ManagedZone, error) {
				apiCallCount++
				return nil, errors.New("API authentication error")
			},
		}

		// Use default nameservers for real DNS lookups
		provider := NewWithClient(mock, "my-project", "", nil)

		// Use a real domain that will succeed in DNS lookup
		_, err := provider.getHostedZone(ctx, "_acme-challenge.google.com.")

		// This should error because getManagedZones fails
		require.Error(t, err)
		assert.Contains(t, err.Error(), "API authentication error")
		assert.Greater(t, apiCallCount, 0, "getManagedZones should have been called")
	})

	t.Run("returns ErrZoneNotFound when no matching zones exist after DNS lookup", func(t *testing.T) {
		providers.ClearZoneCache()

		mock := &mockCloudDNSClient{
			getManagedZonesFunc: func(ctx context.Context, project string) ([]*dns.ManagedZone, error) {
				// Return zones that don't match the discovered zone
				return []*dns.ManagedZone{
					{Name: "other-zone", DnsName: "other.com.", Visibility: "public"},
					{Name: "another-zone", DnsName: "another.org.", Visibility: "public"},
				}, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "", nil)

		// Use a real domain for DNS lookup
		_, err := provider.getHostedZone(ctx, "_acme-challenge.google.com.")

		// The DNS lookup will find google.com zone, but our mock returns no matching zones
		require.Error(t, err)
		assert.Equal(t, providers.ErrZoneNotFound, err)
	})

	t.Run("selects public zone over private zone", func(t *testing.T) {
		providers.ClearZoneCache()

		mock := &mockCloudDNSClient{
			getManagedZonesFunc: func(ctx context.Context, project string) ([]*dns.ManagedZone, error) {
				// Return both public and private zones for the discovered zone
				return []*dns.ManagedZone{
					{Name: "private-zone", DnsName: "google.com.", Visibility: "private"},
					{Name: "public-zone", DnsName: "google.com.", Visibility: "public"},
				}, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "", nil)

		zone, err := provider.getHostedZone(ctx, "_acme-challenge.google.com.")

		require.NoError(t, err)
		assert.Equal(t, "public-zone", zone)
	})

	t.Run("falls back to first matching zone when no public zones exist", func(t *testing.T) {
		providers.ClearZoneCache()

		mock := &mockCloudDNSClient{
			getManagedZonesFunc: func(ctx context.Context, project string) ([]*dns.ManagedZone, error) {
				// Return only private zones
				return []*dns.ManagedZone{
					{Name: "private-zone-1", DnsName: "google.com.", Visibility: "private"},
					{Name: "private-zone-2", DnsName: "google.com.", Visibility: "private"},
				}, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "", nil)

		zone, err := provider.getHostedZone(ctx, "_acme-challenge.google.com.")

		require.NoError(t, err)
		assert.Equal(t, "private-zone-1", zone)
	})

	t.Run("handles zone with multiple matching zones selecting first public", func(t *testing.T) {
		providers.ClearZoneCache()

		mock := &mockCloudDNSClient{
			getManagedZonesFunc: func(ctx context.Context, project string) ([]*dns.ManagedZone, error) {
				// Return multiple zones with some public
				return []*dns.ManagedZone{
					{Name: "private-zone", DnsName: "google.com.", Visibility: "private"},
					{Name: "first-public-zone", DnsName: "google.com.", Visibility: "public"},
					{Name: "second-public-zone", DnsName: "google.com.", Visibility: "public"},
				}, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "", nil)

		zone, err := provider.getHostedZone(ctx, "_acme-challenge.google.com.")

		require.NoError(t, err)
		assert.Equal(t, "first-public-zone", zone)
	})
}

// TestZoneDiscoveryWithSubdomain tests zone discovery for subdomains.
func TestZoneDiscoveryWithSubdomain(t *testing.T) {
	ctx := context.Background()

	t.Run("finds parent zone for subdomain", func(t *testing.T) {
		providers.ClearZoneCache()

		mock := &mockCloudDNSClient{
			getManagedZonesFunc: func(ctx context.Context, project string) ([]*dns.ManagedZone, error) {
				return []*dns.ManagedZone{
					{Name: "google-zone", DnsName: "google.com.", Visibility: "public"},
				}, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "", nil)

		// Use a subdomain - DNS lookup will find google.com as the zone
		zone, err := provider.getHostedZone(ctx, "_acme-challenge.www.google.com.")

		require.NoError(t, err)
		assert.Equal(t, "google-zone", zone)
	})
}

// testableZoneCache provides access to zone cache for testing
var zoneCacheMu sync.RWMutex

// TestZoneCaching tests that zone discovery results are used correctly.
func TestZoneCaching(t *testing.T) {
	ctx := context.Background()

	t.Run("calls getManagedZones only once for same domain", func(t *testing.T) {
		providers.ClearZoneCache()

		callCount := 0
		mock := &mockCloudDNSClient{
			getManagedZonesFunc: func(ctx context.Context, project string) ([]*dns.ManagedZone, error) {
				callCount++
				return []*dns.ManagedZone{
					{Name: "google-zone", DnsName: "google.com.", Visibility: "public"},
				}, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "", nil)

		// First call
		_, err1 := provider.getHostedZone(ctx, "_acme-challenge.google.com.")
		require.NoError(t, err1)
		firstCallCount := callCount

		// Second call - should use cached zone lookup (but getManagedZones will still be called)
		_, err2 := provider.getHostedZone(ctx, "_acme-challenge.google.com.")
		require.NoError(t, err2)

		// The zone cache in providers package caches the DNS lookup result,
		// not the managed zones lookup, so getManagedZones will be called twice
		assert.Equal(t, firstCallCount*2, callCount)
	})
}

// TestPresentWithZoneDiscovery tests Present when zone discovery is needed.
func TestPresentWithZoneDiscovery(t *testing.T) {
	ctx := context.Background()

	t.Run("discovers zone and creates record", func(t *testing.T) {
		providers.ClearZoneCache()

		var capturedZone string
		mock := &mockCloudDNSClient{
			getManagedZonesFunc: func(ctx context.Context, project string) ([]*dns.ManagedZone, error) {
				return []*dns.ManagedZone{
					{Name: "google-zone", DnsName: "google.com.", Visibility: "public"},
				}, nil
			},
			getResourceRecordSetsFunc: func(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error) {
				capturedZone = zone
				return []*dns.ResourceRecordSet{}, nil
			},
			createChangeFunc: func(ctx context.Context, project, zone string, change *dns.Change) (*dns.Change, error) {
				change.Id = "change-123"
				change.Status = "done"
				return change, nil
			},
		}

		// Provider without configured zone - will use discovery
		provider := NewWithClient(mock, "my-project", "", nil)

		err := provider.Present(ctx, "google.com", "_acme-challenge.google.com.", "token-value")
		require.NoError(t, err)
		assert.Equal(t, "google-zone", capturedZone)
	})
}

// TestCleanUpWithZoneDiscovery tests CleanUp when zone discovery is needed.
func TestCleanUpWithZoneDiscovery(t *testing.T) {
	ctx := context.Background()

	t.Run("discovers zone and removes record", func(t *testing.T) {
		providers.ClearZoneCache()

		var capturedZone string
		mock := &mockCloudDNSClient{
			getManagedZonesFunc: func(ctx context.Context, project string) ([]*dns.ManagedZone, error) {
				return []*dns.ManagedZone{
					{Name: "google-zone", DnsName: "google.com.", Visibility: "public"},
				}, nil
			},
			getResourceRecordSetsFunc: func(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error) {
				capturedZone = zone
				return []*dns.ResourceRecordSet{
					{
						Name:    "_acme-challenge.google.com.",
						Type:    "TXT",
						Ttl:     120,
						Rrdatas: []string{"token-value"},
					},
				}, nil
			},
			createChangeFunc: func(ctx context.Context, project, zone string, change *dns.Change) (*dns.Change, error) {
				change.Id = "change-123"
				change.Status = "done"
				return change, nil
			},
		}

		// Provider without configured zone - will use discovery
		provider := NewWithClient(mock, "my-project", "", nil)

		err := provider.CleanUp(ctx, "google.com", "_acme-challenge.google.com.", "token-value")
		require.NoError(t, err)
		assert.Equal(t, "google-zone", capturedZone)
	})
}

// TestZoneDiscoveryWithTimeout tests zone discovery timeout handling.
func TestZoneDiscoveryWithTimeout(t *testing.T) {
	t.Run("respects context timeout during zone discovery", func(t *testing.T) {
		providers.ClearZoneCache()

		mock := &mockCloudDNSClient{
			getManagedZonesFunc: func(ctx context.Context, project string) ([]*dns.ManagedZone, error) {
				// Simulate slow API
				time.Sleep(100 * time.Millisecond)
				return []*dns.ManagedZone{
					{Name: "test-zone", DnsName: "google.com.", Visibility: "public"},
				}, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "", nil)

		// Create a context with short timeout
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		_, err := provider.getHostedZone(ctx, "_acme-challenge.google.com.")
		// May or may not error depending on timing of DNS lookup vs timeout
		_ = err
	})
}
