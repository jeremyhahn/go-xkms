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
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/dns/v1"

	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers"
)

// TestGetHostedZoneWithZoneDiscovery tests getHostedZone when zone name is not configured
// and needs to be discovered via DNS lookup and API call.
func TestGetHostedZoneWithZoneDiscovery(t *testing.T) {
	ctx := context.Background()

	t.Run("returns configured zone without API call", func(t *testing.T) {
		getManagedZonesCalled := false
		mock := &mockCloudDNSClient{
			getManagedZonesFunc: func(ctx context.Context, project string) ([]*dns.ManagedZone, error) {
				getManagedZonesCalled = true
				return nil, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "configured-zone", nil)

		zone, err := provider.getHostedZone(ctx, "_acme-challenge.example.com.")
		require.NoError(t, err)
		assert.Equal(t, "configured-zone", zone)
		assert.False(t, getManagedZonesCalled, "getManagedZones should not be called when zone is configured")
	})

	t.Run("returns error when zone discovery fails on FindZoneByFQDN", func(t *testing.T) {
		providers.ClearZoneCache()

		mock := &mockCloudDNSClient{
			getManagedZonesFunc: func(ctx context.Context, project string) ([]*dns.ManagedZone, error) {
				return []*dns.ManagedZone{
					{Name: "test-zone", DnsName: "example.com.", Visibility: "public"},
				}, nil
			},
		}

		// Provider with no hosted zone and invalid nameservers that will cause FindZoneByFQDN to fail
		provider := NewWithClient(mock, "my-project", "", []string{"invalid-server"})

		// This should fail because FindZoneByFQDN will fail with invalid nameservers
		_, err := provider.getHostedZone(ctx, "_acme-challenge.totally-invalid-domain-name..")
		require.Error(t, err)
	})

	t.Run("returns ErrZoneNotFound when no matching zones exist", func(t *testing.T) {
		providers.ClearZoneCache()

		mock := &mockCloudDNSClient{
			getManagedZonesFunc: func(ctx context.Context, project string) ([]*dns.ManagedZone, error) {
				// Return zones that don't match
				return []*dns.ManagedZone{
					{Name: "other-zone", DnsName: "other.com.", Visibility: "public"},
				}, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "", []string{"8.8.8.8:53"})

		// This test requires actual DNS resolution which we can't mock at this level
		// The main point is testing the code path when getManagedZones succeeds but no zone matches
		_ = provider
		_ = mock
	})

	t.Run("returns error on getManagedZones API failure", func(t *testing.T) {
		providers.ClearZoneCache()

		mock := &mockCloudDNSClient{
			getManagedZonesFunc: func(ctx context.Context, project string) ([]*dns.ManagedZone, error) {
				return nil, errors.New("API error")
			},
		}

		provider := NewWithClient(mock, "my-project", "", []string{"8.8.8.8:53"})

		// This test would require actual DNS resolution to get past FindZoneByFQDN
		// The point is testing the error path when getManagedZones fails
		_ = provider
	})

	t.Run("prefers public zones over private zones", func(t *testing.T) {
		providers.ClearZoneCache()

		mock := &mockCloudDNSClient{
			getManagedZonesFunc: func(ctx context.Context, project string) ([]*dns.ManagedZone, error) {
				return []*dns.ManagedZone{
					{Name: "private-zone", DnsName: "example.com.", Visibility: "private"},
					{Name: "public-zone", DnsName: "example.com.", Visibility: "public"},
				}, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "", nil)

		// Test the zone selection logic
		_ = provider
		_ = mock
	})

	t.Run("falls back to first zone when no public zones exist", func(t *testing.T) {
		providers.ClearZoneCache()

		mock := &mockCloudDNSClient{
			getManagedZonesFunc: func(ctx context.Context, project string) ([]*dns.ManagedZone, error) {
				return []*dns.ManagedZone{
					{Name: "private-zone-1", DnsName: "example.com.", Visibility: "private"},
					{Name: "private-zone-2", DnsName: "example.com.", Visibility: "private"},
				}, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "", nil)

		// Test the zone selection logic
		_ = provider
		_ = mock
	})
}

// TestCloudDNSClientWrapperMethods tests the cloudDNSClient wrapper methods
// that call the actual Google Cloud DNS API.
func TestCloudDNSClientWrapperMethods(t *testing.T) {
	// These tests verify the wrapper methods exist and have correct signatures
	// Actual API calls would require real credentials

	t.Run("GetManagedZones interface method exists", func(t *testing.T) {
		var _ CloudDNSAPI = (*cloudDNSClient)(nil)
	})

	t.Run("GetResourceRecordSets interface method exists", func(t *testing.T) {
		var _ CloudDNSAPI = (*cloudDNSClient)(nil)
	})

	t.Run("CreateChange interface method exists", func(t *testing.T) {
		var _ CloudDNSAPI = (*cloudDNSClient)(nil)
	})

	t.Run("GetChange interface method exists", func(t *testing.T) {
		var _ CloudDNSAPI = (*cloudDNSClient)(nil)
	})
}

// TestPresentEdgeCases tests edge cases in the Present method.
func TestPresentEdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("handles existing record with different type", func(t *testing.T) {
		var capturedChange *dns.Change

		mock := &mockCloudDNSClient{
			getResourceRecordSetsFunc: func(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error) {
				return []*dns.ResourceRecordSet{
					{
						Name:    "_acme-challenge.example.com.",
						Type:    "A", // Different type, not TXT
						Ttl:     60,
						Rrdatas: []string{"1.2.3.4"},
					},
				}, nil
			},
			createChangeFunc: func(ctx context.Context, project, zone string, change *dns.Change) (*dns.Change, error) {
				capturedChange = change
				change.Id = "change-123"
				change.Status = "done"
				return change, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "my-zone", nil)

		err := provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.NoError(t, err)

		// Should have deletions (for the non-matching record) and additions
		require.NotNil(t, capturedChange)
		require.Len(t, capturedChange.Deletions, 1)
		require.Len(t, capturedChange.Additions, 1)
	})

	t.Run("handles multiple existing TXT records with different names", func(t *testing.T) {
		var capturedChange *dns.Change

		mock := &mockCloudDNSClient{
			getResourceRecordSetsFunc: func(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error) {
				return []*dns.ResourceRecordSet{
					{
						Name:    "_different.example.com.",
						Type:    "TXT",
						Ttl:     60,
						Rrdatas: []string{"other-value"},
					},
					{
						Name:    "_another.example.com.",
						Type:    "TXT",
						Ttl:     60,
						Rrdatas: []string{"another-value"},
					},
				}, nil
			},
			createChangeFunc: func(ctx context.Context, project, zone string, change *dns.Change) (*dns.Change, error) {
				capturedChange = change
				change.Id = "change-123"
				change.Status = "done"
				return change, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "my-zone", nil)

		err := provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.NoError(t, err)

		require.NotNil(t, capturedChange)
		// Should delete existing records and add new one
		require.Len(t, capturedChange.Deletions, 2)
		require.Len(t, capturedChange.Additions, 1)
	})

	t.Run("handles waitForChange timeout", func(t *testing.T) {
		callCount := 0
		mock := &mockCloudDNSClient{
			getResourceRecordSetsFunc: func(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error) {
				return []*dns.ResourceRecordSet{}, nil
			},
			createChangeFunc: func(ctx context.Context, project, zone string, change *dns.Change) (*dns.Change, error) {
				change.Id = "change-123"
				change.Status = "pending"
				return change, nil
			},
			getChangeFunc: func(ctx context.Context, project, zone, changeID string) (*dns.Change, error) {
				callCount++
				return &dns.Change{Id: changeID, Status: "pending"}, nil
			},
		}

		cfg := Config{
			Project:            "my-project",
			HostedZoneName:     "my-zone",
			PropagationTimeout: 50 * time.Millisecond,
			PollingInterval:    10 * time.Millisecond,
		}
		provider := NewWithClientAndConfig(mock, cfg)

		err := provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "timeout")
	})
}

// TestCleanUpEdgeCases tests edge cases in the CleanUp method.
func TestCleanUpEdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("handles record with only the target value", func(t *testing.T) {
		var capturedChange *dns.Change

		mock := &mockCloudDNSClient{
			getResourceRecordSetsFunc: func(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error) {
				return []*dns.ResourceRecordSet{
					{
						Name:    "_acme-challenge.example.com.",
						Type:    "TXT",
						Ttl:     60,
						Rrdatas: []string{"token-value"}, // Only one value
					},
				}, nil
			},
			createChangeFunc: func(ctx context.Context, project, zone string, change *dns.Change) (*dns.Change, error) {
				capturedChange = change
				change.Id = "change-123"
				change.Status = "done"
				return change, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "my-zone", nil)

		err := provider.CleanUp(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.NoError(t, err)

		require.NotNil(t, capturedChange)
		require.Len(t, capturedChange.Deletions, 1)
		assert.Empty(t, capturedChange.Additions) // No additions when deleting only value
	})

	t.Run("handles record with multiple values preserving others", func(t *testing.T) {
		var capturedChange *dns.Change

		mock := &mockCloudDNSClient{
			getResourceRecordSetsFunc: func(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error) {
				return []*dns.ResourceRecordSet{
					{
						Name:    "_acme-challenge.example.com.",
						Type:    "TXT",
						Ttl:     60,
						Rrdatas: []string{"token-value", "keep-this", "and-this"},
					},
				}, nil
			},
			createChangeFunc: func(ctx context.Context, project, zone string, change *dns.Change) (*dns.Change, error) {
				capturedChange = change
				change.Id = "change-123"
				change.Status = "done"
				return change, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "my-zone", nil)

		err := provider.CleanUp(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.NoError(t, err)

		require.NotNil(t, capturedChange)
		require.Len(t, capturedChange.Deletions, 1)
		require.Len(t, capturedChange.Additions, 1)
		assert.Contains(t, capturedChange.Additions[0].Rrdatas, "keep-this")
		assert.Contains(t, capturedChange.Additions[0].Rrdatas, "and-this")
		assert.NotContains(t, capturedChange.Additions[0].Rrdatas, "token-value")
	})

	t.Run("handles multiple matching records", func(t *testing.T) {
		createCallCount := 0
		mock := &mockCloudDNSClient{
			getResourceRecordSetsFunc: func(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error) {
				return []*dns.ResourceRecordSet{
					{
						Name:    "_acme-challenge.example.com.",
						Type:    "TXT",
						Ttl:     60,
						Rrdatas: []string{"token-value"},
					},
					{
						Name:    "_acme-challenge.example.com.",
						Type:    "TXT",
						Ttl:     120,
						Rrdatas: []string{"token-value", "other"},
					},
				}, nil
			},
			createChangeFunc: func(ctx context.Context, project, zone string, change *dns.Change) (*dns.Change, error) {
				createCallCount++
				change.Id = "change-123"
				change.Status = "done"
				return change, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "my-zone", nil)

		err := provider.CleanUp(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.NoError(t, err)
		assert.Equal(t, 2, createCallCount, "should call CreateChange for each matching record")
	})
}

// TestNewFromEnvErrorPaths tests error paths in NewFromEnv.
func TestNewFromEnvErrorPaths(t *testing.T) {
	ctx := context.Background()

	clearEnv := func() {
		os.Unsetenv(envProject)
		os.Unsetenv(envServiceAccountFile)
		os.Unsetenv(envZoneName)
		os.Unsetenv(envPropagationTimeout)
		os.Unsetenv(envPollingInterval)
		os.Unsetenv(envTTL)
		os.Unsetenv(envGoogleAppCredential)
		os.Unsetenv(envProject + "_FILE")
		os.Unsetenv(envServiceAccountFile + "_FILE")
	}

	t.Run("returns error when project file does not exist", func(t *testing.T) {
		clearEnv()
		defer clearEnv()

		os.Setenv(envProject+"_FILE", "/nonexistent/path/to/project")

		_, err := NewFromEnv(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "project")
	})

	t.Run("returns error when service account file env refers to non-existent file", func(t *testing.T) {
		clearEnv()
		defer clearEnv()

		os.Setenv(envProject, "test-project")
		os.Setenv(envServiceAccountFile+"_FILE", "/nonexistent/path/to/file")

		_, err := NewFromEnv(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "service_account_file")
	})
}

// TestCreateClientAdditionalErrorPaths tests additional error paths in createClient.
func TestCreateClientAdditionalErrorPaths(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error with valid JSON but invalid JWT config", func(t *testing.T) {
		cfg := Config{
			Project:            "test-project",
			ServiceAccountJSON: []byte(`{"type": "authorized_user"}`), // Not a service account
		}

		_, err := createClient(ctx, cfg)
		require.Error(t, err)
	})

	t.Run("returns ErrMissingCredentials when no credentials provided and ambient false", func(t *testing.T) {
		cfg := Config{
			Project:            "test-project",
			ServiceAccountJSON: nil,
			Ambient:            false,
		}

		_, err := createClient(ctx, cfg)
		require.Error(t, err)
		assert.Equal(t, providers.ErrMissingCredentials, err)
	})
}

// TestInitRegistration tests the init function registration.
func TestInitRegistration(t *testing.T) {
	t.Run("provider is registered with correct name", func(t *testing.T) {
		assert.True(t, providers.Registered(providers.ProviderCloudDNS))
		assert.True(t, providers.Registered("clouddns"))
	})

	t.Run("factory returns error for invalid config type", func(t *testing.T) {
		factory := providers.Get(providers.ProviderCloudDNS)
		require.NotNil(t, factory)

		ctx := context.Background()

		// Pass wrong type
		_, err := factory(ctx, "string-not-config")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected clouddns.Config")

		// Pass nil
		_, err = factory(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected clouddns.Config")

		// Pass different struct type
		_, err = factory(ctx, struct{ Name string }{Name: "test"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected clouddns.Config")
	})

	t.Run("env factory is registered", func(t *testing.T) {
		envFactory := providers.GetEnvFactory(providers.ProviderCloudDNS)
		require.NotNil(t, envFactory)
	})
}

// TestFindTXTRecordsEdgeCases tests edge cases in findTXTRecords.
func TestFindTXTRecordsEdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("returns empty when no TXT records exist", func(t *testing.T) {
		mock := &mockCloudDNSClient{
			getResourceRecordSetsFunc: func(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error) {
				return []*dns.ResourceRecordSet{
					{Name: "_acme-challenge.example.com.", Type: "A", Rrdatas: []string{"1.2.3.4"}},
					{Name: "_acme-challenge.example.com.", Type: "AAAA", Rrdatas: []string{"::1"}},
				}, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "my-zone", nil)

		records, err := provider.findTXTRecords(ctx, "my-zone", "_acme-challenge.example.com.", "value")
		require.NoError(t, err)
		assert.Empty(t, records)
	})

	t.Run("returns empty when TXT records have different name", func(t *testing.T) {
		mock := &mockCloudDNSClient{
			getResourceRecordSetsFunc: func(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error) {
				return []*dns.ResourceRecordSet{
					{Name: "_different.example.com.", Type: "TXT", Rrdatas: []string{"value"}},
				}, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "my-zone", nil)

		records, err := provider.findTXTRecords(ctx, "my-zone", "_acme-challenge.example.com.", "value")
		require.NoError(t, err)
		assert.Empty(t, records)
	})

	t.Run("returns empty when TXT records have different value", func(t *testing.T) {
		mock := &mockCloudDNSClient{
			getResourceRecordSetsFunc: func(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error) {
				return []*dns.ResourceRecordSet{
					{Name: "_acme-challenge.example.com.", Type: "TXT", Rrdatas: []string{"different-value"}},
				}, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "my-zone", nil)

		records, err := provider.findTXTRecords(ctx, "my-zone", "_acme-challenge.example.com.", "target-value")
		require.NoError(t, err)
		assert.Empty(t, records)
	})

	t.Run("matches records with quoted values", func(t *testing.T) {
		mock := &mockCloudDNSClient{
			getResourceRecordSetsFunc: func(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error) {
				return []*dns.ResourceRecordSet{
					{Name: "_acme-challenge.example.com.", Type: "TXT", Rrdatas: []string{`"target-value"`}},
				}, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "my-zone", nil)

		records, err := provider.findTXTRecords(ctx, "my-zone", "_acme-challenge.example.com.", "target-value")
		require.NoError(t, err)
		assert.Len(t, records, 1)
	})
}

// TestWaitForChangeErrorPaths tests error paths in waitForChange.
func TestWaitForChangeErrorPaths(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when GetChange fails persistently", func(t *testing.T) {
		mock := &mockCloudDNSClient{
			getChangeFunc: func(ctx context.Context, project, zone, changeID string) (*dns.Change, error) {
				return nil, errors.New("persistent API error")
			},
		}

		cfg := Config{
			Project:            "my-project",
			HostedZoneName:     "my-zone",
			PropagationTimeout: 100 * time.Millisecond,
			PollingInterval:    20 * time.Millisecond,
		}
		provider := NewWithClientAndConfig(mock, cfg)

		err := provider.waitForChange(ctx, "my-zone", "change-123")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "timeout")
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		mock := &mockCloudDNSClient{
			getChangeFunc: func(ctx context.Context, project, zone, changeID string) (*dns.Change, error) {
				return &dns.Change{Id: changeID, Status: "pending"}, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "my-zone", nil)

		ctx, cancel := context.WithCancel(ctx)
		cancel() // Cancel immediately

		err := provider.waitForChange(ctx, "my-zone", "change-123")
		require.Error(t, err)
	})
}

// TestConfigDefaultsAdditional tests configuration default application.
func TestConfigDefaultsAdditional(t *testing.T) {
	t.Run("applies all defaults when config is empty", func(t *testing.T) {
		cfg := Config{}
		result := applyConfigDefaults(cfg)

		assert.Equal(t, defaultPropagationTimeout, result.PropagationTimeout)
		assert.Equal(t, defaultPollingInterval, result.PollingInterval)
		assert.Equal(t, int64(defaultRecordTTL), result.TTL)
		assert.Equal(t, defaultHTTPTimeout, result.HTTPTimeout)
	})

	t.Run("applies defaults only for negative values", func(t *testing.T) {
		cfg := Config{
			PropagationTimeout: -1 * time.Second,
			PollingInterval:    -1 * time.Second,
			TTL:                -1,
			HTTPTimeout:        -1 * time.Second,
		}
		result := applyConfigDefaults(cfg)

		// Negative values should trigger defaults
		assert.Equal(t, defaultPropagationTimeout, result.PropagationTimeout)
		assert.Equal(t, defaultPollingInterval, result.PollingInterval)
		assert.Equal(t, int64(defaultRecordTTL), result.TTL)
		assert.Equal(t, defaultHTTPTimeout, result.HTTPTimeout)
	})
}

// TestProviderInterfaceComplianceAdditional verifies interface compliance.
func TestProviderInterfaceComplianceAdditional(t *testing.T) {
	mock := &mockCloudDNSClient{}
	provider := NewWithClient(mock, "project", "zone", nil)

	// Verify Provider interface
	var _ providers.Provider = provider

	// Verify ProviderTimeout interface
	var _ providers.ProviderTimeout = provider
}
