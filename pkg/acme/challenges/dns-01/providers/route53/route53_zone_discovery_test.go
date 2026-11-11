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

package route53

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers"
)

// TestGetHostedZoneIDDiscoveryPaths tests zone discovery code paths
// by using real DNS lookups for well-known domains.
func TestGetHostedZoneIDDiscoveryPaths(t *testing.T) {
	ctx := context.Background()

	t.Run("returns configured zone ID without API call", func(t *testing.T) {
		listZonesCalled := false
		mock := &mockRoute53Client{
			listZonesByNameFunc: func(ctx context.Context, params *route53.ListHostedZonesByNameInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error) {
				listZonesCalled = true
				return nil, nil
			},
		}

		provider := NewWithClient(mock, "Z123456", nil)

		zoneID, err := provider.getHostedZoneID(ctx, "_acme-challenge.example.com.")
		require.NoError(t, err)
		assert.Equal(t, "Z123456", zoneID)
		assert.False(t, listZonesCalled, "ListHostedZonesByName should not be called when zone ID is configured")
	})

	t.Run("returns error when ListHostedZonesByName fails after DNS lookup", func(t *testing.T) {
		providers.ClearZoneCache()

		apiCallCount := 0
		mock := &mockRoute53Client{
			listZonesByNameFunc: func(ctx context.Context, params *route53.ListHostedZonesByNameInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error) {
				apiCallCount++
				return nil, errors.New("API authentication error")
			},
		}

		// Use default nameservers for real DNS lookups
		provider := newDiscoveryProvider(mock, "")

		// Use a real domain that will succeed in DNS lookup
		_, err := provider.getHostedZoneID(ctx, "_acme-challenge.google.com.")

		// This should error because ListHostedZonesByName fails
		require.Error(t, err)
		assert.Contains(t, err.Error(), "API authentication error")
		assert.Greater(t, apiCallCount, 0, "ListHostedZonesByName should have been called")
	})

	t.Run("returns ErrZoneNotFound when no matching zones exist after DNS lookup", func(t *testing.T) {
		providers.ClearZoneCache()

		mock := &mockRoute53Client{
			listZonesByNameFunc: func(ctx context.Context, params *route53.ListHostedZonesByNameInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error) {
				// Return zones that don't match the discovered zone
				return &route53.ListHostedZonesByNameOutput{
					HostedZones: []types.HostedZone{
						{
							Id:   aws.String("/hostedzone/Z123"),
							Name: aws.String("other.com."),
							Config: &types.HostedZoneConfig{
								PrivateZone: false,
							},
						},
					},
				}, nil
			},
		}

		provider := newDiscoveryProvider(mock, "")

		// Use a real domain for DNS lookup
		_, err := provider.getHostedZoneID(ctx, "_acme-challenge.google.com.")

		// The DNS lookup will find google.com zone, but our mock returns no matching zones
		require.Error(t, err)
		assert.Equal(t, providers.ErrZoneNotFound, err)
	})

	t.Run("filters out private zones and selects public zone", func(t *testing.T) {
		providers.ClearZoneCache()

		mock := &mockRoute53Client{
			listZonesByNameFunc: func(ctx context.Context, params *route53.ListHostedZonesByNameInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error) {
				// Return both private and public zones
				return &route53.ListHostedZonesByNameOutput{
					HostedZones: []types.HostedZone{
						{
							Id:   aws.String("/hostedzone/PRIVATE123"),
							Name: aws.String("google.com."),
							Config: &types.HostedZoneConfig{
								PrivateZone: true,
							},
						},
						{
							Id:   aws.String("/hostedzone/PUBLIC456"),
							Name: aws.String("google.com."),
							Config: &types.HostedZoneConfig{
								PrivateZone: false,
							},
						},
					},
				}, nil
			},
		}

		provider := newDiscoveryProvider(mock, "")

		zoneID, err := provider.getHostedZoneID(ctx, "_acme-challenge.google.com.")

		require.NoError(t, err)
		// Should select the public zone, and strip the prefix
		assert.Equal(t, "PUBLIC456", zoneID)
	})

	t.Run("strips hostedzone prefix from zone ID", func(t *testing.T) {
		providers.ClearZoneCache()

		mock := &mockRoute53Client{
			listZonesByNameFunc: func(ctx context.Context, params *route53.ListHostedZonesByNameInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error) {
				return &route53.ListHostedZonesByNameOutput{
					HostedZones: []types.HostedZone{
						{
							Id:   aws.String("/hostedzone/Z789ABC"),
							Name: aws.String("google.com."),
							Config: &types.HostedZoneConfig{
								PrivateZone: false,
							},
						},
					},
				}, nil
			},
		}

		provider := newDiscoveryProvider(mock, "")

		zoneID, err := provider.getHostedZoneID(ctx, "_acme-challenge.google.com.")

		require.NoError(t, err)
		assert.Equal(t, "Z789ABC", zoneID)
		assert.NotContains(t, zoneID, "/hostedzone/")
	})

	t.Run("selects matching zone when multiple public zones exist", func(t *testing.T) {
		providers.ClearZoneCache()

		mock := &mockRoute53Client{
			listZonesByNameFunc: func(ctx context.Context, params *route53.ListHostedZonesByNameInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error) {
				return &route53.ListHostedZonesByNameOutput{
					HostedZones: []types.HostedZone{
						{
							Id:   aws.String("/hostedzone/FIRST123"),
							Name: aws.String("google.com."),
							Config: &types.HostedZoneConfig{
								PrivateZone: false,
							},
						},
						{
							Id:   aws.String("/hostedzone/SECOND456"),
							Name: aws.String("google.com."),
							Config: &types.HostedZoneConfig{
								PrivateZone: false,
							},
						},
					},
				}, nil
			},
		}

		provider := newDiscoveryProvider(mock, "")

		zoneID, err := provider.getHostedZoneID(ctx, "_acme-challenge.google.com.")

		require.NoError(t, err)
		// Both zones match, either one is acceptable
		assert.True(t, zoneID == "FIRST123" || zoneID == "SECOND456")
	})

	t.Run("returns ErrZoneNotFound when all zones are private", func(t *testing.T) {
		providers.ClearZoneCache()

		mock := &mockRoute53Client{
			listZonesByNameFunc: func(ctx context.Context, params *route53.ListHostedZonesByNameInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error) {
				// Return only private zones
				return &route53.ListHostedZonesByNameOutput{
					HostedZones: []types.HostedZone{
						{
							Id:   aws.String("/hostedzone/PRIVATE1"),
							Name: aws.String("google.com."),
							Config: &types.HostedZoneConfig{
								PrivateZone: true,
							},
						},
						{
							Id:   aws.String("/hostedzone/PRIVATE2"),
							Name: aws.String("google.com."),
							Config: &types.HostedZoneConfig{
								PrivateZone: true,
							},
						},
					},
				}, nil
			},
		}

		provider := newDiscoveryProvider(mock, "")

		_, err := provider.getHostedZoneID(ctx, "_acme-challenge.google.com.")

		require.Error(t, err)
		assert.Equal(t, providers.ErrZoneNotFound, err)
	})
}

// TestZoneDiscoveryWithSubdomainRoute53 tests zone discovery for subdomains.
func TestZoneDiscoveryWithSubdomainRoute53(t *testing.T) {
	ctx := context.Background()

	t.Run("finds parent zone for subdomain", func(t *testing.T) {
		providers.ClearZoneCache()

		mock := &mockRoute53Client{
			listZonesByNameFunc: func(ctx context.Context, params *route53.ListHostedZonesByNameInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error) {
				return &route53.ListHostedZonesByNameOutput{
					HostedZones: []types.HostedZone{
						{
							Id:   aws.String("/hostedzone/GOOGLEZONE"),
							Name: aws.String("google.com."),
							Config: &types.HostedZoneConfig{
								PrivateZone: false,
							},
						},
					},
				}, nil
			},
		}

		provider := newDiscoveryProvider(mock, "")

		// Use a subdomain - DNS lookup will find google.com as the zone
		zoneID, err := provider.getHostedZoneID(ctx, "_acme-challenge.www.google.com.")

		require.NoError(t, err)
		assert.Equal(t, "GOOGLEZONE", zoneID)
	})
}

// TestPresentWithZoneDiscoveryRoute53 tests Present when zone discovery is needed.
func TestPresentWithZoneDiscoveryRoute53(t *testing.T) {
	ctx := context.Background()

	t.Run("discovers zone and creates record", func(t *testing.T) {
		providers.ClearZoneCache()

		var capturedZoneID string
		mock := &mockRoute53Client{
			listZonesByNameFunc: func(ctx context.Context, params *route53.ListHostedZonesByNameInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error) {
				return &route53.ListHostedZonesByNameOutput{
					HostedZones: []types.HostedZone{
						{
							Id:   aws.String("/hostedzone/GOOGLEZONE"),
							Name: aws.String("google.com."),
							Config: &types.HostedZoneConfig{
								PrivateZone: false,
							},
						},
					},
				}, nil
			},
			changeRecordSetsFunc: func(ctx context.Context, params *route53.ChangeResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error) {
				capturedZoneID = *params.HostedZoneId
				return &route53.ChangeResourceRecordSetsOutput{
					ChangeInfo: &types.ChangeInfo{
						Id:     aws.String("change-123"),
						Status: types.ChangeStatusInsync,
					},
				}, nil
			},
		}

		// Provider without configured zone - will use discovery
		provider := newDiscoveryProvider(mock, "")

		err := provider.Present(ctx, "google.com", "_acme-challenge.google.com.", "token-value")
		require.NoError(t, err)
		assert.Equal(t, "GOOGLEZONE", capturedZoneID)
	})
}

// TestCleanUpWithZoneDiscoveryRoute53 tests CleanUp when zone discovery is needed.
// TestZoneDiscoveryWithTimeoutRoute53 tests zone discovery timeout handling.

// TestZoneSelectionWithLongerMatch tests that zone discovery selects the longest matching zone.
func TestZoneSelectionWithLongerMatch(t *testing.T) {
	ctx := context.Background()

	t.Run("selects longest matching zone", func(t *testing.T) {
		providers.ClearZoneCache()

		mock := &mockRoute53Client{
			listZonesByNameFunc: func(ctx context.Context, params *route53.ListHostedZonesByNameInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error) {
				return &route53.ListHostedZonesByNameOutput{
					HostedZones: []types.HostedZone{
						{
							Id:   aws.String("/hostedzone/SHORT"),
							Name: aws.String("com."),
							Config: &types.HostedZoneConfig{
								PrivateZone: false,
							},
						},
						{
							Id:   aws.String("/hostedzone/LONGER"),
							Name: aws.String("google.com."),
							Config: &types.HostedZoneConfig{
								PrivateZone: false,
							},
						},
					},
				}, nil
			},
		}

		provider := newDiscoveryProvider(mock, "")

		zoneID, err := provider.getHostedZoneID(ctx, "_acme-challenge.google.com.")

		require.NoError(t, err)
		// FindBestMatch should select google.com. over com. as it's a longer match
		assert.Equal(t, "LONGER", zoneID)
	})
}

// TestEmptyHostedZonesResponse tests handling of empty zones response.
func TestEmptyHostedZonesResponse(t *testing.T) {
	ctx := context.Background()

	t.Run("returns ErrZoneNotFound when no zones returned", func(t *testing.T) {
		providers.ClearZoneCache()

		mock := &mockRoute53Client{
			listZonesByNameFunc: func(ctx context.Context, params *route53.ListHostedZonesByNameInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error) {
				return &route53.ListHostedZonesByNameOutput{
					HostedZones: []types.HostedZone{}, // Empty
				}, nil
			},
		}

		provider := newDiscoveryProvider(mock, "")

		_, err := provider.getHostedZoneID(ctx, "_acme-challenge.google.com.")

		require.Error(t, err)
		assert.Equal(t, providers.ErrZoneNotFound, err)
	})
}
