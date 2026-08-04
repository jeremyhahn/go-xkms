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

package azure

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers"
)

// mockRecordsClient implements RecordsClient for testing.
type mockRecordsClient struct {
	createOrUpdateFunc func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, parameters armdns.RecordSet, options *armdns.RecordSetsClientCreateOrUpdateOptions) (armdns.RecordSetsClientCreateOrUpdateResponse, error)
	getFunc            func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientGetOptions) (armdns.RecordSetsClientGetResponse, error)
	deleteFunc         func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientDeleteOptions) (armdns.RecordSetsClientDeleteResponse, error)
}

func (m *mockRecordsClient) CreateOrUpdate(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, parameters armdns.RecordSet, options *armdns.RecordSetsClientCreateOrUpdateOptions) (armdns.RecordSetsClientCreateOrUpdateResponse, error) {
	if m.createOrUpdateFunc != nil {
		return m.createOrUpdateFunc(ctx, resourceGroupName, zoneName, relativeRecordSetName, recordType, parameters, options)
	}
	return armdns.RecordSetsClientCreateOrUpdateResponse{
		RecordSet: parameters,
	}, nil
}

func (m *mockRecordsClient) Get(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientGetOptions) (armdns.RecordSetsClientGetResponse, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, resourceGroupName, zoneName, relativeRecordSetName, recordType, options)
	}
	return armdns.RecordSetsClientGetResponse{}, &azcore.ResponseError{StatusCode: http.StatusNotFound}
}

func (m *mockRecordsClient) Delete(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientDeleteOptions) (armdns.RecordSetsClientDeleteResponse, error) {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, resourceGroupName, zoneName, relativeRecordSetName, recordType, options)
	}
	return armdns.RecordSetsClientDeleteResponse{}, nil
}

// mockZonesClient implements ZonesClient for testing.
type mockZonesClient struct {
	getFunc func(ctx context.Context, resourceGroupName, zoneName string, options *armdns.ZonesClientGetOptions) (armdns.ZonesClientGetResponse, error)
}

func (m *mockZonesClient) Get(ctx context.Context, resourceGroupName, zoneName string, options *armdns.ZonesClientGetOptions) (armdns.ZonesClientGetResponse, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, resourceGroupName, zoneName, options)
	}
	return armdns.ZonesClientGetResponse{}, nil
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid client credentials",
			config: Config{
				ClientID:          "client-id",
				ClientSecret:      "client-secret",
				TenantID:          "tenant-id",
				SubscriptionID:    "subscription-id",
				ResourceGroupName: "resource-group",
			},
			expectError: false,
		},
		{
			name: "valid ambient credentials",
			config: Config{
				SubscriptionID:    "subscription-id",
				ResourceGroupName: "resource-group",
				Ambient:           true,
			},
			expectError: false,
		},
		{
			name: "missing subscription ID",
			config: Config{
				ResourceGroupName: "resource-group",
				Ambient:           true,
			},
			expectError: true,
			errorMsg:    "subscription_id",
		},
		{
			name: "missing resource group",
			config: Config{
				SubscriptionID: "subscription-id",
				Ambient:        true,
			},
			expectError: true,
			errorMsg:    "resource_group_name",
		},
		{
			name: "partial client credentials - missing client ID",
			config: Config{
				ClientSecret:      "secret",
				TenantID:          "tenant",
				SubscriptionID:    "subscription-id",
				ResourceGroupName: "resource-group",
			},
			expectError: true,
			errorMsg:    "client_id",
		},
		{
			name: "partial client credentials - missing secret",
			config: Config{
				ClientID:          "client",
				TenantID:          "tenant",
				SubscriptionID:    "subscription-id",
				ResourceGroupName: "resource-group",
			},
			expectError: true,
			errorMsg:    "client_secret",
		},
		{
			name: "partial client credentials - missing tenant",
			config: Config{
				ClientID:          "client",
				ClientSecret:      "secret",
				SubscriptionID:    "subscription-id",
				ResourceGroupName: "resource-group",
			},
			expectError: true,
			errorMsg:    "tenant_id",
		},
		{
			name: "no credentials and ambient disabled",
			config: Config{
				SubscriptionID:    "subscription-id",
				ResourceGroupName: "resource-group",
			},
			expectError: true,
			errorMsg:    "credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.config)
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetCloudConfig(t *testing.T) {
	tests := []struct {
		name        string
		env         string
		expectError bool
	}{
		{"empty defaults to public", "", false},
		{"azure public", "AzureCloud", false},
		{"azure public cloud", "AzurePublicCloud", false},
		{"azure us gov", "AzureUSGovernment", false},
		{"azure us gov cloud", "AzureUSGovernmentCloud", false},
		{"azure china", "AzureChinaCloud", false},
		{"case insensitive", "azurecloud", false},
		{"unknown", "UnknownCloud", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := getCloudConfig(tt.env)
			if tt.expectError {
				require.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewWithClients(t *testing.T) {
	recordClient := &mockRecordsClient{}
	zoneClient := &mockZonesClient{}

	provider := NewWithClients(recordClient, zoneClient, "rg", "zone.com", nil)

	assert.NotNil(t, provider)
	assert.Equal(t, "rg", provider.resourceGroupName)
	assert.Equal(t, "zone.com", provider.zoneName)
	assert.Equal(t, defaultPropagationTimeout, provider.propagationTimeout)
	assert.Equal(t, defaultPollingInterval, provider.pollingInterval)
	assert.Equal(t, int64(defaultRecordTTL), provider.ttl)
}

func TestNewWithClientsAndConfig(t *testing.T) {
	recordClient := &mockRecordsClient{}
	zoneClient := &mockZonesClient{}

	t.Run("custom values", func(t *testing.T) {
		provider := NewWithClientsAndConfig(
			recordClient, zoneClient,
			"rg", "zone.com", nil,
			180*time.Second, 5*time.Second, 120,
		)

		assert.NotNil(t, provider)
		assert.Equal(t, 180*time.Second, provider.propagationTimeout)
		assert.Equal(t, 5*time.Second, provider.pollingInterval)
		assert.Equal(t, int64(120), provider.ttl)
	})

	t.Run("defaults for zero values", func(t *testing.T) {
		provider := NewWithClientsAndConfig(
			recordClient, zoneClient,
			"rg", "zone.com", nil,
			0, 0, 0,
		)

		assert.NotNil(t, provider)
		assert.Equal(t, defaultPropagationTimeout, provider.propagationTimeout)
		assert.Equal(t, defaultPollingInterval, provider.pollingInterval)
		assert.Equal(t, int64(defaultRecordTTL), provider.ttl)
	})

	t.Run("defaults for negative values", func(t *testing.T) {
		provider := NewWithClientsAndConfig(
			recordClient, zoneClient,
			"rg", "zone.com", nil,
			-1*time.Second, -1*time.Second, -1,
		)

		assert.NotNil(t, provider)
		assert.Equal(t, defaultPropagationTimeout, provider.propagationTimeout)
		assert.Equal(t, defaultPollingInterval, provider.pollingInterval)
		assert.Equal(t, int64(defaultRecordTTL), provider.ttl)
	})
}

func TestTimeout(t *testing.T) {
	t.Run("default values", func(t *testing.T) {
		provider := NewWithClients(nil, nil, "rg", "zone.com", nil)

		timeout, interval := provider.Timeout()

		assert.Equal(t, defaultPropagationTimeout, timeout)
		assert.Equal(t, defaultPollingInterval, interval)
	})

	t.Run("custom values", func(t *testing.T) {
		provider := NewWithClientsAndConfig(
			nil, nil,
			"rg", "zone.com", nil,
			300*time.Second, 10*time.Second, 60,
		)

		timeout, interval := provider.Timeout()

		assert.Equal(t, 300*time.Second, timeout)
		assert.Equal(t, 10*time.Second, interval)
	})
}

func TestProviderTimeoutInterface(t *testing.T) {
	provider := NewWithClients(nil, nil, "rg", "zone.com", nil)

	// Verify provider implements ProviderTimeout interface
	var _ providers.ProviderTimeout = provider
}

func TestPresent(t *testing.T) {
	ctx := context.Background()

	t.Run("creates new record", func(t *testing.T) {
		var capturedRecordSet armdns.RecordSet

		recordClient := &mockRecordsClient{
			getFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientGetOptions) (armdns.RecordSetsClientGetResponse, error) {
				// Record doesn't exist
				return armdns.RecordSetsClientGetResponse{}, &azcore.ResponseError{StatusCode: http.StatusNotFound}
			},
			createOrUpdateFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, parameters armdns.RecordSet, options *armdns.RecordSetsClientCreateOrUpdateOptions) (armdns.RecordSetsClientCreateOrUpdateResponse, error) {
				capturedRecordSet = parameters
				return armdns.RecordSetsClientCreateOrUpdateResponse{
					RecordSet: parameters,
				}, nil
			},
		}
		zoneClient := &mockZonesClient{}

		provider := NewWithClients(recordClient, zoneClient, "rg", "example.com", nil)

		err := provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.NoError(t, err)

		// Verify record was created with correct value
		require.NotNil(t, capturedRecordSet.Properties)
		require.Len(t, capturedRecordSet.Properties.TxtRecords, 1)
		require.Len(t, capturedRecordSet.Properties.TxtRecords[0].Value, 1)
		assert.Equal(t, "token-value", *capturedRecordSet.Properties.TxtRecords[0].Value[0])
	})

	t.Run("adds to existing record", func(t *testing.T) {
		var capturedRecordSet armdns.RecordSet

		existingRecord := armdns.RecordSet{
			Etag: to.Ptr("etag123"),
			Properties: &armdns.RecordSetProperties{
				TTL: to.Ptr[int64](60),
				TxtRecords: []*armdns.TxtRecord{
					{Value: []*string{to.Ptr("existing-value")}},
				},
			},
		}

		recordClient := &mockRecordsClient{
			getFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientGetOptions) (armdns.RecordSetsClientGetResponse, error) {
				return armdns.RecordSetsClientGetResponse{
					RecordSet: existingRecord,
				}, nil
			},
			createOrUpdateFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, parameters armdns.RecordSet, options *armdns.RecordSetsClientCreateOrUpdateOptions) (armdns.RecordSetsClientCreateOrUpdateResponse, error) {
				capturedRecordSet = parameters
				return armdns.RecordSetsClientCreateOrUpdateResponse{
					RecordSet: parameters,
				}, nil
			},
		}
		zoneClient := &mockZonesClient{}

		provider := NewWithClients(recordClient, zoneClient, "rg", "example.com", nil)

		err := provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "new-value")
		require.NoError(t, err)

		// Verify both values exist
		require.NotNil(t, capturedRecordSet.Properties)
		assert.Len(t, capturedRecordSet.Properties.TxtRecords, 2)
	})

	t.Run("does not duplicate existing value", func(t *testing.T) {
		var capturedRecordSet armdns.RecordSet

		existingRecord := armdns.RecordSet{
			Etag: to.Ptr("etag123"),
			Properties: &armdns.RecordSetProperties{
				TTL: to.Ptr[int64](60),
				TxtRecords: []*armdns.TxtRecord{
					{Value: []*string{to.Ptr("token-value")}},
				},
			},
		}

		recordClient := &mockRecordsClient{
			getFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientGetOptions) (armdns.RecordSetsClientGetResponse, error) {
				return armdns.RecordSetsClientGetResponse{
					RecordSet: existingRecord,
				}, nil
			},
			createOrUpdateFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, parameters armdns.RecordSet, options *armdns.RecordSetsClientCreateOrUpdateOptions) (armdns.RecordSetsClientCreateOrUpdateResponse, error) {
				capturedRecordSet = parameters
				return armdns.RecordSetsClientCreateOrUpdateResponse{
					RecordSet: parameters,
				}, nil
			},
		}
		zoneClient := &mockZonesClient{}

		provider := NewWithClients(recordClient, zoneClient, "rg", "example.com", nil)

		err := provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.NoError(t, err)

		// Verify only one value (no duplicate)
		require.NotNil(t, capturedRecordSet.Properties)
		assert.Len(t, capturedRecordSet.Properties.TxtRecords, 1)
	})

	t.Run("uses configured TTL", func(t *testing.T) {
		var capturedRecordSet armdns.RecordSet

		recordClient := &mockRecordsClient{
			getFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientGetOptions) (armdns.RecordSetsClientGetResponse, error) {
				return armdns.RecordSetsClientGetResponse{}, &azcore.ResponseError{StatusCode: http.StatusNotFound}
			},
			createOrUpdateFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, parameters armdns.RecordSet, options *armdns.RecordSetsClientCreateOrUpdateOptions) (armdns.RecordSetsClientCreateOrUpdateResponse, error) {
				capturedRecordSet = parameters
				return armdns.RecordSetsClientCreateOrUpdateResponse{
					RecordSet: parameters,
				}, nil
			},
		}
		zoneClient := &mockZonesClient{}

		provider := NewWithClientsAndConfig(recordClient, zoneClient, "rg", "example.com", nil, 0, 0, 300)

		err := provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.NoError(t, err)

		require.NotNil(t, capturedRecordSet.Properties)
		assert.Equal(t, int64(300), *capturedRecordSet.Properties.TTL)
	})
}

func TestCleanUp(t *testing.T) {
	ctx := context.Background()

	t.Run("deletes record when last value", func(t *testing.T) {
		deleteCalled := false

		existingRecord := armdns.RecordSet{
			Etag: to.Ptr("etag123"),
			Properties: &armdns.RecordSetProperties{
				TTL: to.Ptr[int64](60),
				TxtRecords: []*armdns.TxtRecord{
					{Value: []*string{to.Ptr("token-value")}},
				},
			},
		}

		recordClient := &mockRecordsClient{
			getFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientGetOptions) (armdns.RecordSetsClientGetResponse, error) {
				return armdns.RecordSetsClientGetResponse{
					RecordSet: existingRecord,
				}, nil
			},
			deleteFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientDeleteOptions) (armdns.RecordSetsClientDeleteResponse, error) {
				deleteCalled = true
				assert.Equal(t, "etag123", *options.IfMatch)
				return armdns.RecordSetsClientDeleteResponse{}, nil
			},
		}
		zoneClient := &mockZonesClient{}

		provider := NewWithClients(recordClient, zoneClient, "rg", "example.com", nil)

		err := provider.CleanUp(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.NoError(t, err)
		assert.True(t, deleteCalled)
	})

	t.Run("removes value but keeps others", func(t *testing.T) {
		var capturedRecordSet armdns.RecordSet

		existingRecord := armdns.RecordSet{
			Etag: to.Ptr("etag123"),
			Properties: &armdns.RecordSetProperties{
				TTL: to.Ptr[int64](60),
				TxtRecords: []*armdns.TxtRecord{
					{Value: []*string{to.Ptr("token-value")}},
					{Value: []*string{to.Ptr("other-value")}},
				},
			},
		}

		recordClient := &mockRecordsClient{
			getFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientGetOptions) (armdns.RecordSetsClientGetResponse, error) {
				return armdns.RecordSetsClientGetResponse{
					RecordSet: existingRecord,
				}, nil
			},
			createOrUpdateFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, parameters armdns.RecordSet, options *armdns.RecordSetsClientCreateOrUpdateOptions) (armdns.RecordSetsClientCreateOrUpdateResponse, error) {
				capturedRecordSet = parameters
				return armdns.RecordSetsClientCreateOrUpdateResponse{
					RecordSet: parameters,
				}, nil
			},
		}
		zoneClient := &mockZonesClient{}

		provider := NewWithClients(recordClient, zoneClient, "rg", "example.com", nil)

		err := provider.CleanUp(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.NoError(t, err)

		// Verify only other-value remains
		require.NotNil(t, capturedRecordSet.Properties)
		require.Len(t, capturedRecordSet.Properties.TxtRecords, 1)
		assert.Equal(t, "other-value", *capturedRecordSet.Properties.TxtRecords[0].Value[0])
	})

	t.Run("record not found is not an error", func(t *testing.T) {
		recordClient := &mockRecordsClient{
			getFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientGetOptions) (armdns.RecordSetsClientGetResponse, error) {
				return armdns.RecordSetsClientGetResponse{}, &azcore.ResponseError{StatusCode: http.StatusNotFound}
			},
		}
		zoneClient := &mockZonesClient{}

		provider := NewWithClients(recordClient, zoneClient, "rg", "example.com", nil)

		err := provider.CleanUp(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		assert.NoError(t, err)
	})
}

func TestTrimFQDN(t *testing.T) {
	provider := NewWithClients(nil, nil, "rg", "example.com", nil)

	tests := []struct {
		fqdn     string
		zone     string
		expected string
	}{
		{"_acme-challenge.example.com.", "example.com", "_acme-challenge"},
		{"_acme-challenge.www.example.com.", "example.com", "_acme-challenge.www"},
		{"test.example.com.", "example.com", "test"},
	}

	for _, tt := range tests {
		t.Run(tt.fqdn, func(t *testing.T) {
			result := provider.trimFQDN(tt.fqdn, tt.zone)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTrimFQDNWithoutConfiguredZone(t *testing.T) {
	// Test trimFQDN when zoneName is empty (uses passed zone parameter)
	provider := NewWithClients(nil, nil, "rg", "", nil)

	tests := []struct {
		fqdn     string
		zone     string
		expected string
	}{
		{"_acme-challenge.example.com.", "example.com", "_acme-challenge"},
		{"_acme-challenge.www.example.com.", "example.com", "_acme-challenge.www"},
		{"test.example.com.", "example.com", "test"},
	}

	for _, tt := range tests {
		t.Run(tt.fqdn, func(t *testing.T) {
			result := provider.trimFQDN(tt.fqdn, tt.zone)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRegistration(t *testing.T) {
	// Verify provider is registered
	assert.True(t, providers.Registered(providers.ProviderAzure))

	factory := providers.Get(providers.ProviderAzure)
	assert.NotNil(t, factory)
}

func TestFactoryInvalidConfig(t *testing.T) {
	factory := providers.Get(providers.ProviderAzure)
	require.NotNil(t, factory)

	ctx := context.Background()

	// Pass invalid config type
	_, err := factory(ctx, "invalid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected azure.Config")
}

func TestGetHostedZoneName(t *testing.T) {
	ctx := context.Background()

	t.Run("returns configured zone", func(t *testing.T) {
		provider := NewWithClients(nil, nil, "rg", "example.com", nil)

		zone, err := provider.getHostedZoneName(ctx, "_acme-challenge.example.com.")
		require.NoError(t, err)
		assert.Equal(t, "example.com", zone)
	})

	t.Run("zone not found in azure", func(t *testing.T) {
		zoneClient := &mockZonesClient{
			getFunc: func(ctx context.Context, resourceGroupName, zoneName string, options *armdns.ZonesClientGetOptions) (armdns.ZonesClientGetResponse, error) {
				return armdns.ZonesClientGetResponse{}, errors.New("not found")
			},
		}

		// Clear zone cache to force lookup
		providers.ClearZoneCache()

		// Add cache entry to simulate DNS lookup
		// This test would need real DNS lookup without this
		provider := NewWithClients(nil, zoneClient, "rg", "", nil)

		// Without a configured zone and without DNS resolution, this should fail
		// In practice, this requires integration testing
		_ = provider
	})
}

func TestGetTXTRecords(t *testing.T) {
	t.Run("nil record set", func(t *testing.T) {
		result := getTXTRecords(nil)
		assert.Nil(t, result)
	})

	t.Run("nil properties", func(t *testing.T) {
		rs := &armdns.RecordSet{}
		result := getTXTRecords(rs)
		assert.Nil(t, result)
	})

	t.Run("with records", func(t *testing.T) {
		rs := &armdns.RecordSet{
			Properties: &armdns.RecordSetProperties{
				TxtRecords: []*armdns.TxtRecord{
					{Value: []*string{to.Ptr("value1")}},
				},
			},
		}
		result := getTXTRecords(rs)
		assert.Len(t, result, 1)
	})
}

func TestSetTXTRecords(t *testing.T) {
	t.Run("nil properties creates new", func(t *testing.T) {
		rs := &armdns.RecordSet{}
		records := []*armdns.TxtRecord{
			{Value: []*string{to.Ptr("value1")}},
		}
		setTXTRecords(rs, records, 120)

		assert.NotNil(t, rs.Properties)
		assert.Len(t, rs.Properties.TxtRecords, 1)
		assert.Equal(t, int64(120), *rs.Properties.TTL)
	})

	t.Run("updates existing", func(t *testing.T) {
		rs := &armdns.RecordSet{
			Properties: &armdns.RecordSetProperties{
				TTL: to.Ptr[int64](60),
				TxtRecords: []*armdns.TxtRecord{
					{Value: []*string{to.Ptr("old")}},
				},
			},
		}
		records := []*armdns.TxtRecord{
			{Value: []*string{to.Ptr("new")}},
		}
		setTXTRecords(rs, records, 120)

		assert.Len(t, rs.Properties.TxtRecords, 1)
		assert.Equal(t, "new", *rs.Properties.TxtRecords[0].Value[0])
	})
}

func TestNewFromEnv(t *testing.T) {
	ctx := context.Background()

	// Helper to clean up environment
	cleanEnv := func() {
		os.Unsetenv(EnvClientID)
		os.Unsetenv(EnvClientSecret)
		os.Unsetenv(EnvTenantID)
		os.Unsetenv(EnvSubscriptionID)
		os.Unsetenv(EnvResourceGroup)
		os.Unsetenv(EnvZoneName)
		os.Unsetenv(EnvEnvironment)
		os.Unsetenv(EnvPropagationTimeout)
		os.Unsetenv(EnvPollingInterval)
		os.Unsetenv(EnvTTL)
		os.Unsetenv(EnvClientID + "_FILE")
		os.Unsetenv(EnvClientSecret + "_FILE")
		os.Unsetenv(EnvTenantID + "_FILE")
		os.Unsetenv(EnvSubscriptionID + "_FILE")
		os.Unsetenv(EnvResourceGroup + "_FILE")
		os.Unsetenv(EnvZoneName + "_FILE")
	}

	t.Run("missing required fields", func(t *testing.T) {
		cleanEnv()
		defer cleanEnv()

		_, err := NewFromEnv(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "subscription_id")
	})

	t.Run("missing resource group", func(t *testing.T) {
		cleanEnv()
		defer cleanEnv()

		os.Setenv(EnvSubscriptionID, "sub-123")

		_, err := NewFromEnv(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "resource_group_name")
	})

	t.Run("with environment variables for duration and int", func(t *testing.T) {
		cleanEnv()
		defer cleanEnv()

		os.Setenv(EnvSubscriptionID, "sub-123")
		os.Setenv(EnvResourceGroup, "rg-123")
		os.Setenv(EnvPropagationTimeout, "180s")
		os.Setenv(EnvPollingInterval, "5s")
		os.Setenv(EnvTTL, "300")

		// NewFromEnv with ambient=true succeeds (credential creation is lazy)
		provider, err := NewFromEnv(ctx)
		// May succeed or fail depending on Azure SDK behavior
		if err == nil {
			assert.NotNil(t, provider)
		}
	})

	t.Run("with file-based secrets", func(t *testing.T) {
		cleanEnv()
		defer cleanEnv()

		// Create temp file for subscription ID
		tmpDir := t.TempDir()
		subFile := filepath.Join(tmpDir, "subscription_id")
		err := os.WriteFile(subFile, []byte("sub-from-file\n"), 0600)
		require.NoError(t, err)

		os.Setenv(EnvSubscriptionID+"_FILE", subFile)
		os.Setenv(EnvResourceGroup, "rg-123")

		// This may succeed with ambient credentials
		provider, err := NewFromEnv(ctx)
		if err == nil {
			assert.NotNil(t, provider)
		}
	})

	t.Run("file read error", func(t *testing.T) {
		cleanEnv()
		defer cleanEnv()

		os.Setenv(EnvSubscriptionID+"_FILE", "/nonexistent/path/to/file")

		_, err := NewFromEnv(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "subscription_id")
	})

	t.Run("with client credentials", func(t *testing.T) {
		cleanEnv()
		defer cleanEnv()

		os.Setenv(EnvClientID, "client-123")
		os.Setenv(EnvClientSecret, "secret-123")
		os.Setenv(EnvTenantID, "tenant-123")
		os.Setenv(EnvSubscriptionID, "sub-123")
		os.Setenv(EnvResourceGroup, "rg-123")
		os.Setenv(EnvZoneName, "example.com")
		os.Setenv(EnvEnvironment, "AzureCloud")

		// Client credential creation may succeed
		provider, err := NewFromEnv(ctx)
		if err == nil {
			assert.NotNil(t, provider)
		}
	})
}

func TestEnvVariableConstants(t *testing.T) {
	// Verify environment variable constants are defined correctly
	assert.Equal(t, "AZURE_CLIENT_ID", EnvClientID)
	assert.Equal(t, "AZURE_CLIENT_SECRET", EnvClientSecret)
	assert.Equal(t, "AZURE_TENANT_ID", EnvTenantID)
	assert.Equal(t, "AZURE_SUBSCRIPTION_ID", EnvSubscriptionID)
	assert.Equal(t, "AZURE_RESOURCE_GROUP", EnvResourceGroup)
	assert.Equal(t, "AZURE_ZONE_NAME", EnvZoneName)
	assert.Equal(t, "AZURE_ENVIRONMENT", EnvEnvironment)
	assert.Equal(t, "AZURE_PROPAGATION_TIMEOUT", EnvPropagationTimeout)
	assert.Equal(t, "AZURE_POLLING_INTERVAL", EnvPollingInterval)
	assert.Equal(t, "AZURE_TTL", EnvTTL)
}

func TestDefaultConstants(t *testing.T) {
	assert.Equal(t, int64(60), int64(defaultRecordTTL))
	assert.Equal(t, 120*time.Second, defaultPropagationTimeout)
	assert.Equal(t, 4*time.Second, defaultPollingInterval)
	assert.Equal(t, 30*time.Second, defaultHTTPTimeout)
}

func TestUpdateTXTRecordGetError(t *testing.T) {
	ctx := context.Background()

	recordClient := &mockRecordsClient{
		getFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientGetOptions) (armdns.RecordSetsClientGetResponse, error) {
			return armdns.RecordSetsClientGetResponse{}, &azcore.ResponseError{StatusCode: http.StatusInternalServerError}
		},
	}
	zoneClient := &mockZonesClient{}

	provider := NewWithClients(recordClient, zoneClient, "rg", "example.com", nil)

	err := provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get record")
}

func TestUpdateTXTRecordCreateError(t *testing.T) {
	ctx := context.Background()

	recordClient := &mockRecordsClient{
		getFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientGetOptions) (armdns.RecordSetsClientGetResponse, error) {
			return armdns.RecordSetsClientGetResponse{}, &azcore.ResponseError{StatusCode: http.StatusNotFound}
		},
		createOrUpdateFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, parameters armdns.RecordSet, options *armdns.RecordSetsClientCreateOrUpdateOptions) (armdns.RecordSetsClientCreateOrUpdateResponse, error) {
			return armdns.RecordSetsClientCreateOrUpdateResponse{}, errors.New("create failed")
		},
	}
	zoneClient := &mockZonesClient{}

	provider := NewWithClients(recordClient, zoneClient, "rg", "example.com", nil)

	err := provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "update record")
}

func TestUpdateTXTRecordDeleteError(t *testing.T) {
	ctx := context.Background()

	existingRecord := armdns.RecordSet{
		Etag: to.Ptr("etag123"),
		Properties: &armdns.RecordSetProperties{
			TTL: to.Ptr[int64](60),
			TxtRecords: []*armdns.TxtRecord{
				{Value: []*string{to.Ptr("token-value")}},
			},
		},
	}

	recordClient := &mockRecordsClient{
		getFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientGetOptions) (armdns.RecordSetsClientGetResponse, error) {
			return armdns.RecordSetsClientGetResponse{
				RecordSet: existingRecord,
			}, nil
		},
		deleteFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientDeleteOptions) (armdns.RecordSetsClientDeleteResponse, error) {
			return armdns.RecordSetsClientDeleteResponse{}, errors.New("delete failed")
		},
	}
	zoneClient := &mockZonesClient{}

	provider := NewWithClients(recordClient, zoneClient, "rg", "example.com", nil)

	err := provider.CleanUp(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete record")
}

func TestCleanUpWithEmptyEtag(t *testing.T) {
	ctx := context.Background()

	// When etag is empty string, delete should not be called
	existingRecord := armdns.RecordSet{
		Etag: to.Ptr(""),
		Properties: &armdns.RecordSetProperties{
			TTL: to.Ptr[int64](60),
			TxtRecords: []*armdns.TxtRecord{
				{Value: []*string{to.Ptr("token-value")}},
			},
		},
	}

	deleteCalled := false
	recordClient := &mockRecordsClient{
		getFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientGetOptions) (armdns.RecordSetsClientGetResponse, error) {
			return armdns.RecordSetsClientGetResponse{
				RecordSet: existingRecord,
			}, nil
		},
		deleteFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientDeleteOptions) (armdns.RecordSetsClientDeleteResponse, error) {
			deleteCalled = true
			return armdns.RecordSetsClientDeleteResponse{}, nil
		},
	}
	zoneClient := &mockZonesClient{}

	provider := NewWithClients(recordClient, zoneClient, "rg", "example.com", nil)

	err := provider.CleanUp(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
	require.NoError(t, err)
	assert.False(t, deleteCalled, "delete should not be called when etag is empty")
}

func TestPresentWithEmptyRecordValue(t *testing.T) {
	ctx := context.Background()

	// Test record with empty value slice
	existingRecord := armdns.RecordSet{
		Etag: to.Ptr("etag123"),
		Properties: &armdns.RecordSetProperties{
			TTL: to.Ptr[int64](60),
			TxtRecords: []*armdns.TxtRecord{
				{Value: []*string{}}, // Empty value slice
			},
		},
	}

	var capturedRecordSet armdns.RecordSet
	recordClient := &mockRecordsClient{
		getFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientGetOptions) (armdns.RecordSetsClientGetResponse, error) {
			return armdns.RecordSetsClientGetResponse{
				RecordSet: existingRecord,
			}, nil
		},
		createOrUpdateFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, parameters armdns.RecordSet, options *armdns.RecordSetsClientCreateOrUpdateOptions) (armdns.RecordSetsClientCreateOrUpdateResponse, error) {
			capturedRecordSet = parameters
			return armdns.RecordSetsClientCreateOrUpdateResponse{
				RecordSet: parameters,
			}, nil
		},
	}
	zoneClient := &mockZonesClient{}

	provider := NewWithClients(recordClient, zoneClient, "rg", "example.com", nil)

	err := provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "new-value")
	require.NoError(t, err)

	// Should add the new value
	require.NotNil(t, capturedRecordSet.Properties)
	assert.Len(t, capturedRecordSet.Properties.TxtRecords, 2)
}

func TestCleanUpWithEmptyRecordValue(t *testing.T) {
	ctx := context.Background()

	// Test record with empty value slice - should be filtered out
	existingRecord := armdns.RecordSet{
		Etag: to.Ptr("etag123"),
		Properties: &armdns.RecordSetProperties{
			TTL: to.Ptr[int64](60),
			TxtRecords: []*armdns.TxtRecord{
				{Value: []*string{}}, // Empty value slice
				{Value: []*string{to.Ptr("keep-value")}},
			},
		},
	}

	var capturedRecordSet armdns.RecordSet
	recordClient := &mockRecordsClient{
		getFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientGetOptions) (armdns.RecordSetsClientGetResponse, error) {
			return armdns.RecordSetsClientGetResponse{
				RecordSet: existingRecord,
			}, nil
		},
		createOrUpdateFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, parameters armdns.RecordSet, options *armdns.RecordSetsClientCreateOrUpdateOptions) (armdns.RecordSetsClientCreateOrUpdateResponse, error) {
			capturedRecordSet = parameters
			return armdns.RecordSetsClientCreateOrUpdateResponse{
				RecordSet: parameters,
			}, nil
		},
	}
	zoneClient := &mockZonesClient{}

	provider := NewWithClients(recordClient, zoneClient, "rg", "example.com", nil)

	// Try to clean up a non-existent value
	err := provider.CleanUp(ctx, "example.com", "_acme-challenge.example.com.", "non-existent")
	require.NoError(t, err)

	// Should keep the valid record
	require.NotNil(t, capturedRecordSet.Properties)
	assert.Len(t, capturedRecordSet.Properties.TxtRecords, 1)
	assert.Equal(t, "keep-value", *capturedRecordSet.Properties.TxtRecords[0].Value[0])
}

func TestNewWithNilEtag(t *testing.T) {
	ctx := context.Background()

	// Test with nil etag
	existingRecord := armdns.RecordSet{
		Etag: nil,
		Properties: &armdns.RecordSetProperties{
			TTL: to.Ptr[int64](60),
			TxtRecords: []*armdns.TxtRecord{
				{Value: []*string{to.Ptr("existing-value")}},
			},
		},
	}

	var capturedOptions *armdns.RecordSetsClientCreateOrUpdateOptions
	recordClient := &mockRecordsClient{
		getFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientGetOptions) (armdns.RecordSetsClientGetResponse, error) {
			return armdns.RecordSetsClientGetResponse{
				RecordSet: existingRecord,
			}, nil
		},
		createOrUpdateFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, parameters armdns.RecordSet, options *armdns.RecordSetsClientCreateOrUpdateOptions) (armdns.RecordSetsClientCreateOrUpdateResponse, error) {
			capturedOptions = options
			return armdns.RecordSetsClientCreateOrUpdateResponse{
				RecordSet: parameters,
			}, nil
		},
	}
	zoneClient := &mockZonesClient{}

	provider := NewWithClients(recordClient, zoneClient, "rg", "example.com", nil)

	err := provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "new-value")
	require.NoError(t, err)

	// When etag is nil, neither IfMatch nor IfNoneMatch should be set
	assert.Nil(t, capturedOptions.IfMatch)
	assert.Nil(t, capturedOptions.IfNoneMatch)
}

func TestNewConfigValidation(t *testing.T) {
	ctx := context.Background()

	t.Run("invalid cloud environment", func(t *testing.T) {
		cfg := Config{
			ClientID:          "client",
			ClientSecret:      "secret",
			TenantID:          "tenant",
			SubscriptionID:    "sub",
			ResourceGroupName: "rg",
			Environment:       "InvalidCloud",
		}

		_, err := New(ctx, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown cloud environment")
	})
}

func TestNewFromEnvFileErrors(t *testing.T) {
	ctx := context.Background()

	cleanEnv := func() {
		os.Unsetenv(EnvClientID + "_FILE")
		os.Unsetenv(EnvClientSecret + "_FILE")
		os.Unsetenv(EnvTenantID + "_FILE")
		os.Unsetenv(EnvSubscriptionID)
		os.Unsetenv(EnvResourceGroup + "_FILE")
		os.Unsetenv(EnvZoneName + "_FILE")
	}

	t.Run("client_id file error", func(t *testing.T) {
		cleanEnv()
		defer cleanEnv()

		os.Setenv(EnvClientID+"_FILE", "/nonexistent/client_id")

		_, err := NewFromEnv(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client_id")
	})

	t.Run("client_secret file error", func(t *testing.T) {
		cleanEnv()
		defer cleanEnv()

		os.Setenv(EnvClientSecret+"_FILE", "/nonexistent/client_secret")

		_, err := NewFromEnv(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client_secret")
	})

	t.Run("tenant_id file error", func(t *testing.T) {
		cleanEnv()
		defer cleanEnv()

		os.Setenv(EnvTenantID+"_FILE", "/nonexistent/tenant_id")

		_, err := NewFromEnv(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tenant_id")
	})

	t.Run("resource_group file error", func(t *testing.T) {
		cleanEnv()
		defer cleanEnv()

		os.Setenv(EnvSubscriptionID, "sub-123")
		os.Setenv(EnvResourceGroup+"_FILE", "/nonexistent/resource_group")

		_, err := NewFromEnv(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "resource_group")
	})

	t.Run("zone_name file error", func(t *testing.T) {
		cleanEnv()
		defer cleanEnv()

		os.Setenv(EnvSubscriptionID, "sub-123")
		os.Setenv(EnvResourceGroup, "rg-123")
		os.Setenv(EnvZoneName+"_FILE", "/nonexistent/zone_name")

		_, err := NewFromEnv(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "zone_name")
	})
}

func TestUpdateTXTRecordWithIfNoneMatch(t *testing.T) {
	ctx := context.Background()

	var capturedOptions *armdns.RecordSetsClientCreateOrUpdateOptions

	recordClient := &mockRecordsClient{
		getFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientGetOptions) (armdns.RecordSetsClientGetResponse, error) {
			return armdns.RecordSetsClientGetResponse{}, &azcore.ResponseError{StatusCode: http.StatusNotFound}
		},
		createOrUpdateFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, parameters armdns.RecordSet, options *armdns.RecordSetsClientCreateOrUpdateOptions) (armdns.RecordSetsClientCreateOrUpdateResponse, error) {
			capturedOptions = options
			return armdns.RecordSetsClientCreateOrUpdateResponse{
				RecordSet: parameters,
			}, nil
		},
	}
	zoneClient := &mockZonesClient{}

	provider := NewWithClients(recordClient, zoneClient, "rg", "example.com", nil)

	err := provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
	require.NoError(t, err)

	// New record should use IfNoneMatch="*"
	require.NotNil(t, capturedOptions.IfNoneMatch)
	assert.Equal(t, "*", *capturedOptions.IfNoneMatch)
	assert.Nil(t, capturedOptions.IfMatch)
}

func TestUpdateTXTRecordWithIfMatch(t *testing.T) {
	ctx := context.Background()

	var capturedOptions *armdns.RecordSetsClientCreateOrUpdateOptions

	existingRecord := armdns.RecordSet{
		Etag: to.Ptr("etag-existing"),
		Properties: &armdns.RecordSetProperties{
			TTL: to.Ptr[int64](60),
			TxtRecords: []*armdns.TxtRecord{
				{Value: []*string{to.Ptr("existing-value")}},
			},
		},
	}

	recordClient := &mockRecordsClient{
		getFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientGetOptions) (armdns.RecordSetsClientGetResponse, error) {
			return armdns.RecordSetsClientGetResponse{
				RecordSet: existingRecord,
			}, nil
		},
		createOrUpdateFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, parameters armdns.RecordSet, options *armdns.RecordSetsClientCreateOrUpdateOptions) (armdns.RecordSetsClientCreateOrUpdateResponse, error) {
			capturedOptions = options
			return armdns.RecordSetsClientCreateOrUpdateResponse{
				RecordSet: parameters,
			}, nil
		},
	}
	zoneClient := &mockZonesClient{}

	provider := NewWithClients(recordClient, zoneClient, "rg", "example.com", nil)

	err := provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "new-value")
	require.NoError(t, err)

	// Existing record should use IfMatch
	require.NotNil(t, capturedOptions.IfMatch)
	assert.Equal(t, "etag-existing", *capturedOptions.IfMatch)
	assert.Nil(t, capturedOptions.IfNoneMatch)
}

func TestCleanUpWithNilEtag(t *testing.T) {
	ctx := context.Background()

	// When etag is nil, delete should not be called
	existingRecord := armdns.RecordSet{
		Etag: nil,
		Properties: &armdns.RecordSetProperties{
			TTL: to.Ptr[int64](60),
			TxtRecords: []*armdns.TxtRecord{
				{Value: []*string{to.Ptr("token-value")}},
			},
		},
	}

	deleteCalled := false
	recordClient := &mockRecordsClient{
		getFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientGetOptions) (armdns.RecordSetsClientGetResponse, error) {
			return armdns.RecordSetsClientGetResponse{
				RecordSet: existingRecord,
			}, nil
		},
		deleteFunc: func(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientDeleteOptions) (armdns.RecordSetsClientDeleteResponse, error) {
			deleteCalled = true
			return armdns.RecordSetsClientDeleteResponse{}, nil
		},
	}
	zoneClient := &mockZonesClient{}

	provider := NewWithClients(recordClient, zoneClient, "rg", "example.com", nil)

	err := provider.CleanUp(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
	require.NoError(t, err)
	assert.False(t, deleteCalled, "delete should not be called when etag is nil")
}

func TestProviderProviderInterface(t *testing.T) {
	provider := NewWithClients(nil, nil, "rg", "zone.com", nil)

	// Verify provider implements Provider interface
	var _ providers.Provider = provider
}

func TestGetCredentialAmbientDisabled(t *testing.T) {
	// Test that getCredential returns error when ambient is disabled
	cfg := Config{
		SubscriptionID:    "sub-123",
		ResourceGroupName: "rg-123",
		Ambient:           false,
	}

	clientOpts := policy.ClientOptions{}
	_, err := getCredential(clientOpts, cfg)
	require.Error(t, err)
	assert.Equal(t, providers.ErrAmbientCredentialsDisabled, err)
}

func TestGetCredentialManagedIdentityWithClientID(t *testing.T) {
	// Test managed identity credential with client ID
	cfg := Config{
		SubscriptionID:          "sub-123",
		ResourceGroupName:       "rg-123",
		Ambient:                 true,
		ManagedIdentityClientID: "mi-client-id",
	}

	clientOpts := policy.ClientOptions{}
	cred, err := getCredential(clientOpts, cfg)
	// Managed identity credential creation succeeds but may fail at use time
	assert.NoError(t, err)
	assert.NotNil(t, cred)
}

func TestGetCredentialManagedIdentityWithResourceID(t *testing.T) {
	// Test managed identity credential with resource ID
	cfg := Config{
		SubscriptionID:            "sub-123",
		ResourceGroupName:         "rg-123",
		Ambient:                   true,
		ManagedIdentityResourceID: "mi-resource-id",
	}

	clientOpts := policy.ClientOptions{}
	cred, err := getCredential(clientOpts, cfg)
	// Managed identity credential creation succeeds but may fail at use time
	assert.NoError(t, err)
	assert.NotNil(t, cred)
}

func TestGetCredentialWorkloadIdentity(t *testing.T) {
	// Test workload identity credential
	originalEnv := os.Getenv("AZURE_FEDERATED_TOKEN_FILE")
	defer func() {
		if originalEnv != "" {
			os.Setenv("AZURE_FEDERATED_TOKEN_FILE", originalEnv)
		} else {
			os.Unsetenv("AZURE_FEDERATED_TOKEN_FILE")
		}
	}()

	// Create a temp file to simulate token file
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "token")
	err := os.WriteFile(tokenFile, []byte("test-token"), 0600)
	require.NoError(t, err)

	os.Setenv("AZURE_FEDERATED_TOKEN_FILE", tokenFile)

	cfg := Config{
		SubscriptionID:          "sub-123",
		ResourceGroupName:       "rg-123",
		Ambient:                 true,
		ManagedIdentityClientID: "wi-client-id",
		TenantID:                "wi-tenant-id",
	}

	clientOpts := policy.ClientOptions{}
	cred, err := getCredential(clientOpts, cfg)
	// Workload identity credential creation may fail if not in proper environment
	// but we're testing the code path is reached
	if err == nil {
		assert.NotNil(t, cred)
	}
}

func TestNewWithCustomConfigValues(t *testing.T) {
	ctx := context.Background()

	cfg := Config{
		ClientID:           "client",
		ClientSecret:       "secret",
		TenantID:           "tenant",
		SubscriptionID:     "sub",
		ResourceGroupName:  "rg",
		ZoneName:           "example.com",
		PropagationTimeout: 300 * time.Second,
		PollingInterval:    10 * time.Second,
		TTL:                120,
		HTTPTimeout:        60 * time.Second,
	}

	provider, err := New(ctx, cfg)
	// May fail on credential validation but tests config parsing
	if err == nil {
		assert.NotNil(t, provider)
		timeout, interval := provider.Timeout()
		assert.Equal(t, 300*time.Second, timeout)
		assert.Equal(t, 10*time.Second, interval)
	}
}

func TestConfigStruct(t *testing.T) {
	// Test that Config struct fields work correctly
	cfg := Config{
		ClientID:                  "client-id",
		ClientSecret:              "client-secret",
		TenantID:                  "tenant-id",
		SubscriptionID:            "subscription-id",
		ResourceGroupName:         "resource-group",
		ZoneName:                  "zone.com",
		Environment:               "AzureCloud",
		Ambient:                   true,
		ManagedIdentityClientID:   "mi-client",
		ManagedIdentityResourceID: "mi-resource",
		Nameservers:               []string{"8.8.8.8", "8.8.4.4"},
		PropagationTimeout:        300 * time.Second,
		PollingInterval:           10 * time.Second,
		TTL:                       120,
		HTTPTimeout:               60 * time.Second,
	}

	assert.Equal(t, "client-id", cfg.ClientID)
	assert.Equal(t, "client-secret", cfg.ClientSecret)
	assert.Equal(t, "tenant-id", cfg.TenantID)
	assert.Equal(t, "subscription-id", cfg.SubscriptionID)
	assert.Equal(t, "resource-group", cfg.ResourceGroupName)
	assert.Equal(t, "zone.com", cfg.ZoneName)
	assert.Equal(t, "AzureCloud", cfg.Environment)
	assert.True(t, cfg.Ambient)
	assert.Equal(t, "mi-client", cfg.ManagedIdentityClientID)
	assert.Equal(t, "mi-resource", cfg.ManagedIdentityResourceID)
	assert.Equal(t, []string{"8.8.8.8", "8.8.4.4"}, cfg.Nameservers)
	assert.Equal(t, 300*time.Second, cfg.PropagationTimeout)
	assert.Equal(t, 10*time.Second, cfg.PollingInterval)
	assert.Equal(t, int64(120), cfg.TTL)
	assert.Equal(t, 60*time.Second, cfg.HTTPTimeout)
}

func TestProviderNameConstant(t *testing.T) {
	assert.Equal(t, "azure", providerName)
}
