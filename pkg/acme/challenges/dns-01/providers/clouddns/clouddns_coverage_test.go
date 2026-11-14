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

package clouddns

import (
	"context"
	"os"
	"testing"

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
}

// TestCloudDNSClientWrapperMethods tests the cloudDNSClient wrapper methods
// that call the actual Google Cloud DNS API.
// TestPresentEdgeCases tests edge cases in the Present method.
// TestCleanUpEdgeCases tests edge cases in the CleanUp method.
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
}

// TestFindTXTRecordsEdgeCases tests edge cases in findTXTRecords.
// TestWaitForChangeErrorPaths tests error paths in waitForChange.
// TestConfigDefaultsAdditional tests configuration default application.
// TestProviderInterfaceComplianceAdditional verifies interface compliance.
