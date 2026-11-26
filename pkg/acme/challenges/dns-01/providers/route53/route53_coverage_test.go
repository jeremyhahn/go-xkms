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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers"
)

// TestGetHostedZoneIDWithDiscovery tests getHostedZoneID when zone ID is not configured
// and needs to be discovered via DNS lookup and API call.
// TestInitRegistrationRoute53 tests the init function registration.
func TestInitRegistrationRoute53(t *testing.T) {
	t.Run("provider is registered with correct name", func(t *testing.T) {
		assert.True(t, providers.Registered(providers.ProviderRoute53))
		assert.True(t, providers.Registered("route53"))
	})

	t.Run("factory returns error for invalid config type", func(t *testing.T) {
		factory := providers.Get(providers.ProviderRoute53)
		require.NotNil(t, factory)

		ctx := context.Background()

		// Pass wrong type
		_, err := factory(ctx, "string-not-config")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected route53.Config")

		// Pass nil
		_, err = factory(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected route53.Config")

		// Pass different struct type
		_, err = factory(ctx, struct{ Name string }{Name: "test"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected route53.Config")
	})

	t.Run("env factory is registered", func(t *testing.T) {
		envFactory := providers.GetEnvFactory(providers.ProviderRoute53)
		require.NotNil(t, envFactory)
	})
}

// TestChangeRecordErrorPaths tests error paths in changeRecord.
func TestChangeRecordErrorPaths(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when getHostedZoneID fails", func(t *testing.T) {
		providers.ClearZoneCache()

		mock := &mockRoute53Client{
			listZonesByNameFunc: func(ctx context.Context, params *route53.ListHostedZonesByNameInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error) {
				return nil, errors.New("API error")
			},
		}

		// Provider without configured zone ID and with invalid nameservers
		provider := NewWithClient(mock, "", []string{"invalid-server"})

		err := provider.Present(ctx, "invalid..domain", "_acme-challenge.invalid..domain.", "token-value")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "get zone")
	})
}

// TestWaitForChangeErrorPathsRoute53 tests error paths in waitForChange.
func TestWaitForChangeErrorPathsRoute53(t *testing.T) {
	ctx := context.Background()

	t.Run("times out when change status never becomes INSYNC", func(t *testing.T) {
		mock := &mockRoute53Client{
			getChangeFunc: func(ctx context.Context, params *route53.GetChangeInput, optFns ...func(*route53.Options)) (*route53.GetChangeOutput, error) {
				return &route53.GetChangeOutput{
					ChangeInfo: &types.ChangeInfo{
						Id:     params.Id,
						Status: types.ChangeStatusPending,
					},
				}, nil
			},
		}

		cfg := Config{
			HostedZoneID:       "Z123456",
			PropagationTimeout: 100 * time.Millisecond,
			PollingInterval:    20 * time.Millisecond,
		}
		provider := NewWithClientAndConfig(mock, cfg)

		err := provider.waitForChange(ctx, aws.String("change-id"))
		require.Error(t, err)
	})
}

// TestLoadAWSConfigWithRole tests loadAWSConfig with role assumption.
func TestLoadAWSConfigWithRole(t *testing.T) {
	ctx := context.Background()

	t.Run("loads config with role and static credentials", func(t *testing.T) {
		// This test validates that the loadAWSConfig function handles role config
		// without actually making AWS API calls
		cfg := Config{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			Region:          "us-east-1",
			Role:            "arn:aws:iam::123456789:role/TestRole",
			HTTPTimeout:     30 * time.Second,
		}
		cfg = applyDefaults(cfg)

		// loadAWSConfig will try to assume the role, which will fail without real credentials
		// but we can at least verify it doesn't panic
		_, err := loadAWSConfig(ctx, cfg)
		// Will fail because we can't actually assume the role, but that's expected
		require.Error(t, err)
	})
}

// TestNewFromEnvErrorPathsRoute53 tests error paths in NewFromEnv.

// TestConfigValidationAdditional tests additional validation cases.

// TestProviderInterfaceComplianceRoute53 verifies interface compliance.

// TestPresentWithZoneDiscoveryError tests Present when zone discovery fails.
// TestMultiValueAnswer tests that the provider uses multi-value answer for TXT records.
func TestMultiValueAnswer(t *testing.T) {
	ctx := context.Background()

	var capturedInput *route53.ChangeResourceRecordSetsInput

	mock := &mockRoute53Client{
		changeRecordSetsFunc: func(ctx context.Context, params *route53.ChangeResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error) {
			capturedInput = params
			return &route53.ChangeResourceRecordSetsOutput{
				ChangeInfo: &types.ChangeInfo{
					Id:     aws.String("change-id"),
					Status: types.ChangeStatusInsync,
				},
			}, nil
		},
	}

	provider := NewWithClient(mock, "Z123456", nil)

	err := provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
	require.NoError(t, err)

	require.NotNil(t, capturedInput)
	recordSet := capturedInput.ChangeBatch.Changes[0].ResourceRecordSet

	// Verify multi-value answer is enabled
	assert.True(t, *recordSet.MultiValueAnswer)

	// Verify set identifier is the quoted value
	assert.Contains(t, *recordSet.SetIdentifier, "token-value")
}
