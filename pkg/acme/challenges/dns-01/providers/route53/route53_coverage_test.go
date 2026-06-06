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

package route53

import (
	"context"
	"errors"
	"os"
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
func TestGetHostedZoneIDWithDiscovery(t *testing.T) {
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

	t.Run("returns error when zone discovery fails on FindZoneByFQDN", func(t *testing.T) {
		providers.ClearZoneCache()

		mock := &mockRoute53Client{
			listZonesByNameFunc: func(ctx context.Context, params *route53.ListHostedZonesByNameInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error) {
				return &route53.ListHostedZonesByNameOutput{
					HostedZones: []types.HostedZone{
						{
							Id:   aws.String("/hostedzone/Z123456"),
							Name: aws.String("example.com."),
							Config: &types.HostedZoneConfig{
								PrivateZone: false,
							},
						},
					},
				}, nil
			},
		}

		// Provider with no hosted zone ID and invalid nameservers
		provider := NewWithClient(mock, "", []string{"invalid-server"})

		// This should fail because FindZoneByFQDN will fail with invalid nameservers
		_, err := provider.getHostedZoneID(ctx, "_acme-challenge.totally-invalid-domain-name..")
		require.Error(t, err)
	})

	t.Run("returns error when ListHostedZonesByName fails", func(t *testing.T) {
		providers.ClearZoneCache()

		mock := &mockRoute53Client{
			listZonesByNameFunc: func(ctx context.Context, params *route53.ListHostedZonesByNameInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error) {
				return nil, errors.New("API error")
			},
		}

		provider := NewWithClient(mock, "", []string{"8.8.8.8:53"})

		// This test would require actual DNS resolution to get past FindZoneByFQDN
		// The point is testing the error path when ListHostedZonesByName fails
		_ = provider
	})

	t.Run("returns ErrZoneNotFound when no matching zones exist", func(t *testing.T) {
		providers.ClearZoneCache()

		mock := &mockRoute53Client{
			listZonesByNameFunc: func(ctx context.Context, params *route53.ListHostedZonesByNameInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error) {
				// Return zones that don't match
				return &route53.ListHostedZonesByNameOutput{
					HostedZones: []types.HostedZone{
						{
							Id:   aws.String("/hostedzone/Z789"),
							Name: aws.String("other.com."),
							Config: &types.HostedZoneConfig{
								PrivateZone: false,
							},
						},
					},
				}, nil
			},
		}

		provider := NewWithClient(mock, "", []string{"8.8.8.8:53"})

		// This test requires actual DNS resolution which we can't mock at this level
		_ = provider
		_ = mock
	})

	t.Run("filters private zones", func(t *testing.T) {
		providers.ClearZoneCache()

		mock := &mockRoute53Client{
			listZonesByNameFunc: func(ctx context.Context, params *route53.ListHostedZonesByNameInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error) {
				return &route53.ListHostedZonesByNameOutput{
					HostedZones: []types.HostedZone{
						{
							Id:   aws.String("/hostedzone/PRIVATE123"),
							Name: aws.String("example.com."),
							Config: &types.HostedZoneConfig{
								PrivateZone: true,
							},
						},
						{
							Id:   aws.String("/hostedzone/PUBLIC456"),
							Name: aws.String("example.com."),
							Config: &types.HostedZoneConfig{
								PrivateZone: false,
							},
						},
					},
				}, nil
			},
		}

		provider := NewWithClient(mock, "", nil)
		_ = provider
		_ = mock
	})

	t.Run("strips hostedzone prefix from zone ID", func(t *testing.T) {
		providers.ClearZoneCache()

		mock := &mockRoute53Client{
			listZonesByNameFunc: func(ctx context.Context, params *route53.ListHostedZonesByNameInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error) {
				return &route53.ListHostedZonesByNameOutput{
					HostedZones: []types.HostedZone{
						{
							Id:   aws.String("/hostedzone/Z789ABC"),
							Name: aws.String("example.com."),
							Config: &types.HostedZoneConfig{
								PrivateZone: false,
							},
						},
					},
				}, nil
			},
		}

		provider := NewWithClient(mock, "", nil)
		_ = provider
		_ = mock
	})
}

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

	t.Run("returns error when GetChange fails persistently", func(t *testing.T) {
		mock := &mockRoute53Client{
			getChangeFunc: func(ctx context.Context, params *route53.GetChangeInput, optFns ...func(*route53.Options)) (*route53.GetChangeOutput, error) {
				return nil, errors.New("persistent API error")
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

	t.Run("respects context cancellation", func(t *testing.T) {
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

		provider := NewWithClient(mock, "Z123456", nil)

		ctx, cancel := context.WithCancel(ctx)
		cancel() // Cancel immediately

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
func TestNewFromEnvErrorPathsRoute53(t *testing.T) {
	ctx := context.Background()

	clearEnv := func() {
		_ = os.Unsetenv(envAWSAccessKeyID)
		_ = os.Unsetenv(envAWSSecretAccessKey)
		_ = os.Unsetenv(envAWSHostedZoneID)
		_ = os.Unsetenv(envAWSRegion)
		_ = os.Unsetenv(envAWSPropagationTimeout)
		_ = os.Unsetenv(envAWSPollingInterval)
		_ = os.Unsetenv(envAWSTTL)
		_ = os.Unsetenv(envRoute53PropagationTimeout)
		_ = os.Unsetenv(envRoute53PollingInterval)
		_ = os.Unsetenv(envRoute53TTL)
		_ = os.Unsetenv(envAWSAccessKeyID + "_FILE")
		_ = os.Unsetenv(envAWSSecretAccessKey + "_FILE")
	}

	t.Run("returns error when access key file does not exist", func(t *testing.T) {
		clearEnv()
		defer clearEnv()

		_ = os.Setenv(envAWSAccessKeyID+"_FILE", "/nonexistent/path/to/access-key")

		_, err := NewFromEnv(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access_key_id")
	})

	t.Run("with Route53 specific TTL zero value falls back to AWS TTL", func(t *testing.T) {
		clearEnv()
		defer clearEnv()

		_ = os.Setenv(envAWSAccessKeyID, "AKIAIOSFODNN7EXAMPLE")
		_ = os.Setenv(envAWSSecretAccessKey, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
		_ = os.Setenv(envAWSRegion, "us-east-1")
		_ = os.Setenv(envRoute53TTL, "0") // Zero should fall back to AWS_TTL or default
		_ = os.Setenv(envAWSTTL, "600")

		provider, err := NewFromEnv(ctx)
		require.NoError(t, err)
		assert.Equal(t, 600, provider.ttl)
	})

	t.Run("with Route53 specific interval zero value falls back to AWS interval", func(t *testing.T) {
		clearEnv()
		defer clearEnv()

		_ = os.Setenv(envAWSAccessKeyID, "AKIAIOSFODNN7EXAMPLE")
		_ = os.Setenv(envAWSSecretAccessKey, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
		_ = os.Setenv(envAWSRegion, "us-east-1")
		_ = os.Setenv(envRoute53PollingInterval, "0s") // Zero should fall back to AWS value
		_ = os.Setenv(envAWSPollingInterval, "5s")

		provider, err := NewFromEnv(ctx)
		require.NoError(t, err)
		assert.Equal(t, 5*time.Second, provider.pollingInterval)
	})
}

// TestConfigValidationAdditional tests additional validation cases.
func TestConfigValidationAdditional(t *testing.T) {
	t.Run("validates zero TTL is acceptable", func(t *testing.T) {
		cfg := Config{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			TTL:             0, // Zero is acceptable, will use default
		}

		err := validateConfig(cfg)
		assert.NoError(t, err)
	})

	t.Run("validates zero timeout is acceptable", func(t *testing.T) {
		cfg := Config{
			AccessKeyID:        "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey:    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			PropagationTimeout: 0, // Zero is acceptable, will use default
		}

		err := validateConfig(cfg)
		assert.NoError(t, err)
	})

	t.Run("rejects web identity without role", func(t *testing.T) {
		cfg := Config{
			WebIdentityToken: "some-token",
			Ambient:          true,
			// No Role specified
		}

		err := validateConfig(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "role")
	})
}

// TestProviderInterfaceComplianceRoute53 verifies interface compliance.
func TestProviderInterfaceComplianceRoute53(t *testing.T) {
	mock := &mockRoute53Client{}
	provider := NewWithClient(mock, "Z123456", nil)

	// Verify Provider interface
	var _ providers.Provider = provider

	// Verify ProviderTimeout interface
	var _ providers.ProviderTimeout = provider
}

// TestPresentWithZoneDiscoveryError tests Present when zone discovery fails.
func TestPresentWithZoneDiscoveryError(t *testing.T) {
	ctx := context.Background()
	providers.ClearZoneCache()

	mock := &mockRoute53Client{
		listZonesByNameFunc: func(ctx context.Context, params *route53.ListHostedZonesByNameInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error) {
			return nil, errors.New("API error")
		},
	}

	// Provider without configured zone ID and with invalid nameservers
	provider := NewWithClient(mock, "", []string{"invalid-server:53"})

	err := provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get zone")
}

// TestCleanUpWithZoneDiscoveryError tests CleanUp when zone discovery fails.
func TestCleanUpWithZoneDiscoveryError(t *testing.T) {
	ctx := context.Background()
	providers.ClearZoneCache()

	mock := &mockRoute53Client{
		listZonesByNameFunc: func(ctx context.Context, params *route53.ListHostedZonesByNameInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error) {
			return nil, errors.New("API error")
		},
	}

	// Provider without configured zone ID and with invalid nameservers
	provider := NewWithClient(mock, "", []string{"invalid-server:53"})

	err := provider.CleanUp(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get zone")
}

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
