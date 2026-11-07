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
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers"
)

// mockRoute53Client implements the Route53API interface for testing.
type mockRoute53Client struct {
	changeRecordSetsFunc func(ctx context.Context, params *route53.ChangeResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error)
	getChangeFunc        func(ctx context.Context, params *route53.GetChangeInput, optFns ...func(*route53.Options)) (*route53.GetChangeOutput, error)
	listZonesByNameFunc  func(ctx context.Context, params *route53.ListHostedZonesByNameInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error)
}

func (m *mockRoute53Client) ChangeResourceRecordSets(ctx context.Context, params *route53.ChangeResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error) {
	if m.changeRecordSetsFunc != nil {
		return m.changeRecordSetsFunc(ctx, params, optFns...)
	}
	return &route53.ChangeResourceRecordSetsOutput{
		ChangeInfo: &types.ChangeInfo{
			Id:     aws.String("change-id"),
			Status: types.ChangeStatusInsync,
		},
	}, nil
}

func (m *mockRoute53Client) GetChange(ctx context.Context, params *route53.GetChangeInput, optFns ...func(*route53.Options)) (*route53.GetChangeOutput, error) {
	if m.getChangeFunc != nil {
		return m.getChangeFunc(ctx, params, optFns...)
	}
	return &route53.GetChangeOutput{
		ChangeInfo: &types.ChangeInfo{
			Id:     params.Id,
			Status: types.ChangeStatusInsync,
		},
	}, nil
}

func (m *mockRoute53Client) ListHostedZonesByName(ctx context.Context, params *route53.ListHostedZonesByNameInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error) {
	if m.listZonesByNameFunc != nil {
		return m.listZonesByNameFunc(ctx, params, optFns...)
	}
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
}

// mockStsClient implements the StsAPI interface for testing.
type mockStsClient struct {
	assumeRoleFunc            func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
	assumeRoleWithWebIdentity func(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

func (m *mockStsClient) AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	if m.assumeRoleFunc != nil {
		return m.assumeRoleFunc(ctx, params, optFns...)
	}
	return &sts.AssumeRoleOutput{
		Credentials: &ststypes.Credentials{
			AccessKeyId:     aws.String("ASIATESTACCESSKEY"),
			SecretAccessKey: aws.String("testsecretkey"),
			SessionToken:    aws.String("testsessiontoken"),
		},
	}, nil
}

func (m *mockStsClient) AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	if m.assumeRoleWithWebIdentity != nil {
		return m.assumeRoleWithWebIdentity(ctx, params, optFns...)
	}
	return &sts.AssumeRoleWithWebIdentityOutput{
		Credentials: &ststypes.Credentials{
			AccessKeyId:     aws.String("ASIATESTACCESSKEY"),
			SecretAccessKey: aws.String("testsecretkey"),
			SessionToken:    aws.String("testsessiontoken"),
		},
	}, nil
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name          string
		config        Config
		expectError   bool
		errorType     error
		errorContains string
	}{
		{
			name: "valid static credentials",
			config: Config{
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				Region:          "us-east-1",
			},
			expectError: false,
		},
		{
			name: "valid ambient credentials",
			config: Config{
				Ambient: true,
				Region:  "us-east-1",
			},
			expectError: false,
		},
		{
			name: "missing secret key",
			config: Config{
				AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
				Region:      "us-east-1",
			},
			expectError: true,
		},
		{
			name: "missing access key",
			config: Config{
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				Region:          "us-east-1",
			},
			expectError: true,
		},
		{
			name: "web identity without role",
			config: Config{
				WebIdentityToken: "token",
				Ambient:          true,
			},
			expectError:   true,
			errorContains: "role",
		},
		{
			name: "web identity with role",
			config: Config{
				WebIdentityToken: "token",
				Role:             "arn:aws:iam::123456789:role/TestRole",
				Ambient:          true,
			},
			expectError: false,
		},
		{
			name:        "no credentials and ambient disabled",
			config:      Config{},
			expectError: true,
			errorType:   providers.ErrMissingCredentials,
		},
		{
			name: "negative TTL",
			config: Config{
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				TTL:             -1,
			},
			expectError: true,
		},
		{
			name: "negative propagation timeout",
			config: Config{
				AccessKeyID:        "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey:    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				PropagationTimeout: -1 * time.Second,
			},
			expectError: true,
		},
		{
			name: "negative polling interval",
			config: Config{
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				PollingInterval: -1 * time.Second,
			},
			expectError: true,
		},
		{
			name: "negative HTTP timeout",
			config: Config{
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				HTTPTimeout:     -1 * time.Second,
			},
			expectError: true,
		},
		{
			name: "valid with custom timeouts",
			config: Config{
				AccessKeyID:        "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey:    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				PropagationTimeout: 60 * time.Second,
				PollingInterval:    2 * time.Second,
				TTL:                300,
				HTTPTimeout:        15 * time.Second,
			},
			expectError: false,
		},
		{
			name: "role without credentials uses ambient",
			config: Config{
				Role:    "arn:aws:iam::123456789:role/TestRole",
				Ambient: true,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.config)
			if tt.expectError {
				require.Error(t, err)
				if tt.errorType != nil {
					assert.ErrorIs(t, err, tt.errorType)
				}
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestApplyDefaults(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected Config
	}{
		{
			name:   "all zero values",
			config: Config{},
			expected: Config{
				PropagationTimeout: defaultPropagationTimeout,
				PollingInterval:    defaultPollingInterval,
				TTL:                defaultTTL,
				HTTPTimeout:        defaultHTTPTimeout,
			},
		},
		{
			name: "custom values preserved",
			config: Config{
				PropagationTimeout: 60 * time.Second,
				PollingInterval:    2 * time.Second,
				TTL:                300,
				HTTPTimeout:        15 * time.Second,
			},
			expected: Config{
				PropagationTimeout: 60 * time.Second,
				PollingInterval:    2 * time.Second,
				TTL:                300,
				HTTPTimeout:        15 * time.Second,
			},
		},
		{
			name: "partial custom values",
			config: Config{
				PropagationTimeout: 60 * time.Second,
			},
			expected: Config{
				PropagationTimeout: 60 * time.Second,
				PollingInterval:    defaultPollingInterval,
				TTL:                defaultTTL,
				HTTPTimeout:        defaultHTTPTimeout,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := applyDefaults(tt.config)
			assert.Equal(t, tt.expected.PropagationTimeout, result.PropagationTimeout)
			assert.Equal(t, tt.expected.PollingInterval, result.PollingInterval)
			assert.Equal(t, tt.expected.TTL, result.TTL)
			assert.Equal(t, tt.expected.HTTPTimeout, result.HTTPTimeout)
		})
	}
}

func TestNewWithClient(t *testing.T) {
	mock := &mockRoute53Client{}
	provider := NewWithClient(mock, "Z123456", nil)

	assert.NotNil(t, provider)
	assert.Equal(t, "Z123456", provider.hostedZoneID)
	assert.Equal(t, defaultPropagationTimeout, provider.propagationTimeout)
	assert.Equal(t, defaultPollingInterval, provider.pollingInterval)
	assert.Equal(t, defaultTTL, provider.ttl)
}

func TestNewWithClientAndConfig(t *testing.T) {
	mock := &mockRoute53Client{}
	cfg := Config{
		HostedZoneID:       "Z789",
		Nameservers:        []string{"8.8.8.8:53"},
		PropagationTimeout: 60 * time.Second,
		PollingInterval:    2 * time.Second,
		TTL:                300,
	}
	provider := NewWithClientAndConfig(mock, cfg)

	assert.NotNil(t, provider)
	assert.Equal(t, "Z789", provider.hostedZoneID)
	assert.Equal(t, []string{"8.8.8.8:53"}, provider.nameservers)
	assert.Equal(t, 60*time.Second, provider.propagationTimeout)
	assert.Equal(t, 2*time.Second, provider.pollingInterval)
	assert.Equal(t, 300, provider.ttl)
}

func TestTimeout(t *testing.T) {
	t.Run("default timeouts", func(t *testing.T) {
		mock := &mockRoute53Client{}
		provider := NewWithClient(mock, "Z123456", nil)

		timeout, interval := provider.Timeout()
		assert.Equal(t, defaultPropagationTimeout, timeout)
		assert.Equal(t, defaultPollingInterval, interval)
	})

	t.Run("custom timeouts", func(t *testing.T) {
		mock := &mockRoute53Client{}
		cfg := Config{
			HostedZoneID:       "Z123456",
			PropagationTimeout: 60 * time.Second,
			PollingInterval:    2 * time.Second,
		}
		provider := NewWithClientAndConfig(mock, cfg)

		timeout, interval := provider.Timeout()
		assert.Equal(t, 60*time.Second, timeout)
		assert.Equal(t, 2*time.Second, interval)
	})
}

func TestPresent(t *testing.T) {
	t.Run("successful present", func(t *testing.T) {
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
		ctx := context.Background()

		err := provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.NoError(t, err)

		// Verify the request
		require.NotNil(t, capturedInput)
		assert.Equal(t, "Z123456", *capturedInput.HostedZoneId)
		assert.Len(t, capturedInput.ChangeBatch.Changes, 1)
		change := capturedInput.ChangeBatch.Changes[0]
		assert.Equal(t, types.ChangeActionUpsert, change.Action)
		assert.Equal(t, "_acme-challenge.example.com.", *change.ResourceRecordSet.Name)
		assert.Equal(t, types.RRTypeTxt, change.ResourceRecordSet.Type)
		assert.Contains(t, *change.ResourceRecordSet.ResourceRecords[0].Value, "token-value")
	})

	t.Run("present with API error", func(t *testing.T) {
		mock := &mockRoute53Client{
			changeRecordSetsFunc: func(ctx context.Context, params *route53.ChangeResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error) {
				return nil, errors.New("API error")
			},
		}

		provider := NewWithClient(mock, "Z123456", nil)
		ctx := context.Background()

		err := provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "route53")
	})

	t.Run("present with InvalidChangeBatch error does not ignore for upsert", func(t *testing.T) {
		mock := &mockRoute53Client{
			changeRecordSetsFunc: func(ctx context.Context, params *route53.ChangeResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error) {
				return nil, &types.InvalidChangeBatch{Message: aws.String("some error")}
			},
		}

		provider := NewWithClient(mock, "Z123456", nil)
		ctx := context.Background()

		err := provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "route53")
	})
}

func TestCleanUp(t *testing.T) {
	t.Run("successful cleanup", func(t *testing.T) {
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
		ctx := context.Background()

		err := provider.CleanUp(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.NoError(t, err)

		// Verify the request
		require.NotNil(t, capturedInput)
		change := capturedInput.ChangeBatch.Changes[0]
		assert.Equal(t, types.ChangeActionDelete, change.Action)
	})

	t.Run("cleanup ignores InvalidChangeBatch for delete", func(t *testing.T) {
		mock := &mockRoute53Client{
			changeRecordSetsFunc: func(ctx context.Context, params *route53.ChangeResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error) {
				return nil, &types.InvalidChangeBatch{Message: aws.String("record not found")}
			},
		}

		provider := NewWithClient(mock, "Z123456", nil)
		ctx := context.Background()

		// Should not return error when record doesn't exist
		err := provider.CleanUp(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		assert.NoError(t, err)
	})

	t.Run("cleanup with generic API error", func(t *testing.T) {
		mock := &mockRoute53Client{
			changeRecordSetsFunc: func(ctx context.Context, params *route53.ChangeResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error) {
				return nil, errors.New("API error")
			},
		}

		provider := NewWithClient(mock, "Z123456", nil)
		ctx := context.Background()

		err := provider.CleanUp(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "route53")
	})
}

func TestWaitForChange(t *testing.T) {
	t.Run("immediate sync", func(t *testing.T) {
		mock := &mockRoute53Client{
			getChangeFunc: func(ctx context.Context, params *route53.GetChangeInput, optFns ...func(*route53.Options)) (*route53.GetChangeOutput, error) {
				return &route53.GetChangeOutput{
					ChangeInfo: &types.ChangeInfo{
						Id:     params.Id,
						Status: types.ChangeStatusInsync,
					},
				}, nil
			},
		}

		provider := NewWithClient(mock, "Z123456", nil)
		ctx := context.Background()

		err := provider.waitForChange(ctx, aws.String("change-id"))
		assert.NoError(t, err)
	})

	t.Run("custom polling interval", func(t *testing.T) {
		callCount := 0
		mock := &mockRoute53Client{
			getChangeFunc: func(ctx context.Context, params *route53.GetChangeInput, optFns ...func(*route53.Options)) (*route53.GetChangeOutput, error) {
				callCount++
				status := types.ChangeStatusPending
				if callCount >= 2 {
					status = types.ChangeStatusInsync
				}
				return &route53.GetChangeOutput{
					ChangeInfo: &types.ChangeInfo{
						Id:     params.Id,
						Status: status,
					},
				}, nil
			},
		}

		cfg := Config{
			HostedZoneID:       "Z123456",
			PropagationTimeout: 5 * time.Second,
			PollingInterval:    10 * time.Millisecond, // Fast polling for test
		}
		provider := NewWithClientAndConfig(mock, cfg)
		ctx := context.Background()

		err := provider.waitForChange(ctx, aws.String("change-id"))
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, callCount, 2)
	})

	t.Run("error during polling", func(t *testing.T) {
		mock := &mockRoute53Client{
			getChangeFunc: func(ctx context.Context, params *route53.GetChangeInput, optFns ...func(*route53.Options)) (*route53.GetChangeOutput, error) {
				return nil, errors.New("polling error")
			},
		}

		cfg := Config{
			HostedZoneID:       "Z123456",
			PropagationTimeout: 100 * time.Millisecond,
			PollingInterval:    10 * time.Millisecond,
		}
		provider := NewWithClientAndConfig(mock, cfg)
		ctx := context.Background()

		err := provider.waitForChange(ctx, aws.String("change-id"))
		assert.Error(t, err)
	})

	t.Run("context cancellation", func(t *testing.T) {
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
			PropagationTimeout: 10 * time.Second,
			PollingInterval:    10 * time.Millisecond,
		}
		provider := NewWithClientAndConfig(mock, cfg)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		err := provider.waitForChange(ctx, aws.String("change-id"))
		assert.Error(t, err)
	})
}

func TestNew(t *testing.T) {
	t.Run("with static credentials", func(t *testing.T) {
		ctx := context.Background()
		cfg := Config{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			Region:          "us-east-1",
			HostedZoneID:    "Z123456",
		}

		provider, err := New(ctx, cfg)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, "Z123456", provider.hostedZoneID)
	})

	t.Run("with ambient credentials", func(t *testing.T) {
		ctx := context.Background()
		cfg := Config{
			Ambient:      true,
			Region:       "us-east-1",
			HostedZoneID: "Z123456",
		}

		provider, err := New(ctx, cfg)
		require.NoError(t, err)
		assert.NotNil(t, provider)
	})

	t.Run("with custom timeouts", func(t *testing.T) {
		ctx := context.Background()
		cfg := Config{
			AccessKeyID:        "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey:    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			Region:             "us-east-1",
			PropagationTimeout: 60 * time.Second,
			PollingInterval:    2 * time.Second,
			TTL:                300,
			HTTPTimeout:        15 * time.Second,
		}

		provider, err := New(ctx, cfg)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, 60*time.Second, provider.propagationTimeout)
		assert.Equal(t, 2*time.Second, provider.pollingInterval)
		assert.Equal(t, 300, provider.ttl)
	})

	t.Run("validation error", func(t *testing.T) {
		ctx := context.Background()
		cfg := Config{
			// No credentials and ambient disabled
		}

		_, err := New(ctx, cfg)
		require.Error(t, err)
	})

	t.Run("without region uses default credential chain", func(t *testing.T) {
		ctx := context.Background()
		cfg := Config{
			Ambient:      true,
			HostedZoneID: "Z123456",
		}

		provider, err := New(ctx, cfg)
		require.NoError(t, err)
		assert.NotNil(t, provider)
	})
}

func TestAssumeRole(t *testing.T) {
	t.Run("regular assume role success", func(t *testing.T) {
		mockSts := &mockStsClient{
			assumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
				assert.Equal(t, "arn:aws:iam::123456789:role/TestRole", *params.RoleArn)
				assert.Equal(t, "go-xkms", *params.RoleSessionName)
				return &sts.AssumeRoleOutput{
					Credentials: &ststypes.Credentials{
						AccessKeyId:     aws.String("ASIATESTACCESSKEY"),
						SecretAccessKey: aws.String("testsecretkey"),
						SessionToken:    aws.String("testsessiontoken"),
					},
				}, nil
			},
		}

		providerCfg := Config{
			Role: "arn:aws:iam::123456789:role/TestRole",
		}

		cfg := aws.Config{}
		ctx := context.Background()

		resultCfg, err := assumeRole(ctx, cfg, mockSts, providerCfg)
		require.NoError(t, err)
		assert.NotNil(t, resultCfg.Credentials)
	})

	t.Run("assume role with web identity success", func(t *testing.T) {
		mockSts := &mockStsClient{
			assumeRoleWithWebIdentity: func(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
				assert.Equal(t, "arn:aws:iam::123456789:role/TestRole", *params.RoleArn)
				assert.Equal(t, "go-xkms", *params.RoleSessionName)
				assert.Equal(t, "test-web-identity-token", *params.WebIdentityToken)
				return &sts.AssumeRoleWithWebIdentityOutput{
					Credentials: &ststypes.Credentials{
						AccessKeyId:     aws.String("ASIATESTACCESSKEY"),
						SecretAccessKey: aws.String("testsecretkey"),
						SessionToken:    aws.String("testsessiontoken"),
					},
				}, nil
			},
		}

		providerCfg := Config{
			Role:             "arn:aws:iam::123456789:role/TestRole",
			WebIdentityToken: "test-web-identity-token",
		}

		cfg := aws.Config{}
		ctx := context.Background()

		resultCfg, err := assumeRole(ctx, cfg, mockSts, providerCfg)
		require.NoError(t, err)
		assert.NotNil(t, resultCfg.Credentials)
	})

	t.Run("assume role error", func(t *testing.T) {
		mockSts := &mockStsClient{
			assumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
				return nil, errors.New("assume role failed")
			},
		}

		providerCfg := Config{
			Role: "arn:aws:iam::123456789:role/TestRole",
		}

		cfg := aws.Config{}
		ctx := context.Background()

		_, err := assumeRole(ctx, cfg, mockSts, providerCfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "assume role failed")
	})

	t.Run("assume role with web identity error", func(t *testing.T) {
		mockSts := &mockStsClient{
			assumeRoleWithWebIdentity: func(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
				return nil, errors.New("web identity failed")
			},
		}

		providerCfg := Config{
			Role:             "arn:aws:iam::123456789:role/TestRole",
			WebIdentityToken: "test-web-identity-token",
		}

		cfg := aws.Config{}
		ctx := context.Background()

		_, err := assumeRole(ctx, cfg, mockSts, providerCfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "web identity failed")
	})
}

func TestNewFromEnv(t *testing.T) {
	// Save original environment
	origAccessKeyID := os.Getenv(envAWSAccessKeyID)
	origSecretAccessKey := os.Getenv(envAWSSecretAccessKey)
	origHostedZoneID := os.Getenv(envAWSHostedZoneID)
	origRegion := os.Getenv(envAWSRegion)
	origAWSPropagationTimeout := os.Getenv(envAWSPropagationTimeout)
	origAWSPollingInterval := os.Getenv(envAWSPollingInterval)
	origAWSTTL := os.Getenv(envAWSTTL)
	origRoute53PropagationTimeout := os.Getenv(envRoute53PropagationTimeout)
	origRoute53PollingInterval := os.Getenv(envRoute53PollingInterval)
	origRoute53TTL := os.Getenv(envRoute53TTL)

	// Restore environment after test
	defer func() {
		setEnvOrUnset(envAWSAccessKeyID, origAccessKeyID)
		setEnvOrUnset(envAWSSecretAccessKey, origSecretAccessKey)
		setEnvOrUnset(envAWSHostedZoneID, origHostedZoneID)
		setEnvOrUnset(envAWSRegion, origRegion)
		setEnvOrUnset(envAWSPropagationTimeout, origAWSPropagationTimeout)
		setEnvOrUnset(envAWSPollingInterval, origAWSPollingInterval)
		setEnvOrUnset(envAWSTTL, origAWSTTL)
		setEnvOrUnset(envRoute53PropagationTimeout, origRoute53PropagationTimeout)
		setEnvOrUnset(envRoute53PollingInterval, origRoute53PollingInterval)
		setEnvOrUnset(envRoute53TTL, origRoute53TTL)
	}()

	t.Run("with static credentials", func(t *testing.T) {
		_ = os.Setenv(envAWSAccessKeyID, "AKIAIOSFODNN7EXAMPLE")
		_ = os.Setenv(envAWSSecretAccessKey, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
		_ = os.Setenv(envAWSHostedZoneID, "Z123456")
		_ = os.Setenv(envAWSRegion, "us-east-1")
		_ = os.Unsetenv(envAWSPropagationTimeout)
		_ = os.Unsetenv(envAWSPollingInterval)
		_ = os.Unsetenv(envAWSTTL)
		_ = os.Unsetenv(envRoute53PropagationTimeout)
		_ = os.Unsetenv(envRoute53PollingInterval)
		_ = os.Unsetenv(envRoute53TTL)

		ctx := context.Background()
		provider, err := NewFromEnv(ctx)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, "Z123456", provider.hostedZoneID)
		assert.Equal(t, defaultPropagationTimeout, provider.propagationTimeout)
		assert.Equal(t, defaultPollingInterval, provider.pollingInterval)
		assert.Equal(t, defaultTTL, provider.ttl)
	})

	t.Run("with AWS timeout env vars", func(t *testing.T) {
		_ = os.Setenv(envAWSAccessKeyID, "AKIAIOSFODNN7EXAMPLE")
		_ = os.Setenv(envAWSSecretAccessKey, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
		_ = os.Setenv(envAWSRegion, "us-east-1")
		_ = os.Setenv(envAWSPropagationTimeout, "60s")
		_ = os.Setenv(envAWSPollingInterval, "2s")
		_ = os.Setenv(envAWSTTL, "300")
		_ = os.Unsetenv(envRoute53PropagationTimeout)
		_ = os.Unsetenv(envRoute53PollingInterval)
		_ = os.Unsetenv(envRoute53TTL)

		ctx := context.Background()
		provider, err := NewFromEnv(ctx)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, 60*time.Second, provider.propagationTimeout)
		assert.Equal(t, 2*time.Second, provider.pollingInterval)
		assert.Equal(t, 300, provider.ttl)
	})

	t.Run("Route53 specific env vars take precedence", func(t *testing.T) {
		_ = os.Setenv(envAWSAccessKeyID, "AKIAIOSFODNN7EXAMPLE")
		_ = os.Setenv(envAWSSecretAccessKey, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
		_ = os.Setenv(envAWSRegion, "us-east-1")
		_ = os.Setenv(envAWSPropagationTimeout, "60s")
		_ = os.Setenv(envAWSPollingInterval, "2s")
		_ = os.Setenv(envAWSTTL, "300")
		_ = os.Setenv(envRoute53PropagationTimeout, "90s")
		_ = os.Setenv(envRoute53PollingInterval, "3s")
		_ = os.Setenv(envRoute53TTL, "600")

		ctx := context.Background()
		provider, err := NewFromEnv(ctx)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		// Route53 specific values should take precedence
		assert.Equal(t, 90*time.Second, provider.propagationTimeout)
		assert.Equal(t, 3*time.Second, provider.pollingInterval)
		assert.Equal(t, 600, provider.ttl)
	})

	t.Run("with ambient credentials", func(t *testing.T) {
		_ = os.Unsetenv(envAWSAccessKeyID)
		_ = os.Unsetenv(envAWSSecretAccessKey)
		_ = os.Setenv(envAWSRegion, "us-east-1")
		_ = os.Unsetenv(envAWSPropagationTimeout)
		_ = os.Unsetenv(envAWSPollingInterval)
		_ = os.Unsetenv(envAWSTTL)
		_ = os.Unsetenv(envRoute53PropagationTimeout)
		_ = os.Unsetenv(envRoute53PollingInterval)
		_ = os.Unsetenv(envRoute53TTL)

		ctx := context.Background()
		provider, err := NewFromEnv(ctx)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		// With no credentials, ambient should be enabled
		assert.Equal(t, defaultPropagationTimeout, provider.propagationTimeout)
		assert.Equal(t, defaultPollingInterval, provider.pollingInterval)
		assert.Equal(t, defaultTTL, provider.ttl)
	})

	t.Run("with invalid duration", func(t *testing.T) {
		_ = os.Setenv(envAWSAccessKeyID, "AKIAIOSFODNN7EXAMPLE")
		_ = os.Setenv(envAWSSecretAccessKey, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
		_ = os.Setenv(envAWSRegion, "us-east-1")
		_ = os.Setenv(envAWSPropagationTimeout, "invalid")
		_ = os.Unsetenv(envRoute53PropagationTimeout)

		ctx := context.Background()
		provider, err := NewFromEnv(ctx)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		// Should fall back to default
		assert.Equal(t, defaultPropagationTimeout, provider.propagationTimeout)
	})

	t.Run("with invalid TTL", func(t *testing.T) {
		_ = os.Setenv(envAWSAccessKeyID, "AKIAIOSFODNN7EXAMPLE")
		_ = os.Setenv(envAWSSecretAccessKey, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
		_ = os.Setenv(envAWSRegion, "us-east-1")
		_ = os.Setenv(envAWSTTL, "invalid")
		_ = os.Unsetenv(envRoute53TTL)

		ctx := context.Background()
		provider, err := NewFromEnv(ctx)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		// Should fall back to default
		assert.Equal(t, defaultTTL, provider.ttl)
	})

	t.Run("with partial static credentials error on secret file", func(t *testing.T) {
		_ = os.Setenv(envAWSAccessKeyID, "AKIAIOSFODNN7EXAMPLE")
		_ = os.Unsetenv(envAWSSecretAccessKey)
		_ = os.Setenv(envAWSSecretAccessKey+"_FILE", "/nonexistent/path/to/file")
		_ = os.Setenv(envAWSRegion, "us-east-1")

		ctx := context.Background()
		_, err := NewFromEnv(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "secret_access_key")

		// Cleanup
		_ = os.Unsetenv(envAWSSecretAccessKey + "_FILE")
	})
}

func TestNewFromEnvFileSupport(t *testing.T) {
	// Save original environment
	origAccessKeyID := os.Getenv(envAWSAccessKeyID)
	origSecretAccessKey := os.Getenv(envAWSSecretAccessKey)
	origAccessKeyIDFile := os.Getenv(envAWSAccessKeyID + "_FILE")
	origSecretAccessKeyFile := os.Getenv(envAWSSecretAccessKey + "_FILE")

	// Restore environment after test
	defer func() {
		setEnvOrUnset(envAWSAccessKeyID, origAccessKeyID)
		setEnvOrUnset(envAWSSecretAccessKey, origSecretAccessKey)
		setEnvOrUnset(envAWSAccessKeyID+"_FILE", origAccessKeyIDFile)
		setEnvOrUnset(envAWSSecretAccessKey+"_FILE", origSecretAccessKeyFile)
	}()

	t.Run("reads credentials from file", func(t *testing.T) {
		// Create temporary files for credentials
		accessKeyFile, err := os.CreateTemp("", "aws-access-key")
		require.NoError(t, err)
		defer func() { _ = os.Remove(accessKeyFile.Name()) }()

		secretKeyFile, err := os.CreateTemp("", "aws-secret-key")
		require.NoError(t, err)
		defer func() { _ = os.Remove(secretKeyFile.Name()) }()

		// Write credentials to files
		_, err = accessKeyFile.WriteString("AKIAIOSFODNN7EXAMPLE")
		require.NoError(t, err)
		_ = accessKeyFile.Close()

		_, err = secretKeyFile.WriteString("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
		require.NoError(t, err)
		_ = secretKeyFile.Close()

		// Set file environment variables
		_ = os.Unsetenv(envAWSAccessKeyID)
		_ = os.Unsetenv(envAWSSecretAccessKey)
		_ = os.Setenv(envAWSAccessKeyID+"_FILE", accessKeyFile.Name())
		_ = os.Setenv(envAWSSecretAccessKey+"_FILE", secretKeyFile.Name())
		_ = os.Setenv(envAWSRegion, "us-east-1")

		ctx := context.Background()
		provider, err := NewFromEnv(ctx)
		require.NoError(t, err)
		assert.NotNil(t, provider)
	})

	t.Run("error on non-existent file", func(t *testing.T) {
		_ = os.Unsetenv(envAWSAccessKeyID)
		_ = os.Setenv(envAWSAccessKeyID+"_FILE", "/nonexistent/path/to/file")

		ctx := context.Background()
		_, err := NewFromEnv(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access_key_id")
	})
}

func TestChangeRecordWithTTL(t *testing.T) {
	tests := []struct {
		name        string
		ttl         int
		expectedTTL int64
	}{
		{
			name:        "default TTL",
			ttl:         0,
			expectedTTL: int64(defaultTTL),
		},
		{
			name:        "custom TTL",
			ttl:         300,
			expectedTTL: 300,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedTTL int64

			mock := &mockRoute53Client{
				changeRecordSetsFunc: func(ctx context.Context, params *route53.ChangeResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error) {
					capturedTTL = *params.ChangeBatch.Changes[0].ResourceRecordSet.TTL
					return &route53.ChangeResourceRecordSetsOutput{
						ChangeInfo: &types.ChangeInfo{
							Id:     aws.String("change-id"),
							Status: types.ChangeStatusInsync,
						},
					}, nil
				},
			}

			cfg := Config{
				HostedZoneID: "Z123456",
				TTL:          tt.ttl,
			}
			provider := NewWithClientAndConfig(mock, cfg)
			ctx := context.Background()

			err := provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
			require.NoError(t, err)
			assert.Equal(t, tt.expectedTTL, capturedTTL)
		})
	}
}

func TestConstants(t *testing.T) {
	// Verify constants have expected values
	assert.Equal(t, "route53", providerName)
	assert.Equal(t, 10, defaultTTL)
	assert.Equal(t, 120*time.Second, defaultPropagationTimeout)
	assert.Equal(t, 4*time.Second, defaultPollingInterval)
	assert.Equal(t, 30*time.Second, defaultHTTPTimeout)

	// Verify environment variable names
	assert.Equal(t, "AWS_ACCESS_KEY_ID", envAWSAccessKeyID)
	assert.Equal(t, "AWS_SECRET_ACCESS_KEY", envAWSSecretAccessKey)
	assert.Equal(t, "AWS_HOSTED_ZONE_ID", envAWSHostedZoneID)
	assert.Equal(t, "AWS_REGION", envAWSRegion)
	assert.Equal(t, "AWS_PROPAGATION_TIMEOUT", envAWSPropagationTimeout)
	assert.Equal(t, "AWS_POLLING_INTERVAL", envAWSPollingInterval)
	assert.Equal(t, "AWS_TTL", envAWSTTL)
	assert.Equal(t, "ROUTE53_PROPAGATION_TIMEOUT", envRoute53PropagationTimeout)
	assert.Equal(t, "ROUTE53_POLLING_INTERVAL", envRoute53PollingInterval)
	assert.Equal(t, "ROUTE53_TTL", envRoute53TTL)
}

func TestLoadAWSConfig(t *testing.T) {
	t.Run("with region", func(t *testing.T) {
		ctx := context.Background()
		cfg := Config{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			Region:          "us-east-1",
			HTTPTimeout:     30 * time.Second,
		}
		cfg = applyDefaults(cfg)

		awsCfg, err := loadAWSConfig(ctx, cfg)
		require.NoError(t, err)
		assert.Equal(t, "us-east-1", awsCfg.Region)
	})
}

// setEnvOrUnset sets an environment variable or unsets it if value is empty
func setEnvOrUnset(key, value string) {
	if value == "" {
		_ = os.Unsetenv(key)
	} else {
		_ = os.Setenv(key, value)
	}
}
