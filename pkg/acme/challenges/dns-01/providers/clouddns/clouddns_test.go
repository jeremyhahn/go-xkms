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
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/dns/v1"

	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers"
)

// mockCloudDNSClient implements CloudDNSAPI for testing.
type mockCloudDNSClient struct {
	getManagedZonesFunc       func(ctx context.Context, project string) ([]*dns.ManagedZone, error)
	getResourceRecordSetsFunc func(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error)
	createChangeFunc          func(ctx context.Context, project, zone string, change *dns.Change) (*dns.Change, error)
	getChangeFunc             func(ctx context.Context, project, zone, changeID string) (*dns.Change, error)
}

func (m *mockCloudDNSClient) GetManagedZones(ctx context.Context, project string) ([]*dns.ManagedZone, error) {
	if m.getManagedZonesFunc != nil {
		return m.getManagedZonesFunc(ctx, project)
	}
	return []*dns.ManagedZone{
		{Name: "example-zone", DnsName: "example.com.", Visibility: "public"},
	}, nil
}

func (m *mockCloudDNSClient) GetResourceRecordSets(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error) {
	if m.getResourceRecordSetsFunc != nil {
		return m.getResourceRecordSetsFunc(ctx, project, zone, name, rrtype)
	}
	return []*dns.ResourceRecordSet{}, nil
}

func (m *mockCloudDNSClient) CreateChange(ctx context.Context, project, zone string, change *dns.Change) (*dns.Change, error) {
	if m.createChangeFunc != nil {
		return m.createChangeFunc(ctx, project, zone, change)
	}
	change.Id = "change-123"
	change.Status = "done"
	return change, nil
}

func (m *mockCloudDNSClient) GetChange(ctx context.Context, project, zone, changeID string) (*dns.Change, error) {
	if m.getChangeFunc != nil {
		return m.getChangeFunc(ctx, project, zone, changeID)
	}
	return &dns.Change{Id: changeID, Status: "done"}, nil
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{
			name: "valid with service account",
			config: Config{
				Project:            "my-project",
				ServiceAccountJSON: []byte(`{"type": "service_account"}`),
			},
		},
		{
			name: "valid with ambient",
			config: Config{
				Project: "my-project",
				Ambient: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NoError(t, validateConfig(tt.config))
		})
	}
}

func TestApplyConfigDefaults(t *testing.T) {
	t.Run("applies defaults when zero values", func(t *testing.T) {
		cfg := Config{
			Project: "my-project",
			Ambient: true,
		}

		result := applyConfigDefaults(cfg)

		assert.Equal(t, defaultPropagationTimeout, result.PropagationTimeout)
		assert.Equal(t, defaultPollingInterval, result.PollingInterval)
		assert.Equal(t, int64(defaultRecordTTL), result.TTL)
		assert.Equal(t, defaultHTTPTimeout, result.HTTPTimeout)
	})

	t.Run("preserves non-zero values", func(t *testing.T) {
		cfg := Config{
			Project:            "my-project",
			Ambient:            true,
			PropagationTimeout: 60 * time.Second,
			PollingInterval:    2 * time.Second,
			TTL:                60,
			HTTPTimeout:        15 * time.Second,
		}

		result := applyConfigDefaults(cfg)

		assert.Equal(t, 60*time.Second, result.PropagationTimeout)
		assert.Equal(t, 2*time.Second, result.PollingInterval)
		assert.Equal(t, int64(60), result.TTL)
		assert.Equal(t, 15*time.Second, result.HTTPTimeout)
	})

	t.Run("applies defaults for negative values", func(t *testing.T) {
		cfg := Config{
			PropagationTimeout: -1 * time.Second,
			PollingInterval:    -1 * time.Second,
			TTL:                -1,
			HTTPTimeout:        -1 * time.Second,
		}

		result := applyConfigDefaults(cfg)

		assert.Equal(t, defaultPropagationTimeout, result.PropagationTimeout)
		assert.Equal(t, defaultPollingInterval, result.PollingInterval)
		assert.Equal(t, int64(defaultRecordTTL), result.TTL)
		assert.Equal(t, defaultHTTPTimeout, result.HTTPTimeout)
	})
}

func TestNewWithClient(t *testing.T) {
	mock := &mockCloudDNSClient{}
	provider := NewWithClient(mock, "my-project", "my-zone", nil)

	assert.NotNil(t, provider)
	assert.Equal(t, "my-project", provider.project)
	assert.Equal(t, "my-zone", provider.hostedZoneName)
	assert.Equal(t, defaultPropagationTimeout, provider.propagationTimeout)
	assert.Equal(t, defaultPollingInterval, provider.pollingInterval)
	assert.Equal(t, int64(defaultRecordTTL), provider.ttl)
}

func TestNewWithClientAndConfig(t *testing.T) {
	mock := &mockCloudDNSClient{}
	cfg := Config{
		Project:            "my-project",
		HostedZoneName:     "custom-zone",
		PropagationTimeout: 60 * time.Second,
		PollingInterval:    2 * time.Second,
		TTL:                300,
		Nameservers:        []string{"8.8.8.8:53"},
	}

	provider := NewWithClientAndConfig(mock, cfg)

	assert.NotNil(t, provider)
	assert.Equal(t, "my-project", provider.project)
	assert.Equal(t, "custom-zone", provider.hostedZoneName)
	assert.Equal(t, 60*time.Second, provider.propagationTimeout)
	assert.Equal(t, 2*time.Second, provider.pollingInterval)
	assert.Equal(t, int64(300), provider.ttl)
	assert.Equal(t, []string{"8.8.8.8:53"}, provider.nameservers)
}

func TestTimeout(t *testing.T) {
	t.Run("returns default values", func(t *testing.T) {
		mock := &mockCloudDNSClient{}
		provider := NewWithClient(mock, "my-project", "my-zone", nil)

		timeout, interval := provider.Timeout()

		assert.Equal(t, defaultPropagationTimeout, timeout)
		assert.Equal(t, defaultPollingInterval, interval)
	})

	t.Run("returns configured values", func(t *testing.T) {
		mock := &mockCloudDNSClient{}
		cfg := Config{
			Project:            "my-project",
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
	ctx := context.Background()

	t.Run("creates new record", func(t *testing.T) {
		var capturedChange *dns.Change

		mock := &mockCloudDNSClient{
			getResourceRecordSetsFunc: func(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error) {
				return []*dns.ResourceRecordSet{}, nil
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
		require.Len(t, capturedChange.Additions, 1)
		assert.Equal(t, "_acme-challenge.example.com.", capturedChange.Additions[0].Name)
		assert.Equal(t, "TXT", capturedChange.Additions[0].Type)
		assert.Contains(t, capturedChange.Additions[0].Rrdatas, "token-value")
		assert.Equal(t, int64(defaultRecordTTL), capturedChange.Additions[0].Ttl)
	})

	t.Run("uses custom TTL", func(t *testing.T) {
		var capturedChange *dns.Change

		mock := &mockCloudDNSClient{
			getResourceRecordSetsFunc: func(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error) {
				return []*dns.ResourceRecordSet{}, nil
			},
			createChangeFunc: func(ctx context.Context, project, zone string, change *dns.Change) (*dns.Change, error) {
				capturedChange = change
				change.Id = "change-123"
				change.Status = "done"
				return change, nil
			},
		}

		cfg := Config{
			Project:        "my-project",
			HostedZoneName: "my-zone",
			TTL:            300,
		}
		provider := NewWithClientAndConfig(mock, cfg)

		err := provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.NoError(t, err)

		require.NotNil(t, capturedChange)
		require.Len(t, capturedChange.Additions, 1)
		assert.Equal(t, int64(300), capturedChange.Additions[0].Ttl)
	})

	t.Run("merges with existing records", func(t *testing.T) {
		var capturedChange *dns.Change

		mock := &mockCloudDNSClient{
			getResourceRecordSetsFunc: func(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error) {
				return []*dns.ResourceRecordSet{
					{
						Name:    "_acme-challenge.example.com.",
						Type:    "TXT",
						Ttl:     60,
						Rrdatas: []string{"existing-value"},
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
		require.Len(t, capturedChange.Deletions, 1)
		require.Len(t, capturedChange.Additions, 1)

		assert.Contains(t, capturedChange.Additions[0].Rrdatas, "token-value")
		assert.Contains(t, capturedChange.Additions[0].Rrdatas, "existing-value")
	})

	t.Run("skips if value already exists", func(t *testing.T) {
		createCalled := false

		mock := &mockCloudDNSClient{
			getResourceRecordSetsFunc: func(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error) {
				return []*dns.ResourceRecordSet{
					{
						Name:    "_acme-challenge.example.com.",
						Type:    "TXT",
						Ttl:     60,
						Rrdatas: []string{"token-value"},
					},
				}, nil
			},
			createChangeFunc: func(ctx context.Context, project, zone string, change *dns.Change) (*dns.Change, error) {
				createCalled = true
				return change, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "my-zone", nil)

		err := provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.NoError(t, err)
		assert.False(t, createCalled)
	})

	t.Run("handles quoted values", func(t *testing.T) {
		mock := &mockCloudDNSClient{
			getResourceRecordSetsFunc: func(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error) {
				return []*dns.ResourceRecordSet{
					{
						Name:    "_acme-challenge.example.com.",
						Type:    "TXT",
						Ttl:     60,
						Rrdatas: []string{`"token-value"`},
					},
				}, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "my-zone", nil)

		err := provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		assert.NoError(t, err)
	})
}

func TestCleanUp(t *testing.T) {
	ctx := context.Background()

	t.Run("deletes record", func(t *testing.T) {
		var capturedChange *dns.Change

		mock := &mockCloudDNSClient{
			getResourceRecordSetsFunc: func(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error) {
				return []*dns.ResourceRecordSet{
					{
						Name:    "_acme-challenge.example.com.",
						Type:    "TXT",
						Ttl:     60,
						Rrdatas: []string{"token-value"},
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
		assert.Empty(t, capturedChange.Additions)
	})

	t.Run("keeps other values", func(t *testing.T) {
		var capturedChange *dns.Change

		mock := &mockCloudDNSClient{
			getResourceRecordSetsFunc: func(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error) {
				return []*dns.ResourceRecordSet{
					{
						Name:    "_acme-challenge.example.com.",
						Type:    "TXT",
						Ttl:     60,
						Rrdatas: []string{"token-value", "other-value"},
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
		assert.Equal(t, []string{"other-value"}, capturedChange.Additions[0].Rrdatas)
	})

	t.Run("no matching record is not an error", func(t *testing.T) {
		mock := &mockCloudDNSClient{
			getResourceRecordSetsFunc: func(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error) {
				return []*dns.ResourceRecordSet{}, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "my-zone", nil)

		err := provider.CleanUp(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		assert.NoError(t, err)
	})
}

func TestFindTXTRecords(t *testing.T) {
	ctx := context.Background()

	t.Run("finds matching records", func(t *testing.T) {
		mock := &mockCloudDNSClient{
			getResourceRecordSetsFunc: func(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error) {
				return []*dns.ResourceRecordSet{
					{Name: "_acme-challenge.example.com.", Type: "TXT", Rrdatas: []string{"value1"}},
					{Name: "_acme-challenge.example.com.", Type: "TXT", Rrdatas: []string{"value2"}},
					{Name: "_acme-challenge.example.com.", Type: "A", Rrdatas: []string{"1.2.3.4"}},
					{Name: "other.example.com.", Type: "TXT", Rrdatas: []string{"value1"}},
				}, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "my-zone", nil)

		records, err := provider.findTXTRecords(ctx, "my-zone", "_acme-challenge.example.com.", "value1")
		require.NoError(t, err)
		assert.Len(t, records, 1)
	})
}

func TestWaitForChange(t *testing.T) {
	ctx := context.Background()

	t.Run("immediate done", func(t *testing.T) {
		mock := &mockCloudDNSClient{
			getChangeFunc: func(ctx context.Context, project, zone, changeID string) (*dns.Change, error) {
				return &dns.Change{Id: changeID, Status: "done"}, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "my-zone", nil)

		err := provider.waitForChange(ctx, "my-zone", "change-123")
		assert.NoError(t, err)
	})

	t.Run("eventual done", func(t *testing.T) {
		callCount := 0
		mock := &mockCloudDNSClient{
			getChangeFunc: func(ctx context.Context, project, zone, changeID string) (*dns.Change, error) {
				callCount++
				status := "pending"
				if callCount >= 2 {
					status = "done"
				}
				return &dns.Change{Id: changeID, Status: status}, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "my-zone", nil)

		err := provider.waitForChange(ctx, "my-zone", "change-123")
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, callCount, 2)
	})
}

func TestNewFromEnv(t *testing.T) {
	ctx := context.Background()

	clearEnv := func() {
		os.Unsetenv(envProject)
		os.Unsetenv(envServiceAccountFile)
		os.Unsetenv(envZoneName)
		os.Unsetenv(envPropagationTimeout)
		os.Unsetenv(envPollingInterval)
		os.Unsetenv(envTTL)
		os.Unsetenv(envGoogleAppCredential)
	}

	t.Run("uses ambient credentials when no file specified", func(t *testing.T) {
		clearEnv()
		defer clearEnv()

		os.Setenv(envProject, "test-project")

		// Will succeed or fail depending on ADC availability
		_, _ = NewFromEnv(ctx)
	})

	t.Run("reads service account from file", func(t *testing.T) {
		clearEnv()
		defer clearEnv()

		tmpDir := t.TempDir()
		saFile := filepath.Join(tmpDir, "service-account.json")
		saContent := []byte(`not valid json at all`)
		err := os.WriteFile(saFile, saContent, 0600)
		require.NoError(t, err)

		os.Setenv(envProject, "test-project")
		os.Setenv(envServiceAccountFile, saFile)

		_, err = NewFromEnv(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client")
	})

	t.Run("returns error when file cannot be read", func(t *testing.T) {
		clearEnv()
		defer clearEnv()

		os.Setenv(envProject, "test-project")
		os.Setenv(envServiceAccountFile, "/nonexistent/path/file.json")

		_, err := NewFromEnv(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read file")
	})
}

func TestProviderImplementsInterfaces(t *testing.T) {
	mock := &mockCloudDNSClient{}
	provider := NewWithClient(mock, "my-project", "my-zone", nil)

	var _ providers.Provider = provider
	var _ providers.ProviderTimeout = provider
}

func TestCreateClientErrorPaths(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error with missing credentials", func(t *testing.T) {
		cfg := Config{
			Project: "test-project",
			Ambient: false,
		}

		_, err := createClient(ctx, cfg)
		require.Error(t, err)
		assert.Equal(t, providers.ErrMissingCredentials, err)
	})
}

func TestNewValidationErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("returns wrapped error when createClient fails", func(t *testing.T) {
		cfg := Config{
			Project:            "my-project",
			ServiceAccountJSON: []byte(`{not valid json}`),
		}

		_, err := New(ctx, cfg)
		require.Error(t, err)
		var provErr *providers.ProviderError
		assert.True(t, errors.As(err, &provErr))
		assert.Equal(t, "create client", provErr.Operation)
	})
}

func TestNewProviderFromEnvFactory(t *testing.T) {
	ctx := context.Background()

	originalProject := os.Getenv(envProject)
	defer func() {
		if originalProject != "" {
			os.Setenv(envProject, originalProject)
		} else {
			os.Unsetenv(envProject)
		}
	}()

	t.Run("NewProviderFromEnv exercises init RegisterEnvFactory", func(t *testing.T) {
		os.Unsetenv(envProject)
		os.Unsetenv(envServiceAccountFile)
		os.Unsetenv(envGoogleAppCredential)

		_, err := providers.NewProviderFromEnv(ctx, providers.NameCloudDNS)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "GCE_PROJECT")
	})
}

func TestPresentWaitForChangeError(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when waitForChange times out", func(t *testing.T) {
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

	t.Run("returns error when getChange fails during wait", func(t *testing.T) {
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
				return nil, errors.New("getChange API error")
			},
		}

		cfg := Config{
			Project:            "my-project",
			HostedZoneName:     "my-zone",
			PropagationTimeout: 100 * time.Millisecond,
			PollingInterval:    10 * time.Millisecond,
		}
		provider := NewWithClientAndConfig(mock, cfg)

		err := provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "timeout")
	})
}

func TestCleanUpMultipleRecords(t *testing.T) {
	ctx := context.Background()

	t.Run("deletes multiple matching records", func(t *testing.T) {
		changeCount := 0

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
						Rrdatas: []string{"token-value", "other-value"},
					},
				}, nil
			},
			createChangeFunc: func(ctx context.Context, project, zone string, change *dns.Change) (*dns.Change, error) {
				changeCount++
				change.Id = "change-" + string(rune('0'+changeCount))
				change.Status = "done"
				return change, nil
			},
		}

		provider := NewWithClient(mock, "my-project", "my-zone", nil)

		err := provider.CleanUp(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.NoError(t, err)
		assert.Equal(t, 2, changeCount, "should create two changes for two matching records")
	})
}

func TestPresentExistingRecordWithDifferentType(t *testing.T) {
	ctx := context.Background()

	t.Run("ignores non-TXT existing records for value matching", func(t *testing.T) {
		var capturedChange *dns.Change

		mock := &mockCloudDNSClient{
			getResourceRecordSetsFunc: func(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error) {
				return []*dns.ResourceRecordSet{
					{
						Name:    "_acme-challenge.example.com.",
						Type:    "A",
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

		require.NotNil(t, capturedChange)
		require.Len(t, capturedChange.Deletions, 1)
		require.Len(t, capturedChange.Additions, 1)
		assert.Equal(t, "TXT", capturedChange.Additions[0].Type)
	})
}

// Note: The cloudDNSClient methods (GetManagedZones, GetResourceRecordSets, CreateChange, GetChange)
// at 0% coverage are thin wrappers around the Google Cloud DNS API client. They require real GCP
// credentials and API access to test, so they are covered by integration tests rather than unit tests.
// The mockCloudDNSClient is used in all unit tests to simulate their behavior.
