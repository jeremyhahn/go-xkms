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

package providers

import (
	"context"
	"errors"
	"testing"
)

// factoryTestProvider is a test implementation of Provider for factory tests
type factoryTestProvider struct {
	presentCalled bool
	cleanupCalled bool
}

func (p *factoryTestProvider) Present(ctx context.Context, domain, fqdn, value string) error {
	p.presentCalled = true
	return nil
}

func (p *factoryTestProvider) CleanUp(ctx context.Context, domain, fqdn, value string) error {
	p.cleanupCalled = true
	return nil
}

// factoryTestMockFactory creates a factoryTestProvider
func factoryTestMockFactory(ctx context.Context, config interface{}) (Provider, error) {
	if config == nil {
		return nil, ErrInvalidConfig
	}
	return &factoryTestProvider{}, nil
}

// factoryTestErrorFactory always returns an error
func factoryTestErrorFactory(ctx context.Context, config interface{}) (Provider, error) {
	return nil, errors.New("factory error")
}

func TestFactoryNewProvider(t *testing.T) {
	ctx := context.Background()

	// Register a mock provider for testing
	const testProviderName = "factory-test-provider"
	Register(testProviderName, factoryTestMockFactory)
	defer func() {
		// Clean up registry after test
		registryMu.Lock()
		delete(registry, testProviderName)
		registryMu.Unlock()
	}()

	t.Run("Success", func(t *testing.T) {
		provider, err := NewProvider(ctx, ProviderName(testProviderName), struct{}{})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if provider == nil {
			t.Fatal("expected provider, got nil")
		}

		// Verify the provider works
		ftp, ok := provider.(*factoryTestProvider)
		if !ok {
			t.Fatal("expected factoryTestProvider type")
		}
		if err := provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token"); err != nil {
			t.Errorf("Present failed: %v", err)
		}
		if !ftp.presentCalled {
			t.Error("Present was not called")
		}
	})

	t.Run("ProviderNotFound", func(t *testing.T) {
		provider, err := NewProvider(ctx, "nonexistent-provider", struct{}{})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, ErrProviderNotFound) {
			t.Errorf("expected ErrProviderNotFound, got %v", err)
		}
		if provider != nil {
			t.Error("expected nil provider")
		}
	})

	t.Run("FactoryReturnsError", func(t *testing.T) {
		const errorProviderName = "factory-error-provider"
		Register(errorProviderName, factoryTestErrorFactory)
		defer func() {
			registryMu.Lock()
			delete(registry, errorProviderName)
			registryMu.Unlock()
		}()

		provider, err := NewProvider(ctx, ProviderName(errorProviderName), struct{}{})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if provider != nil {
			t.Error("expected nil provider")
		}
	})

	t.Run("NilConfig", func(t *testing.T) {
		provider, err := NewProvider(ctx, ProviderName(testProviderName), nil)
		if err == nil {
			t.Fatal("expected error for nil config, got nil")
		}
		if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("expected ErrInvalidConfig, got %v", err)
		}
		if provider != nil {
			t.Error("expected nil provider")
		}
	})

	t.Run("EmptyProviderName", func(t *testing.T) {
		provider, err := NewProvider(ctx, "", struct{}{})
		if err == nil {
			t.Fatal("expected error for empty name, got nil")
		}
		if !errors.Is(err, ErrProviderNotFound) {
			t.Errorf("expected ErrProviderNotFound, got %v", err)
		}
		if provider != nil {
			t.Error("expected nil provider")
		}
	})
}

func TestFactoryNewProviderFromEnv(t *testing.T) {
	ctx := context.Background()

	t.Run("UnknownProvider", func(t *testing.T) {
		provider, err := NewProviderFromEnv(ctx, "unknown-provider")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, ErrProviderNotFound) {
			t.Errorf("expected ErrProviderNotFound, got %v", err)
		}
		if provider != nil {
			t.Error("expected nil provider")
		}
	})

	t.Run("EmptyProviderName", func(t *testing.T) {
		provider, err := NewProviderFromEnv(ctx, "")
		if err == nil {
			t.Fatal("expected error for empty name, got nil")
		}
		if !errors.Is(err, ErrProviderNotFound) {
			t.Errorf("expected ErrProviderNotFound, got %v", err)
		}
		if provider != nil {
			t.Error("expected nil provider")
		}
	})

	// Test that known providers return appropriate errors when credentials are not configured
	t.Run("Route53MissingCredentials", func(t *testing.T) {
		// Clear any existing AWS credentials from environment
		t.Setenv("AWS_ACCESS_KEY_ID", "")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "")
		t.Setenv("AWS_REGION", "")

		provider, err := NewProviderFromEnv(ctx, NameRoute53)
		if err == nil {
			t.Fatal("expected error for missing credentials, got nil")
		}
		if provider != nil {
			t.Error("expected nil provider")
		}
		// Route53 returns ErrMissingCredentials when no creds are configured
		if !errors.Is(err, ErrMissingCredentials) {
			t.Logf("got error: %v", err)
		}
	})

	t.Run("CloudflareMissingCredentials", func(t *testing.T) {
		// Clear any existing Cloudflare credentials from environment
		t.Setenv("CLOUDFLARE_API_TOKEN", "")
		t.Setenv("CLOUDFLARE_API_KEY", "")
		t.Setenv("CLOUDFLARE_EMAIL", "")
		t.Setenv("CF_API_TOKEN", "")
		t.Setenv("CF_API_KEY", "")
		t.Setenv("CF_EMAIL", "")

		provider, err := NewProviderFromEnv(ctx, NameCloudflare)
		if err == nil {
			t.Fatal("expected error for missing credentials, got nil")
		}
		if provider != nil {
			t.Error("expected nil provider")
		}
	})

	t.Run("AzureMissingCredentials", func(t *testing.T) {
		// Clear any existing Azure credentials from environment
		t.Setenv("AZURE_SUBSCRIPTION_ID", "")
		t.Setenv("AZURE_RESOURCE_GROUP", "")
		t.Setenv("AZURE_CLIENT_ID", "")
		t.Setenv("AZURE_CLIENT_SECRET", "")
		t.Setenv("AZURE_TENANT_ID", "")

		provider, err := NewProviderFromEnv(ctx, NameAzure)
		if err == nil {
			t.Fatal("expected error for missing credentials, got nil")
		}
		if provider != nil {
			t.Error("expected nil provider")
		}
	})

	t.Run("CloudDNSMissingCredentials", func(t *testing.T) {
		// Clear any existing GCE credentials from environment
		t.Setenv("GCE_PROJECT", "")
		t.Setenv("GCE_SERVICE_ACCOUNT_FILE", "")
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")

		provider, err := NewProviderFromEnv(ctx, NameCloudDNS)
		if err == nil {
			t.Fatal("expected error for missing credentials, got nil")
		}
		if provider != nil {
			t.Error("expected nil provider")
		}
	})
}

func TestFactoryValidProviderName(t *testing.T) {
	tests := []struct {
		name     string
		input    ProviderName
		expected bool
	}{
		{
			name:     "Route53Valid",
			input:    NameRoute53,
			expected: true,
		},
		{
			name:     "CloudflareValid",
			input:    NameCloudflare,
			expected: true,
		},
		{
			name:     "AzureValid",
			input:    NameAzure,
			expected: true,
		},
		{
			name:     "CloudDNSValid",
			input:    NameCloudDNS,
			expected: true,
		},
		{
			name:     "EmptyStringInvalid",
			input:    "",
			expected: false,
		},
		{
			name:     "UnknownProviderInvalid",
			input:    "unknown",
			expected: false,
		},
		{
			name:     "CaseSensitive",
			input:    "Route53",
			expected: false,
		},
		{
			name:     "PartialMatchInvalid",
			input:    "route",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidProviderName(tt.input)
			if result != tt.expected {
				t.Errorf("ValidProviderName(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestFactoryProviderNameConstants(t *testing.T) {
	// Verify that ProviderName constants match the string constants
	t.Run("NameRoute53MatchesConstant", func(t *testing.T) {
		if string(NameRoute53) != ProviderRoute53 {
			t.Errorf("NameRoute53 = %q, want %q", NameRoute53, ProviderRoute53)
		}
	})

	t.Run("NameCloudflareMatchesConstant", func(t *testing.T) {
		if string(NameCloudflare) != ProviderCloudflare {
			t.Errorf("NameCloudflare = %q, want %q", NameCloudflare, ProviderCloudflare)
		}
	})

	t.Run("NameAzureMatchesConstant", func(t *testing.T) {
		if string(NameAzure) != ProviderAzure {
			t.Errorf("NameAzure = %q, want %q", NameAzure, ProviderAzure)
		}
	})

	t.Run("NameCloudDNSMatchesConstant", func(t *testing.T) {
		if string(NameCloudDNS) != ProviderCloudDNS {
			t.Errorf("NameCloudDNS = %q, want %q", NameCloudDNS, ProviderCloudDNS)
		}
	})
}

func TestFactoryNewProviderWithCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	const testProviderName = "factory-context-test-provider"

	// Register a provider that checks context
	contextAwareFactory := func(ctx context.Context, config interface{}) (Provider, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			return &factoryTestProvider{}, nil
		}
	}

	Register(testProviderName, contextAwareFactory)
	defer func() {
		registryMu.Lock()
		delete(registry, testProviderName)
		registryMu.Unlock()
	}()

	provider, err := NewProvider(ctx, ProviderName(testProviderName), struct{}{})
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	if provider != nil {
		t.Error("expected nil provider")
	}
}
