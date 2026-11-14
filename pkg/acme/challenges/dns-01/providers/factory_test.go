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
