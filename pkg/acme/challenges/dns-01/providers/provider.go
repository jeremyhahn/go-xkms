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

// Package providers implements DNS-01 challenge providers for various DNS services.
//
// This package provides a common interface for DNS providers used in ACME DNS-01
// challenge verification. Each provider implements the ability to create and
// remove TXT records required for domain validation.
//
// Supported Providers:
//   - AWS Route53
//   - Cloudflare
//   - Azure DNS
//   - Google Cloud DNS
//
// Usage:
//
//	provider, err := route53.New(ctx, route53.Config{...})
//	if err != nil {
//	    return err
//	}
//	defer provider.CleanUp(ctx, domain, fqdn, value)
//	if err := provider.Present(ctx, domain, fqdn, value); err != nil {
//	    return err
//	}
package providers

import (
	"context"
	"sync"
	"time"
)

// Provider defines the interface for DNS-01 challenge providers.
// Providers are responsible for creating and removing DNS TXT records
// required for ACME DNS-01 challenge verification.
type Provider interface {
	// Present creates a TXT record for the DNS-01 challenge.
	// The record should be created at _acme-challenge.<domain> with the given value.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - domain: The domain being validated (e.g., "example.com")
	//   - fqdn: The fully qualified domain name for the TXT record (e.g., "_acme-challenge.example.com.")
	//   - value: The challenge value to be placed in the TXT record
	//
	// Returns an error if the record cannot be created.
	Present(ctx context.Context, domain, fqdn, value string) error

	// CleanUp removes the TXT record created by Present.
	// This should be called after challenge verification completes.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - domain: The domain being validated
	//   - fqdn: The fully qualified domain name of the TXT record
	//   - value: The challenge value (used to identify the specific record)
	//
	// Returns an error if the record cannot be removed.
	// Implementations should not return an error if the record does not exist.
	CleanUp(ctx context.Context, domain, fqdn, value string) error
}

// ProviderTimeout extends Provider with custom timeout configuration.
// Providers implementing this interface can specify their own propagation
// timeout and polling interval settings.
type ProviderTimeout interface {
	Provider
	// Timeout returns the provider's propagation timeout and polling interval.
	// The timeout is the maximum time to wait for DNS propagation.
	// The interval is the time between DNS propagation checks.
	Timeout() (timeout, interval time.Duration)
}

// ProviderSequential marks providers that must process challenges sequentially.
// Some DNS providers have rate limits or require sequential processing
// of record updates. Providers implementing this interface signal that
// challenges should be processed one at a time with a delay between each.
type ProviderSequential interface {
	Provider
	// Sequential returns the delay between sequential challenge processing.
	// Returns 0 to use the default delay.
	Sequential() time.Duration
}

// ProviderFactory creates a Provider from configuration.
type ProviderFactory func(ctx context.Context, config interface{}) (Provider, error)

// EnvProviderFactory creates a Provider using environment variables.
type EnvProviderFactory func(ctx context.Context) (Provider, error)

// registry holds registered provider factories
var (
	registryMu    sync.RWMutex
	registry      = make(map[string]ProviderFactory)
	envRegistryMu sync.RWMutex
	envRegistry   = make(map[string]EnvProviderFactory)
)

// Register adds a provider factory to the registry.
// This should be called from init() in each provider package.
func Register(name string, factory ProviderFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[name] = factory
}

// Get retrieves a provider factory by name.
// Returns nil if the provider is not registered.
func Get(name string) ProviderFactory {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return registry[name]
}

// RegisterEnvFactory adds an environment-based provider factory to the registry.
// This should be called from init() in each provider package.
func RegisterEnvFactory(name string, factory EnvProviderFactory) {
	envRegistryMu.Lock()
	defer envRegistryMu.Unlock()
	envRegistry[name] = factory
}

// GetEnvFactory retrieves an environment-based provider factory by name.
// Returns nil if the provider is not registered.
func GetEnvFactory(name string) EnvProviderFactory {
	envRegistryMu.RLock()
	defer envRegistryMu.RUnlock()
	return envRegistry[name]
}

// List returns the names of all registered providers.
func List() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}

// Registered returns true if a provider with the given name is registered.
func Registered(name string) bool {
	registryMu.RLock()
	defer registryMu.RUnlock()
	_, ok := registry[name]
	return ok
}

// ProviderName constants for registered providers
const (
	ProviderRoute53    = "route53"
	ProviderCloudflare = "cloudflare"
	ProviderAzure      = "azure"
	ProviderCloudDNS   = "clouddns"
)
