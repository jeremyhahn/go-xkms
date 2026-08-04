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
)

// ProviderName is a type alias for provider name constants.
type ProviderName string

// Provider name constants as typed values for use with factory functions.
const (
	NameRoute53    ProviderName = ProviderRoute53
	NameCloudflare ProviderName = ProviderCloudflare
	NameAzure      ProviderName = ProviderAzure
	NameCloudDNS   ProviderName = ProviderCloudDNS
)

// NewProvider creates a Provider using the given configuration.
// It looks up the provider factory in the registry and invokes it
// with the provided configuration.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - name: The provider name (use ProviderName constants)
//   - config: Provider-specific configuration struct
//
// Returns ErrProviderNotFound if the provider is not registered.
func NewProvider(ctx context.Context, name ProviderName, config interface{}) (Provider, error) {
	factory := Get(string(name))
	if factory == nil {
		return nil, ErrProviderNotFound
	}
	return factory(ctx, config)
}

// NewProviderFromEnv creates a Provider using environment variables.
// Each provider has specific environment variables it reads for configuration.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - name: The provider name (use ProviderName constants)
//
// Environment variables by provider:
//   - route53: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, AWS_HOSTED_ZONE_ID
//   - cloudflare: CLOUDFLARE_API_TOKEN or CLOUDFLARE_API_KEY + CLOUDFLARE_EMAIL
//   - azure: AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP, AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
//   - clouddns: GOOGLE_PROJECT, GOOGLE_APPLICATION_CREDENTIALS
//
// Returns ErrProviderNotFound if the provider is not supported.
func NewProviderFromEnv(ctx context.Context, name ProviderName) (Provider, error) {
	factory := GetEnvFactory(string(name))
	if factory == nil {
		return nil, ErrProviderNotFound
	}
	return factory(ctx)
}

// ValidProviderName checks if the given name is a valid provider name.
func ValidProviderName(name ProviderName) bool {
	switch name {
	case NameRoute53, NameCloudflare, NameAzure, NameCloudDNS:
		return true
	default:
		return false
	}
}
