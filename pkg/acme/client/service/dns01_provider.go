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

package service

import (
	"context"
	"log/slog"
	"strconv"

	dns01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01"
	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers"
	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers/azure"
	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers/clouddns"
	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers/cloudflare"
	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers/route53"
)

// DNS01Challenge is a DNS-01 TXT record provisioned by SetupDNS01Challenge
// through a configured DNS provider. The record must be removed once ACME
// validation completes by calling Cleanup.
type DNS01Challenge struct {
	provider providers.Provider
	domain   string
	fqdn     string
	value    string
	logger   *slog.Logger
}

// Cleanup removes the DNS TXT record created for this challenge. It is a
// no-op on a nil receiver so callers can defer it unconditionally, including
// when SetupDNS01Challenge ran in manual mode and returned a nil challenge.
func (c *DNS01Challenge) Cleanup(ctx context.Context) error {
	if c == nil {
		return nil
	}

	if err := c.provider.CleanUp(ctx, c.domain, c.fqdn, c.value); err != nil {
		return ErrChallengeCleanupFailed{ChallengeType: "dns-01", Reason: err.Error()}
	}

	c.logger.Debug("DNS-01 challenge record removed", slog.String("record", c.fqdn))
	return nil
}

// newDNS01Challenge provisions the TXT record through provider and returns a
// handle for later cleanup. It is the seam that lets DNS-01 record creation
// be tested against a fake Provider without a real DNS API.
func newDNS01Challenge(ctx context.Context, provider providers.Provider, domain, fqdn, value string, logger *slog.Logger) (*DNS01Challenge, error) {
	if err := provider.Present(ctx, domain, fqdn, value); err != nil {
		return nil, ErrChallengeSetupFailed{ChallengeType: "dns-01", Reason: err.Error()}
	}

	logger.Info("DNS-01 challenge record created", slog.String("record", fqdn))

	return &DNS01Challenge{
		provider: provider,
		domain:   domain,
		fqdn:     fqdn,
		value:    value,
		logger:   logger,
	}, nil
}

// buildDNS01Provider constructs the DNS provider named by cfg.Provider from
// cfg.Credentials. Supported providers are route53, cloudflare, azure, and
// clouddns -- the providers this project implements. Any other name fails
// fast with ErrUnsupportedDNSProvider instead of continuing on to a
// validation that can never succeed.
func buildDNS01Provider(ctx context.Context, cfg DNS01Config) (providers.Provider, error) {
	providerConfig, err := buildDNS01ProviderConfig(cfg)
	if err != nil {
		return nil, err
	}

	provider, err := dns01.GetProvider(ctx, cfg.Provider, providerConfig)
	if err != nil {
		return nil, ErrChallengeSetupFailed{ChallengeType: "dns-01", Reason: err.Error()}
	}
	return provider, nil
}

// buildDNS01ProviderConfig maps the generic credentials the operator
// configured into the provider-specific Config struct the named provider's
// constructor requires.
func buildDNS01ProviderConfig(cfg DNS01Config) (interface{}, error) {
	ambient, err := dns01CredentialBool(cfg, "ambient")
	if err != nil {
		return nil, err
	}

	switch cfg.Provider {
	case providers.ProviderRoute53:
		return route53.Config{
			AccessKeyID:      cfg.Credentials["accessKeyId"],
			SecretAccessKey:  cfg.Credentials["secretAccessKey"],
			Region:           cfg.Credentials["region"],
			HostedZoneID:     cfg.Credentials["hostedZoneId"],
			Role:             cfg.Credentials["role"],
			WebIdentityToken: cfg.Credentials["webIdentityToken"],
			Ambient:          ambient,
			TTL:              cfg.TTL,
		}, nil

	case providers.ProviderCloudflare:
		return cloudflare.Config{
			Email:        cfg.Credentials["email"],
			APIKey:       cfg.Credentials["apiKey"],
			APIToken:     cfg.Credentials["apiToken"],
			ZoneAPIToken: cfg.Credentials["zoneApiToken"],
			ZoneID:       cfg.Credentials["zoneId"],
			BaseURL:      cfg.Credentials["baseUrl"],
			TTL:          cfg.TTL,
		}, nil

	case providers.ProviderAzure:
		return azure.Config{
			ClientID:                  cfg.Credentials["clientId"],
			ClientSecret:              cfg.Credentials["clientSecret"],
			TenantID:                  cfg.Credentials["tenantId"],
			SubscriptionID:            cfg.Credentials["subscriptionId"],
			ResourceGroupName:         cfg.Credentials["resourceGroupName"],
			ZoneName:                  cfg.Credentials["zoneName"],
			Environment:               cfg.Credentials["environment"],
			Ambient:                   ambient,
			ManagedIdentityClientID:   cfg.Credentials["managedIdentityClientId"],
			ManagedIdentityResourceID: cfg.Credentials["managedIdentityResourceId"],
			TTL:                       int64(cfg.TTL),
		}, nil

	case providers.ProviderCloudDNS:
		return clouddns.Config{
			Project:            cfg.Credentials["project"],
			ServiceAccountJSON: []byte(cfg.Credentials["serviceAccountJson"]),
			HostedZoneName:     cfg.Credentials["hostedZoneName"],
			Ambient:            ambient,
			TTL:                int64(cfg.TTL),
		}, nil

	default:
		return nil, ErrUnsupportedDNSProvider{Provider: cfg.Provider}
	}
}

// dns01CredentialBool parses an optional boolean credential, failing fast
// with a typed error on a value that is present but not a valid boolean
// rather than silently treating it as false.
func dns01CredentialBool(cfg DNS01Config, key string) (bool, error) {
	value, ok := cfg.Credentials[key]
	if !ok || value == "" {
		return false, nil
	}

	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, ErrInvalidDNSProviderCredential{Provider: cfg.Provider, Key: key, Reason: err.Error()}
	}
	return parsed, nil
}
