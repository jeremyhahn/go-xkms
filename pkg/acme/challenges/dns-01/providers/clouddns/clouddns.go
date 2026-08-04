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

// Package clouddns implements a DNS-01 challenge provider using Google Cloud DNS.
//
// This provider supports:
//   - Service account JSON credentials
//   - Application default credentials (ADC)
//   - Workload Identity (for GKE)
//
// Usage with service account:
//
//	credentials, _ := os.ReadFile("/path/to/service-account.json")
//	provider, err := clouddns.New(ctx, clouddns.Config{
//	    Project:               "my-project",
//	    ServiceAccountJSON:    credentials,
//	})
//	if err != nil {
//	    return err
//	}
//	err = provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "challenge-token")
//
// Usage with ADC:
//
//	provider, err := clouddns.New(ctx, clouddns.Config{
//	    Project: "my-project",
//	    Ambient: true,
//	})
//
// Usage with environment variables:
//
//	provider, err := clouddns.NewFromEnv(ctx)
//	if err != nil {
//	    return err
//	}
package clouddns

import (
	"context"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"

	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers"
)

const (
	providerName = "clouddns"

	// Default configuration values
	defaultRecordTTL          = 120
	defaultPropagationTimeout = 120 * time.Second
	defaultPollingInterval    = 4 * time.Second
	defaultHTTPTimeout        = 30 * time.Second

	// Environment variable names (not credentials - just env var names for configuration)
	envProject             = "GCE_PROJECT"
	envServiceAccountFile  = "GCE_SERVICE_ACCOUNT_FILE"
	envZoneName            = "GCE_ZONE_NAME"
	envPropagationTimeout  = "GCE_PROPAGATION_TIMEOUT"
	envPollingInterval     = "GCE_POLLING_INTERVAL"
	envTTL                 = "GCE_TTL"
	envGoogleAppCredential = "GOOGLE_APPLICATION_CREDENTIALS" // #nosec G101 - env var name, not a credential
)

func init() {
	providers.Register(providers.ProviderCloudDNS, func(ctx context.Context, cfg interface{}) (providers.Provider, error) {
		c, ok := cfg.(Config)
		if !ok {
			return nil, providers.NewConfigError(providerName, "config", "expected clouddns.Config")
		}
		return New(ctx, c)
	})
	providers.RegisterEnvFactory(providers.ProviderCloudDNS, func(ctx context.Context) (providers.Provider, error) {
		return NewFromEnv(ctx)
	})
}

// Config holds the configuration for the Google Cloud DNS provider.
type Config struct {
	// Project is the GCP project ID.
	// Required.
	Project string

	// ServiceAccountJSON is the JSON key file data for a service account.
	// Optional if using ambient credentials.
	ServiceAccountJSON []byte

	// HostedZoneName is the Cloud DNS managed zone name.
	// Optional - if not provided, the zone will be discovered automatically.
	HostedZoneName string

	// Ambient enables ambient credential discovery (ADC, workload identity).
	Ambient bool

	// Nameservers is a list of DNS nameservers for zone lookup.
	// Optional - defaults to system nameservers.
	Nameservers []string

	// PropagationTimeout is the maximum time to wait for DNS propagation.
	// Default: 120 seconds.
	PropagationTimeout time.Duration

	// PollingInterval is the time between DNS propagation checks.
	// Default: 4 seconds.
	PollingInterval time.Duration

	// TTL is the time-to-live for DNS records in seconds.
	// Default: 120 seconds.
	TTL int64

	// HTTPTimeout is the timeout for HTTP requests to the Google Cloud DNS API.
	// Default: 30 seconds.
	HTTPTimeout time.Duration
}

// Provider implements the DNS-01 challenge provider interface for Google Cloud DNS.
type Provider struct {
	project            string
	hostedZoneName     string
	client             CloudDNSAPI
	nameservers        []string
	propagationTimeout time.Duration
	pollingInterval    time.Duration
	ttl                int64
}

// CloudDNSAPI defines the Google Cloud DNS operations used by the provider.
// This interface enables mocking for tests.
type CloudDNSAPI interface {
	GetManagedZones(ctx context.Context, project string) ([]*dns.ManagedZone, error)
	GetResourceRecordSets(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error)
	CreateChange(ctx context.Context, project, zone string, change *dns.Change) (*dns.Change, error)
	GetChange(ctx context.Context, project, zone, changeID string) (*dns.Change, error)
}

// cloudDNSClient wraps the Google Cloud DNS service.
type cloudDNSClient struct {
	service *dns.Service
}

// New creates a new Google Cloud DNS provider.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	// Apply defaults
	cfg = applyConfigDefaults(cfg)

	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	client, err := createClient(ctx, cfg)
	if err != nil {
		return nil, providers.NewProviderError(providerName, "create client", "", err)
	}

	return &Provider{
		project:            cfg.Project,
		hostedZoneName:     cfg.HostedZoneName,
		client:             client,
		nameservers:        cfg.Nameservers,
		propagationTimeout: cfg.PropagationTimeout,
		pollingInterval:    cfg.PollingInterval,
		ttl:                cfg.TTL,
	}, nil
}

// NewFromEnv creates a new Google Cloud DNS provider from environment variables.
//
// Supported environment variables:
//   - GCE_PROJECT: GCP project ID (required)
//   - GCE_SERVICE_ACCOUNT_FILE: Path to service account JSON file (optional)
//   - GCE_ZONE_NAME: Cloud DNS managed zone name (optional)
//   - GCE_PROPAGATION_TIMEOUT: DNS propagation timeout (default: 120s)
//   - GCE_POLLING_INTERVAL: Polling interval for propagation checks (default: 4s)
//   - GCE_TTL: Record TTL in seconds (default: 120)
//   - GOOGLE_APPLICATION_CREDENTIALS: Alternative to GCE_SERVICE_ACCOUNT_FILE
//
// If neither GCE_SERVICE_ACCOUNT_FILE nor GOOGLE_APPLICATION_CREDENTIALS is set,
// ambient credentials (ADC) will be used.
func NewFromEnv(ctx context.Context) (*Provider, error) {
	project, err := providers.GetEnvOrFile(envProject)
	if err != nil {
		return nil, providers.NewConfigError(providerName, "project", err.Error())
	}
	if project == "" {
		return nil, providers.NewConfigError(providerName, "project", "GCE_PROJECT is required")
	}

	cfg := Config{
		Project:            project,
		HostedZoneName:     providers.GetEnvOrDefault(envZoneName, ""),
		PropagationTimeout: providers.GetEnvDuration(envPropagationTimeout, defaultPropagationTimeout),
		PollingInterval:    providers.GetEnvDuration(envPollingInterval, defaultPollingInterval),
		TTL:                int64(providers.GetEnvInt(envTTL, defaultRecordTTL)),
	}

	// Check for service account file
	saFile, err := providers.GetEnvOrFile(envServiceAccountFile)
	if err != nil {
		return nil, providers.NewConfigError(providerName, "service_account_file", err.Error())
	}

	if saFile == "" {
		// Check GOOGLE_APPLICATION_CREDENTIALS
		saFile = os.Getenv(envGoogleAppCredential)
	}

	if saFile != "" {
		// #nosec G304 - service account file path is administrator-controlled config/env
		data, err := os.ReadFile(saFile)
		if err != nil {
			return nil, providers.NewConfigError(providerName, "service_account_file", "failed to read file: "+err.Error())
		}
		cfg.ServiceAccountJSON = data
	} else {
		// Use ambient credentials
		cfg.Ambient = true
	}

	return New(ctx, cfg)
}

// NewWithClient creates a new Google Cloud DNS provider with a custom client.
// This is useful for testing with mock clients.
func NewWithClient(client CloudDNSAPI, project, hostedZoneName string, nameservers []string) *Provider {
	return &Provider{
		project:            project,
		hostedZoneName:     hostedZoneName,
		client:             client,
		nameservers:        nameservers,
		propagationTimeout: defaultPropagationTimeout,
		pollingInterval:    defaultPollingInterval,
		ttl:                defaultRecordTTL,
	}
}

// NewWithClientAndConfig creates a new Google Cloud DNS provider with a custom client
// and full configuration options. This is useful for testing with mock clients while
// also testing timeout and TTL configuration.
func NewWithClientAndConfig(client CloudDNSAPI, cfg Config) *Provider {
	cfg = applyConfigDefaults(cfg)
	return &Provider{
		project:            cfg.Project,
		hostedZoneName:     cfg.HostedZoneName,
		client:             client,
		nameservers:        cfg.Nameservers,
		propagationTimeout: cfg.PropagationTimeout,
		pollingInterval:    cfg.PollingInterval,
		ttl:                cfg.TTL,
	}
}

// Timeout returns the propagation timeout and polling interval for this provider.
// This implements the ProviderTimeout interface.
func (p *Provider) Timeout() (timeout, interval time.Duration) {
	return p.propagationTimeout, p.pollingInterval
}

// Present creates a TXT record for the DNS-01 challenge.
func (p *Provider) Present(ctx context.Context, domain, fqdn, value string) error {
	zone, err := p.getHostedZone(ctx, fqdn)
	if err != nil {
		return providers.NewProviderError(providerName, "get zone", domain, err)
	}

	// Build the new record
	newRecord := &dns.ResourceRecordSet{
		Name:    fqdn,
		Rrdatas: []string{value},
		Ttl:     p.ttl,
		Type:    "TXT",
	}

	change := &dns.Change{}

	// Check for existing records
	existing, err := p.client.GetResourceRecordSets(ctx, p.project, zone, fqdn, "TXT")
	if err != nil {
		return providers.NewProviderError(providerName, "get records", domain, err)
	}

	if len(existing) > 0 {
		// Check if our value already exists
		for _, r := range existing {
			if r.Type == "TXT" && r.Name == fqdn {
				for _, data := range r.Rrdatas {
					if strings.Trim(data, "\"") == value {
						// Already present
						return nil
					}
				}
				// Merge existing data with new value
				newRecord.Rrdatas = append(newRecord.Rrdatas, r.Rrdatas...)
			}
		}
		// Need to delete old and add new in atomic operation
		change.Deletions = existing
	}

	change.Additions = []*dns.ResourceRecordSet{newRecord}

	// Create the change
	chg, err := p.client.CreateChange(ctx, p.project, zone, change)
	if err != nil {
		return providers.NewProviderError(providerName, "create record", domain, err)
	}

	// Wait for propagation
	return p.waitForChange(ctx, zone, chg.Id)
}

// CleanUp removes the TXT record created by Present.
func (p *Provider) CleanUp(ctx context.Context, domain, fqdn, value string) error {
	zone, err := p.getHostedZone(ctx, fqdn)
	if err != nil {
		return providers.NewProviderError(providerName, "get zone", domain, err)
	}

	records, err := p.findTXTRecords(ctx, zone, fqdn, value)
	if err != nil {
		return providers.NewProviderError(providerName, "find records", domain, err)
	}

	for _, rec := range records {
		change := &dns.Change{
			Deletions: []*dns.ResourceRecordSet{rec},
		}

		// If more than one value, keep the others
		if len(rec.Rrdatas) > 1 {
			filtered := &dns.ResourceRecordSet{
				Name:    rec.Name,
				Type:    rec.Type,
				Ttl:     rec.Ttl,
				Rrdatas: make([]string, 0, len(rec.Rrdatas)),
			}
			for _, data := range rec.Rrdatas {
				if strings.Trim(data, "\"") != value {
					filtered.Rrdatas = append(filtered.Rrdatas, data)
				}
			}
			if len(filtered.Rrdatas) > 0 {
				change.Additions = []*dns.ResourceRecordSet{filtered}
			}
		}

		_, err = p.client.CreateChange(ctx, p.project, zone, change)
		if err != nil {
			return providers.NewProviderError(providerName, "delete record", domain, err)
		}
	}

	return nil
}

// getHostedZone returns the managed zone name for the given FQDN.
func (p *Provider) getHostedZone(ctx context.Context, domain string) (string, error) {
	if p.hostedZoneName != "" {
		return p.hostedZoneName, nil
	}

	// Find the authoritative zone
	authZone, err := providers.FindZoneByFQDN(ctx, providers.ToFQDN(domain), p.nameservers)
	if err != nil {
		return "", err
	}

	// List managed zones to find a match
	zones, err := p.client.GetManagedZones(ctx, p.project)
	if err != nil {
		return "", err
	}

	// Find zones with matching DNS name
	var matchingZones []*dns.ManagedZone
	for _, z := range zones {
		if z.DnsName == authZone {
			matchingZones = append(matchingZones, z)
		}
	}

	if len(matchingZones) == 0 {
		return "", providers.ErrZoneNotFound
	}

	// Prefer public zones
	for _, z := range matchingZones {
		if z.Visibility == "public" {
			return z.Name, nil
		}
	}

	// Fall back to first matching zone
	return matchingZones[0].Name, nil
}

// findTXTRecords finds TXT records matching the FQDN and value.
func (p *Provider) findTXTRecords(ctx context.Context, zone, fqdn, value string) ([]*dns.ResourceRecordSet, error) {
	records, err := p.client.GetResourceRecordSets(ctx, p.project, zone, "", "")
	if err != nil {
		return nil, err
	}

	var found []*dns.ResourceRecordSet
	for _, r := range records {
		if r.Type == "TXT" && r.Name == fqdn {
			for _, data := range r.Rrdatas {
				if strings.Trim(data, "\"") == value {
					found = append(found, r)
					break
				}
			}
		}
	}

	return found, nil
}

// waitForChange waits for a DNS change to be synchronized.
func (p *Provider) waitForChange(ctx context.Context, zone, changeID string) error {
	return providers.WaitForCtx(ctx, p.propagationTimeout, p.pollingInterval, func() (bool, error) {
		chg, err := p.client.GetChange(ctx, p.project, zone, changeID)
		if err != nil {
			return false, err
		}
		return chg.Status == "done", nil
	})
}

// createClient creates the Google Cloud DNS client.
func createClient(ctx context.Context, cfg Config) (CloudDNSAPI, error) {
	var opts []option.ClientOption

	if len(cfg.ServiceAccountJSON) > 0 {
		// Use service account credentials
		jwtConfig, err := google.JWTConfigFromJSON(cfg.ServiceAccountJSON, dns.NdevClouddnsReadwriteScope)
		if err != nil {
			return nil, err
		}
		httpClient := jwtConfig.Client(ctx)
		if cfg.HTTPTimeout > 0 {
			httpClient.Timeout = cfg.HTTPTimeout
		}
		opts = append(opts, option.WithHTTPClient(httpClient))
	} else if cfg.Ambient {
		// Use application default credentials
		client, err := google.DefaultClient(ctx, dns.NdevClouddnsReadwriteScope)
		if err != nil {
			return nil, err
		}
		if cfg.HTTPTimeout > 0 {
			client.Timeout = cfg.HTTPTimeout
		}
		opts = append(opts, option.WithHTTPClient(client))
	} else {
		return nil, providers.ErrMissingCredentials
	}

	svc, err := dns.NewService(ctx, opts...)
	if err != nil {
		return nil, err
	}

	return &cloudDNSClient{service: svc}, nil
}

// Implement CloudDNSAPI for cloudDNSClient

func (c *cloudDNSClient) GetManagedZones(ctx context.Context, project string) ([]*dns.ManagedZone, error) {
	resp, err := c.service.ManagedZones.List(project).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	return resp.ManagedZones, nil
}

func (c *cloudDNSClient) GetResourceRecordSets(ctx context.Context, project, zone, name, rrtype string) ([]*dns.ResourceRecordSet, error) {
	call := c.service.ResourceRecordSets.List(project, zone).Context(ctx)
	if name != "" {
		call = call.Name(name)
	}
	if rrtype != "" {
		call = call.Type(rrtype)
	}
	resp, err := call.Do()
	if err != nil {
		return nil, err
	}
	return resp.Rrsets, nil
}

func (c *cloudDNSClient) CreateChange(ctx context.Context, project, zone string, change *dns.Change) (*dns.Change, error) {
	return c.service.Changes.Create(project, zone, change).Context(ctx).Do()
}

func (c *cloudDNSClient) GetChange(ctx context.Context, project, zone, changeID string) (*dns.Change, error) {
	return c.service.Changes.Get(project, zone, changeID).Context(ctx).Do()
}

// applyConfigDefaults applies default values to the configuration.
func applyConfigDefaults(cfg Config) Config {
	if cfg.PropagationTimeout <= 0 {
		cfg.PropagationTimeout = defaultPropagationTimeout
	}
	if cfg.PollingInterval <= 0 {
		cfg.PollingInterval = defaultPollingInterval
	}
	if cfg.TTL <= 0 {
		cfg.TTL = defaultRecordTTL
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = defaultHTTPTimeout
	}
	return cfg
}

// validateConfig validates the Google Cloud DNS configuration.
func validateConfig(cfg Config) error {
	if cfg.Project == "" {
		return providers.NewConfigError(providerName, "project", "is required")
	}

	if len(cfg.ServiceAccountJSON) == 0 && !cfg.Ambient {
		return providers.NewConfigError(providerName, "credentials", "either service account JSON or ambient must be enabled")
	}

	return nil
}
