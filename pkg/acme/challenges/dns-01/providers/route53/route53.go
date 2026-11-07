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

// Package route53 implements a DNS-01 challenge provider using AWS Route53.
//
// This provider supports:
//   - Static credentials (access key ID and secret access key)
//   - Ambient credentials (IAM roles, environment variables, EC2 instance profiles)
//   - STS assume role
//   - Web identity token (for EKS/IRSA)
//
// Usage:
//
//	provider, err := route53.New(ctx, route53.Config{
//	    AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
//	    SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
//	    Region:          "us-east-1",
//	})
//	if err != nil {
//	    return err
//	}
//	err = provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "challenge-token")
//
// Environment Variables:
//
// The provider can be configured via environment variables using NewFromEnv():
//   - AWS_ACCESS_KEY_ID: AWS access key ID
//   - AWS_SECRET_ACCESS_KEY: AWS secret access key
//   - AWS_HOSTED_ZONE_ID: Route53 hosted zone ID
//   - AWS_REGION: AWS region
//   - AWS_PROPAGATION_TIMEOUT or ROUTE53_PROPAGATION_TIMEOUT: DNS propagation timeout (default 120s)
//   - AWS_POLLING_INTERVAL or ROUTE53_POLLING_INTERVAL: Polling interval (default 4s)
//   - AWS_TTL or ROUTE53_TTL: DNS record TTL (default 10)
package route53

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers"
)

const (
	providerName = "route53"

	// Default configuration values
	defaultTTL                = 10
	defaultPropagationTimeout = 120 * time.Second
	defaultPollingInterval    = 4 * time.Second
	defaultHTTPTimeout        = 30 * time.Second

	// Environment variable names (not credentials - just env var names for configuration)
	envAWSAccessKeyID            = "AWS_ACCESS_KEY_ID"
	envAWSSecretAccessKey        = "AWS_SECRET_ACCESS_KEY" // #nosec G101 - env var name, not a credential
	envAWSHostedZoneID           = "AWS_HOSTED_ZONE_ID"
	envAWSRegion                 = "AWS_REGION"
	envAWSPropagationTimeout     = "AWS_PROPAGATION_TIMEOUT"
	envAWSPollingInterval        = "AWS_POLLING_INTERVAL"
	envAWSTTL                    = "AWS_TTL"
	envRoute53PropagationTimeout = "ROUTE53_PROPAGATION_TIMEOUT"
	envRoute53PollingInterval    = "ROUTE53_POLLING_INTERVAL"
	envRoute53TTL                = "ROUTE53_TTL"
)

func init() {
	providers.Register(providers.ProviderRoute53, func(ctx context.Context, cfg interface{}) (providers.Provider, error) {
		c, ok := cfg.(Config)
		if !ok {
			return nil, providers.NewConfigError(providerName, "config", "expected route53.Config")
		}
		return New(ctx, c)
	})
	providers.RegisterEnvFactory(providers.ProviderRoute53, func(ctx context.Context) (providers.Provider, error) {
		provider, err := NewFromEnv(ctx)
		if err != nil {
			return nil, err
		}
		return provider, nil
	})
}

// Config holds the configuration for the Route53 provider.
type Config struct {
	// AccessKeyID is the AWS access key ID for authentication.
	// Optional if using ambient credentials.
	AccessKeyID string

	// SecretAccessKey is the AWS secret access key for authentication.
	// Optional if using ambient credentials.
	SecretAccessKey string

	// Region is the AWS region for the Route53 API.
	// Optional when using ambient credentials with region from environment.
	Region string

	// HostedZoneID is the Route53 hosted zone ID.
	// Optional - if not provided, the zone will be discovered automatically.
	HostedZoneID string

	// Role is the ARN of the IAM role to assume.
	// Optional - only used for cross-account access.
	Role string

	// WebIdentityToken is the web identity token for IRSA authentication.
	// Optional - only used for EKS workload identity.
	WebIdentityToken string

	// Ambient enables ambient credential discovery (IAM roles, env vars, etc).
	// Set to true to use EC2 instance profiles, ECS task roles, or IRSA.
	Ambient bool

	// ZoneFinder resolves the zone apex for an FQDN during zone discovery.
	// Optional - nil selects providers.FindZoneByFQDN, the cached lookup that
	// queries DNS. Supplying one bypasses that cache; see providers.ZoneFinder
	// for why.
	ZoneFinder providers.ZoneFinder

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
	// Default: 10.
	TTL int

	// HTTPTimeout is the timeout for HTTP requests to AWS APIs.
	// Default: 30 seconds.
	HTTPTimeout time.Duration
}

// Provider implements the DNS-01 challenge provider interface for AWS Route53.
type Provider struct {
	client             Route53API
	hostedZoneID       string
	nameservers        []string
	zoneFinder         providers.ZoneFinder
	propagationTimeout time.Duration
	pollingInterval    time.Duration
	ttl                int
}

// Route53API defines the Route53 operations used by the provider.
// This interface enables mocking for tests.
type Route53API interface {
	ChangeResourceRecordSets(ctx context.Context, params *route53.ChangeResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error)
	GetChange(ctx context.Context, params *route53.GetChangeInput, optFns ...func(*route53.Options)) (*route53.GetChangeOutput, error)
	ListHostedZonesByName(ctx context.Context, params *route53.ListHostedZonesByNameInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error)
}

// StsAPI defines the STS operations used for assuming roles.
type StsAPI interface {
	AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
	AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

// New creates a new Route53 DNS provider.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	// Apply defaults
	cfg = applyDefaults(cfg)

	awsCfg, err := loadAWSConfig(ctx, cfg)
	if err != nil {
		return nil, providers.NewProviderError(providerName, "load config", "", err)
	}

	client := route53.NewFromConfig(awsCfg)

	return &Provider{
		client:             client,
		hostedZoneID:       cfg.HostedZoneID,
		nameservers:        cfg.Nameservers,
		zoneFinder:         cfg.ZoneFinder,
		propagationTimeout: cfg.PropagationTimeout,
		pollingInterval:    cfg.PollingInterval,
		ttl:                cfg.TTL,
	}, nil
}

// NewFromEnv creates a new Route53 provider using environment variables.
//
// Supported environment variables:
//   - AWS_ACCESS_KEY_ID: AWS access key ID
//   - AWS_SECRET_ACCESS_KEY: AWS secret access key
//   - AWS_HOSTED_ZONE_ID: Route53 hosted zone ID
//   - AWS_REGION: AWS region
//   - AWS_PROPAGATION_TIMEOUT or ROUTE53_PROPAGATION_TIMEOUT: DNS propagation timeout
//   - AWS_POLLING_INTERVAL or ROUTE53_POLLING_INTERVAL: Polling interval
//   - AWS_TTL or ROUTE53_TTL: DNS record TTL
//
// If no credentials are found in environment variables, ambient credentials will be used.
func NewFromEnv(ctx context.Context) (*Provider, error) {
	accessKeyID, err := providers.GetEnvOrFile(envAWSAccessKeyID)
	if err != nil {
		return nil, providers.NewConfigError(providerName, "access_key_id", err.Error())
	}

	secretAccessKey, err := providers.GetEnvOrFile(envAWSSecretAccessKey)
	if err != nil {
		return nil, providers.NewConfigError(providerName, "secret_access_key", err.Error())
	}

	// Get propagation timeout (prefer provider-specific env var)
	propagationTimeout := providers.GetEnvDuration(envRoute53PropagationTimeout, 0)
	if propagationTimeout == 0 {
		propagationTimeout = providers.GetEnvDuration(envAWSPropagationTimeout, defaultPropagationTimeout)
	}

	// Get polling interval (prefer provider-specific env var)
	pollingInterval := providers.GetEnvDuration(envRoute53PollingInterval, 0)
	if pollingInterval == 0 {
		pollingInterval = providers.GetEnvDuration(envAWSPollingInterval, defaultPollingInterval)
	}

	// Get TTL (prefer provider-specific env var)
	ttl := providers.GetEnvInt(envRoute53TTL, 0)
	if ttl == 0 {
		ttl = providers.GetEnvInt(envAWSTTL, defaultTTL)
	}

	cfg := Config{
		AccessKeyID:        accessKeyID,
		SecretAccessKey:    secretAccessKey,
		HostedZoneID:       providers.GetEnvOrDefault(envAWSHostedZoneID, ""),
		Region:             providers.GetEnvOrDefault(envAWSRegion, ""),
		Ambient:            accessKeyID == "" && secretAccessKey == "",
		PropagationTimeout: propagationTimeout,
		PollingInterval:    pollingInterval,
		TTL:                ttl,
	}

	return New(ctx, cfg)
}

// NewWithClient creates a new Route53 provider with a custom client.
// This is useful for testing with mock clients.
func NewWithClient(client Route53API, hostedZoneID string, nameservers []string) *Provider {
	return &Provider{
		client:             client,
		hostedZoneID:       hostedZoneID,
		nameservers:        nameservers,
		propagationTimeout: defaultPropagationTimeout,
		pollingInterval:    defaultPollingInterval,
		ttl:                defaultTTL,
	}
}

// NewWithClientAndConfig creates a new Route53 provider with a custom client and configuration.
// This is useful for testing with mock clients while also testing timeout configuration.
func NewWithClientAndConfig(client Route53API, cfg Config) *Provider {
	cfg = applyDefaults(cfg)
	return &Provider{
		client:             client,
		hostedZoneID:       cfg.HostedZoneID,
		nameservers:        cfg.Nameservers,
		zoneFinder:         cfg.ZoneFinder,
		propagationTimeout: cfg.PropagationTimeout,
		pollingInterval:    cfg.PollingInterval,
		ttl:                cfg.TTL,
	}
}

// Timeout returns the provider's propagation timeout and polling interval.
// This implements the providers.ProviderTimeout interface.
func (p *Provider) Timeout() (timeout, interval time.Duration) {
	return p.propagationTimeout, p.pollingInterval
}

// Present creates a TXT record for the DNS-01 challenge.
func (p *Provider) Present(ctx context.Context, domain, fqdn, value string) error {
	quotedValue := `"` + value + `"`
	return p.changeRecord(ctx, types.ChangeActionUpsert, fqdn, quotedValue, p.ttl)
}

// CleanUp removes the TXT record created by Present.
func (p *Provider) CleanUp(ctx context.Context, domain, fqdn, value string) error {
	quotedValue := `"` + value + `"`
	return p.changeRecord(ctx, types.ChangeActionDelete, fqdn, quotedValue, p.ttl)
}

// changeRecord creates or deletes a DNS TXT record.
func (p *Provider) changeRecord(ctx context.Context, action types.ChangeAction, fqdn, value string, ttl int) error {
	hostedZoneID, err := p.getHostedZoneID(ctx, fqdn)
	if err != nil {
		return providers.NewProviderError(providerName, "get zone", fqdn, err)
	}

	recordSet := &types.ResourceRecordSet{
		Name:             aws.String(fqdn),
		Type:             types.RRTypeTxt,
		TTL:              aws.Int64(int64(ttl)),
		MultiValueAnswer: aws.Bool(true),
		SetIdentifier:    aws.String(value),
		ResourceRecords: []types.ResourceRecord{
			{Value: aws.String(value)},
		},
	}

	input := &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(hostedZoneID),
		ChangeBatch: &types.ChangeBatch{
			Comment: aws.String("Managed by go-xkms ACME DNS-01 challenge"),
			Changes: []types.Change{
				{
					Action:            action,
					ResourceRecordSet: recordSet,
				},
			},
		},
	}

	resp, err := p.client.ChangeResourceRecordSets(ctx, input)
	if err != nil {
		// If deleting and the record doesn't exist, ignore the error
		var invalidChangeBatch *types.InvalidChangeBatch
		if errors.As(err, &invalidChangeBatch) && action == types.ChangeActionDelete {
			return nil
		}
		return providers.NewProviderError(providerName, "change record", fqdn, err)
	}

	// Wait for the change to propagate
	return p.waitForChange(ctx, resp.ChangeInfo.Id)
}

// waitForChange waits for a Route53 change to be synchronized.
func (p *Provider) waitForChange(ctx context.Context, changeID *string) error {
	return providers.WaitForCtx(ctx, p.propagationTimeout, p.pollingInterval, func() (bool, error) {
		input := &route53.GetChangeInput{
			Id: changeID,
		}
		resp, err := p.client.GetChange(ctx, input)
		if err != nil {
			return false, err
		}
		return resp.ChangeInfo.Status == types.ChangeStatusInsync, nil
	})
}

// findZone resolves the zone apex, defaulting to providers.FindZoneByFQDN when
// no ZoneFinder was configured. The nil check keeps a Provider built by a bare
// struct literal usable, which the package's own tests rely on.
func (p *Provider) findZone(ctx context.Context, fqdn string, nameservers []string) (string, error) {
	if p.zoneFinder != nil {
		return p.zoneFinder(ctx, fqdn, nameservers)
	}
	return providers.FindZoneByFQDN(ctx, fqdn, nameservers)
}

// getHostedZoneID returns the hosted zone ID for the given FQDN.
func (p *Provider) getHostedZoneID(ctx context.Context, fqdn string) (string, error) {
	if p.hostedZoneID != "" {
		return p.hostedZoneID, nil
	}

	// Find the zone apex
	authZone, err := p.findZone(ctx, fqdn, p.nameservers)
	if err != nil {
		return "", err
	}

	// List hosted zones matching the zone name
	input := &route53.ListHostedZonesByNameInput{
		DNSName: aws.String(providers.UnFQDN(authZone)),
	}

	resp, err := p.client.ListHostedZonesByName(ctx, input)
	if err != nil {
		return "", err
	}

	// Build a map of zone names to IDs (public zones only)
	zoneToID := make(map[string]string)
	var zones []string
	for _, zone := range resp.HostedZones {
		if !zone.Config.PrivateZone {
			zoneToID[*zone.Name] = *zone.Id
			zones = append(zones, *zone.Name)
		}
	}

	// Find the best matching zone
	bestZone, err := providers.FindBestMatch(fqdn, zones...)
	if err != nil {
		return "", providers.ErrZoneNotFound
	}

	hostedZoneID, ok := zoneToID[bestZone]
	if !ok || hostedZoneID == "" {
		return "", providers.ErrZoneNotFound
	}

	// Remove the /hostedzone/ prefix if present
	hostedZoneID = strings.TrimPrefix(hostedZoneID, "/hostedzone/")

	return hostedZoneID, nil
}

// validateConfig validates the Route53 configuration.
func validateConfig(cfg Config) error {
	// Check for partial credentials
	if cfg.AccessKeyID == "" && cfg.SecretAccessKey != "" {
		return providers.NewConfigError(providerName, "credentials", "access key ID is required when secret access key is provided")
	}
	if cfg.AccessKeyID != "" && cfg.SecretAccessKey == "" {
		return providers.NewConfigError(providerName, "credentials", "secret access key is required when access key ID is provided")
	}

	// Check for web identity without role
	if cfg.WebIdentityToken != "" && cfg.Role == "" {
		return providers.NewConfigError(providerName, "role", "role is required when using web identity token")
	}

	// Check that credentials are provided or ambient is enabled
	if cfg.AccessKeyID == "" && cfg.SecretAccessKey == "" && !cfg.Ambient && cfg.WebIdentityToken == "" {
		return providers.ErrMissingCredentials
	}

	// Validate TTL is non-negative
	if cfg.TTL < 0 {
		return providers.NewConfigError(providerName, "ttl", "TTL must be non-negative")
	}

	// Validate timeout values
	if cfg.PropagationTimeout < 0 {
		return providers.NewConfigError(providerName, "propagation_timeout", "propagation timeout must be non-negative")
	}

	if cfg.PollingInterval < 0 {
		return providers.NewConfigError(providerName, "polling_interval", "polling interval must be non-negative")
	}

	if cfg.HTTPTimeout < 0 {
		return providers.NewConfigError(providerName, "http_timeout", "HTTP timeout must be non-negative")
	}

	return nil
}

// applyDefaults applies default values to the configuration.
func applyDefaults(cfg Config) Config {
	if cfg.PropagationTimeout <= 0 {
		cfg.PropagationTimeout = defaultPropagationTimeout
	}
	if cfg.PollingInterval <= 0 {
		cfg.PollingInterval = defaultPollingInterval
	}
	if cfg.TTL <= 0 {
		cfg.TTL = defaultTTL
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = defaultHTTPTimeout
	}
	if cfg.ZoneFinder == nil {
		cfg.ZoneFinder = providers.FindZoneByFQDN
	}
	return cfg
}

// loadAWSConfig loads the AWS configuration based on the provider config.
func loadAWSConfig(ctx context.Context, cfg Config) (aws.Config, error) {
	var optFns []func(*config.LoadOptions) error

	// Set region if provided
	if cfg.Region != "" {
		optFns = append(optFns, config.WithRegion(cfg.Region))
	}

	// Configure HTTP client with timeout
	httpClient := &http.Client{
		Timeout: cfg.HTTPTimeout,
	}
	optFns = append(optFns, config.WithHTTPClient(httpClient))

	// Use static credentials if provided
	useAmbient := cfg.Ambient && cfg.AccessKeyID == "" && cfg.SecretAccessKey == "" && cfg.WebIdentityToken == ""
	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		optFns = append(optFns, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		))
	}

	// Load default config
	awsCfg, err := config.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return aws.Config{}, err
	}

	// Handle role assumption
	if cfg.Role != "" {
		stsClient := sts.NewFromConfig(awsCfg)
		awsCfg, err = assumeRole(ctx, awsCfg, stsClient, cfg)
		if err != nil {
			return aws.Config{}, err
		}
	}

	// Validate we have credentials when not using ambient
	if !useAmbient && cfg.Role == "" && cfg.WebIdentityToken == "" {
		// Credentials were provided via config
		return awsCfg, nil
	}

	return awsCfg, nil
}

// assumeRole handles STS role assumption and web identity.
func assumeRole(ctx context.Context, cfg aws.Config, stsClient StsAPI, providerCfg Config) (aws.Config, error) {
	if providerCfg.WebIdentityToken != "" {
		// Assume role with web identity (IRSA)
		result, err := stsClient.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{
			RoleArn:          aws.String(providerCfg.Role),
			RoleSessionName:  aws.String("go-xkms"),
			WebIdentityToken: aws.String(providerCfg.WebIdentityToken),
		})
		if err != nil {
			return aws.Config{}, err
		}
		cfg.Credentials = credentials.NewStaticCredentialsProvider(
			*result.Credentials.AccessKeyId,
			*result.Credentials.SecretAccessKey,
			*result.Credentials.SessionToken,
		)
	} else {
		// Regular assume role
		result, err := stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
			RoleArn:         aws.String(providerCfg.Role),
			RoleSessionName: aws.String("go-xkms"),
		})
		if err != nil {
			return aws.Config{}, err
		}
		cfg.Credentials = credentials.NewStaticCredentialsProvider(
			*result.Credentials.AccessKeyId,
			*result.Credentials.SecretAccessKey,
			*result.Credentials.SessionToken,
		)
	}

	return cfg, nil
}

// Compile-time interface compliance check
var _ providers.ProviderTimeout = (*Provider)(nil)
