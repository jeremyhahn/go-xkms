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

// Package azure implements a DNS-01 challenge provider using Azure DNS.
//
// This provider supports:
//   - Client credentials (client ID, client secret, tenant ID)
//   - Managed Identity (for Azure VMs and AKS)
//   - Workload Identity (for AKS with AAD)
//
// Usage with client credentials:
//
//	provider, err := azure.New(ctx, azure.Config{
//	    ClientID:          "your-client-id",
//	    ClientSecret:      "your-client-secret",
//	    TenantID:          "your-tenant-id",
//	    SubscriptionID:    "your-subscription-id",
//	    ResourceGroupName: "your-resource-group",
//	})
//	if err != nil {
//	    return err
//	}
//	err = provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "challenge-token")
//
// Usage with managed identity:
//
//	provider, err := azure.New(ctx, azure.Config{
//	    SubscriptionID:    "your-subscription-id",
//	    ResourceGroupName: "your-resource-group",
//	    Ambient:           true,
//	})
//
// Usage with environment variables:
//
//	provider, err := azure.NewFromEnv(ctx)
package azure

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"

	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers"
)

const (
	providerName = "azure"

	// Default configuration values
	defaultRecordTTL          = 60
	defaultPropagationTimeout = 120 * time.Second
	defaultPollingInterval    = 4 * time.Second
	defaultHTTPTimeout        = 30 * time.Second
)

// Environment variable names (not credentials - just env var names for configuration)
const (
	EnvClientID           = "AZURE_CLIENT_ID"
	EnvClientSecret       = "AZURE_CLIENT_SECRET" // #nosec G101 - env var name, not a credential
	EnvTenantID           = "AZURE_TENANT_ID"
	EnvSubscriptionID     = "AZURE_SUBSCRIPTION_ID"
	EnvResourceGroup      = "AZURE_RESOURCE_GROUP"
	EnvZoneName           = "AZURE_ZONE_NAME"
	EnvEnvironment        = "AZURE_ENVIRONMENT"
	EnvPropagationTimeout = "AZURE_PROPAGATION_TIMEOUT"
	EnvPollingInterval    = "AZURE_POLLING_INTERVAL"
	EnvTTL                = "AZURE_TTL"
)

func init() {
	providers.Register(providers.ProviderAzure, func(ctx context.Context, cfg interface{}) (providers.Provider, error) {
		c, ok := cfg.(Config)
		if !ok {
			return nil, providers.NewConfigError(providerName, "config", "expected azure.Config")
		}
		return New(ctx, c)
	})
	providers.RegisterEnvFactory(providers.ProviderAzure, func(ctx context.Context) (providers.Provider, error) {
		provider, err := NewFromEnv(ctx)
		if err != nil {
			return nil, err
		}
		return provider, nil
	})
}

// Config holds the configuration for the Azure DNS provider.
type Config struct {
	// ClientID is the Azure AD application client ID.
	// Optional if using ambient credentials.
	ClientID string

	// ClientSecret is the Azure AD application client secret.
	// Required when using client credentials.
	ClientSecret string

	// TenantID is the Azure AD tenant ID.
	// Required when using client credentials.
	TenantID string

	// SubscriptionID is the Azure subscription ID.
	// Required.
	SubscriptionID string

	// ResourceGroupName is the resource group containing the DNS zone.
	// Required.
	ResourceGroupName string

	// ZoneName is the name of the DNS zone.
	// Optional - if not provided, the zone will be discovered automatically.
	ZoneName string

	// Environment is the Azure cloud environment.
	// Valid values: "AzureCloud", "AzurePublicCloud", "AzureUSGovernment", "AzureChinaCloud"
	// Defaults to "AzurePublicCloud".
	Environment string

	// Ambient enables ambient credential discovery (managed identity, workload identity).
	Ambient bool

	// ManagedIdentityClientID is the client ID for user-assigned managed identity.
	// Optional - only used when Ambient is true.
	ManagedIdentityClientID string

	// ManagedIdentityResourceID is the resource ID for user-assigned managed identity.
	// Optional - only used when Ambient is true.
	ManagedIdentityResourceID string

	// Nameservers is a list of DNS nameservers for zone lookup.
	// Optional - defaults to system nameservers.
	Nameservers []string

	// PropagationTimeout is the maximum time to wait for DNS propagation.
	// Defaults to 120 seconds.
	PropagationTimeout time.Duration

	// PollingInterval is the time between DNS propagation checks.
	// Defaults to 4 seconds.
	PollingInterval time.Duration

	// TTL is the time-to-live for DNS records in seconds.
	// Defaults to 60.
	TTL int64

	// HTTPTimeout is the timeout for HTTP requests to Azure API.
	// Defaults to 30 seconds.
	HTTPTimeout time.Duration
}

// Provider implements the DNS-01 challenge provider interface for Azure DNS.
type Provider struct {
	recordClient       RecordsClient
	zoneClient         ZonesClient
	resourceGroupName  string
	zoneName           string
	nameservers        []string
	propagationTimeout time.Duration
	pollingInterval    time.Duration
	ttl                int64
}

// RecordsClient defines the Azure DNS record set operations.
type RecordsClient interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, parameters armdns.RecordSet, options *armdns.RecordSetsClientCreateOrUpdateOptions) (armdns.RecordSetsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientGetOptions) (armdns.RecordSetsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName, zoneName, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientDeleteOptions) (armdns.RecordSetsClientDeleteResponse, error)
}

// ZonesClient defines the Azure DNS zone operations.
type ZonesClient interface {
	Get(ctx context.Context, resourceGroupName, zoneName string, options *armdns.ZonesClientGetOptions) (armdns.ZonesClientGetResponse, error)
}

// NewFromEnv creates a new Azure DNS provider from environment variables.
//
// Supported environment variables:
//   - AZURE_CLIENT_ID: Azure AD application client ID
//   - AZURE_CLIENT_SECRET: Azure AD application client secret
//   - AZURE_TENANT_ID: Azure AD tenant ID
//   - AZURE_SUBSCRIPTION_ID: Azure subscription ID (required)
//   - AZURE_RESOURCE_GROUP: Resource group containing the DNS zone (required)
//   - AZURE_ZONE_NAME: DNS zone name (optional)
//   - AZURE_ENVIRONMENT: Cloud environment (optional, defaults to AzurePublicCloud)
//   - AZURE_PROPAGATION_TIMEOUT: Propagation timeout duration (optional, defaults to 120s)
//   - AZURE_POLLING_INTERVAL: Polling interval duration (optional, defaults to 4s)
//   - AZURE_TTL: DNS record TTL in seconds (optional, defaults to 60)
//
// Each environment variable also supports a _FILE suffix for Docker secrets pattern.
func NewFromEnv(ctx context.Context) (*Provider, error) {
	clientID, err := providers.GetEnvOrFile(EnvClientID)
	if err != nil {
		return nil, providers.NewConfigError(providerName, "client_id", err.Error())
	}

	clientSecret, err := providers.GetEnvOrFile(EnvClientSecret)
	if err != nil {
		return nil, providers.NewConfigError(providerName, "client_secret", err.Error())
	}

	tenantID, err := providers.GetEnvOrFile(EnvTenantID)
	if err != nil {
		return nil, providers.NewConfigError(providerName, "tenant_id", err.Error())
	}

	subscriptionID, err := providers.GetEnvOrFile(EnvSubscriptionID)
	if err != nil {
		return nil, providers.NewConfigError(providerName, "subscription_id", err.Error())
	}

	resourceGroup, err := providers.GetEnvOrFile(EnvResourceGroup)
	if err != nil {
		return nil, providers.NewConfigError(providerName, "resource_group", err.Error())
	}

	zoneName, err := providers.GetEnvOrFile(EnvZoneName)
	if err != nil {
		return nil, providers.NewConfigError(providerName, "zone_name", err.Error())
	}

	// Determine if ambient credentials should be used
	// If no client credentials are provided, enable ambient
	ambient := clientID == "" && clientSecret == "" && tenantID == ""

	cfg := Config{
		ClientID:           clientID,
		ClientSecret:       clientSecret,
		TenantID:           tenantID,
		SubscriptionID:     subscriptionID,
		ResourceGroupName:  resourceGroup,
		ZoneName:           zoneName,
		Environment:        providers.GetEnvOrDefault(EnvEnvironment, ""),
		Ambient:            ambient,
		PropagationTimeout: providers.GetEnvDuration(EnvPropagationTimeout, defaultPropagationTimeout),
		PollingInterval:    providers.GetEnvDuration(EnvPollingInterval, defaultPollingInterval),
		TTL:                int64(providers.GetEnvInt(EnvTTL, defaultRecordTTL)),
	}

	return New(ctx, cfg)
}

// New creates a new Azure DNS provider.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	// Apply defaults
	propagationTimeout := cfg.PropagationTimeout
	if propagationTimeout <= 0 {
		propagationTimeout = defaultPropagationTimeout
	}

	pollingInterval := cfg.PollingInterval
	if pollingInterval <= 0 {
		pollingInterval = defaultPollingInterval
	}

	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = defaultRecordTTL
	}

	httpTimeout := cfg.HTTPTimeout
	if httpTimeout <= 0 {
		httpTimeout = defaultHTTPTimeout
	}

	cloudCfg, err := getCloudConfig(cfg.Environment)
	if err != nil {
		return nil, providers.NewProviderError(providerName, "get cloud config", "", err)
	}

	clientOpts := policy.ClientOptions{
		Cloud: cloudCfg,
		Transport: &http.Client{
			Timeout: httpTimeout,
		},
	}
	cred, err := getCredential(clientOpts, cfg)
	if err != nil {
		return nil, providers.NewProviderError(providerName, "get credentials", "", err)
	}

	armOpts := &arm.ClientOptions{ClientOptions: clientOpts}

	recordClient, err := armdns.NewRecordSetsClient(cfg.SubscriptionID, cred, armOpts)
	if err != nil {
		return nil, providers.NewProviderError(providerName, "create record client", "", err)
	}

	zoneClient, err := armdns.NewZonesClient(cfg.SubscriptionID, cred, armOpts)
	if err != nil {
		return nil, providers.NewProviderError(providerName, "create zone client", "", err)
	}

	return &Provider{
		recordClient:       recordClient,
		zoneClient:         zoneClient,
		resourceGroupName:  cfg.ResourceGroupName,
		zoneName:           cfg.ZoneName,
		nameservers:        cfg.Nameservers,
		propagationTimeout: propagationTimeout,
		pollingInterval:    pollingInterval,
		ttl:                ttl,
	}, nil
}

// NewWithClients creates a new Azure DNS provider with custom clients.
// This is useful for testing with mock clients.
func NewWithClients(recordClient RecordsClient, zoneClient ZonesClient, resourceGroupName, zoneName string, nameservers []string) *Provider {
	return &Provider{
		recordClient:       recordClient,
		zoneClient:         zoneClient,
		resourceGroupName:  resourceGroupName,
		zoneName:           zoneName,
		nameservers:        nameservers,
		propagationTimeout: defaultPropagationTimeout,
		pollingInterval:    defaultPollingInterval,
		ttl:                defaultRecordTTL,
	}
}

// NewWithClientsAndConfig creates a new Azure DNS provider with custom clients and configuration.
// This is useful for testing with mock clients while also testing timeout behavior.
func NewWithClientsAndConfig(recordClient RecordsClient, zoneClient ZonesClient, resourceGroupName, zoneName string, nameservers []string, propagationTimeout, pollingInterval time.Duration, ttl int64) *Provider {
	if propagationTimeout <= 0 {
		propagationTimeout = defaultPropagationTimeout
	}
	if pollingInterval <= 0 {
		pollingInterval = defaultPollingInterval
	}
	if ttl <= 0 {
		ttl = defaultRecordTTL
	}

	return &Provider{
		recordClient:       recordClient,
		zoneClient:         zoneClient,
		resourceGroupName:  resourceGroupName,
		zoneName:           zoneName,
		nameservers:        nameservers,
		propagationTimeout: propagationTimeout,
		pollingInterval:    pollingInterval,
		ttl:                ttl,
	}
}

// Timeout returns the provider's propagation timeout and polling interval.
// This implements the ProviderTimeout interface.
func (p *Provider) Timeout() (timeout, interval time.Duration) {
	return p.propagationTimeout, p.pollingInterval
}

// Present creates a TXT record for the DNS-01 challenge.
func (p *Provider) Present(ctx context.Context, domain, fqdn, value string) error {
	return p.updateTXTRecord(ctx, fqdn, func(recordSet *armdns.RecordSet) {
		txtRecords := getTXTRecords(recordSet)

		// Check if value already exists
		for _, r := range txtRecords {
			if len(r.Value) > 0 && *r.Value[0] == value {
				return
			}
		}

		// Add new value
		txtRecords = append(txtRecords, &armdns.TxtRecord{
			Value: []*string{to.Ptr(value)},
		})
		setTXTRecords(recordSet, txtRecords, p.ttl)
	})
}

// CleanUp removes the TXT record created by Present.
func (p *Provider) CleanUp(ctx context.Context, domain, fqdn, value string) error {
	return p.updateTXTRecord(ctx, fqdn, func(recordSet *armdns.RecordSet) {
		txtRecords := getTXTRecords(recordSet)
		filtered := make([]*armdns.TxtRecord, 0, len(txtRecords))

		for _, r := range txtRecords {
			if len(r.Value) > 0 && *r.Value[0] != value {
				filtered = append(filtered, r)
			}
		}

		setTXTRecords(recordSet, filtered, p.ttl)
	})
}

// updateTXTRecord retrieves, modifies, and saves a TXT record set.
func (p *Provider) updateTXTRecord(ctx context.Context, fqdn string, updater func(*armdns.RecordSet)) error {
	zone, err := p.getHostedZoneName(ctx, fqdn)
	if err != nil {
		return providers.NewProviderError(providerName, "get zone", fqdn, err)
	}

	name := p.trimFQDN(fqdn, zone)

	// Try to get existing record set
	var recordSet *armdns.RecordSet
	var etag *string
	var isNewRecord bool

	resp, err := p.recordClient.Get(ctx, p.resourceGroupName, zone, name, armdns.RecordTypeTXT, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
			// Create new record set
			recordSet = &armdns.RecordSet{
				Properties: &armdns.RecordSetProperties{
					TTL:        to.Ptr(p.ttl),
					TxtRecords: []*armdns.TxtRecord{},
				},
			}
			isNewRecord = true
		} else {
			return providers.NewProviderError(providerName, "get record", fqdn, err)
		}
	} else {
		recordSet = &resp.RecordSet
		etag = recordSet.Etag
	}

	// Apply the update
	updater(recordSet)

	// Delete if no records remain
	if len(getTXTRecords(recordSet)) == 0 {
		if etag != nil && *etag != "" {
			opts := &armdns.RecordSetsClientDeleteOptions{
				IfMatch: etag,
			}
			_, err = p.recordClient.Delete(ctx, p.resourceGroupName, zone, name, armdns.RecordTypeTXT, opts)
			if err != nil {
				return providers.NewProviderError(providerName, "delete record", fqdn, err)
			}
		}
		return nil
	}

	// Create or update the record set
	opts := &armdns.RecordSetsClientCreateOrUpdateOptions{}
	if isNewRecord {
		// New record - fail if already exists
		opts.IfNoneMatch = to.Ptr("*")
	} else if etag != nil {
		// Existing record - use optimistic concurrency
		opts.IfMatch = etag
	}

	_, err = p.recordClient.CreateOrUpdate(ctx, p.resourceGroupName, zone, name, armdns.RecordTypeTXT, *recordSet, opts)
	if err != nil {
		return providers.NewProviderError(providerName, "update record", fqdn, err)
	}

	return nil
}

// getHostedZoneName returns the zone name for the given FQDN.
func (p *Provider) getHostedZoneName(ctx context.Context, fqdn string) (string, error) {
	if p.zoneName != "" {
		return p.zoneName, nil
	}

	// Find zone by FQDN
	zone, err := providers.FindZoneByFQDN(ctx, fqdn, p.nameservers)
	if err != nil {
		return "", err
	}

	zoneName := providers.UnFQDN(zone)

	// Verify zone exists in Azure
	_, err = p.zoneClient.Get(ctx, p.resourceGroupName, zoneName, nil)
	if err != nil {
		return "", providers.ErrZoneNotFound
	}

	return zoneName, nil
}

// trimFQDN removes the zone suffix from the FQDN to get the relative record name.
func (p *Provider) trimFQDN(fqdn, zone string) string {
	z := zone
	if p.zoneName != "" {
		z = p.zoneName
	}
	return strings.TrimSuffix(strings.TrimSuffix(fqdn, "."), "."+z)
}

// getTXTRecords extracts TXT records from a record set.
func getTXTRecords(rs *armdns.RecordSet) []*armdns.TxtRecord {
	if rs == nil || rs.Properties == nil {
		return nil
	}
	return rs.Properties.TxtRecords
}

// setTXTRecords sets TXT records on a record set.
func setTXTRecords(rs *armdns.RecordSet, records []*armdns.TxtRecord, ttl int64) {
	if rs.Properties == nil {
		rs.Properties = &armdns.RecordSetProperties{
			TTL: to.Ptr(ttl),
		}
	}
	rs.Properties.TxtRecords = records
}

// getCloudConfig returns the cloud configuration for the given environment.
func getCloudConfig(env string) (cloud.Configuration, error) {
	switch strings.ToUpper(env) {
	case "AZURECLOUD", "AZUREPUBLICCLOUD", "":
		return cloud.AzurePublic, nil
	case "AZUREUSGOVERNMENT", "AZUREUSGOVERNMENTCLOUD":
		return cloud.AzureGovernment, nil
	case "AZURECHINACLOUD":
		return cloud.AzureChina, nil
	default:
		return cloud.Configuration{}, providers.NewConfigError(providerName, "environment", "unknown cloud environment: "+env)
	}
}

// getCredential returns the appropriate Azure credential based on configuration.
func getCredential(clientOpts policy.ClientOptions, cfg Config) (azcore.TokenCredential, error) {
	// Client credentials
	if cfg.ClientID != "" && cfg.ClientSecret != "" {
		return azidentity.NewClientSecretCredential(cfg.TenantID, cfg.ClientID, cfg.ClientSecret, &azidentity.ClientSecretCredentialOptions{
			ClientOptions: clientOpts,
		})
	}

	// Ambient credentials required
	if !cfg.Ambient {
		return nil, providers.ErrAmbientCredentialsDisabled
	}

	// Try workload identity first
	if os.Getenv("AZURE_FEDERATED_TOKEN_FILE") != "" {
		opts := &azidentity.WorkloadIdentityCredentialOptions{
			ClientOptions: clientOpts,
		}
		if cfg.ManagedIdentityClientID != "" {
			opts.ClientID = cfg.ManagedIdentityClientID
		}
		if cfg.TenantID != "" {
			opts.TenantID = cfg.TenantID
		}
		return azidentity.NewWorkloadIdentityCredential(opts)
	}

	// Fall back to managed identity
	msiOpts := &azidentity.ManagedIdentityCredentialOptions{
		ClientOptions: clientOpts,
	}
	if cfg.ManagedIdentityClientID != "" {
		msiOpts.ID = azidentity.ClientID(cfg.ManagedIdentityClientID)
	}
	if cfg.ManagedIdentityResourceID != "" {
		msiOpts.ID = azidentity.ResourceID(cfg.ManagedIdentityResourceID)
	}

	return azidentity.NewManagedIdentityCredential(msiOpts)
}

// validateConfig validates the Azure configuration.
func validateConfig(cfg Config) error {
	if cfg.SubscriptionID == "" {
		return providers.NewConfigError(providerName, "subscription_id", "is required")
	}

	if cfg.ResourceGroupName == "" {
		return providers.NewConfigError(providerName, "resource_group_name", "is required")
	}

	// Client credentials require all three values
	if cfg.ClientID != "" || cfg.ClientSecret != "" || cfg.TenantID != "" {
		if cfg.ClientID == "" {
			return providers.NewConfigError(providerName, "client_id", "is required when using client credentials")
		}
		if cfg.ClientSecret == "" {
			return providers.NewConfigError(providerName, "client_secret", "is required when using client credentials")
		}
		if cfg.TenantID == "" {
			return providers.NewConfigError(providerName, "tenant_id", "is required when using client credentials")
		}
	} else if !cfg.Ambient {
		return providers.NewConfigError(providerName, "credentials", "either client credentials or ambient must be enabled")
	}

	return nil
}
