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

// Package cloudflare implements a DNS-01 challenge provider using Cloudflare DNS.
//
// This provider supports two authentication methods:
//   - API Key: email + API key (legacy)
//   - API Token: scoped API token (recommended)
//
// For enterprise setups with separate zone listing permissions, split token
// authentication is supported via ZoneAPIToken.
//
// Usage with API Token:
//
//	provider, err := cloudflare.New(ctx, cloudflare.Config{
//	    APIToken: "your-api-token",
//	})
//	if err != nil {
//	    return err
//	}
//	err = provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "challenge-token")
//
// Usage with API Key:
//
//	provider, err := cloudflare.New(ctx, cloudflare.Config{
//	    Email:  "user@example.com",
//	    APIKey: "your-api-key",
//	})
//
// Usage with environment variables:
//
//	provider, err := cloudflare.NewFromEnv(ctx)
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers"
)

const (
	providerName        = "cloudflare"
	defaultAPIURL       = "https://api.cloudflare.com/client/v4"
	maxResponseBodySize = 1024 * 1024 // 1 MB

	// Default configuration values
	defaultPropagationTimeout = 120 * time.Second
	defaultPollingInterval    = 4 * time.Second
	defaultHTTPTimeout        = 30 * time.Second
	defaultRecordTTL          = 120
)

// Environment variable names (not credentials - just env var names for configuration)
const (
	envEmail              = "CLOUDFLARE_EMAIL"
	envAPIKey             = "CLOUDFLARE_API_KEY"        // #nosec G101 - env var name, not a credential
	envDNSAPIToken        = "CLOUDFLARE_DNS_API_TOKEN"  // #nosec G101 - env var name, not a credential
	envZoneAPIToken       = "CLOUDFLARE_ZONE_API_TOKEN" // #nosec G101 - env var name, not a credential
	envZoneID             = "CLOUDFLARE_ZONE_ID"
	envPropagationTimeout = "CLOUDFLARE_PROPAGATION_TIMEOUT"
	envPollingInterval    = "CLOUDFLARE_POLLING_INTERVAL"
	envTTL                = "CLOUDFLARE_TTL"
	envHTTPTimeout        = "CLOUDFLARE_HTTP_TIMEOUT"

	// CF_* aliases
	envCFEmail              = "CF_EMAIL"
	envCFAPIKey             = "CF_API_KEY"        // #nosec G101 - env var name, not a credential
	envCFDNSAPIToken        = "CF_DNS_API_TOKEN"  // #nosec G101 - env var name, not a credential
	envCFZoneAPIToken       = "CF_ZONE_API_TOKEN" // #nosec G101 - env var name, not a credential
	envCFZoneID             = "CF_ZONE_ID"
	envCFPropagationTimeout = "CF_PROPAGATION_TIMEOUT"
	envCFPollingInterval    = "CF_POLLING_INTERVAL"
	envCFTTL                = "CF_TTL"
	envCFHTTPTimeout        = "CF_HTTP_TIMEOUT"
)

func init() {
	providers.Register(providers.ProviderCloudflare, func(ctx context.Context, cfg interface{}) (providers.Provider, error) {
		c, ok := cfg.(Config)
		if !ok {
			return nil, providers.NewConfigError(providerName, "config", "expected cloudflare.Config")
		}
		return New(ctx, c)
	})
	providers.RegisterEnvFactory(providers.ProviderCloudflare, func(ctx context.Context) (providers.Provider, error) {
		provider, err := NewFromEnv(ctx)
		if err != nil {
			return nil, err
		}
		return provider, nil
	})
}

// Config holds the configuration for the Cloudflare provider.
type Config struct {
	// Email is the Cloudflare account email.
	// Required when using API key authentication.
	Email string

	// APIKey is the global API key for authentication.
	// Cannot be used together with APIToken.
	APIKey string

	// APIToken is a scoped API token for authentication.
	// Recommended over APIKey for security.
	// Cannot be used together with APIKey.
	APIToken string

	// ZoneAPIToken is an optional separate token for zone listing operations.
	// Useful for enterprise setups with split token permissions.
	// If not set, APIToken is used for zone operations.
	ZoneAPIToken string

	// ZoneID is a pre-configured zone ID to skip zone lookup.
	// Useful when the zone is known ahead of time.
	ZoneID string

	// BaseURL is a custom API endpoint for enterprise setups.
	// Defaults to https://api.cloudflare.com/client/v4
	BaseURL string

	// PropagationTimeout is the maximum time to wait for DNS propagation.
	// Defaults to 120 seconds.
	PropagationTimeout time.Duration

	// PollingInterval is the time between DNS propagation checks.
	// Defaults to 4 seconds.
	PollingInterval time.Duration

	// TTL is the time-to-live for DNS records in seconds.
	// Defaults to 120 seconds.
	TTL int

	// HTTPTimeout is the timeout for HTTP requests.
	// Defaults to 30 seconds.
	HTTPTimeout time.Duration

	// Nameservers is a list of DNS nameservers for zone lookup.
	// Optional - defaults to system nameservers.
	Nameservers []string

	// HTTPClient is an optional custom HTTP client.
	// If not provided, a default client with timeout is used.
	HTTPClient HTTPClient
}

// HTTPClient defines the HTTP operations needed by the provider.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Provider implements the DNS-01 challenge provider interface for Cloudflare.
type Provider struct {
	email              string
	apiKey             string
	apiToken           string
	zoneAPIToken       string
	zoneID             string
	baseURL            string
	propagationTimeout time.Duration
	pollingInterval    time.Duration
	ttl                int
	nameservers        []string
	httpClient         HTTPClient

	// recordIDs caches created record IDs for efficient cleanup
	recordIDsMu sync.RWMutex
	recordIDs   map[string]recordInfo
}

// recordInfo stores information about a created DNS record
type recordInfo struct {
	recordID string
	zoneID   string
}

// Compile-time interface compliance checks
var (
	_ providers.Provider        = (*Provider)(nil)
	_ providers.ProviderTimeout = (*Provider)(nil)
)

// New creates a new Cloudflare DNS provider.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	// Apply defaults
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultAPIURL
	}

	propagationTimeout := cfg.PropagationTimeout
	if propagationTimeout == 0 {
		propagationTimeout = defaultPropagationTimeout
	}

	pollingInterval := cfg.PollingInterval
	if pollingInterval == 0 {
		pollingInterval = defaultPollingInterval
	}

	ttl := cfg.TTL
	if ttl == 0 {
		ttl = defaultRecordTTL
	}

	httpTimeout := cfg.HTTPTimeout
	if httpTimeout == 0 {
		httpTimeout = defaultHTTPTimeout
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: httpTimeout,
		}
	}

	return &Provider{
		email:              cfg.Email,
		apiKey:             cfg.APIKey,
		apiToken:           cfg.APIToken,
		zoneAPIToken:       cfg.ZoneAPIToken,
		zoneID:             cfg.ZoneID,
		baseURL:            baseURL,
		propagationTimeout: propagationTimeout,
		pollingInterval:    pollingInterval,
		ttl:                ttl,
		nameservers:        cfg.Nameservers,
		httpClient:         httpClient,
		recordIDs:          make(map[string]recordInfo),
	}, nil
}

// NewFromEnv creates a new Cloudflare DNS provider from environment variables.
//
// Supported environment variables (CLOUDFLARE_* or CF_* prefix):
//   - EMAIL: Cloudflare account email
//   - API_KEY: Global API key
//   - DNS_API_TOKEN: Scoped API token for DNS operations
//   - ZONE_API_TOKEN: Optional separate token for zone listing
//   - ZONE_ID: Pre-configured zone ID
//   - PROPAGATION_TIMEOUT: Max propagation wait time (e.g., "120s")
//   - POLLING_INTERVAL: Time between checks (e.g., "4s")
//   - TTL: DNS record TTL in seconds
//   - HTTP_TIMEOUT: HTTP request timeout (e.g., "30s")
func NewFromEnv(ctx context.Context) (*Provider, error) {
	// Get credentials with fallback to CF_* aliases
	email := getEnvWithAlias(envEmail, envCFEmail)
	apiKey := getEnvWithAlias(envAPIKey, envCFAPIKey)
	apiToken := getEnvWithAlias(envDNSAPIToken, envCFDNSAPIToken)
	zoneAPIToken := getEnvWithAlias(envZoneAPIToken, envCFZoneAPIToken)
	zoneID := getEnvWithAlias(envZoneID, envCFZoneID)

	// Get timeout configurations
	propagationTimeout := getDurationWithAlias(envPropagationTimeout, envCFPropagationTimeout, defaultPropagationTimeout)
	pollingInterval := getDurationWithAlias(envPollingInterval, envCFPollingInterval, defaultPollingInterval)
	ttl := getIntWithAlias(envTTL, envCFTTL, defaultRecordTTL)
	httpTimeout := getDurationWithAlias(envHTTPTimeout, envCFHTTPTimeout, defaultHTTPTimeout)

	cfg := Config{
		Email:              email,
		APIKey:             apiKey,
		APIToken:           apiToken,
		ZoneAPIToken:       zoneAPIToken,
		ZoneID:             zoneID,
		PropagationTimeout: propagationTimeout,
		PollingInterval:    pollingInterval,
		TTL:                ttl,
		HTTPTimeout:        httpTimeout,
	}

	return New(ctx, cfg)
}

// getEnvWithAlias returns the value from the primary env var, falling back to alias
func getEnvWithAlias(primary, alias string) string {
	value := providers.GetEnvOrDefault(primary, "")
	if value == "" {
		value = providers.GetEnvOrDefault(alias, "")
	}
	return value
}

// getDurationWithAlias returns a duration from primary env var, falling back to alias
func getDurationWithAlias(primary, alias string, defaultVal time.Duration) time.Duration {
	value := providers.GetEnvDuration(primary, 0)
	if value == 0 {
		value = providers.GetEnvDuration(alias, defaultVal)
	}
	return value
}

// getIntWithAlias returns an int from primary env var, falling back to alias
func getIntWithAlias(primary, alias string, defaultVal int) int {
	value := providers.GetEnvInt(primary, 0)
	if value == 0 {
		value = providers.GetEnvInt(alias, defaultVal)
	}
	return value
}

// Timeout implements the ProviderTimeout interface.
// Returns the configured propagation timeout and polling interval.
func (p *Provider) Timeout() (timeout, interval time.Duration) {
	return p.propagationTimeout, p.pollingInterval
}

// Present creates a TXT record for the DNS-01 challenge.
func (p *Provider) Present(ctx context.Context, domain, fqdn, value string) error {
	// Check if record already exists
	_, err := p.findTXTRecord(ctx, fqdn, value)
	if err == nil {
		// Record already exists
		return nil
	}
	if !errors.Is(err, errRecordNotFound) {
		return err
	}

	// Get zone ID
	zoneID, err := p.getZoneID(ctx, fqdn)
	if err != nil {
		return providers.NewProviderError(providerName, "get zone", domain, err)
	}

	// Create the record
	record := cloudflareRecord{
		Type:    "TXT",
		Name:    providers.UnFQDN(fqdn),
		Content: value,
		TTL:     p.ttl,
	}

	body, err := json.Marshal(record)
	if err != nil {
		return providers.NewProviderError(providerName, "marshal record", domain, err)
	}

	result, err := p.makeRequest(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", bytes.NewReader(body), false)
	if err != nil {
		return providers.NewProviderError(providerName, "create record", domain, err)
	}

	// Parse the created record to get its ID for caching
	var createdRecord cloudflareRecord
	if err := json.Unmarshal(result, &createdRecord); err == nil && createdRecord.ID != "" {
		cacheKey := p.recordCacheKey(fqdn, value)
		p.recordIDsMu.Lock()
		p.recordIDs[cacheKey] = recordInfo{
			recordID: createdRecord.ID,
			zoneID:   zoneID,
		}
		p.recordIDsMu.Unlock()
	}

	return nil
}

// CleanUp removes the TXT record created by Present.
func (p *Provider) CleanUp(ctx context.Context, domain, fqdn, value string) error {
	// First check the cache for the record ID
	cacheKey := p.recordCacheKey(fqdn, value)
	p.recordIDsMu.RLock()
	info, cached := p.recordIDs[cacheKey]
	p.recordIDsMu.RUnlock()

	if cached {
		// Use cached record ID for cleanup
		_, err := p.makeRequest(ctx, http.MethodDelete, "/zones/"+info.zoneID+"/dns_records/"+info.recordID, nil, false)
		if err != nil {
			return providers.NewProviderError(providerName, "delete record", domain, err)
		}

		// Remove from cache
		p.recordIDsMu.Lock()
		delete(p.recordIDs, cacheKey)
		p.recordIDsMu.Unlock()

		return nil
	}

	// Fallback to finding the record via API
	record, err := p.findTXTRecord(ctx, fqdn, value)
	if errors.Is(err, errRecordNotFound) {
		// Record doesn't exist, nothing to clean up
		return nil
	}
	if err != nil {
		return providers.NewProviderError(providerName, "find record", domain, err)
	}

	_, err = p.makeRequest(ctx, http.MethodDelete, "/zones/"+record.ZoneID+"/dns_records/"+record.ID, nil, false)
	if err != nil {
		return providers.NewProviderError(providerName, "delete record", domain, err)
	}

	return nil
}

// recordCacheKey generates a cache key for a record
func (p *Provider) recordCacheKey(fqdn, value string) string {
	return fqdn + "|" + value
}

// cloudflareRecord represents a Cloudflare DNS record.
type cloudflareRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl,omitempty"`
	ZoneID  string `json:"zone_id,omitempty"`
}

// cloudflareZone represents a Cloudflare DNS zone.
type cloudflareZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// apiResponse represents a Cloudflare API response.
type apiResponse struct {
	Success bool            `json:"success"`
	Errors  []apiError      `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

// apiError represents a Cloudflare API error.
type apiError struct {
	Code       int        `json:"code,omitempty"`
	Message    string     `json:"message,omitempty"`
	ErrorChain []apiError `json:"error_chain,omitempty"`
}

// errRecordNotFound is a sentinel error for record not found.
var errRecordNotFound = providers.ErrRecordNotFound

// getZoneID finds the zone ID for the given FQDN.
func (p *Provider) getZoneID(ctx context.Context, fqdn string) (string, error) {
	// Use pre-configured zone ID if available
	if p.zoneID != "" {
		return p.zoneID, nil
	}

	zone, err := p.findNearestZone(ctx, fqdn)
	if err != nil {
		return "", err
	}
	return zone.ID, nil
}

// findNearestZone traverses up the domain hierarchy to find the zone.
func (p *Provider) findNearestZone(ctx context.Context, fqdn string) (cloudflareZone, error) {
	if fqdn == "" {
		return cloudflareZone{}, providers.NewConfigError(providerName, "fqdn", "cannot be empty")
	}

	parts := strings.Split(fqdn, ".")
	nextName := providers.UnFQDN(fqdn)

	for i := 0; i < len(parts)-1; i++ {
		// Skip wildcard entries
		if parts[i] == "*" {
			from := len(parts[i]) + 1
			if from <= len(nextName) {
				nextName = nextName[from:]
			}
			continue
		}

		result, err := p.makeRequest(ctx, http.MethodGet, "/zones?name="+nextName, nil, true)
		if err != nil {
			// Move up the domain hierarchy on error
			from := len(parts[i]) + 1
			if from <= len(nextName) {
				nextName = nextName[from:]
			}
			continue
		}

		var zones []cloudflareZone
		if err := json.Unmarshal(result, &zones); err != nil {
			return cloudflareZone{}, err
		}

		if len(zones) > 0 {
			return zones[0], nil
		}

		// Move up the domain hierarchy
		from := len(parts[i]) + 1
		if from <= len(nextName) {
			nextName = nextName[from:]
		}
	}

	return cloudflareZone{}, providers.ErrZoneNotFound
}

// findTXTRecord finds an existing TXT record.
func (p *Provider) findTXTRecord(ctx context.Context, fqdn, content string) (*cloudflareRecord, error) {
	zoneID, err := p.getZoneID(ctx, fqdn)
	if err != nil {
		return nil, err
	}

	uri := "/zones/" + zoneID + "/dns_records?per_page=100&type=TXT&name=" + providers.UnFQDN(fqdn)
	result, err := p.makeRequest(ctx, http.MethodGet, uri, nil, false)
	if err != nil {
		return nil, err
	}

	var records []cloudflareRecord
	if err := json.Unmarshal(result, &records); err != nil {
		return nil, err
	}

	for _, rec := range records {
		if rec.Name == providers.UnFQDN(fqdn) && rec.Content == content {
			// Set the zone ID (Cloudflare removed it from responses)
			rec.ZoneID = zoneID
			return &rec, nil
		}
	}

	return nil, errRecordNotFound
}

// makeRequest performs an HTTP request to the Cloudflare API.
// The zoneRequest parameter indicates if this is a zone listing request,
// which may use the separate ZoneAPIToken if configured.
func (p *Provider) makeRequest(ctx context.Context, method, uri string, body io.Reader, zoneRequest bool) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, method, p.baseURL+uri, body)
	if err != nil {
		return nil, err
	}

	// Determine which token to use for authentication
	token := p.apiToken
	if zoneRequest && p.zoneAPIToken != "" {
		token = p.zoneAPIToken
	}

	// Set authentication headers
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	} else {
		req.Header.Set("X-Auth-Email", p.email)
		req.Header.Set("X-Auth-Key", p.apiKey)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			slog.Debug("cloudflare: failed to close response body", slog.String("error", closeErr.Error()))
		}
	}()

	var apiResp apiResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodySize)).Decode(&apiResp); err != nil {
		return nil, err
	}

	if !apiResp.Success {
		return nil, formatAPIErrors(apiResp.Errors)
	}

	return apiResp.Result, nil
}

// formatAPIErrors formats Cloudflare API errors into a single error.
func formatAPIErrors(errors []apiError) error {
	if len(errors) == 0 {
		return providers.ErrAPIError
	}

	var sb strings.Builder
	for i, err := range errors {
		if i > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(err.Message)
		for _, chain := range err.ErrorChain {
			sb.WriteString(" <- ")
			sb.WriteString(chain.Message)
		}
	}

	return providers.NewAPIError(providerName, 0, sb.String(), "")
}

// validateConfig validates the Cloudflare configuration.
func validateConfig(cfg Config) error {
	// Check for API token or key
	if cfg.APIToken == "" && cfg.APIKey == "" {
		return providers.NewConfigError(providerName, "credentials", "either API token or API key is required")
	}

	// Cannot use both
	if cfg.APIToken != "" && cfg.APIKey != "" {
		return providers.NewConfigError(providerName, "credentials", "cannot use both API token and API key")
	}

	// API key requires email
	if cfg.APIKey != "" && cfg.Email == "" {
		return providers.NewConfigError(providerName, "email", "email is required when using API key")
	}

	// Validate header values (prevent log injection)
	if !isValidHeaderValue(cfg.APIKey) {
		return providers.NewConfigError(providerName, "api_key", "contains invalid characters")
	}
	if !isValidHeaderValue(cfg.APIToken) {
		return providers.NewConfigError(providerName, "api_token", "contains invalid characters")
	}
	if !isValidHeaderValue(cfg.ZoneAPIToken) {
		return providers.NewConfigError(providerName, "zone_api_token", "contains invalid characters")
	}

	return nil
}

// isValidHeaderValue checks if a string is safe for use in HTTP headers.
func isValidHeaderValue(v string) bool {
	for i := 0; i < len(v); i++ {
		b := v[i]
		// Check for control characters (except spaces and tabs)
		if (b < ' ' || b == 0x7f) && b != ' ' && b != '\t' {
			return false
		}
	}
	return true
}
