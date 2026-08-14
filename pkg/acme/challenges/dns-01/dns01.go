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

package dns01

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// dns-01 Challenge Implementation
//
// This implements the standard ACME dns-01 challenge as defined in RFC 8555 Section 8.4.
// The challenge verifies control of a domain by requiring the client to provision a DNS TXT
// record containing a specified value derived from the key authorization.
//
// Challenge Flow:
// 1. ACME server generates a challenge token and computes key authorization
// 2. Client computes SHA-256 hash of key authorization and base64url encodes it
// 3. Client provisions DNS TXT record at _acme-challenge.<domain> with the encoded value
// 4. Client notifies ACME server that challenge is ready for validation
// 5. ACME server queries DNS for TXT record at _acme-challenge.<domain>
// 6. Server verifies TXT record value matches expected hash
// 7. Challenge succeeds if DNS record matches, fails otherwise
//
// RFC 8555 Compliance:
// - Uses _acme-challenge.<domain> DNS record name as defined in RFC 8555 Section 8.4
// - Computes SHA-256 hash of key authorization
// - Base64url encodes the hash (without padding)
// - Validates DNS TXT record content matches expected value
//
// DNS Service Integration:
// This implementation supports two modes:
// 1. Local DNS Service - For self-hosted DNS via SetDNSService()
// 2. Cloud Providers - For Route53, Cloudflare, Azure DNS, Cloud DNS via provider registry

var (
	DNSService DNSServiceInterface

	ErrChallengeFailed          = errors.New("dns-01: challenge failed")
	ErrDNSServiceNotInitialized = errors.New("dns-01: DNS service not initialized")
	ErrProviderNotConfigured    = errors.New("dns-01: provider not configured")
)

// Resolver defines the DNS resolver interface for TXT record lookups
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// DNSServiceInterface defines the required DNS service operations for dns-01 challenges
type DNSServiceInterface interface {
	// Zone retrieves a DNS zone by domain name
	Zone(domain string) (DNSZone, error)

	// Save persists zone changes to the datastore
	Save(zone DNSZone) error
}

// DNSZone represents a DNS zone with TXT record operations
type DNSZone interface {
	// AddTXTRecord adds a TXT record to the zone
	AddTXTRecord(record TXTRecord)

	// RemoveTXTRecord removes a TXT record from the zone by name
	RemoveTXTRecord(name string)
}

// TXTRecord represents a DNS TXT record
type TXTRecord interface {
	// Name returns the fully qualified domain name for this record
	Name() string

	// Value returns the TXT record value
	Value() string

	// TTL returns the time-to-live in seconds
	TTL() uint32
}

// SetDNSService configures the DNS service for dns-01 challenge operations.
//
// This function must be called before Setup() or Verify() to initialize
// the DNS service dependency. The service is used to provision and remove
// DNS TXT records for challenge validation.
func SetDNSService(service DNSServiceInterface) {
	DNSService = service
}

// Verify checks if the dns-01 challenge is valid by querying the DNS resolver
// for the expected key authorization hash in the _acme-challenge.<domain> TXT record.
//
// The function performs the following steps:
// 1. Computes SHA-256 hash of the expected key authorization
// 2. Base64url encodes the hash (without padding)
// 3. Queries DNS for TXT records at _acme-challenge.<domain>
// 4. Compares TXT record values with expected hash
// 5. Removes the TXT record from DNS upon successful verification
//
// Parameters:
//   - resolver: DNS resolver for TXT record lookups
//   - domain: Domain name to verify (e.g., "example.com")
//   - port: Not used for dns-01 challenges (reserved for interface compatibility)
//   - challengeToken: Not used directly (reserved for interface compatibility)
//   - expectedKeyAuth: Expected key authorization value (token.thumbprint)
//
// Returns:
//   - nil if challenge verification succeeds and DNS record is removed
//   - ErrDNSServiceNotInitialized if DNS service is not configured
//   - ErrChallengeFailed if DNS record doesn't match expected value
//   - error for DNS query failures or zone update errors
func Verify(
	resolver Resolver,
	domain, port, challengeToken, expectedKeyAuth string) error {

	if DNSService == nil {
		return ErrDNSServiceNotInitialized
	}

	// Compute SHA-256 hash of key authorization per RFC 8555 Section 8.4
	sha := sha256.Sum256([]byte(expectedKeyAuth))
	expected := base64.RawURLEncoding.EncodeToString(sha[:])

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Query DNS for TXT records at _acme-challenge.<domain>
	txtRecords, err := resolver.LookupTXT(ctx, fmt.Sprintf("_acme-challenge.%s", domain))
	if err != nil {
		return caerrors.DNSError("dns-01: failed to query DNS TXT records: %v", err)
	}

	// Check if any TXT record matches the expected value
	for _, txt := range txtRecords {

		if txt == expected {

			// Retrieve the zone from the DNS service
			zone, err := DNSService.Zone(domain)
			if err != nil {
				return err
			}

			// Define the ACME TXT record for removal
			name := fmt.Sprintf("_acme-challenge.%s", domain)

			// Remove the record from the zone
			zone.RemoveTXTRecord(name)

			// Save the zone to the datastore
			if err := DNSService.Save(zone); err != nil {
				return err
			}

			return nil
		}
	}

	return ErrChallengeFailed
}

// Setup provisions the DNS TXT record required for dns-01 challenge validation.
//
// This function adds a TXT record at _acme-challenge.<authzValue> containing
// the challenge token. The record is immediately available for DNS resolution
// after the zone is saved to the datastore.
//
// Parameters:
//   - challengeToken: The value to provision in the DNS TXT record (typically base64url-encoded SHA-256 hash)
//   - authzValue: The domain name to create the challenge record for
//
// Returns:
//   - nil if DNS record is successfully provisioned
//   - ErrDNSServiceNotInitialized if DNS service is not configured
//   - error if domain parsing, zone retrieval, or zone saving fails
//
// The function:
// 1. Parses the domain from authzValue
// 2. Ensures authzValue has proper FQDN format (trailing dot)
// 3. Creates TXT record at _acme-challenge.<authzValue>
// 4. Adds record to the appropriate DNS zone
// 5. Saves zone changes to make the record immediately resolvable
func Setup(challengeToken, authzValue string) error {

	if DNSService == nil {
		return ErrDNSServiceNotInitialized
	}

	// Parse domain components from authzValue
	domain, err := parseDomain(authzValue)
	if err != nil {
		return err
	}

	// Ensure authzValue ends with a dot (FQDN format)
	if !strings.HasSuffix(authzValue, ".") {
		authzValue += "."
	}

	// Define the ACME TXT record
	name := fmt.Sprintf("_acme-challenge.%s", authzValue)
	ttl := uint32(300) // 5 minutes
	txt := NewTXTRecord(name, challengeToken, ttl)

	// Retrieve the zone from the DNS service
	zone, err := DNSService.Zone(domain)
	if err != nil {
		return err
	}

	// Add the record to the zone
	zone.AddTXTRecord(txt)

	// Save the zone to the datastore making the record
	// immediately available for resolution
	if err := DNSService.Save(zone); err != nil {
		return err
	}

	return nil
}

// SetupWithProvider provisions a DNS TXT record using a cloud provider.
//
// This function is an alternative to Setup() that uses external DNS providers
// (Route53, Cloudflare, Azure DNS, Cloud DNS) instead of a local DNS service.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - provider: The DNS provider to use for record management
//   - domain: The base domain (e.g., "example.com")
//   - challengeToken: The challenge value to provision
//
// Returns:
//   - nil if DNS record is successfully provisioned
//   - error if record creation fails
func SetupWithProvider(ctx context.Context, provider providers.Provider, domain, challengeToken string) error {
	if provider == nil {
		return ErrProviderNotConfigured
	}

	fqdn := providers.ToFQDN(fmt.Sprintf("_acme-challenge.%s", domain))
	return provider.Present(ctx, domain, fqdn, challengeToken)
}

// CleanupWithProvider removes a DNS TXT record using a cloud provider.
//
// This function cleans up records created by SetupWithProvider().
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - provider: The DNS provider to use for record management
//   - domain: The base domain (e.g., "example.com")
//   - challengeToken: The challenge value to remove
//
// Returns:
//   - nil if DNS record is successfully removed
//   - error if record deletion fails
func CleanupWithProvider(ctx context.Context, provider providers.Provider, domain, challengeToken string) error {
	if provider == nil {
		return ErrProviderNotConfigured
	}

	fqdn := providers.ToFQDN(fmt.Sprintf("_acme-challenge.%s", domain))
	return provider.CleanUp(ctx, domain, fqdn, challengeToken)
}

// GetProvider retrieves a registered DNS provider by name and creates an instance
// with the given configuration.
//
// Supported providers:
//   - "route53" - AWS Route53
//   - "cloudflare" - Cloudflare DNS
//   - "azure" - Azure DNS
//   - "clouddns" - Google Cloud DNS
//
// Parameters:
//   - ctx: Context for provider initialization
//   - name: Provider name (use providers.Provider* constants)
//   - config: Provider-specific configuration struct
//
// Returns:
//   - Provider instance if successful
//   - error if provider not found or configuration is invalid
func GetProvider(ctx context.Context, name string, config interface{}) (providers.Provider, error) {
	factory := providers.Get(name)
	if factory == nil {
		return nil, providers.ErrProviderNotFound
	}
	return factory(ctx, config)
}

// ListProviders returns the names of all registered DNS providers.
func ListProviders() []string {
	return providers.List()
}

// parseDomain extracts the domain from a fully qualified domain name.
//
// This is a simplified implementation that extracts the domain and TLD.
// For production use, consider using a public suffix list library like
// golang.org/x/net/publicsuffix for accurate domain parsing.
//
// Parameters:
//   - fqdn: Fully qualified domain name (e.g., "www.example.com" or "example.com.")
//
// Returns:
//   - domain name (e.g., "example.com")
//   - error if domain cannot be parsed
func parseDomain(fqdn string) (string, error) {
	// Remove trailing dot if present
	fqdn = strings.TrimSuffix(fqdn, ".")

	parts := strings.Split(fqdn, ".")
	if len(parts) < 2 {
		return "", caerrors.MalformedError("dns-01: invalid domain name: %s", fqdn)
	}

	// Return domain.tld (last two parts)
	return strings.Join(parts[len(parts)-2:], "."), nil
}

// txtRecord implements the TXTRecord interface
type txtRecord struct {
	name  string
	value string
	ttl   uint32
}

// NewTXTRecord creates a new DNS TXT record
func NewTXTRecord(name, value string, ttl uint32) TXTRecord {
	return &txtRecord{
		name:  name,
		value: value,
		ttl:   ttl,
	}
}

func (r *txtRecord) Name() string {
	return r.name
}

func (r *txtRecord) Value() string {
	return r.value
}

func (r *txtRecord) TTL() uint32 {
	return r.ttl
}

// ComputeChallengeValue computes the DNS TXT record value from a key authorization.
// This is the value that should be placed in the _acme-challenge TXT record.
//
// Per RFC 8555 Section 8.4, the value is:
// base64url(SHA-256(keyAuthorization))
//
// Parameters:
//   - keyAuth: The key authorization string (token.thumbprint)
//
// Returns:
//   - base64url-encoded SHA-256 hash of the key authorization
func ComputeChallengeValue(keyAuth string) string {
	hash := sha256.Sum256([]byte(keyAuth))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
