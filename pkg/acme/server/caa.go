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

package server

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	dns01providers "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/miekg/dns"
)

// caaCriticalFlag is the CAA record's Issuer Critical flag (RFC 8659 Section
// 4.1, bit 0, the most significant bit of the flags octet). A record with
// this bit set whose property tag the CA does not implement MUST prevent
// issuance.
const caaCriticalFlag uint8 = 0x80

// caaKnownTags are the property tags this validator understands per RFC 8659
// Section 4. Any other tag encountered with the critical flag set fails
// validation closed, per RFC 8659 Section 4: "the CA MUST NOT issue
// certificates for any Domain Name if the relevant CAA Resource Record Set
// contains any unrecognized property with the critical flag set."
var caaKnownTags = map[string]bool{
	"issue":     true,
	"issuewild": true,
	"iodef":     true,
}

// CAAValidator performs CAA (Certification Authority Authorization) validation
// per RFC 8659 and RFC 8555 Section 8.1. CAA records allow domain owners to
// specify which CAs are authorized to issue certificates for their domains.
//
// RFC 8659 specifies:
// - CAA record format and property tags (issue, issuewild, iodef)
// - DNS tree climbing algorithm for finding CAA records
// - CNAME following behavior
// - Wildcard validation with issuewild tag
//
// RFC 8555 Section 8.1 requires ACME servers to:
//   - Check CAA records before issuing certificates
//   - Return "caa" error type when validation fails
//   - Fail closed on a DNS error per RFC 8659 Section 5.1: a CA MUST NOT
//     issue if it cannot determine the relevant CAA RRset, for any reason
type CAAValidator struct {
	client        *dns.Client
	resolver      string
	timeout       time.Duration
	logger        *slog.Logger
	cache         *caaCache
	caaIdentities []string
}

// CAAValidatorParams contains configuration for creating a CAA validator.
type CAAValidatorParams struct {
	// Resolver is the DNS server address (e.g., "8.8.8.8:53")
	// If empty, uses system default resolver
	Resolver string

	// Timeout for DNS queries
	Timeout time.Duration

	// Logger for structured logging
	Logger *slog.Logger

	// CAAIdentities are the CAA identities for this server
	// These are matched against CAA record values
	CAAIdentities []string
}

// CAARecord represents a parsed CAA DNS record.
type CAARecord struct {
	Tag   string // issue, issuewild, or iodef
	Value string // CA domain name or URL
	Flags uint8  // Critical flag (bit 7)
}

// caaCache provides time-based caching for CAA lookup results.
type caaCache struct {
	mu      sync.RWMutex
	entries map[string]*caaEntry
	ttl     time.Duration
}

type caaEntry struct {
	records   []*CAARecord
	timestamp time.Time
}

// ErrCAAValidationFailed is returned when CAA validation fails.
type ErrCAAValidationFailed struct {
	Domain string
	Reason string
}

func (e *ErrCAAValidationFailed) Error() string {
	return fmt.Sprintf("CAA validation failed for %s: %s", e.Domain, e.Reason)
}

// ErrCAADNSError is returned when DNS lookup fails during CAA validation.
type ErrCAADNSError struct {
	Domain string
	Err    error
}

func (e *ErrCAADNSError) Error() string {
	return fmt.Sprintf("DNS error during CAA validation for %s: %v", e.Domain, e.Err)
}

// NewCAAValidator creates a new CAA validator with the specified configuration.
func NewCAAValidator(params *CAAValidatorParams) (*CAAValidator, error) {
	if params == nil {
		return nil, caerrors.MalformedError("caa: params cannot be nil")
	}

	if params.Logger == nil {
		return nil, caerrors.MalformedError("caa: logger is required")
	}

	// Default to 5 second timeout if not specified
	timeout := params.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	resolver := params.Resolver
	if resolver == "" {
		// Reuse the same recursive resolver the dns-01 challenge tooling
		// defaults to (pkg/acme/challenges/dns-01/providers), rather than
		// maintaining a second hardcoded default here.
		resolver = dns01providers.DefaultNameservers[0]
	}

	return &CAAValidator{
		client: &dns.Client{
			Timeout: timeout,
		},
		resolver:      resolver,
		timeout:       timeout,
		logger:        params.Logger,
		caaIdentities: params.CAAIdentities,
		cache: &caaCache{
			entries: make(map[string]*caaEntry),
			ttl:     5 * time.Minute, // Cache for 5 minutes
		},
	}, nil
}

// Validate performs CAA validation for a domain and wildcard flag.
// It implements the tree climbing algorithm per RFC 8659 Section 3.
//
// Parameters:
//   - ctx: Context for cancellation
//   - domain: The domain name to validate
//   - isWildcard: Whether this is for a wildcard certificate
//
// Returns:
//   - nil if validation succeeds
//   - *ErrCAAValidationFailed if CAA records prevent issuance
//   - *ErrCAADNSError if the CAA RRset could not be determined (DNS failure)
func (v *CAAValidator) Validate(ctx context.Context, domain string, isWildcard bool) error {
	v.logger.Debug("CAA validation starting",
		"domain", domain,
		"wildcard", isWildcard,
		"identities", v.caaIdentities)

	// Normalize domain to lowercase
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	// Check cache first
	if records := v.getCached(domain); records != nil {
		v.logger.Debug("CAA records found in cache", "domain", domain)
		return v.validateRecords(domain, records, isWildcard)
	}

	// Perform CAA lookup with tree climbing
	records, err := v.lookupCAA(ctx, domain)
	if err != nil {
		// RFC 8659 Section 5.1: a CA MUST NOT issue if it is unable to
		// determine the relevant CAA RRset for any reason (network failure,
		// SERVFAIL, malformed response, timeout). This is a fail-closed
		// design; issuance proceeds only when the RRset was actually
		// observed (including an authoritative "no CAA records" outcome).
		v.logger.Error("CAA DNS lookup failed; denying issuance per RFC 8659 Section 5.1",
			"domain", domain,
			"error", err)
		return err
	}

	// Cache the results
	v.setCached(domain, records)

	// Validate the records
	return v.validateRecords(domain, records, isWildcard)
}

// lookupCAA performs CAA record lookup with tree climbing per RFC 8659.
func (v *CAAValidator) lookupCAA(ctx context.Context, domain string) ([]*CAARecord, error) {
	v.logger.Debug("Looking up CAA records", "domain", domain)

	// Climb the DNS tree from the requested domain to the TLD
	currentDomain := domain
	for {
		// Check for CNAME first
		cname, err := v.resolveCNAME(ctx, currentDomain)
		if err != nil {
			// CNAME lookup error - continue with original domain
			v.logger.Debug("CNAME lookup failed, continuing", "domain", currentDomain, "error", err)
		} else if cname != "" && cname != currentDomain {
			// Found a CNAME - follow it
			v.logger.Debug("Following CNAME", "from", currentDomain, "to", cname)
			currentDomain = cname
			// Continue to check for CAA at CNAME target
		}

		// Look up CAA records at current domain level
		records, err := v.queryCAARecords(ctx, currentDomain)
		if err != nil {
			return nil, &ErrCAADNSError{Domain: currentDomain, Err: err}
		}

		// If we found CAA records, return them
		if len(records) > 0 {
			v.logger.Debug("Found CAA records",
				"domain", currentDomain,
				"count", len(records))
			return records, nil
		}

		// Climb to parent domain
		parts := strings.SplitN(currentDomain, ".", 2)
		if len(parts) < 2 {
			// Reached TLD or invalid domain
			v.logger.Debug("Reached TLD, no CAA records found", "domain", currentDomain)
			break
		}

		currentDomain = parts[1]
		v.logger.Debug("Climbing to parent domain", "domain", currentDomain)
	}

	// No CAA records found in entire tree
	v.logger.Debug("No CAA records found in DNS tree", "domain", domain)
	return nil, nil
}

// resolveCNAME checks if a domain has a CNAME record and returns the target.
func (v *CAAValidator) resolveCNAME(ctx context.Context, domain string) (string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeCNAME)
	msg.RecursionDesired = true

	resp, _, err := v.client.ExchangeContext(ctx, msg, v.resolver)
	if err != nil {
		return "", err
	}

	if resp.Rcode != dns.RcodeSuccess {
		return "", nil
	}

	for _, ans := range resp.Answer {
		if cname, ok := ans.(*dns.CNAME); ok {
			return strings.TrimSuffix(cname.Target, "."), nil
		}
	}

	return "", nil
}

// queryCAARecords queries CAA records for a specific domain.
func (v *CAAValidator) queryCAARecords(ctx context.Context, domain string) ([]*CAARecord, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeCAA)
	msg.RecursionDesired = true

	resp, _, err := v.client.ExchangeContext(ctx, msg, v.resolver)
	if err != nil {
		return nil, err
	}

	// Handle various DNS response codes per RFC 8659 Section 3.
	//
	// RcodeNameError (NXDOMAIN) means this specific owner name does not
	// exist; that is an ordinary outcome while climbing the label tree and
	// is treated as "no CAA records at this level" so the search continues
	// at the parent. Every other non-success code (SERVFAIL, REFUSED, ...)
	// means the RRset could not be determined at all, which Section 5.1
	// requires the CA to treat as a failure to issue, not as an absence of
	// records.
	switch resp.Rcode {
	case dns.RcodeSuccess:
		// Continue to parse records
	case dns.RcodeNameError:
		// NXDOMAIN - no CAA records at this level
		return nil, nil
	default:
		return nil, caerrors.DNSError("DNS query failed with rcode: %s", dns.RcodeToString[resp.Rcode])
	}

	var records []*CAARecord
	for _, ans := range resp.Answer {
		if caa, ok := ans.(*dns.CAA); ok {
			records = append(records, &CAARecord{
				Tag:   caa.Tag,
				Value: caa.Value,
				Flags: caa.Flag,
			})
		}
	}

	return records, nil
}

// validateRecords checks if the CAA records allow issuance.
func (v *CAAValidator) validateRecords(domain string, records []*CAARecord, isWildcard bool) error {
	// If no CAA records exist, issuance is allowed
	if len(records) == 0 {
		v.logger.Debug("No CAA records, allowing issuance", "domain", domain)
		return nil
	}

	// RFC 8659 Section 4: a critical property this CA does not recognize
	// MUST prevent issuance, regardless of any issue/issuewild record that
	// would otherwise authorize it. "issue", "issuewild", and "iodef" are
	// the only tags this validator understands.
	for _, record := range records {
		if !caaKnownTags[record.Tag] && record.Flags&caaCriticalFlag != 0 {
			return &ErrCAAValidationFailed{
				Domain: domain,
				Reason: fmt.Sprintf("unrecognized critical CAA property tag %q", record.Tag),
			}
		}
	}

	// A validator with no configured identities cannot determine whether it
	// is among the authorized issuers, so with an existing CAA RRset present
	// it must fail closed rather than assume authorization (RFC 8659
	// Section 5.1).
	if len(v.caaIdentities) == 0 {
		return &ErrCAAValidationFailed{
			Domain: domain,
			Reason: "no CAA identities configured for this CA; cannot verify authorization",
		}
	}

	// Track if we found any relevant CAA records
	foundIssue := false
	foundIssuewild := false
	authorized := false

	for _, record := range records {
		// Log iodef records for incident reporting
		if record.Tag == "iodef" {
			v.logger.Info("CAA iodef record found",
				"domain", domain,
				"iodef", record.Value)
			continue
		}

		// Check issuewild tag for wildcard certificates
		if isWildcard && record.Tag == "issuewild" {
			foundIssuewild = true
			if v.isAuthorized(record.Value) {
				v.logger.Debug("Authorized by issuewild CAA record",
					"domain", domain,
					"value", record.Value)
				authorized = true
			}
		}

		// Check issue tag for all certificates
		if record.Tag == "issue" {
			foundIssue = true
			if v.isAuthorized(record.Value) {
				v.logger.Debug("Authorized by issue CAA record",
					"domain", domain,
					"value", record.Value)
				authorized = true
			}
		}
	}

	// RFC 8659: For wildcard certificates, issuewild takes precedence over issue
	if isWildcard && foundIssuewild {
		if !authorized {
			return &ErrCAAValidationFailed{
				Domain: domain,
				Reason: "no matching issuewild CAA record found",
			}
		}
		return nil
	}

	// For non-wildcard or when no issuewild present, check issue tag
	if foundIssue {
		if !authorized {
			return &ErrCAAValidationFailed{
				Domain: domain,
				Reason: "no matching issue CAA record found",
			}
		}
		return nil
	}

	// If we get here and found wildcard records but no issue records,
	// wildcard validation failed
	if isWildcard && foundIssuewild && !authorized {
		return &ErrCAAValidationFailed{
			Domain: domain,
			Reason: "no matching issuewild CAA record found",
		}
	}

	// No relevant CAA records found, allow issuance
	v.logger.Debug("No relevant CAA records found, allowing issuance", "domain", domain)
	return nil
}

// isAuthorized checks if a CAA issue/issuewild record value authorizes this
// CA per RFC 8659 Section 4.2 / RFC 8657 Section 3. The value grammar is:
//
//	issue-value = issuer-domain-name *(";" parameter)
//	parameter   = tag "=" *VCHAR
//
// The issuer-domain-name is matched against the configured CAA identities as
// a full domain name, exact and case-insensitive — never as a prefix. A
// prefix match would let "ca.example.com.attacker.example" (or any other
// domain merely beginning with an authorized identity) impersonate an
// authorized issuer, which is the bug RFC 8659's exact-match rule exists to
// prevent.
func (v *CAAValidator) isAuthorized(value string) bool {
	trimmed := strings.TrimSpace(value)

	// Empty value, or a bare ";", means "no CA is authorized to issue".
	if trimmed == "" || trimmed == ";" {
		return false
	}

	issuer, params := parseCAAIssueValue(trimmed)
	if issuer == "" {
		return false
	}

	if accountURI, ok := params["accounturi"]; ok {
		v.logger.Info("CAA record specifies accounturi parameter (RFC 8657); not enforced",
			"issuer", issuer, "accounturi", accountURI)
	}
	if methods, ok := params["validationmethods"]; ok {
		v.logger.Info("CAA record specifies validationmethods parameter (RFC 8657); not enforced",
			"issuer", issuer, "validationmethods", methods)
	}

	for _, identity := range v.caaIdentities {
		normalizedIdentity := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(identity)), ".")
		if issuer == normalizedIdentity {
			return true
		}
	}

	return false
}

// parseCAAIssueValue splits a CAA issue/issuewild property value into its
// issuer-domain-name and any trailing ";"-separated "tag=value" parameters
// (RFC 8657 accounturi / validationmethods), per the RFC 8659 Section 4.2
// grammar. The issuer domain is lowercased with any trailing root dot
// stripped; parameter tags are lowercased, values are left as-is.
func parseCAAIssueValue(value string) (issuer string, params map[string]string) {
	fields := strings.Split(value, ";")

	issuer = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fields[0])), ".")

	if len(fields) > 1 {
		params = make(map[string]string, len(fields)-1)
		for _, field := range fields[1:] {
			field = strings.TrimSpace(field)
			if field == "" {
				continue
			}
			tag, val, found := strings.Cut(field, "=")
			tag = strings.ToLower(strings.TrimSpace(tag))
			if found {
				val = strings.TrimSpace(val)
			}
			params[tag] = val
		}
	}

	return issuer, params
}

// getCached retrieves CAA records from cache if not expired.
func (v *caaCache) getCached(domain string) []*CAARecord {
	v.mu.RLock()
	defer v.mu.RUnlock()

	entry, ok := v.entries[domain]
	if !ok {
		return nil
	}

	// Check if entry is expired
	if time.Since(entry.timestamp) > v.ttl {
		return nil
	}

	return entry.records
}

// setCached stores CAA records in cache.
func (v *caaCache) setCached(domain string, records []*CAARecord) {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.entries[domain] = &caaEntry{
		records:   records,
		timestamp: time.Now(),
	}
}

// getCached is a convenience method on the validator.
func (v *CAAValidator) getCached(domain string) []*CAARecord {
	return v.cache.getCached(domain)
}

// setCached is a convenience method on the validator.
func (v *CAAValidator) setCached(domain string, records []*CAARecord) {
	v.cache.setCached(domain, records)
}

// ClearCache clears all cached CAA records.
// This is primarily useful for testing.
func (v *CAAValidator) ClearCache() {
	v.cache.mu.Lock()
	defer v.cache.mu.Unlock()
	v.cache.entries = make(map[string]*caaEntry)
}
