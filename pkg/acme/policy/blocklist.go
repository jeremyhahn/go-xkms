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

package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"gopkg.in/yaml.v3"
)

// Blocklist provides multi-tier domain and IP blocklisting for certificate issuance.
// It supports three tiers of domain blocking:
//   - Domain blocklist: Label-wise suffix matching for high-risk domains
//   - FQDN blocklist: Exact FQDN matches only
//   - Wildcard FQDN blocklist: Controls wildcard certificate issuance
//   - IP prefix blocklist: CIDR ranges of blocked IP addresses
//
// The Blocklist is safe for concurrent access.
type Blocklist struct {
	// domainBlocklist contains high-risk domains using label-wise suffix matching.
	// Blocking "example.com" also blocks "www.example.com".
	domainBlocklist map[string]bool

	// fqdnBlocklist contains exact FQDN matches only.
	fqdnBlocklist map[string]bool

	// wildcardFqdnBlocklist controls wildcard certificate issuance.
	// Contains the base domain (without *.) that would be blocked as a wildcard.
	wildcardFqdnBlocklist map[string]bool

	// ipPrefixBlocklist contains IP CIDR ranges that are blocked.
	ipPrefixBlocklist []netip.Prefix

	// mu protects all blocklist fields during updates.
	mu sync.RWMutex

	// loaded indicates whether a policy has been loaded.
	loaded atomic.Bool

	// logger for policy operations.
	logger *slog.Logger
}

// NewBlocklist creates a new empty Blocklist.
func NewBlocklist() *Blocklist {
	return &Blocklist{
		domainBlocklist:       make(map[string]bool),
		fqdnBlocklist:         make(map[string]bool),
		wildcardFqdnBlocklist: make(map[string]bool),
		ipPrefixBlocklist:     make([]netip.Prefix, 0),
		logger:                slog.Default(),
	}
}

// NewBlocklistWithLogger creates a new empty Blocklist with a custom logger.
func NewBlocklistWithLogger(logger *slog.Logger) *Blocklist {
	if logger == nil {
		logger = slog.Default()
	}
	return &Blocklist{
		domainBlocklist:       make(map[string]bool),
		fqdnBlocklist:         make(map[string]bool),
		wildcardFqdnBlocklist: make(map[string]bool),
		ipPrefixBlocklist:     make([]netip.Prefix, 0),
		logger:                logger,
	}
}

// LoadFromFile loads a blocklist configuration from a YAML file.
// The file's SHA256 checksum is logged for audit purposes.
func (b *Blocklist) LoadFromFile(path string) error {
	// #nosec G304 - path is administrator-controlled configuration file
	configBytes, err := os.ReadFile(path)
	if err != nil {
		return NewBlocklistError(ErrBlocklistFileRead, path, "", err.Error())
	}

	hash := sha256.Sum256(configBytes)
	b.logger.Info("loading blocklist policy",
		slog.String("file", path),
		slog.String("sha256", hex.EncodeToString(hash[:])),
	)

	var config BlocklistConfig
	if err := yaml.Unmarshal(configBytes, &config); err != nil {
		return NewBlocklistError(ErrBlocklistFileParse, path, "", err.Error())
	}

	return b.LoadFromConfig(&config)
}

// LoadFromConfig loads a blocklist configuration from a BlocklistConfig struct.
func (b *Blocklist) LoadFromConfig(config *BlocklistConfig) error {
	if config == nil {
		return NewBlocklistError(ErrBlocklistFileParse, "", "", "config is nil")
	}

	// Build the domain blocklist from high-risk and admin blocked names
	nameMap := make(map[string]bool)
	for _, v := range config.HighRiskBlockedNames {
		nameMap[strings.ToLower(v)] = true
	}
	for _, v := range config.AdminBlockedNames {
		nameMap[strings.ToLower(v)] = true
	}

	// Build the exact FQDN blocklist and wildcard FQDN blocklist
	exactNameMap := make(map[string]bool)
	wildcardNameMap := make(map[string]bool)
	for _, v := range config.ExactBlockedNames {
		v = strings.ToLower(v)
		exactNameMap[v] = true

		// Extract the parent domain to prevent wildcard issuance
		// If "highvalue.example.com" is blocked, then "*.example.com" should also be blocked
		parts := strings.SplitN(v, ".", 2)
		if len(parts) < 2 {
			return NewBlocklistError(
				ErrMalformedBlocklistEntry,
				"",
				v,
				"ExactBlockedNames entry must have at least two labels",
			)
		}
		wildcardNameMap[parts[1]] = true
	}

	// Parse IP prefixes
	var prefixes []netip.Prefix
	for _, p := range config.AdminBlockedPrefixes {
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			return NewBlocklistError(ErrMalformedIPPrefix, "", p, err.Error())
		}
		prefixes = append(prefixes, prefix)
	}

	// Update the blocklists atomically
	b.mu.Lock()
	b.domainBlocklist = nameMap
	b.fqdnBlocklist = exactNameMap
	b.wildcardFqdnBlocklist = wildcardNameMap
	b.ipPrefixBlocklist = prefixes
	b.mu.Unlock()

	b.loaded.Store(true)

	b.logger.Info("blocklist policy loaded",
		slog.Int("domain_entries", len(nameMap)),
		slog.Int("fqdn_entries", len(exactNameMap)),
		slog.Int("wildcard_entries", len(wildcardNameMap)),
		slog.Int("ip_prefix_entries", len(prefixes)),
	)

	return nil
}

// IsLoaded returns true if a blocklist policy has been loaded.
func (b *Blocklist) IsLoaded() bool {
	return b.loaded.Load()
}

// IsDomainBlocked checks if a domain is blocked by any of the blocklists.
// It checks the exact FQDN blocklist first, then the domain blocklist using
// label-wise suffix matching.
//
// Returns:
//   - blocked: true if the domain is blocked
//   - reason: human-readable reason for blocking (empty if not blocked)
func (b *Blocklist) IsDomainBlocked(domain string) (blocked bool, reason string) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if !b.loaded.Load() {
		return false, ""
	}

	domain = strings.ToLower(domain)

	// Remove wildcard prefix for checking if present
	checkDomain := domain
	if strings.HasPrefix(domain, "*.") {
		checkDomain = strings.TrimPrefix(domain, "*.")
	}

	// Check exact FQDN blocklist
	if b.fqdnBlocklist[checkDomain] {
		return true, "domain is in the exact FQDN blocklist"
	}

	// Check domain blocklist with label-wise suffix matching
	labels := strings.Split(checkDomain, ".")
	for i := range labels {
		joined := strings.Join(labels[i:], ".")
		if b.domainBlocklist[joined] {
			return true, "domain matches high-risk blocklist pattern: " + joined
		}
	}

	return false, ""
}

// IsIPBlocked checks if an IP address is blocked by the IP prefix blocklist.
//
// Returns:
//   - blocked: true if the IP is blocked
//   - reason: human-readable reason for blocking (empty if not blocked)
func (b *Blocklist) IsIPBlocked(ip netip.Addr) (blocked bool, reason string) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if !b.loaded.Load() {
		return false, ""
	}

	// Strip zone identifier if present
	ip = ip.WithZone("")

	for _, prefix := range b.ipPrefixBlocklist {
		if prefix.Contains(ip) {
			return true, "IP address is in blocked prefix: " + prefix.String()
		}
	}

	return false, ""
}

// IsWildcardBlocked checks if wildcard certificate issuance is blocked for a domain.
// The domain should be the base domain (without the *. prefix).
//
// Wildcard cascade: if a domain is in the domain blocklist, wildcard issuance
// is also blocked for that domain.
//
// Returns:
//   - blocked: true if wildcard issuance is blocked
//   - reason: human-readable reason for blocking (empty if not blocked)
func (b *Blocklist) IsWildcardBlocked(domain string) (blocked bool, reason string) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if !b.loaded.Load() {
		return false, ""
	}

	domain = strings.ToLower(domain)

	// Check wildcard FQDN blocklist
	if b.wildcardFqdnBlocklist[domain] {
		return true, "wildcard blocked due to exact FQDN blocklist entry"
	}

	// Wildcard cascade: check if the domain or any parent is in the domain blocklist
	labels := strings.Split(domain, ".")
	for i := range labels {
		joined := strings.Join(labels[i:], ".")
		if b.domainBlocklist[joined] {
			return true, "wildcard blocked due to domain blocklist pattern: " + joined
		}
	}

	return false, ""
}

// CheckIdentifier checks if an identifier (domain or IP) is blocked.
// This is a convenience method that dispatches to the appropriate check method.
//
// Parameters:
//   - identifierType: "dns" or "ip"
//   - value: the identifier value (domain name or IP address)
//
// Returns an error if the identifier is blocked, nil otherwise.
func (b *Blocklist) CheckIdentifier(identifierType, value string) error {
	if !b.loaded.Load() {
		return ErrPolicyNotLoaded
	}

	switch identifierType {
	case IdentifierTypeDNS:
		// Check if this is a wildcard
		if strings.HasPrefix(value, "*.") {
			baseDomain := strings.TrimPrefix(value, "*.")
			if blocked, reason := b.IsWildcardBlocked(baseDomain); blocked {
				return NewPolicyError(ErrPolicyForbidden, identifierType, value, reason)
			}
		}

		if blocked, reason := b.IsDomainBlocked(value); blocked {
			return NewPolicyError(ErrPolicyForbidden, identifierType, value, reason)
		}

	case IdentifierTypeIP:
		ip, err := netip.ParseAddr(value)
		if err != nil {
			return NewPolicyError(ErrIPInvalid, identifierType, value, err.Error())
		}
		if blocked, reason := b.IsIPBlocked(ip); blocked {
			return NewPolicyError(ErrPolicyForbidden, identifierType, value, reason)
		}

	default:
		return NewPolicyError(ErrUnsupportedIdentifierType, identifierType, value, "")
	}

	return nil
}

// AddDomainBlock adds a domain to the high-risk domain blocklist.
// The block takes effect immediately for subsequent checks.
func (b *Blocklist) AddDomainBlock(domain string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.domainBlocklist[strings.ToLower(domain)] = true
}

// AddFQDNBlock adds a domain to the exact FQDN blocklist.
// Also adds the parent domain to the wildcard blocklist to prevent *.parent.com.
func (b *Blocklist) AddFQDNBlock(fqdn string) {
	fqdn = strings.ToLower(fqdn)

	b.mu.Lock()
	defer b.mu.Unlock()

	b.fqdnBlocklist[fqdn] = true

	// Add parent to wildcard blocklist
	parts := strings.SplitN(fqdn, ".", 2)
	if len(parts) >= 2 {
		b.wildcardFqdnBlocklist[parts[1]] = true
	}
}

// AddIPPrefixBlock adds an IP prefix to the blocklist.
func (b *Blocklist) AddIPPrefixBlock(prefix netip.Prefix) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ipPrefixBlocklist = append(b.ipPrefixBlocklist, prefix)
}

// RemoveDomainBlock removes a domain from the high-risk domain blocklist.
func (b *Blocklist) RemoveDomainBlock(domain string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.domainBlocklist, strings.ToLower(domain))
}

// RemoveFQDNBlock removes a domain from the exact FQDN blocklist.
// Note: does not automatically remove from wildcard blocklist.
func (b *Blocklist) RemoveFQDNBlock(fqdn string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.fqdnBlocklist, strings.ToLower(fqdn))
}

// Clear removes all entries from all blocklists but keeps the policy loaded state.
func (b *Blocklist) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.domainBlocklist = make(map[string]bool)
	b.fqdnBlocklist = make(map[string]bool)
	b.wildcardFqdnBlocklist = make(map[string]bool)
	b.ipPrefixBlocklist = make([]netip.Prefix, 0)
}

// Stats returns statistics about the blocklist.
func (b *Blocklist) Stats() BlocklistStats {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return BlocklistStats{
		DomainEntries:       len(b.domainBlocklist),
		FQDNEntries:         len(b.fqdnBlocklist),
		WildcardFQDNEntries: len(b.wildcardFqdnBlocklist),
		IPPrefixEntries:     len(b.ipPrefixBlocklist),
		Loaded:              b.loaded.Load(),
	}
}

// BlocklistStats contains statistics about the blocklist.
type BlocklistStats struct {
	DomainEntries       int  `json:"domainEntries"`
	FQDNEntries         int  `json:"fqdnEntries"`
	WildcardFQDNEntries int  `json:"wildcardFqdnEntries"`
	IPPrefixEntries     int  `json:"ipPrefixEntries"`
	Loaded              bool `json:"loaded"`
}
