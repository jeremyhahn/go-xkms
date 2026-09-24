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

package policy

import (
	"github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// BlocklistConfig represents the blocklist configuration.
// This can be loaded from a YAML file or constructed programmatically.
type BlocklistConfig struct {
	// HighRiskBlockedNames is a list of domain names that block issuance for
	// the domain and all subdomains using label-wise suffix matching.
	// Example: "example.com" blocks "www.example.com", "mail.example.com", etc.
	HighRiskBlockedNames []string `yaml:"highRiskBlockedNames" json:"highRiskBlockedNames"`

	// ExactBlockedNames is a list of FQDNs that are blocked exactly as specified.
	// Example: "www.example.com" blocks only "www.example.com", not "example.com"
	// or "mail.example.com".
	ExactBlockedNames []string `yaml:"exactBlockedNames" json:"exactBlockedNames"`

	// AdminBlockedNames operates the same as HighRiskBlockedNames but is intended
	// for administrative blocks that change more frequently.
	AdminBlockedNames []string `yaml:"adminBlockedNames" json:"adminBlockedNames"`

	// AdminBlockedPrefixes is a list of IP address prefixes in CIDR notation.
	// All IP addresses within the prefix are blocked.
	// Example: "192.168.0.0/16" blocks all addresses from 192.168.0.0 to 192.168.255.255.
	AdminBlockedPrefixes []string `yaml:"adminBlockedPrefixes" json:"adminBlockedPrefixes"`
}

// PolicyConfig represents the full policy configuration including enabled
// identifier types, challenge types, and blocklist settings.
type PolicyConfig struct {
	// Blocklist contains the blocklist configuration.
	Blocklist BlocklistConfig `yaml:"blocklist" json:"blocklist"`

	// EnabledIdentifierTypes specifies which identifier types are allowed.
	// Keys are identifier types ("dns", "ip", "permanent-identifier").
	EnabledIdentifierTypes map[string]bool `yaml:"enabledIdentifierTypes" json:"enabledIdentifierTypes"`

	// EnabledChallengeTypes specifies which challenge types are allowed.
	// Keys are challenge types ("http-01", "dns-01", "tls-alpn-01", etc.).
	EnabledChallengeTypes map[string]bool `yaml:"enabledChallengeTypes" json:"enabledChallengeTypes"`

	// RequirePublicSuffix requires that domain names end with a valid public suffix.
	// When true, domains like "internal" or "localhost" are rejected.
	RequirePublicSuffix bool `yaml:"requirePublicSuffix" json:"requirePublicSuffix"`

	// AllowWildcards controls whether wildcard certificates are allowed.
	AllowWildcards bool `yaml:"allowWildcards" json:"allowWildcards"`

	// RejectReservedIPs rejects IP identifiers in reserved/special-purpose
	// ranges (loopback, private, link-local, multicast, documentation,
	// unspecified) per RFC 6890. See ValidateIPWithReservedCheck.
	RejectReservedIPs bool `yaml:"rejectReservedIPs" json:"rejectReservedIPs"`

	// IdentifierChallengeTypes overrides the default candidate challenge
	// types considered for an identifier type ("dns", "ip",
	// "permanent-identifier") before the enabled-challenge-type filter is
	// applied. An identifier type absent from this map keeps the package's
	// built-in default candidates. Wildcard DNS identifiers are exempt: per
	// RFC 8555 Section 7.1.4 and the CA/Browser Forum Baseline
	// Requirements, a wildcard MUST only use dns-01, and that restriction is
	// not configurable.
	IdentifierChallengeTypes map[string][]string `yaml:"identifierChallengeTypes" json:"identifierChallengeTypes"`
}

// DefaultBlocklistConfig returns a BlocklistConfig with sensible defaults.
// The default blocklist includes common high-risk and reserved domains.
func DefaultBlocklistConfig() *BlocklistConfig {
	return &BlocklistConfig{
		HighRiskBlockedNames: []string{
			// RFC 2606 reserved domains
			"example.com",
			"example.net",
			"example.org",
			"example.edu",
			"test",
			"example",
			"invalid",
			"localhost",
			// RFC 6761 special-use domains
			"local",
			"onion",
		},
		ExactBlockedNames: []string{
			// Typically empty - populated by specific policy requirements
		},
		AdminBlockedNames: []string{
			// Typically empty - populated by administrative actions
		},
		AdminBlockedPrefixes: []string{
			// RFC 1918 private networks
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			// RFC 5737 documentation addresses
			"192.0.2.0/24",
			"198.51.100.0/24",
			"203.0.113.0/24",
			// RFC 3927 link-local
			"169.254.0.0/16",
			// RFC 4193 unique local addresses (IPv6)
			"fc00::/7",
			// RFC 4291 link-local addresses (IPv6)
			"fe80::/10",
		},
	}
}

// DefaultPolicyConfig returns a PolicyConfig with sensible defaults.
func DefaultPolicyConfig() *PolicyConfig {
	return &PolicyConfig{
		Blocklist: *DefaultBlocklistConfig(),
		EnabledIdentifierTypes: map[string]bool{
			IdentifierTypeDNS:                 true,
			IdentifierTypeIP:                  true,
			IdentifierTypePermanentIdentifier: true,
		},
		EnabledChallengeTypes: map[string]bool{
			ChallengeTypeHTTP01:         true,
			ChallengeTypeDNS01:          true,
			ChallengeTypeTLSALPN01:      true,
			ChallengeTypeDeviceAttest01: true,
			ChallengeTypeEnroll01:       true,
			ChallengeTypeEndorse01:      true,
		},
		RequirePublicSuffix: true,
		AllowWildcards:      true,
	}
}

// Validate validates the policy configuration.
// A non-empty policy must have at least one enabled identifier type or
// at least one enabled challenge type to be useful.
func (c *PolicyConfig) Validate() error {
	hasIdentifiers := hasEnabledEntry(c.EnabledIdentifierTypes)
	hasChallenges := hasEnabledEntry(c.EnabledChallengeTypes)

	// If the config has no blocklist entries, no identifiers, and no challenges,
	// it is an empty/zero-value config which is valid (no policy enforcement).
	if c.Blocklist.IsEmpty() && !hasIdentifiers && !hasChallenges {
		return nil
	}

	// A non-empty policy must define at least one identifier type or challenge type.
	if !hasIdentifiers && !hasChallenges {
		return errors.MalformedError(
			"policy config must have at least one enabled identifier type or challenge type")
	}

	return nil
}

// hasEnabledEntry returns true if the map contains at least one key with a true value.
func hasEnabledEntry(m map[string]bool) bool {
	for _, v := range m {
		if v {
			return true
		}
	}
	return false
}

// Merge combines two BlocklistConfigs, with entries from other appended to b.
func (b *BlocklistConfig) Merge(other *BlocklistConfig) {
	if other == nil {
		return
	}
	b.HighRiskBlockedNames = append(b.HighRiskBlockedNames, other.HighRiskBlockedNames...)
	b.ExactBlockedNames = append(b.ExactBlockedNames, other.ExactBlockedNames...)
	b.AdminBlockedNames = append(b.AdminBlockedNames, other.AdminBlockedNames...)
	b.AdminBlockedPrefixes = append(b.AdminBlockedPrefixes, other.AdminBlockedPrefixes...)
}

// IsEmpty returns true if the blocklist configuration has no entries.
func (b *BlocklistConfig) IsEmpty() bool {
	return len(b.HighRiskBlockedNames) == 0 &&
		len(b.ExactBlockedNames) == 0 &&
		len(b.AdminBlockedNames) == 0 &&
		len(b.AdminBlockedPrefixes) == 0
}

// Clone creates a deep copy of the BlocklistConfig.
func (b *BlocklistConfig) Clone() *BlocklistConfig {
	if b == nil {
		return nil
	}
	clone := &BlocklistConfig{
		HighRiskBlockedNames: make([]string, len(b.HighRiskBlockedNames)),
		ExactBlockedNames:    make([]string, len(b.ExactBlockedNames)),
		AdminBlockedNames:    make([]string, len(b.AdminBlockedNames)),
		AdminBlockedPrefixes: make([]string, len(b.AdminBlockedPrefixes)),
	}
	copy(clone.HighRiskBlockedNames, b.HighRiskBlockedNames)
	copy(clone.ExactBlockedNames, b.ExactBlockedNames)
	copy(clone.AdminBlockedNames, b.AdminBlockedNames)
	copy(clone.AdminBlockedPrefixes, b.AdminBlockedPrefixes)
	return clone
}

// Clone creates a deep copy of the PolicyConfig.
func (c *PolicyConfig) Clone() *PolicyConfig {
	if c == nil {
		return nil
	}
	clone := &PolicyConfig{
		Blocklist:           *c.Blocklist.Clone(),
		RequirePublicSuffix: c.RequirePublicSuffix,
		AllowWildcards:      c.AllowWildcards,
		RejectReservedIPs:   c.RejectReservedIPs,
	}
	if c.EnabledIdentifierTypes != nil {
		clone.EnabledIdentifierTypes = make(map[string]bool)
		for k, v := range c.EnabledIdentifierTypes {
			clone.EnabledIdentifierTypes[k] = v
		}
	}
	if c.EnabledChallengeTypes != nil {
		clone.EnabledChallengeTypes = make(map[string]bool)
		for k, v := range c.EnabledChallengeTypes {
			clone.EnabledChallengeTypes[k] = v
		}
	}
	if c.IdentifierChallengeTypes != nil {
		clone.IdentifierChallengeTypes = make(map[string][]string, len(c.IdentifierChallengeTypes))
		for k, v := range c.IdentifierChallengeTypes {
			clone.IdentifierChallengeTypes[k] = append([]string(nil), v...)
		}
	}
	return clone
}
