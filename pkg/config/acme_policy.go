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

package config

import (
	"errors"
	"net/netip"

	"github.com/jeremyhahn/go-xkms/pkg/acme/policy"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// Error types returned when validating the ACME policy configuration section.
var (
	// ErrACMEPolicyInvalidCIDR is returned when policy.blocklist.cidrs
	// contains an entry that is not a valid CIDR prefix.
	ErrACMEPolicyInvalidCIDR = errors.New("acme: policy.blocklist.cidrs entry is not a valid CIDR")

	// ErrACMEPolicyUnknownIdentifierType is returned when
	// policy.identifier_challenge_types names an identifier type other than
	// "dns", "ip", or "permanent-identifier".
	ErrACMEPolicyUnknownIdentifierType = errors.New(
		"acme: policy.identifier_challenge_types key is not a known identifier type (dns, ip, permanent-identifier)")

	// ErrACMEPolicyUnknownChallengeType is returned when
	// policy.identifier_challenge_types names a challenge type the ACME
	// server does not recognize.
	ErrACMEPolicyUnknownChallengeType = errors.New(
		"acme: policy.identifier_challenge_types value is not a known challenge type")
)

// ACMEPolicyConfig configures the ACME identifier issuance policy engine
// (pkg/acme/policy): the domain/FQDN/wildcard/CIDR blocklist, public-suffix
// and reserved-IP enforcement, and per-identifier-type challenge selection.
//
// The three boolean knobs are pointers so an omitted key can be told apart
// from an explicit "false": omitting one leaves the corresponding
// enforcement on. This is secure by default — an operator has to take an
// explicit action to relax it, and Validate never has to guess whether an
// absent key meant "off" or "not configured".
type ACMEPolicyConfig struct {
	// Blocklist configures blocked domains, FQDNs, wildcards, and IP CIDRs.
	Blocklist ACMEBlocklistConfig `yaml:"blocklist"`

	// RequirePublicSuffix rejects DNS identifiers that do not end in a
	// recognized public suffix (e.g. "internal", "localhost"). Nil leaves
	// the check on.
	RequirePublicSuffix *bool `yaml:"require_public_suffix,omitempty"`

	// RejectReservedIPs rejects IP identifiers in reserved/special-purpose
	// ranges (loopback, private, link-local, multicast, documentation,
	// unspecified). Nil leaves the check on.
	RejectReservedIPs *bool `yaml:"reject_reserved_ips,omitempty"`

	// AllowWildcards permits wildcard DNS identifiers (e.g.
	// "*.example.com"). Nil leaves wildcard issuance on.
	AllowWildcards *bool `yaml:"allow_wildcards,omitempty"`

	// IdentifierChallengeTypes overrides the default candidate challenge
	// types offered for an identifier type ("dns", "ip",
	// "permanent-identifier"). An identifier type absent from this map
	// keeps go-xkms's default challenge candidates: standard web-PKI
	// challenges (http-01, dns-01) for DNS identifiers, and TPM/TCG
	// attestation challenges (device-attest-01, enroll-01, endorse-01) for
	// IP and permanent identifiers. Wildcard DNS identifiers are exempt:
	// per RFC 8555 Section 7.1.4, a wildcard MUST only use dns-01, and that
	// restriction is not configurable.
	IdentifierChallengeTypes map[string][]string `yaml:"identifier_challenge_types,omitempty"`
}

// ACMEBlocklistConfig configures the ACME identifier blocklist.
type ACMEBlocklistConfig struct {
	// UseDefaults seeds the blocklist with policy.DefaultBlocklistConfig()
	// (RFC 2606 reserved names such as "example.com" and "invalid"; RFC
	// 1918/5737/3927/4193/4291 reserved IP ranges) before applying the
	// entries below. Nil leaves the defaults on.
	UseDefaults *bool `yaml:"use_defaults,omitempty"`

	// HighRiskDomains blocks the named domain and all of its subdomains
	// using label-wise suffix matching, and cascades to block wildcard
	// issuance for the same domain.
	HighRiskDomains []string `yaml:"high_risk_domains,omitempty"`

	// ExactFQDNs blocks only the named FQDN, not its parent or siblings,
	// and blocks wildcard issuance for its parent domain.
	ExactFQDNs []string `yaml:"exact_fqdns,omitempty"`

	// AdminDomains operates the same as HighRiskDomains but is intended for
	// administrative blocks that change more frequently than the
	// operator's static configuration.
	AdminDomains []string `yaml:"admin_domains,omitempty"`

	// CIDRs blocks every IP address within the named prefixes.
	CIDRs []string `yaml:"cidrs,omitempty"`
}

// RequiresPublicSuffix reports whether DNS identifiers must end in a
// recognized public suffix. Omitting the key leaves the check on.
func (p ACMEPolicyConfig) RequiresPublicSuffix() bool {
	return p.RequirePublicSuffix == nil || *p.RequirePublicSuffix
}

// RejectsReservedIPs reports whether IP identifiers in reserved ranges are
// refused. Omitting the key leaves the check on.
func (p ACMEPolicyConfig) RejectsReservedIPs() bool {
	return p.RejectReservedIPs == nil || *p.RejectReservedIPs
}

// AllowsWildcards reports whether wildcard DNS identifiers are permitted.
// Omitting the key leaves wildcard issuance on.
func (p ACMEPolicyConfig) AllowsWildcards() bool {
	return p.AllowWildcards == nil || *p.AllowWildcards
}

// UsesDefaults reports whether the blocklist is seeded with
// policy.DefaultBlocklistConfig(). Omitting the key leaves the defaults on.
func (b ACMEBlocklistConfig) UsesDefaults() bool {
	return b.UseDefaults == nil || *b.UseDefaults
}

// Validate checks the policy section: that every configured CIDR parses,
// and that identifier_challenge_types names only identifier types and
// challenge types the ACME server recognizes. It is meaningful regardless
// of whether ACME itself is enabled, since a misconfigured policy section
// should fail fast at load time rather than at first order.
func (p ACMEPolicyConfig) Validate() error {
	for _, cidr := range p.Blocklist.CIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return &errs.Detail{Err: ErrACMEPolicyInvalidCIDR, Detail: cidr}
		}
	}

	validIdentifierTypes := map[string]bool{
		policy.IdentifierTypeDNS:                 true,
		policy.IdentifierTypeIP:                  true,
		policy.IdentifierTypePermanentIdentifier: true,
	}
	validChallengeTypes := make(map[string]bool, len(policy.AllChallengeTypes()))
	for _, ct := range policy.AllChallengeTypes() {
		validChallengeTypes[ct] = true
	}

	for idType, challengeTypes := range p.IdentifierChallengeTypes {
		if !validIdentifierTypes[idType] {
			return &errs.Detail{Err: ErrACMEPolicyUnknownIdentifierType, Detail: idType}
		}
		for _, ct := range challengeTypes {
			if !validChallengeTypes[ct] {
				return &errs.Detail{Err: ErrACMEPolicyUnknownChallengeType, Detail: idType + ": " + ct}
			}
		}
	}

	return nil
}

// PolicyConfig translates the operator's YAML into the runtime
// policy.PolicyConfig the ACME REST service constructs its identifier
// policy engine from (pkg/acme/policy). Every identifier type and challenge
// type is enabled here; the ACME handlers additionally intersect a given
// identifier's candidate challenge types with the verifiers the daemon
// actually registered (acme.challenges), so disabling a challenge type
// there is still sufficient to keep it out of an authorization.
func (p ACMEPolicyConfig) PolicyConfig() *policy.PolicyConfig {
	blocklistCfg := policy.BlocklistConfig{}
	if p.Blocklist.UsesDefaults() {
		blocklistCfg = *policy.DefaultBlocklistConfig()
	}
	blocklistCfg.HighRiskBlockedNames = append(blocklistCfg.HighRiskBlockedNames, p.Blocklist.HighRiskDomains...)
	blocklistCfg.ExactBlockedNames = append(blocklistCfg.ExactBlockedNames, p.Blocklist.ExactFQDNs...)
	blocklistCfg.AdminBlockedNames = append(blocklistCfg.AdminBlockedNames, p.Blocklist.AdminDomains...)
	blocklistCfg.AdminBlockedPrefixes = append(blocklistCfg.AdminBlockedPrefixes, p.Blocklist.CIDRs...)

	return &policy.PolicyConfig{
		Blocklist: blocklistCfg,
		EnabledIdentifierTypes: map[string]bool{
			policy.IdentifierTypeDNS:                 true,
			policy.IdentifierTypeIP:                  true,
			policy.IdentifierTypePermanentIdentifier: true,
		},
		EnabledChallengeTypes: map[string]bool{
			policy.ChallengeTypeHTTP01:         true,
			policy.ChallengeTypeDNS01:          true,
			policy.ChallengeTypeTLSALPN01:      true,
			policy.ChallengeTypeDeviceAttest01: true,
			policy.ChallengeTypeEnroll01:       true,
			policy.ChallengeTypeEndorse01:      true,
		},
		RequirePublicSuffix:      p.RequiresPublicSuffix(),
		AllowWildcards:           p.AllowsWildcards(),
		RejectReservedIPs:        p.RejectsReservedIPs(),
		IdentifierChallengeTypes: p.IdentifierChallengeTypes,
	}
}
