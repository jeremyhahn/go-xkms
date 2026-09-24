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
	"slices"
	"strings"
	"sync"
)

// ChallengePolicy enforces which challenge types are allowed for each identifier type.
type ChallengePolicy struct {
	// enabledChallenges maps challenge type to enabled status.
	enabledChallenges map[string]bool

	// enabledIdentifiers maps identifier type to enabled status.
	enabledIdentifiers map[string]bool

	// enableDNSAccount01 controls whether dns-account-01 is enabled.
	enableDNSAccount01 bool

	// identifierOverrides replaces the built-in candidate challenge types for
	// an identifier type when set (see PolicyConfig.IdentifierChallengeTypes).
	// A nil or absent entry keeps the built-in default for that identifier
	// type. Never consulted for wildcard DNS identifiers.
	identifierOverrides map[string][]string

	// mu protects the enabled maps.
	mu sync.RWMutex
}

// NewChallengePolicy creates a new ChallengePolicy with default settings.
func NewChallengePolicy() *ChallengePolicy {
	return &ChallengePolicy{
		enabledChallenges: map[string]bool{
			ChallengeTypeHTTP01:         true,
			ChallengeTypeDNS01:          true,
			ChallengeTypeTLSALPN01:      true,
			ChallengeTypeDeviceAttest01: true,
			ChallengeTypeEnroll01:       true,
			ChallengeTypeEndorse01:      true,
		},
		enabledIdentifiers: map[string]bool{
			IdentifierTypeDNS:                 true,
			IdentifierTypeIP:                  true,
			IdentifierTypePermanentIdentifier: true,
		},
		enableDNSAccount01: false,
	}
}

// NewChallengePolicyFromConfig creates a ChallengePolicy from a PolicyConfig.
func NewChallengePolicyFromConfig(config *PolicyConfig) *ChallengePolicy {
	if config == nil {
		return NewChallengePolicy()
	}

	cp := &ChallengePolicy{
		enabledChallenges:  make(map[string]bool),
		enabledIdentifiers: make(map[string]bool),
	}

	// Copy enabled challenges
	for k, v := range config.EnabledChallengeTypes {
		cp.enabledChallenges[k] = v
	}

	// Copy enabled identifiers
	for k, v := range config.EnabledIdentifierTypes {
		cp.enabledIdentifiers[k] = v
	}

	// Check for dns-account-01
	cp.enableDNSAccount01 = config.EnabledChallengeTypes[ChallengeTypeDNSAccount01]

	// Copy per-identifier-type candidate overrides
	if len(config.IdentifierChallengeTypes) > 0 {
		cp.identifierOverrides = make(map[string][]string, len(config.IdentifierChallengeTypes))
		for k, v := range config.IdentifierChallengeTypes {
			cp.identifierOverrides[k] = append([]string(nil), v...)
		}
	}

	return cp
}

// AllowedChallenges returns the challenge types that are allowed for a given identifier.
// The returned list respects both identifier-type restrictions and enabled challenge settings.
//
// Challenge type restrictions per identifier type:
//   - DNS identifiers: http-01, dns-01, tls-alpn-01, device-attest-01, dns-account-01 (if enabled)
//   - DNS wildcard identifiers: dns-01, dns-account-01 only (per CA/Browser Forum BRs)
//   - IP identifiers: http-01, tls-alpn-01 only (per RFC 8738)
//   - Permanent identifiers: device-attest-01, enroll-01, endorse-01
func (cp *ChallengePolicy) AllowedChallenges(identifierType, value string) []string {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	var candidates []string

	switch identifierType {
	case IdentifierTypeDNS:
		// Check if this is a wildcard. Per RFC 8555 Section 7.1.4 and the
		// CA/Browser Forum Baseline Requirements, a wildcard MUST only use
		// dns-01; this is never subject to identifierOverrides.
		if strings.HasPrefix(value, "*.") {
			candidates = []string{ChallengeTypeDNS01}
			if cp.enableDNSAccount01 {
				candidates = append(candidates, ChallengeTypeDNSAccount01)
			}
		} else if override, ok := cp.identifierOverrides[IdentifierTypeDNS]; ok {
			candidates = append([]string(nil), override...)
		} else {
			// Non-wildcard DNS identifiers can use all standard web PKI challenges
			candidates = []string{
				ChallengeTypeHTTP01,
				ChallengeTypeDNS01,
				ChallengeTypeTLSALPN01,
			}
			if cp.enableDNSAccount01 {
				candidates = append(candidates, ChallengeTypeDNSAccount01)
			}
			// Device attestation is also valid for DNS
			candidates = append(candidates, ChallengeTypeDeviceAttest01)
		}

	case IdentifierTypeIP:
		if override, ok := cp.identifierOverrides[IdentifierTypeIP]; ok {
			candidates = append([]string(nil), override...)
		} else {
			// IP identifiers only support HTTP-01 and TLS-ALPN-01 per RFC 8738
			candidates = []string{
				ChallengeTypeHTTP01,
				ChallengeTypeTLSALPN01,
			}
		}

	case IdentifierTypePermanentIdentifier:
		if override, ok := cp.identifierOverrides[IdentifierTypePermanentIdentifier]; ok {
			candidates = append([]string(nil), override...)
		} else {
			// Permanent identifiers use device/TPM-specific challenges
			candidates = []string{
				ChallengeTypeDeviceAttest01,
				ChallengeTypeEnroll01,
				ChallengeTypeEndorse01,
			}
		}

	default:
		// Unknown identifier type - no challenges allowed
		return nil
	}

	// Filter by enabled challenges
	var allowed []string
	for _, c := range candidates {
		if cp.enabledChallenges[c] {
			allowed = append(allowed, c)
		}
	}

	return allowed
}

// IsChallengeTypeEnabled returns whether a challenge type is globally enabled.
func (cp *ChallengePolicy) IsChallengeTypeEnabled(challengeType string) bool {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return cp.enabledChallenges[challengeType]
}

// IsIdentifierTypeEnabled returns whether an identifier type is enabled.
func (cp *ChallengePolicy) IsIdentifierTypeEnabled(identifierType string) bool {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return cp.enabledIdentifiers[identifierType]
}

// SetChallengeEnabled enables or disables a challenge type.
func (cp *ChallengePolicy) SetChallengeEnabled(challengeType string, enabled bool) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.enabledChallenges[challengeType] = enabled
	if challengeType == ChallengeTypeDNSAccount01 {
		cp.enableDNSAccount01 = enabled
	}
}

// SetIdentifierEnabled enables or disables an identifier type.
func (cp *ChallengePolicy) SetIdentifierEnabled(identifierType string, enabled bool) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.enabledIdentifiers[identifierType] = enabled
}

// IsChallengeAllowedForIdentifier checks if a specific challenge type is allowed
// for a specific identifier type and value.
func (cp *ChallengePolicy) IsChallengeAllowedForIdentifier(challengeType, identifierType, value string) bool {
	allowed := cp.AllowedChallenges(identifierType, value)
	return slices.Contains(allowed, challengeType)
}

// ValidateChallengeForIdentifier validates that a challenge type is appropriate
// for the given identifier.
func (cp *ChallengePolicy) ValidateChallengeForIdentifier(challengeType, identifierType, value string) error {
	// Check if identifier type is enabled
	if !cp.IsIdentifierTypeEnabled(identifierType) {
		return NewPolicyError(ErrIdentifierTypeDisabled, identifierType, value, "")
	}

	// Check if challenge type is enabled
	if !cp.IsChallengeTypeEnabled(challengeType) {
		return NewPolicyError(ErrChallengeTypeDisabled, identifierType, value, challengeType)
	}

	// Check if challenge is allowed for this identifier
	if !cp.IsChallengeAllowedForIdentifier(challengeType, identifierType, value) {
		return NewPolicyError(ErrChallengeTypeNotAllowed, identifierType, value, challengeType)
	}

	return nil
}

// Clone creates a deep copy of the ChallengePolicy.
func (cp *ChallengePolicy) Clone() *ChallengePolicy {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	clone := &ChallengePolicy{
		enabledChallenges:  make(map[string]bool),
		enabledIdentifiers: make(map[string]bool),
		enableDNSAccount01: cp.enableDNSAccount01,
	}

	for k, v := range cp.enabledChallenges {
		clone.enabledChallenges[k] = v
	}
	for k, v := range cp.enabledIdentifiers {
		clone.enabledIdentifiers[k] = v
	}
	if cp.identifierOverrides != nil {
		clone.identifierOverrides = make(map[string][]string, len(cp.identifierOverrides))
		for k, v := range cp.identifierOverrides {
			clone.identifierOverrides[k] = append([]string(nil), v...)
		}
	}

	return clone
}

// AllChallengeTypes returns all known challenge types.
func AllChallengeTypes() []string {
	return []string{
		ChallengeTypeHTTP01,
		ChallengeTypeDNS01,
		ChallengeTypeTLSALPN01,
		ChallengeTypeDeviceAttest01,
		ChallengeTypeEnroll01,
		ChallengeTypeEndorse01,
		ChallengeTypeDNSAccount01,
	}
}

// AllIdentifierTypes returns all known identifier types.
func AllIdentifierTypes() []string {
	return []string{
		IdentifierTypeDNS,
		IdentifierTypeIP,
		IdentifierTypePermanentIdentifier,
	}
}

// StandardWebPKIChallenges returns challenge types suitable for standard web PKI.
func StandardWebPKIChallenges() []string {
	return []string{
		ChallengeTypeHTTP01,
		ChallengeTypeDNS01,
		ChallengeTypeTLSALPN01,
	}
}

// DeviceAttestationChallenges returns challenge types for device/TPM attestation.
func DeviceAttestationChallenges() []string {
	return []string{
		ChallengeTypeDeviceAttest01,
		ChallengeTypeEnroll01,
		ChallengeTypeEndorse01,
	}
}
