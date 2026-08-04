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
	"net/netip"
	"regexp"
	"strings"

	"github.com/weppos/publicsuffix-go/publicsuffix"
	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"
)

// Domain validation constants per RFC 1035
const (
	// MaxLabels is the maximum number of labels (parts) in a domain name.
	MaxLabels = 10

	// MaxLabelLength is the maximum length of a single label in a domain name.
	MaxLabelLength = 63

	// MaxDNSIdentifierLength is the maximum length of a complete domain name.
	// RFC 1034 specifies 255 octets total, minus 2 for length byte and root.
	MaxDNSIdentifierLength = 253
)

// Identifier type constants
const (
	IdentifierTypeDNS                 = "dns"
	IdentifierTypeIP                  = "ip"
	IdentifierTypePermanentIdentifier = "permanent-identifier"
)

// Challenge type constants
const (
	ChallengeTypeHTTP01         = "http-01"
	ChallengeTypeDNS01          = "dns-01"
	ChallengeTypeTLSALPN01      = "tls-alpn-01"
	ChallengeTypeDeviceAttest01 = "device-attest-01"
	ChallengeTypeEnroll01       = "enroll-01"
	ChallengeTypeEndorse01      = "endorse-01"
	ChallengeTypeDNSAccount01   = "dns-account-01"
)

// dnsLabelCharacterRegexp matches valid DNS label characters (lowercase letters, digits, hyphens).
var dnsLabelCharacterRegexp = regexp.MustCompile("^[a-z0-9-]+$")

// DomainValidator validates domain names according to RFC 1035 and ACME requirements.
type DomainValidator struct {
	// RequirePublicSuffix requires domains to end with a valid public suffix.
	RequirePublicSuffix bool

	// AllowWildcards allows wildcard domain names.
	AllowWildcards bool
}

// NewDomainValidator creates a new DomainValidator with default settings.
func NewDomainValidator() *DomainValidator {
	return &DomainValidator{
		RequirePublicSuffix: true,
		AllowWildcards:      true,
	}
}

// isDNSCharacter checks if a byte is a valid DNS character.
func isDNSCharacter(ch byte) bool {
	return ('a' <= ch && ch <= 'z') ||
		('A' <= ch && ch <= 'Z') ||
		('0' <= ch && ch <= '9') ||
		ch == '.' || ch == '-'
}

// ValidateDomain validates a domain name according to RFC 1035.
// It checks:
//   - Non-empty
//   - Valid DNS characters only
//   - Length constraints (total and per-label)
//   - Not an IP address
//   - Proper label structure
//   - Valid IDN/punycode if applicable
//   - Valid public suffix (if RequirePublicSuffix is true)
func (v *DomainValidator) ValidateDomain(domain string) error {
	if domain == "" {
		return ErrEmptyIdentifier
	}

	// Check for wildcards
	if strings.Count(domain, "*") > 0 {
		return v.validateWildcardDomain(domain)
	}

	return v.validateNonWildcardDomain(domain)
}

// validateNonWildcardDomain validates a domain that should not contain wildcards.
func (v *DomainValidator) validateNonWildcardDomain(domain string) error {
	if domain == "" {
		return ErrEmptyIdentifier
	}

	// Wildcards not expected in this path
	if strings.HasPrefix(domain, "*.") {
		return ErrWildcardNotSupported
	}

	// Check for invalid characters
	for _, ch := range []byte(domain) {
		if !isDNSCharacter(ch) {
			return ErrInvalidDNSCharacter
		}
	}

	// Check total length
	if len(domain) > MaxDNSIdentifierLength {
		return ErrNameTooLong
	}

	// Check if it's an IP address
	_, err := netip.ParseAddr(domain)
	if err == nil {
		return ErrIPAddressInDNS
	}

	// Check for trailing dot
	if strings.HasSuffix(domain, ".") {
		return ErrNameEndsInDot
	}

	// Split into labels
	labels := strings.Split(domain, ".")
	if len(labels) > MaxLabels {
		return ErrTooManyLabels
	}
	if len(labels) < 2 {
		return ErrTooFewLabels
	}

	// Validate each label
	for _, label := range labels {
		if err := validateLabel(label); err != nil {
			return err
		}
	}

	// Check public suffix if required
	if v.RequirePublicSuffix {
		return v.validatePublicSuffix(domain)
	}

	return nil
}

// validateLabel validates a single DNS label according to RFC 5890/5891.
func validateLabel(label string) error {
	// Check for empty label (consecutive dots)
	if len(label) < 1 {
		return ErrLabelTooShort
	}

	// Check label length
	if len(label) > MaxLabelLength {
		return ErrLabelTooLong
	}

	// Check that label contains only valid LDH characters
	if !dnsLabelCharacterRegexp.MatchString(label) {
		return ErrInvalidDNSCharacter
	}

	// Labels cannot start or end with hyphen
	if label[0] == '-' {
		return ErrLabelStartsWithHyphen
	}
	if label[len(label)-1] == '-' {
		return ErrLabelEndsWithHyphen
	}

	// Check for Reserved LDH Labels (R-LDH): "--" in positions 3-4
	if len(label) >= 4 && label[2:4] == "--" {
		// Only xn-- (punycode) is allowed among R-LDH labels
		if label[0:2] != "xn" {
			return ErrInvalidRLDH
		}

		// Validate punycode decoding
		ulabel, err := idna.ToUnicode(label)
		if err != nil {
			return ErrMalformedIDN
		}
		// Check NFC normalization
		if !norm.NFC.IsNormalString(ulabel) {
			return ErrMalformedIDN
		}
	}

	return nil
}

// validatePublicSuffix checks that a domain ends with a valid public suffix.
func (v *DomainValidator) validatePublicSuffix(domain string) error {
	// Use publicsuffix library to extract the suffix
	parsed, err := publicsuffix.Parse(domain)
	if err != nil {
		return ErrNonPublicSuffix
	}

	// The domain must not BE a public suffix (must have labels beyond the suffix)
	if parsed.SLD == "" {
		return ErrICANNTLD
	}

	return nil
}

// validateWildcardDomain validates a wildcard domain name.
func (v *DomainValidator) validateWildcardDomain(domain string) error {
	if !v.AllowWildcards {
		return ErrWildcardNotSupported
	}

	// More than one wildcard is invalid
	if strings.Count(domain, "*") > 1 {
		return ErrTooManyWildcards
	}

	// Wildcard must be leftmost label
	if !strings.HasPrefix(domain, "*.") {
		return ErrMalformedWildcard
	}

	// Extract base domain (without *.)
	baseDomain := strings.TrimPrefix(domain, "*.")

	// Validate the base domain
	if err := v.validateNonWildcardDomain(baseDomain); err != nil {
		return err
	}

	// Check that wildcard is not immediately adjacent to TLD
	if v.RequirePublicSuffix {
		parsed, err := publicsuffix.Parse(baseDomain)
		if err != nil {
			return ErrNonPublicSuffix
		}
		// baseDomain must not BE just a public suffix (no *.com allowed)
		if parsed.SLD == "" {
			return ErrICANNTLDWildcard
		}
	}

	return nil
}

// ValidateIP validates an IP address according to RFC 8738.
// It checks:
//   - Non-empty
//   - Valid IPv4 or IPv6 address
//   - No zone identifier
//   - Not in a reserved range (if checkReserved is true)
func ValidateIP(ip string) error {
	if ip == "" {
		return ErrEmptyIdentifier
	}

	// Parse the IP address
	parsedIP, err := netip.ParseAddr(ip)
	if err != nil {
		return ErrIPInvalid
	}

	// RFC 8738 requires canonical form. Check by comparing String() output.
	// ParseAddr accepts non-canonical forms, so we need to verify.
	if parsedIP.WithZone("").String() != ip {
		return ErrIPInvalid
	}

	return nil
}

// ValidateIPWithReservedCheck validates an IP address and checks for reserved ranges.
func ValidateIPWithReservedCheck(ip string) error {
	if err := ValidateIP(ip); err != nil {
		return err
	}

	parsedIP, _ := netip.ParseAddr(ip)

	// Check for reserved/special ranges
	if isReservedIP(parsedIP) {
		return ErrIPReserved
	}

	return nil
}

// isReservedIP checks if an IP address is in a reserved/special-purpose range.
func isReservedIP(ip netip.Addr) bool {
	// Check various reserved ranges
	if ip.IsLoopback() {
		return true
	}
	if ip.IsMulticast() {
		return true
	}
	if ip.IsPrivate() {
		return true
	}
	if ip.IsLinkLocalUnicast() {
		return true
	}
	if ip.IsLinkLocalMulticast() {
		return true
	}
	if ip.IsUnspecified() {
		return true
	}

	// IPv4 specific checks
	if ip.Is4() {
		// Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
		docRanges := []netip.Prefix{
			netip.MustParsePrefix("192.0.2.0/24"),
			netip.MustParsePrefix("198.51.100.0/24"),
			netip.MustParsePrefix("203.0.113.0/24"),
		}
		for _, r := range docRanges {
			if r.Contains(ip) {
				return true
			}
		}
	}

	// IPv6 specific checks
	if ip.Is6() {
		// Documentation range (2001:db8::/32)
		if netip.MustParsePrefix("2001:db8::/32").Contains(ip) {
			return true
		}
	}

	return false
}

// ValidateIdentifier validates an identifier based on its type.
func ValidateIdentifier(identifierType, value string) error {
	switch identifierType {
	case IdentifierTypeDNS:
		v := NewDomainValidator()
		return v.ValidateDomain(value)

	case IdentifierTypeIP:
		return ValidateIP(value)

	case IdentifierTypePermanentIdentifier:
		// Permanent identifiers have minimal validation requirements
		if value == "" {
			return ErrEmptyIdentifier
		}
		return nil

	default:
		return NewPolicyError(ErrUnsupportedIdentifierType, identifierType, value, "")
	}
}

// ValidateDomain is a package-level convenience function using default settings.
func ValidateDomain(domain string) error {
	v := NewDomainValidator()
	return v.ValidateDomain(domain)
}
