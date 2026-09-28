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
	"unicode"
	"unicode/utf8"

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

	// MaxPermanentIdentifierLength bounds a permanent-identifier value. The
	// longest value the server issues for is an endorse-01 identifier, a
	// base64url-encoded PKIX public key: 736 bytes for an RSA-4096 key.
	MaxPermanentIdentifierLength = 1024
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

	// ValidateIP above already parsed ip successfully, so this cannot fail;
	// the error is still checked (never discarded) for defensive
	// correctness against a future refactor of ValidateIP.
	parsedIP, err := netip.ParseAddr(ip)
	if err != nil {
		return ErrIPInvalid
	}

	// Check for reserved/special ranges
	if IsReservedIP(parsedIP) {
		return ErrIPReserved
	}

	return nil
}

// reservedPrefixes are the special-purpose ranges (RFC 6890 and its IANA
// registries) that IsReservedIP treats as reserved in addition to the
// netip classifications it checks directly: loopback, private (RFC 1918 and
// RFC 4193), link-local, multicast and unspecified.
var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network" (RFC 791)
	netip.MustParsePrefix("100.64.0.0/10"),   // shared address space, CGNAT (RFC 6598)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments (RFC 6890)
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1 (RFC 5737)
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking (RFC 2544)
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2 (RFC 5737)
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3 (RFC 5737)
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, and limited broadcast (RFC 1112, RFC 919)
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64 well-known prefix (RFC 6052)
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64 (RFC 8215)
	netip.MustParsePrefix("100::/64"),        // discard-only (RFC 6666)
	netip.MustParsePrefix("2001::/23"),       // IETF protocol assignments, incl. Teredo (RFC 2928)
	netip.MustParsePrefix("2001:db8::/32"),   // documentation (RFC 3849)
	netip.MustParsePrefix("2002::/16"),       // 6to4, which embeds an arbitrary IPv4 address (RFC 3056)
	netip.MustParsePrefix("fec0::/10"),       // deprecated site-local (RFC 3879)
}

// IsReservedIP reports whether ip is in a reserved or special-purpose range:
// loopback, private (RFC 1918, RFC 4193), link-local (which holds the
// 169.254.169.254 cloud metadata address), multicast, unspecified, or one of
// the special-purpose ranges in reservedPrefixes. An IPv4-mapped IPv6
// address is classified by the IPv4 address it carries, so ::ffff:127.0.0.1
// is loopback.
//
// It is the one reserved-address classification in the ACME server: the
// reserved-IP identifier policy (ValidateIPWithReservedCheck) and the
// challenge-validation dialer (pkg/acme/challenges/validation) both use it,
// so an address the policy calls reserved is an address validation will not
// connect to.
func IsReservedIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, prefix := range reservedPrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateNetworkTarget validates host as a bare network target: a
// hostname (RFC 1123 labels, single-label names included) or a canonical IP
// address literal without a zone. It is the check applied to an identifier
// before the ACME server dials it to validate a challenge, so anything that
// could change the meaning of the URL built around it -- a path, query,
// fragment, userinfo, port, or whitespace -- is refused.
func ValidateNetworkTarget(host string) error {
	if host == "" {
		return ErrEmptyIdentifier
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return ErrInvalidNetworkTarget
		}
		if ip.String() != host {
			return ErrInvalidNetworkTarget
		}
		return nil
	}
	if len(host) > MaxDNSIdentifierLength {
		return ErrInvalidNetworkTarget
	}
	for _, label := range strings.Split(strings.ToLower(host), ".") {
		if err := validateLabel(label); err != nil {
			return ErrInvalidNetworkTarget
		}
	}
	return nil
}

// ValidatePermanentIdentifier validates the value of a permanent-identifier
// ACME identifier. The ACME device-attestation draft
// (draft-ietf-acme-device-attest, section "Permanent Identifier") carries the
// value as the identifierValue of an RFC 4043 PermanentIdentifier, a
// UTF8String with no further syntax, so the value is opaque: a device
// serial, a base64url public key (endorse-01), or a host (enroll-01). It
// must be non-empty, valid UTF-8, at most MaxPermanentIdentifierLength
// bytes, and free of whitespace and control characters. Whether the value
// is also usable as a network target is a separate check,
// ValidateNetworkTarget, applied where the server dials it.
func ValidatePermanentIdentifier(value string) error {
	if value == "" {
		return ErrEmptyIdentifier
	}
	if len(value) > MaxPermanentIdentifierLength {
		return ErrPermanentIdentifierTooLong
	}
	if !utf8.ValidString(value) {
		return ErrPermanentIdentifierInvalidCharacter
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return ErrPermanentIdentifierInvalidCharacter
		}
	}
	return nil
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
		return ValidatePermanentIdentifier(value)

	default:
		return NewPolicyError(ErrUnsupportedIdentifierType, identifierType, value, "")
	}
}

// ValidateDomain is a package-level convenience function using default settings.
func ValidateDomain(domain string) error {
	v := NewDomainValidator()
	return v.ValidateDomain(domain)
}
