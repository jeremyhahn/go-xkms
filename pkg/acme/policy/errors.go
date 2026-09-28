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

import "errors"

// Domain validation errors - RFC 1035 compliance
var (
	// ErrEmptyIdentifier is returned when the identifier value is empty.
	ErrEmptyIdentifier = errors.New("policy: identifier value is empty")

	// ErrNameTooLong is returned when the domain name exceeds 253 bytes.
	ErrNameTooLong = errors.New("policy: domain name is longer than 253 bytes")

	// ErrLabelTooLong is returned when a domain label exceeds 63 bytes.
	ErrLabelTooLong = errors.New("policy: domain label is longer than 63 bytes")

	// ErrLabelTooShort is returned when a domain contains consecutive dots.
	ErrLabelTooShort = errors.New("policy: domain name cannot have two dots in a row")

	// ErrTooManyLabels is returned when the domain has more than 10 labels.
	ErrTooManyLabels = errors.New("policy: domain name has more than 10 labels")

	// ErrTooFewLabels is returned when the domain needs at least one dot.
	ErrTooFewLabels = errors.New("policy: domain name needs at least one dot")

	// ErrNameEndsInDot is returned when the domain name ends with a trailing dot.
	ErrNameEndsInDot = errors.New("policy: domain name ends in a dot")

	// ErrInvalidDNSCharacter is returned when the domain contains invalid characters.
	ErrInvalidDNSCharacter = errors.New("policy: domain name contains an invalid character")

	// ErrIPAddressInDNS is returned when a DNS identifier contains an IP address.
	ErrIPAddressInDNS = errors.New("policy: identifier type is DNS but value is an IP address")

	// ErrInvalidRLDH is returned when a domain contains an invalid reserved label.
	ErrInvalidRLDH = errors.New("policy: domain name contains an invalid label in a reserved format")

	// ErrMalformedIDN is returned when a domain contains malformed punycode.
	ErrMalformedIDN = errors.New("policy: domain name contains malformed punycode")

	// ErrNonPublicSuffix is returned when the domain does not end with a valid public suffix.
	ErrNonPublicSuffix = errors.New("policy: domain name does not end with a valid public suffix")

	// ErrICANNTLD is returned when the domain name is an ICANN TLD.
	ErrICANNTLD = errors.New("policy: domain name is an ICANN TLD")

	// ErrLabelStartsWithHyphen is returned when a label starts with a hyphen.
	ErrLabelStartsWithHyphen = errors.New("policy: domain label cannot start with a hyphen")

	// ErrLabelEndsWithHyphen is returned when a label ends with a hyphen.
	ErrLabelEndsWithHyphen = errors.New("policy: domain label cannot end with a hyphen")
)

// Wildcard validation errors
var (
	// ErrTooManyWildcards is returned when the domain contains more than one wildcard.
	ErrTooManyWildcards = errors.New("policy: domain name has more than one wildcard")

	// ErrMalformedWildcard is returned when the wildcard is not in the leftmost label.
	ErrMalformedWildcard = errors.New("policy: wildcard is only permitted before the first dot")

	// ErrICANNTLDWildcard is returned when attempting to issue wildcard for an ICANN TLD.
	ErrICANNTLDWildcard = errors.New("policy: domain name is a wildcard for an ICANN TLD")

	// ErrWildcardNotSupported is returned when wildcards are not expected.
	ErrWildcardNotSupported = errors.New("policy: wildcard domain names are not supported")
)

// IP validation errors - RFC 8738 compliance
var (
	// ErrIPInvalid is returned when the IP address is invalid.
	ErrIPInvalid = errors.New("policy: IP address is invalid")

	// ErrIPReserved is returned when the IP address is in a reserved range.
	ErrIPReserved = errors.New("policy: IP address is in a reserved range")

	// ErrIPHasZone is returned when the IP address contains a zone identifier.
	ErrIPHasZone = errors.New("policy: IP address contains a zone identifier")
)

// Permanent-identifier and network-target errors
var (
	// ErrPermanentIdentifierTooLong is returned when a permanent-identifier
	// value exceeds MaxPermanentIdentifierLength.
	ErrPermanentIdentifierTooLong = errors.New("policy: permanent-identifier is too long")

	// ErrPermanentIdentifierInvalidCharacter is returned when a
	// permanent-identifier value is not valid UTF-8 or contains whitespace
	// or a control character.
	ErrPermanentIdentifierInvalidCharacter = errors.New("policy: permanent-identifier contains an invalid character")

	// ErrInvalidNetworkTarget is returned when a value the server would dial
	// is not a bare hostname or canonical IP address.
	ErrInvalidNetworkTarget = errors.New("policy: identifier is not a bare hostname or IP address")
)

// Blocklist errors
var (
	// ErrPolicyForbidden is returned when an identifier is forbidden by policy.
	ErrPolicyForbidden = errors.New("policy: the ACME server refuses to issue a certificate for this identifier")

	// ErrPolicyNotLoaded is returned when the blocklist policy is not yet loaded.
	ErrPolicyNotLoaded = errors.New("policy: identifier policy not yet loaded")

	// ErrBlocklistFileRead is returned when the blocklist file cannot be read.
	ErrBlocklistFileRead = errors.New("policy: failed to read blocklist file")

	// ErrBlocklistFileParse is returned when the blocklist file cannot be parsed.
	ErrBlocklistFileParse = errors.New("policy: failed to parse blocklist file")

	// ErrMalformedBlocklistEntry is returned when a blocklist entry is malformed.
	ErrMalformedBlocklistEntry = errors.New("policy: malformed blocklist entry")

	// ErrMalformedIPPrefix is returned when an IP prefix is malformed.
	ErrMalformedIPPrefix = errors.New("policy: malformed IP prefix")
)

// Identifier type errors
var (
	// ErrUnsupportedIdentifierType is returned when the identifier type is not supported.
	ErrUnsupportedIdentifierType = errors.New("policy: unsupported identifier type")

	// ErrIdentifierTypeDisabled is returned when the identifier type is disabled.
	ErrIdentifierTypeDisabled = errors.New("policy: identifier type is disabled")
)

// Challenge type errors
var (
	// ErrChallengeTypeDisabled is returned when the challenge type is disabled.
	ErrChallengeTypeDisabled = errors.New("policy: challenge type is disabled")

	// ErrChallengeTypeNotAllowed is returned when the challenge type is not allowed for the identifier.
	ErrChallengeTypeNotAllowed = errors.New("policy: challenge type not allowed for this identifier")

	// ErrUnsupportedChallengeType is returned when the challenge type is not supported.
	ErrUnsupportedChallengeType = errors.New("policy: unsupported challenge type")
)

// PolicyError provides detailed information about a policy violation.
type PolicyError struct {
	// Err is the underlying error type.
	Err error
	// Identifier is the identifier that caused the error.
	Identifier string
	// IdentifierType is the type of the identifier (dns, ip, etc.).
	IdentifierType string
	// Detail provides additional context about the failure.
	Detail string
}

// Error implements the error interface.
func (e *PolicyError) Error() string {
	msg := "policy"
	if e.IdentifierType != "" {
		msg += " [" + e.IdentifierType + "]"
	}
	if e.Identifier != "" {
		msg += " " + e.Identifier
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	if e.Detail != "" {
		msg += " (" + e.Detail + ")"
	}
	return msg
}

// Unwrap returns the underlying error for errors.Is/As support.
func (e *PolicyError) Unwrap() error {
	return e.Err
}

// NewPolicyError creates a new PolicyError.
func NewPolicyError(err error, identifierType, identifier, detail string) *PolicyError {
	return &PolicyError{
		Err:            err,
		IdentifierType: identifierType,
		Identifier:     identifier,
		Detail:         detail,
	}
}

// BlocklistError provides information about blocklist loading failures.
type BlocklistError struct {
	// Err is the underlying error type.
	Err error
	// FilePath is the path to the blocklist file.
	FilePath string
	// Entry is the specific entry that caused the error.
	Entry string
	// Detail provides additional context.
	Detail string
}

// Error implements the error interface.
func (e *BlocklistError) Error() string {
	msg := "policy: blocklist error"
	if e.FilePath != "" {
		msg += " [" + e.FilePath + "]"
	}
	if e.Entry != "" {
		msg += " entry=" + e.Entry
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	if e.Detail != "" {
		msg += " (" + e.Detail + ")"
	}
	return msg
}

// Unwrap returns the underlying error for errors.Is/As support.
func (e *BlocklistError) Unwrap() error {
	return e.Err
}

// NewBlocklistError creates a new BlocklistError.
func NewBlocklistError(err error, filePath, entry, detail string) *BlocklistError {
	return &BlocklistError{
		Err:      err,
		FilePath: filePath,
		Entry:    entry,
		Detail:   detail,
	}
}
