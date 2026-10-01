// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package spiffe

import (
	"errors"
	"net/url"
	"strings"
)

// The general SPIFFE ID grammar, from the SPIFFE-ID specification
// (https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md):
//
//	spiffe://<trust-domain>[/<segment>]*
//
// The tenant-scoped ID above is one shape of it. TrustDomain and WorkloadID
// accept every shape the specification allows and nothing else, so a caller
// that builds an X.509-SVID for an arbitrary workload path validates it here
// rather than against a hand-written check.
const (
	// maxIDLength is the specification's limit on a SPIFFE ID's length in
	// bytes (SPIFFE-ID §2.3).
	maxIDLength = 2048

	// maxTrustDomainLength is the specification's limit on the trust-domain
	// component (SPIFFE-ID §2.1), the DNS host-name limit.
	maxTrustDomainLength = 255

	// schemePrefix is the literal every SPIFFE ID begins with.
	schemePrefix = scheme + "://"
)

// Sentinel errors for the general SPIFFE ID grammar. InvalidIDError wraps one
// of them, so callers match with errors.Is.
var (
	// ErrTrustDomainCharacters reports a trust domain holding a character
	// outside [a-z0-9._-].
	ErrTrustDomainCharacters = errors.New("spiffe: trust domain may hold only lowercase letters, digits, '.', '-' and '_'")

	// ErrTrustDomainTooLong reports a trust domain longer than 255 bytes.
	ErrTrustDomainTooLong = errors.New("spiffe: trust domain exceeds 255 bytes")

	// ErrSchemeInvalid reports an ID that does not start with spiffe://.
	ErrSchemeInvalid = errors.New("spiffe: id must use the spiffe scheme")

	// ErrSegmentEmpty reports an empty path segment ("//" or a trailing "/").
	ErrSegmentEmpty = errors.New("spiffe: path segments must not be empty")

	// ErrSegmentDotted reports a "." or ".." path segment.
	ErrSegmentDotted = errors.New("spiffe: path segments must not be '.' or '..'")

	// ErrSegmentCharacters reports a path segment holding a character outside
	// [A-Za-z0-9._-].
	ErrSegmentCharacters = errors.New("spiffe: path segments may hold only letters, digits, '.', '-' and '_'")

	// ErrIDTooLong reports an ID longer than 2048 bytes.
	ErrIDTooLong = errors.New("spiffe: id exceeds 2048 bytes")

	// ErrIDComponents reports an ID carrying a component the specification
	// forbids: user info, a port, a query or a fragment.
	ErrIDComponents = errors.New("spiffe: id must not carry user info, port, query or fragment")

	// ErrPathPrefixInvalid reports a path prefix that is not "/" followed by
	// valid segments.
	ErrPathPrefixInvalid = errors.New("spiffe: path prefix must be '/' or a valid segment path")
)

// InvalidIDError reports input that does not satisfy the SPIFFE ID grammar.
// Err is one of this package's sentinels; Input is the offending value.
type InvalidIDError struct {
	// Input is the value that failed validation.
	Input string
	// Err is the sentinel naming the rule it broke.
	Err error
}

// Error implements error.
func (e *InvalidIDError) Error() string {
	return e.Err.Error() + ": " + e.Input
}

// Unwrap returns the sentinel, so errors.Is matches it.
func (e *InvalidIDError) Unwrap() error { return e.Err }

// TrustDomain is a validated SPIFFE trust-domain name. The zero value is not a
// valid trust domain; obtain one from ParseTrustDomain.
type TrustDomain struct {
	name string
}

// ParseTrustDomain validates name as a SPIFFE trust domain. It accepts the
// bare name ("example.org"), not a spiffe:// URI.
func ParseTrustDomain(name string) (TrustDomain, error) {
	if err := validateTrustDomain(name); err != nil {
		return TrustDomain{}, err
	}
	return TrustDomain{name: name}, nil
}

// Name returns the trust-domain name.
func (td TrustDomain) Name() string { return td.name }

// IsZero reports whether td is the unset zero value.
func (td TrustDomain) IsZero() bool { return td.name == "" }

// String returns the trust domain's own SPIFFE ID, spiffe://<name>.
func (td TrustDomain) String() string { return schemePrefix + td.name }

// ID builds the workload ID spiffe://<td>/<segments...>. Each segment is
// validated on its own, so a segment carrying "/" is refused rather than
// silently becoming two. With no segments the result is the trust domain's ID.
func (td TrustDomain) ID(segments ...string) (WorkloadID, error) {
	if td.IsZero() {
		return WorkloadID{}, ErrTrustDomainEmpty
	}
	for _, segment := range segments {
		if err := validateSegment(segment); err != nil {
			return WorkloadID{}, err
		}
	}
	path := ""
	if len(segments) > 0 {
		path = "/" + strings.Join(segments, "/")
	}
	return newWorkloadID(td, path)
}

// IDFromPath builds the workload ID spiffe://<td><path>. path is empty or
// begins with "/" and is validated segment by segment.
func (td TrustDomain) IDFromPath(path string) (WorkloadID, error) {
	if td.IsZero() {
		return WorkloadID{}, ErrTrustDomainEmpty
	}
	if err := ValidatePath(path); err != nil {
		return WorkloadID{}, err
	}
	return newWorkloadID(td, path)
}

// WorkloadID is a validated SPIFFE ID: a trust domain plus a path that may be
// empty. The zero value is not a valid ID.
type WorkloadID struct {
	td   TrustDomain
	path string
}

// newWorkloadID enforces the whole-ID length limit on an already validated
// trust domain and path.
func newWorkloadID(td TrustDomain, path string) (WorkloadID, error) {
	id := WorkloadID{td: td, path: path}
	if s := id.String(); len(s) > maxIDLength {
		return WorkloadID{}, &InvalidIDError{Input: s[:64] + "...", Err: ErrIDTooLong}
	}
	return id, nil
}

// ParseWorkloadID parses and validates a SPIFFE ID in its string form.
func ParseWorkloadID(s string) (WorkloadID, error) {
	if len(s) > maxIDLength {
		return WorkloadID{}, &InvalidIDError{Input: s[:64] + "...", Err: ErrIDTooLong}
	}
	rest, ok := strings.CutPrefix(s, schemePrefix)
	if !ok {
		return WorkloadID{}, &InvalidIDError{Input: s, Err: ErrSchemeInvalid}
	}
	if strings.ContainsAny(rest, "?#@") {
		return WorkloadID{}, &InvalidIDError{Input: s, Err: ErrIDComponents}
	}
	name, path, _ := strings.Cut(rest, "/")
	if path != "" || strings.HasSuffix(rest, "/") {
		path = "/" + path
	}
	td, err := ParseTrustDomain(name)
	if err != nil {
		return WorkloadID{}, err
	}
	return td.IDFromPath(path)
}

// WorkloadIDFromURL validates u as a SPIFFE ID. A certificate's URI SAN
// arrives as a *url.URL; this is the check an X.509-SVID verifier runs on it.
func WorkloadIDFromURL(u *url.URL) (WorkloadID, error) {
	if u == nil {
		return WorkloadID{}, &InvalidIDError{Err: ErrSchemeInvalid}
	}
	if u.Opaque != "" || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return WorkloadID{}, &InvalidIDError{Input: u.String(), Err: ErrIDComponents}
	}
	return ParseWorkloadID(u.String())
}

// TrustDomain returns the ID's trust domain.
func (id WorkloadID) TrustDomain() TrustDomain { return id.td }

// Path returns the ID's path: empty, or "/" followed by its segments.
func (id WorkloadID) Path() string { return id.path }

// IsZero reports whether id is the unset zero value.
func (id WorkloadID) IsZero() bool { return id.td.IsZero() }

// String returns the canonical string form, spiffe://<td><path>.
func (id WorkloadID) String() string {
	if id.IsZero() {
		return ""
	}
	return id.td.String() + id.path
}

// URL returns the ID as a *url.URL, ready for a certificate template's URIs.
func (id WorkloadID) URL() *url.URL {
	return &url.URL{Scheme: scheme, Host: id.td.name, Path: id.path}
}

// MemberOf reports whether id belongs to td.
func (id WorkloadID) MemberOf(td TrustDomain) bool {
	return !id.IsZero() && id.td == td
}

// HasPathPrefix reports whether id's path lies under prefix, matching whole
// segments: "/tenant/a" is under "/tenant" but "/tenantx" is not. The prefix
// "/" admits every path, including the empty one. An invalid prefix admits
// nothing; use ValidatePathPrefix to tell that case apart.
func (id WorkloadID) HasPathPrefix(prefix string) bool {
	if id.IsZero() || ValidatePathPrefix(prefix) != nil {
		return false
	}
	if prefix == "/" {
		return true
	}
	return id.path == prefix || strings.HasPrefix(id.path, prefix+"/")
}

// ValidatePath validates a SPIFFE ID path: empty, or one or more "/segment"
// groups where every segment is non-empty, is not "." or "..", and holds only
// [A-Za-z0-9._-].
func ValidatePath(path string) error {
	if path == "" {
		return nil
	}
	if !strings.HasPrefix(path, "/") {
		return &InvalidIDError{Input: path, Err: ErrSegmentEmpty}
	}
	for _, segment := range strings.Split(path[1:], "/") {
		if err := validateSegment(segment); err != nil {
			return err
		}
	}
	return nil
}

// ValidatePathPrefix validates a path prefix used to scope issuance or
// verification: "/" (everything), or a valid non-empty path.
func ValidatePathPrefix(prefix string) error {
	if prefix == "/" {
		return nil
	}
	if prefix == "" {
		return &InvalidIDError{Input: prefix, Err: ErrPathPrefixInvalid}
	}
	if err := ValidatePath(prefix); err != nil {
		return &InvalidIDError{Input: prefix, Err: ErrPathPrefixInvalid}
	}
	return nil
}

// validateTrustDomain applies SPIFFE-ID §2.1.
func validateTrustDomain(name string) error {
	if name == "" {
		return ErrTrustDomainEmpty
	}
	if len(name) > maxTrustDomainLength {
		return &InvalidIDError{Input: name[:64] + "...", Err: ErrTrustDomainTooLong}
	}
	for i := 0; i < len(name); i++ {
		if !isTrustDomainChar(name[i]) {
			return &InvalidIDError{Input: name, Err: ErrTrustDomainCharacters}
		}
	}
	return nil
}

// validateSegment applies SPIFFE-ID §2.2 to one path segment.
func validateSegment(segment string) error {
	switch segment {
	case "":
		return &InvalidIDError{Input: segment, Err: ErrSegmentEmpty}
	case ".", "..":
		return &InvalidIDError{Input: segment, Err: ErrSegmentDotted}
	}
	for i := 0; i < len(segment); i++ {
		if !isSegmentChar(segment[i]) {
			return &InvalidIDError{Input: segment, Err: ErrSegmentCharacters}
		}
	}
	return nil
}

// isTrustDomainChar reports whether c may appear in a trust domain.
func isTrustDomainChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_'
}

// isSegmentChar reports whether c may appear in a path segment.
func isSegmentChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_'
}
