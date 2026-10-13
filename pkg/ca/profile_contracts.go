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

package ca

import (
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// Optional profile contracts. A ProfileProvider may implement any of these to
// take part in issuance decisions the base interface cannot express. They are
// optional so the existing profiles, and every caller-registered profile,
// keep compiling and behaving exactly as before.

// CallerSANProfile is implemented by a profile whose subject alternative names
// — and subject — come only from the issuing caller. CSR signing under such a
// profile never copies the names or subject the requester put in its CSR:
// the requester proves possession of the key and nothing else. The names
// travel on SignOptions.SANS and the subject on SignOptions.Subject.
type CallerSANProfile interface {
	// CallerSuppliedSANs reports whether the names must come from the caller.
	CallerSuppliedSANs() bool
}

// LifetimeBoundedProfile is implemented by a profile whose certificates have a
// lifetime finer than whole days, or a hard maximum. CSR signing uses
// DefaultLifetime when the caller asks for no validity and refuses a request
// longer than MaxLifetime with ErrValidityExceedsProfile.
type LifetimeBoundedProfile interface {
	// DefaultLifetime is the lifetime used when the caller names none.
	DefaultLifetime() time.Duration
	// MaxLifetime is the longest lifetime the profile issues.
	MaxLifetime() time.Duration
}

// TemplateValidator is implemented by a profile that must inspect the
// finished template — names, public key and extra extensions included —
// before it is signed. Issuer.Template calls it last, so no issuance path can
// sign a certificate the profile has not seen in full.
type TemplateValidator interface {
	// ValidateTemplate returns an error describing why template must not be
	// signed under the profile. template.PublicKey carries the key being
	// certified.
	ValidateTemplate(template *x509.Certificate) error
}

// CSRValidator is implemented by a profile that constrains what a requester
// may ask for, not only what the certificate ends up carrying. CSR signing
// calls it on the parsed, signature-checked request before anything is built
// from it, so a request outside the profile is refused rather than reshaped:
// no requested field is ever stripped silently.
type CSRValidator interface {
	// ValidateCSR returns an error describing why csr must not be signed
	// under the profile.
	ValidateCSR(csr *x509.CertificateRequest) error
}

// Errors for caller-supplied names, lifetimes and name constraints. Each is a
// sentinel; refusals wrap it in an errs.Detail naming the offending value, so
// callers match with errors.Is.
var (
	// ErrCallerSANsRequired reports a CSR signed under a CallerSANProfile
	// with no names on SignOptions.SANS.
	ErrCallerSANsRequired = errors.New("ca: profile requires subject alternative names supplied by the issuing caller")

	// ErrTenantSPIFFEWithCallerSANs reports a request that combines the
	// tenant SPIFFE synthesis options with a CallerSANProfile: the profile's
	// names come from the caller alone.
	ErrTenantSPIFFEWithCallerSANs = errors.New("ca: tenant SPIFFE synthesis cannot be combined with a caller-supplied-SAN profile")

	// ErrRawSubjectWithNames reports a SignOptions.RawSubject combined with
	// anything else that names the certificate: Subject, SANS, the tenant
	// SPIFFE options or a caller-supplied-SAN profile. A raw subject is the
	// whole name, so any other source of names would contradict it.
	ErrRawSubjectWithNames = errors.New("ca: a raw subject cannot be combined with another source of certificate names")

	// ErrInvalidRawSubject reports a SignOptions.RawSubject that is not a
	// DER-encoded RDNSequence.
	ErrInvalidRawSubject = errors.New("ca: raw subject is not a DER-encoded distinguished name")

	// ErrInvalidSAN reports a caller-supplied subject alternative name that
	// does not parse, or a name of a type the profile does not permit.
	ErrInvalidSAN = errors.New("ca: invalid subject alternative name")

	// ErrInvalidValidity reports a negative requested lifetime.
	ErrInvalidValidity = errors.New("ca: invalid validity period")

	// ErrValidityExceedsProfile reports a requested lifetime longer than the
	// profile's MaxLifetime.
	ErrValidityExceedsProfile = errors.New("ca: requested validity exceeds the profile maximum")

	// ErrValidityExceedsIssuer reports a subordinate CA that would outlive
	// the certificate issuing it.
	ErrValidityExceedsIssuer = errors.New("ca: requested validity extends past the issuing certificate")

	// ErrUnsupportedProfileKey reports a public key the profile does not
	// certify.
	ErrUnsupportedProfileKey = errors.New("ca: public key is not permitted by the profile")

	// ErrInvalidNameConstraints reports a NameConstraints value that cannot
	// be encoded: a nil or malformed range, an invalid domain, or no
	// permitted subtree on a subordinate CA.
	ErrInvalidNameConstraints = errors.New("ca: invalid name constraints")

	// ErrNameConstraintViolation reports a certificate whose names fall
	// outside the issuing certificate's name constraints. The CA refuses to
	// sign it: the result would fail path validation everywhere.
	ErrNameConstraintViolation = errors.New("ca: certificate names violate the issuer's name constraints")

	// ErrSubjectNotCommonNameOnly reports a subject other than exactly one
	// non-empty common name, under a profile that permits nothing else.
	ErrSubjectNotCommonNameOnly = errors.New("ca: profile requires a subject of a single common name")

	// ErrSubjectAltNameNotPermitted reports subject alternative names, in the
	// request or from the caller, under a profile that permits none.
	ErrSubjectAltNameNotPermitted = errors.New("ca: profile does not permit subject alternative names")

	// ErrCARequestNotPermitted reports a CSR whose basic constraints request
	// a CA certificate under an end-entity profile.
	ErrCARequestNotPermitted = errors.New("ca: profile does not permit a request for a CA certificate")

	// ErrKeyUsageNotPermitted reports a CSR requesting a key usage other
	// than the profile's.
	ErrKeyUsageNotPermitted = errors.New("ca: requested key usage is not permitted by the profile")

	// ErrExtKeyUsageNotPermitted reports a CSR requesting an extended key
	// usage other than the profile's.
	ErrExtKeyUsageNotPermitted = errors.New("ca: requested extended key usage is not permitted by the profile")

	// ErrBoundKeyNotFound reports a SignOptions.BoundKey the CA's keystore
	// holds no key for.
	ErrBoundKeyNotFound = errors.New("ca: bound key not found in the keystore")

	// ErrBoundKeyMismatch reports a CSR whose public key is not the public
	// key of SignOptions.BoundKey.
	ErrBoundKeyMismatch = errors.New("ca: CSR public key does not match the bound key")
)

// isCallerSANProfile reports whether profile takes its names only from the
// caller.
func isCallerSANProfile(profile ProfileProvider) bool {
	p, ok := profile.(CallerSANProfile)
	return ok && p.CallerSuppliedSANs()
}

// callerNames are caller-supplied subject alternative names, parsed strictly.
type callerNames struct {
	dns    []string
	emails []string
	ips    []net.IP
	uris   []*url.URL
}

// empty reports whether no name of any type was supplied.
func (n *callerNames) empty() bool {
	return len(n.dns) == 0 && len(n.emails) == 0 && len(n.ips) == 0 && len(n.uris) == 0
}

// parseCallerSANs parses the caller's names strictly. Unlike
// SubjectAlternativeNames.ParseIPs and ParseURIs, which skip what does not
// parse, a name the caller meant to certify and that cannot be encoded is an
// error: silently dropping it would issue a certificate for fewer names than
// were asked for.
func parseCallerSANs(sans *SubjectAlternativeNames) (*callerNames, error) {
	names := &callerNames{}
	if sans == nil {
		return names, nil
	}
	names.dns = append(names.dns, sans.DNS...)
	names.emails = append(names.emails, sans.Email...)
	for _, s := range sans.IPs {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, &errs.Detail{Err: ErrInvalidSAN, Detail: "ip address " + s}
		}
		names.ips = append(names.ips, ip)
	}
	for _, s := range sans.URIs {
		u, err := url.Parse(s)
		if err != nil || u.Scheme == "" {
			return nil, &errs.Detail{Err: ErrInvalidSAN, Detail: "uri " + s}
		}
		names.uris = append(names.uris, u)
	}
	return names, nil
}

// resolveLifetime decides a CSR-signed certificate's lifetime.
//
// A non-zero requested duration wins, then a non-zero day count, then the
// profile's DefaultLifetime when it is lifetime-bounded; zero means "use the
// day-based default" and is returned as such. A lifetime-bounded profile
// refuses anything above its MaxLifetime.
func resolveLifetime(profile ProfileProvider, requested time.Duration, requestedDays int) (time.Duration, error) {
	if requested < 0 || requestedDays < 0 {
		return 0, &errs.Detail{Err: ErrInvalidValidity, Detail: "validity must not be negative"}
	}
	lifetime := requested
	if lifetime == 0 && requestedDays > 0 {
		lifetime = time.Duration(requestedDays) * 24 * time.Hour
	}
	bounded, ok := profile.(LifetimeBoundedProfile)
	if !ok {
		return lifetime, nil
	}
	if lifetime == 0 {
		lifetime = bounded.DefaultLifetime()
	}
	if lifetime > bounded.MaxLifetime() {
		return 0, &errs.Detail{
			Err:    ErrValidityExceedsProfile,
			Detail: "profile " + profile.Name() + " issues at most " + bounded.MaxLifetime().String() + ", requested " + lifetime.String(),
		}
	}
	return lifetime, nil
}
