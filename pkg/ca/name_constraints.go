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
	"net"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// NameConstraints is the RFC 5280 §4.2.1.10 name constraints extension of a
// CA certificate: the subtrees every name in a certificate below it must fall
// inside (Permitted*) and must stay out of (Excluded*).
//
// A domain constraint "example.com" admits example.com and every name below
// it; ".example.com" admits only the names below it. These are the semantics
// crypto/x509 enforces during path validation.
//
// URI constraints bind the URI's host only (RFC 5280 §4.2.1.10: "the
// constraint MUST be specified as a fully qualified domain name and MAY
// specify a host or a domain"). For a SPIFFE ID the host is the trust domain,
// so a URI constraint confines a subordinate to one trust domain, which is one
// tenant (spiffe://<tenantID>/<kind>/<name>), and cannot confine it to a path
// such as /svc/. Path scoping is the
// issuing caller's policy, enforced before it asks for a certificate (see
// spiffe.WorkloadID.HasPathPrefix).
type NameConstraints struct {
	// Critical marks the extension critical. RFC 5280 §4.2.1.10 requires
	// conforming CAs to mark it critical; it is a field so a deployment that
	// must interoperate with a relying party that rejects critical name
	// constraints can say so explicitly.
	Critical bool

	// PermittedIPRanges and ExcludedIPRanges are IPv4 or IPv6 networks.
	PermittedIPRanges []*net.IPNet
	ExcludedIPRanges  []*net.IPNet

	// PermittedDNSDomains and ExcludedDNSDomains constrain dNSName SANs.
	PermittedDNSDomains []string
	ExcludedDNSDomains  []string

	// PermittedURIDomains and ExcludedURIDomains constrain the host of
	// uniformResourceIdentifier SANs.
	PermittedURIDomains []string
	ExcludedURIDomains  []string
}

// hasPermittedSubtree reports whether at least one permitted subtree is set.
func (nc *NameConstraints) hasPermittedSubtree() bool {
	return len(nc.PermittedIPRanges) > 0 || len(nc.PermittedDNSDomains) > 0 || len(nc.PermittedURIDomains) > 0
}

// Validate checks that every range and domain can be encoded. It does not
// require a permitted subtree; IssueSubordinateCA does.
func (nc *NameConstraints) Validate() error {
	if nc == nil {
		return &errs.Detail{Err: ErrInvalidNameConstraints, Detail: "name constraints required"}
	}
	for _, ranges := range [][]*net.IPNet{nc.PermittedIPRanges, nc.ExcludedIPRanges} {
		for _, n := range ranges {
			if err := validateIPConstraint(n); err != nil {
				return err
			}
		}
	}
	for _, domains := range [][]string{nc.PermittedDNSDomains, nc.ExcludedDNSDomains, nc.PermittedURIDomains, nc.ExcludedURIDomains} {
		for _, d := range domains {
			if !validConstraintDomain(d) {
				return &errs.Detail{Err: ErrInvalidNameConstraints, Detail: "domain " + d}
			}
		}
	}
	return nil
}

// apply writes the constraints onto a CA certificate template.
func (nc *NameConstraints) apply(template *x509.Certificate) {
	template.PermittedDNSDomainsCritical = nc.Critical
	template.PermittedIPRanges = nc.PermittedIPRanges
	template.ExcludedIPRanges = nc.ExcludedIPRanges
	template.PermittedDNSDomains = nc.PermittedDNSDomains
	template.ExcludedDNSDomains = nc.ExcludedDNSDomains
	template.PermittedURIDomains = nc.PermittedURIDomains
	template.ExcludedURIDomains = nc.ExcludedURIDomains
}

// validateIPConstraint requires a network whose address and mask agree in
// family and whose address has no host bits set.
func validateIPConstraint(n *net.IPNet) error {
	if n == nil || n.IP == nil || n.Mask == nil {
		return &errs.Detail{Err: ErrInvalidNameConstraints, Detail: "nil ip range"}
	}
	ip := n.IP
	if v4 := ip.To4(); v4 != nil && len(n.Mask) == net.IPv4len {
		ip = v4
	}
	if len(ip) != len(n.Mask) {
		return &errs.Detail{Err: ErrInvalidNameConstraints, Detail: "ip range " + n.String() + " mixes address families"}
	}
	if _, bits := n.Mask.Size(); bits == 0 {
		return &errs.Detail{Err: ErrInvalidNameConstraints, Detail: "ip range " + n.String() + " has a non-canonical mask"}
	}
	if !ip.Mask(n.Mask).Equal(ip) {
		return &errs.Detail{Err: ErrInvalidNameConstraints, Detail: "ip range " + n.String() + " has host bits set"}
	}
	return nil
}

// validConstraintDomain reports whether d is a host name, optionally with a
// leading "." meaning "subdomains only".
func validConstraintDomain(d string) bool {
	host := strings.TrimPrefix(d, ".")
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			alnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
			if !alnum && c != '-' && c != '_' {
				return false
			}
		}
	}
	return true
}

// checkIssuerNameConstraints refuses a template whose names fall outside the
// issuing certificate's name constraints. A CA that signed it would mint a
// certificate every conforming relying party rejects, so the refusal happens
// before the signature rather than at the first handshake.
//
// The rules mirror crypto/x509's path validation: every name of a constrained
// type must match a permitted subtree when any is listed and must match no
// excluded subtree.
func checkIssuerNameConstraints(issuer, template *x509.Certificate) error {
	if issuer == nil || template == nil {
		return nil
	}
	for _, ip := range template.IPAddresses {
		if !nameAllowed(ip.String(), issuer.PermittedIPRanges, issuer.ExcludedIPRanges, ipInRange) {
			return &errs.Detail{Err: ErrNameConstraintViolation, Detail: "ip address " + ip.String()}
		}
	}
	for _, name := range template.DNSNames {
		if !nameAllowed(name, issuer.PermittedDNSDomains, issuer.ExcludedDNSDomains, domainMatches) {
			return &errs.Detail{Err: ErrNameConstraintViolation, Detail: "dns name " + name}
		}
	}
	for _, u := range template.URIs {
		if !nameAllowed(u.Hostname(), issuer.PermittedURIDomains, issuer.ExcludedURIDomains, domainMatches) {
			return &errs.Detail{Err: ErrNameConstraintViolation, Detail: "uri " + u.String()}
		}
	}
	for _, email := range template.EmailAddresses {
		host := email
		if at := strings.LastIndex(email, "@"); at >= 0 {
			host = email[at+1:]
		}
		if !nameAllowed(host, issuer.PermittedEmailAddresses, issuer.ExcludedEmailAddresses, emailMatches(email)) {
			return &errs.Detail{Err: ErrNameConstraintViolation, Detail: "email address " + email}
		}
	}
	return nil
}

// nameAllowed applies one constraint type: excluded subtrees always refuse,
// and when permitted subtrees exist the name must match one.
func nameAllowed[C any](name string, permitted, excluded []C, match func(string, C) bool) bool {
	for _, c := range excluded {
		if match(name, c) {
			return false
		}
	}
	if len(permitted) == 0 {
		return true
	}
	for _, c := range permitted {
		if match(name, c) {
			return true
		}
	}
	return false
}

// ipInRange reports whether the textual address lies in n. An IPv4 address
// matches only an IPv4 range and an IPv6 address only an IPv6 range, as in
// crypto/x509.
func ipInRange(addr string, n *net.IPNet) bool {
	ip := net.ParseIP(addr)
	if ip == nil || n == nil {
		return false
	}
	rangeIsV4 := n.IP.To4() != nil && len(n.Mask) == net.IPv4len
	if (ip.To4() != nil) != rangeIsV4 {
		return false
	}
	return n.Contains(ip)
}

// domainMatches applies RFC 5280 domain matching: "example.com" matches the
// domain and its subdomains, ".example.com" only its subdomains. Comparison
// is case-insensitive.
func domainMatches(name, constraint string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	constraint = strings.ToLower(constraint)
	if strings.HasPrefix(constraint, ".") {
		return strings.HasSuffix(name, constraint) && len(name) > len(constraint)
	}
	return name == constraint || strings.HasSuffix(name, "."+constraint)
}

// emailMatches returns the RFC 5280 rfc822Name matcher for one address: a
// constraint holding "@" names a single mailbox, ".example.com" any host
// below example.com, and "example.com" that host exactly.
func emailMatches(address string) func(string, string) bool {
	return func(host, constraint string) bool {
		switch {
		case strings.Contains(constraint, "@"):
			return strings.EqualFold(address, constraint)
		case strings.HasPrefix(constraint, "."):
			return domainMatches(host, constraint)
		default:
			return strings.EqualFold(host, constraint)
		}
	}
}
