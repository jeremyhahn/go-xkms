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

// Package spiffe is the single source of truth for the tenant-scoped SPIFFE
// identity path used across the stack. The canonical string form is:
//
//	spiffe://<trust-domain>/tenant/<tenantID>/<kind>/<name>
//
// where kind is "user" (human identity) or "svc" (service identity). Both
// certificate issuance (go-xkms CA) and login-time verification (go-qrdb mTLS
// authenticator) must route through this package rather than hand-assembling
// or hand-parsing the path, so the format and the trust-domain pin stay
// consistent. The package is a leaf with no go-xkms dependencies, so it can be
// imported by any layer without creating an import cycle.
package spiffe

import (
	"errors"
	"net/url"
	"strings"
)

// SPIFFE identity errors. These are sentinel errors callers may match with
// errors.Is to distinguish malformed SPIFFE issuance/verification parameters.
var (
	// ErrTrustDomainEmpty indicates an empty trust domain was supplied.
	ErrTrustDomainEmpty = errors.New("spiffe: trust domain must not be empty")

	// ErrTenantEmpty indicates an empty tenant ID was supplied.
	ErrTenantEmpty = errors.New("spiffe: tenant id must not be empty")

	// ErrKindInvalid indicates an unsupported workload kind was supplied.
	ErrKindInvalid = errors.New("spiffe: kind must be user or svc")

	// ErrNameEmpty indicates an empty workload name was supplied.
	ErrNameEmpty = errors.New("spiffe: name must not be empty")

	// ErrTrustDomainMismatch indicates a certificate's SPIFFE trust domain
	// does not match the operator-pinned trust domain. This is a fail-closed
	// security condition: the certificate must be rejected.
	ErrTrustDomainMismatch = errors.New("spiffe: trust domain does not match pinned trust domain")

	// ErrNoTenantSPIFFEID indicates no tenant-scoped SPIFFE SAN was found on
	// a certificate.
	ErrNoTenantSPIFFEID = errors.New("spiffe: no tenant spiffe identity present")
)

// Workload kinds. The tenant SPIFFE path encodes whether the leaf belongs to a
// human user or a service identity.
const (
	// KindUser identifies a human user (PIV/CAC/WebAuthn/federated subject).
	KindUser = "user"

	// KindService identifies a non-human service/workload identity.
	KindService = "svc"

	// scheme is the fixed SPIFFE URI scheme.
	scheme = "spiffe"
)

// ID describes a tenant-scoped SPIFFE identity.
type ID struct {
	// TrustDomain is the operator-configured SPIFFE trust domain (e.g.
	// "example.com"). It carries no scheme and no path.
	TrustDomain string

	// TenantID is the QuicBaaS tenant the workload belongs to.
	TenantID string

	// Kind is the workload kind: KindUser or KindService.
	Kind string

	// Name is the workload name (username for users, service name for
	// services).
	Name string
}

// Validate verifies all SPIFFE identity fields are present and well-formed.
func (id ID) Validate() error {
	if strings.TrimSpace(id.TrustDomain) == "" {
		return ErrTrustDomainEmpty
	}
	if strings.TrimSpace(id.TenantID) == "" {
		return ErrTenantEmpty
	}
	if id.Kind != KindUser && id.Kind != KindService {
		return ErrKindInvalid
	}
	if strings.TrimSpace(id.Name) == "" {
		return ErrNameEmpty
	}
	return nil
}

// URI renders the SPIFFE identity as a *url.URL ready to append to a
// certificate template's URIs slice.
func (id ID) URI() (*url.URL, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	return &url.URL{
		Scheme: scheme,
		Host:   id.TrustDomain,
		Path:   "/tenant/" + id.TenantID + "/" + id.Kind + "/" + id.Name,
	}, nil
}

// String renders the canonical SPIFFE string form. It returns an empty string
// if the identity is invalid; callers needing error detail should use URI.
func (id ID) String() string {
	u, err := id.URI()
	if err != nil {
		return ""
	}
	return u.String()
}

// BuildURI is a convenience constructor that validates the inputs and returns
// the canonical SPIFFE URI for a tenant-scoped workload.
func BuildURI(trustDomain, tenantID, kind, name string) (*url.URL, error) {
	return ID{
		TrustDomain: trustDomain,
		TenantID:    tenantID,
		Kind:        kind,
		Name:        name,
	}.URI()
}

// ParseID extracts a tenant SPIFFE identity from a URI. It returns false (not
// an error) when the URI is not a SPIFFE tenant path, so callers can iterate a
// certificate's URIs and skip non-SPIFFE SANs. It returns an error only when
// the URI looks like a SPIFFE tenant path but is malformed.
func ParseID(u *url.URL) (ID, bool, error) {
	if u == nil || u.Scheme != scheme {
		return ID{}, false, nil
	}

	td := u.Host
	if td == "" {
		return ID{}, false, ErrTrustDomainEmpty
	}

	// Expected path: /tenant/<tenantID>/<kind>/<name>
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 4 || parts[0] != "tenant" {
		// SPIFFE URI but not a tenant-scoped workload path. Not our format.
		return ID{}, false, nil
	}

	id := ID{
		TrustDomain: td,
		TenantID:    parts[1],
		Kind:        parts[2],
		Name:        parts[3],
	}
	if err := id.Validate(); err != nil {
		return ID{}, false, err
	}
	return id, true, nil
}

// TenantFromURIs scans a certificate's URI SANs for a tenant-scoped SPIFFE
// identity and returns it, enforcing the pinned trust domain (fail-closed).
//
// Resolution rules:
//   - If pinnedTrustDomain is non-empty, any SPIFFE tenant SAN whose trust
//     domain differs returns ErrTrustDomainMismatch. This rejects certificates
//     minted under a foreign trust domain.
//   - If no tenant SPIFFE SAN is present, returns ErrNoTenantSPIFFEID so the
//     caller can fall back to home-realm discovery or fail closed.
//   - A malformed tenant SPIFFE SAN returns the parse error (fail-closed).
func TenantFromURIs(uris []*url.URL, pinnedTrustDomain string) (ID, error) {
	for _, u := range uris {
		id, ok, err := ParseID(u)
		if err != nil {
			return ID{}, err
		}
		if !ok {
			continue
		}
		if pinnedTrustDomain != "" && id.TrustDomain != pinnedTrustDomain {
			return ID{}, ErrTrustDomainMismatch
		}
		return id, nil
	}
	return ID{}, ErrNoTenantSPIFFEID
}
