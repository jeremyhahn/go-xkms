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

// Package spiffe is the single source of truth for the tenant SPIFFE identity
// go-xkms issues. A tenant is a SPIFFE trust domain, so a tenant's principal
// has the canonical string form:
//
//	spiffe://<tenantID>/<kind>/<name>
//
// where kind is "user" (human identity) or "svc" (service identity). It is the
// form go-qrdb v0.51.0-alpha issues (auth.TenantPrincipalURIs) and reads at
// login (sdk.TenantFromClientCert): a certificate names its tenant only when
// its first Subject OU and this SAN's trust domain agree, and no tenant may be
// the cluster trust domain. The go-xkms CA builds the SAN here rather than
// hand-assembling the path. The package is a leaf with no go-xkms
// dependencies, so it can be imported by any layer without creating an import
// cycle.
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

	// ErrTenantIsClusterTrustDomain indicates a tenant equal to the cluster
	// trust domain. No tenant may be the cluster trust domain: a certificate
	// naming it is refused at login.
	ErrTenantIsClusterTrustDomain = errors.New("spiffe: tenant must not be the cluster trust domain")

	// ErrAmbiguousTenant indicates a certificate whose tenant SPIFFE SANs name
	// more than one tenant; such a certificate names no tenant.
	ErrAmbiguousTenant = errors.New("spiffe: tenant spiffe identities name more than one tenant")

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

// ID describes a tenant's SPIFFE principal.
type ID struct {
	// TenantID is the tenant the principal belongs to. It is the SPIFFE ID's
	// trust domain, so it must be a valid trust domain name.
	TenantID string

	// Kind is the workload kind: KindUser or KindService.
	Kind string

	// Name is the workload name (username for users, service name for
	// services). It is one SPIFFE ID path segment.
	Name string
}

// Validate verifies all SPIFFE identity fields are present and well-formed.
func (id ID) Validate() error {
	if strings.TrimSpace(id.TenantID) == "" {
		return ErrTenantEmpty
	}
	if err := validateTrustDomain(id.TenantID); err != nil {
		return err
	}
	if id.Kind != KindUser && id.Kind != KindService {
		return ErrKindInvalid
	}
	if strings.TrimSpace(id.Name) == "" {
		return ErrNameEmpty
	}
	return validateSegment(id.Name)
}

// URI renders the SPIFFE identity as a *url.URL ready to append to a
// certificate template's URIs slice.
func (id ID) URI() (*url.URL, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	return &url.URL{
		Scheme: scheme,
		Host:   id.TenantID,
		Path:   "/" + id.Kind + "/" + id.Name,
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

// BuildURI returns the URI SAN of a certificate issued to a tenant principal,
// spiffe://<tenantID>/<kind>/<name>, as go-qrdb's auth.TenantPrincipalURIs
// builds it. clusterTrustDomain is the cluster's own trust domain: it must be
// a valid trust domain name, and tenantID must not equal it
// (ErrTenantIsClusterTrustDomain), since login would refuse the certificate.
// The issuer pairs the SAN with tenantID as the Subject's first OU.
func BuildURI(clusterTrustDomain, tenantID, kind, name string) (*url.URL, error) {
	if err := validateTrustDomain(clusterTrustDomain); err != nil {
		return nil, err
	}
	if tenantID == clusterTrustDomain {
		return nil, ErrTenantIsClusterTrustDomain
	}
	return ID{
		TenantID: tenantID,
		Kind:     kind,
		Name:     name,
	}.URI()
}

// ParseID extracts a tenant principal from a URI. It returns false (not an
// error) when the URI is not a SPIFFE ID or is a SPIFFE ID of another shape (a
// node's spiffe://<td>/node/<id>, say), so callers can iterate a certificate's
// URIs and skip other SANs. It returns an error when a spiffe URI is not a
// valid SPIFFE ID, or names a tenant principal with an invalid field.
func ParseID(u *url.URL) (ID, bool, error) {
	if u == nil || u.Scheme != scheme {
		return ID{}, false, nil
	}
	workload, err := WorkloadIDFromURL(u)
	if err != nil {
		return ID{}, false, err
	}

	// Expected path: /<kind>/<name>
	parts := strings.Split(strings.TrimPrefix(workload.Path(), "/"), "/")
	if len(parts) != 2 || (parts[0] != KindUser && parts[0] != KindService) {
		return ID{}, false, nil
	}

	id := ID{
		TenantID: workload.TrustDomain().Name(),
		Kind:     parts[0],
		Name:     parts[1],
	}
	if err := id.Validate(); err != nil {
		return ID{}, false, err
	}
	return id, true, nil
}

// TenantFromURIs scans a certificate's URI SANs for its tenant principal and
// returns it, failing closed.
//
// Resolution rules:
//   - A tenant principal naming clusterTrustDomain returns
//     ErrTenantIsClusterTrustDomain. clusterTrustDomain == "" skips the check
//     and is for tests only.
//   - Tenant principals naming more than one tenant return
//     ErrAmbiguousTenant.
//   - A malformed SPIFFE SAN returns the parse error.
//   - No tenant principal returns ErrNoTenantSPIFFEID.
//
// It reads the SAN half of the tenant rule only. Login resolves the tenant
// with go-qrdb's sdk.TenantFromClientCert, which also requires the first
// Subject OU to name the same tenant.
func TenantFromURIs(uris []*url.URL, clusterTrustDomain string) (ID, error) {
	var found ID
	for _, u := range uris {
		id, ok, err := ParseID(u)
		if err != nil {
			return ID{}, err
		}
		if !ok {
			continue
		}
		if clusterTrustDomain != "" && id.TenantID == clusterTrustDomain {
			return ID{}, ErrTenantIsClusterTrustDomain
		}
		if found.TenantID != "" && found.TenantID != id.TenantID {
			return ID{}, ErrAmbiguousTenant
		}
		if found.TenantID == "" {
			found = id
		}
	}
	if found.TenantID == "" {
		return ID{}, ErrNoTenantSPIFFEID
	}
	return found, nil
}
