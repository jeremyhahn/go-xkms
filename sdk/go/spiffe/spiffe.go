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

// Package spiffe re-exports go-xkms pkg/spiffe: the SPIFFE ID builder and
// validator (any trust domain and path, per the SPIFFE-ID specification) and
// the tenant-scoped identity shape the stack's CA and mTLS login share.
//
// Consumers import this package rather than go-xkms pkg/spiffe, so the SDK is
// the only go-xkms surface they depend on.
package spiffe

import (
	pkgspiffe "github.com/jeremyhahn/go-xkms/pkg/spiffe"
)

// General SPIFFE IDs.
type (
	// TrustDomain is a validated SPIFFE trust-domain name.
	TrustDomain = pkgspiffe.TrustDomain

	// WorkloadID is a validated SPIFFE ID: a trust domain plus a path.
	WorkloadID = pkgspiffe.WorkloadID

	// InvalidIDError reports input that breaks the SPIFFE ID grammar.
	InvalidIDError = pkgspiffe.InvalidIDError
)

// Tenant-scoped identities.
type (
	// ID is a tenant's principal spiffe://<tenant>/<kind>/<name>: the tenant
	// is the SPIFFE trust domain.
	ID = pkgspiffe.ID
)

// Constructors and validators.
var (
	// ParseTrustDomain validates a bare trust-domain name.
	ParseTrustDomain = pkgspiffe.ParseTrustDomain

	// ParseWorkloadID parses and validates a SPIFFE ID string.
	ParseWorkloadID = pkgspiffe.ParseWorkloadID

	// WorkloadIDFromURL validates a URI SAN as a SPIFFE ID.
	WorkloadIDFromURL = pkgspiffe.WorkloadIDFromURL

	// ValidatePath validates a SPIFFE ID path.
	ValidatePath = pkgspiffe.ValidatePath

	// ValidatePathPrefix validates a path prefix used to scope issuance.
	ValidatePathPrefix = pkgspiffe.ValidatePathPrefix

	// ValidateName validates a principal name, the SPIFFE URI's last segment
	// and the CSR CommonName a SPIFFE kind is issued for.
	ValidateName = pkgspiffe.ValidateName

	// BuildURI builds a tenant principal's SPIFFE URI under a cluster trust
	// domain the tenant must not equal.
	BuildURI = pkgspiffe.BuildURI

	// ParseID extracts a tenant-scoped identity from a URI.
	ParseID = pkgspiffe.ParseID

	// TenantFromURIs finds the tenant-scoped identity among URI SANs.
	TenantFromURIs = pkgspiffe.TenantFromURIs
)

// Tenant identity kinds.
const (
	// KindUser identifies a human user.
	KindUser = pkgspiffe.KindUser

	// KindService identifies a service identity.
	KindService = pkgspiffe.KindService
)

// Sentinel errors, matched with errors.Is.
var (
	ErrTrustDomainEmpty      = pkgspiffe.ErrTrustDomainEmpty
	ErrTrustDomainCharacters = pkgspiffe.ErrTrustDomainCharacters
	ErrTrustDomainTooLong    = pkgspiffe.ErrTrustDomainTooLong
	ErrSchemeInvalid         = pkgspiffe.ErrSchemeInvalid
	ErrSegmentEmpty          = pkgspiffe.ErrSegmentEmpty
	ErrSegmentDotted         = pkgspiffe.ErrSegmentDotted
	ErrSegmentCharacters     = pkgspiffe.ErrSegmentCharacters
	ErrIDTooLong             = pkgspiffe.ErrIDTooLong
	ErrIDComponents          = pkgspiffe.ErrIDComponents
	ErrPathPrefixInvalid     = pkgspiffe.ErrPathPrefixInvalid
	ErrTenantEmpty           = pkgspiffe.ErrTenantEmpty
	ErrKindInvalid           = pkgspiffe.ErrKindInvalid
	ErrNameEmpty             = pkgspiffe.ErrNameEmpty
	ErrNoTenantSPIFFEID      = pkgspiffe.ErrNoTenantSPIFFEID

	ErrTenantIsClusterTrustDomain = pkgspiffe.ErrTenantIsClusterTrustDomain
	ErrAmbiguousTenant            = pkgspiffe.ErrAmbiguousTenant
)
