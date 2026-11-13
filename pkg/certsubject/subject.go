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

// Package certsubject stamps the tenant into the subject of every certificate
// go-xkms issues. It is a leaf package (standard library only) so that both
// pkg/ca and the packages pkg/ca imports, such as pkg/xkms, call the one
// stamping function.
package certsubject

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"slices"
)

var (
	// ErrTenantRequired indicates a certificate request that names no tenant.
	// Every certificate go-xkms issues carries its tenant as the subject's
	// first organizational unit; the system tenant's own certificates name
	// qrdbsdk.SystemTenantID.
	ErrTenantRequired = errors.New("ca: certificate request names no tenant")

	// ErrInvalidRawSubject reports a raw subject that is not a DER-encoded
	// RDNSequence.
	ErrInvalidRawSubject = errors.New("ca: raw subject is not a DER-encoded distinguished name")
)

var (
	oidAttributeOrganizationalUnit = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidAttributeCommonName         = asn1.ObjectIdentifier{2, 5, 4, 3}
)

// StampTenant returns subject, and rawSubject when it is set, with tenantID as
// the subject's first organizational unit: Subject.OrganizationalUnit[0], the
// tenant key on every layer, which qrdbsdk.TenantFromClientCert requires to
// match the trust domain of the certificate's SPIFFE SAN. It is the one place an issued
// certificate gets its tenant, and every issuance path calls it.
//
// tenantID is the request's tenant: the authenticated caller's or the issuing
// CA's, never a value the certificate signing request asserts. subject comes
// from the request, so every organizational unit it carries is replaced by
// the tenant, not appended to.
//
// rawSubject is a subject the issuing caller chose whole and never comes from
// the request (go-qrdb's ceremony names CN, then the tenant OU, then its
// profile OU, and refuses any other certificate). Its first organizational
// unit becomes the tenant, or the tenant is inserted before the first common
// name when it carries none; every other attribute keeps its value and order,
// and a rawSubject whose first organizational unit already is the tenant is
// returned byte for byte.
//
// An empty tenantID is refused with ErrTenantRequired: the system tenant's own
// certificates name qrdbsdk.SystemTenantID.
func StampTenant(tenantID string, subject pkix.Name, rawSubject []byte) (pkix.Name, []byte, error) {
	if tenantID == "" {
		return pkix.Name{}, nil, ErrTenantRequired
	}

	if len(rawSubject) == 0 {
		subject.OrganizationalUnit = []string{tenantID}
		subject.ExtraNames = withoutOrganizationalUnit(subject.ExtraNames)
		subject.Names = withoutOrganizationalUnit(subject.Names)
		return subject, nil, nil
	}

	var rdns pkix.RDNSequence
	if rest, err := asn1.Unmarshal(rawSubject, &rdns); err != nil || len(rest) != 0 {
		return pkix.Name{}, nil, ErrInvalidRawSubject
	}
	raw := rawSubject
	if firstOrganizationalUnit(rdns) != tenantID {
		rdns = stampTenantRDNs(tenantID, rdns)
		var err error
		if raw, err = asn1.Marshal(rdns); err != nil {
			return pkix.Name{}, nil, ErrInvalidRawSubject
		}
	}

	// The raw encoding is what the certificate carries, so the name that
	// profiles and the issuance record read is rebuilt from it.
	var name pkix.Name
	name.FillFromRDNSequence(&rdns)
	return name, raw, nil
}

// stampTenantRDNs returns a copy of rdns whose first organizational unit is
// tenantID, or with an RDN holding tenantID before the first common name when
// rdns carries no organizational unit.
func stampTenantRDNs(tenantID string, rdns pkix.RDNSequence) pkix.RDNSequence {
	stamped := make(pkix.RDNSequence, len(rdns))
	for i, rdn := range rdns {
		stamped[i] = slices.Clone(rdn)
	}
	for _, rdn := range stamped {
		for i := range rdn {
			if rdn[i].Type.Equal(oidAttributeOrganizationalUnit) {
				rdn[i].Value = tenantID
				return stamped
			}
		}
	}
	tenant := pkix.RelativeDistinguishedNameSET{{Type: oidAttributeOrganizationalUnit, Value: tenantID}}
	return slices.Insert(stamped, firstCommonName(stamped), tenant)
}

// firstOrganizationalUnit returns the value of the first organizational unit
// in rdns, or "" when it carries none.
func firstOrganizationalUnit(rdns pkix.RDNSequence) string {
	for _, rdn := range rdns {
		for _, attribute := range rdn {
			if attribute.Type.Equal(oidAttributeOrganizationalUnit) {
				if value, ok := attribute.Value.(string); ok {
					return value
				}
				return ""
			}
		}
	}
	return ""
}

// withoutOrganizationalUnit returns attributes without its organizational
// units, leaving attributes itself unchanged.
func withoutOrganizationalUnit(attributes []pkix.AttributeTypeAndValue) []pkix.AttributeTypeAndValue {
	if attributes == nil {
		return nil
	}
	return slices.DeleteFunc(slices.Clone(attributes), func(attribute pkix.AttributeTypeAndValue) bool {
		return attribute.Type.Equal(oidAttributeOrganizationalUnit)
	})
}

// firstCommonName returns the index of the first RDN in rdns holding a common
// name, or len(rdns) when none does.
func firstCommonName(rdns pkix.RDNSequence) int {
	for i, rdn := range rdns {
		for _, attribute := range rdn {
			if attribute.Type.Equal(oidAttributeCommonName) {
				return i
			}
		}
	}
	return len(rdns)
}
