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

package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// applyRevocationEndpoints
// =============================================================================

func TestApplyRevocationEndpoints_FillsFromIdentity(t *testing.T) {
	identity := &Identity{
		CRLDistributionPoints:  []string{"http://crl.example.com/ca.crl"},
		OCSPServers:            []string{"http://ocsp.example.com"},
		IssuingCertificateURLs: []string{"http://aia.example.com/ca.cer"},
	}
	template := &x509.Certificate{}

	applyRevocationEndpoints(template, identity)

	assert.Equal(t, identity.CRLDistributionPoints, template.CRLDistributionPoints)
	assert.Equal(t, identity.OCSPServers, template.OCSPServer)
	assert.Equal(t, identity.IssuingCertificateURLs, template.IssuingCertificateURL)
}

func TestApplyRevocationEndpoints_DoesNotClobberExistingValues(t *testing.T) {
	identity := &Identity{
		CRLDistributionPoints:  []string{"http://identity.example.com/ca.crl"},
		OCSPServers:            []string{"http://identity.example.com/ocsp"},
		IssuingCertificateURLs: []string{"http://identity.example.com/ca.cer"},
	}
	template := &x509.Certificate{
		CRLDistributionPoints: []string{"http://profile.example.com/leaf.crl"},
		OCSPServer:            []string{"http://profile.example.com/ocsp"},
		IssuingCertificateURL: []string{"http://profile.example.com/leaf.cer"},
	}

	applyRevocationEndpoints(template, identity)

	assert.Equal(t, []string{"http://profile.example.com/leaf.crl"}, template.CRLDistributionPoints)
	assert.Equal(t, []string{"http://profile.example.com/ocsp"}, template.OCSPServer)
	assert.Equal(t, []string{"http://profile.example.com/leaf.cer"}, template.IssuingCertificateURL)
}

func TestApplyRevocationEndpoints_ResolvesEachListIndependently(t *testing.T) {
	identity := &Identity{
		CRLDistributionPoints:  []string{"http://identity.example.com/ca.crl"},
		OCSPServers:            []string{"http://identity.example.com/ocsp"},
		IssuingCertificateURLs: []string{"http://identity.example.com/ca.cer"},
	}
	template := &x509.Certificate{
		OCSPServer: []string{"http://profile.example.com/ocsp"},
	}

	applyRevocationEndpoints(template, identity)

	assert.Equal(t, []string{"http://identity.example.com/ca.crl"}, template.CRLDistributionPoints)
	assert.Equal(t, []string{"http://profile.example.com/ocsp"}, template.OCSPServer)
	assert.Equal(t, []string{"http://identity.example.com/ca.cer"}, template.IssuingCertificateURL)
}

func TestApplyRevocationEndpoints_NoEndpointsLeavesTemplateEmpty(t *testing.T) {
	template := &x509.Certificate{}

	applyRevocationEndpoints(template, &Identity{})

	assert.Nil(t, template.CRLDistributionPoints,
		"an unconfigured identity must not produce an empty CRL Distribution Points list")
	assert.Nil(t, template.OCSPServer)
	assert.Nil(t, template.IssuingCertificateURL)
}

func TestApplyRevocationEndpoints_NilInputsAreNoOps(t *testing.T) {
	template := &x509.Certificate{}

	assert.NotPanics(t, func() { applyRevocationEndpoints(template, nil) })
	assert.NotPanics(t, func() {
		applyRevocationEndpoints(nil, &Identity{CRLDistributionPoints: []string{"http://crl"}})
	})
	assert.Nil(t, template.CRLDistributionPoints)
}

func TestApplyRevocationEndpoints_CopiesIdentitySlices(t *testing.T) {
	identity := &Identity{CRLDistributionPoints: []string{"http://crl.example.com/ca.crl"}}
	template := &x509.Certificate{}

	applyRevocationEndpoints(template, identity)
	identity.CRLDistributionPoints[0] = "http://mutated.example.com/ca.crl"

	assert.Equal(t, []string{"http://crl.example.com/ca.crl"}, template.CRLDistributionPoints,
		"issued templates must not alias the running configuration")
}

// =============================================================================
// applyProfile
// =============================================================================

func TestApplyProfile_AppliesProviderToTemplate(t *testing.T) {
	template := &x509.Certificate{}

	require.NoError(t, applyProfile(template, NewServerProfile(), &CertificateRequest{}))

	assert.Equal(t, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, template.KeyUsage)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, template.ExtKeyUsage)
}

func TestApplyProfile_NilProfileIsNoOp(t *testing.T) {
	template := &x509.Certificate{KeyUsage: x509.KeyUsageCRLSign}

	require.NoError(t, applyProfile(template, nil, nil))

	assert.Equal(t, x509.KeyUsageCRLSign, template.KeyUsage)
}

func TestApplyProfile_WrapsProviderErrorAsInvalidProfile(t *testing.T) {
	// A real profile rejects a nil template, which is the error path callers
	// must be able to identify.
	err := applyProfile(nil, NewClientProfile(), &CertificateRequest{})

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidProfile),
		"profile failures must be identifiable as ErrInvalidProfile")
	assert.Contains(t, err.Error(), `profile "client"`)
}

func TestApplyProfile_CAProfileSetsBasicConstraints(t *testing.T) {
	template := &x509.Certificate{}

	require.NoError(t, applyProfile(template, NewCAProfile(), &CertificateRequest{
		TenantID:       testTenant,
		IsCA:           true,
		MaxPathLen:     2,
		MaxPathLenZero: false,
	}))

	assert.True(t, template.IsCA)
	assert.True(t, template.BasicConstraintsValid)
	assert.Equal(t, 2, template.MaxPathLen)
}

// =============================================================================
// certificateRequestFromTemplate
// =============================================================================

func TestCertificateRequestFromTemplate_CarriesTemplateContext(t *testing.T) {
	uri, err := url.Parse("spiffe://example.com/tenant/acme/user/alice")
	require.NoError(t, err)

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:    "leaf.example.com",
			Organization:  []string{"Example Org"},
			Country:       []string{"US"},
			Province:      []string{"CA"},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"1 Market St"},
			PostalCode:    []string{"94105"},
		},
		DNSNames:              []string{"leaf.example.com"},
		EmailAddresses:        []string{"alice@example.com"},
		IPAddresses:           []net.IP{net.ParseIP("10.0.0.1")},
		URIs:                  []*url.URL{uri},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
		BasicConstraintsValid: true,
	}

	request := certificateRequestFromTemplate(template, &SignOptions{
		TenantID:          "acme",
		SPIFFETrustDomain: "example.com",
		SPIFFEKind:        "user",
		SPIFFEName:        "alice",
	}, 90)

	assert.Equal(t, "leaf.example.com", request.Subject.CommonName)
	assert.Equal(t, "Example Org", request.Subject.Organization)
	assert.Equal(t, "US", request.Subject.Country)
	assert.Equal(t, "CA", request.Subject.Province)
	assert.Equal(t, "San Francisco", request.Subject.Locality)
	assert.Equal(t, "1 Market St", request.Subject.Address)
	assert.Equal(t, "94105", request.Subject.PostalCode)

	assert.Equal(t, 90, request.Valid)
	assert.Equal(t, x509.KeyUsageDigitalSignature, request.KeyUsage)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, request.ExtKeyUsage)
	assert.True(t, request.IsCA)
	assert.Equal(t, 1, request.MaxPathLen)

	require.NotNil(t, request.SANS)
	assert.Equal(t, []string{"leaf.example.com"}, request.SANS.DNS)
	assert.Equal(t, []string{"alice@example.com"}, request.SANS.Email)
	assert.Equal(t, []string{"10.0.0.1"}, request.SANS.IPs)
	assert.Equal(t, []string{"spiffe://example.com/tenant/acme/user/alice"}, request.SANS.URIs)

	assert.Equal(t, "acme", request.TenantID)
	assert.Equal(t, "example.com", request.SPIFFETrustDomain)
	assert.Equal(t, "user", request.SPIFFEKind)
	assert.Equal(t, "alice", request.SPIFFEName)
}

func TestCertificateRequestFromTemplate_WithoutOptionsOrSANs(t *testing.T) {
	template := &x509.Certificate{Subject: pkix.Name{CommonName: "bare.example.com"}}

	request := certificateRequestFromTemplate(template, nil, 0)

	assert.Equal(t, "bare.example.com", request.Subject.CommonName)
	assert.Empty(t, request.Subject.Organization)
	assert.Nil(t, request.SANS, "a template without SANs must not synthesize an empty SAN set")
	assert.Zero(t, request.Valid)
	assert.Nil(t, request.Signer)
	assert.Nil(t, request.IssuerCert)
}

func TestSubjectAltNamesFromTemplate_SkipsNilURIs(t *testing.T) {
	template := &x509.Certificate{URIs: []*url.URL{nil}}

	sans := subjectAltNamesFromTemplate(template)

	require.NotNil(t, sans)
	assert.Empty(t, sans.URIs)
}

// =============================================================================
// Conversion Helpers
// =============================================================================

func TestCloneStrings(t *testing.T) {
	original := []string{"a", "b"}

	clone := cloneStrings(original)
	clone[0] = "mutated"

	assert.Equal(t, []string{"a", "b"}, original)
	assert.Nil(t, cloneStrings(nil))
	assert.Nil(t, cloneStrings([]string{}))
}

func TestFirstOrEmpty(t *testing.T) {
	assert.Equal(t, "first", firstOrEmpty([]string{"first", "second"}))
	assert.Equal(t, "", firstOrEmpty(nil))
	assert.Equal(t, "", firstOrEmpty([]string{}))
}

func TestIPStrings(t *testing.T) {
	out := ipStrings([]net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::1")})

	assert.Equal(t, []string{"192.0.2.10", "2001:db8::1"}, out)
	assert.Nil(t, ipStrings(nil))
}

func TestURIStrings(t *testing.T) {
	first, err := url.Parse("https://example.com/a")
	require.NoError(t, err)
	second, err := url.Parse("spiffe://example.com/svc/b")
	require.NoError(t, err)

	assert.Equal(t, []string{"https://example.com/a", "spiffe://example.com/svc/b"},
		uriStrings([]*url.URL{first, second}))
	assert.Nil(t, uriStrings(nil))
	assert.Empty(t, uriStrings([]*url.URL{nil}))
}

func TestSubjectFromPkixName_EmptyName(t *testing.T) {
	subject := subjectFromPkixName(pkix.Name{})

	assert.Equal(t, Subject{}, subject)
}
