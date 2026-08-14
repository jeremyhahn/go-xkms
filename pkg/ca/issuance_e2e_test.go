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

// Package ca_test exercises certificate issuance end to end through the real
// CA object: certificates are issued, their DER re-parsed, and the resulting
// extensions asserted. The tests live in the external test package so they
// can define their own ca.ProfileProvider fixtures (modeling the mTLS and
// PIV certificate profiles a downstream consumer would register) entirely
// against the root package's public profile surface: ca.ProfileProvider,
// ca.ProfileRegistry, and ca.ProfileBuilder.
package ca_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// =============================================================================
// X.509 Extension OIDs asserted by these tests
// =============================================================================

var (
	oidExtensionBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtensionCRLDistribution  = asn1.ObjectIdentifier{2, 5, 29, 31}
	oidExtensionAuthorityInfo    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
)

// hasExtension reports whether the certificate carries the given extension OID.
func hasExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return true
		}
	}
	return false
}

// =============================================================================
// mTLS / PIV Profile Fixtures
//
// These model the ca.ProfileProvider implementations a downstream mTLS/PIV
// integration would register with the CA's registry: mTLS via
// ca.ProfileBuilder (the root package's public custom-profile extension
// point), and PIV via a small hand-written ca.ProfileProvider that stamps a
// vendor extended-key-usage OID through UnknownExtKeyUsage, the same
// extension point a real PIV/smart-card integration uses for slot-specific
// EKUs that x509.ExtKeyUsage has no enum value for.
// =============================================================================

// mTLS and PIV profile names used by the fixtures below. These mirror the
// canonical names a real mTLS/PIV integration would register under.
const (
	mtlsClientProfileName        = "mtls-client"
	mtlsServerProfileName        = "mtls-server"
	mtlsDualProfileName          = "mtls-dual"
	pivAuthenticationProfileName = "piv-authentication"
	pivCardAuthProfileName       = "piv-card-auth"
)

// PIV extended-key-usage OIDs per NIST SP 800-73-4 (Card Authentication) and
// the Microsoft Smart Card Logon EKU used by PIV Authentication credentials.
var (
	oidSmartCardLogon        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 2}
	oidPIVCardAuthentication = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 6, 8}
)

// pivProfile models a downstream PIV credential profile: a third-party
// ca.ProfileProvider that stamps custom extended-key-usage OIDs via
// UnknownExtKeyUsage.
type pivProfile struct {
	name        string
	extKeyUsage []x509.ExtKeyUsage
	oids        []asn1.ObjectIdentifier
}

func (p *pivProfile) Name() string { return p.name }

func (p *pivProfile) Apply(template *x509.Certificate, request *ca.CertificateRequest) error {
	if template == nil {
		return ca.ErrInvalidProfile
	}
	template.KeyUsage = p.KeyUsage()
	template.ExtKeyUsage = p.ExtKeyUsage()
	template.UnknownExtKeyUsage = append(template.UnknownExtKeyUsage, p.oids...)
	template.IsCA = false
	template.BasicConstraintsValid = true
	return nil
}

func (p *pivProfile) KeyUsage() x509.KeyUsage { return x509.KeyUsageDigitalSignature }

func (p *pivProfile) ExtKeyUsage() []x509.ExtKeyUsage { return p.extKeyUsage }

func (p *pivProfile) DefaultValidity() int { return 1095 }

// newMTLSProfile builds an mTLS end-entity profile with ca.ProfileBuilder,
// the root package's public extension point for custom profiles. This is the
// same construction a downstream mTLS integration would use.
func newMTLSProfile(name string, extKeyUsage ...x509.ExtKeyUsage) ca.ProfileProvider {
	return ca.NewProfileBuilder(name).
		WithKeyUsage(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment).
		WithExtKeyUsage(extKeyUsage...).
		Build()
}

// =============================================================================
// Test Fixtures
// =============================================================================

// revocationEndpoints groups the three URL lists a CA can publish so tests can
// configure identities and profiles from one place.
type revocationEndpoints struct {
	crl  []string
	ocsp []string
	aia  []string
}

// endpointProfile is a certificate profile that publishes revocation and AIA
// endpoints from its Apply method. It models a downstream profile that pins
// certificate-type-specific endpoints, overriding the issuing identity's
// defaults.
type endpointProfile struct {
	name      string
	endpoints revocationEndpoints
	applyErr  error
}

func (p *endpointProfile) Name() string { return p.name }

func (p *endpointProfile) Apply(template *x509.Certificate, request *ca.CertificateRequest) error {
	if p.applyErr != nil {
		return p.applyErr
	}
	template.KeyUsage = p.KeyUsage()
	template.ExtKeyUsage = p.ExtKeyUsage()
	template.CRLDistributionPoints = p.endpoints.crl
	template.OCSPServer = p.endpoints.ocsp
	template.IssuingCertificateURL = p.endpoints.aia
	return nil
}

func (p *endpointProfile) KeyUsage() x509.KeyUsage {
	return x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
}

func (p *endpointProfile) ExtKeyUsage() []x509.ExtKeyUsage {
	return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
}

func (p *endpointProfile) DefaultValidity() int { return 90 }

// newTestRegistry returns a profile registry seeded with the built-in
// profiles plus in-test mTLS and PIV profile fixtures (see pivProfile and
// newMTLSProfile above), which model the ca.ProfileProvider implementations a
// downstream mTLS/PIV integration would register.
func newTestRegistry(t *testing.T) ca.ProfileRegistry {
	t.Helper()

	registry := ca.NewDefaultProfileRegistry()
	require.NoError(t, registry.Register(mtlsClientProfileName,
		newMTLSProfile(mtlsClientProfileName, x509.ExtKeyUsageClientAuth)))
	require.NoError(t, registry.Register(mtlsServerProfileName,
		newMTLSProfile(mtlsServerProfileName, x509.ExtKeyUsageServerAuth)))
	require.NoError(t, registry.Register(mtlsDualProfileName,
		newMTLSProfile(mtlsDualProfileName, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth)))
	require.NoError(t, registry.Register(pivAuthenticationProfileName, &pivProfile{
		name:        pivAuthenticationProfileName,
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		oids:        []asn1.ObjectIdentifier{oidSmartCardLogon},
	}))
	require.NoError(t, registry.Register(pivCardAuthProfileName, &pivProfile{
		name:        pivCardAuthProfileName,
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		oids:        []asn1.ObjectIdentifier{oidSmartCardLogon, oidPIVCardAuthentication},
	}))
	return registry
}

// rootOnlyConfig returns a single-identity (root) CA configuration.
func rootOnlyConfig(t *testing.T, cn string) *ca.MultiIdentityCAConfig {
	t.Helper()

	config := ca.DefaultMultiIdentityCAConfig()
	config.Identity[0].Subject.CommonName = cn
	config.Identity[0].Keys[0].KeyType = "CA"
	return config
}

// intermediateConfig returns a root + intermediate CA configuration with the
// intermediate selected as the issuing identity.
func intermediateConfig(t *testing.T, rootCN, intermediateCN string) *ca.MultiIdentityCAConfig {
	t.Helper()

	config := ca.DefaultMultiIdentityCAConfigWithIntermediate()
	config.Identity[0].Subject.CommonName = rootCN
	config.Identity[0].Keys[0].KeyType = "CA"
	config.Identity[1].Subject.CommonName = intermediateCN
	config.Identity[1].Keys[0].KeyType = "CA"
	return config
}

// newIssuingCA builds and initializes a CA backed entirely by in-memory
// storage. Passing a nil registry selects the CA's built-in profiles.
func newIssuingCA(t *testing.T, config *ca.MultiIdentityCAConfig, registry ca.ProfileRegistry) ca.TrustedCA {
	t.Helper()

	swBackend, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	require.NoError(t, err)

	backend, err := xkms.New(&xkms.BackendConfig{
		Backend:     swBackend,
		CertStorage: storage.NewMemory(),
	})
	require.NoError(t, err)

	certStore, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(storage.NewMemory()),
	})
	require.NoError(t, err)

	trustedCA, err := ca.NewFromMultiIdentityConfig(&ca.MultiIdentityParams{
		Config:    config,
		KeyStore:  backend,
		CertStore: certStore,
		Profiles:  registry,
	})
	require.NoError(t, err)
	require.NoError(t, trustedCA.Init(context.Background()))

	return trustedCA
}

// newHierarchicalIssuingCA builds and initializes a CA that preserves the full
// root -> intermediate hierarchy, so both CA tiers are created and the
// intermediate is the issuing identity.
func newHierarchicalIssuingCA(t *testing.T, config *ca.MultiIdentityCAConfig, registry ca.ProfileRegistry) ca.TrustedCA {
	t.Helper()

	swBackend, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	require.NoError(t, err)

	backend, err := xkms.New(&xkms.BackendConfig{
		Backend:     swBackend,
		CertStorage: storage.NewMemory(),
	})
	require.NoError(t, err)

	certStore, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(storage.NewMemory()),
	})
	require.NoError(t, err)

	trustedCA, err := ca.NewHierarchicalCA(&ca.MultiIdentityParams{
		Config:    config,
		KeyStore:  backend,
		CertStore: certStore,
		Profiles:  registry,
	})
	require.NoError(t, err)
	require.NoError(t, trustedCA.Init(context.Background()))

	return trustedCA
}

// issueLeaf issues an end-entity certificate and re-parses it from DER so the
// assertions run against the encoded certificate rather than the template.
func issueLeaf(t *testing.T, trustedCA ca.TrustedCA, cn, profile string) *x509.Certificate {
	t.Helper()

	issued, err := trustedCA.IssueCertificateWithProfile(context.Background(), &ca.CertificateRequest{
		Subject: ca.Subject{CommonName: cn},
		SANS:    &ca.SubjectAlternativeNames{DNS: []string{cn}},
	}, profile)
	require.NoError(t, err)
	require.NotNil(t, issued)

	block, _ := pem.Decode(issued.CertificatePEM)
	require.NotNil(t, block, "issued certificate must be PEM encoded")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

// generateCSR builds a PEM-encoded CSR for the CSR-signing path.
func generateCSR(t *testing.T, cn string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: []string{cn},
	}, key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

// =============================================================================
// Revocation & AIA Endpoints on End-Entity Certificates
// =============================================================================

// TestIssuance_LeafInheritsIdentityRevocationEndpoints proves that end-entity
// certificates carry the issuing identity's revocation and AIA endpoints. This
// is the compliance-relevant behaviour: a leaf without a CRL distribution
// point or OCSP responder cannot be revocation-checked by a relying party.
func TestIssuance_LeafInheritsIdentityRevocationEndpoints(t *testing.T) {
	endpoints := revocationEndpoints{
		crl:  []string{"http://crl.example.com/root.crl"},
		ocsp: []string{"http://ocsp.example.com"},
		aia:  []string{"http://aia.example.com/root.cer"},
	}

	config := rootOnlyConfig(t, "Endpoint Root CA")
	config.Identity[0].CRLDistributionPoints = endpoints.crl
	config.Identity[0].OCSPServers = endpoints.ocsp
	config.Identity[0].IssuingCertificateURLs = endpoints.aia

	trustedCA := newIssuingCA(t, config, nil)
	cert := issueLeaf(t, trustedCA, "leaf-endpoints.example.com", "server")

	assert.Equal(t, endpoints.crl, cert.CRLDistributionPoints,
		"leaf must publish the issuing identity's CRL distribution points")
	assert.Equal(t, endpoints.ocsp, cert.OCSPServer,
		"leaf must publish the issuing identity's OCSP responders")
	assert.Equal(t, endpoints.aia, cert.IssuingCertificateURL,
		"leaf must publish the issuing identity's CA issuer URLs")

	assert.True(t, hasExtension(cert, oidExtensionCRLDistribution),
		"CRL Distribution Points extension must be encoded")
	assert.True(t, hasExtension(cert, oidExtensionAuthorityInfo),
		"Authority Information Access extension must be encoded")
}

// TestIssuance_LeafEndpointsOnCSRPath proves the CSR-signing entry point stamps
// the same endpoints as the key-generation entry point.
func TestIssuance_LeafEndpointsOnCSRPath(t *testing.T) {
	config := rootOnlyConfig(t, "CSR Endpoint Root CA")
	config.Identity[0].CRLDistributionPoints = []string{"http://crl.example.com/csr.crl"}
	config.Identity[0].OCSPServers = []string{"http://ocsp.example.com/csr"}
	config.Identity[0].IssuingCertificateURLs = []string{"http://aia.example.com/csr.cer"}

	trustedCA := newIssuingCA(t, config, nil)

	cert, err := trustedCA.SignCSR(context.Background(),
		generateCSR(t, "csr-endpoints.example.com"), &ca.SignOptions{Profile: "server"})
	require.NoError(t, err)

	assert.Equal(t, []string{"http://crl.example.com/csr.crl"}, cert.CRLDistributionPoints)
	assert.Equal(t, []string{"http://ocsp.example.com/csr"}, cert.OCSPServer)
	assert.Equal(t, []string{"http://aia.example.com/csr.cer"}, cert.IssuingCertificateURL)
}

// TestIssuance_ProfileEndpointsOverrideIdentity documents the precedence rule:
// an explicit profile value wins over the issuing identity's default, and each
// URL list is resolved independently.
func TestIssuance_ProfileEndpointsOverrideIdentity(t *testing.T) {
	config := rootOnlyConfig(t, "Precedence Root CA")
	config.Identity[0].CRLDistributionPoints = []string{"http://identity.example.com/root.crl"}
	config.Identity[0].OCSPServers = []string{"http://identity.example.com/ocsp"}
	config.Identity[0].IssuingCertificateURLs = []string{"http://identity.example.com/root.cer"}

	registry := ca.NewDefaultProfileRegistry()
	require.NoError(t, registry.Register("pinned-endpoints", &endpointProfile{
		name: "pinned-endpoints",
		endpoints: revocationEndpoints{
			crl:  []string{"http://profile.example.com/leaf.crl"},
			ocsp: []string{"http://profile.example.com/ocsp"},
		},
	}))

	trustedCA := newIssuingCA(t, config, registry)
	cert := issueLeaf(t, trustedCA, "precedence.example.com", "pinned-endpoints")

	assert.Equal(t, []string{"http://profile.example.com/leaf.crl"}, cert.CRLDistributionPoints,
		"profile CRL distribution points must win over the identity default")
	assert.Equal(t, []string{"http://profile.example.com/ocsp"}, cert.OCSPServer,
		"profile OCSP responders must win over the identity default")
	assert.Equal(t, []string{"http://identity.example.com/root.cer"}, cert.IssuingCertificateURL,
		"a list the profile leaves empty must still inherit the identity default")
}

// TestIssuance_NoEndpointsConfiguredIsNoOp proves a CA without revocation URLs
// still issues a valid certificate and encodes no degenerate extensions.
func TestIssuance_NoEndpointsConfiguredIsNoOp(t *testing.T) {
	trustedCA := newIssuingCA(t, rootOnlyConfig(t, "Bare Root CA"), nil)
	cert := issueLeaf(t, trustedCA, "bare.example.com", "server")

	assert.Empty(t, cert.CRLDistributionPoints)
	assert.Empty(t, cert.OCSPServer)
	assert.Empty(t, cert.IssuingCertificateURL)

	assert.False(t, hasExtension(cert, oidExtensionCRLDistribution),
		"no CRL Distribution Points extension may be encoded when none are configured")
	assert.False(t, hasExtension(cert, oidExtensionAuthorityInfo),
		"no Authority Information Access extension may be encoded when none are configured")

	chains, err := trustedCA.Verify(cert)
	require.NoError(t, err)
	assert.NotEmpty(t, chains)
}

// TestIssuance_ExternalSignerKeepsCallerEndpoints proves that certificates
// signed with a caller-supplied signer are not stamped with this CA's
// endpoints: the issuer is a different CA whose revocation services this CA
// does not operate.
func TestIssuance_ExternalSignerKeepsCallerEndpoints(t *testing.T) {
	config := rootOnlyConfig(t, "Umbrella Root CA")
	config.Identity[0].CRLDistributionPoints = []string{"http://umbrella.example.com/root.crl"}
	config.Identity[0].OCSPServers = []string{"http://umbrella.example.com/ocsp"}

	trustedCA := newIssuingCA(t, config, nil)

	tenantKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tenantTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Tenant CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	tenantDER, err := x509.CreateCertificate(rand.Reader, tenantTemplate, tenantTemplate,
		&tenantKey.PublicKey, tenantKey)
	require.NoError(t, err)
	tenantCert, err := x509.ParseCertificate(tenantDER)
	require.NoError(t, err)

	cert, err := trustedCA.SignCSR(context.Background(),
		generateCSR(t, "tenant-leaf.example.com"), &ca.SignOptions{
			Signer:     tenantKey,
			IssuerCert: tenantCert,
		})
	require.NoError(t, err)

	assert.Empty(t, cert.CRLDistributionPoints,
		"externally-issued certificates must not advertise this CA's CRL")
	assert.Empty(t, cert.OCSPServer,
		"externally-issued certificates must not advertise this CA's OCSP responder")
}

// =============================================================================
// Profile Application
// =============================================================================

// TestIssuance_PIVProfileAppliesCustomExtKeyUsageOIDs proves a PIV profile's
// custom extended key usage OIDs reach the issued certificate. These OIDs are
// only written by the profile's Apply method.
func TestIssuance_PIVProfileAppliesCustomExtKeyUsageOIDs(t *testing.T) {
	trustedCA := newIssuingCA(t, rootOnlyConfig(t, "PIV Root CA"), newTestRegistry(t))
	cert := issueLeaf(t, trustedCA, "piv-user.example.com", pivAuthenticationProfileName)

	assert.Contains(t, cert.UnknownExtKeyUsage, oidSmartCardLogon,
		"PIV authentication certificates must carry the Smart Card Logon EKU OID")
	assert.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	assert.Equal(t, x509.KeyUsageDigitalSignature, cert.KeyUsage)
	assert.False(t, cert.IsCA)
}

// TestIssuance_PIVProfileOnCSRPath proves the CSR-signing entry point applies
// profiles too, not just the key-generation entry point.
func TestIssuance_PIVProfileOnCSRPath(t *testing.T) {
	trustedCA := newIssuingCA(t, rootOnlyConfig(t, "PIV CSR Root CA"), newTestRegistry(t))

	cert, err := trustedCA.SignCSR(context.Background(),
		generateCSR(t, "piv-csr.example.com"),
		&ca.SignOptions{Profile: pivCardAuthProfileName})
	require.NoError(t, err)

	assert.Contains(t, cert.UnknownExtKeyUsage, oidPIVCardAuthentication,
		"PIV card authentication certificates must carry the PIV card auth EKU OID")
}

// TestIssuance_MTLSProfileAppliesBasicConstraints proves an mTLS profile's
// basic constraints reach the issued certificate: an mTLS credential is an
// end-entity certificate and must say so.
func TestIssuance_MTLSProfileAppliesBasicConstraints(t *testing.T) {
	trustedCA := newIssuingCA(t, rootOnlyConfig(t, "mTLS Root CA"), newTestRegistry(t))

	client := issueLeaf(t, trustedCA, "mtls-client.example.com", mtlsClientProfileName)
	assert.True(t, hasExtension(client, oidExtensionBasicConstraints),
		"mTLS client certificates must encode basic constraints")
	assert.False(t, client.IsCA, "mTLS client certificates must not be CA certificates")
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, client.ExtKeyUsage)
	assert.Equal(t, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, client.KeyUsage)

	dual := issueLeaf(t, trustedCA, "mtls-dual.example.com", mtlsDualProfileName)
	assert.True(t, hasExtension(dual, oidExtensionBasicConstraints))
	assert.False(t, dual.IsCA)
	assert.ElementsMatch(t,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		dual.ExtKeyUsage)
}

// TestIssuance_ProfileApplyFailureIsTyped proves a profile that rejects the
// template aborts issuance with an ErrInvalidProfile-typed error rather than
// silently issuing a certificate the profile did not approve.
func TestIssuance_ProfileApplyFailureIsTyped(t *testing.T) {
	registry := ca.NewDefaultProfileRegistry()
	require.NoError(t, registry.Register("rejecting", &endpointProfile{
		name:     "rejecting",
		applyErr: ca.ErrInvalidProfile,
	}))

	trustedCA := newIssuingCA(t, rootOnlyConfig(t, "Rejecting Root CA"), registry)

	_, err := trustedCA.SignCSR(context.Background(),
		generateCSR(t, "rejected.example.com"), &ca.SignOptions{Profile: "rejecting"})
	require.Error(t, err)
	assert.ErrorIs(t, err, ca.ErrInvalidProfile)
	assert.Contains(t, err.Error(), "rejecting")
}

// TestIssuance_UnknownProfileRejected proves an unregistered profile name is
// rejected before any certificate is produced.
func TestIssuance_UnknownProfileRejected(t *testing.T) {
	trustedCA := newIssuingCA(t, rootOnlyConfig(t, "Unknown Profile Root CA"), nil)

	_, err := trustedCA.SignCSR(context.Background(),
		generateCSR(t, "unknown.example.com"), &ca.SignOptions{Profile: "does-not-exist"})
	require.Error(t, err)
	assert.ErrorIs(t, err, ca.ErrProfileNotFound)
}

// =============================================================================
// Chain Verification
// =============================================================================

// TestIssuance_ChainVerifiesWithEndpoints proves the root -> intermediate ->
// leaf chain still verifies once every tier publishes revocation endpoints,
// and that the leaf inherits the *issuing* (intermediate) identity's endpoints
// rather than the root's.
func TestIssuance_ChainVerifiesWithEndpoints(t *testing.T) {
	config := intermediateConfig(t, "Chain Root CA", "Chain Intermediate CA")
	config.Identity[0].CRLDistributionPoints = []string{"http://crl.example.com/root.crl"}
	config.Identity[0].OCSPServers = []string{"http://ocsp.example.com/root"}
	config.Identity[1].CRLDistributionPoints = []string{"http://crl.example.com/intermediate.crl"}
	config.Identity[1].OCSPServers = []string{"http://ocsp.example.com/intermediate"}
	config.Identity[1].IssuingCertificateURLs = []string{"http://aia.example.com/intermediate.cer"}

	trustedCA := newHierarchicalIssuingCA(t, config, newTestRegistry(t))
	leaf := issueLeaf(t, trustedCA, "chain-leaf.example.com", mtlsServerProfileName)

	assert.Equal(t, []string{"http://crl.example.com/intermediate.crl"}, leaf.CRLDistributionPoints,
		"leaf must inherit the issuing intermediate's CRL, not the root's")
	assert.Equal(t, []string{"http://ocsp.example.com/intermediate"}, leaf.OCSPServer)
	assert.Equal(t, []string{"http://aia.example.com/intermediate.cer"}, leaf.IssuingCertificateURL)

	root, err := trustedCA.TrustedRoot()
	require.NoError(t, err)
	assert.Equal(t, []string{"http://crl.example.com/root.crl"}, root.CRLDistributionPoints)

	intermediate, err := trustedCA.TrustedIntermediate()
	require.NoError(t, err)
	assert.Equal(t, []string{"http://crl.example.com/intermediate.crl"}, intermediate.CRLDistributionPoints)

	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)

	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	require.NoError(t, err, "root -> intermediate -> leaf chain must verify")
	require.NotEmpty(t, chains)
	assert.Len(t, chains[0], 3, "verified chain must be leaf, intermediate, root")

	caChains, err := trustedCA.Verify(leaf)
	require.NoError(t, err)
	assert.NotEmpty(t, caChains)
}
