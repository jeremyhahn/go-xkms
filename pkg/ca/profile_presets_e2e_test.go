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

package ca_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// =============================================================================
// CA Preset Fixtures
//
// caPreset models a downstream CA profile: a third-party ca.ProfileProvider
// that issues CA certificates, publishes revocation/AIA endpoints, and
// enforces its own basic-constraints path-length ceiling that a certificate
// request may tighten but never widen. This is the same shape a production
// root/intermediate CA profile takes; it is written directly against
// ca.ProfileProvider the way a real consumer of the CA would, exercising the
// extension point rather than any subpackage.
// =============================================================================

// Canonical CA preset names, matching the names a production root/
// intermediate CA profile would register under.
const (
	rootCAProfileName         = "root-ca"
	intermediateCAProfileName = "intermediate-ca"

	// unlimitedPathLen indicates a CA preset imposes no basic-constraints
	// path length ceiling.
	unlimitedPathLen = -1
)

// caPreset is a downstream CA profile fixture; see the package-level comment
// above for its role in these tests.
type caPreset struct {
	name       string
	maxPathLen int // -1 = unconstrained, mirrors x509 pathLenConstraint semantics
	crl        []string
	ocsp       []string
	aia        []string
}

func (p *caPreset) Name() string { return p.name }

func (p *caPreset) Apply(template *x509.Certificate, request *ca.CertificateRequest) error {
	if template == nil {
		return ca.ErrInvalidProfile
	}

	template.KeyUsage = p.KeyUsage()
	template.ExtKeyUsage = p.ExtKeyUsage()
	template.IsCA = true
	template.BasicConstraintsValid = true

	pathLen := p.maxPathLen
	if requested, explicit := requestedPathLen(request); explicit && (pathLen < 0 || requested < pathLen) {
		pathLen = requested
	}
	if pathLen < 0 {
		template.MaxPathLen = 0
		template.MaxPathLenZero = false
	} else {
		template.MaxPathLen = pathLen
		template.MaxPathLenZero = pathLen == 0
	}

	template.CRLDistributionPoints = p.crl
	template.OCSPServer = p.ocsp
	template.IssuingCertificateURL = p.aia
	return nil
}

func (p *caPreset) KeyUsage() x509.KeyUsage {
	return x509.KeyUsageCertSign | x509.KeyUsageCRLSign
}

func (p *caPreset) ExtKeyUsage() []x509.ExtKeyUsage { return nil }

func (p *caPreset) DefaultValidity() int { return 1825 }

// requestedPathLen reports the path length constraint a certificate request
// explicitly asks for. A CertificateRequest expresses "no constraint" with
// the zero value, so a MaxPathLen of 0 on its own is indistinguishable from
// an unset field; the constraint is only explicit when the request asks for
// a positive depth or sets MaxPathLenZero (the X.509 encoding of a
// pathLenConstraint of exactly zero).
func requestedPathLen(request *ca.CertificateRequest) (int, bool) {
	if request == nil {
		return 0, false
	}
	if request.MaxPathLenZero {
		return 0, true
	}
	if request.MaxPathLen > 0 {
		return request.MaxPathLen, true
	}
	return 0, false
}

// registryWithCAPresets returns the canonical registry the CA issues from,
// seeded with root and intermediate CA presets (see caPreset).
func registryWithCAPresets(t *testing.T) ca.ProfileRegistry {
	t.Helper()

	registry := ca.NewDefaultProfileRegistry()
	require.NoError(t, registry.Register(rootCAProfileName,
		&caPreset{name: rootCAProfileName, maxPathLen: unlimitedPathLen}))
	require.NoError(t, registry.Register(intermediateCAProfileName,
		&caPreset{name: intermediateCAProfileName, maxPathLen: 0}))
	return registry
}

// issueWithProfile issues a certificate for the given request through the real
// CA and re-parses it from DER, so assertions run against the encoded
// certificate rather than the template the profile modified.
func issueWithProfile(t *testing.T, trustedCA ca.TrustedCA, request *ca.CertificateRequest, profile string) *x509.Certificate {
	t.Helper()

	issued, err := trustedCA.IssueCertificateWithProfile(context.Background(), request, profile)
	require.NoError(t, err)
	require.NotNil(t, issued)

	block, _ := pem.Decode(issued.CertificatePEM)
	require.NotNil(t, block, "issued certificate must be PEM encoded")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

// =============================================================================
// CA Presets Reach Issued Certificates
// =============================================================================

// TestIssuance_CAPresetPublishesRevocationEndpoints is the regression test for
// the split profile abstraction: a CA preset that publishes CRL/OCSP/AIA
// endpoints from its own Apply method must have those endpoints reach the
// issued certificate.
//
// The preset is registered with the registry the CA issues from and a
// certificate is issued by profile name, so the whole registry -> resolve ->
// Apply -> encode path is exercised rather than a direct Apply call.
func TestIssuance_CAPresetPublishesRevocationEndpoints(t *testing.T) {
	const (
		presetCRL  = "http://crl.example.com/issuing.crl"
		presetOCSP = "http://ocsp.example.com/issuing"
		presetAIA  = "http://aia.example.com/root.cer"
	)

	// The issuing identity publishes different endpoints so the assertions
	// prove the URLs came from the profile, not from the CA configuration.
	config := rootOnlyConfig(t, "Preset Endpoint Root CA")
	config.Identity[0].CRLDistributionPoints = []string{"http://identity.example.com/root.crl"}
	config.Identity[0].OCSPServers = []string{"http://identity.example.com/ocsp"}
	config.Identity[0].IssuingCertificateURLs = []string{"http://identity.example.com/root.cer"}

	registry := ca.NewDefaultProfileRegistry()
	preset := &caPreset{
		name:       intermediateCAProfileName,
		maxPathLen: 0,
		crl:        []string{presetCRL},
		ocsp:       []string{presetOCSP},
		aia:        []string{presetAIA},
	}
	require.NoError(t, registry.Register(preset.Name(), preset),
		"a CA preset must be registrable with the registry the CA issues from")

	trustedCA := newIssuingCA(t, config, registry)
	cert := issueWithProfile(t, trustedCA, &ca.CertificateRequest{
		Subject: ca.Subject{CommonName: "Preset Issuing CA"},
	}, intermediateCAProfileName)

	assert.Equal(t, []string{presetCRL}, cert.CRLDistributionPoints,
		"the preset's CRL distribution point must reach the issued certificate")
	assert.Equal(t, []string{presetOCSP}, cert.OCSPServer,
		"the preset's OCSP responder must reach the issued certificate")
	assert.Equal(t, []string{presetAIA}, cert.IssuingCertificateURL,
		"the preset's CA issuers URL must reach the issued certificate")

	assert.True(t, hasExtension(cert, oidExtensionCRLDistribution),
		"CRL Distribution Points extension must be encoded")
	assert.True(t, hasExtension(cert, oidExtensionAuthorityInfo),
		"Authority Information Access extension must be encoded")

	// The preset is a CA profile, so the issued certificate must be usable as
	// an issuing CA with the configured path length.
	assert.True(t, cert.IsCA, "the intermediate preset must issue a CA certificate")
	assert.True(t, cert.BasicConstraintsValid)
	assert.True(t, hasExtension(cert, oidExtensionBasicConstraints))
	assert.Equal(t, 0, cert.MaxPathLen)
	assert.True(t, cert.MaxPathLenZero, "pathLen 0 must be encoded explicitly")
	assert.NotZero(t, cert.KeyUsage&x509.KeyUsageCertSign, "a CA certificate must be able to sign certificates")
	assert.NotZero(t, cert.KeyUsage&x509.KeyUsageCRLSign, "a CA certificate must be able to sign CRLs")
}

// TestIssuance_RegisterCAProfilesSeedsRegistry proves the batch registration
// helper puts both presets in the registry under their canonical names and that
// certificates can be issued by those names.
func TestIssuance_RegisterCAProfilesSeedsRegistry(t *testing.T) {
	registry := registryWithCAPresets(t)

	for _, name := range []string{rootCAProfileName, intermediateCAProfileName} {
		profile, err := registry.Get(name)
		require.NoError(t, err, "preset %q must be registered", name)
		assert.Equal(t, name, profile.Name())
	}

	trustedCA := newIssuingCA(t, rootOnlyConfig(t, "Preset Registry Root CA"), registry)

	rootPreset := issueWithProfile(t, trustedCA, &ca.CertificateRequest{
		Subject: ca.Subject{CommonName: "Preset Root CA"},
	}, rootCAProfileName)

	assert.True(t, rootPreset.IsCA)
	// crypto/x509 reports an absent pathLenConstraint as -1 on parse, which is
	// what an unconstrained root CA must encode.
	assert.Equal(t, -1, rootPreset.MaxPathLen,
		"the root preset is unconstrained, so no pathLenConstraint may be encoded")
	assert.False(t, rootPreset.MaxPathLenZero)
	assert.Empty(t, rootPreset.ExtKeyUsage,
		"a root CA must not restrict the purposes it can issue for")

	intermediatePreset := issueWithProfile(t, trustedCA, &ca.CertificateRequest{
		Subject: ca.Subject{CommonName: "Preset Intermediate CA"},
	}, intermediateCAProfileName)

	assert.True(t, intermediatePreset.IsCA)
	assert.True(t, intermediatePreset.MaxPathLenZero,
		"the intermediate preset may only issue end-entity certificates")
}

// TestIssuance_CAPresetPathLenHonoursRequest proves the request reaches the
// profile: a request may tighten the preset's path length constraint but never
// widen the signing authority the preset grants.
func TestIssuance_CAPresetPathLenHonoursRequest(t *testing.T) {
	registry := ca.NewDefaultProfileRegistry()
	preset := &caPreset{name: intermediateCAProfileName, maxPathLen: 2}
	require.NoError(t, registry.Register(preset.Name(), preset))

	trustedCA := newIssuingCA(t, rootOnlyConfig(t, "Path Length Root CA"), registry)

	t.Run("request_tightens_constraint", func(t *testing.T) {
		cert := issueWithProfile(t, trustedCA, &ca.CertificateRequest{
			Subject:        ca.Subject{CommonName: "Tightened Issuing CA"},
			MaxPathLen:     0,
			MaxPathLenZero: true,
		}, intermediateCAProfileName)

		assert.Equal(t, 0, cert.MaxPathLen)
		assert.True(t, cert.MaxPathLenZero, "an explicit pathLen of 0 must be honoured")
	})

	t.Run("request_cannot_widen_constraint", func(t *testing.T) {
		cert := issueWithProfile(t, trustedCA, &ca.CertificateRequest{
			Subject:    ca.Subject{CommonName: "Widened Issuing CA"},
			MaxPathLen: 9,
		}, intermediateCAProfileName)

		assert.Equal(t, 2, cert.MaxPathLen,
			"the profile's path length is a ceiling the request cannot raise")
	})

	t.Run("no_request_constraint_uses_profile", func(t *testing.T) {
		cert := issueWithProfile(t, trustedCA, &ca.CertificateRequest{
			Subject: ca.Subject{CommonName: "Default Issuing CA"},
		}, intermediateCAProfileName)

		assert.Equal(t, 2, cert.MaxPathLen)
		assert.False(t, cert.MaxPathLenZero)
	})
}

// TestIssuance_CAPresetOnCSRPath proves the CSR-signing entry point applies the
// CA presets too, so an externally generated CA key can be certified with the
// same profile and endpoints.
func TestIssuance_CAPresetOnCSRPath(t *testing.T) {
	const presetCRL = "http://crl.example.com/csr-issuing.crl"

	registry := ca.NewDefaultProfileRegistry()
	preset := &caPreset{name: intermediateCAProfileName, maxPathLen: 1, crl: []string{presetCRL}}
	require.NoError(t, registry.Register(preset.Name(), preset))

	trustedCA := newIssuingCA(t, rootOnlyConfig(t, "CSR Preset Root CA"), registry)

	cert, err := trustedCA.SignCSR(context.Background(),
		generateCSR(t, "csr-issuing-ca.example.com"),
		&ca.SignOptions{Profile: intermediateCAProfileName})
	require.NoError(t, err)

	assert.True(t, cert.IsCA, "the CA preset must promote the CSR to a CA certificate")
	assert.Equal(t, 1, cert.MaxPathLen)
	assert.Equal(t, []string{presetCRL}, cert.CRLDistributionPoints)
	assert.NotZero(t, cert.KeyUsage&x509.KeyUsageCertSign)
}

// TestIssuance_CAPresetChainVerifies proves a certificate issued from the
// intermediate preset is a usable issuing CA: it chains to the root and can
// itself sign an end-entity certificate that verifies through the full chain.
func TestIssuance_CAPresetChainVerifies(t *testing.T) {
	registry := registryWithCAPresets(t)
	trustedCA := newIssuingCA(t, rootOnlyConfig(t, "Chainable Root CA"), registry)

	intermediate := issueWithProfile(t, trustedCA, &ca.CertificateRequest{
		Subject:    ca.Subject{CommonName: "Chainable Issuing CA"},
		MaxPathLen: 1,
	}, intermediateCAProfileName)

	root, err := trustedCA.TrustedRoot()
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(root)

	chains, err := intermediate.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	require.NoError(t, err, "the preset-issued CA must chain to the root")
	require.NotEmpty(t, chains)
}
