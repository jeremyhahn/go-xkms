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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// =============================================================================
// Certificate Policy Regression Suite (pkg/ca issuance paths)
// =============================================================================
//
// Every CA-issued certificate in go-xkms is created by Issuer.Issue. These
// tests pin the policy surface of each issuance path that used to construct
// its own x509.Certificate template, so that a change to the canonical path
// cannot silently alter an extended key usage, a path length or a set of
// extensions on any one of them.
//
// The fingerprint deliberately excludes the serial number, the absolute
// validity instants and everything derived from key material — see
// testutil.CertificatePolicyOf.

// caPolicyGoldens pins the policy fingerprint of each pkg/ca issuance path.
// A deliberate policy change updates these; an accidental one fails the build.
var caPolicyGoldens = map[string]string{
	"root":                "7bba11261e267fe9de786327a6a90ed919943b949d9071fc7192ddc3a5cb8b5f",
	"leaf_no_profile":     "f3504bb4896ac1d445b3791e146d845ebded6bdbd6fa7584e547e2a43d580418",
	"leaf_server_profile": "9aa2c2df622bd5a7f4a5e587b882bc9788a7d5b5c1adb2c55ea28154cb55ec6b",
	"leaf_ca_profile":     "685341dd3605b6bed20fa3258383844c72cdbec64004eb2e2340a5a9a97e9bd1",
	// tcg_ek changed 2026-09-08 (TCG DevID §8.1 conformance): the permanent
	// identifier moved from a standalone extension under the RFC 4043
	// otherName OID into subjectAltName where the otherName belongs; the device
	// model moved from tcg-at-tpmModel to tcg-at-platformModel and the device
	// serial out of tcg-at-tpmVersion into the subject's serialNumber
	// attribute, per §8.1 "the subject field's DN encoding SHOULD include the
	// 'serialNumber' attribute". Verified field by field against the renderer's
	// output before and after, not re-pinned blindly.
	//
	// Changed again 2026-09-23 (#715): the tcg-kp-EKCertificate marker
	// (2.23.133.8.1) moved out of a standalone extension under its own Id and
	// into the standard ExtKeyUsage extension's unknown_ext_key_usage, where
	// RFC 5280 section 4.2.1.12 puts extended key usage purposes and where
	// requireTCGEKCertificateEKU already looked for it.
	"tcg_ek": "f6d77797f0bacb5e642ab3d39068fc0048c64fdd7443998310ec64b3e121364a",
	// tcg_ak changed 2026-09-04 (#358): the certificatePolicies extension
	// carries tcg-cap-verifiedTPMRestricted (2.23.133.11.1.3). TCG DevID v1 r12
	// §8.2 makes checking it a MUST for a relying party evaluating an
	// attestation, and it was never issued.
	//
	// Changed again 2026-09-08 (TCG DevID §8.1/§8.2 conformance): the
	// certificate no longer carries tcg-cap-verifiedTPMFixed, which §8.2 says
	// "MUST NOT be combined with TCG-CE-FixedTPM-RestrictedKey"; and the
	// extended key usage gained 2.23.133.11.1.3, "the one TCG OID most
	// appropriate for the type of key used" per §8.1. Both diffs read off the
	// renderer's output before and after; every other field is unchanged.
	//
	// Changed again 2026-09-23 (#715, WebAuthn L2 §8.3.1 TPM Attestation
	// Statement Certificate Requirements): the tcg-kp-AIKCertificate marker
	// (2.23.133.8.3) moved out of a standalone extension and into the standard
	// ExtKeyUsage extension, where go-webauthn's "tpm" attestation format
	// verifier requires it; and basicConstraints is now explicitly asserted
	// with CA:false (requirement 5), which the TCG spec never mentions for an
	// AK/IAK certificate and therefore does not forbid.
	"tcg_ak": "a5cdb57d553972da4e23942823c7c052dcdf8f23acf85c67b1cc513fceb31512",
}

// caPolicyCase names one issuance path and the certificate it produced.
type caPolicyCase struct {
	name string
	cert *x509.Certificate
}

// issueAllCAPaths drives every pkg/ca issuance path against a single CA and
// returns the resulting certificates. The CA is configured without revocation
// endpoints so this reflects the historical, endpoint-free baseline.
func issueAllCAPaths(t *testing.T) []caPolicyCase {
	t.Helper()
	ctx := context.Background()
	testCA := setupTestCA(t)

	cases := []caPolicyCase{
		{name: "root", cert: testCA.rootCert},
	}

	// Leaf issued from a CSR with no profile: the historical default key usage
	// and extended key usage.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "leaf.example.com"},
		DNSNames: []string{"leaf.example.com"},
	}, leafKey)
	require.NoError(t, err)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	leaf, err := testCA.SignCSR(ctx, csrPEM, &SignOptions{TenantID: testTenant})
	require.NoError(t, err)
	cases = append(cases, caPolicyCase{name: "leaf_no_profile", cert: leaf})

	leafServer, err := testCA.SignCSR(ctx, csrPEM, &SignOptions{TenantID: testTenant, Profile: "server"})
	require.NoError(t, err)
	cases = append(cases, caPolicyCase{name: "leaf_server_profile", cert: leafServer})

	leafCA, err := testCA.SignCSR(ctx, csrPEM, &SignOptions{TenantID: testTenant, Profile: "ca"})
	require.NoError(t, err)
	cases = append(cases, caPolicyCase{name: "leaf_ca_profile", cert: leafCA})

	// TCG endorsement and attestation key certificates.
	ekKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ekCert, err := testCA.IssueEKCertificate(ctx, &CertificateRequest{
		TenantID:    testTenant,
		Subject:     Subject{CommonName: "tpm-ek", Organization: "Test Organization"},
		ProdModel:   "model-1",
		ProdSerial:  "serial-1",
		PermanentID: "perm-1",
	}, &ekKey.PublicKey)
	require.NoError(t, err)
	cases = append(cases, caPolicyCase{name: "tcg_ek", cert: ekCert})

	akKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	akCert, err := testCA.IssueAKCertificate(ctx, &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "tpm-ak", Organization: "Test Organization"},
	}, &akKey.PublicKey)
	require.NoError(t, err)
	cases = append(cases, caPolicyCase{name: "tcg_ak", cert: akCert})

	return cases
}

// TestCertificatePolicy_PkgCAPaths pins the policy surface of every pkg/ca
// issuance path.
func TestCertificatePolicy_PkgCAPaths(t *testing.T) {
	for _, c := range issueAllCAPaths(t) {
		t.Run(c.name, func(t *testing.T) {
			require.NotNil(t, c.cert)
			got := testutil.PolicyFingerprint(c.cert)
			want, ok := caPolicyGoldens[c.name]
			if !ok || want != got {
				t.Errorf("certificate policy changed for path %q\nwant fingerprint %s\ngot  fingerprint %s\npolicy:\n%s",
					c.name, want, got, testutil.RenderCertificatePolicy(c.cert))
			}
		})
	}
}

// =============================================================================
// Policy Reach: one configuration change, every issuance path
// =============================================================================

// Endpoints configured on the issuing identity for the reach tests. Their
// exact values do not matter; that every path carries them does.
const (
	reachOCSPServer = "http://ocsp.reach.example.com"
	reachCRLPoint   = "http://crl.reach.example.com/ca.crl"
	reachCAIssuer   = "http://aia.reach.example.com/ca.cer"
)

// setupTestCAWithEndpoints creates an initialized CA whose issuing identity
// declares revocation and Authority Information Access endpoints. It mirrors
// setupTestCA and differs only in that configuration.
func setupTestCAWithEndpoints(t *testing.T) *CA {
	t.Helper()

	keyStorage := storage.NewMemory()
	swBackend, err := software.NewBackend(&software.Config{KeyStorage: keyStorage})
	require.NoError(t, err)

	backend, err := xkms.New(&xkms.BackendConfig{
		Backend:     swBackend,
		CertStorage: storage.NewMemory(),
	})
	require.NoError(t, err)

	cs, err := certstore.New(&certstore.Config{
		DAOs: testutil.NewMemoryDAOFactory(),
	})
	require.NoError(t, err)

	config := DefaultMultiIdentityCAConfig()
	config.Identity[0].Subject.CommonName = "Reach Root CA"
	config.Identity[0].Subject.Organization = "Test Organization"
	config.Identity[0].Keys[0].KeyType = "CA"
	config.Identity[0].OCSPServers = []string{reachOCSPServer}
	config.Identity[0].CRLDistributionPoints = []string{reachCRLPoint}
	config.Identity[0].IssuingCertificateURLs = []string{reachCAIssuer}

	caIface, err := NewFromMultiIdentityConfig(&MultiIdentityParams{
		Config:          config,
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
	})
	require.NoError(t, err)
	require.NoError(t, caIface.Init(context.Background()))

	concrete, ok := caIface.(*CA)
	require.True(t, ok)
	return concrete
}

// TestCertificatePolicy_EndpointsReachEveryPath is the regression this whole
// consolidation exists to prevent.
//
// Adding an OCSP responder to the issuing identity is a single configuration
// change. Before every issuance path was routed through Issuer.Issue it
// reached only the certificates pkg/ca's own CSR-signing path produced: the
// TCG credential paths built their own templates and never called
// applyRevocationEndpoints, so a TPM device certificate silently carried no
// revocation information at all.
//
// If this test fails for one path, that path has stopped going through the
// canonical issuer.
func TestCertificatePolicy_EndpointsReachEveryPath(t *testing.T) {
	ctx := context.Background()
	testCA := setupTestCAWithEndpoints(t)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "reach.example.com"},
	}, leafKey)
	require.NoError(t, err)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	leaf, err := testCA.SignCSR(ctx, csrPEM, &SignOptions{TenantID: testTenant})
	require.NoError(t, err)

	leafWithProfile, err := testCA.SignCSR(ctx, csrPEM, &SignOptions{TenantID: testTenant, Profile: "server"})
	require.NoError(t, err)

	ekKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ekCert, err := testCA.IssueEKCertificate(ctx, &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "reach-ek"},
	}, &ekKey.PublicKey)
	require.NoError(t, err)

	akKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	akCert, err := testCA.IssueAKCertificate(ctx, &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "reach-ak"},
	}, &akKey.PublicKey)
	require.NoError(t, err)

	paths := map[string]*x509.Certificate{
		"root":                testCA.rootCert,
		"leaf_no_profile":     leaf,
		"leaf_server_profile": leafWithProfile,
		"tcg_ek":              ekCert,
		"tcg_ak":              akCert,
	}

	for name, cert := range paths {
		t.Run(name, func(t *testing.T) {
			require.NotNil(t, cert)
			require.Equal(t, []string{reachOCSPServer}, cert.OCSPServer,
				"path %q does not carry the issuing identity's OCSP responder", name)
			require.Equal(t, []string{reachCRLPoint}, cert.CRLDistributionPoints,
				"path %q does not carry the issuing identity's CRL distribution point", name)
			require.Equal(t, []string{reachCAIssuer}, cert.IssuingCertificateURL,
				"path %q does not carry the issuing identity's CA issuer URL", name)
		})
	}
}

// TestCertificatePolicy_ProfileChangeReachesCAPaths asserts that re-registering
// the CA profile changes the root and every intermediate together. Root,
// intermediate and per-tenant CA certificates are all issued with the profile
// named ProfileNameCA precisely so they cannot drift apart.
func TestCertificatePolicy_ProfileChangeReachesCAPaths(t *testing.T) {
	ctx := context.Background()
	testCA := setupTestCA(t)

	// A stricter CA profile: no digital signature, and subordinate CAs may not
	// themselves issue CAs.
	stricter := NewProfileBuilder(ProfileNameCA).
		WithKeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign).
		AsCA().
		Build()
	require.NoError(t, testCA.profiles.Register(ProfileNameCA, stricter))

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "sub.example.com"},
	}, leafKey)
	require.NoError(t, err)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	sub, err := testCA.SignCSR(ctx, csrPEM, &SignOptions{TenantID: testTenant, Profile: ProfileNameCA})
	require.NoError(t, err)

	require.True(t, sub.IsCA)
	require.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, sub.KeyUsage,
		"the re-registered CA profile did not reach the CSR-signing path")
	require.Zero(t, sub.KeyUsage&x509.KeyUsageDigitalSignature)
}

// TestCertificatePolicy_IssueRequiresProfile asserts that the canonical issuer
// refuses to build a certificate without a profile. That refusal is what
// guarantees no issuance path can bypass Profile.Apply.
func TestCertificatePolicy_IssueRequiresProfile(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuer := &Issuer{Signer: key}
	_, err = issuer.Issue(rand.Reader, &CertificateSpec{
		Serial:  big.NewInt(1),
		Subject: pkix.Name{CommonName: "no-profile"},
	})
	require.ErrorIs(t, err, ErrInvalidProfile)
}

// TestCertificatePolicy_IssueRejectsIncompleteIssuer asserts the issuer
// validates its own inputs rather than panicking inside crypto/x509.
func TestCertificatePolicy_IssueRejectsIncompleteIssuer(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = (&Issuer{}).Issue(rand.Reader, &CertificateSpec{
		Serial:  big.NewInt(1),
		Profile: NewCAProfile(),
	})
	require.ErrorIs(t, err, ErrInvalidIssuer)

	_, err = (&Issuer{Signer: key}).Issue(rand.Reader, nil)
	require.ErrorIs(t, err, ErrInvalidCertificate)

	_, err = (&Issuer{Signer: key}).Issue(rand.Reader, &CertificateSpec{
		Profile: NewCAProfile(),
	})
	require.ErrorIs(t, err, ErrInvalidCertificate)
}

// TestCertificatePolicy_DumpPkgCA writes the rendered policy of every pkg/ca
// issuance path to the file named by XKMS_CERTPOLICY_DUMP. It exists so the
// before/after comparison of an issuance refactor can be produced mechanically
// rather than by eye; with the variable unset it is a no-op assertion that
// every path still produces a certificate.
func TestCertificatePolicy_DumpPkgCA(t *testing.T) {
	dump := os.Getenv("XKMS_CERTPOLICY_DUMP")
	var out []byte
	for _, c := range issueAllCAPaths(t) {
		require.NotNil(t, c.cert, "path %s produced no certificate", c.name)
		out = append(out, []byte("=== "+c.name+"\n")...)
		out = append(out, []byte(testutil.RenderCertificatePolicy(c.cert))...)
		out = append(out, []byte("fingerprint="+testutil.PolicyFingerprint(c.cert)+"\n")...)
	}
	if dump == "" {
		return
	}
	require.NoError(t, os.WriteFile(dump, out, 0o600))
}
