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

//go:build codec_json
// +build codec_json

// These tests build on createTestInfrastructure from test_helpers_test.go,
// which is itself gated on codec_json. Without the same tag the helper is
// absent and the package fails to compile under a plain `go vet ./...`.
package admin

import (
	"context"
	"crypto/x509"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// =============================================================================
// Certificate Policy Regression Suite (tenant CA issuance paths)
// =============================================================================
//
// The tenant root and intermediate CAs are created through pkg/ca like every
// other CA-issued certificate in go-xkms. These tests pin their policy surface
// so that routing them through the canonical path did not — and cannot later —
// change the key usage, basic constraints or path length a tenant CA carries.

// tenantPolicyGoldens pins the policy fingerprint of each tenant CA path.
var tenantPolicyGoldens = map[string]string{
	"tenant_root":         "4d95ded5d47ac5b7505c67dd234192537ac9090631e6a2b49a65fe868e06abd4",
	"tenant_intermediate": "79fe651e26830d46baa43bb5ce235f856762ce0751102adf007d51ce31db086e",
}

// newPolicyTestTenantService builds a TenantAwareAdminService with no keystore,
// no DAO and no KV service. Tenant CA creation degrades to in-memory caching in
// that configuration, which is exactly the surface these tests need.
func newPolicyTestTenantService() *TenantAwareAdminService {
	return &TenantAwareAdminService{
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		tenantCAs: make(map[string]*tenantCAEntry),
	}
}

// issueTenantCAPaths drives tenant root and intermediate CA creation and
// returns the resulting certificates keyed by path name.
func issueTenantCAPaths(t *testing.T) map[string]*x509.Certificate {
	t.Helper()
	ctx := context.Background()
	svc := newPolicyTestTenantService()

	rootInfo, err := svc.CreateTenantRootCA(ctx, "tenant-a", CreateTenantRootCARequest{
		CommonName:    "Tenant A Root CA",
		KeyAlgorithm:  "ECDSA",
		ValidityYears: 10,
	})
	require.NoError(t, err)
	require.NotNil(t, rootInfo)

	intInfo, err := svc.CreateTenantIntermediateCA(ctx, "tenant-a", CreateTenantIntermediateCARequest{
		CommonName:    "Tenant A Intermediate CA",
		KeyAlgorithm:  "ECDSA",
		ValidityYears: 5,
		ParentType:    "tenant",
	})
	require.NoError(t, err)
	require.NotNil(t, intInfo)

	svc.mu.RLock()
	entry := svc.tenantCAs["tenant-a"]
	svc.mu.RUnlock()
	require.NotNil(t, entry)
	require.NotNil(t, entry.rootCA)
	require.Len(t, entry.intermediateCAs, 1)

	certs := map[string]*x509.Certificate{"tenant_root": entry.rootCA}
	for _, ic := range entry.intermediateCAs {
		certs["tenant_intermediate"] = ic.cert
	}
	return certs
}

// TestCertificatePolicy_TenantCAPaths pins the policy surface of the tenant
// root and intermediate CA issuance paths.
func TestCertificatePolicy_TenantCAPaths(t *testing.T) {
	for name, cert := range issueTenantCAPaths(t) {
		t.Run(name, func(t *testing.T) {
			require.NotNil(t, cert)
			got := testutil.PolicyFingerprint(cert)
			want, ok := tenantPolicyGoldens[name]
			if !ok || want != got {
				t.Errorf("certificate policy changed for path %q\nwant fingerprint %s\ngot  fingerprint %s\npolicy:\n%s",
					name, want, got, testutil.RenderCertificatePolicy(cert))
			}
		})
	}
}

// TestCertificatePolicy_TenantRootIsSelfSignedCA asserts the properties that
// make a tenant root usable as a trust anchor, independently of the
// fingerprint: it is self-signed, it is a CA, and it can sign the tenant
// intermediate.
func TestCertificatePolicy_TenantRootIsSelfSignedCA(t *testing.T) {
	certs := issueTenantCAPaths(t)
	root := certs["tenant_root"]
	intermediate := certs["tenant_intermediate"]

	require.True(t, root.IsCA)
	require.True(t, root.BasicConstraintsValid)
	require.Equal(t, root.Subject.String(), root.Issuer.String())
	require.NoError(t, root.CheckSignatureFrom(root))

	require.True(t, intermediate.IsCA)
	require.Equal(t, root.Subject.String(), intermediate.Issuer.String())
	require.NoError(t, intermediate.CheckSignatureFrom(root))
}

// TestCertificatePolicy_PlatformProfileReachesTenantCAs asserts that a CA
// profile registered against the platform CA decides what a tenant CA carries.
//
// The tenant root used to be hand-signed here with its own hard-coded key
// usage and basic constraints, so no platform policy could reach it. Routing
// it through pkg/ca means the platform's CA profile is the one authority for
// every CA certificate the deployment creates.
func TestCertificatePolicy_PlatformProfileReachesTenantCAs(t *testing.T) {
	testCA, storageFactory, cleanup := createTestInfrastructure(t)
	defer cleanup()

	concrete, ok := testCA.(interface{ Profiles() ca.ProfileRegistry })
	require.True(t, ok, "the platform CA must expose its profile registry")

	// A stricter CA profile: certificate and CRL signing only.
	stricter := ca.NewProfileBuilder(ca.ProfileNameCA).
		WithKeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign).
		AsCA().
		Build()
	require.NoError(t, concrete.Profiles().Register(ca.ProfileNameCA, stricter))

	svc := NewTenantAwareAdminService(
		testCA,
		storageFactory,
		nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		"test",
	)

	ctx := context.Background()
	_, err := svc.CreateTenantRootCA(ctx, "tenant-strict", CreateTenantRootCARequest{
		CommonName:    "Strict Tenant Root CA",
		KeyAlgorithm:  "ECDSA",
		ValidityYears: 5,
	})
	require.NoError(t, err)

	svc.mu.RLock()
	root := svc.tenantCAs["tenant-strict"].rootCA
	svc.mu.RUnlock()

	require.NotNil(t, root)
	require.True(t, root.IsCA)
	require.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, root.KeyUsage,
		"the platform CA profile did not reach the tenant root")
	require.Zero(t, root.KeyUsage&x509.KeyUsageDigitalSignature)
}

// TestCertificatePolicy_TenantParentIdentity asserts which issuing identity's
// revocation endpoints a tenant intermediate inherits. An intermediate under a
// tenant's own root has no platform authority behind it and carries none; one
// under the platform CA inherits the platform CA's.
func TestCertificatePolicy_TenantParentIdentity(t *testing.T) {
	svc := newPolicyTestTenantService()
	require.Nil(t, svc.parentIdentity("tenant"))
	require.Nil(t, svc.parentIdentity("global"), "no platform CA is wired in this service")

	testCA, storageFactory, cleanup := createTestInfrastructure(t)
	defer cleanup()

	wired := NewTenantAwareAdminService(
		testCA,
		storageFactory,
		nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		"test",
	)
	require.Nil(t, wired.parentIdentity("tenant"))
	require.NotNil(t, wired.parentIdentity("global"))
}

// TestCertificatePolicy_DumpTenant writes the rendered policy of the tenant CA
// paths to the file named by XKMS_CERTPOLICY_DUMP.
func TestCertificatePolicy_DumpTenant(t *testing.T) {
	dump := os.Getenv("XKMS_CERTPOLICY_DUMP")
	certs := issueTenantCAPaths(t)
	var out []byte
	for _, name := range []string{"tenant_root", "tenant_intermediate"} {
		cert := certs[name]
		require.NotNil(t, cert, "path %s produced no certificate", name)
		out = append(out, []byte("=== "+name+"\n")...)
		out = append(out, []byte(testutil.RenderCertificatePolicy(cert))...)
		out = append(out, []byte("fingerprint="+testutil.PolicyFingerprint(cert)+"\n")...)
	}
	if dump == "" {
		return
	}
	require.NoError(t, os.WriteFile(dump, out, 0o600))
}
