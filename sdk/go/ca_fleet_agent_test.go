// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xkms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"testing"

	pkgca "github.com/jeremyhahn/go-xkms/pkg/ca"
)

// TestFleetAgentReExports_AliasPkgCA proves the fleet agent claim's SDK
// names are the pkg/ca values, so go-quicbaas's errors.Is checks match.
func TestFleetAgentReExports_AliasPkgCA(t *testing.T) {
	if !OIDFleetAgent.Equal(pkgca.OIDFleetAgent) {
		t.Fatalf("OIDFleetAgent = %v, want %v", OIDFleetAgent, pkgca.OIDFleetAgent)
	}
	errorCases := map[string]struct{ sdk, canonical error }{
		"ErrCAFleetAgentClaimRequested": {ErrCAFleetAgentClaimRequested, pkgca.ErrFleetAgentClaimRequested},
		"ErrCAFleetAgentClaimReserved":  {ErrCAFleetAgentClaimReserved, pkgca.ErrFleetAgentClaimReserved},
		"ErrCAFleetAgentClaimAbsent":    {ErrCAFleetAgentClaimAbsent, pkgca.ErrFleetAgentClaimAbsent},
		"ErrCAFleetAgentClaimMalformed": {ErrCAFleetAgentClaimMalformed, pkgca.ErrFleetAgentClaimMalformed},
		"ErrCAFleetAgentClaimUntrusted": {ErrCAFleetAgentClaimUntrusted, pkgca.ErrFleetAgentClaimUntrusted},
	}
	for name, tc := range errorCases {
		if tc.sdk != tc.canonical {
			t.Errorf("%s does not alias pkg/ca", name)
		}
	}
}

// TestSDK_FleetAgentClaim stamps the claim through the SDK's
// TrustedCASignOptions, verifies it against the issuing CA, and refuses it
// against another CA. A CSR requesting the claim yields no certificate.
func TestSDK_FleetAgentClaim(t *testing.T) {
	ctx := context.Background()
	trustedCA := newSDKTestCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := trustedCA.SignCSR(ctx, sdkCSR(t, key), &TrustedCASignOptions{TenantID: sdkTestTenant, FleetAgent: true})
	if err != nil {
		t.Fatalf("sign with FleetAgent: %v", err)
	}
	if err := VerifyFleetAgentClaim(cert, sdkFleetRoots(t, trustedCA)); err != nil {
		t.Fatalf("verify against the issuer: %v", err)
	}

	otherCA := newSDKTestCA(t)
	if err := VerifyFleetAgentClaim(cert, sdkFleetRoots(t, otherCA)); !errors.Is(err, ErrCAFleetAgentClaimUntrusted) {
		t.Fatalf("verify against another CA: err = %v, want ErrCAFleetAgentClaimUntrusted", err)
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: "node-1"},
		ExtraExtensions: []pkix.Extension{{Id: OIDFleetAgent, Value: []byte{0x05, 0x00}}},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	requesting := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	refused, err := trustedCA.SignCSR(ctx, requesting, &TrustedCASignOptions{TenantID: sdkTestTenant})
	if !errors.Is(err, ErrCAFleetAgentClaimRequested) || refused != nil {
		t.Fatalf("CSR requesting the claim: cert = %v, err = %v, want ErrCAFleetAgentClaimRequested", refused, err)
	}
}

// sdkFleetRoots returns verify options trusting only trustedCA's certificate.
func sdkFleetRoots(t *testing.T, trustedCA TrustedCA) x509.VerifyOptions {
	t.Helper()
	root, err := trustedCA.CACertificate()
	if err != nil {
		t.Fatalf("CA certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return x509.VerifyOptions{Roots: roots}
}
