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

package ca

// Tests for CA.IssueLAKCertificateRaw (pkg/ca/service_adapter.go), the
// primitive-typed adapter every transport (REST, gRPC, Unix, QUIC, MCP,
// embedded) reaches IssueLAKCertificate through. setupTestCA (not the
// external-signer fixtures in tcg_lak_test.go) is used here because the Raw
// adapter never carries a request.Signer/IssuerCert -- it always signs with
// the CA's own internal identity -- so the evidence must be built against a
// real, internally-signed IAK certificate.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/certstore"
)

// issueInternalTestIAK issues an IAK-shaped certificate (tcg-kp-AIKCertificate
// EKU, CA:false) signed by ca's own internal identity, for use as the raw
// adapter's iakCertDER input.
func issueInternalTestIAK(t *testing.T, ca *CA, iakKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	cert, err := ca.IssueAKCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "iak-raw-fixture"},
	}, iakKey.Public())
	if err != nil {
		t.Fatalf("IssueAKCertificate() for IAK fixture: %v", err)
	}
	return cert.Raw
}

func TestIssueLAKCertificateRaw_Success(t *testing.T) {
	ca := setupTestCA(t)

	iakKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate iak key: %v", err)
	}
	iakCertDER := issueInternalTestIAK(t, ca, iakKey)

	lakKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate lak key: %v", err)
	}
	lakPubArea := lakFixturePublicArea(t, &lakKey.PublicKey)
	nonce := []byte("nonce-TestIssueLAKCertificateRaw_Success")
	certifyInfo, sig := buildLAKCertifyEvidence(t, iakKey, lakPubArea, nonce)

	certDER, err := ca.IssueLAKCertificateRaw(
		context.Background(),
		"id:49465800", "NPCT6xx", "7.2.3.1",
		iakCertDER,
		certifyInfo, sig,
		x509.ECDSAWithSHA256,
		lakPubArea, nonce,
	)
	if err != nil {
		t.Fatalf("IssueLAKCertificateRaw() returned unexpected error: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse issued LAK certificate: %v", err)
	}
	if cert.Subject.String() != "" {
		t.Errorf("LAK Subject = %q, want empty", cert.Subject.String())
	}

	stored, err := ca.certStore.GetCertificate(certstore.CertificateKey(cert))
	if err != nil {
		t.Fatalf("LAK certificate not retrievable from the store: %v", err)
	}
	if string(stored.Raw) != string(cert.Raw) {
		t.Error("stored LAK record differs from the certificate returned to the caller")
	}
}

func TestIssueLAKCertificateRaw_InvalidIAKCertificateDER(t *testing.T) {
	ca := setupTestCA(t)

	_, err := ca.IssueLAKCertificateRaw(
		context.Background(),
		"id:49465800", "NPCT6xx", "7.2.3.1",
		[]byte("not-a-certificate"),
		[]byte("certify-info"), []byte("signature"),
		x509.ECDSAWithSHA256,
		[]byte("lak-public-area"), []byte("nonce"),
	)
	if err == nil {
		t.Fatal("IssueLAKCertificateRaw() error = nil, want a parse error for garbage IAK certificate DER")
	}
}
