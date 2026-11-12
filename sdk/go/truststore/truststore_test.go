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

package truststore_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	pkgtruststore "github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/sdk/go/truststore"
)

// The SDK names must be aliases of the pkg types, not new types: a value of
// one assigns to the other without conversion.
var (
	_ *pkgtruststore.CertMetadata = (*truststore.CertMetadata)(nil)
	_ *truststore.CertMetadata    = (*pkgtruststore.CertMetadata)(nil)
	_ pkgtruststore.OSCertStore   = truststore.OSCertStore(nil)
	_ truststore.OSCertStore      = pkgtruststore.OSCertStore(nil)

	_ func(*x509.Certificate) pkgtruststore.CertPurpose = truststore.ClassifyCertificate
)

func TestErrorsAreThePkgValues(t *testing.T) {
	cases := map[string][2]error{
		"ErrInvalidCertificate": {truststore.ErrInvalidCertificate, pkgtruststore.ErrInvalidCertificate},
		"ErrPermissionDenied":   {truststore.ErrPermissionDenied, pkgtruststore.ErrPermissionDenied},
		"ErrRemoveFailed":       {truststore.ErrRemoveFailed, pkgtruststore.ErrRemoveFailed},
	}
	for name, pair := range cases {
		if pair[0] == nil || pair[0] != pair[1] {
			t.Errorf("%s: sdk %v, pkg %v", name, pair[0], pair[1])
		}
	}
}

func TestClassifyCertificateForwards(t *testing.T) {
	cert := &x509.Certificate{
		IsCA:    true,
		Issuer:  pkix.Name{CommonName: "sdk-truststore-test"},
		Subject: pkix.Name{CommonName: "sdk-truststore-test"},
	}
	got := truststore.ClassifyCertificate(cert)
	if got != truststore.PurposeUserCA {
		t.Fatalf("ClassifyCertificate = %q, want %q", got, truststore.PurposeUserCA)
	}
	if want := pkgtruststore.ClassifyCertificate(cert); got != want {
		t.Fatalf("sdk %q, pkg %q", got, want)
	}
}

func TestCertMetadataFields(t *testing.T) {
	meta := truststore.CertMetadata{Purpose: truststore.PurposeBootstrapCA}
	var pkgMeta pkgtruststore.CertMetadata = meta
	if pkgMeta.Purpose != pkgtruststore.PurposeBootstrapCA {
		t.Fatalf("Purpose = %q", pkgMeta.Purpose)
	}
}
