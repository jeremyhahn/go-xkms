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

package piv

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"reflect"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

func enrolledCertificate(t *testing.T, e *qrdbsdk.AuthFactorEnrollment) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(e.PublicKey)
	if block == nil {
		t.Fatal("enrollment public key is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse enrollment certificate: %v", err)
	}
	return cert
}

// The PIV enrollment certificate names the enrollment tenant as OU[0].
func TestPIVFactor_Enroll_CertificateCarriesTenantOU(t *testing.T) {
	const tenant = "tenant-t"
	e, err := New(Config{}).Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{UserID: "u1", TenantID: tenant})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	cert := enrolledCertificate(t, e)
	if got := cert.Subject.OrganizationalUnit; !reflect.DeepEqual(got, []string{tenant}) {
		t.Fatalf("enrollment certificate OU = %v, want [%s]", got, tenant)
	}
	if e.TenantID != tenant {
		t.Fatalf("enrollment tenant = %q, want %q", e.TenantID, tenant)
	}
}

// An enrollment that names no tenant is refused: no certificate is issued
// without its tenant.
func TestPIVFactor_Enroll_RefusesEmptyTenant(t *testing.T) {
	e, err := New(Config{}).Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{UserID: "u1"})
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	if !errors.As(err, &inv) {
		t.Fatalf("Enroll without tenant err = %v, want AuthFactorEnrollmentInvalidError", err)
	}
	if e != nil {
		t.Fatal("a refused enrollment must return no enrollment")
	}
}

// A decoy enrollment's certificate carries the tenant OU its real
// counterparts carry, so the subject does not tell a decoy apart.
func TestDecoyEnrollment_CertificateCarriesLikeTenantOU(t *testing.T) {
	f := New(Config{})
	like := []*qrdbsdk.AuthFactorEnrollment{enrollHolder(t, "holder-1", nil), enrollHolder(t, "holder-2", nil)}
	d := decoyFor(t, f, decoySeed, "stranger", like)
	real := enrolledCertificate(t, like[0])
	got := enrolledCertificate(t, d)
	if !reflect.DeepEqual(got.Subject.OrganizationalUnit, real.Subject.OrganizationalUnit) ||
		len(got.Subject.OrganizationalUnit) == 0 || got.Subject.OrganizationalUnit[0] != d.TenantID {
		t.Fatalf("decoy OU = %v (tenant %q), real OU = %v", got.Subject.OrganizationalUnit, d.TenantID, real.Subject.OrganizationalUnit)
	}
}

// The ceremony rebuilds quorum roster enrollments with PublicKey and Metadata
// only (no TenantID). A decoy built from that roster carries the same tenant
// OU as the real holders' certificates, so an anonymous quorum challenge
// cannot tell a stranger from a holder by the OU.
func TestDecoyEnrollment_RosterShapedLikeCarriesHolderTenantOU(t *testing.T) {
	f := New(Config{})
	holders := []*qrdbsdk.AuthFactorEnrollment{enrollHolder(t, "holder-1", nil), enrollHolder(t, "holder-2", nil)}
	roster := make([]*qrdbsdk.AuthFactorEnrollment, 0, len(holders))
	for _, h := range holders {
		roster = append(roster, &qrdbsdk.AuthFactorEnrollment{
			UserID:     h.UserID,
			FactorName: h.FactorName,
			PublicKey:  h.PublicKey,
			Metadata:   h.Metadata,
		})
	}
	d := decoyFor(t, f, decoySeed, "stranger", roster)
	real := enrolledCertificate(t, holders[0])
	got := enrolledCertificate(t, d)
	if !reflect.DeepEqual(got.Subject.OrganizationalUnit, real.Subject.OrganizationalUnit) {
		t.Fatalf("roster decoy OU = %v, real holder OU = %v", got.Subject.OrganizationalUnit, real.Subject.OrganizationalUnit)
	}
	if got.Issuer.String() != got.Subject.String() {
		t.Fatalf("decoy issuer %q != subject %q", got.Issuer, got.Subject)
	}
}
