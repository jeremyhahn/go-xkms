// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Ruling 1073 (a): a tenant certificate must name its tenant as Subject
// OU[0]; FIDO2 attestation, TCG LAK and system CA subjects are exempt.

func TestCheckOwnerOU_TenantLeafWithoutOURefused(t *testing.T) {
	subject := pkix.Name{CommonName: "leaf.example", OrganizationalUnit: []string{"other"}}
	err := CheckOwnerOU(OwnerOUKindTenantLeaf, "tenant-a", subject)
	if !errors.Is(err, ErrOwnerOUMissing) {
		t.Fatalf("CheckOwnerOU = %v, want ErrOwnerOUMissing", err)
	}
	if err := CheckOwnerOU(OwnerOUKindTenantLeaf, "tenant-a", pkix.Name{CommonName: "leaf.example"}); !errors.Is(err, ErrOwnerOUMissing) {
		t.Fatalf("CheckOwnerOU empty OU = %v, want ErrOwnerOUMissing", err)
	}
}

func TestCheckOwnerOU_TenantLeafWithOUPasses(t *testing.T) {
	subject := pkix.Name{CommonName: "leaf.example", OrganizationalUnit: []string{"tenant-a"}}
	if err := CheckOwnerOU(OwnerOUKindTenantLeaf, "tenant-a", subject); err != nil {
		t.Fatalf("CheckOwnerOU = %v, want nil", err)
	}
}

func TestCheckOwnerOU_TenantCAWithoutOURefused(t *testing.T) {
	if err := CheckOwnerOU(OwnerOUKindTenantCA, "tenant-a", pkix.Name{CommonName: "Tenant CA"}); !errors.Is(err, ErrOwnerOUMissing) {
		t.Fatalf("CheckOwnerOU tenant CA = %v, want ErrOwnerOUMissing", err)
	}
}

func TestCheckOwnerOU_ExemptKindsPass(t *testing.T) {
	fido2 := pkix.Name{CommonName: "Authenticator", OrganizationalUnit: []string{FIDO2AttestationCertificateOU}}
	for name, tc := range map[string]struct {
		kind    OwnerOUKind
		subject pkix.Name
	}{
		"fido2 attestation":   {OwnerOUKindFIDO2Attestation, fido2},
		"tcg lak":             {OwnerOUKindTCGLAK, pkix.Name{}},
		"system root":         {OwnerOUKindSystemCA, pkix.Name{CommonName: "Root CA"}},
		"system intermediate": {OwnerOUKindSystemCA, pkix.Name{CommonName: "Intermediate CA"}},
	} {
		if err := CheckOwnerOU(tc.kind, "tenant-a", tc.subject); err != nil {
			t.Errorf("%s: CheckOwnerOU = %v, want nil", name, err)
		}
	}
}

func TestOwnerOUKindFor(t *testing.T) {
	for name, tc := range map[string]struct {
		profile  string
		isCA     bool
		tenantID string
		want     OwnerOUKind
	}{
		"fido2 attestation": {ProfileNameFIDO2Attestation, false, "tenant-a", OwnerOUKindFIDO2Attestation},
		"tcg lak":           {ProfileNameTCGLocalAK, false, "tenant-a", OwnerOUKindTCGLAK},
		"tenant leaf":       {"", false, "tenant-a", OwnerOUKindTenantLeaf},
		"tenant ca":         {"", true, "tenant-a", OwnerOUKindTenantCA},
		"system ca":         {"", true, "", OwnerOUKindSystemCA},
	} {
		if got := OwnerOUKindFor(tc.profile, tc.isCA, tc.tenantID); got != tc.want {
			t.Errorf("%s: OwnerOUKindFor = %v, want %v", name, got, tc.want)
		}
	}
}

func TestCreateHybridCertificate_TenantCATemplateCarriesTenantOU(t *testing.T) {
	classicalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	quantumKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)
	tmpl := makeHybridCACertTemplate()
	der, err := CreateHybridCertificate("tenant-t", tmpl, tmpl, classicalKey, quantumKey)
	if err != nil {
		t.Fatalf("CreateHybridCertificate tenant CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse tenant CA: %v", err)
	}
	if ou := cert.Subject.OrganizationalUnit; len(ou) == 0 || ou[0] != "tenant-t" {
		t.Fatalf("tenant CA OU = %v, want [tenant-t]", ou)
	}
	if string(cert.RawIssuer) != string(cert.RawSubject) {
		t.Fatal("self-signed tenant CA issuer differs from its subject")
	}
	if len(tmpl.Subject.OrganizationalUnit) != 0 {
		t.Fatalf("caller template mutated: OU = %v", tmpl.Subject.OrganizationalUnit)
	}
}
