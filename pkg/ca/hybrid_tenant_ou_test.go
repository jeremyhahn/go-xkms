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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/quantum"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func makeHybridLeafTemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject: pkix.Name{
			CommonName:         "hybrid-leaf",
			Organization:       []string{"Test Org"},
			OrganizationalUnit: []string{"other-tenant"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

// hybridTestIssuer returns a self-signed hybrid CA and its keys.
func hybridTestIssuer(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *quantum.MLDSAPrivateKey) {
	t.Helper()
	classicalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	quantumKey := generateTestMLDSAKey(t, types.QuantumAlgorithmMLDSA65)
	caTemplate := makeHybridCACertTemplate()
	caDER, err := CreateHybridCertificate("", caTemplate, caTemplate, classicalKey, quantumKey)
	if err != nil {
		t.Fatalf("CreateHybridCertificate CA: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return caCert, classicalKey, quantumKey
}

func TestCreateHybridCertificate_LeafCarriesTenantOU(t *testing.T) {
	caCert, classicalKey, quantumKey := hybridTestIssuer(t)
	leaf := makeHybridLeafTemplate()
	before := *leaf
	beforeOU := append([]string(nil), leaf.Subject.OrganizationalUnit...)

	const tenant = "tenant-t"
	leafDER, err := CreateHybridCertificate(tenant, leaf, caCert, classicalKey, quantumKey)
	if err != nil {
		t.Fatalf("CreateHybridCertificate leaf: %v", err)
	}
	parsed, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if got := parsed.Subject.OrganizationalUnit; !reflect.DeepEqual(got, []string{tenant}) {
		t.Fatalf("leaf OU = %v, want [%s]", got, tenant)
	}
	if err := VerifyHybridCertificate(leafDER, caCert, quantumKey.PublicKey); err != nil {
		t.Fatalf("VerifyHybridCertificate leaf: %v", err)
	}

	if !reflect.DeepEqual(leaf.Subject.OrganizationalUnit, beforeOU) ||
		!reflect.DeepEqual(leaf.Subject, before.Subject) ||
		leaf.RawSubject != nil {
		t.Fatalf("caller template mutated: subject %+v", leaf.Subject)
	}
}

func TestCreateHybridCertificate_LeafRequiresTenant(t *testing.T) {
	caCert, classicalKey, quantumKey := hybridTestIssuer(t)
	_, err := CreateHybridCertificate("", makeHybridLeafTemplate(), caCert, classicalKey, quantumKey)
	if !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("err = %v, want ErrTenantRequired", err)
	}
	var hybridErr *HybridCertError
	if !errors.As(err, &hybridErr) || hybridErr.Op != "create" {
		t.Fatalf("err = %v, want *HybridCertError{Op: create}", err)
	}
}

func TestCreateHybridCertificate_CAKeepsSubject(t *testing.T) {
	caCert, _, _ := hybridTestIssuer(t)
	want := makeHybridCACertTemplate().Subject
	if got := caCert.Subject.OrganizationalUnit; len(got) != 0 {
		t.Fatalf("CA OU = %v, want none", got)
	}
	if caCert.Subject.CommonName != want.CommonName ||
		!reflect.DeepEqual(caCert.Subject.Organization, want.Organization) ||
		!reflect.DeepEqual(caCert.Subject.Country, want.Country) {
		t.Fatalf("CA subject = %+v, want %+v", caCert.Subject, want)
	}
}

// A raw subject whose RDN SET holds two OUs (OU=a, OU=system) must not let DER
// SET sorting move another OU ahead of the stamped tenant: the parsed
// certificate names the tenant as OU[0], or the subject is refused.
func TestCreateHybridCertificate_RawMultiOUSetKeepsTenantFirst(t *testing.T) {
	caCert, classicalKey, quantumKey := hybridTestIssuer(t)
	oidOU := asn1.ObjectIdentifier{2, 5, 4, 11}
	oidCN := asn1.ObjectIdentifier{2, 5, 4, 3}
	raw, err := asn1.Marshal(pkix.RDNSequence{
		{{Type: oidCN, Value: "leaf"}},
		{{Type: oidOU, Value: "a"}, {Type: oidOU, Value: "system"}},
	})
	if err != nil {
		t.Fatalf("marshal raw subject: %v", err)
	}
	leaf := makeHybridLeafTemplate()
	leaf.RawSubject = raw

	const tenant = "tenant-t"
	leafDER, err := CreateHybridCertificate(tenant, leaf, caCert, classicalKey, quantumKey)
	if err != nil {
		if !errors.Is(err, ErrInvalidRawSubject) {
			t.Fatalf("CreateHybridCertificate: err = %v, want ErrInvalidRawSubject or success", err)
		}
		return
	}
	parsed, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if ou := parsed.Subject.OrganizationalUnit; len(ou) == 0 || ou[0] != tenant {
		t.Fatalf("leaf OU = %v, want OU[0] = %s", ou, tenant)
	}
}

// A self-signed hybrid leaf (parent == template) names the stamped subject as
// its issuer too, and the caller's template is left untouched.
func TestCreateHybridCertificate_SelfSignedLeafIssuerIsSubject(t *testing.T) {
	_, classicalKey, quantumKey := hybridTestIssuer(t)
	leaf := makeHybridLeafTemplate()
	before := leaf.Subject.String()

	const tenant = "tenant-t"
	der, err := CreateHybridCertificate(tenant, leaf, leaf, classicalKey, quantumKey)
	if err != nil {
		t.Fatalf("CreateHybridCertificate self-signed: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if got := parsed.Subject.OrganizationalUnit; !reflect.DeepEqual(got, []string{tenant}) {
		t.Fatalf("leaf OU = %v, want [%s]", got, tenant)
	}
	if string(parsed.RawIssuer) != string(parsed.RawSubject) {
		t.Fatalf("issuer %q != subject %q", parsed.Issuer, parsed.Subject)
	}
	if leaf.Subject.String() != before || leaf.RawSubject != nil {
		t.Fatalf("caller template mutated: subject %+v", leaf.Subject)
	}
}
