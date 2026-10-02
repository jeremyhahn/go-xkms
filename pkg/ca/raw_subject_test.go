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

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// holderRawSubject encodes CN=cn, OU=ou[0], OU=ou[1], ... one RDN each, the
// layout go-qrdb's ceremony SignCSROptions.RawSubject produces.
func holderRawSubject(t *testing.T, cn string, ous ...string) []byte {
	t.Helper()
	rdns := pkix.RDNSequence{{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: cn}}}
	for _, ou := range ous {
		rdns = append(rdns, pkix.RelativeDistinguishedNameSET{{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: ou}})
	}
	der, err := asn1.Marshal(rdns)
	require.NoError(t, err)
	return der
}

// hostileCSR asks for another account's name and a SPIFFE identity, the way
// an officer registration could request a login it should not get.
func hostileCSR(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spiffeID, err := url.Parse("spiffe://example.com/tenant/globex/user/admin")
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "admin", OrganizationalUnit: []string{"system"}},
		DNSNames: []string{"admin.example.com"},
		URIs:     []*url.URL{spiffeID},
	}, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), key
}

// A raw subject is the whole name: the CSR's subject and every one of its
// subject alternative names are dropped, the key is kept, and the RDN order
// survives -- a tenant longer than the profile stays the first OU.
func TestSignCSR_RawSubjectIsTheWholeName(t *testing.T) {
	ca := setupTestCA(t)
	csrPEM, key := hostileCSR(t)
	raw := holderRawSubject(t, "officer-1", "a-tenant-with-a-long-name", "custodian")

	cert, err := ca.SignCSR(context.Background(), csrPEM, &SignOptions{RawSubject: raw})
	require.NoError(t, err)
	assert.Equal(t, raw, cert.RawSubject)
	assert.Equal(t, "officer-1", cert.Subject.CommonName)
	assert.Equal(t, []string{"a-tenant-with-a-long-name", "custodian"}, cert.Subject.OrganizationalUnit)
	assert.Empty(t, cert.DNSNames)
	assert.Empty(t, cert.URIs)
	assert.Empty(t, cert.EmailAddresses)
	assert.Empty(t, cert.IPAddresses)
	assert.True(t, key.PublicKey.Equal(cert.PublicKey), "the CSR's key is certified")
}

func TestSignCSR_RawSubjectRefusesAnotherSourceOfNames(t *testing.T) {
	ca := setupTestCA(t)
	csrPEM, _ := hostileCSR(t)
	raw := holderRawSubject(t, "officer-1", "system")

	for name, opts := range map[string]*SignOptions{
		"subject override": {RawSubject: raw, Subject: &Subject{CommonName: "x"}},
		"extra SANs":       {RawSubject: raw, SANS: &SubjectAlternativeNames{DNS: []string{"x.example.com"}}},
		"tenant SPIFFE":    {RawSubject: raw, SPIFFETrustDomain: "example.com", TenantID: "system"},
		"SPIFFE name":      {RawSubject: raw, SPIFFEName: "x"},
		"issuer otherName": {RawSubject: raw, OtherNames: []OtherName{{TypeID: OIDPermanentIdentifier, Value: []byte{0x30, 0x00}}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ca.SignCSR(context.Background(), csrPEM, opts)
			require.ErrorIs(t, err, ErrRawSubjectWithNames)
		})
	}
}

func TestSignCSR_RawSubjectMustBeADistinguishedName(t *testing.T) {
	ca := setupTestCA(t)
	csrPEM, _ := hostileCSR(t)
	empty, err := asn1.Marshal(pkix.RDNSequence{})
	require.NoError(t, err)
	for name, raw := range map[string][]byte{
		"not DER":        []byte("not a name"),
		"trailing bytes": append(holderRawSubject(t, "officer-1", "system"), 0x00),
		"empty sequence": empty,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ca.SignCSR(context.Background(), csrPEM, &SignOptions{RawSubject: raw})
			require.ErrorIs(t, err, ErrInvalidRawSubject)
		})
	}
}
