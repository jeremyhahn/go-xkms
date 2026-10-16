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

package ca_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	deviceattest01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/device-attest-01"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// permanentIdentifierOf returns the RFC 4043 permanentIdentifier value a
// certificate carries, or "" when it carries none.
func permanentIdentifierOf(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	otherNames, err := ca.ParseOtherNames(cert.Extensions)
	require.NoError(t, err)
	for _, other := range otherNames {
		if other.TypeID.Equal(ca.OIDPermanentIdentifier) {
			parsed, err := ca.ParsePermanentIdentifierExtension(other.Value)
			require.NoError(t, err)
			return parsed.IdentifierValue
		}
	}
	return ""
}

func csrWith(t *testing.T, template *x509.CertificateRequest) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// The CA copies no otherName a CSR requests, so an attested device's identity
// reaches its certificate only when the issuer passes it in SignOptions.
func TestSignCSR_OtherNamesFromTheIssuerReachTheCertificate(t *testing.T) {
	trustedCA := newIssuingCA(t, rootOnlyConfig(t, "OtherNames Root CA"), nil)
	identifier, err := ca.MarshalPermanentIdentifier("0102030405060708", nil)
	require.NoError(t, err)

	t.Run("an issuer-asserted permanentIdentifier is in the certificate beside the CSR's names", func(t *testing.T) {
		csr := csrWith(t, &x509.CertificateRequest{
			Subject:  pkix.Name{CommonName: "device-1"},
			DNSNames: []string{"device-1.example.com"},
		})

		cert, err := trustedCA.SignCSR(context.Background(), csr, &ca.SignOptions{
			TenantID:   e2eTenant,
			OtherNames: []ca.OtherName{{TypeID: ca.OIDPermanentIdentifier, Value: identifier}},
		})

		require.NoError(t, err)
		assert.Equal(t, "0102030405060708", permanentIdentifierOf(t, cert))
		assert.Equal(t, []string{"device-1.example.com"}, cert.DNSNames, "the CSR's own names are kept")
	})

	t.Run("one the CSR asked for is not copied", func(t *testing.T) {
		requested := csrWith(t, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "device-2"},
			ExtraExtensions: []pkix.Extension{{
				Id:    []int{2, 5, 29, 17},
				Value: mustSAN(t, "requested-by-the-device"),
			}},
		})

		cert, err := trustedCA.SignCSR(context.Background(), requested, &ca.SignOptions{TenantID: e2eTenant})

		require.NoError(t, err)
		assert.Empty(t, permanentIdentifierOf(t, cert), "a requester must not name its own otherName")
	})

	t.Run("a DICE possession request's extensions are not copied", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		nonce := deviceattest01.DICENonce("token.thumbprint")
		claims := &dice.ClaimsSet{Other: map[int64][]byte{
			dice.ClaimUeid:         {0x42, 0xfe, 0xed}, // CBOR bstr h'feed'
			dice.ClaimMeasurements: {0x00},
		}}
		der, err := deviceattest01.SignPossessionCSR(key, claims, nonce)
		require.NoError(t, err)
		requested := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

		cert, err := trustedCA.SignCSR(context.Background(), requested, &ca.SignOptions{
			TenantID:   e2eTenant,
			OtherNames: []ca.OtherName{{TypeID: ca.OIDPermanentIdentifier, Value: identifier}},
		})

		require.NoError(t, err)
		assert.Equal(t, "0102030405060708", permanentIdentifierOf(t, cert), "only the issuer's identity is asserted, not the one the request names")
		for _, ext := range cert.Extensions {
			assert.False(t, ext.Id.Equal(dice.OIDUccsEvidence), "the requested UCCS evidence was copied onto the certificate")
		}
	})

	t.Run("otherNames and a pre-encoded subjectAltName extension are not both honored", func(t *testing.T) {
		csr := csrWith(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "device-3"}})

		cert, err := trustedCA.SignCSR(context.Background(), csr, &ca.SignOptions{
			TenantID:        e2eTenant,
			OtherNames:      []ca.OtherName{{TypeID: ca.OIDPermanentIdentifier, Value: identifier}},
			ExtraExtensions: []pkix.Extension{{Id: []int{2, 5, 29, 17}, Value: mustSAN(t, "another")}},
		})

		assert.ErrorIs(t, err, ca.ErrInvalidCertificate)
		assert.Nil(t, cert)
	})
}

// mustSAN encodes a subjectAltName carrying the permanentIdentifier otherName a
// device could request.
func mustSAN(t *testing.T, identifier string) []byte {
	t.Helper()
	value, err := ca.MarshalPermanentIdentifier(identifier, nil)
	require.NoError(t, err)
	san, err := ca.BuildSubjectAltName(pkix.Name{}, nil, nil, nil, nil, []ca.OtherName{{TypeID: ca.OIDPermanentIdentifier, Value: value}}, nil)
	require.NoError(t, err)
	return san.Value
}
