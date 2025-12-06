// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package certstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ========================================================================
// Test OIDToName
// ========================================================================

func TestOIDToName_KnownTCGOID(t *testing.T) {
	oid := asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	name := OIDToName(oid)
	assert.Equal(t, "tcg-at-tpmManufacturer", name)
}

func TestOIDToName_KnownTrustedPlatformOID(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 1}
	name := OIDToName(oid)
	assert.Equal(t, "tp-issuerKeyStore", name)
}

func TestOIDToName_KnownStandardOID(t *testing.T) {
	oid := asn1.ObjectIdentifier{2, 5, 29, 14}
	name := OIDToName(oid)
	assert.Equal(t, "subjectKeyIdentifier", name)
}

func TestOIDToName_UnknownTCGOID(t *testing.T) {
	oid := asn1.ObjectIdentifier{2, 23, 133, 99, 99}
	name := OIDToName(oid)
	assert.Contains(t, name, "tcg-unknown")
	assert.Contains(t, name, "2.23.133.99.99")
}

func TestOIDToName_UnknownTrustedPlatformOID(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 999, 999}
	name := OIDToName(oid)
	assert.Contains(t, name, "tp-unknown")
}

func TestOIDToName_CompletelyUnknownOID(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	name := OIDToName(oid)
	assert.Equal(t, "1.2.3.4.5", name)
}

func TestOIDToName_AllKnownOIDs(t *testing.T) {
	testCases := []struct {
		oid      asn1.ObjectIdentifier
		expected string
	}{
		{asn1.ObjectIdentifier{2, 23, 133, 2, 1}, "tcg-at-tpmManufacturer"},
		{asn1.ObjectIdentifier{2, 23, 133, 2, 2}, "tcg-at-tpmModel"},
		{asn1.ObjectIdentifier{2, 23, 133, 2, 3}, "tcg-at-tpmVersion"},
		{asn1.ObjectIdentifier{2, 23, 133, 8, 1}, "tcg-kp-EKCertificate"},
		{asn1.ObjectIdentifier{2, 23, 133, 8, 2}, "tcg-kp-PlatformCertificate"},
		{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 2}, "tp-keyStore"},
		{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 3}, "tp-fips140"},
		{asn1.ObjectIdentifier{2, 5, 29, 15}, "keyUsage"},
		{asn1.ObjectIdentifier{2, 5, 29, 17}, "subjectAltName"},
		{asn1.ObjectIdentifier{2, 5, 29, 19}, "basicConstraints"},
		{asn1.ObjectIdentifier{2, 5, 29, 35}, "authorityKeyIdentifier"},
		{asn1.ObjectIdentifier{2, 5, 29, 37}, "extKeyUsage"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			name := OIDToName(tc.oid)
			assert.Equal(t, tc.expected, name)
		})
	}
}

// ========================================================================
// Test IsTCGOID
// ========================================================================

func TestIsTCGOID_ValidTCGOID(t *testing.T) {
	oid := asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	assert.True(t, IsTCGOID(oid))
}

func TestIsTCGOID_ValidTCGBase(t *testing.T) {
	oid := asn1.ObjectIdentifier{2, 23, 133}
	assert.True(t, IsTCGOID(oid))
}

func TestIsTCGOID_ExtendedTCGArc(t *testing.T) {
	oid := asn1.ObjectIdentifier{2, 23, 133, 11, 1, 1}
	assert.True(t, IsTCGOID(oid))
}

func TestIsTCGOID_InvalidWrongFirstNumber(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 23, 133}
	assert.False(t, IsTCGOID(oid))
}

func TestIsTCGOID_InvalidShortOID(t *testing.T) {
	oid := asn1.ObjectIdentifier{2, 23}
	assert.False(t, IsTCGOID(oid))
}

func TestIsTCGOID_InvalidWrongSecondNumber(t *testing.T) {
	oid := asn1.ObjectIdentifier{2, 5, 133}
	assert.False(t, IsTCGOID(oid))
}

// ========================================================================
// Test IsTrustedPlatformOID
// ========================================================================

func TestIsTrustedPlatformOID_ValidTPOID(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 1}
	assert.True(t, IsTrustedPlatformOID(oid))
}

func TestIsTrustedPlatformOID_ValidTPBase(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377}
	assert.True(t, IsTrustedPlatformOID(oid))
}

func TestIsTrustedPlatformOID_InvalidWrongBase(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12345}
	assert.False(t, IsTrustedPlatformOID(oid))
}

func TestIsTrustedPlatformOID_InvalidShortOID(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1}
	assert.False(t, IsTrustedPlatformOID(oid))
}

func TestIsTrustedPlatformOID_ExtendedTPArc(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 10}
	assert.True(t, IsTrustedPlatformOID(oid))
}

// ========================================================================
// Test keyUsageToString
// ========================================================================

func TestKeyUsageToString_None(t *testing.T) {
	result := keyUsageToString(0)
	assert.Equal(t, "None", result)
}

func TestKeyUsageToString_DigitalSignature(t *testing.T) {
	result := keyUsageToString(x509.KeyUsageDigitalSignature)
	assert.Equal(t, "DigitalSignature", result)
}

func TestKeyUsageToString_MultipleUsages(t *testing.T) {
	usage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	result := keyUsageToString(usage)
	assert.Contains(t, result, "DigitalSignature")
	assert.Contains(t, result, "KeyEncipherment")
}

func TestKeyUsageToString_AllUsages(t *testing.T) {
	usage := x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign | x509.KeyUsageEncipherOnly |
		x509.KeyUsageDecipherOnly
	result := keyUsageToString(usage)
	assert.Contains(t, result, "DigitalSignature")
	assert.Contains(t, result, "ContentCommitment")
	assert.Contains(t, result, "KeyEncipherment")
	assert.Contains(t, result, "DataEncipherment")
	assert.Contains(t, result, "KeyAgreement")
	assert.Contains(t, result, "CertSign")
	assert.Contains(t, result, "CRLSign")
	assert.Contains(t, result, "EncipherOnly")
	assert.Contains(t, result, "DecipherOnly")
}

func TestKeyUsageToString_CAUsages(t *testing.T) {
	usage := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	result := keyUsageToString(usage)
	assert.Contains(t, result, "CertSign")
	assert.Contains(t, result, "CRLSign")
}

// ========================================================================
// Test extKeyUsageToString
// ========================================================================

func TestExtKeyUsageToString_AllKnownUsages(t *testing.T) {
	testCases := []struct {
		usage    x509.ExtKeyUsage
		expected string
	}{
		{x509.ExtKeyUsageAny, "Any"},
		{x509.ExtKeyUsageServerAuth, "ServerAuth"},
		{x509.ExtKeyUsageClientAuth, "ClientAuth"},
		{x509.ExtKeyUsageCodeSigning, "CodeSigning"},
		{x509.ExtKeyUsageEmailProtection, "EmailProtection"},
		{x509.ExtKeyUsageIPSECEndSystem, "IPSECEndSystem"},
		{x509.ExtKeyUsageIPSECTunnel, "IPSECTunnel"},
		{x509.ExtKeyUsageIPSECUser, "IPSECUser"},
		{x509.ExtKeyUsageTimeStamping, "TimeStamping"},
		{x509.ExtKeyUsageOCSPSigning, "OCSPSigning"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			result := extKeyUsageToString(tc.usage)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestExtKeyUsageToString_UnknownUsage(t *testing.T) {
	result := extKeyUsageToString(x509.ExtKeyUsage(999))
	assert.Contains(t, result, "Unknown")
	assert.Contains(t, result, "999")
}

// ========================================================================
// Test publicKeyTypeString
// ========================================================================

func TestPublicKeyTypeString_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	result := publicKeyTypeString(&key.PublicKey)
	assert.Contains(t, result, "RSA")
	assert.Contains(t, result, "2048")
}

func TestPublicKeyTypeString_ECDSA_P256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	result := publicKeyTypeString(&key.PublicKey)
	assert.Contains(t, result, "ECDSA")
	assert.Contains(t, result, "P-256")
}

func TestPublicKeyTypeString_ECDSA_P384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	result := publicKeyTypeString(&key.PublicKey)
	assert.Contains(t, result, "ECDSA")
	assert.Contains(t, result, "P-384")
}

func TestPublicKeyTypeString_ECDSA_P521(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	result := publicKeyTypeString(&key.PublicKey)
	assert.Contains(t, result, "ECDSA")
	assert.Contains(t, result, "P-521")
}

func TestPublicKeyTypeString_Unknown(t *testing.T) {
	result := publicKeyTypeString("unknown")
	assert.Contains(t, result, "Unknown")
}

// ========================================================================
// Test parseExtensionValue
// ========================================================================

func TestParseExtensionValue_SubjectKeyIdentifier(t *testing.T) {
	ski := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	skiEncoded, err := asn1.Marshal(ski)
	require.NoError(t, err)

	ext := pkix.Extension{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 14},
		Value: skiEncoded,
	}

	result := parseExtensionValue(ext)
	assert.Equal(t, "0102030405", result)
}

func TestParseExtensionValue_AuthorityKeyIdentifier(t *testing.T) {
	aki := authorityKeyIdentifier{
		KeyIdentifier: []byte{0xAA, 0xBB, 0xCC},
	}
	akiEncoded, err := asn1.Marshal(aki)
	require.NoError(t, err)

	ext := pkix.Extension{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 35},
		Value: akiEncoded,
	}

	result := parseExtensionValue(ext)
	assert.Contains(t, result, "KeyID")
	assert.Contains(t, result, "aabbcc")
}

func TestParseExtensionValue_TCGOIDWithString(t *testing.T) {
	strVal := "TPM Manufacturer"
	strEncoded, err := asn1.Marshal(strVal)
	require.NoError(t, err)

	ext := pkix.Extension{
		Id:    asn1.ObjectIdentifier{2, 23, 133, 2, 1},
		Value: strEncoded,
	}

	result := parseExtensionValue(ext)
	assert.Equal(t, strVal, result)
}

func TestParseExtensionValue_TCGOIDWithBoolean(t *testing.T) {
	boolVal := true
	boolEncoded, err := asn1.Marshal(boolVal)
	require.NoError(t, err)

	ext := pkix.Extension{
		Id:    asn1.ObjectIdentifier{2, 23, 133, 11, 1, 1},
		Value: boolEncoded,
	}

	result := parseExtensionValue(ext)
	assert.Equal(t, "true", result)
}

func TestParseExtensionValue_LongValue(t *testing.T) {
	longValue := make([]byte, 100)
	for i := range longValue {
		longValue[i] = byte(i)
	}

	ext := pkix.Extension{
		Id:    asn1.ObjectIdentifier{1, 2, 3, 4, 5},
		Value: longValue,
	}

	result := parseExtensionValue(ext)
	assert.Contains(t, result, "...")
}

func TestParseExtensionValue_ShortValue(t *testing.T) {
	shortValue := []byte{0x01, 0x02, 0x03}

	ext := pkix.Extension{
		Id:    asn1.ObjectIdentifier{1, 2, 3, 4, 5},
		Value: shortValue,
	}

	result := parseExtensionValue(ext)
	assert.Equal(t, "010203", result)
}

// ========================================================================
// Test ToString
// ========================================================================

func TestToString_NilCertificate(t *testing.T) {
	result := ToString(nil)
	assert.Equal(t, "<nil certificate>", result)
}

func TestToString_BasicCertificate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	result := ToString(cert)
	assert.Contains(t, result, "CERTIFICATE DETAILS")
	assert.Contains(t, result, "Test Certificate")
	assert.Contains(t, result, "RSA")
}

func TestToString_CertificateWithAllFields(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName:         "Full Test Certificate",
			Organization:       []string{"Test Org"},
			OrganizationalUnit: []string{"Test OU"},
			Country:            []string{"US"},
			Province:           []string{"California"},
			Locality:           []string{"San Francisco"},
			SerialNumber:       "CN12345",
		},
		Issuer: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test CA Org"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	result := ToString(cert)
	assert.Contains(t, result, "Full Test Certificate")
	assert.Contains(t, result, "Test Org")
	assert.Contains(t, result, "Test OU")
	assert.Contains(t, result, "US")
	assert.Contains(t, result, "California")
	assert.Contains(t, result, "San Francisco")
	assert.Contains(t, result, "DigitalSignature")
	assert.Contains(t, result, "ServerAuth")
}

func TestToString_CACertificate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		MaxPathLen:            2,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	result := ToString(cert)
	assert.Contains(t, result, "Is CA")
	assert.Contains(t, result, "true")
}

func TestToString_CACertificateWithMaxPathLenZero(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Intermediate CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	result := ToString(cert)
	assert.Contains(t, result, "Max Path Length")
	assert.Contains(t, result, "0")
}

func TestToString_CertificateWithSANs(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	testURI, _ := url.Parse("https://example.com")

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "SAN Test",
		},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(24 * time.Hour),
		DNSNames:       []string{"example.com", "www.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.1")},
		URIs:           []*url.URL{testURI},
		EmailAddresses: []string{"test@example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	result := ToString(cert)
	assert.Contains(t, result, "Subject Alternative Names")
	assert.Contains(t, result, "example.com")
	assert.Contains(t, result, "192.168.1.1")
	assert.Contains(t, result, "https://example.com")
	assert.Contains(t, result, "test@example.com")
}

func TestToString_ECDSACertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "ECDSA Certificate",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	result := ToString(cert)
	assert.Contains(t, result, "ECDSA")
	assert.Contains(t, result, "P-256")
}

// ========================================================================
// Test ChainToString
// ========================================================================

func TestChainToString_EmptyChain(t *testing.T) {
	result := ChainToString(nil)
	assert.Equal(t, "<empty certificate chain>", result)
}

func TestChainToString_EmptySlice(t *testing.T) {
	result := ChainToString([]*x509.Certificate{})
	assert.Equal(t, "<empty certificate chain>", result)
}

func TestChainToString_SingleCertificate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Single Cert",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	result := ChainToString([]*x509.Certificate{cert})
	assert.Contains(t, result, "1 certificate(s)")
	assert.Contains(t, result, "Certificate [1/1]")
	assert.Contains(t, result, "Single Cert")
}

func TestChainToString_MultipleCertificates(t *testing.T) {
	// Create root CA
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	// Create intermediate CA
	intKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	intTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Intermediate CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(180 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	intDER, err := x509.CreateCertificate(rand.Reader, intTemplate, rootTemplate, &intKey.PublicKey, rootKey)
	require.NoError(t, err)
	intCert, err := x509.ParseCertificate(intDER)
	require.NoError(t, err)

	// Create end-entity certificate
	eeKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	eeTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "End Entity",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	eeDER, err := x509.CreateCertificate(rand.Reader, eeTemplate, intTemplate, &eeKey.PublicKey, intKey)
	require.NoError(t, err)
	eeCert, err := x509.ParseCertificate(eeDER)
	require.NoError(t, err)

	chain := []*x509.Certificate{eeCert, intCert, rootCert}
	result := ChainToString(chain)

	assert.Contains(t, result, "3 certificate(s)")
	assert.Contains(t, result, "Certificate [1/3]")
	assert.Contains(t, result, "Certificate [2/3]")
	assert.Contains(t, result, "Certificate [3/3]")
	assert.Contains(t, result, "End Entity")
	assert.Contains(t, result, "Intermediate CA")
	assert.Contains(t, result, "Root CA")
}
