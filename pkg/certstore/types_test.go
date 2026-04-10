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

package certstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"net"
	"net/url"
	"strings"
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
// Test KeyUsageToString
// ========================================================================

func TestKeyUsageToString_None(t *testing.T) {
	result := KeyUsageToString(0)
	assert.Equal(t, "None", result)
}

func TestKeyUsageToString_DigitalSignature(t *testing.T) {
	result := KeyUsageToString(x509.KeyUsageDigitalSignature)
	assert.Equal(t, "DigitalSignature", result)
}

func TestKeyUsageToString_MultipleUsages(t *testing.T) {
	usage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	result := KeyUsageToString(usage)
	assert.Contains(t, result, "DigitalSignature")
	assert.Contains(t, result, "KeyEncipherment")
}

func TestKeyUsageToString_AllUsages(t *testing.T) {
	usage := x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign | x509.KeyUsageEncipherOnly |
		x509.KeyUsageDecipherOnly
	result := KeyUsageToString(usage)
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
	result := KeyUsageToString(usage)
	assert.Contains(t, result, "CertSign")
	assert.Contains(t, result, "CRLSign")
}

// ========================================================================
// Test ExtKeyUsageToString
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
			result := ExtKeyUsageToString(tc.usage)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestExtKeyUsageToString_UnknownUsage(t *testing.T) {
	result := ExtKeyUsageToString(x509.ExtKeyUsage(999))
	assert.Contains(t, result, "Unknown")
	assert.Contains(t, result, "999")
}

// ========================================================================
// Test PublicKeyTypeString
// ========================================================================

func TestPublicKeyTypeString_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	result := PublicKeyTypeString(&key.PublicKey)
	assert.Contains(t, result, "RSA")
	assert.Contains(t, result, "2048")
}

func TestPublicKeyTypeString_ECDSA_P256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	result := PublicKeyTypeString(&key.PublicKey)
	assert.Contains(t, result, "ECDSA")
	assert.Contains(t, result, "P-256")
}

func TestPublicKeyTypeString_ECDSA_P384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	result := PublicKeyTypeString(&key.PublicKey)
	assert.Contains(t, result, "ECDSA")
	assert.Contains(t, result, "P-384")
}

func TestPublicKeyTypeString_ECDSA_P521(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	result := PublicKeyTypeString(&key.PublicKey)
	assert.Contains(t, result, "ECDSA")
	assert.Contains(t, result, "P-521")
}

func TestPublicKeyTypeString_Unknown(t *testing.T) {
	result := PublicKeyTypeString("unknown")
	assert.Contains(t, result, "Unknown")
}

// ========================================================================
// Test ParseExtensionValue
// ========================================================================

func TestParseExtensionValue_SubjectKeyIdentifier(t *testing.T) {
	ski := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	skiEncoded, err := asn1.Marshal(ski)
	require.NoError(t, err)

	ext := pkix.Extension{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 14},
		Value: skiEncoded,
	}

	result := ParseExtensionValue(ext)
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

	result := ParseExtensionValue(ext)
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

	result := ParseExtensionValue(ext)
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

	result := ParseExtensionValue(ext)
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

	result := ParseExtensionValue(ext)
	// Full hex is returned without truncation
	assert.Equal(t, hex.EncodeToString(longValue), result)
}

func TestParseExtensionValue_ShortValue(t *testing.T) {
	shortValue := []byte{0x01, 0x02, 0x03}

	ext := pkix.Extension{
		Id:    asn1.ObjectIdentifier{1, 2, 3, 4, 5},
		Value: shortValue,
	}

	result := ParseExtensionValue(ext)
	assert.Equal(t, "010203", result)
}

func TestParseExtensionValue_SubjectAltNameOID(t *testing.T) {
	// Build a SAN with DNS name to exercise the ParseSubjectAltName dispatch.
	dnsName := asn1.RawValue{
		Class: asn1.ClassContextSpecific,
		Tag:   2,
		Bytes: []byte("example.com"),
	}
	sanBytes, err := asn1.Marshal([]asn1.RawValue{dnsName})
	require.NoError(t, err)

	ext := pkix.Extension{
		Id:    OIDSubjectAltName,
		Value: sanBytes,
	}
	result := ParseExtensionValue(ext)
	assert.Contains(t, result, "DNS:example.com")
}

func TestParseExtensionValue_AuthorityInfoAccessOID(t *testing.T) {
	// Build AIA with CA Issuers URI.
	aiaBytes := buildAIA(t, oidCAIssuers, 6, []byte("http://ca.example.com/ca.crt"))

	ext := pkix.Extension{
		Id:    oidAuthorityInfoAccess,
		Value: aiaBytes,
	}
	result := ParseExtensionValue(ext)
	assert.Contains(t, result, "CA Issuers")
	assert.Contains(t, result, "http://ca.example.com/ca.crt")
}

func TestParseExtensionValue_SubjectDirectoryAttributesOID(t *testing.T) {
	// Build SDA with a UTF8 string attribute.
	sdaBytes := buildSDAString(t, OIDTCGAttributeTPMModel, "TestModel")

	ext := pkix.Extension{
		Id:    OIDSubjectDirectoryAttributes,
		Value: sdaBytes,
	}
	result := ParseExtensionValue(ext)
	assert.Contains(t, result, "TestModel")
}

func TestParseExtensionValue_TCGOIDWithHexFallback(t *testing.T) {
	// Raw bytes that cannot be parsed as string or boolean.
	rawValue := []byte{0x04, 0x02, 0xAB, 0xCD}

	ext := pkix.Extension{
		Id:    asn1.ObjectIdentifier{2, 23, 133, 2, 15}, // tcg-at-tpmIdLabel
		Value: rawValue,
	}
	result := ParseExtensionValue(ext)
	assert.Equal(t, hex.EncodeToString(rawValue), result)
}

func TestParseExtensionValue_TrustedPlatformOIDWithString(t *testing.T) {
	strVal := "FIPS 140-2"
	strEncoded, err := asn1.Marshal(strVal)
	require.NoError(t, err)

	ext := pkix.Extension{
		Id:    OIDTPFIPS140,
		Value: strEncoded,
	}
	result := ParseExtensionValue(ext)
	assert.Equal(t, strVal, result)
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

func TestToString_CACertificateUnlimitedPathLen(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Root CA Unlimited",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		// MaxPathLen defaults to 0, MaxPathLenZero defaults to false -> "unlimited"
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	result := ToString(cert)
	assert.Contains(t, result, "unlimited")
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

func TestToString_WithTCGExtensions(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	strVal := "TestManufacturer"
	strEncoded, err := asn1.Marshal(strVal)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "TCG Ext Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{
				Id:    OIDTCGAttributeTPMManufacturer,
				Value: strEncoded,
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	result := ToString(cert)
	assert.Contains(t, result, "TCG Extensions")
	assert.Contains(t, result, "TestManufacturer")
}

func TestToString_WithTrustedPlatformExtensions(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	strVal := "SoftHSM"
	strEncoded, err := asn1.Marshal(strVal)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "TP Ext Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{
				Id:    OIDTPKeyStore,
				Value: strEncoded,
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	result := ToString(cert)
	assert.Contains(t, result, "Trusted Platform Extensions")
	assert.Contains(t, result, "SoftHSM")
}

func TestToString_WithOtherExtensions(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Other Ext Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}, // challengePassword
				Value: []byte{0x04, 0x03, 0x41, 0x42, 0x43},
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	result := ToString(cert)
	assert.Contains(t, result, "Other Extensions")
}

func TestToString_WithCriticalExtension(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	boolVal := true
	boolEncoded, err := asn1.Marshal(boolVal)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Critical Ext Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{
				Id:       OIDTCGVerifiedTPMResidency,
				Critical: true,
				Value:    boolEncoded,
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	result := ToString(cert)
	assert.Contains(t, result, "[CRITICAL]")
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

// ========================================================================
// Test ParseTCGAttributes
// ========================================================================

func TestParseTCGAttributes_NilCert(t *testing.T) {
	attrs := ParseTCGAttributes(nil)
	assert.Equal(t, "", attrs.Manufacturer)
	assert.Equal(t, "", attrs.Model)
	assert.Equal(t, "", attrs.Version)
	assert.Equal(t, "", attrs.SpecFamily)
	assert.Equal(t, 0, attrs.SpecLevel)
	assert.Equal(t, 0, attrs.SpecRevision)
}

func TestParseTCGAttributes_NoExtensions(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	attrs := ParseTCGAttributes(cert)
	assert.Equal(t, "", attrs.Manufacturer)
	assert.Equal(t, "", attrs.Model)
}

func TestParseTCGAttributes_SANWithTCGDirName(t *testing.T) {
	// Build an RDN sequence with TCG manufacturer/model/version
	rdnSeq := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  OIDTCGAttributeTPMManufacturer,
				Value: "id:49465800",
			},
		},
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  OIDTCGAttributeTPMModel,
				Value: "SLB 9670",
			},
		},
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  OIDTCGAttributeTPMVersion,
				Value: "id:00070055",
			},
		},
	}

	rdnBytes, err := asn1.Marshal(rdnSeq)
	require.NoError(t, err)

	// Wrap in directoryName (context tag 4, constructed)
	dirName := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        4,
		IsCompound: true,
		Bytes:      rdnBytes,
	}

	// Wrap in GeneralNames SEQUENCE
	sanBytes, err := asn1.Marshal([]asn1.RawValue{dirName})
	require.NoError(t, err)

	// Create a certificate with this SAN extension
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "EK Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{
				Id:    OIDSubjectAltName,
				Value: sanBytes,
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	attrs := ParseTCGAttributes(cert)
	assert.Equal(t, "id:49465800", attrs.Manufacturer)
	assert.Equal(t, "Infineon", attrs.ManufacturerName)
	assert.Equal(t, "SLB 9670", attrs.Model)
	assert.Equal(t, "id:00070055", attrs.Version)
	// No SDA extension, so spec fields should be empty
	assert.Equal(t, "", attrs.SpecFamily)
	assert.Equal(t, 0, attrs.SpecLevel)
}

func TestParseTCGAttributes_SubjectDirectoryAttributes(t *testing.T) {
	// Build a tpmSpecification: SEQUENCE { UTF8String "2.0", INTEGER 0, INTEGER 116 }
	type tpmSpec struct {
		Family   string
		Level    int
		Revision int
	}
	specBytes, err := asn1.Marshal(tpmSpec{Family: "2.0", Level: 0, Revision: 116})
	require.NoError(t, err)

	// Wrap in SET
	specSet := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      specBytes,
	}

	// Build Attribute: SEQUENCE { OID, SET { value } }
	type attribute struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue `asn1:"set"`
	}
	attrBytes, err := asn1.Marshal([]attribute{
		{
			Type:   OIDTCGAttributeTPMSpecification,
			Values: specSet,
		},
	})
	require.NoError(t, err)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "SDA Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{
				Id:    OIDSubjectDirectoryAttributes,
				Value: attrBytes,
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	attrs := ParseTCGAttributes(cert)
	assert.Equal(t, "2.0", attrs.SpecFamily)
	assert.Equal(t, 0, attrs.SpecLevel)
	assert.Equal(t, 116, attrs.SpecRevision)
	// No SAN, so manufacturer/model/version should be empty
	assert.Equal(t, "", attrs.Manufacturer)
}

func TestParseTCGAttributes_BothSANAndSDA(t *testing.T) {
	// Build SAN with TCG DirName
	rdnSeq := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  OIDTCGAttributeTPMManufacturer,
				Value: "id:49465800",
			},
		},
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  OIDTCGAttributeTPMModel,
				Value: "SLB 9670",
			},
		},
	}
	rdnBytes, err := asn1.Marshal(rdnSeq)
	require.NoError(t, err)

	dirName := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        4,
		IsCompound: true,
		Bytes:      rdnBytes,
	}
	sanBytes, err := asn1.Marshal([]asn1.RawValue{dirName})
	require.NoError(t, err)

	// Build SDA with tpmSpecification
	type tpmSpec struct {
		Family   string
		Level    int
		Revision int
	}
	specBytes, err := asn1.Marshal(tpmSpec{Family: "2.0", Level: 0, Revision: 138})
	require.NoError(t, err)

	specSet := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      specBytes,
	}

	type attribute struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue `asn1:"set"`
	}
	sdaBytes, err := asn1.Marshal([]attribute{
		{
			Type:   OIDTCGAttributeTPMSpecification,
			Values: specSet,
		},
	})
	require.NoError(t, err)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Full TCG Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{
				Id:    OIDSubjectAltName,
				Value: sanBytes,
			},
			{
				Id:    OIDSubjectDirectoryAttributes,
				Value: sdaBytes,
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	attrs := ParseTCGAttributes(cert)
	assert.Equal(t, "id:49465800", attrs.Manufacturer)
	assert.Equal(t, "SLB 9670", attrs.Model)
	assert.Equal(t, "2.0", attrs.SpecFamily)
	assert.Equal(t, 138, attrs.SpecRevision)
}

func TestParseTCGAttributes_MalformedSAN(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Malformed SAN Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Inject a malformed SAN extension directly into the parsed certificate
	cert.Extensions = append(cert.Extensions, pkix.Extension{
		Id:    OIDSubjectAltName,
		Value: []byte{0xFF, 0xFE, 0xFD},
	})

	attrs := ParseTCGAttributes(cert)
	assert.Equal(t, "", attrs.Manufacturer)
	assert.Equal(t, "", attrs.Model)
}

func TestParseTCGAttributes_MalformedSDA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Malformed SDA Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{
				Id:    OIDSubjectDirectoryAttributes,
				Value: []byte{0xFF, 0xFE, 0xFD},
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	attrs := ParseTCGAttributes(cert)
	assert.Equal(t, "", attrs.SpecFamily)
	assert.Equal(t, 0, attrs.SpecLevel)
}

func TestParseTCGAttributes_ManufacturerResolution_STMicro(t *testing.T) {
	rdnSeq := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  OIDTCGAttributeTPMManufacturer,
				Value: "id:53544D20",
			},
		},
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  OIDTCGAttributeTPMModel,
				Value: "ST33HTPHAHD8",
			},
		},
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  OIDTCGAttributeTPMVersion,
				Value: "id:00010102",
			},
		},
	}

	rdnBytes, err := asn1.Marshal(rdnSeq)
	require.NoError(t, err)

	dirName := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        4,
		IsCompound: true,
		Bytes:      rdnBytes,
	}
	sanBytes, err := asn1.Marshal([]asn1.RawValue{dirName})
	require.NoError(t, err)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ST Micro EK"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{
				Id:    OIDSubjectAltName,
				Value: sanBytes,
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	attrs := ParseTCGAttributes(cert)
	assert.Equal(t, "id:53544D20", attrs.Manufacturer)
	assert.Equal(t, "ST Microelectronics", attrs.ManufacturerName)
	assert.Equal(t, "ST33HTPHAHD8", attrs.Model)
	assert.Equal(t, "id:00010102", attrs.Version)
}

func TestParseTCGAttributes_ManufacturerResolution_UnknownVendor(t *testing.T) {
	rdnSeq := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  OIDTCGAttributeTPMManufacturer,
				Value: "id:DEADBEEF",
			},
		},
	}

	rdnBytes, err := asn1.Marshal(rdnSeq)
	require.NoError(t, err)

	dirName := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        4,
		IsCompound: true,
		Bytes:      rdnBytes,
	}
	sanBytes, err := asn1.Marshal([]asn1.RawValue{dirName})
	require.NoError(t, err)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Unknown Vendor EK"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{
				Id:    OIDSubjectAltName,
				Value: sanBytes,
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	attrs := ParseTCGAttributes(cert)
	assert.Equal(t, "id:DEADBEEF", attrs.Manufacturer)
	assert.Equal(t, "", attrs.ManufacturerName) // unknown vendor ID
}

// ========================================================================
// Test formatRDNSequence
// ========================================================================

func TestFormatRDNSequence_StringValues(t *testing.T) {
	rdnSeq := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  OIDTCGAttributeTPMManufacturer,
				Value: "id:49465800",
			},
		},
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  OIDTCGAttributeTPMModel,
				Value: "SLB 9670",
			},
		},
	}

	result := formatRDNSequence(rdnSeq)
	assert.Contains(t, result, "tcg-at-tpmManufacturer=id:49465800")
	assert.Contains(t, result, "tcg-at-tpmModel=SLB 9670")
}

func TestFormatRDNSequence_NonStringValue(t *testing.T) {
	rdnSeq := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  OIDTCGAttributeTPMVersion,
				Value: 42, // integer, not string
			},
		},
	}

	result := formatRDNSequence(rdnSeq)
	assert.Contains(t, result, "tcg-at-tpmVersion=42")
}

func TestFormatRDNSequence_Empty(t *testing.T) {
	result := formatRDNSequence(pkix.RDNSequence{})
	assert.Equal(t, "", result)
}

// ========================================================================
// Test ParseSubjectAltName
// ========================================================================

func TestParseSubjectAltName_DNSName(t *testing.T) {
	dnsName := asn1.RawValue{
		Class: asn1.ClassContextSpecific,
		Tag:   2,
		Bytes: []byte("example.com"),
	}
	sanBytes, err := asn1.Marshal([]asn1.RawValue{dnsName})
	require.NoError(t, err)

	result := ParseSubjectAltName(sanBytes)
	assert.Equal(t, "DNS:example.com", result)
}

func TestParseSubjectAltName_Email(t *testing.T) {
	email := asn1.RawValue{
		Class: asn1.ClassContextSpecific,
		Tag:   1,
		Bytes: []byte("user@example.com"),
	}
	sanBytes, err := asn1.Marshal([]asn1.RawValue{email})
	require.NoError(t, err)

	result := ParseSubjectAltName(sanBytes)
	assert.Equal(t, "email:user@example.com", result)
}

func TestParseSubjectAltName_URI(t *testing.T) {
	uri := asn1.RawValue{
		Class: asn1.ClassContextSpecific,
		Tag:   6,
		Bytes: []byte("https://example.com/cert"),
	}
	sanBytes, err := asn1.Marshal([]asn1.RawValue{uri})
	require.NoError(t, err)

	result := ParseSubjectAltName(sanBytes)
	assert.Equal(t, "URI:https://example.com/cert", result)
}

func TestParseSubjectAltName_IPv4(t *testing.T) {
	ip := asn1.RawValue{
		Class: asn1.ClassContextSpecific,
		Tag:   7,
		Bytes: []byte{192, 168, 1, 1},
	}
	sanBytes, err := asn1.Marshal([]asn1.RawValue{ip})
	require.NoError(t, err)

	result := ParseSubjectAltName(sanBytes)
	assert.Equal(t, "IP:192.168.1.1", result)
}

func TestParseSubjectAltName_IPv6(t *testing.T) {
	ipv6 := net.ParseIP("::1")
	ip := asn1.RawValue{
		Class: asn1.ClassContextSpecific,
		Tag:   7,
		Bytes: []byte(ipv6),
	}
	sanBytes, err := asn1.Marshal([]asn1.RawValue{ip})
	require.NoError(t, err)

	result := ParseSubjectAltName(sanBytes)
	assert.Contains(t, result, "IP:")
	assert.Contains(t, result, "01") // last byte of ::1
}

func TestParseSubjectAltName_UnknownTag(t *testing.T) {
	unknown := asn1.RawValue{
		Class: asn1.ClassContextSpecific,
		Tag:   9, // not a standard SAN tag
		Bytes: []byte{0xAB, 0xCD},
	}
	sanBytes, err := asn1.Marshal([]asn1.RawValue{unknown})
	require.NoError(t, err)

	result := ParseSubjectAltName(sanBytes)
	assert.Contains(t, result, "tag9:")
	assert.Contains(t, result, "abcd")
}

func TestParseSubjectAltName_DirectoryName(t *testing.T) {
	rdnSeq := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  OIDTCGAttributeTPMManufacturer,
				Value: "id:49465800",
			},
		},
	}
	rdnBytes, err := asn1.Marshal(rdnSeq)
	require.NoError(t, err)

	dirName := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        4,
		IsCompound: true,
		Bytes:      rdnBytes,
	}
	sanBytes, err := asn1.Marshal([]asn1.RawValue{dirName})
	require.NoError(t, err)

	result := ParseSubjectAltName(sanBytes)
	assert.Contains(t, result, "DirName:")
	assert.Contains(t, result, "tcg-at-tpmManufacturer=id:49465800")
}

func TestParseSubjectAltName_DirectoryNameParseError(t *testing.T) {
	// directoryName with garbage bytes that fail RDN parsing
	dirName := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        4,
		IsCompound: true,
		Bytes:      []byte{0xFF, 0xFE},
	}
	sanBytes, err := asn1.Marshal([]asn1.RawValue{dirName})
	require.NoError(t, err)

	result := ParseSubjectAltName(sanBytes)
	assert.Contains(t, result, "DirName:<parse error>")
}

func TestParseSubjectAltName_InvalidASN1(t *testing.T) {
	result := ParseSubjectAltName([]byte{0xFF, 0xFE, 0xFD})
	// Falls back to hex encoding
	assert.Equal(t, "fffefd", result)
}

func TestParseSubjectAltName_Multiple(t *testing.T) {
	dns := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("a.com")}
	email := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, Bytes: []byte("b@c.com")}
	sanBytes, err := asn1.Marshal([]asn1.RawValue{dns, email})
	require.NoError(t, err)

	result := ParseSubjectAltName(sanBytes)
	assert.Contains(t, result, "DNS:a.com")
	assert.Contains(t, result, "email:b@c.com")
	assert.Contains(t, result, "; ")
}

// ========================================================================
// Test ParseAuthorityInfoAccess
// ========================================================================

// buildAIA is a helper to construct AIA ASN.1 encoding.
func buildAIA(t *testing.T, method asn1.ObjectIdentifier, locationTag int, locationBytes []byte) []byte {
	t.Helper()
	type ad struct {
		AccessMethod   asn1.ObjectIdentifier
		AccessLocation asn1.RawValue
	}
	aiaBytes, err := asn1.Marshal([]ad{
		{
			AccessMethod: method,
			AccessLocation: asn1.RawValue{
				Class: asn1.ClassContextSpecific,
				Tag:   locationTag,
				Bytes: locationBytes,
			},
		},
	})
	require.NoError(t, err)
	return aiaBytes
}

func TestParseAuthorityInfoAccess_CAIssuersURI(t *testing.T) {
	aiaBytes := buildAIA(t, oidCAIssuers, 6, []byte("http://ca.example.com/ca.crt"))

	result := ParseAuthorityInfoAccess(aiaBytes)
	assert.Contains(t, result, "CA Issuers")
	assert.Contains(t, result, "http://ca.example.com/ca.crt")
}

func TestParseAuthorityInfoAccess_OCSPURI(t *testing.T) {
	aiaBytes := buildAIA(t, oidOCSP, 6, []byte("http://ocsp.example.com"))

	result := ParseAuthorityInfoAccess(aiaBytes)
	assert.Contains(t, result, "OCSP")
	assert.Contains(t, result, "http://ocsp.example.com")
}

func TestParseAuthorityInfoAccess_UnknownMethod(t *testing.T) {
	unknownOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	aiaBytes := buildAIA(t, unknownOID, 6, []byte("http://unknown.example.com"))

	result := ParseAuthorityInfoAccess(aiaBytes)
	assert.Contains(t, result, "1.2.3.4.5")
	assert.Contains(t, result, "http://unknown.example.com")
}

func TestParseAuthorityInfoAccess_NonURILocation(t *testing.T) {
	// Tag 2 = dNSName (not a URI tag 6)
	aiaBytes := buildAIA(t, oidCAIssuers, 2, []byte{0xAB, 0xCD})

	result := ParseAuthorityInfoAccess(aiaBytes)
	assert.Contains(t, result, "CA Issuers")
	assert.Contains(t, result, "abcd")
}

func TestParseAuthorityInfoAccess_InvalidASN1(t *testing.T) {
	result := ParseAuthorityInfoAccess([]byte{0xFF, 0xFE})
	assert.Equal(t, "fffe", result)
}

// ========================================================================
// Test ParseSubjectDirectoryAttributes
// ========================================================================

// buildSDAString builds an SDA ASN.1 encoding with a single UTF8 string attribute.
func buildSDAString(t *testing.T, oid asn1.ObjectIdentifier, value string) []byte {
	t.Helper()
	valBytes, err := asn1.Marshal(value)
	require.NoError(t, err)

	type attribute struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue `asn1:"set"`
	}
	sdaBytes, err := asn1.Marshal([]attribute{
		{
			Type: oid,
			Values: asn1.RawValue{
				Class:      asn1.ClassUniversal,
				Tag:        asn1.TagSet,
				IsCompound: true,
				Bytes:      valBytes,
			},
		},
	})
	require.NoError(t, err)
	return sdaBytes
}

func TestParseSubjectDirectoryAttributes_TPMSpecification(t *testing.T) {
	type tpmSpec struct {
		Family   string
		Level    int
		Revision int
	}
	specBytes, err := asn1.Marshal(tpmSpec{Family: "2.0", Level: 0, Revision: 138})
	require.NoError(t, err)

	type attribute struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue `asn1:"set"`
	}
	sdaBytes, err := asn1.Marshal([]attribute{
		{
			Type: OIDTCGAttributeTPMSpecification,
			Values: asn1.RawValue{
				Class:      asn1.ClassUniversal,
				Tag:        asn1.TagSet,
				IsCompound: true,
				Bytes:      specBytes,
			},
		},
	})
	require.NoError(t, err)

	result := ParseSubjectDirectoryAttributes(sdaBytes)
	assert.Contains(t, result, "Family=2.0")
	assert.Contains(t, result, "Level=0")
	assert.Contains(t, result, "Revision=138")
}

func TestParseSubjectDirectoryAttributes_UTF8StringFallback(t *testing.T) {
	sdaBytes := buildSDAString(t, OIDTCGAttributeTPMModel, "TestModel-XYZ")

	result := ParseSubjectDirectoryAttributes(sdaBytes)
	assert.Contains(t, result, "TestModel-XYZ")
}

func TestParseSubjectDirectoryAttributes_HexFallback(t *testing.T) {
	// Build an attribute with raw binary that can't be parsed as string.
	rawInner := []byte{0x04, 0x02, 0xAB, 0xCD} // OCTET STRING 2 bytes

	type attribute struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue `asn1:"set"`
	}
	sdaBytes, err := asn1.Marshal([]attribute{
		{
			Type: OIDTCGAttributeTPMVersion,
			Values: asn1.RawValue{
				Class:      asn1.ClassUniversal,
				Tag:        asn1.TagSet,
				IsCompound: true,
				Bytes:      rawInner,
			},
		},
	})
	require.NoError(t, err)

	result := ParseSubjectDirectoryAttributes(sdaBytes)
	// Should contain hex encoding of the raw inner bytes
	assert.True(t, len(result) > 0)
}

func TestParseSubjectDirectoryAttributes_InvalidASN1(t *testing.T) {
	result := ParseSubjectDirectoryAttributes([]byte{0xFF, 0xFE, 0xFD})
	assert.Equal(t, "fffefd", result)
}

// ========================================================================
// Test resolveManufacturerID
// ========================================================================

func TestResolveManufacturerID_NoPrefix(t *testing.T) {
	result := resolveManufacturerID("DEADBEEF")
	assert.Equal(t, "", result)
}

func TestResolveManufacturerID_WrongLength(t *testing.T) {
	result := resolveManufacturerID("id:DEAD")
	assert.Equal(t, "", result)
}

func TestResolveManufacturerID_InvalidHex(t *testing.T) {
	result := resolveManufacturerID("id:ZZZZZZZZ")
	assert.Equal(t, "", result)
}

func TestResolveManufacturerID_KnownVendor(t *testing.T) {
	result := resolveManufacturerID("id:49465800")
	assert.Equal(t, "Infineon", result)
}

func TestResolveManufacturerID_UnknownVendor(t *testing.T) {
	result := resolveManufacturerID("id:DEADBEEF")
	assert.Equal(t, "", result)
}

func TestResolveManufacturerID_AllKnownVendors(t *testing.T) {
	testCases := []struct {
		hex      string
		expected string
	}{
		{"id:414D4400", "AMD"},
		{"id:49424D00", "IBM"},
		{"id:4D534654", "Microsoft"},
		{"id:494E5443", "Intel"},
		{"id:474F4F47", "Google"},
	}
	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			result := resolveManufacturerID(tc.hex)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// ========================================================================
// Test ToString - additional extension grouping
// ========================================================================

func TestToString_StandardExtensionsSection(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Build a cert with a standard X.509 extension (2.5.29.x).
	// SubjectKeyIdentifier is standard and will be auto-added.
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Std Ext Test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{0x01, 0x02, 0x03},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	result := ToString(cert)
	assert.Contains(t, result, "Standard X.509 Extensions")
}

func TestToString_MixedExtensions(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	strVal := "TestValue"
	strEncoded, err := asn1.Marshal(strVal)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Mixed Ext Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		SubjectKeyId: []byte{0x01, 0x02},
		ExtraExtensions: []pkix.Extension{
			{Id: OIDTCGAttributeTPMManufacturer, Value: strEncoded},
			{Id: OIDTPKeyStore, Value: strEncoded},
			{Id: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}, Value: []byte{0x04, 0x01, 0x41}},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	result := ToString(cert)
	// All 4 extension sections should appear.
	assert.True(t, strings.Contains(result, "TCG Extensions"))
	assert.True(t, strings.Contains(result, "Trusted Platform Extensions"))
	assert.True(t, strings.Contains(result, "Standard X.509 Extensions"))
	assert.True(t, strings.Contains(result, "Other Extensions"))
}
