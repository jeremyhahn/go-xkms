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

package attestation

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
)

// rootTypeStatement is a signed, self-signed statement in format whose
// certificate carries info as its DiceTcbInfo; a nil info leaves it out.
func rootTypeStatement(t *testing.T, format string, info *dice.TcbInfo) *AttestationStatement {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var extensions []pkix.Extension
	if info != nil {
		extension, err := dice.CreateTcbInfoExtension(info)
		require.NoError(t, err)
		// Only a DICE statement is anchored by a verifier that handles the
		// critical DiceTcbInfo; under another format it stays readable but
		// non-critical, so the chain still anchors and the case tests the
		// format, not crypto/x509's refusal.
		extension.Critical = Normalize(format) == FormatDICE
		extensions = append(extensions, extension)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test DICE Alias"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtraExtensions:       extensions,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	data := []byte("dice attestation data")
	digest := sha256.Sum256(data)
	signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)

	return &AttestationStatement{
		Format:                format,
		AttestingKeyAlgorithm: x509.ECDSA,
		AttestingKeyPublic:    key.Public(),
		Signature:             signature,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		CertificateChain:      []*x509.Certificate{cert},
		AttestedKeyPublic:     key.Public(),
		AttestationData:       data,
	}
}

// rootTypeInfo is a DiceTcbInfo whose vendorInfo names root, with notSecure
// as given.
func rootTypeInfo(t *testing.T, root dice.RootType, notSecure bool) *dice.TcbInfo {
	t.Helper()
	vendorInfo, err := dice.RootTypeVendorInfo(root)
	require.NoError(t, err)
	return &dice.TcbInfo{
		Vendor: "Automate The Things",
		FWIDs: []dice.FWID{{
			HashAlg: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1},
			Digest:  make([]byte, 32),
		}},
		Flags:      &dice.OperationalFlags{NotSecure: notSecure},
		VendorInfo: vendorInfo,
	}
}

func TestVerifyReportsTheDICERootType(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		info     *dice.TcbInfo
		expected dice.RootType
	}{
		{name: "a hardware chain", format: FormatDICE, info: rootTypeInfo(t, dice.RootTypeHardware, false), expected: dice.RootTypeHardware},
		{name: "a software chain", format: FormatDICE, info: rootTypeInfo(t, dice.RootTypeSoftware, true), expected: dice.RootTypeSoftware},
		{name: "a hardware vendorInfo with notSecure set", format: FormatDICE, info: rootTypeInfo(t, dice.RootTypeHardware, true), expected: dice.RootTypeSoftware},
		{name: "a chain with no DiceTcbInfo", format: FormatDICE, info: nil, expected: dice.RootTypeUnreported},
		{name: "the format in another case and padded", format: " DICE ", info: rootTypeInfo(t, dice.RootTypeSoftware, true), expected: dice.RootTypeSoftware},
		{name: "a declaration under another format", format: "tpm2", info: rootTypeInfo(t, dice.RootTypeHardware, false), expected: dice.RootTypeUnreported},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stmt := rootTypeStatement(t, test.format, test.info)

			// The self-signed alias is its own trusted root.
			result, err := NewVerifier(stmt.CertificateChain).Verify(stmt, &VerifyOptions{})
			require.NoError(t, err)
			assert.True(t, result.Valid)
			assert.Equal(t, test.expected, result.RootType)
		})
	}
}

func TestVerifyReadsNoDICERootTypeWithoutATrustedRoot(t *testing.T) {
	stmt := rootTypeStatement(t, FormatDICE, rootTypeInfo(t, dice.RootTypeHardware, false))

	result, err := NewVerifier(nil).Verify(stmt, &VerifyOptions{AllowSelfSigned: true})
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, dice.RootTypeUnreported, result.RootType)
}

func TestVerifyCarriesAnAncestorsNotSecureToTheResult(t *testing.T) {
	stmt, root, _ := twoLayerStatement(t, &dice.TcbInfo{Flags: &dice.OperationalFlags{NotSecure: true}})

	result, err := NewVerifier([]*x509.Certificate{root}).Verify(stmt, &VerifyOptions{})
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, dice.RootTypeSoftware, result.RootType)
}

// forgedAncestorStatement is a DICE statement whose alias certificate a trusted
// root signed, followed by a certificate that carries the root's name and key
// and declares a hardware root of trust, but that someone else signed. It
// returns the statement and the genuine root.
// twoLayerStatement returns a DICE statement whose alias is signed by a root
// carrying rootInfo (none when nil), with the chain [alias, root], the root
// and its key.
func twoLayerStatement(t *testing.T, rootInfo *dice.TcbInfo) (*AttestationStatement, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	aliasKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test DICE Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if rootInfo != nil {
		extension, err := dice.CreateTcbInfoExtension(rootInfo)
		require.NoError(t, err)
		// The root is a trust anchor, taken from the verifier's own pool, and
		// crypto/x509 refuses an anchor with an unhandled critical extension.
		// Non-critical, its DiceTcbInfo is still read off the verified path.
		extension.Critical = false
		rootTemplate.ExtraExtensions = []pkix.Extension{extension}
	}
	der, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	der, err = x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test DICE Alias"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, root, aliasKey.Public(), rootKey)
	require.NoError(t, err)
	alias, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	data := []byte("dice attestation data")
	digest := sha256.Sum256(data)
	signature, err := aliasKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)

	return &AttestationStatement{
		Format:                FormatDICE,
		AttestingKeyAlgorithm: x509.ECDSA,
		AttestingKeyPublic:    aliasKey.Public(),
		Signature:             signature,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		CertificateChain:      []*x509.Certificate{alias, root},
		AttestedKeyPublic:     aliasKey.Public(),
		AttestationData:       data,
	}, root, rootKey
}

// forgedAncestorStatement returns a two-layer statement whose root is
// replaced by a forgery: the root's name and key with a hardware DiceTcbInfo,
// signed by a key nobody trusts. It also returns the genuine root.
func forgedAncestorStatement(t *testing.T) (*AttestationStatement, *x509.Certificate) {
	t.Helper()
	stmt, root, rootKey := twoLayerStatement(t, nil)
	forgerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	extension, err := dice.CreateTcbInfoExtension(rootTypeInfo(t, dice.RootTypeHardware, false))
	require.NoError(t, err)
	forgedTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               root.Subject,
		NotBefore:             root.NotBefore,
		NotAfter:              root.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtraExtensions:       []pkix.Extension{extension},
	}
	forger := &x509.Certificate{Subject: root.Subject, PublicKey: forgerKey.Public()}
	der, err := x509.CreateCertificate(rand.Reader, forgedTemplate, forger, rootKey.Public(), forgerKey)
	require.NoError(t, err)
	forged, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	stmt.CertificateChain = []*x509.Certificate{stmt.CertificateChain[0], forged}
	return stmt, root
}

func TestVerifyIgnoresADICECertificateOffTheVerifiedPath(t *testing.T) {
	// The forged certificate carries the root's key, so the alias's signature
	// checks out against it, but the path x509 verifies runs through the
	// genuine root: nothing authenticated the forged one's hardware claim.
	stmt, root := forgedAncestorStatement(t)

	result, err := NewVerifier([]*x509.Certificate{root}).Verify(stmt, &VerifyOptions{})
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, dice.RootTypeUnreported, result.RootType)
}

func TestVerifyResultOnFailure(t *testing.T) {
	t.Run("an invalid statement has no result", func(t *testing.T) {
		result, err := NewVerifier(nil).Verify(&AttestationStatement{}, &VerifyOptions{})
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("a failed check is recorded in the result", func(t *testing.T) {
		stmt := rootTypeStatement(t, FormatDICE, rootTypeInfo(t, dice.RootTypeHardware, false))
		stmt.Signature = []byte("not a signature")

		result, err := NewVerifier(stmt.CertificateChain).Verify(stmt, &VerifyOptions{})
		assert.ErrorIs(t, err, ErrSignatureVerificationFailed)
		require.NotNil(t, result)
		assert.False(t, result.Valid)
		assert.True(t, result.ChainValid)
		assert.False(t, result.SignatureValid)
		assert.Error(t, result.Error)
		assert.Equal(t, dice.RootTypeHardware, result.RootType)
	})

	t.Run("a DICE chain that does not anchor reads no root type", func(t *testing.T) {
		stmt := rootTypeStatement(t, FormatDICE, rootTypeInfo(t, dice.RootTypeHardware, false))
		unrelated := rootTypeStatement(t, FormatDICE, nil).CertificateChain

		result, err := NewVerifier(unrelated).Verify(stmt, &VerifyOptions{})
		assert.ErrorIs(t, err, ErrChainNotAnchored)
		require.NotNil(t, result)
		assert.False(t, result.ChainValid)
		assert.Equal(t, dice.RootTypeUnreported, result.RootType)
	})
}
