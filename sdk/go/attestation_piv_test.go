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

package xkms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sdkAttestationChain builds a root and a leaf carrying exts, as a device
// would present them.
func sdkAttestationChain(t *testing.T, exts []pkix.Extension) (*x509.Certificate, *x509.CertPool) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "SDK PIV Attestation Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "PIV Attestation 9a"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(24 * time.Hour),
		ExtraExtensions: exts,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	return leaf, roots
}

// TestSDK_PIVAttestation_RoundTrip verifies the SDK re-exports let a consumer
// build, verify and read an attestation without reaching past sdk/go.
func TestSDK_PIVAttestation_RoundTrip(t *testing.T) {
	fw := PIVFirmwareVersion{Major: 5, Minor: 7, Patch: 1}
	serial := uint64(31415926)
	pin := PIVPINPolicyOnce
	touch := PIVTouchPolicyAlways
	ff := PIVFormFactorUSBCKeychain

	exts, err := BuildPIVAttestationExtensions(&PIVAttestation{
		FirmwareVersion: &fw,
		SerialNumber:    &serial,
		PINPolicy:       &pin,
		TouchPolicy:     &touch,
		FormFactor:      &ff,
	})
	require.NoError(t, err)

	leaf, roots := sdkAttestationChain(t, exts)

	got, err := VerifyPIVAttestation([]*x509.Certificate{leaf},
		&PIVAttestationVerifyOptions{TrustedRoots: roots})
	require.NoError(t, err)
	require.NotNil(t, got)

	// The three claims a policy is actually written against.
	require.NotNil(t, got.TouchPolicy)
	assert.Equal(t, PIVTouchPolicyAlways, *got.TouchPolicy)
	require.NotNil(t, got.SerialNumber)
	assert.Equal(t, uint64(31415926), *got.SerialNumber)
	require.NotNil(t, got.FirmwareVersion)
	assert.True(t, got.FirmwareVersion.AtLeast(5, 7, 0))
}

// TestSDK_PIVAttestation_UntrustedRejected proves the SDK re-export verifies
// rather than merely parsing. Without this the positive test above would pass
// against a verifier that accepts anything.
func TestSDK_PIVAttestation_UntrustedRejected(t *testing.T) {
	exts, err := BuildPIVAttestationExtensions(&PIVAttestation{SerialNumber: ptrUint64(7)})
	require.NoError(t, err)
	leaf, _ := sdkAttestationChain(t, exts)
	_, unrelatedRoots := sdkAttestationChain(t, nil)

	got, err := VerifyPIVAttestation([]*x509.Certificate{leaf},
		&PIVAttestationVerifyOptions{TrustedRoots: unrelatedRoots})
	require.Error(t, err)
	assert.Nil(t, got)
}

// TestSDK_ParsePIVAttestation_WithoutTrust covers the presence-check path a
// deployment with no vendor root configured still needs: parse without
// verifying, and ask whether this is an attestation certificate at all.
func TestSDK_ParsePIVAttestation_WithoutTrust(t *testing.T) {
	exts, err := BuildPIVAttestationExtensions(&PIVAttestation{SerialNumber: ptrUint64(11)})
	require.NoError(t, err)
	leaf, _ := sdkAttestationChain(t, exts)

	got, err := ParsePIVAttestation(leaf)
	require.NoError(t, err)
	assert.True(t, got.HasAttestationExtensions())
	require.NotNil(t, got.SerialNumber)
	assert.Equal(t, uint64(11), *got.SerialNumber)

	// An ordinary certificate is not an attestation, and that is not an error.
	plain, _ := sdkAttestationChain(t, nil)
	got, err = ParsePIVAttestation(plain)
	require.NoError(t, err)
	assert.False(t, got.HasAttestationExtensions())
}

// TestSDK_PIVAttestationOIDs pins the Yubico arc on the SDK surface, so a
// consumer performing a presence check names the same OIDs the parser reads.
func TestSDK_PIVAttestationOIDs(t *testing.T) {
	assert.Equal(t, "1.3.6.1.4.1.41482.3.3", OIDPIVFirmwareVersion.String())
	assert.Equal(t, "1.3.6.1.4.1.41482.3.7", OIDPIVSerialNumber.String())
	assert.Equal(t, "1.3.6.1.4.1.41482.3.8", OIDPIVPINTouchPolicy.String())
	assert.Equal(t, "1.3.6.1.4.1.41482.3.9", OIDPIVFormFactor.String())
}

func ptrUint64(n uint64) *uint64 { return &n }
