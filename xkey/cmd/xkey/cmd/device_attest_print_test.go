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

//go:build ble

package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// selfSignedCert builds a minimal, real self-signed certificate for the
// given subject/issuer pair, used by the printing-function tests below.
func selfSignedCert(t *testing.T, cn string, organization ...string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: cn, Organization: organization},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestFindMatchingTrustRoot_EmptyChain(t *testing.T) {
	require.Nil(t, findMatchingTrustRoot(nil, []*x509.Certificate{selfSignedCert(t, "root")}))
}

func TestFindMatchingTrustRoot_Match(t *testing.T) {
	root := selfSignedCert(t, "shared-root")
	leaf := selfSignedCert(t, "leaf")
	chain := []*x509.Certificate{leaf, root}

	got := findMatchingTrustRoot(chain, []*x509.Certificate{selfSignedCert(t, "other"), root})
	require.Same(t, root, got)
}

func TestFindMatchingTrustRoot_NoMatch(t *testing.T) {
	chain := []*x509.Certificate{selfSignedCert(t, "leaf"), selfSignedCert(t, "device-root")}
	got := findMatchingTrustRoot(chain, []*x509.Certificate{selfSignedCert(t, "unrelated")})
	require.Nil(t, got)
}

func TestFormatTrustAnchor_Nil(t *testing.T) {
	require.Equal(t, "Google Hardware Attestation Root (unknown variant)", formatTrustAnchor(nil))
}

func TestFormatTrustAnchor_OrganizationAndCommonName(t *testing.T) {
	cert := selfSignedCert(t, "GlobalSign Root", "Google")
	require.Equal(t, "Google - GlobalSign Root", formatTrustAnchor(cert))
}

func TestFormatTrustAnchor_CommonNameOnly(t *testing.T) {
	cert := selfSignedCert(t, "Some Root")
	require.Equal(t, "Some Root", formatTrustAnchor(cert))
}

func TestFormatTrustAnchor_OrganizationOnly(t *testing.T) {
	cert := selfSignedCert(t, "", "Acme Org")
	require.Equal(t, "Acme Org", formatTrustAnchor(cert))
}

func TestFormatTrustAnchor_SerialNumberFallback(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{SerialNumber: "SN123"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	require.Equal(t, "Google Hardware Attestation Root (SN=SN123)", formatTrustAnchor(cert))
}

func TestFormatTrustAnchor_Empty(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	require.Equal(t, "Google Hardware Attestation Root", formatTrustAnchor(cert))
}

func TestPrintAttestationCertificateChain_NoTrustInfo(t *testing.T) {
	leaf := selfSignedCert(t, "leaf")
	root := selfSignedCert(t, "root")
	out := captureDeviceInfoStdout(t, func() {
		printAttestationCertificateChain([]*x509.Certificate{leaf, root})
	})
	require.Contains(t, out, "Certificate Chain")
	require.Contains(t, out, "[0] Leaf/Attestation")
	require.Contains(t, out, "[1] Root")
	require.NotContains(t, out, "TRUST ANCHOR")
}

func TestPrintAttestationCertificateChain_WithTrustInfo(t *testing.T) {
	leaf := selfSignedCert(t, "leaf")
	inter := selfSignedCert(t, "intermediate")
	root := selfSignedCert(t, "root", "Google")
	chain := []*x509.Certificate{leaf, inter, root}

	out := captureDeviceInfoStdout(t, func() {
		printAttestationCertificateChainWithTrustInfo(chain, root)
	})
	require.Contains(t, out, "[2] Root")
	require.Contains(t, out, "TRUST ANCHOR")
	require.Contains(t, out, "Google - root")
	require.Contains(t, out, "FINGERPRINT MATCHES EMBEDDED ROOT")
}

func TestPrintAuthorizationList_Nil(t *testing.T) {
	out := captureDeviceInfoStdout(t, func() {
		printAuthorizationList(nil, "  ")
	})
	require.Contains(t, out, "(empty)")
}

func TestPrintAuthorizationList_NoParsedFields(t *testing.T) {
	out := captureDeviceInfoStdout(t, func() {
		printAuthorizationList(&xkms.AndroidAuthorizationList{}, "  ")
	})
	require.Contains(t, out, "(no parsed fields)")
}

func TestPrintAuthorizationList_FullFields(t *testing.T) {
	list := &xkms.AndroidAuthorizationList{
		Purpose:   []int{2, 3},
		Algorithm: 3,
		KeySize:   256,
		EcCurve:   1,
		Origin:    0,
	}
	out := captureDeviceInfoStdout(t, func() {
		printAuthorizationList(list, "  ")
	})
	require.Contains(t, out, "Purpose:")
	require.Contains(t, out, "Algorithm:")
	require.Contains(t, out, "Key Size:")
	require.Contains(t, out, "256 bits")
	require.Contains(t, out, "EC Curve:")
}

func TestPrintKeyDescription_Minimal(t *testing.T) {
	desc := &xkms.AndroidKeyDescription{
		AttestationVersion: 3,
		KeymasterVersion:   4,
	}
	out := captureDeviceInfoStdout(t, func() {
		printKeyDescription(desc)
	})
	require.Contains(t, out, "Key Attestation Extension")
	require.Contains(t, out, "Challenge (nonce):       (empty)")
	require.Contains(t, out, "Unique ID:               (not present)")
}

func TestPrintKeyDescription_WithChallengeAndRootOfTrust(t *testing.T) {
	desc := &xkms.AndroidKeyDescription{
		AttestationVersion:   3,
		KeymasterVersion:     4,
		AttestationChallenge: []byte("nonce-bytes"),
		UniqueID:             []byte{0xde, 0xad},
		TeeEnforced: xkms.AndroidAuthorizationList{
			RootOfTrust: &xkms.AndroidRootOfTrust{
				VerifiedBootKey:  []byte{0x01, 0x02},
				DeviceLocked:     true,
				VerifiedBootHash: []byte{0x03, 0x04},
			},
		},
	}
	out := captureDeviceInfoStdout(t, func() {
		printKeyDescription(desc)
	})
	require.Contains(t, out, "Root of Trust")
	require.Contains(t, out, "Device Locked:           yes")
	require.Contains(t, out, "Verified Boot Key:       0102")
	require.Contains(t, out, "Verified Boot Hash:      0304")
}

func deviceAttestTestCmd() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("device", "", "")
	cmd.Flags().Bool("no-verify", false, "")
	cmd.Flags().Duration("timeout", 50*time.Millisecond, "")
	return cmd
}

func TestRunDeviceAttest_NoConfig(t *testing.T) {
	deviceInfoTestHome(t)
	err := runDeviceAttest(deviceAttestTestCmd(), []string{"my-key"})
	require.ErrorIs(t, err, ErrDeviceNotPaired)
}

func TestRunDeviceAttest_DeviceNotFound(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	cmd := deviceAttestTestCmd()
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "device", "Nonexistent"))
	err := runDeviceAttest(cmd, []string{"my-key"})
	require.ErrorIs(t, err, ErrDeviceNotFound)
}

func TestRunDeviceAttest_ConnectFailure(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	err := runDeviceAttest(deviceAttestTestCmd(), []string{"my-key"})
	require.Error(t, err)
}
