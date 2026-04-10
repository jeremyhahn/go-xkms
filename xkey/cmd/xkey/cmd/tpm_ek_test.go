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

package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"os"
	"testing"
	"time"

	xkeyAttestation "github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateEKTestCA creates a self-signed CA certificate that simulates a
// TPM manufacturer root CA. The certificate is valid for issuing EK certs.
func generateEKTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test TPM Manufacturer CA",
			Organization: []string{"Infineon Technologies AG"},
		},
		Issuer: pkix.Name{
			CommonName:   "Test TPM Manufacturer CA",
			Organization: []string{"Infineon Technologies AG"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	return caCert, caKey
}

// generateEKTestLeaf creates an EK leaf certificate signed by the given CA.
func generateEKTestLeaf(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			CommonName: "Test EK Certificate",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	return leafCert
}

// TestVerifyEKCertificateResult_Verified tests that verifyEKCertificateResult
// returns a successful verification when the EK cert chains to a trusted
// TPM manufacturer root in the trust store.
func TestVerifyEKCertificateResult_Verified(t *testing.T) {
	resetViperForTest(t)

	// Create a CA and EK leaf cert signed by it
	caCert, caKey := generateEKTestCA(t)
	ekLeaf := generateEKTestLeaf(t, caCert, caKey)

	// Set up trust store with the CA cert classified as tpm-manufacturer
	dir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)

	err = store.AddCertificateWithOptions(caCert, &truststore.AddCertificateOptions{
		Purpose: truststore.PurposeTPMManufacturer,
		Source:  "test",
	})
	require.NoError(t, err)
	require.NoError(t, store.Close())

	viper.Set("trust.store_path", dir)

	result := verifyEKCertificateResult(ekLeaf)
	require.NotNil(t, result)
	assert.True(t, result.Verified)
	assert.Equal(t, xkeyAttestation.TrustLevelHardware, result.TrustLevel)
	assert.Equal(t, ekLeaf.Subject.String(), result.Subject)
	assert.Equal(t, ekLeaf.Issuer.String(), result.Issuer)
	assert.GreaterOrEqual(t, result.ChainLength, 2)
	assert.Contains(t, result.Message, "TPM EK certificate verified")
}

// TestVerifyEKCertificateResult_NotVerified tests that verifyEKCertificateResult
// returns a failure result when the EK cert does not chain to any trusted root.
func TestVerifyEKCertificateResult_NotVerified(t *testing.T) {
	resetViperForTest(t)

	// Create an EK cert signed by an unknown CA (not in trust store)
	unknownCA, unknownKey := generateEKTestCA(t)
	ekLeaf := generateEKTestLeaf(t, unknownCA, unknownKey)

	// Set up empty trust store (no manufacturer CAs)
	dir := t.TempDir()

	// Add a different, unrelated cert so the store is not empty but has
	// no TPM manufacturer certs
	otherCert := generateTrustTestCert(t)
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	err = store.AddCertificateWithOptions(otherCert, &truststore.AddCertificateOptions{
		Purpose: truststore.PurposeUserCA,
		Source:  "test",
	})
	require.NoError(t, err)
	require.NoError(t, store.Close())

	viper.Set("trust.store_path", dir)

	result := verifyEKCertificateResult(ekLeaf)
	// When no TPM manufacturer certs exist, the verifier returns
	// ErrNoTrustAnchors and verifyEKCertificateResult falls back to
	// a constructed failure result.
	require.NotNil(t, result)
	assert.False(t, result.Verified)
}

// TestVerifyEKCertificateResult_TrustStoreUnavailable tests that
// verifyEKCertificateResult returns nil when the trust store cannot be opened.
func TestVerifyEKCertificateResult_TrustStoreUnavailable(t *testing.T) {
	resetViperForTest(t)

	// Point to a non-existent path that cannot be created
	viper.Set("trust.store_path", "/nonexistent/path/that/cannot/be/created/\x00invalid")

	cert := generateTrustTestCert(t)
	result := verifyEKCertificateResult(cert)
	assert.Nil(t, result)
}

// TestVerifyEKCertificate_PrintsVerified tests that verifyEKCertificate
// prints VERIFIED status to stdout when verification succeeds.
func TestVerifyEKCertificate_PrintsVerified(t *testing.T) {
	resetViperForTest(t)

	caCert, caKey := generateEKTestCA(t)
	ekLeaf := generateEKTestLeaf(t, caCert, caKey)

	dir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)

	err = store.AddCertificateWithOptions(caCert, &truststore.AddCertificateOptions{
		Purpose: truststore.PurposeTPMManufacturer,
		Source:  "test",
	})
	require.NoError(t, err)
	require.NoError(t, store.Close())

	viper.Set("trust.store_path", dir)

	output := captureStdout(t, func() {
		verifyEKCertificate(ekLeaf)
	})

	assert.Contains(t, output, "EK Certificate Verification:")
	assert.Contains(t, output, "VERIFIED")
	assert.Contains(t, output, "hardware")
	assert.Contains(t, output, "certificate(s)")
}

// TestVerifyEKCertificate_PrintsNotVerified tests that verifyEKCertificate
// prints NOT VERIFIED status when verification fails due to untrusted chain.
func TestVerifyEKCertificate_PrintsNotVerified(t *testing.T) {
	resetViperForTest(t)

	// Create an EK cert that won't be verified
	unknownCA, unknownKey := generateEKTestCA(t)
	ekLeaf := generateEKTestLeaf(t, unknownCA, unknownKey)

	// Trust store with no manufacturer certs
	dir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)

	// Add a cert classified as something else so store opens fine
	otherCert := generateTrustTestCert(t)
	err = store.AddCertificateWithOptions(otherCert, &truststore.AddCertificateOptions{
		Purpose: truststore.PurposeUserCA,
	})
	require.NoError(t, err)
	require.NoError(t, store.Close())

	viper.Set("trust.store_path", dir)

	output := captureStdout(t, func() {
		verifyEKCertificate(ekLeaf)
	})

	assert.Contains(t, output, "EK Certificate Verification:")
	assert.Contains(t, output, "NOT VERIFIED")
}

// TestVerifyEKCertificate_PrintsSkipped tests that verifyEKCertificate
// prints the skipped message when the trust store cannot be opened.
func TestVerifyEKCertificate_PrintsSkipped(t *testing.T) {
	resetViperForTest(t)

	// Point to invalid path
	viper.Set("trust.store_path", "/nonexistent/path/\x00invalid")

	cert := generateTrustTestCert(t)

	output := captureStdout(t, func() {
		verifyEKCertificate(cert)
	})

	assert.Contains(t, output, "EK Certificate Verification:")
	assert.Contains(t, output, "Skipped (trust store not available)")
}

// TestVerifyEKCertificate_SelfSignedCA tests verification when the EK cert
// is self-signed (the CA cert IS the EK cert) and is in the trust store.
func TestVerifyEKCertificate_SelfSignedCA(t *testing.T) {
	resetViperForTest(t)

	// Self-signed cert acting as both CA and EK
	caCert, _ := generateEKTestCA(t)

	dir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)

	err = store.AddCertificateWithOptions(caCert, &truststore.AddCertificateOptions{
		Purpose: truststore.PurposeTPMManufacturer,
		Source:  "test",
	})
	require.NoError(t, err)
	require.NoError(t, store.Close())

	viper.Set("trust.store_path", dir)

	// Self-signed CA cert should verify against itself in the trust store
	result := verifyEKCertificateResult(caCert)
	require.NotNil(t, result)
	assert.True(t, result.Verified)
	assert.Equal(t, xkeyAttestation.TrustLevelHardware, result.TrustLevel)
}

// TestTPMEKCmdStructure verifies the tpm ek command tree is properly initialized.
func TestTPMEKCmdStructure(t *testing.T) {
	require.NotNil(t, tpmEKCmd)
	assert.Equal(t, "ek", tpmEKCmd.Use)

	subcommands := tpmEKCmd.Commands()
	expectedNames := map[string]bool{
		"show":    false,
		"export":  false,
		"backup":  false,
		"restore": false,
	}

	for _, cmd := range subcommands {
		if _, ok := expectedNames[cmd.Use]; ok {
			expectedNames[cmd.Use] = true
		}
	}

	for name, found := range expectedNames {
		assert.True(t, found, "subcommand %q not registered", name)
	}
}

// TestTPMEKCmdFlags verifies that all expected flags are registered.
func TestTPMEKCmdFlags(t *testing.T) {
	// Show command should have --ec flag
	ecFlag := tpmEKShowCmd.Flags().Lookup("ec")
	require.NotNil(t, ecFlag)
	assert.Equal(t, "false", ecFlag.DefValue)

	// Export command should have --output and --ec flags
	outputFlag := tpmEKExportCmd.Flags().Lookup("output")
	require.NotNil(t, outputFlag)

	ecExportFlag := tpmEKExportCmd.Flags().Lookup("ec")
	require.NotNil(t, ecExportFlag)

	// Backup command should have --output flag
	backupOutputFlag := tpmEKBackupCmd.Flags().Lookup("output")
	require.NotNil(t, backupOutputFlag)
	assert.Equal(t, ".", backupOutputFlag.DefValue)

	// Restore command should have --input, --ec, --force flags
	inputFlag := tpmEKRestoreCmd.Flags().Lookup("input")
	require.NotNil(t, inputFlag)

	ecRestoreFlag := tpmEKRestoreCmd.Flags().Lookup("ec")
	require.NotNil(t, ecRestoreFlag)

	forceFlag := tpmEKRestoreCmd.Flags().Lookup("force")
	require.NotNil(t, forceFlag)
	assert.Equal(t, "false", forceFlag.DefValue)
}

// captureStdout redirects os.Stdout to a pipe for the duration of fn(),
// returning the captured output as a string.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	origStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)

	os.Stdout = w

	fn()

	require.NoError(t, w.Close())
	os.Stdout = origStdout

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)

	return buf.String()
}
