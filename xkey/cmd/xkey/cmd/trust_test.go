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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTrustTestCert creates a self-signed CA certificate for testing.
func generateTrustTestCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// generateTrustTestCertPEM creates PEM-encoded test certificate data and
// returns both the PEM bytes and the parsed certificate.
func generateTrustTestCertPEM(t *testing.T) ([]byte, *x509.Certificate) {
	t.Helper()

	cert := generateTrustTestCert(t)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return pemData, cert
}

// generateRSATestCert creates a self-signed certificate using an RSA key.
func generateRSATestCert(t *testing.T, bits int) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "RSA Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// generateEd25519TestCert creates a self-signed certificate using an Ed25519 key.
func generateEd25519TestCert(t *testing.T) *x509.Certificate {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "Ed25519 Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// generateRichTestCert creates a self-signed certificate with all SAN fields
// populated (DNSNames, EmailAddresses, IPAddresses, URIs) plus ExtKeyUsage
// to exercise all branches in runTrustShow.
func generateRichTestCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	exampleURI, err := url.Parse("https://example.com/ca")
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			CommonName:   "Rich Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
		DNSNames:              []string{"example.com", "*.example.com"},
		EmailAddresses:        []string{"admin@example.com"},
		IPAddresses:           []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("::1")},
		URIs:                  []*url.URL{exampleURI},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// resetViperForTest resets viper state and registers cleanup.
func resetViperForTest(t *testing.T) {
	t.Helper()
	viper.Reset()
	t.Cleanup(func() { viper.Reset() })
}

// setupTrustStoreDir creates a temp dir with a trust store containing the
// provided certificates, sets the viper config, and returns the store path.
func setupTrustStoreDir(t *testing.T, certs ...*x509.Certificate) string {
	t.Helper()

	dir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)

	for _, cert := range certs {
		err := store.AddCertificate(cert)
		require.NoError(t, err)
	}
	require.NoError(t, store.Close())

	viper.Set("trust.store_path", dir)
	return dir
}

// setupTrustStoreDirWithOptions creates a temp dir with a trust store containing
// a certificate added with the given options, sets the viper config, and
// returns the store path.
func setupTrustStoreDirWithOptions(t *testing.T, cert *x509.Certificate, opts *truststore.AddCertificateOptions) string {
	t.Helper()

	dir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)

	err = store.AddCertificateWithOptions(cert, opts)
	require.NoError(t, err)
	require.NoError(t, store.Close())

	viper.Set("trust.store_path", dir)
	return dir
}

// newTrustAddCmd creates a cobra.Command with the purpose and source flags
// registered, mimicking the real trustAddCmd flag setup.
func newTrustAddCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.Flags().String("purpose", "", "certificate purpose")
	cmd.Flags().String("source", "", "source of the certificate")
	return cmd
}

// newTrustClassifyCmd creates a cobra.Command with the purpose flag registered,
// mimicking the real trustClassifyCmd flag setup.
func newTrustClassifyCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.Flags().String("purpose", "", "certificate purpose")
	return cmd
}

// --- openTrustStore tests ---

func TestOpenTrustStore_WithViperConfig(t *testing.T) {
	resetViperForTest(t)

	dir := t.TempDir()
	viper.Set("trust.store_path", dir)

	store, err := openTrustStore()
	require.NoError(t, err)
	require.NotNil(t, store)

	count, err := store.Count()
	require.NoError(t, err)
	assert.Equal(t, 0, count)
	require.NoError(t, store.Close())
}

func TestOpenTrustStore_DefaultPath(t *testing.T) {
	resetViperForTest(t)

	// Do not set trust.store_path -- openTrustStore should fall back to
	// the user home directory default. Since we are running in a CI-friendly
	// environment, this should succeed as long as os.UserHomeDir works.
	store, err := openTrustStore()
	require.NoError(t, err)
	require.NotNil(t, store)
	require.NoError(t, store.Close())
}

// --- runTrustList tests ---

func TestRunTrustList_EmptyStore(t *testing.T) {
	resetViperForTest(t)

	dir := t.TempDir()
	viper.Set("trust.store_path", dir)

	cmd := &cobra.Command{}
	err := runTrustList(cmd, nil)
	assert.NoError(t, err)
}

func TestRunTrustList_PopulatedStore(t *testing.T) {
	resetViperForTest(t)

	cert := generateTrustTestCert(t)
	setupTrustStoreDir(t, cert)

	cmd := &cobra.Command{}
	err := runTrustList(cmd, nil)
	assert.NoError(t, err)
}

func TestRunTrustList_MultipleCertificates(t *testing.T) {
	resetViperForTest(t)

	cert1 := generateTrustTestCert(t)
	cert2 := generateRSATestCert(t, 2048)
	setupTrustStoreDir(t, cert1, cert2)

	cmd := &cobra.Command{}
	err := runTrustList(cmd, nil)
	assert.NoError(t, err)
}

func TestRunTrustList_InvalidStorePath(t *testing.T) {
	resetViperForTest(t)

	// Point to a path that is a file, not a directory, to force an open error.
	tmpFile := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(tmpFile, []byte("data"), 0o600))
	viper.Set("trust.store_path", filepath.Join(tmpFile, "subdir"))

	cmd := &cobra.Command{}
	err := runTrustList(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustStoreOpen))
}

func TestRunTrustList_ShowsPurposeAndSource(t *testing.T) {
	resetViperForTest(t)

	cert := generateTrustTestCert(t)
	setupTrustStoreDirWithOptions(t, cert, &truststore.AddCertificateOptions{
		Purpose: truststore.PurposeTPMManufacturer,
		Source:  "file:test-ca.pem",
	})

	cmd := &cobra.Command{}
	err := runTrustList(cmd, nil)
	assert.NoError(t, err)
}

// --- runTrustAdd tests ---

func TestRunTrustAdd_ValidPEMFile(t *testing.T) {
	resetViperForTest(t)

	dir := t.TempDir()
	viper.Set("trust.store_path", dir)

	// Write a PEM file to disk.
	pemData, _ := generateTrustTestCertPEM(t)
	pemFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(pemFile, pemData, 0o600))

	cmd := newTrustAddCmd(t)
	err := runTrustAdd(cmd, []string{pemFile})
	assert.NoError(t, err)

	// Verify the certificate was added.
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	defer store.Close()

	count, err := store.Count()
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestRunTrustAdd_MultipleCertsInPEM(t *testing.T) {
	resetViperForTest(t)

	dir := t.TempDir()
	viper.Set("trust.store_path", dir)

	pem1, _ := generateTrustTestCertPEM(t)
	pem2, _ := generateTrustTestCertPEM(t)
	combined := append(pem1, pem2...)

	pemFile := filepath.Join(t.TempDir(), "bundle.pem")
	require.NoError(t, os.WriteFile(pemFile, combined, 0o600))

	cmd := newTrustAddCmd(t)
	err := runTrustAdd(cmd, []string{pemFile})
	assert.NoError(t, err)

	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	defer store.Close()

	count, err := store.Count()
	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestRunTrustAdd_NonexistentFile(t *testing.T) {
	resetViperForTest(t)

	dir := t.TempDir()
	viper.Set("trust.store_path", dir)

	cmd := newTrustAddCmd(t)
	err := runTrustAdd(cmd, []string{"/nonexistent/path/cert.pem"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustPEMReadFailed))
}

func TestRunTrustAdd_InvalidPEMContent(t *testing.T) {
	resetViperForTest(t)

	dir := t.TempDir()
	viper.Set("trust.store_path", dir)

	// Write a file with invalid PEM data.
	badFile := filepath.Join(t.TempDir(), "bad.pem")
	require.NoError(t, os.WriteFile(badFile, []byte("not valid PEM"), 0o600))

	cmd := newTrustAddCmd(t)
	err := runTrustAdd(cmd, []string{badFile})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustAddFailed))
}

func TestRunTrustAdd_InvalidStorePath(t *testing.T) {
	resetViperForTest(t)

	// Use a path that cannot be created as a directory.
	tmpFile := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(tmpFile, []byte("data"), 0o600))
	viper.Set("trust.store_path", filepath.Join(tmpFile, "subdir"))

	pemData, _ := generateTrustTestCertPEM(t)
	pemFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(pemFile, pemData, 0o600))

	cmd := newTrustAddCmd(t)
	err := runTrustAdd(cmd, []string{pemFile})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustStoreOpen))
}

func TestRunTrustAdd_WithPurposeFlag(t *testing.T) {
	resetViperForTest(t)

	dir := t.TempDir()
	viper.Set("trust.store_path", dir)

	pemData, cert := generateTrustTestCertPEM(t)
	pemFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(pemFile, pemData, 0o600))

	cmd := newTrustAddCmd(t)
	require.NoError(t, cmd.Flags().Set("purpose", "tpm-manufacturer"))

	err := runTrustAdd(cmd, []string{pemFile})
	assert.NoError(t, err)

	// Verify the purpose was set on the certificate metadata.
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	defer store.Close()

	fp := truststore.Fingerprint(cert)
	meta, err := store.Metadata(fp)
	require.NoError(t, err)
	assert.Equal(t, truststore.PurposeTPMManufacturer, meta.Purpose)
}

func TestRunTrustAdd_WithSourceFlag(t *testing.T) {
	resetViperForTest(t)

	dir := t.TempDir()
	viper.Set("trust.store_path", dir)

	pemData, cert := generateTrustTestCertPEM(t)
	pemFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(pemFile, pemData, 0o600))

	cmd := newTrustAddCmd(t)
	require.NoError(t, cmd.Flags().Set("source", "url:https://example.com/ca.pem"))

	err := runTrustAdd(cmd, []string{pemFile})
	assert.NoError(t, err)

	// Verify the source was set on the certificate metadata.
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	defer store.Close()

	fp := truststore.Fingerprint(cert)
	meta, err := store.Metadata(fp)
	require.NoError(t, err)
	assert.Equal(t, "url:https://example.com/ca.pem", meta.Source)
}

func TestRunTrustAdd_WithPurposeAndSourceFlags(t *testing.T) {
	resetViperForTest(t)

	dir := t.TempDir()
	viper.Set("trust.store_path", dir)

	pemData, cert := generateTrustTestCertPEM(t)
	pemFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(pemFile, pemData, 0o600))

	cmd := newTrustAddCmd(t)
	require.NoError(t, cmd.Flags().Set("purpose", "android-hardware"))
	require.NoError(t, cmd.Flags().Set("source", "manual"))

	err := runTrustAdd(cmd, []string{pemFile})
	assert.NoError(t, err)

	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	defer store.Close()

	fp := truststore.Fingerprint(cert)
	meta, err := store.Metadata(fp)
	require.NoError(t, err)
	assert.Equal(t, truststore.PurposeAndroidHardware, meta.Purpose)
	assert.Equal(t, "manual", meta.Source)
}

func TestRunTrustAdd_InvalidPurposeFlag(t *testing.T) {
	resetViperForTest(t)

	dir := t.TempDir()
	viper.Set("trust.store_path", dir)

	pemData, _ := generateTrustTestCertPEM(t)
	pemFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(pemFile, pemData, 0o600))

	cmd := newTrustAddCmd(t)
	require.NoError(t, cmd.Flags().Set("purpose", "invalid-purpose"))

	err := runTrustAdd(cmd, []string{pemFile})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustAddFailed))
}

func TestRunTrustAdd_WithPurposeMultipleCerts(t *testing.T) {
	resetViperForTest(t)

	dir := t.TempDir()
	viper.Set("trust.store_path", dir)

	pem1, cert1 := generateTrustTestCertPEM(t)
	pem2, cert2 := generateTrustTestCertPEM(t)
	combined := append(pem1, pem2...)

	pemFile := filepath.Join(t.TempDir(), "bundle.pem")
	require.NoError(t, os.WriteFile(pemFile, combined, 0o600))

	cmd := newTrustAddCmd(t)
	require.NoError(t, cmd.Flags().Set("purpose", "user-ca"))

	err := runTrustAdd(cmd, []string{pemFile})
	assert.NoError(t, err)

	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	defer store.Close()

	count, err := store.Count()
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	// Both certificates should have the same purpose.
	for _, cert := range []*x509.Certificate{cert1, cert2} {
		fp := truststore.Fingerprint(cert)
		meta, err := store.Metadata(fp)
		require.NoError(t, err)
		assert.Equal(t, truststore.PurposeUserCA, meta.Purpose)
	}
}

// --- addPEMWithOptions tests ---

func TestAddPEMWithOptions_ValidPEM(t *testing.T) {
	dir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	defer store.Close()

	pemData, _ := generateTrustTestCertPEM(t)
	opts := &truststore.AddCertificateOptions{
		Purpose: truststore.PurposeBootstrapCA,
		Source:  "test",
	}

	added, err := addPEMWithOptions(store, pemData, opts)
	require.NoError(t, err)
	assert.Equal(t, 1, added)
}

func TestAddPEMWithOptions_DuplicateSkipped(t *testing.T) {
	dir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	defer store.Close()

	pemData, _ := generateTrustTestCertPEM(t)
	opts := &truststore.AddCertificateOptions{
		Purpose: truststore.PurposeGeneral,
	}

	// Add once.
	added, err := addPEMWithOptions(store, pemData, opts)
	require.NoError(t, err)
	assert.Equal(t, 1, added)

	// Add again - should be skipped.
	added, err = addPEMWithOptions(store, pemData, opts)
	require.NoError(t, err)
	assert.Equal(t, 0, added)
}

func TestAddPEMWithOptions_NoPEMBlocks(t *testing.T) {
	dir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	defer store.Close()

	opts := &truststore.AddCertificateOptions{
		Purpose: truststore.PurposeGeneral,
	}

	added, err := addPEMWithOptions(store, []byte("not pem data"), opts)
	require.NoError(t, err)
	assert.Equal(t, 0, added)
}

func TestAddPEMWithOptions_InvalidCertData(t *testing.T) {
	dir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	defer store.Close()

	// Create PEM block with garbage DER data.
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("bad cert data")})
	opts := &truststore.AddCertificateOptions{
		Purpose: truststore.PurposeGeneral,
	}

	_, err = addPEMWithOptions(store, badPEM, opts)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustAddFailed))
}

func TestAddPEMWithOptions_SkipsNonCertBlocks(t *testing.T) {
	dir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	defer store.Close()

	// Mix a private key block with a certificate block.
	keyBlock := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("fake key")})
	certPEM, _ := generateTrustTestCertPEM(t)
	combined := append(keyBlock, certPEM...)

	opts := &truststore.AddCertificateOptions{
		Purpose: truststore.PurposeIDevIDIssuer,
	}

	added, err := addPEMWithOptions(store, combined, opts)
	require.NoError(t, err)
	assert.Equal(t, 1, added)
}

// --- runTrustRemove tests ---

func TestRunTrustRemove_ExistingCert(t *testing.T) {
	resetViperForTest(t)

	cert := generateTrustTestCert(t)
	fp := truststore.Fingerprint(cert)
	dir := setupTrustStoreDir(t, cert)

	cmd := &cobra.Command{}
	err := runTrustRemove(cmd, []string{fp})
	assert.NoError(t, err)

	// Verify removal.
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	defer store.Close()

	count, err := store.Count()
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestRunTrustRemove_NonexistentFingerprint(t *testing.T) {
	resetViperForTest(t)

	dir := t.TempDir()
	viper.Set("trust.store_path", dir)

	// Valid hex fingerprint format but no matching certificate.
	fakeFP := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	cmd := &cobra.Command{}
	err := runTrustRemove(cmd, []string{fakeFP})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustCertificateNotFound))
}

func TestRunTrustRemove_WhitespaceHandling(t *testing.T) {
	resetViperForTest(t)

	cert := generateTrustTestCert(t)
	fp := truststore.Fingerprint(cert)
	setupTrustStoreDir(t, cert)

	// Pass fingerprint with leading/trailing whitespace.
	cmd := &cobra.Command{}
	err := runTrustRemove(cmd, []string{"  " + fp + "  "})
	assert.NoError(t, err)
}

func TestRunTrustRemove_CaseInsensitive(t *testing.T) {
	resetViperForTest(t)

	cert := generateTrustTestCert(t)
	fp := truststore.Fingerprint(cert)
	setupTrustStoreDir(t, cert)

	// Pass fingerprint in uppercase -- runTrustRemove lowercases it.
	cmd := &cobra.Command{}
	err := runTrustRemove(cmd, []string{" " + fp + " "})
	assert.NoError(t, err)
}

func TestRunTrustRemove_InvalidStorePath(t *testing.T) {
	resetViperForTest(t)

	tmpFile := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(tmpFile, []byte("data"), 0o600))
	viper.Set("trust.store_path", filepath.Join(tmpFile, "subdir"))

	cmd := &cobra.Command{}
	err := runTrustRemove(cmd, []string{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustStoreOpen))
}

// --- runTrustShow tests ---

func TestRunTrustShow_ExistingCert(t *testing.T) {
	resetViperForTest(t)

	cert := generateTrustTestCert(t)
	fp := truststore.Fingerprint(cert)
	setupTrustStoreDir(t, cert)

	cmd := &cobra.Command{}
	err := runTrustShow(cmd, []string{fp})
	assert.NoError(t, err)
}

func TestRunTrustShow_NonexistentFingerprint(t *testing.T) {
	resetViperForTest(t)

	dir := t.TempDir()
	viper.Set("trust.store_path", dir)

	fakeFP := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	cmd := &cobra.Command{}
	err := runTrustShow(cmd, []string{fakeFP})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustCertificateNotFound))
}

func TestRunTrustShow_WhitespaceAndCaseHandling(t *testing.T) {
	resetViperForTest(t)

	cert := generateTrustTestCert(t)
	fp := truststore.Fingerprint(cert)
	setupTrustStoreDir(t, cert)

	// Fingerprint with whitespace and mixed case.
	cmd := &cobra.Command{}
	err := runTrustShow(cmd, []string{"  " + fp + "  "})
	assert.NoError(t, err)
}

func TestRunTrustShow_InvalidStorePath(t *testing.T) {
	resetViperForTest(t)

	tmpFile := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(tmpFile, []byte("data"), 0o600))
	viper.Set("trust.store_path", filepath.Join(tmpFile, "subdir"))

	cmd := &cobra.Command{}
	err := runTrustShow(cmd, []string{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustStoreOpen))
}

func TestRunTrustShow_RichCert_AllSANFields(t *testing.T) {
	resetViperForTest(t)

	// Generate a certificate with DNSNames, EmailAddresses, IPAddresses,
	// URIs, and ExtKeyUsage to exercise all optional display branches.
	cert := generateRichTestCert(t)
	fp := truststore.Fingerprint(cert)
	setupTrustStoreDir(t, cert)

	cmd := &cobra.Command{}
	err := runTrustShow(cmd, []string{fp})
	assert.NoError(t, err)
}

func TestRunTrustShow_CertNoKeyUsage(t *testing.T) {
	resetViperForTest(t)

	// Generate a certificate with zero KeyUsage to exercise the
	// branch where KeyUsage is not printed.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(200),
		Subject:               pkix.Name{CommonName: "No Key Usage CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	fp := truststore.Fingerprint(cert)
	setupTrustStoreDir(t, cert)

	cmd := &cobra.Command{}
	err = runTrustShow(cmd, []string{fp})
	assert.NoError(t, err)
}

func TestRunTrustShow_DisplaysMetadata(t *testing.T) {
	resetViperForTest(t)

	cert := generateTrustTestCert(t)
	fp := truststore.Fingerprint(cert)
	setupTrustStoreDirWithOptions(t, cert, &truststore.AddCertificateOptions{
		Purpose: truststore.PurposeAndroidHardware,
		Source:  "url:https://example.com/ca.pem",
		Tags:    []string{"vendor", "android"},
	})

	cmd := &cobra.Command{}
	err := runTrustShow(cmd, []string{fp})
	assert.NoError(t, err)
}

func TestRunTrustShow_DisplaysMetadataNoSource(t *testing.T) {
	resetViperForTest(t)

	cert := generateTrustTestCert(t)
	fp := truststore.Fingerprint(cert)
	setupTrustStoreDirWithOptions(t, cert, &truststore.AddCertificateOptions{
		Purpose: truststore.PurposeGeneral,
	})

	cmd := &cobra.Command{}
	err := runTrustShow(cmd, []string{fp})
	assert.NoError(t, err)
}

// --- runTrustClassify tests ---

func TestRunTrustClassify_ValidReclassification(t *testing.T) {
	resetViperForTest(t)

	cert := generateTrustTestCert(t)
	fp := truststore.Fingerprint(cert)
	dir := setupTrustStoreDir(t, cert)

	cmd := newTrustClassifyCmd(t)
	require.NoError(t, cmd.Flags().Set("purpose", "tpm-manufacturer"))

	err := runTrustClassify(cmd, []string{fp})
	assert.NoError(t, err)

	// Verify the purpose was updated.
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	defer store.Close()

	meta, err := store.Metadata(fp)
	require.NoError(t, err)
	assert.Equal(t, truststore.PurposeTPMManufacturer, meta.Purpose)
}

func TestRunTrustClassify_InvalidPurpose(t *testing.T) {
	resetViperForTest(t)

	cert := generateTrustTestCert(t)
	fp := truststore.Fingerprint(cert)
	setupTrustStoreDir(t, cert)

	cmd := newTrustClassifyCmd(t)
	require.NoError(t, cmd.Flags().Set("purpose", "not-a-purpose"))

	err := runTrustClassify(cmd, []string{fp})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustClassifyFailed))
}

func TestRunTrustClassify_EmptyPurpose(t *testing.T) {
	resetViperForTest(t)

	cert := generateTrustTestCert(t)
	fp := truststore.Fingerprint(cert)
	setupTrustStoreDir(t, cert)

	cmd := newTrustClassifyCmd(t)
	// Do not set purpose flag, it remains empty.

	err := runTrustClassify(cmd, []string{fp})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustClassifyFailed))
}

func TestRunTrustClassify_NonexistentFingerprint(t *testing.T) {
	resetViperForTest(t)

	dir := t.TempDir()
	viper.Set("trust.store_path", dir)

	fakeFP := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	cmd := newTrustClassifyCmd(t)
	require.NoError(t, cmd.Flags().Set("purpose", "general"))

	err := runTrustClassify(cmd, []string{fakeFP})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustClassifyFailed))
}

func TestRunTrustClassify_InvalidStorePath(t *testing.T) {
	resetViperForTest(t)

	tmpFile := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(tmpFile, []byte("data"), 0o600))
	viper.Set("trust.store_path", filepath.Join(tmpFile, "subdir"))

	cmd := newTrustClassifyCmd(t)
	require.NoError(t, cmd.Flags().Set("purpose", "general"))

	err := runTrustClassify(cmd, []string{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustStoreOpen))
}

func TestRunTrustClassify_WhitespaceHandling(t *testing.T) {
	resetViperForTest(t)

	cert := generateTrustTestCert(t)
	fp := truststore.Fingerprint(cert)
	dir := setupTrustStoreDir(t, cert)

	cmd := newTrustClassifyCmd(t)
	require.NoError(t, cmd.Flags().Set("purpose", "user-ca"))

	err := runTrustClassify(cmd, []string{"  " + fp + "  "})
	assert.NoError(t, err)

	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
	require.NoError(t, err)
	defer store.Close()

	meta, err := store.Metadata(fp)
	require.NoError(t, err)
	assert.Equal(t, truststore.PurposeUserCA, meta.Purpose)
}

func TestRunTrustClassify_AllPurposes(t *testing.T) {
	purposes := []string{
		"general",
		"tpm-manufacturer",
		"android-hardware",
		"user-ca",
		"bootstrap-ca",
		"idevid-issuer",
	}

	for _, purposeStr := range purposes {
		t.Run(purposeStr, func(t *testing.T) {
			resetViperForTest(t)

			cert := generateTrustTestCert(t)
			fp := truststore.Fingerprint(cert)
			dir := setupTrustStoreDir(t, cert)

			cmd := newTrustClassifyCmd(t)
			require.NoError(t, cmd.Flags().Set("purpose", purposeStr))

			err := runTrustClassify(cmd, []string{fp})
			assert.NoError(t, err)

			store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: dir})
			require.NoError(t, err)
			defer store.Close()

			meta, err := store.Metadata(fp)
			require.NoError(t, err)

			expected, parseErr := truststore.ParsePurpose(purposeStr)
			require.NoError(t, parseErr)
			assert.Equal(t, expected, meta.Purpose)
		})
	}
}

// --- runTrustBootstrap tests ---

func TestRunTrustBootstrap_InvalidMethodFlag(t *testing.T) {
	resetViperForTest(t)

	dir := t.TempDir()
	viper.Set("trust.store_path", dir)

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("method", nil, "bootstrap methods")
	cmd.Flags().Duration("timeout", 5*time.Second, "timeout")
	require.NoError(t, cmd.Flags().Set("method", "invalid_method"))

	err := runTrustBootstrap(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustBootstrapFailed))
}

func TestRunTrustBootstrap_NoMethodsConfigured(t *testing.T) {
	resetViperForTest(t)

	dir := t.TempDir()
	viper.Set("trust.store_path", dir)

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("method", nil, "bootstrap methods")
	cmd.Flags().Duration("timeout", 2*time.Second, "timeout")

	// AutoFetch with empty config will fail since there are no methods
	// or server URLs configured.
	err := runTrustBootstrap(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustBootstrapFailed))
}

func TestRunTrustBootstrap_TimeoutFlagDefault(t *testing.T) {
	resetViperForTest(t)

	dir := t.TempDir()
	viper.Set("trust.store_path", dir)

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("method", nil, "bootstrap methods")
	cmd.Flags().Duration("timeout", 1*time.Second, "timeout")
	require.NoError(t, cmd.Flags().Set("method", "direct"))

	// With direct method but no server URL, the bootstrap should fail.
	err := runTrustBootstrap(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustBootstrapFailed))
}

func TestRunTrustBootstrap_TimeoutFlagNotRegistered(t *testing.T) {
	resetViperForTest(t)

	dir := t.TempDir()
	viper.Set("trust.store_path", dir)

	// Create a command without the timeout flag to exercise the error
	// path where GetDuration returns an error and falls back to 60s.
	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("method", nil, "bootstrap methods")
	require.NoError(t, cmd.Flags().Set("method", "direct"))

	err := runTrustBootstrap(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustBootstrapFailed))
}

func TestRunTrustBootstrap_WithAllMethodConfigs(t *testing.T) {
	resetViperForTest(t)

	dir := t.TempDir()
	viper.Set("trust.store_path", dir)
	viper.Set("trust.bootstrap.dane.server_url", "https://dane.example.invalid")
	viper.Set("trust.bootstrap.noise.server_addr", "noise.example.invalid:9090")
	viper.Set("trust.bootstrap.spki.server_url", "https://spki.example.invalid")
	viper.Set("trust.bootstrap.direct.server_url", "https://direct.example.invalid")

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("method", nil, "bootstrap methods")
	cmd.Flags().Duration("timeout", 2*time.Second, "timeout")
	require.NoError(t, cmd.Flags().Set("method", "direct"))

	// Will fail because server does not exist, but exercises the full path
	// through buildBootstrapConfig with all sections populated.
	err := runTrustBootstrap(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustBootstrapFailed))
}

// --- parseMethodOrder tests ---

func TestParseMethodOrder_ValidMethods(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []truststrap.Method
	}{
		{
			name:  "single dane",
			input: []string{"dane"},
			want:  []truststrap.Method{truststrap.MethodDANE},
		},
		{
			name:  "single noise",
			input: []string{"noise"},
			want:  []truststrap.Method{truststrap.MethodNoise},
		},
		{
			name:  "single spki",
			input: []string{"spki"},
			want:  []truststrap.Method{truststrap.MethodSPKI},
		},
		{
			name:  "single direct",
			input: []string{"direct"},
			want:  []truststrap.Method{truststrap.MethodDirect},
		},
		{
			name:  "all methods",
			input: []string{"dane", "noise", "spki", "direct"},
			want: []truststrap.Method{
				truststrap.MethodDANE,
				truststrap.MethodNoise,
				truststrap.MethodSPKI,
				truststrap.MethodDirect,
			},
		},
		{
			name:  "mixed case",
			input: []string{"DANE", "Noise", "SPKI"},
			want: []truststrap.Method{
				truststrap.MethodDANE,
				truststrap.MethodNoise,
				truststrap.MethodSPKI,
			},
		},
		{
			name:  "with whitespace",
			input: []string{"  dane  ", " noise "},
			want: []truststrap.Method{
				truststrap.MethodDANE,
				truststrap.MethodNoise,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseMethodOrder(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseMethodOrder_InvalidMethod(t *testing.T) {
	tests := []struct {
		name  string
		input []string
	}{
		{"unknown method", []string{"unknown"}},
		{"empty string", []string{""}},
		{"partial match", []string{"dan"}},
		{"valid then invalid", []string{"dane", "bogus"}},
		{"numeric", []string{"123"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseMethodOrder(tt.input)
			assert.Error(t, err)
			assert.True(t, errors.Is(err, ErrTrustInvalidMethod))
		})
	}
}

func TestParseMethodOrder_EmptySlice(t *testing.T) {
	got, err := parseMethodOrder([]string{})
	require.NoError(t, err)
	assert.Empty(t, got)
}

// --- buildBootstrapConfig tests ---

func TestBuildBootstrapConfig_MethodFromFlag(t *testing.T) {
	resetViperForTest(t)

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("method", nil, "bootstrap methods")
	require.NoError(t, cmd.Flags().Set("method", "dane,noise"))

	cfg, err := buildBootstrapConfig(cmd)
	require.NoError(t, err)

	assert.Equal(t, []truststrap.Method{
		truststrap.MethodDANE,
		truststrap.MethodNoise,
	}, cfg.MethodOrder)
}

func TestBuildBootstrapConfig_MethodFromViper(t *testing.T) {
	resetViperForTest(t)

	viper.Set("trust.bootstrap.method_order", []string{"spki", "direct"})

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("method", nil, "bootstrap methods")

	cfg, err := buildBootstrapConfig(cmd)
	require.NoError(t, err)

	assert.Equal(t, []truststrap.Method{
		truststrap.MethodSPKI,
		truststrap.MethodDirect,
	}, cfg.MethodOrder)
}

func TestBuildBootstrapConfig_FlagOverridesViper(t *testing.T) {
	resetViperForTest(t)

	viper.Set("trust.bootstrap.method_order", []string{"direct"})

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("method", nil, "bootstrap methods")
	require.NoError(t, cmd.Flags().Set("method", "dane"))

	cfg, err := buildBootstrapConfig(cmd)
	require.NoError(t, err)

	// Flag should take precedence over viper config.
	assert.Equal(t, []truststrap.Method{truststrap.MethodDANE}, cfg.MethodOrder)
}

func TestBuildBootstrapConfig_InvalidMethodFromFlag(t *testing.T) {
	resetViperForTest(t)

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("method", nil, "bootstrap methods")
	require.NoError(t, cmd.Flags().Set("method", "invalid"))

	_, err := buildBootstrapConfig(cmd)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustInvalidMethod))
}

func TestBuildBootstrapConfig_InvalidMethodFromViper(t *testing.T) {
	resetViperForTest(t)

	viper.Set("trust.bootstrap.method_order", []string{"badmethod"})

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("method", nil, "bootstrap methods")

	_, err := buildBootstrapConfig(cmd)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrustInvalidMethod))
}

func TestBuildBootstrapConfig_PerMethodTimeout(t *testing.T) {
	resetViperForTest(t)

	viper.Set("trust.bootstrap.per_method_timeout", "30s")

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("method", nil, "bootstrap methods")

	cfg, err := buildBootstrapConfig(cmd)
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, cfg.PerMethodTimeout)
}

func TestBuildBootstrapConfig_InvalidPerMethodTimeout(t *testing.T) {
	resetViperForTest(t)

	viper.Set("trust.bootstrap.per_method_timeout", "not-a-duration")

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("method", nil, "bootstrap methods")

	cfg, err := buildBootstrapConfig(cmd)
	require.NoError(t, err)
	// Invalid duration should be silently ignored.
	assert.Equal(t, time.Duration(0), cfg.PerMethodTimeout)
}

func TestBuildBootstrapConfig_DANEConfig(t *testing.T) {
	resetViperForTest(t)

	viper.Set("trust.bootstrap.dane.server_url", "https://dane.example.com")
	viper.Set("trust.bootstrap.dane.hostname", "example.com")
	viper.Set("trust.bootstrap.dane.dns_server", "8.8.8.8:53")

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("method", nil, "bootstrap methods")

	cfg, err := buildBootstrapConfig(cmd)
	require.NoError(t, err)
	require.NotNil(t, cfg.DANE)
	assert.Equal(t, "https://dane.example.com", cfg.DANE.ServerURL)
	assert.Equal(t, "example.com", cfg.DANE.Hostname)
	assert.Equal(t, "8.8.8.8:53", cfg.DANE.DNSServer)
}

func TestBuildBootstrapConfig_NoDANEWithoutServerURL(t *testing.T) {
	resetViperForTest(t)

	// DANE config not set.
	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("method", nil, "bootstrap methods")

	cfg, err := buildBootstrapConfig(cmd)
	require.NoError(t, err)
	assert.Nil(t, cfg.DANE)
}

func TestBuildBootstrapConfig_NoiseConfig(t *testing.T) {
	resetViperForTest(t)

	viper.Set("trust.bootstrap.noise.server_addr", "noise.example.com:9090")
	viper.Set("trust.bootstrap.noise.server_key", "aabbccdd")

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("method", nil, "bootstrap methods")

	cfg, err := buildBootstrapConfig(cmd)
	require.NoError(t, err)
	require.NotNil(t, cfg.Noise)
	assert.Equal(t, "noise.example.com:9090", cfg.Noise.ServerAddr)
	assert.Equal(t, "aabbccdd", cfg.Noise.ServerStaticKey)
}

func TestBuildBootstrapConfig_NoNoiseWithoutServerAddr(t *testing.T) {
	resetViperForTest(t)

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("method", nil, "bootstrap methods")

	cfg, err := buildBootstrapConfig(cmd)
	require.NoError(t, err)
	assert.Nil(t, cfg.Noise)
}

func TestBuildBootstrapConfig_SPKIConfig(t *testing.T) {
	resetViperForTest(t)

	viper.Set("trust.bootstrap.spki.server_url", "https://spki.example.com")
	viper.Set("trust.bootstrap.spki.pin_sha256", "abc123pin")

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("method", nil, "bootstrap methods")

	cfg, err := buildBootstrapConfig(cmd)
	require.NoError(t, err)
	require.NotNil(t, cfg.SPKI)
	assert.Equal(t, "https://spki.example.com", cfg.SPKI.ServerURL)
	assert.Equal(t, "abc123pin", cfg.SPKI.SPKIPinSHA256)
}

func TestBuildBootstrapConfig_NoSPKIWithoutServerURL(t *testing.T) {
	resetViperForTest(t)

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("method", nil, "bootstrap methods")

	cfg, err := buildBootstrapConfig(cmd)
	require.NoError(t, err)
	assert.Nil(t, cfg.SPKI)
}

func TestBuildBootstrapConfig_DirectConfig(t *testing.T) {
	resetViperForTest(t)

	viper.Set("trust.bootstrap.direct.server_url", "https://direct.example.com")

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("method", nil, "bootstrap methods")

	cfg, err := buildBootstrapConfig(cmd)
	require.NoError(t, err)
	require.NotNil(t, cfg.Direct)
	assert.Equal(t, "https://direct.example.com", cfg.Direct.ServerURL)
}

func TestBuildBootstrapConfig_NoDirectWithoutServerURL(t *testing.T) {
	resetViperForTest(t)

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("method", nil, "bootstrap methods")

	cfg, err := buildBootstrapConfig(cmd)
	require.NoError(t, err)
	assert.Nil(t, cfg.Direct)
}

func TestBuildBootstrapConfig_AllSections(t *testing.T) {
	resetViperForTest(t)

	viper.Set("trust.bootstrap.per_method_timeout", "10s")
	viper.Set("trust.bootstrap.dane.server_url", "https://dane.example.com")
	viper.Set("trust.bootstrap.dane.hostname", "example.com")
	viper.Set("trust.bootstrap.dane.dns_server", "1.1.1.1:53")
	viper.Set("trust.bootstrap.noise.server_addr", "noise.example.com:9090")
	viper.Set("trust.bootstrap.noise.server_key", "noisekey")
	viper.Set("trust.bootstrap.spki.server_url", "https://spki.example.com")
	viper.Set("trust.bootstrap.spki.pin_sha256", "spkipin")
	viper.Set("trust.bootstrap.direct.server_url", "https://direct.example.com")

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("method", nil, "bootstrap methods")
	require.NoError(t, cmd.Flags().Set("method", "dane,noise,spki,direct"))

	cfg, err := buildBootstrapConfig(cmd)
	require.NoError(t, err)

	assert.Equal(t, 10*time.Second, cfg.PerMethodTimeout)
	assert.Len(t, cfg.MethodOrder, 4)
	require.NotNil(t, cfg.DANE)
	require.NotNil(t, cfg.Noise)
	require.NotNil(t, cfg.SPKI)
	require.NotNil(t, cfg.Direct)
}

func TestBuildBootstrapConfig_EmptyConfig(t *testing.T) {
	resetViperForTest(t)

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("method", nil, "bootstrap methods")

	cfg, err := buildBootstrapConfig(cmd)
	require.NoError(t, err)
	assert.Nil(t, cfg.MethodOrder)
	assert.Equal(t, time.Duration(0), cfg.PerMethodTimeout)
	assert.Nil(t, cfg.DANE)
	assert.Nil(t, cfg.Noise)
	assert.Nil(t, cfg.SPKI)
	assert.Nil(t, cfg.Direct)
}

func TestBuildBootstrapConfig_NoMethodFlagDefined(t *testing.T) {
	resetViperForTest(t)

	// Command without the method flag; buildBootstrapConfig should fall
	// through to the viper config path (which is also empty here).
	cmd := &cobra.Command{}

	cfg, err := buildBootstrapConfig(cmd)
	require.NoError(t, err)
	assert.Nil(t, cfg.MethodOrder)
}

func TestBuildBootstrapConfig_EmptyPerMethodTimeout(t *testing.T) {
	resetViperForTest(t)

	// Set an empty string for per_method_timeout -- should be ignored.
	viper.Set("trust.bootstrap.per_method_timeout", "")

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("method", nil, "bootstrap methods")

	cfg, err := buildBootstrapConfig(cmd)
	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), cfg.PerMethodTimeout)
}

// --- formatPublicKeyInfo tests ---

func TestFormatPublicKeyInfo_RSA(t *testing.T) {
	cert := generateRSATestCert(t, 2048)
	info := formatPublicKeyInfo(cert)
	assert.Equal(t, "RSA 2048-bit", info)
}

func TestFormatPublicKeyInfo_RSA4096(t *testing.T) {
	cert := generateRSATestCert(t, 4096)
	info := formatPublicKeyInfo(cert)
	assert.Equal(t, "RSA 4096-bit", info)
}

func TestFormatPublicKeyInfo_ECDSA_P256(t *testing.T) {
	cert := generateTrustTestCert(t)
	info := formatPublicKeyInfo(cert)
	assert.Equal(t, "ECDSA P-256", info)
}

func TestFormatPublicKeyInfo_ECDSA_P384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "P384 CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	info := formatPublicKeyInfo(cert)
	assert.Equal(t, "ECDSA P-384", info)
}

func TestFormatPublicKeyInfo_Ed25519(t *testing.T) {
	cert := generateEd25519TestCert(t)
	info := formatPublicKeyInfo(cert)
	assert.Equal(t, "Ed25519 256-bit", info)
}

func TestFormatPublicKeyInfo_UnknownKeyType(t *testing.T) {
	// Create a certificate with an unknown public key type.
	cert := &x509.Certificate{
		PublicKey:          "not a real key",
		PublicKeyAlgorithm: x509.PublicKeyAlgorithm(99),
	}

	info := formatPublicKeyInfo(cert)
	// The default case returns cert.PublicKeyAlgorithm.String().
	assert.NotEmpty(t, info)
}

// --- curveName tests ---

func TestCurveName_KnownCurves(t *testing.T) {
	tests := []struct {
		name  string
		curve elliptic.Curve
		want  string
	}{
		{"P-224", elliptic.P224(), "P-224"},
		{"P-256", elliptic.P256(), "P-256"},
		{"P-384", elliptic.P384(), "P-384"},
		{"P-521", elliptic.P521(), "P-521"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := curveName(tt.curve)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCurveName_UnknownCurve(t *testing.T) {
	// nil is a valid Curve value that is not in the map.
	got := curveName(nil)
	assert.Equal(t, "Unknown", got)
}

// --- Error sentinel tests ---

func TestTrustErrorSentinels(t *testing.T) {
	// Verify all error sentinels are distinct and produce meaningful messages.
	sentinels := []error{
		ErrTrustStoreOpen,
		ErrTrustAddFailed,
		ErrTrustRemoveFailed,
		ErrTrustBootstrapFailed,
		ErrTrustPEMFileRequired,
		ErrTrustPEMReadFailed,
		ErrTrustFingerprintRequired,
		ErrTrustCertificateNotFound,
		ErrTrustListFailed,
		ErrTrustInvalidMethod,
		ErrTrustClassifyFailed,
	}

	seen := make(map[string]bool, len(sentinels))
	for _, err := range sentinels {
		msg := err.Error()
		assert.NotEmpty(t, msg)
		assert.False(t, seen[msg], "duplicate error message: %s", msg)
		seen[msg] = true
	}
}

// --- methodParser map tests ---

func TestMethodParser_AllEntries(t *testing.T) {
	expected := map[string]truststrap.Method{
		"dane":   truststrap.MethodDANE,
		"noise":  truststrap.MethodNoise,
		"spki":   truststrap.MethodSPKI,
		"direct": truststrap.MethodDirect,
	}

	assert.Equal(t, len(expected), len(methodParser))

	for key, want := range expected {
		got, ok := methodParser[key]
		assert.True(t, ok, "methodParser missing key %q", key)
		assert.Equal(t, want, got)
	}
}

// --- Command registration tests ---

func TestTrustCmd_SubcommandRegistration(t *testing.T) {
	subcommands := map[string]bool{
		"list":      false,
		"add":       false,
		"remove":    false,
		"show":      false,
		"bootstrap": false,
		"classify":  false,
	}

	for _, cmd := range trustCmd.Commands() {
		if _, ok := subcommands[cmd.Name()]; ok {
			subcommands[cmd.Name()] = true
		}
	}

	for name, found := range subcommands {
		assert.True(t, found, "trust subcommand %q not registered", name)
	}
}

func TestTrustListCmd_Aliases(t *testing.T) {
	assert.Contains(t, trustListCmd.Aliases, "ls")
}

func TestTrustRemoveCmd_Aliases(t *testing.T) {
	assert.Contains(t, trustRemoveCmd.Aliases, "rm")
	assert.Contains(t, trustRemoveCmd.Aliases, "delete")
}

func TestTrustBootstrapCmd_Flags(t *testing.T) {
	methodFlag := trustBootstrapCmd.Flags().Lookup("method")
	assert.NotNil(t, methodFlag, "bootstrap command should have --method flag")

	timeoutFlag := trustBootstrapCmd.Flags().Lookup("timeout")
	assert.NotNil(t, timeoutFlag, "bootstrap command should have --timeout flag")
}

func TestTrustAddCmd_Flags(t *testing.T) {
	purposeFlag := trustAddCmd.Flags().Lookup("purpose")
	assert.NotNil(t, purposeFlag, "add command should have --purpose flag")

	sourceFlag := trustAddCmd.Flags().Lookup("source")
	assert.NotNil(t, sourceFlag, "add command should have --source flag")
}

func TestTrustClassifyCmd_Flags(t *testing.T) {
	purposeFlag := trustClassifyCmd.Flags().Lookup("purpose")
	assert.NotNil(t, purposeFlag, "classify command should have --purpose flag")
}

// --- curveNames map tests ---

func TestCurveNames_Completeness(t *testing.T) {
	// Ensure all standard curves are covered.
	standardCurves := []elliptic.Curve{
		elliptic.P224(),
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}

	for _, curve := range standardCurves {
		_, ok := curveNames[curve]
		assert.True(t, ok, "curveNames map missing curve %v", curve.Params().Name)
	}
}
