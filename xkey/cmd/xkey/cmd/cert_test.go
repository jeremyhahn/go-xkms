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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newCertRequestCmd creates a cobra.Command with all cert request flags registered.
func newCertRequestCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{RunE: runCertRequest}
	cmd.Flags().String("server", "", "")
	cmd.Flags().String("cn", "", "")
	cmd.Flags().String("slot", defaultCertSlot, "")
	cmd.Flags().String("spki-pin", "", "")
	cmd.Flags().String("organization", "", "")
	cmd.Flags().String("profile", defaultCertProfile, "")
	cmd.Flags().Int("validity-days", 0, "")
	return cmd
}

// newCertShowCmd creates a cobra.Command with all cert show flags registered.
func newCertShowCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{RunE: runCertShow}
	cmd.Flags().String("slot", defaultCertSlot, "")
	return cmd
}

// newCertExportCmd creates a cobra.Command with all cert export flags registered.
func newCertExportCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{RunE: runCertExport}
	cmd.Flags().String("slot", defaultCertSlot, "")
	cmd.Flags().String("file", "", "")
	return cmd
}

// generateTestCertPEM creates a self-signed test certificate and returns its PEM encoding.
func generateTestCertPEM(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	require.NotNil(t, pemData)

	return pemData
}

// --- Command existence and structure tests ---

func TestCertCmd_Exists(t *testing.T) {
	assert.NotNil(t, certCmd)
}

func TestCertCmd_Properties(t *testing.T) {
	assert.Equal(t, "cert", certCmd.Use)
	assert.NotEmpty(t, certCmd.Short)
	assert.NotEmpty(t, certCmd.Long)
}

func TestCertCmd_Subcommands(t *testing.T) {
	subcommands := certCmd.Commands()
	assert.Len(t, subcommands, 3)

	names := make(map[string]bool, len(subcommands))
	for _, sub := range subcommands {
		names[sub.Use] = true
	}
	assert.True(t, names["request"], "missing 'request' subcommand")
	assert.True(t, names["show"], "missing 'show' subcommand")
	assert.True(t, names["export"], "missing 'export' subcommand")
}

func TestCertRequestCmd_Properties(t *testing.T) {
	assert.Equal(t, "request", certRequestCmd.Use)
	assert.NotEmpty(t, certRequestCmd.Short)
	assert.NotEmpty(t, certRequestCmd.Long)
	assert.NotNil(t, certRequestCmd.RunE)
}

func TestCertShowCmd_Properties(t *testing.T) {
	assert.Equal(t, "show", certShowCmd.Use)
	assert.NotEmpty(t, certShowCmd.Short)
	assert.NotEmpty(t, certShowCmd.Long)
	assert.NotNil(t, certShowCmd.RunE)
}

func TestCertExportCmd_Properties(t *testing.T) {
	assert.Equal(t, "export", certExportCmd.Use)
	assert.NotEmpty(t, certExportCmd.Short)
	assert.NotEmpty(t, certExportCmd.Long)
	assert.NotNil(t, certExportCmd.RunE)
}

// --- Flag registration tests ---

func TestCertRequestCmd_Flags(t *testing.T) {
	flags := []string{"server", "slot", "cn", "organization", "spki-pin", "profile", "validity-days"}
	for _, name := range flags {
		f := certRequestCmd.Flags().Lookup(name)
		assert.NotNilf(t, f, "flag %q should be registered on certRequestCmd", name)
	}
}

func TestCertRequestCmd_FlagDefaults(t *testing.T) {
	slotFlag := certRequestCmd.Flags().Lookup("slot")
	require.NotNil(t, slotFlag)
	assert.Equal(t, defaultCertSlot, slotFlag.DefValue)

	profileFlag := certRequestCmd.Flags().Lookup("profile")
	require.NotNil(t, profileFlag)
	assert.Equal(t, defaultCertProfile, profileFlag.DefValue)
}

func TestCertShowCmd_Flags(t *testing.T) {
	f := certShowCmd.Flags().Lookup("slot")
	assert.NotNilf(t, f, "flag 'slot' should be registered on certShowCmd")
}

func TestCertShowCmd_FlagDefaults(t *testing.T) {
	slotFlag := certShowCmd.Flags().Lookup("slot")
	require.NotNil(t, slotFlag)
	assert.Equal(t, defaultCertSlot, slotFlag.DefValue)
}

func TestCertExportCmd_Flags(t *testing.T) {
	flags := []string{"slot", "file"}
	for _, name := range flags {
		f := certExportCmd.Flags().Lookup(name)
		assert.NotNilf(t, f, "flag %q should be registered on certExportCmd", name)
	}
}

func TestCertExportCmd_FlagDefaults(t *testing.T) {
	slotFlag := certExportCmd.Flags().Lookup("slot")
	require.NotNil(t, slotFlag)
	assert.Equal(t, defaultCertSlot, slotFlag.DefValue)

	fileFlag := certExportCmd.Flags().Lookup("file")
	require.NotNil(t, fileFlag)
	assert.Equal(t, "", fileFlag.DefValue)
}

// --- Constants tests ---

func TestCertDefaults(t *testing.T) {
	assert.Equal(t, "9a", defaultCertSlot)
	assert.Equal(t, "client", defaultCertProfile)
}

// --- Error sentinel tests ---

func TestCertErrors_NonEmpty(t *testing.T) {
	sentinels := []error{
		ErrCertServerRequired,
		ErrCertCommonNameRequired,
		ErrCertCSRGenerationFailed,
		ErrCertSigningFailed,
		ErrCertClientCreationFailed,
		ErrCertStorageFailed,
		ErrCertNotFound,
		ErrCertExportFailed,
		ErrCertFileRequired,
		ErrCertSignerUnavailable,
		ErrCertParseFailed,
		ErrCertTrustRequired,
	}
	for _, err := range sentinels {
		assert.NotEmpty(t, err.Error(), "error sentinel should have non-empty message")
	}
}

func TestCertErrors_AreDistinct(t *testing.T) {
	sentinels := []error{
		ErrCertServerRequired,
		ErrCertCommonNameRequired,
		ErrCertCSRGenerationFailed,
		ErrCertSigningFailed,
		ErrCertClientCreationFailed,
		ErrCertStorageFailed,
		ErrCertNotFound,
		ErrCertExportFailed,
		ErrCertFileRequired,
		ErrCertSignerUnavailable,
		ErrCertParseFailed,
		ErrCertTrustRequired,
	}

	seen := make(map[string]bool, len(sentinels))
	for _, err := range sentinels {
		msg := err.Error()
		assert.False(t, seen[msg], "duplicate error message: %s", msg)
		seen[msg] = true
	}
}

func TestCertErrors_ContainPrefix(t *testing.T) {
	sentinels := []error{
		ErrCertServerRequired,
		ErrCertCommonNameRequired,
		ErrCertCSRGenerationFailed,
		ErrCertSigningFailed,
		ErrCertClientCreationFailed,
		ErrCertStorageFailed,
		ErrCertNotFound,
		ErrCertExportFailed,
		ErrCertFileRequired,
		ErrCertSignerUnavailable,
		ErrCertParseFailed,
		ErrCertTrustRequired,
	}
	for _, err := range sentinels {
		assert.Contains(t, err.Error(), "cert:", "all cert errors should contain 'cert:' prefix")
	}
}

// --- parsePEMCertificate tests ---

func TestParsePEMCertificate_Valid(t *testing.T) {
	pemData := generateTestCertPEM(t)

	cert, err := parsePEMCertificate(pemData)
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, big.NewInt(1), cert.SerialNumber)
}

func TestParsePEMCertificate_ValidFieldsPreserved(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	notBefore := time.Now().Truncate(time.Second)
	notAfter := notBefore.Add(24 * time.Hour)
	serial := big.NewInt(42)

	template := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	cert, err := parsePEMCertificate(pemData)
	require.NoError(t, err)
	assert.Equal(t, serial, cert.SerialNumber)
	assert.Equal(t, x509.ECDSA, cert.PublicKeyAlgorithm)
}

func TestParsePEMCertificate_NilInput(t *testing.T) {
	cert, err := parsePEMCertificate(nil)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.True(t, errors.Is(err, ErrCertParseFailed))
}

func TestParsePEMCertificate_EmptyInput(t *testing.T) {
	cert, err := parsePEMCertificate([]byte{})
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.True(t, errors.Is(err, ErrCertParseFailed))
}

func TestParsePEMCertificate_InvalidPEM(t *testing.T) {
	cert, err := parsePEMCertificate([]byte("this is not PEM data"))
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.True(t, errors.Is(err, ErrCertParseFailed))
}

func TestParsePEMCertificate_WrongPEMType(t *testing.T) {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("fake-key-data"),
	}
	pemData := pem.EncodeToMemory(block)

	cert, err := parsePEMCertificate(pemData)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.True(t, errors.Is(err, ErrCertParseFailed))
	assert.Contains(t, err.Error(), "RSA PRIVATE KEY")
}

func TestParsePEMCertificate_WrongPEMType_PublicKey(t *testing.T) {
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: []byte("fake-public-key-data"),
	}
	pemData := pem.EncodeToMemory(block)

	cert, err := parsePEMCertificate(pemData)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.True(t, errors.Is(err, ErrCertParseFailed))
	assert.Contains(t, err.Error(), "PUBLIC KEY")
}

func TestParsePEMCertificate_InvalidDER(t *testing.T) {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("this-is-not-valid-der-data"),
	}
	pemData := pem.EncodeToMemory(block)

	cert, err := parsePEMCertificate(pemData)
	assert.Error(t, err)
	assert.Nil(t, cert)
	// x509.ParseCertificate returns its own error, not wrapped with ErrCertParseFailed
}

func TestParsePEMCertificate_MultiplePEMBlocks(t *testing.T) {
	// Generate two different certificates
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template1 := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	template2 := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER1, err := x509.CreateCertificate(rand.Reader, template1, template1, &key1.PublicKey, key1)
	require.NoError(t, err)

	certDER2, err := x509.CreateCertificate(rand.Reader, template2, template2, &key2.PublicKey, key2)
	require.NoError(t, err)

	pem1 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER1})
	pem2 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER2})

	// Concatenate both PEM blocks
	combined := append(pem1, pem2...)

	cert, err := parsePEMCertificate(combined)
	require.NoError(t, err)
	assert.NotNil(t, cert)
	// Only the first block is parsed
	assert.Equal(t, big.NewInt(100), cert.SerialNumber)
}

func TestParsePEMCertificate_TrailingGarbage(t *testing.T) {
	pemData := generateTestCertPEM(t)
	// Append garbage after valid PEM
	pemData = append(pemData, []byte("\nsome trailing garbage data")...)

	cert, err := parsePEMCertificate(pemData)
	require.NoError(t, err)
	assert.NotNil(t, cert)
}

func TestParsePEMCertificate_LeadingWhitespace(t *testing.T) {
	pemData := generateTestCertPEM(t)
	// Prepend whitespace
	pemData = append([]byte("\n\n  "), pemData...)

	cert, err := parsePEMCertificate(pemData)
	require.NoError(t, err)
	assert.NotNil(t, cert)
}

// --- runCertRequest flag validation tests ---

func TestRunCertRequest_MissingServer(t *testing.T) {
	cmd := newCertRequestCmd(t)

	err := cmd.RunE(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCertServerRequired))
}

func TestRunCertRequest_EmptyServer(t *testing.T) {
	cmd := newCertRequestCmd(t)
	require.NoError(t, cmd.Flags().Set("server", ""))

	err := cmd.RunE(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCertServerRequired))
}

func TestRunCertRequest_MissingCN(t *testing.T) {
	cmd := newCertRequestCmd(t)
	require.NoError(t, cmd.Flags().Set("server", "https://xkms.example.com:8443"))

	err := cmd.RunE(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCertCommonNameRequired))
}

func TestRunCertRequest_EmptyCN(t *testing.T) {
	cmd := newCertRequestCmd(t)
	require.NoError(t, cmd.Flags().Set("server", "https://xkms.example.com:8443"))
	require.NoError(t, cmd.Flags().Set("cn", ""))

	err := cmd.RunE(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCertCommonNameRequired))
}

func TestRunCertRequest_InvalidSlot(t *testing.T) {
	cmd := newCertRequestCmd(t)
	require.NoError(t, cmd.Flags().Set("server", "https://xkms.example.com:8443"))
	require.NoError(t, cmd.Flags().Set("cn", "test-user"))
	require.NoError(t, cmd.Flags().Set("slot", "invalid"))

	err := cmd.RunE(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPIVInvalidSlot))
}

func TestRunCertRequest_InvalidSlotNumeric(t *testing.T) {
	cmd := newCertRequestCmd(t)
	require.NoError(t, cmd.Flags().Set("server", "https://xkms.example.com:8443"))
	require.NoError(t, cmd.Flags().Set("cn", "test-user"))
	require.NoError(t, cmd.Flags().Set("slot", "99"))

	err := cmd.RunE(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPIVInvalidSlot))
}

// --- runCertShow flag validation tests ---

func TestRunCertShow_InvalidSlot(t *testing.T) {
	cmd := newCertShowCmd(t)
	require.NoError(t, cmd.Flags().Set("slot", "invalid"))

	err := cmd.RunE(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPIVInvalidSlot))
}

func TestRunCertShow_InvalidSlotEmpty(t *testing.T) {
	cmd := newCertShowCmd(t)
	require.NoError(t, cmd.Flags().Set("slot", ""))

	err := cmd.RunE(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPIVInvalidSlot))
}

func TestRunCertShow_InvalidSlotNumeric(t *testing.T) {
	cmd := newCertShowCmd(t)
	require.NoError(t, cmd.Flags().Set("slot", "00"))

	err := cmd.RunE(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPIVInvalidSlot))
}

// --- runCertExport flag validation tests ---

func TestRunCertExport_MissingFile(t *testing.T) {
	cmd := newCertExportCmd(t)

	err := cmd.RunE(cmd, nil)
	assert.Error(t, err)
	// With default slot (9a), slot validation passes, then file check triggers
	assert.True(t, errors.Is(err, ErrCertFileRequired) || errors.Is(err, ErrPIVInvalidSlot),
		"expected ErrCertFileRequired or ErrPIVInvalidSlot, got: %v", err)
}

func TestRunCertExport_EmptyFile(t *testing.T) {
	cmd := newCertExportCmd(t)
	require.NoError(t, cmd.Flags().Set("file", ""))

	err := cmd.RunE(cmd, nil)
	assert.Error(t, err)
}

func TestRunCertExport_InvalidSlot(t *testing.T) {
	cmd := newCertExportCmd(t)
	require.NoError(t, cmd.Flags().Set("slot", "zz"))
	require.NoError(t, cmd.Flags().Set("file", "/tmp/test-cert.pem"))

	err := cmd.RunE(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPIVInvalidSlot))
}

func TestRunCertExport_InvalidSlotSpecialChars(t *testing.T) {
	cmd := newCertExportCmd(t)
	require.NoError(t, cmd.Flags().Set("slot", "!@"))
	require.NoError(t, cmd.Flags().Set("file", "/tmp/test-cert.pem"))

	err := cmd.RunE(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPIVInvalidSlot))
}

// --- Validation ordering tests ---

func TestRunCertRequest_ServerValidatedBeforeCN(t *testing.T) {
	cmd := newCertRequestCmd(t)
	// Neither server nor cn set - server should fail first

	err := cmd.RunE(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCertServerRequired),
		"server validation should occur before cn validation")
}

func TestRunCertRequest_CNValidatedBeforeSlot(t *testing.T) {
	cmd := newCertRequestCmd(t)
	require.NoError(t, cmd.Flags().Set("server", "https://xkms.example.com:8443"))
	require.NoError(t, cmd.Flags().Set("slot", "invalid"))
	// cn not set - cn should fail before slot validation

	err := cmd.RunE(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCertCommonNameRequired),
		"cn validation should occur before slot validation")
}

func TestRunCertExport_SlotValidatedBeforeFile(t *testing.T) {
	cmd := newCertExportCmd(t)
	require.NoError(t, cmd.Flags().Set("slot", "invalid"))
	// file not set - slot should fail before file check

	err := cmd.RunE(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPIVInvalidSlot),
		"slot validation should occur before file validation")
}

// --- Command registration tests ---

func TestCertCmd_RegisteredOnRoot(t *testing.T) {
	found := false
	for _, cmd := range RootCmd.Commands() {
		if cmd.Use == "cert" {
			found = true
			break
		}
	}
	assert.True(t, found, "certCmd should be registered on RootCmd")
}

func TestCertCmd_RequestSubcommandRegistered(t *testing.T) {
	found := false
	for _, cmd := range certCmd.Commands() {
		if cmd.Use == "request" {
			found = true
			break
		}
	}
	assert.True(t, found, "certRequestCmd should be registered on certCmd")
}

func TestCertCmd_ShowSubcommandRegistered(t *testing.T) {
	found := false
	for _, cmd := range certCmd.Commands() {
		if cmd.Use == "show" {
			found = true
			break
		}
	}
	assert.True(t, found, "certShowCmd should be registered on certCmd")
}

func TestCertCmd_ExportSubcommandRegistered(t *testing.T) {
	found := false
	for _, cmd := range certCmd.Commands() {
		if cmd.Use == "export" {
			found = true
			break
		}
	}
	assert.True(t, found, "certExportCmd should be registered on certCmd")
}
