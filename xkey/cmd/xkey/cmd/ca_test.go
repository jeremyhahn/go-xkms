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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newCAIssueCmd creates a cobra.Command with all issue flags registered.
func newCAIssueCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.Flags().String("profile", "", "")
	cmd.Flags().String("cn", "", "")
	cmd.Flags().String("organization", "", "")
	cmd.Flags().String("san", "", "")
	cmd.Flags().Int("validity-days", 0, "")
	cmd.Flags().String("algorithm", "", "")
	cmd.Flags().String("output", "", "")
	return cmd
}

// newCASignCSRCmd creates a cobra.Command with all sign-csr flags registered.
func newCASignCSRCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.Flags().String("csr", "", "")
	cmd.Flags().String("profile", "", "")
	cmd.Flags().Int("validity-days", 0, "")
	cmd.Flags().String("output", "", "")
	return cmd
}

// newCARevokeCmd creates a cobra.Command with the reason flag registered.
func newCARevokeCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.Flags().String("reason", "unspecified", "")
	return cmd
}

// newCAOutputCmd creates a cobra.Command with the output flag registered.
func newCAOutputCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.Flags().String("output", "", "")
	return cmd
}

// --- parseSANs tests ---

func TestParseSANs_ValidDNS(t *testing.T) {
	sans, err := parseSANs("DNS:example.com")
	require.NoError(t, err)
	assert.Equal(t, []string{"DNS:example.com"}, sans)
}

func TestParseSANs_ValidIP(t *testing.T) {
	sans, err := parseSANs("IP:10.0.0.1")
	require.NoError(t, err)
	assert.Equal(t, []string{"IP:10.0.0.1"}, sans)
}

func TestParseSANs_ValidIPv6(t *testing.T) {
	sans, err := parseSANs("IP:::1")
	require.NoError(t, err)
	assert.Equal(t, []string{"IP:::1"}, sans)
}

func TestParseSANs_ValidEmail(t *testing.T) {
	sans, err := parseSANs("Email:user@example.com")
	require.NoError(t, err)
	assert.Equal(t, []string{"Email:user@example.com"}, sans)
}

func TestParseSANs_MultipleMixed(t *testing.T) {
	sans, err := parseSANs("DNS:example.com,IP:10.0.0.1,Email:admin@example.com")
	require.NoError(t, err)
	assert.Equal(t, []string{
		"DNS:example.com",
		"IP:10.0.0.1",
		"Email:admin@example.com",
	}, sans)
}

func TestParseSANs_WildcardDNS(t *testing.T) {
	sans, err := parseSANs("DNS:*.example.com")
	require.NoError(t, err)
	assert.Equal(t, []string{"DNS:*.example.com"}, sans)
}

func TestParseSANs_EmptyString(t *testing.T) {
	sans, err := parseSANs("")
	require.NoError(t, err)
	assert.Nil(t, sans)
}

func TestParseSANs_WhitespaceHandling(t *testing.T) {
	sans, err := parseSANs("  DNS:example.com , IP:10.0.0.1 ")
	require.NoError(t, err)
	assert.Equal(t, []string{
		"DNS:example.com",
		"IP:10.0.0.1",
	}, sans)
}

func TestParseSANs_CaseInsensitiveType(t *testing.T) {
	sans, err := parseSANs("dns:example.com,ip:10.0.0.1,email:user@host.com")
	require.NoError(t, err)
	assert.Equal(t, []string{
		"DNS:example.com",
		"IP:10.0.0.1",
		"Email:user@host.com",
	}, sans)
}

func TestParseSANs_MissingTypePrefix(t *testing.T) {
	_, err := parseSANs("example.com")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCASANParseFailed))
}

func TestParseSANs_EmptyValue(t *testing.T) {
	_, err := parseSANs("DNS:")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCASANParseFailed))
}

func TestParseSANs_InvalidIPAddress(t *testing.T) {
	_, err := parseSANs("IP:not-an-ip")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCASANParseFailed))
}

func TestParseSANs_UnsupportedType(t *testing.T) {
	_, err := parseSANs("URI:https://example.com")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCASANParseFailed))
}

func TestParseSANs_SkipsEmptyEntries(t *testing.T) {
	sans, err := parseSANs("DNS:example.com,,DNS:other.com")
	require.NoError(t, err)
	assert.Equal(t, []string{
		"DNS:example.com",
		"DNS:other.com",
	}, sans)
}

func TestParseSANs_ColonOnly(t *testing.T) {
	_, err := parseSANs(":")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCASANParseFailed))
}

// --- parseReasonCode tests ---

func TestParseReasonCode_AllValidCodes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"unspecified", "unspecified", 0},
		{"key-compromise", "key-compromise", 1},
		{"ca-compromise", "ca-compromise", 2},
		{"affiliation-changed", "affiliation-changed", 3},
		{"superseded", "superseded", 4},
		{"cessation-of-operation", "cessation-of-operation", 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, err := parseReasonCode(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, code)
		})
	}
}

func TestParseReasonCode_CaseInsensitive(t *testing.T) {
	code, err := parseReasonCode("Key-Compromise")
	require.NoError(t, err)
	assert.Equal(t, 1, code)
}

func TestParseReasonCode_WithWhitespace(t *testing.T) {
	code, err := parseReasonCode("  superseded  ")
	require.NoError(t, err)
	assert.Equal(t, 4, code)
}

func TestParseReasonCode_InvalidCode(t *testing.T) {
	_, err := parseReasonCode("invalid-reason")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCAInvalidReasonCode))
}

func TestParseReasonCode_EmptyString(t *testing.T) {
	_, err := parseReasonCode("")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCAInvalidReasonCode))
}

func TestParseReasonCode_NumericString(t *testing.T) {
	_, err := parseReasonCode("0")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCAInvalidReasonCode))
}

// --- reasonCodeName tests ---

func TestReasonCodeName_AllKnownCodes(t *testing.T) {
	tests := []struct {
		code int
		name string
	}{
		{0, "unspecified"},
		{1, "key-compromise"},
		{2, "ca-compromise"},
		{3, "affiliation-changed"},
		{4, "superseded"},
		{5, "cessation-of-operation"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := reasonCodeName(tt.code)
			assert.Equal(t, tt.name, got)
		})
	}
}

func TestReasonCodeName_UnknownCode(t *testing.T) {
	got := reasonCodeName(99)
	assert.Equal(t, "unknown", got)
}

// --- reasonCodes map tests ---

func TestReasonCodes_Completeness(t *testing.T) {
	expectedCodes := map[string]int{
		"unspecified":            0,
		"key-compromise":         1,
		"ca-compromise":          2,
		"affiliation-changed":    3,
		"superseded":             4,
		"cessation-of-operation": 5,
	}

	assert.Equal(t, len(expectedCodes), len(reasonCodes))

	for name, code := range expectedCodes {
		got, ok := reasonCodes[name]
		assert.True(t, ok, "reasonCodes missing key %q", name)
		assert.Equal(t, code, got)
	}
}

// --- writeOutput tests ---

func TestWriteOutput_ToFile(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "output.pem")
	data := []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n")

	err := writeOutput(outFile, data)
	require.NoError(t, err)

	contents, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Equal(t, data, contents)
}

func TestWriteOutput_ToFilePermissions(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "output.pem")
	data := []byte("test data")

	err := writeOutput(outFile, data)
	require.NoError(t, err)

	info, err := os.Stat(outFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestWriteOutput_InvalidPath(t *testing.T) {
	err := writeOutput("/nonexistent/dir/file.pem", []byte("data"))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCAOutputWriteFailed))
}

// --- Command structure tests ---

func TestCACmd_SubcommandRegistration(t *testing.T) {
	subcommands := map[string]bool{
		"info":             false,
		"issue":            false,
		"sign-csr":         false,
		"revoke":           false,
		"crl":              false,
		"check-revocation": false,
		"bundle":           false,
	}

	for _, cmd := range caCmd.Commands() {
		if _, ok := subcommands[cmd.Name()]; ok {
			subcommands[cmd.Name()] = true
		}
	}

	for name, found := range subcommands {
		assert.True(t, found, "ca subcommand %q not registered", name)
	}
}

func TestCACmd_RegisteredOnRoot(t *testing.T) {
	found := false
	for _, cmd := range RootCmd.Commands() {
		if cmd.Name() == "ca" {
			found = true
			break
		}
	}
	assert.True(t, found, "ca command not registered on root")
}

func TestCACRLCmd_Aliases(t *testing.T) {
	assert.Contains(t, caCRLCmd.Aliases, "gen-crl")
}

func TestCAIssueCmd_Flags(t *testing.T) {
	flags := []string{"profile", "cn", "organization", "san", "validity-days", "algorithm", "output"}
	for _, name := range flags {
		flag := caIssueCmd.Flags().Lookup(name)
		assert.NotNil(t, flag, "issue command should have --%s flag", name)
	}
}

func TestCASignCSRCmd_Flags(t *testing.T) {
	flags := []string{"csr", "profile", "validity-days", "output"}
	for _, name := range flags {
		flag := caSignCSRCmd.Flags().Lookup(name)
		assert.NotNil(t, flag, "sign-csr command should have --%s flag", name)
	}
}

func TestCARevokeCmd_Flags(t *testing.T) {
	flag := caRevokeCmd.Flags().Lookup("reason")
	assert.NotNil(t, flag, "revoke command should have --reason flag")
	assert.Equal(t, "unspecified", flag.DefValue)
}

func TestCARevokeCmd_RequiresArg(t *testing.T) {
	assert.NotNil(t, caRevokeCmd.Args)
}

func TestCACheckRevocationCmd_RequiresArg(t *testing.T) {
	assert.NotNil(t, caCheckRevocationCmd.Args)
}

func TestCACRLCmd_OutputFlag(t *testing.T) {
	flag := caCRLCmd.Flags().Lookup("output")
	assert.NotNil(t, flag, "crl command should have --output flag")
}

func TestCABundleCmd_OutputFlag(t *testing.T) {
	flag := caBundleCmd.Flags().Lookup("output")
	assert.NotNil(t, flag, "bundle command should have --output flag")
}

// --- Error sentinel tests ---

func TestCAErrorSentinels(t *testing.T) {
	sentinels := []error{
		ErrCANotInitialized,
		ErrCAInfoFailed,
		ErrCAIssueFailed,
		ErrCASignCSRFailed,
		ErrCARevokeFailed,
		ErrCACRLFailed,
		ErrCACheckRevocationFailed,
		ErrCABundleFailed,
		ErrCACSRReadFailed,
		ErrCAOutputWriteFailed,
		ErrCASerialRequired,
		ErrCACommonNameRequired,
		ErrCAProfileRequired,
		ErrCACSRRequired,
		ErrCASANParseFailed,
		ErrCAInvalidReasonCode,
	}

	seen := make(map[string]bool, len(sentinels))
	for _, err := range sentinels {
		msg := err.Error()
		assert.NotEmpty(t, msg)
		assert.False(t, seen[msg], "duplicate error message: %s", msg)
		seen[msg] = true
	}
}

// --- getSDKClient tests ---

func TestGetSDKClient_ReturnsNotInitialized(t *testing.T) {
	client, err := getSDKClient()
	assert.Nil(t, client)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCANotInitialized))
}

// --- RunE error propagation tests ---

func TestRunCAInfo_ClientNotInitialized(t *testing.T) {
	cmd := &cobra.Command{}
	err := runCAInfo(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCAInfoFailed))
	assert.True(t, strings.Contains(err.Error(), ErrCANotInitialized.Error()))
}

func TestRunCAIssue_MissingProfile(t *testing.T) {
	cmd := newCAIssueCmd(t)

	err := runCAIssue(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCAProfileRequired))
}

func TestRunCAIssue_MissingCommonName(t *testing.T) {
	cmd := newCAIssueCmd(t)
	require.NoError(t, cmd.Flags().Set("profile", "server"))

	err := runCAIssue(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCACommonNameRequired))
}

func TestRunCAIssue_InvalidSAN(t *testing.T) {
	cmd := newCAIssueCmd(t)
	require.NoError(t, cmd.Flags().Set("profile", "server"))
	require.NoError(t, cmd.Flags().Set("cn", "example.com"))
	require.NoError(t, cmd.Flags().Set("san", "INVALID:bad"))

	err := runCAIssue(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCAIssueFailed))
}

func TestRunCAIssue_ClientNotInitialized(t *testing.T) {
	cmd := newCAIssueCmd(t)
	require.NoError(t, cmd.Flags().Set("profile", "server"))
	require.NoError(t, cmd.Flags().Set("cn", "example.com"))

	err := runCAIssue(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCAIssueFailed))
	assert.True(t, strings.Contains(err.Error(), ErrCANotInitialized.Error()))
}

func TestRunCASignCSR_MissingCSRPath(t *testing.T) {
	cmd := newCASignCSRCmd(t)

	err := runCASignCSR(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCACSRRequired))
}

func TestRunCASignCSR_NonexistentCSRFile(t *testing.T) {
	cmd := newCASignCSRCmd(t)
	require.NoError(t, cmd.Flags().Set("csr", "/nonexistent/path/request.csr"))

	err := runCASignCSR(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCACSRReadFailed))
}

func TestRunCASignCSR_ClientNotInitialized(t *testing.T) {
	dir := t.TempDir()
	csrFile := filepath.Join(dir, "test.csr")
	require.NoError(t, os.WriteFile(csrFile, []byte("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----\n"), 0600))

	cmd := newCASignCSRCmd(t)
	require.NoError(t, cmd.Flags().Set("csr", csrFile))

	err := runCASignCSR(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCASignCSRFailed))
	assert.True(t, strings.Contains(err.Error(), ErrCANotInitialized.Error()))
}

func TestRunCARevoke_ClientNotInitialized(t *testing.T) {
	cmd := newCARevokeCmd(t)

	err := runCARevoke(cmd, []string{"ABC123"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCARevokeFailed))
	assert.True(t, strings.Contains(err.Error(), ErrCANotInitialized.Error()))
}

func TestRunCARevoke_InvalidReason(t *testing.T) {
	cmd := newCARevokeCmd(t)
	require.NoError(t, cmd.Flags().Set("reason", "bogus-reason"))

	err := runCARevoke(cmd, []string{"ABC123"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCARevokeFailed))
}

func TestRunCACRL_ClientNotInitialized(t *testing.T) {
	cmd := newCAOutputCmd(t)

	err := runCACRL(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCACRLFailed))
	assert.True(t, strings.Contains(err.Error(), ErrCANotInitialized.Error()))
}

func TestRunCACheckRevocation_ClientNotInitialized(t *testing.T) {
	cmd := &cobra.Command{}
	err := runCACheckRevocation(cmd, []string{"ABC123"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCACheckRevocationFailed))
	assert.True(t, strings.Contains(err.Error(), ErrCANotInitialized.Error()))
}

func TestRunCABundle_ClientNotInitialized(t *testing.T) {
	cmd := newCAOutputCmd(t)

	err := runCABundle(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCABundleFailed))
	assert.True(t, strings.Contains(err.Error(), ErrCANotInitialized.Error()))
}
