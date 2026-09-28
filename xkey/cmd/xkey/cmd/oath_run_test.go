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
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
)

// newOATHCmd builds a detached copy of an oath subcommand wired to a
// temporary store, so the tests never touch the developer's credentials.
func newOATHCmd(t *testing.T, template *cobra.Command, storePath string) (*cobra.Command, *bytes.Buffer) {
	t.Helper()

	cmd := &cobra.Command{Use: template.Use, RunE: template.RunE}
	// Reuse the real flag definitions (names, types, defaults) but on a
	// private FlagSet so tests never mutate the shared command state.
	template.Flags().VisitAll(func(f *pflag.Flag) {
		cmd.Flags().AddFlag(&pflag.Flag{
			Name:     f.Name,
			Usage:    f.Usage,
			Value:    newFlagValue(f),
			DefValue: f.DefValue,
		})
	})
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "store", storePath))

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	return cmd, &buf
}

// newFlagValue builds an independent pflag.Value of the same type as f,
// initialised to f's default, so a test can set flags without touching the
// package-level command.
func newFlagValue(f *pflag.Flag) pflag.Value {
	fs := pflag.NewFlagSet("copy", pflag.ContinueOnError)
	switch f.Value.Type() {
	case "bool":
		fs.Bool(f.Name, f.DefValue == "true", f.Usage)
	case "int":
		var n int
		_, _ = fmt.Sscanf(f.DefValue, "%d", &n)
		fs.Int(f.Name, n, f.Usage)
	default:
		fs.String(f.Name, f.DefValue, f.Usage)
	}
	return fs.Lookup(f.Name).Value
}

// oathStorePath returns a fresh store path inside a temp directory.
func oathStorePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "oath.json")
}

// addTestCredential writes a credential directly into the store so tests can
// set up state without going through the add command.
func addTestCredential(t *testing.T, storePath string, cred *oath.Credential) {
	t.Helper()

	store, err := oath.NewFileStore(storePath)
	require.NoError(t, err)
	require.NoError(t, store.Add(cred))
	require.NoError(t, store.Close())
}

// totpCredential returns a valid TOTP credential for the given name.
func totpCredential(name string) *oath.Credential {
	return withOATHSecret(&oath.Credential{
		ID:        strings.ToLower(name),
		Name:      name,
		Issuer:    "Example",
		Type:      oath.TypeTOTP,
		Algorithm: "SHA1",
		Digits:    6,
		Period:    30,
	}, "JBSWY3DPEHPK3PXP")
}

var sixDigits = regexp.MustCompile(`\b\d{6}\b`)

// --- oath add ---

func TestRunOATHAdd_FromIndividualFlags(t *testing.T) {
	store := oathStorePath(t)
	cmd, buf := newOATHCmd(t, oathAddCmd, store)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "name", "GitHub"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "issuer", "GitHub Inc"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "secret", "jbswy3dpehpk3pxp"))

	require.NoError(t, runOATHAdd(cmd, nil))
	assert.Contains(t, buf.String(), "Added OATH credential: GitHub")

	fs, err := oath.NewFileStore(store)
	require.NoError(t, err)
	defer func() { _ = fs.Close() }()

	cred, err := fs.Get("github")
	require.NoError(t, err)
	assert.Equal(t, "GitHub", cred.Name)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", cred.SecretString(), "the secret must be normalised to upper case")
	assert.Equal(t, oath.TypeTOTP, cred.Type)
	assert.Equal(t, 6, cred.Digits)
}

func TestRunOATHAdd_FromURI(t *testing.T) {
	store := oathStorePath(t)
	cmd, buf := newOATHCmd(t, oathAddCmd, store)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "uri",
		"otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=8&period=60"))

	require.NoError(t, runOATHAdd(cmd, nil))
	assert.Contains(t, buf.String(), "Added OATH credential:")

	fs, err := oath.NewFileStore(store)
	require.NoError(t, err)
	defer func() { _ = fs.Close() }()

	creds, err := fs.List()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, 8, creds[0].Digits)
	assert.Equal(t, 60, creds[0].Period)
	assert.Equal(t, "Example", creds[0].Issuer)
}

func TestRunOATHAdd_URINameOverride(t *testing.T) {
	store := oathStorePath(t)
	cmd, _ := newOATHCmd(t, oathAddCmd, store)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "uri",
		"otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "name", "Renamed"))

	require.NoError(t, runOATHAdd(cmd, nil))

	fs, err := oath.NewFileStore(store)
	require.NoError(t, err)
	defer func() { _ = fs.Close() }()

	creds, err := fs.List()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "Renamed", creds[0].Name)
}

func TestRunOATHAdd_RejectsInvalidURI(t *testing.T) {
	cmd, _ := newOATHCmd(t, oathAddCmd, oathStorePath(t))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "uri", "https://example.com/not-otpauth"))

	err := runOATHAdd(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOATHInvalidURI)
}

func TestRunOATHAdd_RequiresNameAndSecret(t *testing.T) {
	cmd, _ := newOATHCmd(t, oathAddCmd, oathStorePath(t))
	assert.ErrorIs(t, runOATHAdd(cmd, nil), ErrOATHMissingName)

	require.NoError(t, setFlagForTest(t, cmd.Flags(), "name", "GitHub"))
	assert.ErrorIs(t, runOATHAdd(cmd, nil), ErrOATHMissingSecret)
}

func TestRunOATHAdd_RejectsInvalidCredential(t *testing.T) {
	cmd, _ := newOATHCmd(t, oathAddCmd, oathStorePath(t))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "name", "Bad"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "secret", "JBSWY3DPEHPK3PXP"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "digits", "9"))

	err := runOATHAdd(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOATHInvalidCredential)
}

// --- oath list ---

func TestRunOATHList_EmptyStore(t *testing.T) {
	cmd, buf := newOATHCmd(t, oathListCmd, oathStorePath(t))

	require.NoError(t, runOATHList(cmd, nil))
	assert.Contains(t, buf.String(), "No OATH credentials found.")
}

func TestRunOATHList_ShowsCredentialDetails(t *testing.T) {
	store := oathStorePath(t)
	addTestCredential(t, store, totpCredential("GitHub"))

	hotp := totpCredential("Bank")
	hotp.ID = "bank"
	hotp.Type = oath.TypeHOTP
	hotp.Counter = 7
	hotp.Period = 0
	addTestCredential(t, store, hotp)

	cmd, buf := newOATHCmd(t, oathListCmd, store)
	require.NoError(t, runOATHList(cmd, nil))
	out := buf.String()

	assert.Contains(t, out, "OATH Credentials (2):")
	assert.Contains(t, out, "Name:      GitHub")
	assert.Contains(t, out, "Issuer:    Example")
	assert.Contains(t, out, "Type:      TOTP")
	assert.Contains(t, out, "Period:    30s")
	assert.Contains(t, out, "Type:      HOTP")
	assert.Contains(t, out, "Counter:   7")

	// Secrets are sensitive: they must stay hidden unless asked for.
	assert.NotContains(t, out, "JBSWY3DPEHPK3PXP")
	assert.NotContains(t, out, "URI:")
}

func TestRunOATHList_SecretsAndURIsOnDemand(t *testing.T) {
	store := oathStorePath(t)
	addTestCredential(t, store, totpCredential("GitHub"))

	cmd, buf := newOATHCmd(t, oathListCmd, store)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "secrets", "true"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "uri", "true"))

	require.NoError(t, runOATHList(cmd, nil))
	out := buf.String()
	assert.Contains(t, out, "Secret:    JBSWY3DPEHPK3PXP")
	assert.Contains(t, out, "URI:       otpauth://totp/")
}

// --- oath generate ---

func TestRunOATHGenerate_SingleCredential(t *testing.T) {
	store := oathStorePath(t)
	addTestCredential(t, store, totpCredential("GitHub"))

	cmd, buf := newOATHCmd(t, oathGenerateCmd, store)
	require.NoError(t, runOATHGenerate(cmd, []string{"github"}))

	out := buf.String()
	assert.Regexp(t, sixDigits, out, "a TOTP code must be printed")
	assert.Contains(t, out, "expires in")
}

func TestRunOATHGenerate_RequiresCredentialName(t *testing.T) {
	cmd, _ := newOATHCmd(t, oathGenerateCmd, oathStorePath(t))
	assert.ErrorIs(t, runOATHGenerate(cmd, nil), ErrOATHMissingCredential)
}

func TestRunOATHGenerate_UnknownCredentialIsReportedNotFatal(t *testing.T) {
	store := oathStorePath(t)
	addTestCredential(t, store, totpCredential("GitHub"))

	cmd, buf := newOATHCmd(t, oathGenerateCmd, store)
	// One good, one bad: the good code must still be emitted.
	require.NoError(t, runOATHGenerate(cmd, []string{"nope", "github"}))
	assert.Regexp(t, sixDigits, buf.String())
}

func TestRunOATHGenerate_AllEmptyStore(t *testing.T) {
	cmd, buf := newOATHCmd(t, oathGenerateCmd, oathStorePath(t))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "all", "true"))

	require.NoError(t, runOATHGenerate(cmd, nil))
	assert.Contains(t, buf.String(), "No OATH credentials found.")
}

func TestRunOATHGenerate_AllAlignsNames(t *testing.T) {
	store := oathStorePath(t)
	addTestCredential(t, store, totpCredential("A"))
	long := totpCredential("VeryLongCredentialName")
	addTestCredential(t, store, long)

	cmd, buf := newOATHCmd(t, oathGenerateCmd, store)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "all", "true"))
	require.NoError(t, runOATHGenerate(cmd, nil))

	out := buf.String()
	assert.Contains(t, out, "A")
	assert.Contains(t, out, "VeryLongCredentialName")
	// Both names are padded to the widest name, so the short one is followed
	// by the padding that lines the codes up.
	assert.Contains(t, out, "  A                       ")
}

func TestRunOATHGenerate_HOTPIncrementsCounter(t *testing.T) {
	store := oathStorePath(t)
	hotp := totpCredential("Bank")
	hotp.Type = oath.TypeHOTP
	hotp.Counter = 0
	hotp.Period = 0
	addTestCredential(t, store, hotp)

	cmd, buf := newOATHCmd(t, oathGenerateCmd, store)
	require.NoError(t, runOATHGenerate(cmd, []string{"bank"}))
	first := strings.TrimSpace(buf.String())
	assert.NotContains(t, first, "expires in", "HOTP codes do not expire on a timer")

	fs, err := oath.NewFileStore(store)
	require.NoError(t, err)
	cred, err := fs.Get("bank")
	require.NoError(t, err)
	require.NoError(t, fs.Close())
	assert.Equal(t, uint64(1), cred.Counter, "generating a HOTP code must advance the counter")

	// The next code differs because the counter moved.
	cmd2, buf2 := newOATHCmd(t, oathGenerateCmd, store)
	require.NoError(t, runOATHGenerate(cmd2, []string{"bank"}))
	assert.NotEqual(t, first, strings.TrimSpace(buf2.String()))
}

// --- oath remove ---

func TestRunOATHRemove_RequiresArgument(t *testing.T) {
	cmd, _ := newOATHCmd(t, oathRemoveCmd, oathStorePath(t))
	assert.ErrorIs(t, runOATHRemove(cmd, nil), ErrOATHMissingRemoveArg)
}

func TestRunOATHRemove_ForceSkipsConfirmation(t *testing.T) {
	store := oathStorePath(t)
	addTestCredential(t, store, totpCredential("GitHub"))

	cmd, buf := newOATHCmd(t, oathRemoveCmd, store)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "force", "true"))
	require.NoError(t, runOATHRemove(cmd, []string{"github"}))
	assert.Contains(t, buf.String(), "Removed: GitHub")

	fs, err := oath.NewFileStore(store)
	require.NoError(t, err)
	defer func() { _ = fs.Close() }()

	creds, err := fs.List()
	require.NoError(t, err)
	assert.Empty(t, creds)
}

func TestRunOATHRemove_ConfirmationAccepted(t *testing.T) {
	store := oathStorePath(t)
	addTestCredential(t, store, totpCredential("GitHub"))
	pipeStdin(t, "y\n")

	cmd, buf := newOATHCmd(t, oathRemoveCmd, store)
	require.NoError(t, runOATHRemove(cmd, []string{"github"}))

	out := buf.String()
	assert.Contains(t, out, "Remove credential 'GitHub'? [y/N]: ")
	assert.Contains(t, out, "Removed: GitHub")
}

func TestRunOATHRemove_ConfirmationDeclinedKeepsCredential(t *testing.T) {
	store := oathStorePath(t)
	addTestCredential(t, store, totpCredential("GitHub"))
	pipeStdin(t, "n\n")

	cmd, buf := newOATHCmd(t, oathRemoveCmd, store)
	require.NoError(t, runOATHRemove(cmd, []string{"github"}))
	assert.Contains(t, buf.String(), "Skipped GitHub")

	fs, err := oath.NewFileStore(store)
	require.NoError(t, err)
	defer func() { _ = fs.Close() }()

	creds, err := fs.List()
	require.NoError(t, err)
	assert.Len(t, creds, 1, "declining the prompt must not delete the credential")
}

func TestRunOATHRemove_UnknownCredentialIsSkipped(t *testing.T) {
	store := oathStorePath(t)
	addTestCredential(t, store, totpCredential("GitHub"))

	cmd, buf := newOATHCmd(t, oathRemoveCmd, store)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "force", "true"))
	require.NoError(t, runOATHRemove(cmd, []string{"missing", "github"}))
	assert.Contains(t, buf.String(), "Removed: GitHub")
}

// --- oath scan ---

func TestRunOATHScan_ListDisplays(t *testing.T) {
	cmd, buf := newOATHCmd(t, oathScanCmd, oathStorePath(t))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "list-displays", "true"))

	require.NoError(t, runOATHScan(cmd, nil))
	out := buf.String()
	// Headless CI has no displays; a machine with displays lists them. Both
	// are valid, but the command must never fail or stay silent.
	assert.True(t,
		strings.Contains(out, "No displays found.") || strings.Contains(out, "display(s):"),
		"unexpected list-displays output: %q", out)
}
