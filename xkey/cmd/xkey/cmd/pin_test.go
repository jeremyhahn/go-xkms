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
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// isolatePIN gives a test its own PIN data directory and neutralises every
// other source that resolvePINDataDir consults, so PIN state never leaks
// between tests or onto the developer's machine.
func isolatePIN(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	isolateDaemonSocket(t)

	previousFlag := pinDataDir
	previousViper := viper.Get("data_dir")
	previousType := pinVerifyType
	previousJSON := pinStatusJSON

	pinDataDir = dir
	viper.Set("data_dir", "")
	pinVerifyType = "user"
	pinStatusJSON = false
	t.Setenv("XKEY_DATA_DIR", "")

	t.Cleanup(func() {
		pinDataDir = previousFlag
		viper.Set("data_dir", previousViper)
		pinVerifyType = previousType
		pinStatusJSON = previousJSON
	})

	return dir
}

// pipePIN feeds lines to the PIN reader as if they had been piped in on
// stdin and forces the non-terminal code path.
func pipePIN(t *testing.T, lines ...string) {
	t.Helper()

	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\n")
	}

	restoreStdin := setPINStdin(strings.NewReader(b.String()))
	previousIsTerminal := pinInputIsTerminal
	pinInputIsTerminal = func() bool { return false }

	t.Cleanup(func() {
		restoreStdin()
		pinInputIsTerminal = previousIsTerminal
	})
}

// runPINCmd invokes a PIN RunE with a captured output buffer.
func runPINCmd(t *testing.T, run func(*cobra.Command, []string) error) (string, error) {
	t.Helper()

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	err := run(cmd, nil)
	return buf.String(), err
}

// --- readLineFromPipedStdin ---

func TestReadLineFromPipedStdin_TrimsLineEndings(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"unix newline", "123456\n", "123456"},
		// A CRLF-terminated PIN must not retain the carriage return: a PIN
		// stored with a trailing \r can never be re-entered from a terminal,
		// which permanently locks the credential.
		{"crlf newline", "123456\r\n", "123456"},
		{"no trailing newline", "123456", "123456"},
		{"interior spaces preserved", "pass phrase\n", "pass phrase"},
		{"leading space preserved", " 123456\n", " 123456"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restore := setPINStdin(strings.NewReader(tt.input))
			defer restore()

			got, err := readLineFromPipedStdin()
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestReadLineFromPipedStdin_RejectsEmptyInput(t *testing.T) {
	for _, input := range []string{"", "\n", "\r\n"} {
		restore := setPINStdin(strings.NewReader(input))
		got, err := readLineFromPipedStdin()
		restore()

		assert.Empty(t, got)
		assert.ErrorIs(t, err, ErrPINCmdEmpty, "input %q must be rejected as empty", input)
	}
}

func TestReadLineFromPipedStdin_PropagatesReaderError(t *testing.T) {
	restore := setPINStdin(errReader{err: errors.New("boom")})
	defer restore()

	_, err := readLineFromPipedStdin()
	require.Error(t, err)

	var pinErr *PINCommandError
	require.ErrorAs(t, err, &pinErr)
	assert.Equal(t, "read_pin", pinErr.Operation)
	assert.Contains(t, err.Error(), "boom")
}

// errReader always fails, exercising the non-EOF read error path.
type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

func TestSetPINStdin_ResetsBufferedReader(t *testing.T) {
	// The reader is shared and buffered; swapping the source must discard
	// whatever the previous source had already buffered, otherwise a stale
	// PIN would be returned.
	restoreFirst := setPINStdin(strings.NewReader("first\nleftover\n"))
	first, err := readLineFromPipedStdin()
	require.NoError(t, err)
	assert.Equal(t, "first", first)

	restoreSecond := setPINStdin(strings.NewReader("second\n"))
	second, err := readLineFromPipedStdin()
	require.NoError(t, err)
	assert.Equal(t, "second", second)

	restoreSecond()
	restoreFirst()
}

func TestReadPIN_ReadsPipedLine(t *testing.T) {
	pipePIN(t, "sekret1")

	var buf bytes.Buffer
	got, err := readPIN(&buf, "Enter PIN: ")
	require.NoError(t, err)
	assert.Equal(t, "sekret1", got)
	// The prompt is only written on the interactive path.
	assert.Empty(t, buf.String())
}

func TestReadPIN_TerminalPathReportsReadFailure(t *testing.T) {
	// Force the interactive branch while stdin is not a real terminal; the
	// password read must fail rather than silently returning an empty PIN.
	previous := pinInputIsTerminal
	pinInputIsTerminal = func() bool { return true }
	defer func() { pinInputIsTerminal = previous }()

	var buf bytes.Buffer
	_, err := readPIN(&buf, "Enter PIN: ")
	require.Error(t, err)
	assert.Contains(t, buf.String(), "Enter PIN: ")
}

func TestReadAndConfirmPIN_MatchingPipedLines(t *testing.T) {
	pipePIN(t, "matching", "matching")

	var buf bytes.Buffer
	got, err := readAndConfirmPIN(&buf, "Enter PIN: ")
	require.NoError(t, err)
	assert.Equal(t, "matching", got)
}

func TestReadAndConfirmPIN_MismatchedPipedLines(t *testing.T) {
	pipePIN(t, "first-pin", "second-pin")

	var buf bytes.Buffer
	_, err := readAndConfirmPIN(&buf, "Enter PIN: ")
	assert.ErrorIs(t, err, ErrPINCmdMismatch)
}

func TestReadAndConfirmPIN_SecondLineMissing(t *testing.T) {
	pipePIN(t, "only-one")

	var buf bytes.Buffer
	_, err := readAndConfirmPIN(&buf, "Enter PIN: ")
	assert.ErrorIs(t, err, ErrPINCmdEmpty)
}

func TestReadAndConfirmPIN_TerminalPathReportsReadFailure(t *testing.T) {
	previous := pinInputIsTerminal
	pinInputIsTerminal = func() bool { return true }
	defer func() { pinInputIsTerminal = previous }()

	var buf bytes.Buffer
	_, err := readAndConfirmPIN(&buf, "Enter PIN: ")
	require.Error(t, err)
}

// --- resolvePINDataDir ---

func TestResolvePINDataDir_FlagWins(t *testing.T) {
	dir := isolatePIN(t)
	t.Setenv("XKEY_DATA_DIR", "/env/should/lose")
	viper.Set("data_dir", "/viper/should/lose")

	got, err := resolvePINDataDir()
	require.NoError(t, err)
	assert.Equal(t, dir, got)
}

func TestResolvePINDataDir_EnvBeatsViper(t *testing.T) {
	isolatePIN(t)
	pinDataDir = ""
	t.Setenv("XKEY_DATA_DIR", "/env/wins/")
	viper.Set("data_dir", "/viper/loses")

	got, err := resolvePINDataDir()
	require.NoError(t, err)
	assert.Equal(t, "/env/wins", got, "path must be cleaned")
}

func TestResolvePINDataDir_ViperFallback(t *testing.T) {
	isolatePIN(t)
	pinDataDir = ""
	viper.Set("data_dir", "/viper/./dir")

	got, err := resolvePINDataDir()
	require.NoError(t, err)
	assert.Equal(t, "/viper/dir", got)
}

func TestResolvePINDataDir_HomeFallback(t *testing.T) {
	isolatePIN(t)
	pinDataDir = ""
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(xhome.EnvHome, "")
	xhome.ResetRoot()

	got, err := resolvePINDataDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(home, ".xkey", "data"), got,
		"pin must fall back to the same ~/.xkey/data every other subsystem uses (issue #295)")
}

func TestResolvePINDataDirExisting_FlagWins(t *testing.T) {
	dir := isolatePIN(t)
	t.Setenv("XKEY_DATA_DIR", "/env/should/lose")
	viper.Set("data_dir", "/viper/should/lose")

	got, err := resolvePINDataDirExisting()
	require.NoError(t, err)
	assert.Equal(t, dir, got)
}

func TestResolvePINDataDirExisting_NothingResolvableErrors(t *testing.T) {
	isolatePIN(t)
	pinDataDir = ""
	t.Setenv(xhome.EnvHome, filepath.Join(t.TempDir(), "missing"))
	xhome.ResetRoot()

	_, err := resolvePINDataDirExisting()
	require.Error(t, err)

	var pinErr *PINCommandError
	require.ErrorAs(t, err, &pinErr)
	assert.Equal(t, "resolve_data_dir", pinErr.Operation)
	assert.ErrorIs(t, err, xhome.ErrHomeNotResolved)
}

// --- createPINService ---

func TestCreatePINService_CreatesPrivateDirectory(t *testing.T) {
	dir := t.TempDir()

	svc, err := createPINService(dir)
	require.NoError(t, err)
	require.NotNil(t, svc)

	info, err := os.Stat(filepath.Join(dir, defaultPINStateSubdir))
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	assert.Equal(t, os.FileMode(0700), info.Mode().Perm(),
		"PIN state directory must not be readable by other users")

	assert.False(t, svc.SOPINSet(), "a fresh store must report no SO PIN")
}

func TestCreatePINService_RejectsUnusableDataDir(t *testing.T) {
	// A regular file cannot host the pin/ subdirectory.
	file := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0600))

	_, err := createPINService(file)
	require.Error(t, err)

	var pinErr *PINCommandError
	require.ErrorAs(t, err, &pinErr)
	assert.Equal(t, "create_pin_dir", pinErr.Operation)
}

// --- openPINService ---

func TestOpenPINService_MissingStoreReturnsTypedError(t *testing.T) {
	dir := t.TempDir()

	_, err := openPINService(dir)
	require.Error(t, err)

	var notFound *PINStoreNotFoundError
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, filepath.Join(dir, defaultPINStateSubdir), notFound.Dir)

	_, statErr := os.Stat(filepath.Join(dir, defaultPINStateSubdir))
	assert.True(t, os.IsNotExist(statErr),
		"opening for read must not create the pin directory")
}

func TestOpenPINService_OpensExistingStore(t *testing.T) {
	dir := t.TempDir()

	svc, err := createPINService(dir)
	require.NoError(t, err)
	require.NoError(t, svc.SetSOPIN("", "so-pin-one"))

	opened, err := openPINService(dir)
	require.NoError(t, err)
	assert.True(t, opened.SOPINSet())
	require.NoError(t, opened.VerifySOPIN("so-pin-one"))
}

// TestPINReadCommands_MissingStoreReturnsNotFound pins the read commands'
// behavior against an absent store: a typed not-found error, never a
// phantom fresh store (issue #295).
func TestPINReadCommands_MissingStoreReturnsNotFound(t *testing.T) {
	runs := map[string]func(*cobra.Command, []string) error{
		"verify":        runPINVerify,
		"change-so":     runPINChangeSO,
		"change-user":   runPINChangeUser,
		"reset-lockout": runPINResetLockout,
	}

	for name, run := range runs {
		t.Run(name, func(t *testing.T) {
			dir := isolatePIN(t)
			pipePIN(t, "some-pin", "some-pin", "some-pin")

			_, err := runPINCmd(t, run)
			var notFound *PINStoreNotFoundError
			require.ErrorAs(t, err, &notFound)

			_, statErr := os.Stat(filepath.Join(dir, defaultPINStateSubdir))
			assert.True(t, os.IsNotExist(statErr),
				"a failed read command must not create the pin directory")
		})
	}
}

// TestPINCommands_AddressTheWizardDataDirectory reproduces issue #295: the
// setup wizard persists PIN state under ~/.xkey/data/pin/, and every pin
// subcommand run with no overrides must address that same store. On the
// defective code the pin group resolved ~/.xkey instead, read a phantom
// empty store, reported PINs as unset, and let set-so fork a second SO PIN
// record without presenting the current one.
func TestPINCommands_AddressTheWizardDataDirectory(t *testing.T) {
	isolatePIN(t)
	pinDataDir = ""
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(xhome.EnvHome, "")
	xhome.ResetRoot()

	// The wizard writes through xhome: ~/.xkey/data/pin/{so-pin,user-pin}.
	wizardDataDir := filepath.Join(home, ".xkey", "data")
	wizard, err := createPINService(wizardDataDir)
	require.NoError(t, err)
	require.NoError(t, wizard.SetSOPIN("", "wizard-so-pin"))
	require.NoError(t, wizard.SetUserPIN("wizard-so-pin", "wizard-user-pin"))

	// pin status must report the store the wizard wrote.
	out, err := runPINCmd(t, runPINStatus)
	require.NoError(t, err)
	assert.Contains(t, out, "SO PIN set:       Yes")
	assert.Contains(t, out, "User PIN set:     Yes")

	// ... without manufacturing the phantom ~/.xkey/pin store.
	_, statErr := os.Stat(filepath.Join(home, ".xkey", "pin"))
	assert.True(t, os.IsNotExist(statErr),
		"a status read must not create ~/.xkey/pin")

	// pin verify must authenticate against the wizard's store.
	pinVerifyType = "user"
	pipePIN(t, "wizard-user-pin")
	out, err = runPINCmd(t, runPINVerify)
	require.NoError(t, err)
	assert.Contains(t, out, "User PIN: VALID")

	// set-so addresses the same store, so with an SO PIN already set it
	// demands the current one: a caller who cannot present it is refused
	// instead of silently forking a divergent SO PIN record.
	pipePIN(t, "not-the-so-pin", "forked-so-pin", "forked-so-pin")
	_, err = runPINCmd(t, runPINSetSO)
	require.Error(t, err, "set-so without the current SO PIN must be refused")

	after, err := openPINService(wizardDataDir)
	require.NoError(t, err)
	require.NoError(t, after.VerifySOPIN("wizard-so-pin"),
		"the wizard's SO PIN must survive a refused set-so")
	_, statErr = os.Stat(filepath.Join(home, ".xkey", "pin"))
	assert.True(t, os.IsNotExist(statErr), "no divergent store may appear")

	// With the current SO PIN presented, rotation succeeds in place.
	pipePIN(t, "wizard-so-pin", "rotated-so-pin", "rotated-so-pin")
	out, err = runPINCmd(t, runPINSetSO)
	require.NoError(t, err)
	assert.Contains(t, out, "SO PIN set successfully.")

	after, err = openPINService(wizardDataDir)
	require.NoError(t, err)
	require.NoError(t, after.VerifySOPIN("rotated-so-pin"))
}

// --- pin set-so / set-user ---

func TestRunPINSetSO_SetsAndThenRotatesPIN(t *testing.T) {
	dir := isolatePIN(t)

	pipePIN(t, "so-pin-one", "so-pin-one")
	out, err := runPINCmd(t, runPINSetSO)
	require.NoError(t, err)
	assert.Contains(t, out, "SO PIN set successfully.")

	// The PIN really landed in the store, so a second run must demand the
	// current PIN before accepting a replacement.
	svc, err := createPINService(dir)
	require.NoError(t, err)
	assert.True(t, svc.SOPINSet())

	pipePIN(t, "so-pin-one", "so-pin-two", "so-pin-two")
	out, err = runPINCmd(t, runPINSetSO)
	require.NoError(t, err)
	assert.Contains(t, out, "SO PIN set successfully.")

	svc, err = createPINService(dir)
	require.NoError(t, err)
	require.NoError(t, svc.VerifySOPIN("so-pin-two"))
}

func TestRunPINSetSO_RejectsWrongCurrentPIN(t *testing.T) {
	isolatePIN(t)

	pipePIN(t, "so-pin-one", "so-pin-one")
	_, err := runPINCmd(t, runPINSetSO)
	require.NoError(t, err)

	pipePIN(t, "not-the-pin", "so-pin-two", "so-pin-two")
	_, err = runPINCmd(t, runPINSetSO)
	require.Error(t, err)

	var pinErr *PINCommandError
	require.ErrorAs(t, err, &pinErr)
	assert.Equal(t, "set_so", pinErr.Operation)
}

func TestRunPINSetSO_PropagatesConfirmationMismatch(t *testing.T) {
	isolatePIN(t)

	pipePIN(t, "so-pin-one", "different")
	_, err := runPINCmd(t, runPINSetSO)
	assert.ErrorIs(t, err, ErrPINCmdMismatch)
}

func TestRunPINSetUser_RequiresSOPINFirst(t *testing.T) {
	isolatePIN(t)

	_, err := runPINCmd(t, runPINSetUser)
	require.Error(t, err)

	var pinErr *PINCommandError
	require.ErrorAs(t, err, &pinErr)
	assert.Equal(t, "set_user", pinErr.Operation)
	assert.Contains(t, err.Error(), "SO PIN must be set first")
}

func TestRunPINSetUser_SetsUserPINWithSOAuthorization(t *testing.T) {
	dir := isolatePIN(t)

	pipePIN(t, "so-pin-one", "so-pin-one")
	_, err := runPINCmd(t, runPINSetSO)
	require.NoError(t, err)

	pipePIN(t, "so-pin-one", "user-pin-1", "user-pin-1")
	out, err := runPINCmd(t, runPINSetUser)
	require.NoError(t, err)
	assert.Contains(t, out, "User PIN set successfully.")

	svc, err := createPINService(dir)
	require.NoError(t, err)
	assert.True(t, svc.UserPINSet())
	require.NoError(t, svc.VerifyUserPIN("user-pin-1"))
}

func TestRunPINSetUser_RejectsWrongSOPIN(t *testing.T) {
	isolatePIN(t)

	pipePIN(t, "so-pin-one", "so-pin-one")
	_, err := runPINCmd(t, runPINSetSO)
	require.NoError(t, err)

	pipePIN(t, "wrong-so-pin", "user-pin-1", "user-pin-1")
	_, err = runPINCmd(t, runPINSetUser)
	require.Error(t, err)

	var pinErr *PINCommandError
	require.ErrorAs(t, err, &pinErr)
	assert.Equal(t, "set_user", pinErr.Operation)
}

// --- pin change-so / change-user ---

func TestRunPINChangeSO_ChangesPIN(t *testing.T) {
	dir := isolatePIN(t)

	pipePIN(t, "so-pin-one", "so-pin-one")
	_, err := runPINCmd(t, runPINSetSO)
	require.NoError(t, err)

	pipePIN(t, "so-pin-one", "so-pin-new", "so-pin-new")
	out, err := runPINCmd(t, runPINChangeSO)
	require.NoError(t, err)
	assert.Contains(t, out, "SO PIN changed successfully.")

	svc, err := createPINService(dir)
	require.NoError(t, err)
	require.NoError(t, svc.VerifySOPIN("so-pin-new"))
	assert.Error(t, svc.VerifySOPIN("so-pin-one"), "the old SO PIN must stop working")
}

func TestRunPINChangeSO_RejectsWrongCurrentPIN(t *testing.T) {
	isolatePIN(t)

	pipePIN(t, "so-pin-one", "so-pin-one")
	_, err := runPINCmd(t, runPINSetSO)
	require.NoError(t, err)

	pipePIN(t, "bogus-current", "so-pin-new", "so-pin-new")
	_, err = runPINCmd(t, runPINChangeSO)
	require.Error(t, err)

	var pinErr *PINCommandError
	require.ErrorAs(t, err, &pinErr)
	assert.Equal(t, "change_so", pinErr.Operation)
}

func TestRunPINChangeUser_ChangesPIN(t *testing.T) {
	dir := isolatePIN(t)

	pipePIN(t, "so-pin-one", "so-pin-one")
	_, err := runPINCmd(t, runPINSetSO)
	require.NoError(t, err)
	pipePIN(t, "so-pin-one", "user-pin-1", "user-pin-1")
	_, err = runPINCmd(t, runPINSetUser)
	require.NoError(t, err)

	pipePIN(t, "user-pin-1", "user-pin-2", "user-pin-2")
	out, err := runPINCmd(t, runPINChangeUser)
	require.NoError(t, err)
	assert.Contains(t, out, "User PIN changed successfully.")

	svc, err := createPINService(dir)
	require.NoError(t, err)
	require.NoError(t, svc.VerifyUserPIN("user-pin-2"))
}

func TestRunPINChangeUser_RejectsWrongCurrentPIN(t *testing.T) {
	isolatePIN(t)

	pipePIN(t, "so-pin-one", "so-pin-one")
	_, err := runPINCmd(t, runPINSetSO)
	require.NoError(t, err)
	pipePIN(t, "so-pin-one", "user-pin-1", "user-pin-1")
	_, err = runPINCmd(t, runPINSetUser)
	require.NoError(t, err)

	pipePIN(t, "wrong-user-pin", "user-pin-2", "user-pin-2")
	_, err = runPINCmd(t, runPINChangeUser)
	require.Error(t, err)

	var pinErr *PINCommandError
	require.ErrorAs(t, err, &pinErr)
	assert.Equal(t, "change_user", pinErr.Operation)
}

// --- pin verify ---

func TestRunPINVerify_ValidSOAndUserPINs(t *testing.T) {
	isolatePIN(t)

	pipePIN(t, "so-pin-one", "so-pin-one")
	_, err := runPINCmd(t, runPINSetSO)
	require.NoError(t, err)
	pipePIN(t, "so-pin-one", "user-pin-1", "user-pin-1")
	_, err = runPINCmd(t, runPINSetUser)
	require.NoError(t, err)

	pinVerifyType = "so"
	pipePIN(t, "so-pin-one")
	out, err := runPINCmd(t, runPINVerify)
	require.NoError(t, err)
	assert.Contains(t, out, "SO PIN: VALID")

	pinVerifyType = "user"
	pipePIN(t, "user-pin-1")
	out, err = runPINCmd(t, runPINVerify)
	require.NoError(t, err)
	assert.Contains(t, out, "User PIN: VALID")
}

func TestRunPINVerify_InvalidPINReportsAndErrors(t *testing.T) {
	isolatePIN(t)

	pipePIN(t, "so-pin-one", "so-pin-one")
	_, err := runPINCmd(t, runPINSetSO)
	require.NoError(t, err)

	pinVerifyType = "so"
	pipePIN(t, "wrong-pin")
	out, err := runPINCmd(t, runPINVerify)
	require.Error(t, err)
	assert.Contains(t, out, "SO PIN: INVALID")

	var pinErr *PINCommandError
	require.ErrorAs(t, err, &pinErr)
	assert.Equal(t, "verify_so", pinErr.Operation)
}

func TestRunPINVerify_UnknownTypeRejected(t *testing.T) {
	isolatePIN(t)
	pinVerifyType = "admin"

	_, err := runPINCmd(t, runPINVerify)
	assert.ErrorIs(t, err, ErrPINCmdInvalidType)
}

func TestPINVerifyHandlers_CoverBothDocumentedTypes(t *testing.T) {
	// The --type flag help promises exactly "so" and "user"; the dispatch
	// table must agree or the flag documentation lies.
	assert.Len(t, pinVerifyHandlers, 2)
	assert.Contains(t, pinVerifyHandlers, "so")
	assert.Contains(t, pinVerifyHandlers, "user")
}

// --- pin status ---

func TestRunPINStatus_TextReflectsStoreState(t *testing.T) {
	dir := isolatePIN(t)

	// No store yet: status must say so, not report a confident "not set".
	out, err := runPINCmd(t, runPINStatus)
	require.NoError(t, err)
	assert.Contains(t, out, "PIN store:        not found")
	assert.NotContains(t, out, "SO PIN set:")

	// The read must not have created the store it failed to find.
	_, statErr := os.Stat(filepath.Join(dir, defaultPINStateSubdir))
	assert.True(t, os.IsNotExist(statErr),
		"a status read must not create the pin directory")

	pipePIN(t, "so-pin-one", "so-pin-one")
	_, err = runPINCmd(t, runPINSetSO)
	require.NoError(t, err)

	out, err = runPINCmd(t, runPINStatus)
	require.NoError(t, err)
	assert.Contains(t, out, "SO PIN set:       Yes")
	assert.Contains(t, out, "User PIN set:     No")
	assert.Contains(t, out, "Locked:           No")
}

func TestRunPINStatus_JSONMatchesTextState(t *testing.T) {
	isolatePIN(t)

	pipePIN(t, "so-pin-one", "so-pin-one")
	_, err := runPINCmd(t, runPINSetSO)
	require.NoError(t, err)

	pinStatusJSON = true
	out, err := runPINCmd(t, runPINStatus)
	require.NoError(t, err)

	var info pinStatusInfo
	require.NoError(t, json.Unmarshal([]byte(out), &info))
	assert.True(t, info.SOPINSet)
	assert.False(t, info.UserPINSet)
	assert.False(t, info.IsLocked)
	assert.NotEmpty(t, info.Strategy)
}

// TestRunPINStatus_RendersZeroLockoutWhenBackendHasNoCounters pins the
// rendering of the nil-lockout case. The qrdb software backend deliberately
// returns no LockoutStatus (it relies on Argon2id cost instead of attempt
// counters), so the CLI must degrade to zeros rather than panic or omit the
// section. See the reported finding about the misleading wording.
func TestRunPINStatus_RendersZeroLockoutWhenBackendHasNoCounters(t *testing.T) {
	isolatePIN(t)

	pipePIN(t, "so-pin-one", "so-pin-one")
	_, err := runPINCmd(t, runPINSetSO)
	require.NoError(t, err)

	pinVerifyType = "so"
	pipePIN(t, "wrong-pin")
	_, err = runPINCmd(t, runPINVerify)
	require.Error(t, err)

	out, err := runPINCmd(t, runPINStatus)
	require.NoError(t, err)
	assert.Contains(t, out, "Lockout Status:")
	assert.Contains(t, out, "Failed attempts:  0 / 0")
	assert.Contains(t, out, "Locked:           No")
	assert.NotContains(t, out, "Recovery in:")

	pinStatusJSON = true
	jsonOut, err := runPINCmd(t, runPINStatus)
	require.NoError(t, err)

	var info pinStatusInfo
	require.NoError(t, json.Unmarshal([]byte(jsonOut), &info))
	assert.Zero(t, info.FailedAttempts)
	assert.Zero(t, info.MaxAttempts)
	assert.False(t, info.IsLocked)
}

func TestRunPINStatus_UnusableDataDirReportsStoreNotFound(t *testing.T) {
	// A data dir that is a regular file cannot hold a pin/ directory: the
	// store is simply not there, and status must say so rather than fail
	// trying to create storage during a read.
	isolatePIN(t)
	file := filepath.Join(t.TempDir(), "regular-file")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0600))
	pinDataDir = file

	out, err := runPINCmd(t, runPINStatus)
	require.NoError(t, err)
	assert.Contains(t, out, "PIN store:        not found")
}

func TestRunPINStatus_MissingStoreJSONReportsStoreAbsent(t *testing.T) {
	isolatePIN(t)
	pinStatusJSON = true

	out, err := runPINCmd(t, runPINStatus)
	require.NoError(t, err)

	var info pinStatusInfo
	require.NoError(t, json.Unmarshal([]byte(out), &info))
	assert.False(t, info.StorePresent)
	assert.False(t, info.Initialized)
}

func TestBoolToYesNo(t *testing.T) {
	assert.Equal(t, "Yes", boolToYesNo(true))
	assert.Equal(t, "No", boolToYesNo(false))
}

// --- pin reset-lockout ---

func TestRunPINResetLockout_ReportsSuccess(t *testing.T) {
	isolatePIN(t)

	pipePIN(t, "so-pin-one", "so-pin-one")
	_, err := runPINCmd(t, runPINSetSO)
	require.NoError(t, err)

	pipePIN(t, "so-pin-one")
	out, err := runPINCmd(t, runPINResetLockout)
	require.NoError(t, err)
	assert.Contains(t, out, "Lockout reset successfully.")
}

// TestRunPINResetLockout_RequiresAPIN checks the CLI-layer precondition:
// reset-lockout must read an SO PIN before touching the service, and must
// surface a read failure rather than silently succeeding.
func TestRunPINResetLockout_RequiresAPIN(t *testing.T) {
	isolatePIN(t)

	pipePIN(t, "so-pin-one", "so-pin-one")
	_, err := runPINCmd(t, runPINSetSO)
	require.NoError(t, err)

	pipePIN(t) // no input at all
	_, err = runPINCmd(t, runPINResetLockout)
	assert.ErrorIs(t, err, ErrPINCmdEmpty)
}

func TestRunPINResetLockout_FailsWhenDataDirUnusable(t *testing.T) {
	isolatePIN(t)
	file := filepath.Join(t.TempDir(), "regular-file")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0600))
	pinDataDir = file

	_, err := runPINCmd(t, runPINResetLockout)
	require.Error(t, err)

	var notFound *PINStoreNotFoundError
	require.ErrorAs(t, err, &notFound,
		"a data dir with no store must surface as store-not-found")
}

// --- PINCommandError ---

func TestPINCommandError_Message(t *testing.T) {
	tests := []struct {
		name string
		err  *PINCommandError
		want string
	}{
		{"operation only", &PINCommandError{Operation: "verify"}, "pin: verify"},
		{"operation and message", &PINCommandError{Operation: "verify", Message: "bad type"}, "pin: verify: bad type"},
		{"operation and cause", &PINCommandError{Operation: "verify", Err: io.EOF}, "pin: verify: EOF"},
		{"all three", &PINCommandError{Operation: "verify", Message: "bad type", Err: io.EOF}, "pin: verify: bad type: EOF"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.err.Error())
		})
	}
}

func TestPINCommandError_Unwrap(t *testing.T) {
	wrapped := &PINCommandError{Operation: "verify", Err: io.EOF}
	assert.ErrorIs(t, wrapped, io.EOF)
	assert.Nil(t, (&PINCommandError{Operation: "verify"}).Unwrap())
}
