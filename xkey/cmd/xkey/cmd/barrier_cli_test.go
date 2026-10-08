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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// isolateBarrier gives a test its own barrier data directory and neutralises
// every other source resolveBarrierDataDir consults.
func isolateBarrier(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	isolateDaemonSocket(t)

	previousDataDir := barrierDataDir
	previousStrategy := barrierStrategy
	previousJSON := barrierStatusJSON
	previousViper := viper.Get("data_dir")

	barrierDataDir = dir
	barrierStrategy = "software"
	barrierStatusJSON = false
	viper.Set("data_dir", "")
	t.Setenv("XKEY_DATA_DIR", "")

	t.Cleanup(func() {
		barrierDataDir = previousDataDir
		barrierStrategy = previousStrategy
		barrierStatusJSON = previousJSON
		viper.Set("data_dir", previousViper)
	})

	return dir
}

// writeBarrierRootKey stores blob as the sealed root key in the barrier
// storage under dataDir, where barrier init would put it.
func writeBarrierRootKey(t *testing.T, dataDir string, blob []byte) {
	t.Helper()

	backend, err := xkms.NewFileStorageBackend(dataDir)
	require.NoError(t, err)
	defer func() { require.NoError(t, backend.Close()) }()
	require.NoError(t, backend.Put(t.Context(), defaultBarrierRootKeyPath, blob))
}

// readStorageEntry returns the raw bytes the go-qrdb file engine under dir
// holds for key: ciphertext when a barrier wrote it, plaintext otherwise.
func readStorageEntry(t *testing.T, dir, key string) []byte {
	t.Helper()

	backend, err := xkms.NewFileStorageBackend(dir)
	require.NoError(t, err)
	defer func() { require.NoError(t, backend.Close()) }()
	data, err := backend.Get(t.Context(), key)
	require.NoError(t, err, "storage under %s must hold %s", dir, key)
	return data
}

// storageEntryExists reports whether the go-qrdb file engine under dir holds
// key.
func storageEntryExists(t *testing.T, dir, key string) bool {
	t.Helper()

	backend, err := xkms.NewFileStorageBackend(dir)
	require.NoError(t, err)
	defer func() { require.NoError(t, backend.Close()) }()
	exists, err := backend.Exists(t.Context(), key)
	require.NoError(t, err)
	return exists
}

// pipeBarrier feeds lines to the barrier password reader as if piped in on
// stdin and forces the non-terminal code path.
func pipeBarrier(t *testing.T, lines ...string) {
	t.Helper()

	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\n")
	}

	restore := setBarrierStdin(strings.NewReader(b.String()))
	previous := barrierInputIsTerminal
	barrierInputIsTerminal = func() bool { return false }

	t.Cleanup(func() {
		restore()
		barrierInputIsTerminal = previous
	})
}

func runBarrierCmd(t *testing.T, run func(*cobra.Command, []string) error) (string, error) {
	t.Helper()

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetContext(t.Context())
	err := run(cmd, nil)
	return buf.String(), err
}

// --- password reading ---

func TestReadBarrierLineFromPipedStdin_TrimsCRLF(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"unix newline", "hunter2\n", "hunter2"},
		// A CRLF-terminated password must not retain the carriage return:
		// the barrier would be sealed with a secret that can never be
		// re-entered from a terminal.
		{"crlf newline", "hunter2\r\n", "hunter2"},
		{"no trailing newline", "hunter2", "hunter2"},
		{"empty line", "\n", ""},
		{"empty crlf line", "\r\n", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restore := setBarrierStdin(strings.NewReader(tt.input))
			defer restore()

			got, err := readBarrierLineFromPipedStdin()
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestReadBarrierLineFromPipedStdin_PropagatesReaderError(t *testing.T) {
	restore := setBarrierStdin(errReader{err: errors.New("pipe broke")})
	defer restore()

	_, err := readBarrierLineFromPipedStdin()
	require.Error(t, err)

	var barrierErr *BarrierError
	require.ErrorAs(t, err, &barrierErr)
	assert.Equal(t, "read_password", barrierErr.Operation)
}

func TestReadBarrierPassword_PipedAndEmpty(t *testing.T) {
	pipeBarrier(t, "hunter2")

	var buf bytes.Buffer
	got, err := readBarrierPassword(&buf, "Password: ")
	require.NoError(t, err)
	assert.Equal(t, "hunter2", got)

	pipeBarrier(t, "")
	_, err = readBarrierPassword(&buf, "Password: ")
	assert.ErrorIs(t, err, ErrBarrierPasswordEmpty)
}

func TestReadBarrierPassword_TerminalPathReportsReadFailure(t *testing.T) {
	previous := barrierInputIsTerminal
	barrierInputIsTerminal = func() bool { return true }
	defer func() { barrierInputIsTerminal = previous }()

	var buf bytes.Buffer
	_, err := readBarrierPassword(&buf, "Password: ")
	require.Error(t, err)
	assert.Contains(t, buf.String(), "Password: ")
}

func TestReadAndConfirmBarrierPassword_MatchesMismatchesAndEmpty(t *testing.T) {
	var buf bytes.Buffer

	pipeBarrier(t, "hunter2", "hunter2")
	got, err := readAndConfirmBarrierPassword(&buf)
	require.NoError(t, err)
	assert.Equal(t, "hunter2", got)

	pipeBarrier(t, "hunter2", "hunter3")
	_, err = readAndConfirmBarrierPassword(&buf)
	assert.ErrorIs(t, err, ErrBarrierPasswordConfirm)

	pipeBarrier(t, "", "")
	_, err = readAndConfirmBarrierPassword(&buf)
	assert.ErrorIs(t, err, ErrBarrierPasswordEmpty)
}

// TestReadAndConfirmBarrierPassword_SharedReaderKeepsSecondLine guards the
// read-ahead hazard: the confirmation line must survive the first read.
func TestReadAndConfirmBarrierPassword_SharedReaderKeepsSecondLine(t *testing.T) {
	pipeBarrier(t, "a-long-passphrase-value", "a-long-passphrase-value")

	var buf bytes.Buffer
	got, err := readAndConfirmBarrierPassword(&buf)
	require.NoError(t, err)
	assert.Equal(t, "a-long-passphrase-value", got)
}

func TestReadAndConfirmBarrierPassword_TerminalPathReportsReadFailure(t *testing.T) {
	previous := barrierInputIsTerminal
	barrierInputIsTerminal = func() bool { return true }
	defer func() { barrierInputIsTerminal = previous }()

	var buf bytes.Buffer
	_, err := readAndConfirmBarrierPassword(&buf)
	require.Error(t, err)
}

// --- data dir + strategy resolution ---

func TestResolveBarrierDataDir_Precedence(t *testing.T) {
	dir := isolateBarrier(t)
	t.Setenv("XKEY_DATA_DIR", "/env/loses")
	viper.Set("data_dir", "/viper/loses")

	got, err := resolveBarrierDataDir()
	require.NoError(t, err)
	assert.Equal(t, dir, got)

	barrierDataDir = ""
	got, err = resolveBarrierDataDir()
	require.NoError(t, err)
	assert.Equal(t, "/env/loses", got)

	t.Setenv("XKEY_DATA_DIR", "")
	got, err = resolveBarrierDataDir()
	require.NoError(t, err)
	assert.Equal(t, "/viper/loses", got)
}

func TestResolveBarrierDataDir_HomeFallback(t *testing.T) {
	isolateBarrier(t)
	barrierDataDir = ""
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XKEY_HOME", filepath.Join(home, ".xkey"))

	got, err := resolveBarrierDataDir()
	require.NoError(t, err)
	assert.NotEmpty(t, got)
	assert.True(t, strings.HasPrefix(got, home), "resolved dir %q must live under HOME", got)
}

func TestStrategyDisplayName(t *testing.T) {
	assert.Equal(t, "software", strategyDisplayName(xkms.StrategyPassphrase),
		"the CLI documents the passphrase strategy as \"software\"")
	assert.Equal(t, string(xkms.StrategyTPM2), strategyDisplayName(xkms.StrategyTPM2))
	assert.Equal(t, "made-up", strategyDisplayName(xkms.StrategyID("made-up")))
}

func TestIsValidStrategy(t *testing.T) {
	for _, valid := range []string{"software", "tpm2", "pkcs11"} {
		assert.True(t, isValidStrategy(valid), "%q must be accepted", valid)
	}
	for _, invalid := range []string{"", "SOFTWARE", "passphrase", "yubikey"} {
		assert.False(t, isValidStrategy(invalid), "%q must be rejected", invalid)
	}
}

func TestResolveBarrierStrategyID_FlagWins(t *testing.T) {
	dir := isolateBarrier(t)

	barrierStrategy = "software"
	id, err := resolveBarrierStrategyID(dir)
	require.NoError(t, err)
	assert.Equal(t, xkms.StrategyPassphrase, id)

	barrierStrategy = "tpm2"
	id, err = resolveBarrierStrategyID(dir)
	require.NoError(t, err)
	assert.Equal(t, xkms.StrategyTPM2, id)
}

func TestResolveBarrierStrategyID_RejectsUnknownFlag(t *testing.T) {
	dir := isolateBarrier(t)
	barrierStrategy = "not-a-strategy"

	_, err := resolveBarrierStrategyID(dir)
	require.Error(t, err)

	var barrierErr *BarrierError
	require.ErrorAs(t, err, &barrierErr)
	assert.Equal(t, "validate_strategy", barrierErr.Operation)
	assert.Contains(t, err.Error(), "valid values: software, tpm2, pkcs11")
}

func TestResolveBarrierStrategyID_ReadsExistingRootKeyStrategy(t *testing.T) {
	dir := isolateBarrier(t)
	barrierStrategy = ""

	// Initialize with the software strategy, then clear the flag: the
	// strategy recorded in the sealed blob must win over auto-detection so
	// an existing barrier is never opened with the wrong strategy.
	barrierStrategy = "software"
	pipeBarrier(t, "hunter2", "hunter2")
	_, err := runBarrierCmd(t, runBarrierInit)
	require.NoError(t, err)

	barrierStrategy = ""
	id, err := resolveBarrierStrategyID(dir)
	require.NoError(t, err)
	assert.Equal(t, xkms.StrategyPassphrase, id)
}

func TestResolveBarrierStrategyID_CorruptRootKeyIsReported(t *testing.T) {
	dir := isolateBarrier(t)
	barrierStrategy = ""

	writeBarrierRootKey(t, dir, []byte("not json"))

	_, err := resolveBarrierStrategyID(dir)
	require.Error(t, err)

	var barrierErr *BarrierError
	require.ErrorAs(t, err, &barrierErr)
	assert.Equal(t, "read_strategy", barrierErr.Operation)
}

func TestAssembleBarrierStrategy(t *testing.T) {
	dir := isolateBarrier(t)

	strategy, closer, err := assembleBarrierStrategy(xkms.StrategyPassphrase, dir)
	require.NoError(t, err)
	require.NotNil(t, strategy)
	assert.Nil(t, closer, "the software strategy holds no hardware resources")

	_, _, err = assembleBarrierStrategy(xkms.StrategyID("bogus"), dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unsupported strategy "bogus"`)
}

func TestBarrierRootKeyExists(t *testing.T) {
	dir := t.TempDir()
	assert.False(t, barrierRootKeyExists(dir))

	writeBarrierRootKey(t, dir, []byte("{}"))
	assert.True(t, barrierRootKeyExists(dir))
}

// --- barrier init / unseal / seal / status round trip ---

func TestBarrierLifecycle_InitUnsealSeal(t *testing.T) {
	dir := isolateBarrier(t)

	pipeBarrier(t, "correct-horse", "correct-horse")
	out, err := runBarrierCmd(t, runBarrierInit)
	require.NoError(t, err)
	assert.Contains(t, out, "Barrier initialized successfully.")
	assert.Contains(t, out, "Strategy:        software")
	assert.Contains(t, out, dir)
	assert.True(t, barrierRootKeyExists(dir), "init must persist the sealed root key")

	pipeBarrier(t, "correct-horse")
	out, err = runBarrierCmd(t, runBarrierUnseal)
	require.NoError(t, err)
	assert.Contains(t, out, "Barrier unsealed successfully.")
	assert.Contains(t, out, "Strategy: software")

	out, err = runBarrierCmd(t, runBarrierSeal)
	require.NoError(t, err)
	assert.Contains(t, out, "Barrier sealed successfully.")
}

func TestRunBarrierInit_RefusesSecondInitialization(t *testing.T) {
	isolateBarrier(t)

	pipeBarrier(t, "correct-horse", "correct-horse")
	_, err := runBarrierCmd(t, runBarrierInit)
	require.NoError(t, err)

	pipeBarrier(t, "another-pass", "another-pass")
	_, err = runBarrierCmd(t, runBarrierInit)
	require.Error(t, err)

	var barrierErr *BarrierError
	require.ErrorAs(t, err, &barrierErr)
	assert.Equal(t, "check_initialized", barrierErr.Operation)
	assert.Contains(t, err.Error(), "barrier already initialized")
}

func TestRunBarrierInit_RejectsUnknownStrategyBeforeTouchingDisk(t *testing.T) {
	dir := isolateBarrier(t)
	barrierStrategy = "quantum"

	_, err := runBarrierCmd(t, runBarrierInit)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown strategy "quantum"`)
	assert.False(t, barrierRootKeyExists(dir),
		"a rejected strategy must not leave a partially initialized barrier")
}

func TestRunBarrierInit_PropagatesPasswordMismatch(t *testing.T) {
	dir := isolateBarrier(t)

	pipeBarrier(t, "one-pass", "other-pass")
	_, err := runBarrierCmd(t, runBarrierInit)
	assert.ErrorIs(t, err, ErrBarrierPasswordConfirm)
	assert.False(t, barrierRootKeyExists(dir))
}

func TestRunBarrierUnseal_WrongPasswordFails(t *testing.T) {
	isolateBarrier(t)

	pipeBarrier(t, "correct-horse", "correct-horse")
	_, err := runBarrierCmd(t, runBarrierInit)
	require.NoError(t, err)

	pipeBarrier(t, "wrong-horse")
	_, err = runBarrierCmd(t, runBarrierUnseal)
	require.Error(t, err)

	var barrierErr *BarrierError
	require.ErrorAs(t, err, &barrierErr)
	assert.Equal(t, "unseal", barrierErr.Operation)
}

// TestRunBarrierUnseal_CRLFPasswordMatchesTerminalEntry is the regression
// test for the CRLF trimming fix: a password piped in with Windows line
// endings must unseal a barrier that was initialized from a terminal.
func TestRunBarrierUnseal_CRLFPasswordMatchesTerminalEntry(t *testing.T) {
	isolateBarrier(t)

	pipeBarrier(t, "correct-horse", "correct-horse")
	_, err := runBarrierCmd(t, runBarrierInit)
	require.NoError(t, err)

	restore := setBarrierStdin(strings.NewReader("correct-horse\r\n"))
	defer restore()
	previous := barrierInputIsTerminal
	barrierInputIsTerminal = func() bool { return false }
	defer func() { barrierInputIsTerminal = previous }()

	out, err := runBarrierCmd(t, runBarrierUnseal)
	require.NoError(t, err, "a CRLF-terminated password must not lock the barrier")
	assert.Contains(t, out, "Barrier unsealed successfully.")
}

func TestRunBarrierUnseal_RequiresInitializedBarrier(t *testing.T) {
	isolateBarrier(t)

	_, err := runBarrierCmd(t, runBarrierUnseal)
	require.Error(t, err)

	var barrierErr *BarrierError
	require.ErrorAs(t, err, &barrierErr)
	assert.Equal(t, "check_initialized", barrierErr.Operation)
	assert.Contains(t, err.Error(), "run 'xkey barrier init' first")
}

func TestRunBarrierSeal_RequiresInitializedBarrier(t *testing.T) {
	isolateBarrier(t)

	_, err := runBarrierCmd(t, runBarrierSeal)
	require.Error(t, err)

	var barrierErr *BarrierError
	require.ErrorAs(t, err, &barrierErr)
	assert.Equal(t, "check_initialized", barrierErr.Operation)
}

func TestRunBarrierSeal_IsIdempotent(t *testing.T) {
	isolateBarrier(t)

	pipeBarrier(t, "correct-horse", "correct-horse")
	_, err := runBarrierCmd(t, runBarrierInit)
	require.NoError(t, err)

	for i := 0; i < 2; i++ {
		out, err := runBarrierCmd(t, runBarrierSeal)
		require.NoError(t, err, "sealing an already-sealed barrier must be a no-op")
		assert.Contains(t, out, "Barrier sealed successfully.")
	}
}

// --- barrier status ---

func TestRunBarrierStatus_UninitializedText(t *testing.T) {
	dir := isolateBarrier(t)

	out, err := runBarrierCmd(t, runBarrierStatus)
	require.NoError(t, err)
	assert.Contains(t, out, "Barrier Status: Not Initialized")
	assert.Contains(t, out, dir)
	assert.Contains(t, out, "Run 'xkey barrier init' to initialize the barrier.")
}

func TestRunBarrierStatus_UninitializedJSON(t *testing.T) {
	dir := isolateBarrier(t)
	barrierStatusJSON = true

	out, err := runBarrierCmd(t, runBarrierStatus)
	require.NoError(t, err)

	var info barrierStatusInfo
	require.NoError(t, json.Unmarshal([]byte(out), &info))
	assert.False(t, info.Initialized)
	assert.True(t, info.Sealed, "an uninitialized barrier must never report itself unsealed")
	assert.Equal(t, dir, info.DataDir)
	assert.Equal(t, defaultBarrierRootKeyPath, info.RootKeyEntry)
}

func TestRunBarrierStatus_InitializedReportsStrategy(t *testing.T) {
	isolateBarrier(t)

	pipeBarrier(t, "correct-horse", "correct-horse")
	_, err := runBarrierCmd(t, runBarrierInit)
	require.NoError(t, err)

	out, err := runBarrierCmd(t, runBarrierStatus)
	require.NoError(t, err)
	assert.Contains(t, out, "Initialized:      Yes")
	assert.Contains(t, out, "State:            Sealed")
	assert.Contains(t, out, "Strategy:         software")
	assert.Contains(t, out, "Hardware-backed:  No")

	barrierStatusJSON = true
	jsonOut, err := runBarrierCmd(t, runBarrierStatus)
	require.NoError(t, err)

	var info barrierStatusInfo
	require.NoError(t, json.Unmarshal([]byte(jsonOut), &info))
	assert.True(t, info.Initialized)
	assert.Equal(t, "software", info.Strategy)
	assert.False(t, info.HardwareBacked)
}

func TestRunBarrierStatus_HardwareStrategyFlagged(t *testing.T) {
	dir := isolateBarrier(t)
	barrierStatusJSON = true

	// Write a sealed root key that claims a TPM2 strategy so the
	// hardware-backed classification is exercised without a real TPM.
	blob, err := json.Marshal(xkms.SealedRootKey{Strategy: xkms.StrategyTPM2})
	require.NoError(t, err)
	writeBarrierRootKey(t, dir, blob)

	out, err := runBarrierCmd(t, runBarrierStatus)
	require.NoError(t, err)

	var info barrierStatusInfo
	require.NoError(t, json.Unmarshal([]byte(out), &info))
	assert.Equal(t, string(xkms.StrategyTPM2), info.Strategy)
	assert.True(t, info.HardwareBacked)
}

func TestRunBarrierStatus_UnreadableRootKeyStillReportsInitialized(t *testing.T) {
	dir := isolateBarrier(t)

	writeBarrierRootKey(t, dir, []byte("garbage"))

	out, err := runBarrierCmd(t, runBarrierStatus)
	require.NoError(t, err, "unparseable root key must not crash status")
	assert.Contains(t, out, "Initialized:      Yes")
	assert.Contains(t, out, "Hardware-backed:  No")
}

// --- writeJSON ---

func TestWriteJSON_IndentsAndTerminates(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, writeJSON(&buf, map[string]int{"a": 1}))

	assert.Equal(t, "{\n  \"a\": 1\n}\n", buf.String())
}

func TestWriteJSON_ReportsMarshalFailure(t *testing.T) {
	var buf bytes.Buffer
	err := writeJSON(&buf, make(chan int))
	require.Error(t, err)

	var barrierErr *BarrierError
	require.ErrorAs(t, err, &barrierErr)
	assert.Equal(t, "json_marshal", barrierErr.Operation)
}

func TestWriteJSON_ReportsWriteFailure(t *testing.T) {
	err := writeJSON(failingWriter{}, map[string]int{"a": 1})
	require.Error(t, err)

	var barrierErr *BarrierError
	require.ErrorAs(t, err, &barrierErr)
	assert.Equal(t, "write_output", barrierErr.Operation)
}

// failingWriter rejects every write, exercising output error handling.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// --- BarrierError ---

func TestBarrierError_Message(t *testing.T) {
	tests := []struct {
		name string
		err  *BarrierError
		want string
	}{
		{"operation only", &BarrierError{Operation: "seal"}, "barrier: seal"},
		{"with message", &BarrierError{Operation: "seal", Message: "nope"}, "barrier: seal: nope"},
		{"with cause", &BarrierError{Operation: "seal", Err: os.ErrPermission}, "barrier: seal: permission denied"},
		{"with both", &BarrierError{Operation: "seal", Message: "nope", Err: os.ErrPermission}, "barrier: seal: nope: permission denied"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.err.Error())
		})
	}
}

func TestBarrierError_Unwrap(t *testing.T) {
	assert.ErrorIs(t, &BarrierError{Operation: "seal", Err: os.ErrPermission}, os.ErrPermission)
	assert.Nil(t, (&BarrierError{Operation: "seal"}).Unwrap())
}
